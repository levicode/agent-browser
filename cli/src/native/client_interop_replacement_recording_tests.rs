// Hosted encoder negative, not real PW/Chromium conformance. The existing CDP
// peer scripts an external context owner; native admission, recording, encoder,
// phase-two cleanup, terminal artifact transfer and Close are production code.

async fn setup_interop_recording(
    fixture: &mut FramedFixture,
    endpoint: &str,
    context_present: &AtomicBool,
) -> Result<String, String> {
    fixture.ready().await?;
    let preparation = uuid::Uuid::new_v4().to_string();
    let mut args = fixture_scope_open("connect", Some(endpoint));
    args["preparationId"] = json!(preparation);
    fixture.command("scope.interop.prepare", args, 5).await?;
    // No native creation ACK is fabricated: the independent inventory before
    // this transition was empty. Adoption must verify this new blank target.
    context_present.store(true, Ordering::SeqCst);
    let opened = fixture
        .command(
            "scope.interop.adopt",
            json!({"preparationId":preparation,"contextId":"synthetic-context","targetId":"page-1"}),
            5,
        )
        .await?;
    let scope = opened["identityScope"]
        .as_str()
        .ok_or("missing interop scope")?
        .to_owned();
    fixture.scope = Some(scope.clone());
    fixture
        .command("scope.configure", fixture_configuration(&scope, None), 5)
        .await?;
    fixture
        .command("network.routes.replace", fixture_routes(&scope), 5)
        .await?;
    fixture.registry = 1;
    fixture
        .command("page.activate", json!({"identityScope":scope}), 5)
        .await?;
    Ok(scope)
}

#[tokio::test]
#[ignore = "hosted ffmpeg/ffprobe: real marker3 recording cleanup after private replacement refusal"]
async fn interop_marker_three_create_refusal_joins_recording_and_terminal_close() {
    let context_present = Arc::new(AtomicBool::new(false));
    let peer = peer_with_interop(true, None, None, Some(context_present.clone())).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture = FramedFixture::with_capabilities(
        broker.clone(),
        browser.clone(),
        vec![
            "terminal.close/1".into(),
            crate::native::client_protocol::TERMINAL_RECORDING_ARTIFACTS.into(),
            crate::native::client_protocol::INTEROP_CONTEXT_REPLACEMENT.into(),
        ],
    );
    let mut notices = TerminalNotices::default();
    let mut retained_actions = None;
    let mut recording_directory = None;
    let mut phase_one_enrollment = None;
    let proof: Result<Vec<u8>, String> = async {
        let scope = setup_interop_recording(&mut fixture, &peer.endpoint, &context_present).await?;
        let (actions, original_enrollment) = {
            let owner = browser.owner.lock().await;
            let resource = owner.as_ref().ok_or("adopted owner missing")?;
            let runtime = resource.runtime.as_ref().ok_or("adopted runtime missing")?;
            if !runtime.interop_context || resource.context_id != "synthetic-context" {
                return Err("real adoption did not install exact interop custody".into());
            }
            (runtime.actions.clone(), runtime.enrollment.clone())
        };
        retained_actions = Some(actions.clone());
        fixture.command("recording.start", json!({"identityScope":scope}), 5).await?;
        if !actions.is_recording_armed().await.map_err(|_| "recording arm read")?
            || browser.blobs.charged_for_test().1 != 1
        {
            return Err("actual armed recording and quota were not established".into());
        }
        let (encoder_status, directory) = actions.recording_encoder_status_for_test().await;
        recording_directory = Some(directory.clone());
        let (sender, snapshot) = tokio::sync::oneshot::channel();
        *browser.interop_replacement_phase_one_snapshot.lock().unwrap() = Some(sender);
        let mut snapshot = Some(snapshot);
        fixture.sequence += 1;
        let failed = fixture.sequence;
        let reset_id = "marker-three-reset";
        fixture.write(json!({"type":"request","id":reset_id,"generation":1,
            "operationSeq":failed,"timeoutMs":10000,"command":"scope.reset",
            "args":{"identityScope":scope}})).await?;

        let mut phase = 0;
        let mut controls = std::collections::HashSet::new();
        let mut outcome = None;
        for _ in 0..64 {
            let frame = tokio::time::timeout(Duration::from_secs(5), fixture.read())
                .await.map_err(|_| "replacement frame timed out")??;
            if frame["generation"] != 1 {
                return Err("replacement frame changed generation".into());
            }
            match frame["type"].as_str() {
                Some("event") if frame["event"] == "scope.interop.replacement" => {
                    if frame["sequence"] != fixture.event_sequence + 1 || phase >= 2 {
                        return Err("replacement decision order/replay".into());
                    }
                    fixture.event_sequence += 1;
                    let token = frame["decision"]["token"].as_str().filter(|value| !value.is_empty()).ok_or("private token missing")?;
                    let timeout = frame["decision"]["timeoutMs"].as_u64().ok_or("private timeout missing")?;
                    if timeout == 0 || timeout > 10000 {
                        return Err("private decision renewed original request budget".into());
                    }
                    let (control_id, decision) = if phase == 0 {
                        if frame["payload"] != json!({"version":1,"identityScope":scope,"operationSeq":failed,
                            "phase":"retire","contextId":"synthetic-context"}) {
                            return Err("retire decision changed exact owner".into());
                        }
                        let observed = tokio::time::timeout(Duration::from_secs(2), snapshot.take().ok_or("snapshot replay")?)
                            .await.map_err(|_| "marker3 snapshot timed out")?.map_err(|_| "marker3 snapshot dropped")?;
                        if observed.phase != 3 || observed.operation_seq != failed
                            || observed.identity_scope != scope || observed.context_id != "synthetic-context"
                            || !Arc::ptr_eq(&observed.enrollment, &original_enrollment)
                        {
                            return Err("actual recording-preserving phase3 owner was not reached".into());
                        }
                        phase_one_enrollment = Some(observed.enrollment);
                        if encoder_status() != (true, true)
                            || !actions.is_recording_armed().await.map_err(|_| "preserved recording arm")?
                            || !directory.exists()
                        {
                            return Err("phase3 failed to join encoder while retaining arm/private-file custody".into());
                        }
                        // Model the exact external context.close before selecting
                        // retired. Native must independently observe absence.
                        context_present.store(false, Ordering::SeqCst);
                        ("marker-three-retired", json!({"kind":"interop-retired"}))
                    } else {
                        if frame["payload"] != json!({"version":1,"identityScope":scope,"operationSeq":failed,"phase":"create"}) {
                            return Err("create decision changed original operation".into());
                        }
                        let cleanup = original_enrollment.cleanup_outcome().map_err(|_| "phase2 outcome")?;
                        if !cleanup.isolated_context_disposed || !cleanup.autoattach_disabled {
                            return Err("create preceded real independent absence and phase-two ACK".into());
                        }
                        ("marker-three-create-refused", json!({"kind":"interop-failed"}))
                    };
                    phase += 1;
                    controls.insert(control_id.to_owned());
                    fixture.write(json!({"type":"decision","id":control_id,"generation":1,"token":token,"decision":decision})).await?;
                }
                Some("event") => {
                    validate_terminal_notice(&frame, &scope, 1, fixture.event_sequence, &mut notices)?;
                    fixture.event_sequence += 1;
                }
                Some("control-result") => {
                    let id = frame["id"].as_str().ok_or("control identity missing")?;
                    if !controls.remove(id) || frame["accepted"] != true || frame.get("error").is_some() {
                        return Err("original private decision control was not actually accepted".into());
                    }
                }
                Some("result") => {
                    if outcome.is_some() || frame["id"] != reset_id || frame["operationSeq"] != failed {
                        return Err("replacement result correlation/replay".into());
                    }
                    outcome = Some(frame);
                }
                _ => return Err("unexpected replacement wire frame".into()),
            }
            if phase == 2 && controls.is_empty() && outcome.is_some() { break; }
        }
        if phase != 2 || !controls.is_empty() { return Err("private receipts did not settle".into()); }
        let outcome = outcome.ok_or("replacement result missing")?;
        if outcome["ok"] != false || outcome["effects"] != "unknown"
            || outcome["scopeState"] != "quarantined" || outcome["error"]["code"] != "browser-failure"
            || outcome.get("retention").is_some() || outcome.get("recovery").is_some()
        {
            return Err("create refusal did not retain its original Unknown failure".into());
        }

        // Use the existing legal terminal-artifact lane while automatic shutdown
        // proceeds concurrently. Nothing holds the runtime owner or stops cleanup.
        let identity = json!({"identityScope":scope,"failedOperationSeq":failed});
        let manifest = completed(command(&mut fixture, &mut notices, "recording.finalized.collect", identity.clone()).await?)?;
        if manifest["identityScope"] != scope || manifest["failedOperationSeq"] != failed
            || manifest["segments"].as_array().map(Vec::len) != Some(1)
        { return Err("terminal batch changed owner or manufactured a new segment".into()); }
        let segment = &manifest["segments"][0];
        if segment["ordinal"] != 1 || segment["mediaType"] != "video/webm" {
            return Err("terminal segment metadata changed".into());
        }
        let mut base = identity;
        base["token"] = manifest["token"].clone();
        base["handle"] = segment["handle"].clone();
        let mut bytes = Vec::new();
        let mut eof = false;
        for _ in 0..64 {
            let mut args = base.clone();
            args["offset"] = json!(bytes.len());
            args["maxBytes"] = json!(262144);
            let chunk = completed(command(&mut fixture, &mut notices, "recording.finalized.read", args).await?)?;
            bytes.extend(base64::engine::general_purpose::STANDARD.decode(chunk["base64"].as_str().ok_or("terminal bytes missing")?).map_err(|_| "terminal base64")?);
            if chunk["nextOffset"] != bytes.len() { return Err("terminal read offset changed".into()); }
            if chunk["eof"] == true { eof = true; break; }
        }
        use sha2::{Digest, Sha256};
        if !eof || bytes.is_empty() || segment["size"] != bytes.len()
            || segment["sha256"] != format!("{:x}", Sha256::digest(&bytes))
        { return Err("actual terminal recording bytes failed size/hash validation".into()); }
        if completed(command(&mut fixture, &mut notices, "recording.finalized.release", base).await?)? != json!({"released":true}) {
            return Err("terminal byte release receipt missing".into());
        }
        let denied = command(&mut fixture, &mut notices, "page.title", json!({"identityScope":scope})).await?;
        if denied["ok"] != false || denied["effects"] != "not-dispatched" || denied["error"]["code"] != "scope-unavailable" {
            return Err("terminal collection reopened ordinary operation authority".into());
        }
        fixture.write(json!({"type":"close","id":"marker-three-close","generation":1})).await?;
        let mut closed = false;
        for _ in 0..16 {
            let frame = tokio::time::timeout(Duration::from_secs(5), fixture.read()).await.map_err(|_| "terminal Close timed out")??;
            if frame == json!({"type":"closed","id":"marker-three-close","generation":1,"scopeState":"closed"}) {
                closed = true; break;
            }
            validate_terminal_notice(&frame, &scope, 1, fixture.event_sequence, &mut notices)?;
            fixture.event_sequence += 1;
        }
        if !closed { return Err("actual terminal Closed receipt missing".into()); }
        Ok(bytes)
    }.await;

    let cleanup = fixture.finish().await;
    let log = peer.requests.lock().unwrap().clone();
    let owner_retired = browser.owner.lock().await.is_none();
    let manager_returned = browser.retained_browser.lock().await.is_some();
    peer.task.abort();
    let _ = peer.task.await;
    cleanup.expect("real marker3 terminal cleanup must be proven");
    let bytes = proof.unwrap();
    assert!(owner_retired);
    assert!(
        !manager_returned,
        "failed replacement cannot grant worker reuse"
    );
    assert_eq!(browser.blobs.charged_for_test(), (0, 0));
    assert!(browser.terminal_recording.lock().unwrap().is_none());
    let actions = retained_actions.expect("actual recording actions retained by test");
    assert!(!actions.is_recording_armed().await.unwrap());
    // Keep actions strongly alive: deletion cannot be explained by dropping its
    // runtime. Only real full terminal action cleanup empties this retained ledger.
    assert!(!recording_directory
        .expect("actual private encoder directory")
        .exists());
    let retired = phase_one_enrollment
        .expect("actual marker3 enrollment")
        .cleanup_outcome()
        .unwrap();
    assert!(retired.isolated_context_disposed && retired.autoattach_disabled);
    for method in [
        "Page.startScreencast",
        "Page.stopScreencast",
        "Page.captureScreenshot",
    ] {
        assert_eq!(
            log.iter()
                .filter(|request| request["method"] == method)
                .count(),
            1,
            "missing/replayed real recorder command {method}"
        );
    }
    assert_eq!(
        log.iter()
            .filter(|request| request["method"] == "Target.attachToTarget")
            .count(),
        2
    );
    assert!(log.iter().all(|request| !matches!(
        request["method"].as_str(),
        Some(
            "Browser.close"
                | "Target.createBrowserContext"
                | "Target.createTarget"
                | "Target.closeTarget"
                | "Target.disposeBrowserContext"
        )
    )));
    // Decode after the real Closed receipt and owner join, never extending the
    // production terminal collection window merely for a test's ffmpeg process.
    decode_video(&bytes).await.unwrap();
}
