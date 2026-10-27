//! Real managed ClientBrowser, ClientSession, framed result writer and CDP peer.
//! Only CDP responses are scripted. Recording state, journals, attachments,
//! encoder children, private files and quota reservations are production-owned.
use super::*;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    StopError,
    DetachError,
    StopMissingAck,
    DetachMissingAck,
    EncoderError,
    Cancel,
    Deadline,
    OwnerDetached,
    StartMissingAck,
}
struct Peer {
    endpoint: String,
    requests: Arc<Mutex<Vec<Value>>>,
    reached: tokio::sync::mpsc::UnboundedReceiver<Value>,
    replies: tokio::sync::mpsc::UnboundedSender<Option<Value>>,
    task: tokio::task::JoinHandle<()>,
}
fn reply(request: &Value, error: bool) -> Value {
    let mut result = if error {
        json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic recorder refusal"}})
    } else {
        json!({"id":request["id"],"result":{}})
    };
    if let Some(session) = request.get("sessionId") {
        result["sessionId"] = session.clone();
    }
    result
}
async fn peer(fault: Fault) -> Peer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = requests.clone();
    let (reached_tx, reached) = tokio::sync::mpsc::unbounded_channel();
    let (replies, mut replies_rx) = tokio::sync::mpsc::unbounded_channel::<Option<Value>>();
    let mut jpeg = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
        320,
        200,
        image::Rgb([23, 41, 89]),
    ))
    .write_to(&mut jpeg, image::ImageFormat::Jpeg)
    .unwrap();
    let image = base64::engine::general_purpose::STANDARD.encode(if fault == Fault::EncoderError {
        b"not-a-jpeg".as_slice()
    } else {
        jpeg.get_ref().as_slice()
    });
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut page = None;
        let mut attaches = 0;
        let mut loader = "initial-loader";
        let mut isolated_world: Option<(&str, i64)> = None;
        loop {
            let incoming = tokio::select! {
                incoming = socket.next() => incoming,
                Some(injected) = replies_rx.recv() => {
                    let Some(injected) = injected else { let _ = socket.close(None).await; return; };
                    if socket.send(Message::Text(injected.to_string())).await.is_err() { return; }
                    continue;
                }
            };
            let Some(Ok(Message::Text(text))) = incoming else {
                break;
            };
            let request: Value = serde_json::from_str(&text).unwrap();
            log.lock().unwrap().push(request.clone());
            let method = request["method"].as_str().unwrap();
            let session = request["sessionId"].as_str().unwrap_or("");
            let mut after = Vec::new();
            let mut error = false;
            let result = match method {
                "Browser.getVersion" => {
                    json!({"protocolVersion":"1.3","product":"Synthetic Chromium/1.0",
                    "revision":"synthetic-revision","userAgent":"Synthetic Chromium Linux","jsVersion":"synthetic-js"})
                }
                "Target.createBrowserContext" => json!({"browserContextId":"synthetic-context"}),
                "Target.createTarget" => {
                    assert!(page.is_none(), "unexpected new application page");
                    page = Some(
                        json!({"targetId":"page-1","type":"page","browserContextId":"synthetic-context","url":"about:blank","title":""}),
                    );
                    json!({"targetId":"page-1"})
                }
                "Target.attachToTarget" => {
                    assert_eq!(request["params"]["targetId"], "page-1");
                    attaches += 1;
                    assert!(attaches <= 2, "recorder attach was replayed");
                    json!({"sessionId":if attaches == 1 { "session-1" } else { "capture-1" }})
                }
                "Target.getTargets" => {
                    json!({"targetInfos":page.iter().cloned().collect::<Vec<_>>()})
                }
                "Target.getTargetInfo" => {
                    json!({"targetInfo":page.as_ref().expect("requested gone target")})
                }
                "Target.closeTarget" => {
                    page = None;
                    after.push(json!({"method":"Target.detachedFromTarget","params":{"targetId":"page-1","sessionId":"session-1"}}));
                    json!({"success":true})
                }
                "Target.disposeBrowserContext" => {
                    page = None;
                    json!({})
                }
                "Page.getFrameTree" => {
                    assert_eq!(session, "session-1");
                    assert!(page.is_some(), "frame tree belongs to a live fixture page");
                    json!({"frameTree":{"frame":{"id":"frame-session-1","loaderId":loader,
                    "url":"about:blank","securityOrigin":"null"}}})
                }
                "Page.createIsolatedWorld" => {
                    // Real managed recording admission enumerates its one owned
                    // document before geometry. Do not substitute a ready frame.
                    assert_eq!(session, "session-1");
                    assert_eq!(
                        page.as_ref().expect("world requested for gone page")["browserContextId"],
                        "synthetic-context"
                    );
                    assert_eq!(
                        request["params"],
                        json!({
                            "frameId":"frame-session-1", "worldName":"agent-browser-native-observation"
                        })
                    );
                    let context = if loader == "initial-loader" { 7 } else { 8 };
                    isolated_world = Some((loader, context));
                    json!({"executionContextId":context})
                }
                "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":"synthetic-script"}),
                "Runtime.evaluate" => {
                    assert_eq!(session, "session-1");
                    assert!(page.is_some(), "evaluation belongs to a live fixture page");
                    assert_eq!(request["params"]["returnByValue"], true);
                    if let Some(context) = request["params"].get("contextId") {
                        assert_eq!(isolated_world, Some((loader, context.as_i64().unwrap())));
                    }
                    match request["params"]["expression"].as_str().unwrap_or("") {
                        "[window.innerWidth, window.innerHeight]" => {
                            json!({"result":{"type":"object","value":[320,200]}})
                        }
                        "document.title" => {
                            json!({"result":{"type":"string","value":"recording-survived"}})
                        }
                        "location.href" => {
                            json!({"result":{"type":"string","value":"about:blank"}})
                        }
                        other => panic!("unmodeled recording Runtime.evaluate expression: {other}"),
                    }
                }
                "Page.navigate" => {
                    assert_eq!(session, "session-1");
                    loader = "activated-loader";
                    isolated_world = None;
                    after.push(json!({"method":"Page.frameNavigated","sessionId":session,"params":{"frame":{
                        "id":"frame-session-1","loaderId":loader,"url":"about:blank","securityOrigin":"null"}}}));
                    after.push(
                        json!({"method":"Page.lifecycleEvent","sessionId":session,"params":{
                        "frameId":"frame-session-1","loaderId":loader,"name":"load"}}),
                    );
                    json!({"frameId":"frame-session-1","loaderId":loader})
                }
                "Page.getLayoutMetrics" => {
                    json!({"cssLayoutViewport":{"pageX":0,"pageY":0,"clientWidth":320,"clientHeight":200},
                    "cssVisualViewport":{"pageX":0,"pageY":0,"offsetX":0,"offsetY":0,"clientWidth":320,"clientHeight":200,"scale":1}})
                }
                "Page.captureScreenshot" => json!({"data":image}),
                "Page.startScreencast" => {
                    assert_eq!(session, "capture-1");
                    reached_tx.send(request.clone()).unwrap();
                    // Every case is ordered by the actual tracked submission.
                    // Keep servicing control/cleanup commands while its ACK is held.
                    continue;
                }
                "Page.stopScreencast" => {
                    assert_eq!(session, "capture-1");
                    if fault == Fault::StopMissingAck {
                        reached_tx.send(request.clone()).unwrap();
                        continue;
                    }
                    error = fault == Fault::StopError;
                    json!({})
                }
                "Target.detachFromTarget" => {
                    assert_eq!(request["params"]["sessionId"], "capture-1");
                    if fault == Fault::DetachMissingAck {
                        reached_tx.send(request.clone()).unwrap();
                        continue;
                    }
                    error = fault == Fault::DetachError;
                    json!({})
                }
                "Page.enable"
                | "Runtime.enable"
                | "Network.enable"
                | "WebMCP.enable"
                | "DOM.enable"
                | "DOM.disable"
                | "Network.setBypassServiceWorker"
                | "Fetch.enable"
                | "Fetch.disable"
                | "Browser.setDownloadBehavior"
                | "Browser.close"
                | "Page.setLifecycleEventsEnabled"
                | "Emulation.setEmulatedMedia"
                | "Target.setDiscoverTargets"
                | "Page.removeScriptToEvaluateOnNewDocument"
                | "Target.setAutoAttach"
                | "Runtime.runIfWaitingForDebugger"
                | "Emulation.setDeviceMetricsOverride" => json!({}),
                other => panic!("unmodeled recording CDP method {other}: {request}"),
            };
            let mut response = reply(&request, error);
            if !error {
                response["result"] = result;
            }
            if socket
                .send(Message::Text(response.to_string()))
                .await
                .is_err()
            {
                return;
            }
            for event in after {
                if socket.send(Message::Text(event.to_string())).await.is_err() {
                    return;
                }
            }
        }
    });
    Peer {
        endpoint,
        requests,
        reached,
        replies,
        task,
    }
}
async fn setup(fixture: &mut FramedFixture, endpoint: &str) -> Result<String, String> {
    fixture.ready().await?;
    let opened = fixture
        .command(
            "scope.open",
            fixture_scope_open("connect", Some(endpoint)),
            5,
        )
        .await?;
    let scope = opened["identityScope"]
        .as_str()
        .ok_or("missing scope")?
        .to_owned();
    fixture.scope = Some(scope.clone());
    fixture
        .command("scope.configure", fixture_configuration(&scope, None), 5)
        .await?;
    fixture
        .command("network.routes.replace", fixture_routes(&scope), 5)
        .await?;
    fixture.registry = 1;
    // Activation is separately acknowledged before the tested recorder attempt.
    fixture
        .command("page.activate", json!({"identityScope":scope}), 5)
        .await?;
    Ok(scope)
}
async fn start(fixture: &mut FramedFixture, scope: &str, millis: u64) -> Result<(), String> {
    fixture.sequence += 1;
    fixture
        .write(
            json!({"type":"request","id":"refused-recording","generation":1,
        "operationSeq":fixture.sequence,"timeoutMs":millis,"command":"recording.start",
        "args":{"identityScope":scope}}),
        )
        .await
}
fn callback_retirement_matches(frame: &Value, scope: &str, through: u64) -> bool {
    frame["type"] == "event"
        && frame["generation"] == 1
        && through
            .checked_add(1)
            .is_some_and(|next| frame["sequence"] == next)
        && frame["event"] == "scope.callbacks-retired"
        && frame["payload"] == json!({"identityScope":scope,"throughEventSequence":through})
        && frame.get("decision").is_none()
}

fn notice(
    fixture: &mut FramedFixture,
    frame: &Value,
    callbacks_retired: &mut bool,
) -> Result<(), String> {
    if frame["generation"] != 1
        || frame["type"] != "event"
        || frame["sequence"] != fixture.event_sequence + 1
    {
        return Err("wrong recording event generation/order".into());
    }
    if frame["event"] == "browser.disconnected" {
        if frame["payload"] != json!({"reason":"browser-connection-closed"})
            || frame.get("decision").is_some()
        {
            return Err("invalid native disconnect notice".into());
        }
    } else if frame["event"] == "scope.callbacks-retired" {
        // This is the production terminal callback fence, not an application
        // notice or permission to resume the retired recording operation.
        if *callbacks_retired
            || !callback_retirement_matches(
                frame,
                fixture
                    .scope
                    .as_deref()
                    .ok_or("retirement notice without scope")?,
                fixture.event_sequence,
            )
        {
            return Err("invalid or repeated native callback retirement notice".into());
        }
        *callbacks_retired = true;
    } else {
        validate_fixture_notice(frame)?;
        if frame["payload"]["identityScope"] != fixture.scope.as_deref().unwrap_or("") {
            return Err("wrong notice scope".into());
        }
    }
    fixture.event_sequence += 1;
    Ok(())
}
async fn correlated(
    fixture: &mut FramedFixture,
    id: &str,
    callbacks_retired: &mut bool,
) -> Result<Value, String> {
    let phase = match id {
        "refused-recording" => "recording start outcome",
        "after-unknown" => "terminal ordinary-command refusal",
        _ => return Err("unrecognized recording fixture phase".into()),
    };
    for _ in 0..32 {
        let frame = tokio::time::timeout(Duration::from_secs(12), fixture.read())
            .await
            .map_err(|_| "recording result timed out")??;
        if frame["generation"] != 1 {
            let kind = match frame["type"].as_str() {
                Some("result") => "result",
                Some("event") => "event",
                Some("error") => "terminal error",
                Some("closed") => "closed",
                Some("control-result") => "control result",
                _ => "unexpected",
            };
            // Closed categories only: never log an unvalidated frame body.
            return Err(format!("{phase}: {kind} frame did not carry generation 1"));
        }
        if frame["type"] == "result" {
            if frame["id"] != id || frame["operationSeq"] != fixture.sequence {
                return Err("wrong recording result correlation".into());
            }
            return Ok(frame);
        }
        notice(fixture, &frame, callbacks_retired)?;
    }
    Err("recording frame bound exceeded".into())
}
async fn run(fault: Fault) {
    let mut peer = peer(fault).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    // Unknown retires ordinary admission. Negotiate the production terminal
    // lane so the follow-up below receives a refusal, not an EOF/shutdown error.
    // This does not permit recording.stop to execute or revive the old scope.
    let mut fixture = FramedFixture::with_capabilities(
        broker.clone(),
        browser.clone(),
        vec!["terminal.close/1".into()],
    );
    let mut callbacks_retired = false;
    let proof: Result<(),String> = async {
        let scope = setup(&mut fixture,&peer.endpoint).await?;
        let page = browser.page_lease(false).await.map_err(|e|format!("original page {e:?}"))?;
        let ledger = page.client.debt_ledger().ok_or("missing managed ledger")?;
        if !ledger.matches_owner(1,&scope) { return Err("wrong owner ledger".into()); }
        start(&mut fixture,&scope,if fault == Fault::Deadline { 1000 } else { 5000 }).await?;
        let submitted = tokio::time::timeout(Duration::from_secs(4),peer.reached.recv()).await
            .map_err(|_|"actual start RPC never submitted")?.ok_or("peer ended before start")?;
        if submitted["method"] != "Page.startScreencast" { return Err("wrong fault boundary".into()); }
        if fault == Fault::Cancel {
            fixture.write(json!({"type":"cancel","id":"cancel-recording","generation":1,"operationSeq":fixture.sequence})).await?;
            let mut accepted = false;
            for _ in 0..32 {
                let frame = tokio::time::timeout(Duration::from_secs(2),fixture.read()).await
                    .map_err(|_|"cancel control timed out")??;
                if frame["type"] == "control-result" {
                    if frame["generation"] != 1 || frame["id"] != "cancel-recording" || frame["accepted"] != true {
                        return Err("real recording cancellation was not accepted".into());
                    }
                    accepted = true;
                    break;
                }
                notice(&mut fixture,&frame,&mut callbacks_retired)?;
            }
            if !accepted { return Err("cancel notice bound exceeded".into()); }
        } else if fault == Fault::Deadline {
            // Original lease expiry, not a synthetic cancellation signal.
            tokio::time::sleep(Duration::from_millis(1100)).await;
        } else if fault == Fault::OwnerDetached {
            peer.replies.send(Some(json!({"method":"Target.detachedFromTarget","params":{
                "targetId":"page-1","sessionId":"session-1"}}))).map_err(|_|"peer closed")?;
            tokio::time::timeout(Duration::from_secs(1),async {
                while page.targets.owned_target("page-1").is_ok() { tokio::task::yield_now().await; }
            }).await.map_err(|_|"real detach not applied")?;
        }
        if fault == Fault::StartMissingAck {
            peer.replies.send(None).map_err(|_|"peer closed")?;
        } else {
            peer.replies.send(Some(reply(&submitted,true))).map_err(|_|"peer closed")?;
        }
        // Missing cleanup ACKs remain missing through the existing 2s cleanup
        // bound. Only afterwards acknowledge the exact original command so EOF
        // can reclaim resources; this cannot turn its fixed failure into success.
        let late = if matches!(fault,Fault::StopMissingAck|Fault::DetachMissingAck) {
            Some(tokio::time::timeout(Duration::from_secs(3),peer.reached.recv()).await
                .map_err(|_|"cleanup command not reached")?.ok_or("peer ended during cleanup")?)
        } else { None };
        if let Some(late) = &late {
            tokio::time::sleep(Duration::from_millis(2200)).await;
            peer.replies.send(Some(reply(late,false))).map_err(|_|"peer closed")?;
        }
        let frame = correlated(&mut fixture,"refused-recording",&mut callbacks_retired).await?;
        if frame["ok"] != false { return Err("refused start succeeded".into()); }
        if fault == Fault::None {
            if frame["error"]["code"] != "browser-failure" || frame["effects"] != "completed" || frame["scopeState"] != "usable" {
                return Err(format!("clean exact refusal not reusable: {frame}"));
            }
            if broker.health().map_err(|_|"health")?.1 != ScopeState::Usable { return Err("broker quarantined clean refusal".into()); }
            let stopped = fixture.command("recording.stop",json!({"identityScope":scope}),5).await?;
            if stopped["segments"] != json!([]) { return Err("failed recorder published segment".into()); }
            fixture.command("context.media",json!({"identityScope":scope,"colorScheme":"dark","reducedMotion":"reduce"}),5).await?;
            let title = fixture.command("page.title",json!({"identityScope":scope}),5).await?;
            if title["title"] != "recording-survived" { return Err(format!("follow-up title failed {title}")); }
            let actions = browser.owner.lock().await.as_ref().ok_or("missing owner")?
                .runtime.as_ref().ok_or("missing runtime")?.actions.clone();
            if actions.is_recording_armed().await.map_err(|_|"armed state unavailable")? {
                return Err("failed start left recording armed".into());
            }
            browser.blobs.check_budget_integrity().map_err(|_|"blob budget corrupt")?;
            // Two default full producer reservations consume the complete 128MiB
            // budget without allocating payload bytes. Any retained recording
            // charge prevents this exact capacity check.
            let blob_scope = crate::native::client_blobs::BlobScope { generation:1, identity_scope:scope.clone() };
            let first = browser.blobs.reserve_producer(blob_scope.clone()).map_err(|_|"first released quota unavailable")?;
            let second = browser.blobs.reserve_producer(blob_scope).map_err(|_|"recording retained quota")?;
            drop((first,second));
            let debt = ledger.snapshot();
            if debt.outstanding_commands != 0 || debt.input_debt != 0 || debt.object_debt != 0 || debt.integrity_lost {
                return Err("reusable result retained protocol debt".into());
            }
        } else {
            if fault == Fault::Cancel && frame["error"]["code"] != "cancelled" {
                return Err(format!("cancel reason changed: {frame}"));
            }
            if fault == Fault::Deadline && frame["error"]["code"] != "deadline-exceeded" {
                return Err(format!("deadline reason changed: {frame}"));
            }
            if frame["effects"] != "unknown" || frame["scopeState"] != "quarantined" {
                return Err(format!("unproved refusal incorrectly reusable ({fault:?}): {frame}"));
            }
            if broker.health().map_err(|_|"health")?.1 != ScopeState::Quarantined { return Err("unknown did not quarantine actual broker".into()); }
            // Real framed follow-up is rejected before any recorder replay.
            fixture.sequence += 1;
            fixture.write(json!({"type":"request","id":"after-unknown","generation":1,"operationSeq":fixture.sequence,
                "timeoutMs":1000,"command":"recording.stop","args":{"identityScope":scope}})).await?;
            let rejected = correlated(&mut fixture,"after-unknown",&mut callbacks_retired).await?;
            if rejected["id"] != "after-unknown" || rejected["ok"] != false || rejected["effects"] != "not-dispatched"
                || rejected["error"]["code"] != "scope-unavailable" || rejected["scopeState"] != "quarantined"
                || rejected.get("retention").is_some() || rejected.get("recovery").is_some() {
                return Err("quarantined follow-up was not a closed terminal refusal".into());
            }
        }
        let requests = peer.requests.lock().unwrap();
        let count = |method: &str| requests.iter().filter(|r|r["method"] == method).count();
        if count("Page.startScreencast") != 1 || count("Page.captureScreenshot") != 1 { return Err("recording start replayed".into()); }
        if fault == Fault::None && (count("Page.stopScreencast") != 1 || count("Target.detachFromTarget") != 1) {
            return Err("clean refusal cleanup was skipped or replayed".into());
        }
        Ok(())
    }.await;
    // Joining the real retained owner is mandatory even after a failed assertion.
    // Fault cases need not claim successful owner teardown, but never abort it.
    drop(fixture.stream);
    let cleanup = fixture.server.await;
    peer.task.abort();
    let _ = peer.task.await;
    // A fault may prevent teardown proof, but a task panic is never that proof.
    let cleanup = cleanup.expect("recording fixture server panicked during cleanup");
    if fault == Fault::None {
        assert!(cleanup, "cleanup unproven; proof {proof:?}");
    }
    proof.unwrap();
}

#[tokio::test]
#[ignore = "hosted ffmpeg; real managed framed recording refusal and successful encoder cleanup"]
async fn acknowledged_clean_recording_start_refusal_preserves_public_stop_and_scope() {
    run(Fault::None).await;
}
#[tokio::test]
#[ignore = "hosted ffmpeg; actual recorder cleanup error ACKs"]
async fn recording_start_refusal_cleanup_errors_remain_unknown() {
    for fault in [Fault::StopError, Fault::DetachError] {
        run(fault).await;
    }
}
#[tokio::test]
#[ignore = "hosted ffmpeg; original bounded recorder cleanup missing-ACK negatives"]
async fn recording_start_refusal_missing_cleanup_acks_remain_unknown() {
    for fault in [Fault::StopMissingAck, Fault::DetachMissingAck] {
        run(fault).await;
    }
}
#[tokio::test]
#[ignore = "hosted ffmpeg; actual encoder decode failure after start refusal"]
async fn recording_start_refusal_encoder_failure_remains_unknown() {
    run(Fault::EncoderError).await;
}
#[tokio::test]
#[ignore = "hosted ffmpeg; real framed cancel and original recording lease expiry"]
async fn recording_start_refusal_cancel_and_deadline_remain_unknown() {
    for fault in [Fault::Cancel, Fault::Deadline] {
        run(fault).await;
    }
}
#[tokio::test]
#[ignore = "hosted ffmpeg; real attachment retirement and missing start ACK"]
async fn recording_start_refusal_owner_change_and_missing_start_ack_remain_unknown() {
    for fault in [Fault::OwnerDetached, Fault::StartMissingAck] {
        run(fault).await;
    }
}

#[test]
fn recording_callback_retirement_notice_requires_exact_closed_identity_and_order() {
    let valid = json!({"type":"event","generation":1,"sequence":4,
        "event":"scope.callbacks-retired","payload":{"identityScope":"scope","throughEventSequence":3}});
    assert!(callback_retirement_matches(&valid, "scope", 3));
    assert!(!callback_retirement_matches(&valid, "foreign", 3));
    assert!(!callback_retirement_matches(&valid, "scope", 2));
    assert!(!callback_retirement_matches(&valid, "scope", u64::MAX));
    for field in ["type", "generation", "sequence", "event", "payload"] {
        let mut malformed = valid.clone();
        malformed.as_object_mut().unwrap().remove(field);
        assert!(!callback_retirement_matches(&malformed, "scope", 3));
    }
    for (field, value) in [
        ("type", json!("result")),
        ("generation", json!(2)),
        ("sequence", json!(5)),
        ("event", json!("other")),
        ("decision", Value::Null),
        (
            "payload",
            json!({"identityScope":"scope","throughEventSequence":3,"extra":true}),
        ),
        (
            "payload",
            json!({"identityScope":"scope","throughEventSequence":2}),
        ),
    ] {
        let mut malformed = valid.clone();
        malformed[field] = value;
        assert!(!callback_retirement_matches(&malformed, "scope", 3));
    }
}
