//! Full ClientBrowser/framed lifecycle, using the existing strict CDP peer.
//! Hosted encoder dependency is explicit: native recording and child joins are real;
//! only CDP replies are scripted. Page.stopScreencast receives an actual error ACK.
#[tokio::test]
#[ignore = "hosted ffmpeg: actual managed recorder stop failure during peer retirement"]
async fn failed_peer_phase_one_still_contains_exact_context_on_terminal_shutdown() {
    let peer = peer(false, None, None).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture = FramedFixture::with_capabilities(
        broker.clone(),
        browser.clone(),
        vec!["terminal.close/1".into()],
    );
    let mut retired_enrollment = None;
    let mut recording_directory = None;
    let result: Result<(), String> = async {
        let scope = setup(&mut fixture, &peer.endpoint).await?;
        // This ACK is the actual managed recorder startup, including its native
        // attachment and encoder child. No synthetic recording ledger is seeded.
        fixture
            .command("recording.start", json!({"identityScope":scope}), 5)
            .await?;
        if browser.blobs.charged_for_test().1 != 1 {
            return Err("actual recorder reservation was not established".into());
        }
        let actions = browser
            .owner
            .lock()
            .await
            .as_ref()
            .and_then(|owner| owner.runtime.as_ref())
            .ok_or("runtime missing")?
            .actions
            .clone();
        let (encoder_status, directory) = actions.recording_encoder_status_for_test().await;
        recording_directory = Some(directory);
        // Test-only five-second request bound; no production cleanup extension.
        fixture.sequence += 1;
        let id = format!("peer-retire-{}", fixture.sequence);
        fixture
            .write(json!({"type":"request","id":id,"generation":1,
            "operationSeq":fixture.sequence,"timeoutMs":5000,
            "command":"scope.interop.retire","args":{
                "identityScope":scope,"contextId":"synthetic-context"
            }}))
            .await?;
        let sequence = fixture.sequence;
        let outcome = receive_result(&mut fixture, &id, sequence, 1).await?;
        if outcome["ok"] != false
            || outcome["effects"] != "unknown"
            || outcome["error"]["code"] != "cleanup-failed"
        {
            return Err(format!(
                "exact phase one cleanup failure was not reached: {outcome}"
            ));
        }
        if encoder_status() != (true, true) {
            return Err("the owned encoder did not actually join with success".into());
        }
        let owner = browser.owner.lock().await;
        let resource = owner.as_ref().ok_or("phase one dropped owner")?;
        let runtime = resource.runtime.as_ref().ok_or("phase one lost runtime")?;
        if runtime
            .peer_retirement
            .load(std::sync::atomic::Ordering::Acquire)
            != 1
        {
            return Err("the intended partial phase one was not reached".into());
        }
        if browser
            .startup_uncertain
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("phase one invented allocation uncertainty".into());
        }
        retired_enrollment = Some(runtime.enrollment.clone());
        Ok(())
    }
    .await;
    // Production shutdown, not dispose_context. The failed request is already
    // recorded above. A later, independently proven detach/encoder join may
    // finish physical cleanup; it cannot rewrite that earlier request result.
    let cleanup = fixture.finish().await;
    let log = peer.requests.lock().unwrap().clone();
    let outcome = retired_enrollment
        .as_ref()
        .map(|owner| owner.cleanup_outcome());
    let owner_retired = browser.owner.lock().await.is_none();
    let manager_returned = browser.retained_browser.lock().await.is_some();
    peer.task.abort();
    let _ = peer.task.await;
    result.unwrap();
    cleanup.expect("terminal shutdown must independently prove actual cleanup");
    assert!(
        owner_retired,
        "successful shutdown must retire its actual owner"
    );
    assert!(!recording_directory
        .expect("real private recording directory")
        .exists());
    assert_eq!(browser.blobs.charged_for_test(), (0, 0));
    // Exact hit: clean_stop=false in the existing strict peer rejects only
    // Page.stopScreencast here. Startup must succeed and cleanup is not replayed.
    for method in ["Page.startScreencast", "Page.stopScreencast"] {
        let hit: Vec<_> = log
            .iter()
            .filter(|request| request["method"] == method)
            .collect();
        assert_eq!(
            hit.len(),
            1,
            "missing or replayed actual recorder command {method}"
        );
        assert_eq!(hit[0]["sessionId"], "capture-1");
    }

    let disposals: Vec<_> = log
        .iter()
        .filter(|request| request["method"] == "Target.disposeBrowserContext")
        .collect();
    assert_eq!(disposals.len(), 1);
    assert_eq!(
        disposals[0]["params"],
        json!({"browserContextId":"synthetic-context"})
    );
    assert!(log
        .iter()
        .any(|request| request["method"] == "Target.setAutoAttach"
            && request["params"]
                == json!({"autoAttach":false,"waitForDebuggerOnStart":false,"flatten":true})));
    let outcome = outcome.expect("captured exact retired enrollment").unwrap();
    assert!(outcome.isolated_context_disposed && outcome.autoattach_disabled);
    assert!(
        !manager_returned,
        "a failed phase one cannot grant worker reuse"
    );
    assert!(
        !log.iter()
            .any(|request| request["method"] == "Browser.close"),
        "borrowed host process is not ours"
    );
}
