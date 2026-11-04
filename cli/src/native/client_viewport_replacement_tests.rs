#[test]
fn replacement_viewport_selection_preserves_creation_and_dynamic_precedence() {
    use super::super::client_browser::select_scope_viewport;

    assert_eq!(
        select_scope_viewport(true, Some((1280, 720)), || Err(ProtocolError::StaleScope)),
        Err(ProtocolError::StaleScope)
    );
    let mut mismatches = Vec::new();
    for (case, seeded, creation, dynamic, expected) in [
        (
            "seeded-default",
            true,
            Some((1280, 720)),
            None,
            Some((1280, 720)),
        ),
        (
            "seeded-custom",
            true,
            Some((901, 703)),
            None,
            Some((901, 703)),
        ),
        (
            "dynamic-over-creation",
            true,
            Some((1280, 720)),
            Some((640, 480)),
            Some((640, 480)),
        ),
        (
            "borrowed-null-dynamic",
            true,
            None,
            Some((640, 480)),
            Some((640, 480)),
        ),
        ("borrowed-null-unchanged", true, None, None, None),
        (
            "unseeded-creation",
            false,
            Some((901, 703)),
            Some((640, 480)),
            Some((901, 703)),
        ),
        ("unseeded-null", false, None, Some((640, 480)), None),
    ] {
        let read = std::cell::Cell::new(false);
        let actual = select_scope_viewport(seeded, creation, || {
            assert!(
                seeded,
                "unseeded initialization must not read dynamic state"
            );
            read.set(true);
            Ok(dynamic)
        })
        .unwrap();
        assert_eq!(read.get(), seeded, "{case}");
        if actual != expected {
            mismatches.push((case, actual, expected));
        }
    }
    assert!(
        mismatches.is_empty(),
        "viewport selection mismatches: {mismatches:?}"
    );
}

async fn replacement_viewport_ack(success: bool) {
    let selected =
        super::super::client_browser::select_scope_viewport(true, Some((1280, 720)), || Ok(None))
            .unwrap();
    assert_eq!(selected, Some((1280, 720)), "use the real seeded selection");
    let f = CaptureWireFixture::with_viewport(false, selected).await;
    let session = "replacement-session";
    f.held
        .lock()
        .unwrap()
        .insert(("Emulation.setDeviceMetricsOverride".into(), session.into()));
    f.inventory
        .lock()
        .unwrap()
        .push(capture_info("replacement-page", "page"));
    f.emit
        .send(capture_attach_event("replacement-page", session, "page"))
        .await
        .unwrap();
    let metrics = f.request("Emulation.setDeviceMetricsOverride", 2).await;
    assert_eq!(metrics["sessionId"], session);
    assert_eq!(
        metrics["params"],
        json!({"width":1280,"height":720,"deviceScaleFactor":1,"mobile":false})
    );
    f.server_barrier().await;
    assert!(f
        .owner
        .index
        .lock()
        .unwrap()
        .pending_enrollment
        .contains_key(session));
    assert!(f.owner.targets.inventory().is_err());
    assert!(!f
        .requests("Runtime.runIfWaitingForDebugger")
        .iter()
        .any(|r| r["sessionId"] == session));
    let reply = if success {
        json!({"id":metrics["id"],"result":{}})
    } else {
        json!({"id":metrics["id"],"error":{"code":-32000,"message":"synthetic viewport failure"}})
    };
    f.emit.send(reply).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let settled = {
                let index = f.owner.index.lock().unwrap();
                if success {
                    !index.pending_enrollment.contains_key(session)
                } else {
                    index.failure.is_some()
                }
            };
            if settled {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let resumed = f.requests("Runtime.runIfWaitingForDebugger");
    assert_eq!(
        resumed.iter().filter(|r| r["sessionId"] == session).count(),
        usize::from(success)
    );
    assert_eq!(
        f.owner.index.lock().unwrap().failure,
        if success {
            None
        } else {
            Some(ProtocolError::BrowserFailure)
        }
    );
    if success {
        let target = f
            .owner
            .targets
            .inventory()
            .unwrap()
            .1
            .into_iter()
            .find(|t| t.session_id == session)
            .unwrap();
        assert!(target.configured && target.resumed);
    }
    f.finish().await;
}

#[tokio::test]
async fn replacement_viewport_successful_ack_is_required_before_resume() {
    replacement_viewport_ack(true).await;
}

#[tokio::test]
async fn replacement_viewport_error_ack_fails_without_resume() {
    replacement_viewport_ack(false).await;
}

#[tokio::test]
async fn replacement_viewport_null_sends_no_override() {
    let selected =
        super::super::client_browser::select_scope_viewport(true, None, || Ok(None)).unwrap();
    assert_eq!(selected, None);
    let f = CaptureWireFixture::with_viewport(false, selected).await;
    f.inventory
        .lock()
        .unwrap()
        .push(capture_info("replacement-page", "page"));
    f.attach("replacement-page", "replacement-session", "page")
        .await;
    let resume = f.request("Runtime.runIfWaitingForDebugger", 2).await;
    assert_eq!(resume["sessionId"], "replacement-session");
    assert!(f.requests("Emulation.setDeviceMetricsOverride").is_empty());
    assert!(f
        .requests("Emulation.clearDeviceMetricsOverride")
        .is_empty());
    f.finish().await;
}
