//! P19 uses the real generic dispatcher, operation journal, framed result writer,
//! and a finite native peer. No replacement executor supplies the result/error.
use super::*;

async fn title_interruption_case(explicit_cancel: bool) {
    let (seen, mut requests) = tokio::sync::mpsc::unbounded_channel();
    let (endpoint, log, peer) = peer_with_title(false, None, false, None, Some(seen)).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture = framed(browser, broker, Arc::new(RestartFlush::default()));
    fixture.ready().await.unwrap();
    let opened = fixture
        .command(
            "scope.open",
            fixture_scope_open("connect", Some(&endpoint)),
            5,
        )
        .await
        .unwrap();
    let scope = opened["identityScope"].as_str().unwrap().to_owned();
    fixture.scope = Some(scope.clone());
    fixture
        .command("scope.configure", fixture_configuration(&scope, None), 5)
        .await
        .unwrap();
    fixture
        .command("network.routes.replace", fixture_routes(&scope), 5)
        .await
        .unwrap();
    fixture.registry = 1;
    fixture
        .command("page.activate", json!({"identityScope":scope}), 5)
        .await
        .unwrap();

    let before = log.lock().unwrap().len();
    fixture.sequence += 1;
    let sequence = fixture.sequence;
    fixture
        .write(json!({"type":"request","id":"title","generation":1,
            "operationSeq":sequence,"timeoutMs":if explicit_cancel { 5000 } else { 1000 },
            "command":"page.title","args":{"identityScope":scope}}))
        .await
        .unwrap();
    let request = tokio::time::timeout(Duration::from_secs(2), requests.recv())
        .await
        .expect("title must reach the real native transport")
        .unwrap();
    assert_eq!(request["method"], "Runtime.evaluate");
    assert_eq!(request["params"]["expression"], "document.title");
    if explicit_cancel {
        // Native submission, not a sleep, orders the explicit user cancellation.
        fixture
            .write(json!({"type":"cancel","id":"cancel-title","generation":1,
                "operationSeq":sequence}))
            .await
            .unwrap();
    }
    let mut result = None;
    let mut cancel_ack = false;
    for _ in 0..8 {
        let frame = tokio::time::timeout(Duration::from_secs(3), fixture.read())
            .await
            .expect("native interruption must settle")
            .unwrap();
        assert_eq!(frame["generation"], 1);
        match frame["type"].as_str() {
            Some("control-result") => {
                assert!(explicit_cancel && !cancel_ack);
                assert_eq!(frame["id"], "cancel-title");
                assert_eq!(frame["accepted"], true);
                assert_eq!(frame["scopeState"], "usable");
                cancel_ack = true;
            }
            Some("result") => {
                assert!(result.is_none());
                assert_eq!(frame["id"], "title");
                assert_eq!(frame["operationSeq"], sequence);
                result = Some(frame);
            }
            Some("event") => {
                assert_eq!(frame["sequence"], fixture.event_sequence + 1);
                fixture.event_sequence += 1;
                validate_fixture_notice(&frame).unwrap();
            }
            _ => panic!("unexpected interruption frame: {frame}"),
        }
        if result.is_some() && (!explicit_cancel || cancel_ack) {
            break;
        }
    }
    let result = result.expect("one correlated title result");
    assert_eq!(result["ok"], false);
    assert_eq!(result["effects"], "not-dispatched");
    assert_eq!(result["scopeState"], "usable");
    assert_eq!(
        result["error"]["code"],
        if explicit_cancel {
            "cancelled"
        } else {
            "deadline-exceeded"
        }
    );
    assert_eq!(cancel_ack, explicit_cancel);
    {
        let log = log.lock().unwrap();
        let sent = &log[before..];
        assert_eq!(
            sent.iter()
                .filter(|r| r["method"] == "Runtime.evaluate"
                    && r["params"]["expression"] == "document.title")
                .count(),
            1
        );
        assert!(sent
            .iter()
            .all(|r| !r["method"].as_str().unwrap().starts_with("Input.")));
    }
    // The existing journal/effects path must still prove safe reuse, not just
    // produce the desired error code or quarantine the otherwise healthy scope.
    let fresh = fixture
        .command("page.url", json!({"identityScope":scope}), 5)
        .await
        .unwrap();
    assert_eq!(fresh["url"], "https://synthetic.test/after-restart");
    fixture
        .command("scope.end", json!({"identityScope":scope}), 5)
        .await
        .unwrap();
    let cleanup = fixture.finish().await;
    peer.abort();
    cleanup.unwrap();
}

#[tokio::test]
async fn generic_title_deadline_is_not_relabelled_as_user_cancellation() {
    title_interruption_case(false).await;
}

#[tokio::test]
async fn generic_title_user_cancellation_is_not_relabelled_as_deadline() {
    title_interruption_case(true).await;
}
