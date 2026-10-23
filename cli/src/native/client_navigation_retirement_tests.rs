//! Mock-CDP provenance tests, not a claim of real Chromium settlement or speed.
use super::*;
use crate::native::cdp::client::CdpClient;
use crate::native::client_browser::ExecutionGate;
use crate::native::client_debt::OwnerDebtLedger;
use crate::native::client_protocol::Effects;
use crate::native::client_session::ClientSession;
use crate::native::client_targets::ClientTargets;
use crate::native::client_transport::NativeOutcome;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;

const METHODS: &[&str] = &[
    "Page.frameStartedNavigating",
    "Page.frameStoppedLoading",
    "Page.lifecycleEvent",
    "Page.frameNavigated",
    "Page.navigatedWithinDocument",
    "Page.frameDetached",
    "Inspector.detached",
    "Target.detachedFromTarget",
];
fn boundary() -> Boundary<'static> {
    Boundary {
        session: "session",
        frame: "frame",
        previous_loader: Some("old"),
        requested_url: "https://example.test/never",
        loader: None,
        sequence: 0,
        trigger_sequence: 0,
        stopped: false,
    }
}
fn event(method: &str, params: Value) -> CdpEvent {
    CdpEvent {
        method: method.into(),
        params,
        session_id: Some("session".into()),
    }
}
fn started() -> CdpEvent {
    event(
        "Page.frameStartedNavigating",
        json!({"frameId":"frame", "loaderId":"new", "url":"https://example.test/never"}),
    )
}
fn response() -> Value {
    json!({"frameId":"frame", "loaderId":"new", "errorText":"net::ERR_ABORTED", "isDownload":false})
}
#[test]
fn aborted_response_requires_exact_started_loader_and_explicit_non_download() {
    let mut proof = boundary();
    assert!(
        !proof.aborted(&response()),
        "response alone is not a start witness"
    );
    proof.observe_event(1, &started()).unwrap();
    assert!(proof.aborted(&response()));
    for (field, bad) in [
        ("frameId", json!("other")),
        ("loaderId", json!("old")),
        ("loaderId", Value::Null),
        ("errorText", json!("net::ERR_FAILED")),
        ("errorText", Value::Null),
        ("isDownload", json!(true)),
        ("isDownload", json!("false")),
        ("isDownload", Value::Null),
    ] {
        let mut altered = response();
        altered[field] = bad;
        assert!(!proof.aborted(&altered), "accepted altered {field}");
    }
    for field in ["frameId", "loaderId", "errorText", "isDownload"] {
        let mut altered = response();
        altered.as_object_mut().unwrap().remove(field);
        assert!(!proof.aborted(&altered), "accepted omitted {field}");
    }
}
#[test]
fn subscription_sequence_and_pretrigger_events_are_not_navigation_authority() {
    let mut proof = boundary();
    proof.trigger_sequence = 1;
    assert!(
        proof.observe_event(1, &started()).is_none(),
        "queued pre-trigger start"
    );
    let mut proof = boundary();
    proof.trigger_sequence = 1;
    proof
        .observe_event(
            1,
            &event(
                "Page.lifecycleEvent",
                json!({"frameId":"frame", "loaderId":"old", "name":"load"}),
            ),
        )
        .unwrap();
    proof.observe_event(2, &started()).unwrap();
    assert!(
        proof.aborted(&response()),
        "old-loader event may precede exact new start"
    );
    assert!(
        proof
            .observe_event(
                4,
                &event("Page.frameStoppedLoading", json!({"frameId":"frame"}))
            )
            .is_none(),
        "sequence gap"
    );
    let mut proof = boundary();
    let mut foreign = started();
    foreign.session_id = Some("other".into());
    proof.observe_event(1, &foreign).unwrap();
    assert!(!proof.aborted(&response()));
    proof.observe_event(2, &started()).unwrap();
    assert!(proof
        .observe_event(
            3,
            &event(
                "Page.frameNavigated",
                json!({"frame":{"id":"frame", "loaderId":"foreign"}})
            )
        )
        .is_none());
}
#[test]
fn intervening_navigation_detach_and_malformed_events_fail_closed() {
    for changed in [
        event(
            "Page.frameStartedNavigating",
            json!({"frameId":"frame", "loaderId":"foreign", "url":"https://example.test/never"}),
        ),
        event(
            "Page.frameStartedNavigating",
            json!({"frameId":"frame", "loaderId":"new", "url":"https://example.test/other"}),
        ),
        event("Page.navigatedWithinDocument", json!({"frameId":"frame"})),
        event("Page.frameDetached", json!({"frameId":"frame"})),
        event("Inspector.detached", json!({})),
        event("Target.detachedFromTarget", json!({"sessionId":"session"})),
        event("Page.frameStoppedLoading", json!({})),
    ] {
        let mut proof = boundary();
        proof.observe_event(1, &started()).unwrap();
        assert!(
            proof.observe_event(2, &changed).is_none(),
            "accepted {}",
            changed.method
        );
    }
    let mut proof = boundary();
    proof
        .observe_event(
            1,
            &event("Page.frameStoppedLoading", json!({"frameId":"frame"})),
        )
        .unwrap();
    assert!(!proof.stopped, "old stop before start is not proof");
    proof.observe_event(2, &started()).unwrap();
    assert!(!proof.stopped);
}

#[derive(Clone, Copy, Debug)]
enum Reply {
    Complete,
    WrongLoader,
    OriginalError,
    StopError,
    MissingOriginal,
    MissingStop,
    MissingStopped,
}
#[derive(Clone, Copy)]
enum Cause {
    Cancel,
    Deadline,
    CancelThenLoseReceiver,
}
// Uses the real CDP reader, journal and retained producer. Its NativeOutcome
// projection exercises the private receipt, not the full public transport.
async fn run(reply: Reply, cause: Cause) -> (bool, u32, u32) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let (seen_tx, seen_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut navigate = None;
        let mut seen = Some(seen_tx);
        let mut stops = 0;
        while let Some(Ok(message)) = socket.next().await {
            let Message::Text(text) = message else {
                continue;
            };
            let command: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(command["sessionId"], "session");
            match command["method"].as_str().unwrap() {
                "Page.navigate" => {
                    assert!(navigate.replace(command["id"].clone()).is_none());
                    socket.send(Message::Text(json!({"method":"Page.frameStartedNavigating", "sessionId":"session", "params":started().params}).to_string())).await.unwrap();
                    seen.take().unwrap().send(()).unwrap();
                }
                "Page.stopLoading" => {
                    stops += 1;
                    assert_eq!(stops, 1, "cancellation cannot duplicate cleanup");
                    assert_eq!(command["params"], json!({}));
                    let mut result = response();
                    if matches!(reply, Reply::WrongLoader) {
                        result["loaderId"] = json!("foreign");
                    }
                    if !matches!(reply, Reply::MissingOriginal) {
                        let original = if matches!(reply, Reply::OriginalError) {
                            json!({"id":navigate.as_ref().unwrap(), "sessionId":"session", "error":{"code":-32000,"message":"rejected"}})
                        } else {
                            json!({"id":navigate.as_ref().unwrap(), "sessionId":"session", "result":result})
                        };
                        socket
                            .send(Message::Text(original.to_string()))
                            .await
                            .unwrap();
                    }
                    if !matches!(reply, Reply::MissingStopped) {
                        socket.send(Message::Text(json!({"method":"Page.frameStoppedLoading", "sessionId":"session", "params":{"frameId":"frame"}}).to_string())).await.unwrap();
                    }
                    if !matches!(reply, Reply::MissingStop) {
                        let stop = if matches!(reply, Reply::StopError) {
                            json!({"id":command["id"], "sessionId":"session", "error":{"code":-32000,"message":"rejected"}})
                        } else {
                            json!({"id":command["id"], "sessionId":"session", "result":{}})
                        };
                        socket.send(Message::Text(stop.to_string())).await.unwrap();
                    }
                }
                method => panic!("unexpected command {method}"),
            }
        }
        stops
    });
    let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
    let ledger = OwnerDebtLedger::new(1, "scope".into());
    client.install_debt_ledger(ledger.clone()).unwrap();
    let targets = ClientTargets::new("context".into(), "scope".into());
    targets
        .attached("context", "target".into(), "session".into(), "page".into())
        .unwrap();
    targets.configured("target").unwrap();
    targets
        .resume_permit("target")
        .await
        .unwrap()
        .complete()
        .unwrap();
    targets.acknowledge_enrollment().unwrap();
    let gate = Arc::new(ExecutionGate::default());
    let page = BrowserExecutionLease {
        client: client.clone(),
        page_session_id: "session".into(),
        target_id: "target".into(),
        identity_scope: "scope".into(),
        permit: gate.enter(false).unwrap(),
        targets: targets.clone(),
    };
    let broker = Arc::new(ClientSession::new());
    let operation = broker
        .admit(
            1,
            1,
            if matches!(cause, Cause::Deadline) {
                500
            } else {
                10_000
            },
        )
        .unwrap();
    assert!(broker.start(1, 1).unwrap());
    let journal = ledger
        .operation(
            OperationKey {
                generation: 1,
                operation_seq: 1,
            },
            "target".into(),
            "session".into(),
        )
        .unwrap();
    journal.bind_operation(&operation).unwrap();
    let tasks = Arc::new(RetainedTasks::default());
    let mut events = client
        .subscribe_bounded_methods(METHODS, 256, 65536)
        .unwrap();
    let watermark = events.watermark();
    let owner = tasks.clone();
    let owner_journal = journal.clone();
    let (finished_tx, finished_rx) = oneshot::channel();
    let receive = tasks
        .start_operation(
            "scope".into(),
            targets,
            broker.clone(),
            journal.clone(),
            operation.cancellation.clone(),
            async move {
                let mut receipt = None;
                let result = trigger(
                    &page,
                    &operation,
                    "Page.navigate",
                    json!({"url":"https://example.test/never"}),
                    "frame",
                    Some("old"),
                    &mut events,
                    Some((&owner, &mut receipt)),
                )
                .await;
                let confirmed =
                    receipt.is_some_and(|proof| proof.confirms(&page, &operation, &owner_journal));
                let expected = if matches!(cause, Cause::Deadline) {
                    ProtocolError::DeadlineExceeded
                } else {
                    ProtocolError::Cancelled
                };
                assert_eq!(result, Err(expected));
                let _ = finished_tx.send(confirmed);
                (
                    NativeOutcome {
                        result,
                        effects: if confirmed {
                            Effects::Completed
                        } else {
                            Effects::Unknown
                        },
                        retention: None,
                    },
                    false,
                )
            },
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), seen_rx)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_millis(250), async {
        while watermark.received().unwrap() < 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    if !matches!(cause, Cause::Deadline) {
        broker.cancel(1, 1).unwrap();
        broker.cancel(1, 1).unwrap();
    }
    if matches!(cause, Cause::CancelThenLoseReceiver) {
        drop(receive);
    } else {
        let outcome = tokio::time::timeout(Duration::from_secs(4), receive)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            outcome.effects,
            if matches!(reply, Reply::Complete) {
                Effects::Completed
            } else {
                Effects::Unknown
            }
        );
    }
    let confirmed = tokio::time::timeout(Duration::from_secs(4), finished_rx)
        .await
        .unwrap()
        .unwrap();
    tasks.drain().await.unwrap();
    let debt = journal.snapshot().input_debt;
    client.close().await;
    let stops = tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
    (confirmed, stops, debt)
}
#[tokio::test]
async fn exact_abort_and_stop_proof_preserves_both_original_interruption_causes() {
    for cause in [
        Cause::Cancel,
        Cause::Deadline,
        Cause::CancelThenLoseReceiver,
    ] {
        let (confirmed, stops, debt) = run(Reply::Complete, cause).await;
        assert!(confirmed);
        assert_eq!(stops, 1);
        assert_eq!(debt, 0);
    }
}
#[tokio::test]
async fn stop_ack_alone_wrong_loader_or_rejected_command_never_mints_receipt() {
    for reply in [
        Reply::WrongLoader,
        Reply::OriginalError,
        Reply::StopError,
        Reply::MissingOriginal,
        Reply::MissingStop,
        Reply::MissingStopped,
    ] {
        let (confirmed, stops, debt) = run(reply, Cause::Cancel).await;
        assert!(!confirmed, "accepted {reply:?}");
        assert_eq!(stops, 1);
        if matches!(
            reply,
            Reply::OriginalError | Reply::StopError | Reply::MissingOriginal | Reply::MissingStop
        ) {
            assert!(debt > 0, "forgot unresolved command for {reply:?}");
        }
    }
}
