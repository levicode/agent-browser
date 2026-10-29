//! Close-receipt boundary controls, NOT complete state.capture/Enrollment tests.
//! The synthetic peer orders actual reader-delivered events and ACKs. Registry
//! detach is applied through its real API, explicitly not a second Enrollment.
use super::*;
use crate::native::client_debt::{OperationKey, OwnerDebtLedger};
use crate::native::client_protocol::{Effects, ScopeState};
use crate::native::client_session::ClientSession;
use crate::native::client_tasks::RetainedTasks;
use crate::native::client_transport::NativeOutcome;
use futures_util::{SinkExt, StreamExt};
use std::sync::Mutex;
use tokio::sync::oneshot;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloseOrder {
    AckThenDetach,
    DetachThenAck,
    DestroyedThenAck,
}

async fn close_receipt_order(order: CloseOrder) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let commands = Arc::new(Mutex::new(Vec::new()));
    let recorded = commands.clone();
    let (event_applied, applied) = oneshot::channel();
    let (stop_peer, stopped) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut applied = Some(applied);
        while let Some(Ok(message)) = socket.next().await {
            let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
            let method = request["method"].as_str().unwrap();
            recorded.lock().unwrap().push(request.clone());
            let result = match method {
                "Target.createTarget" => {
                    assert_eq!(request["params"], json!({"url":"about:blank","browserContextId":"ctx"}));
                    json!({"targetId":"temporary"})
                }
                "Target.getTargets" => json!({"targetInfos":[
                    {"targetId":"temporary","browserContextId":"ctx","type":"page"},
                    {"targetId":"foreign-host","browserContextId":"foreign-ctx","type":"page"}
                ]}),
                "Target.closeTarget" => {
                    assert_eq!(request["params"], json!({"targetId":"temporary"}));
                    assert!(request.get("sessionId").is_none(), "close is a root RPC");
                    let event = if order == CloseOrder::DestroyedThenAck {
                        json!({"method":"Target.targetDestroyed","params":{"targetId":"temporary"}})
                    } else {
                        json!({"method":"Target.detachedFromTarget","params":{"sessionId":"temporary-session","targetId":"temporary"}})
                    };
                    let ack = json!({"id":request["id"],"result":{"success":true}});
                    if order == CloseOrder::AckThenDetach {
                        // The same websocket reader processes this ACK before
                        // the following event; no sleep selects the ordering.
                        socket.send(tokio_tungstenite::tungstenite::Message::Text(ack.to_string())).await.unwrap();
                        socket.send(tokio_tungstenite::tungstenite::Message::Text(event.to_string())).await.unwrap();
                    } else {
                        socket.send(tokio_tungstenite::tungstenite::Message::Text(event.to_string())).await.unwrap();
                        // Prove real reader delivery and registry processing
                        // before allowing the close ACK onto the wire.
                        applied.take().unwrap().await.unwrap();
                        socket.send(tokio_tungstenite::tungstenite::Message::Text(ack.to_string())).await.unwrap();
                    }
                    stopped.await.unwrap();
                    socket.close(None).await.unwrap();
                    return;
                }
                other => panic!("unexpected synthetic command: {other}"),
            };
            socket.send(tokio_tungstenite::tungstenite::Message::Text(
                json!({"id":request["id"],"result":result}).to_string(),
            )).await.unwrap();
        }
        panic!("peer ended before the exact close receipt");
    });

    let transport = CdpClient::connect(&url).await.unwrap();
    let broker = Arc::new(ClientSession::new());
    // Preserve the caller's 40 s budget and production close_bootstrap's 2 s.
    let lease = broker.admit(1, 1, 40_000).unwrap();
    assert!(broker.start(1, 1).unwrap());
    let ledger = OwnerDebtLedger::new(1, "scope".into());
    ledger.bind_context("ctx").unwrap();
    ledger.bind_session("ctx", "application", "application-session").unwrap();
    transport.install_debt_ledger(ledger.clone()).unwrap();
    let client = transport.owner_view(ledger.clone()).unwrap();
    let journal = ledger.operation(
        OperationKey { generation: 1, operation_seq: 1 },
        "application".into(), "application-session".into(),
    ).unwrap();
    journal.bind_operation(&lease).unwrap();
    let observed_journal = journal.clone();
    let targets = ClientTargets::new("ctx".into(), "scope".into());
    let unrelated = ClientTargets::new("foreign-ctx".into(), "foreign-scope".into());
    let captured_targets = targets.clone();
    let captured_ledger = ledger.clone();
    let mut events = client.subscribe_methods(&["Target.detachedFromTarget", "Target.targetDestroyed"]);
    let tasks = RetainedTasks::default();
    let receiver = tasks.start_operation(
        "scope".into(), targets.clone(), broker.clone(), journal,
        lease.cancellation.clone(), async move {
            let mut reservation = captured_targets.reserve_creation(TargetPurpose::StateBootstrap).unwrap();
            let created = client.send_command("Target.createTarget",
                Some(json!({"url":"about:blank","browserContextId":"ctx"})), None,
            ).await.unwrap();
            let target = created["targetId"].as_str().unwrap();
            reservation.record_native_created_target(target).unwrap();
            // Explicit helper-boundary fixture enrollment. These are real
            // registry APIs, not a claimed run of Enrollment's event supervisor.
            reservation.acknowledge_native_created_target(&json!({
                "targetId":target,"browserContextId":"ctx","type":"page","url":"about:blank"
            })).unwrap();
            captured_targets.attached("ctx", target.into(), "temporary-session".into(), "page".into()).unwrap();
            reservation.claim(target).unwrap();
            drop(reservation);
            captured_targets.configured(target).unwrap();
            captured_targets.resume_permit(target).await.unwrap().complete().unwrap();
            captured_ledger.bind_session("ctx", target, "temporary-session").unwrap();
            let event_targets = captured_targets.clone();
            let event_ledger = captured_ledger.clone();
            let consumer = tokio::spawn(async move {
                let event = events.recv().await.unwrap();
                assert_eq!(event.params["targetId"], "temporary");
                if order != CloseOrder::AckThenDetach {
                    assert_eq!(event_targets.native_bootstrap_cleanup_targets().unwrap(), vec!["temporary"]);
                    // Root close must remain reader-owned debt. A target event
                    // is NOT a root RPC acknowledgement.
                    assert_eq!(event_ledger.snapshot().outstanding_commands, 1);
                }
                if event.method == "Target.detachedFromTarget" {
                    assert_eq!(event.params["sessionId"], "temporary-session");
                    event_targets.detach("temporary").unwrap();
                } else {
                    assert_eq!(event.method, "Target.targetDestroyed");
                    // Enrollment does not turn targetDestroyed into detach.
                }
                if order != CloseOrder::AckThenDetach {
                    assert_eq!(event_targets.native_bootstrap_cleanup_targets().unwrap(), vec!["temporary"]);
                }
                let _ = event_applied.send(());
            });
            let context = NativeStateContext {
                client: &client, context_id: "ctx", targets: &captured_targets,
                origins: &[], origins_complete: true,
            };
            // Exercise the unchanged production helper, including shared 2 s
            // inventory/close deadline and exact ACK success validation.
            let result = close_bootstrap(&context, "temporary").await;
            consumer.await.unwrap();
            assert_eq!(result, Ok(()), "{order:?}");
            assert!(captured_targets.native_bootstrap_cleanup_complete().unwrap());
            assert_eq!(captured_ledger.snapshot().outstanding_commands, 0);
            (NativeOutcome { retention: None, result: Ok(Value::Null), effects: Effects::Completed }, false)
        },
    ).await.unwrap();
    let outcome = receiver.await.unwrap();
    assert_eq!(outcome.result, Ok(Value::Null), "{order:?}");
    assert_eq!(outcome.effects, Effects::Completed, "{order:?}");
    assert!(outcome.retention.is_none());
    assert!(observed_journal.snapshot().mutation_dispatched, "actual create/close submission must not be erased");
    assert_eq!(broker.settle(1, 1, outcome.effects), Ok(ScopeState::Usable));
    assert_eq!(tasks.drain().await, Ok(()));
    assert!(targets.native_bootstrap_cleanup_complete().unwrap());
    assert!(unrelated.inventory().is_ok(), "foreign owner must remain untouched");
    let log = commands.lock().unwrap().clone();
    assert_eq!(log.iter().map(|r| r["method"].as_str().unwrap()).collect::<Vec<_>>(),
        ["Target.createTarget", "Target.getTargets", "Target.closeTarget"]);
    assert_eq!(log.iter().filter(|r| r["method"] == "Target.closeTarget").count(), 1);
    assert!(!log.iter().any(|r| r["params"]["targetId"] == "foreign-host"));
    stop_peer.send(()).unwrap();
    peer.await.unwrap();
}

#[tokio::test]
async fn state_close_receipt_ack_then_detach_keeps_exact_cleanup() {
    tokio::time::timeout(std::time::Duration::from_secs(45), close_receipt_order(CloseOrder::AckThenDetach))
        .await.expect("test-only deadlock watchdog; production 40 s/2 s unchanged");
}
#[tokio::test]
async fn state_close_receipt_detach_then_ack_keeps_root_waiter() {
    tokio::time::timeout(std::time::Duration::from_secs(45), close_receipt_order(CloseOrder::DetachThenAck))
        .await.expect("test-only deadlock watchdog; production 40 s/2 s unchanged");
}
#[tokio::test]
async fn state_close_receipt_destroyed_then_ack_is_not_synthetic_ack() {
    tokio::time::timeout(std::time::Duration::from_secs(45), close_receipt_order(CloseOrder::DestroyedThenAck))
        .await.expect("test-only deadlock watchdog; production 40 s/2 s unchanged");
}
