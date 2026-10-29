//! Real managed-CDP controls at the world/resolve submission boundary.
use super::resolve_custody::{install_resolve_hook, ResolveHookPoint};
use super::*;
use crate::native::client_debt::{AdmissionClass, OperationKey, OwnerDebtLedger};
use futures_util::{SinkExt, StreamExt};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Copy)]
enum Stop {
    BeforeReservation,
    DeadlineBeforeReservation,
    AfterReservation,
    AdmissionRevoked,
    MixedAcknowledgedAndAbandoned,
    None,
}
fn selected_frame() -> ObservationFrame {
    ObservationFrame {
        parent_frame_id: None,
        owner_backend_id: None,
        url: "https://fixture.invalid".into(),
        binding: ExactBinding {
            page_session: "renderer".into(),
            session: "renderer".into(),
            frame: "main".into(),
            loader: "doc".into(),
            actionable: false,
        },
        offset_x: 0.0,
        offset_y: 0.0,
        frame_path: vec![],
    }
}
async fn boundary_case(stop: Stop) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::<Value>::new()));
    let seen = log.clone();
    let (held_tx, mut held_rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let mixed = matches!(stop, Stop::MixedAcknowledgedAndAbandoned);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        loop {
            tokio::select! {
                Some(reply) = reply_rx.recv() => {
                    socket.send(tokio_tungstenite::tungstenite::Message::Text(reply.to_string())).await.unwrap();
                }
                message = socket.next() => {
                    let Some(Ok(message)) = message else { break; };
                    let text = match message {
                        Message::Text(text) => text,
                        Message::Close(_) => break,
                        Message::Ping(payload) => {
                            socket.send(Message::Pong(payload)).await.unwrap();
                            continue;
                        }
                        Message::Pong(_) => continue,
                        Message::Binary(_) | Message::Frame(_) => {
                            panic!("unexpected non-text CDP frame in resolve-boundary peer")
                        }
                    };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    assert_eq!(request["sessionId"], "renderer");
                    seen.lock().unwrap().push(request.clone());
                    let result = match request["method"].as_str().unwrap() {
                        "Page.getFrameTree" => json!({"frameTree":{"frame":{"id":"main","loaderId":"doc"}}}),
                        "DOM.getDocument" => if mixed {
                            json!({"root":{"nodeType":9,"backendNodeId":99,"children":[{"nodeType":1,"backendNodeId":100,"children":[],"shadowRoots":[{"nodeType":11,"backendNodeId":11,"shadowRootType":"closed","children":[]}]}]}})
                        } else { json!({"root":{"nodeType":9,"backendNodeId":99,"children":[]}}) },
                        "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                        "DOM.resolveNode" | "Runtime.releaseObjectGroup" => {
                            held_tx.send(request).unwrap();
                            continue;
                        }
                        "Runtime.callFunctionOn" if matches!(stop, Stop::None) => {
                            assert_eq!(request["params"]["returnByValue"], true);
                            json!({"result":{"value":{"values":[]}}})
                        }
                        other => panic!("unexpected resolve-boundary command: {other}"),
                    };
                    socket.send(tokio_tungstenite::tungstenite::Message::Text(json!({"id":request["id"],"sessionId":"renderer","result":result}).to_string())).await.unwrap();
                }
            }
        }
    });
    let transport = CdpClient::connect(&endpoint).await.unwrap();
    let ledger = OwnerDebtLedger::new(1, "pre-resolve-owner".into());
    transport.install_debt_ledger(ledger.clone()).unwrap();
    let client = transport.owner_view(ledger.clone()).unwrap();
    let (cancellation, receiver) = tokio::sync::watch::channel(CancelSignal::None);
    let operation = OperationLease {
        is_callback: false,
        generation: 1,
        sequence: 1,
        deadline: std::time::Instant::now()
            + if matches!(stop, Stop::DeadlineBeforeReservation) {
                Duration::from_millis(200)
            } else {
                Duration::from_secs(5)
            },
        cancellation: receiver,
    };
    let journal = ledger
        .operation(
            OperationKey {
                generation: 1,
                operation_seq: 1,
            },
            "target".into(),
            "renderer".into(),
        )
        .unwrap();
    journal.bind_operation(&operation).unwrap();
    ledger.check_admission(AdmissionClass::Reference).unwrap();
    let point = if matches!(
        stop,
        Stop::AfterReservation | Stop::AdmissionRevoked | Stop::MixedAcknowledgedAndAbandoned
    ) {
        ResolveHookPoint::AfterReservation
    } else {
        ResolveHookPoint::BeforeReservation
    };
    let backend = if mixed { 11 } else { 99 };
    let (guard, entered, release) = journal
        .scope(async { install_resolve_hook(&client, "renderer", &operation, backend, point) })
        .await;
    let original_deadline = operation.deadline;
    let read_journal = journal.clone();
    let read = tokio::spawn(async move {
        let query: LocatorExpression = serde_json::from_value(json!({"kind":"query","query":{"kind":"testId","value":{"kind":"string","value":"city","exact":true}}})).unwrap();
        read_journal
            .scope(fields(
                &client,
                &selected_frame(),
                &query,
                &QueryOptions {
                    expression: query.clone(),
                    test_id_attribute: default_test_id(),
                    secure_field_selector: default_secure_selector(),
                },
                &[ReadField::Value],
                &operation,
            ))
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), entered)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .filter(|r| r["method"] == "Page.createIsolatedWorld")
            .count(),
        1,
        "hook follows an actual world ACK"
    );
    let mut real_group = None;
    if mixed {
        let resolve = tokio::time::timeout(Duration::from_secs(1), held_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolve["method"], "DOM.resolveNode");
        assert_eq!(resolve["params"]["backendNodeId"], 99);
        real_group = Some(
            resolve["params"]["objectGroup"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
        reply_tx.send(json!({"id":resolve["id"],"sessionId":"renderer","result":{"object":{"objectId":"acknowledged-root","subtype":"node"}}})).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while ledger.snapshot().outstanding_commands != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(ledger.snapshot().object_debt, 1);
    } else {
        assert!(
            held_rx.try_recv().is_err(),
            "no resolve was submitted before the gate"
        );
        let reserved = matches!(stop, Stop::AfterReservation | Stop::AdmissionRevoked);
        assert_eq!(ledger.snapshot().outstanding_commands, u32::from(reserved));
        assert_eq!(ledger.snapshot().object_debt, u32::from(reserved));
    }
    if matches!(stop, Stop::AdmissionRevoked) {
        // Actual native journal admission refusal after reservation, without a
        // cancellation select race or a fabricated quota/transport response.
        journal.revoke_application_submission();
    } else if matches!(stop, Stop::DeadlineBeforeReservation) {
        tokio::time::sleep_until(original_deadline.into()).await;
    } else if !matches!(stop, Stop::None) {
        cancellation.send_replace(CancelSignal::Requested);
    }
    let released = release.send(());
    if !matches!(
        stop,
        Stop::AfterReservation | Stop::MixedAcknowledgedAndAbandoned
    ) {
        released.unwrap();
    }
    // For watch cancellation after reservation, the original select may have
    // already dropped its gated send future. Receiver drop is expected custody
    // transfer to the reservation destructor, not a skipped assertion of debt.
    if matches!(stop, Stop::None) {
        let resolve = tokio::time::timeout(Duration::from_secs(1), held_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolve["method"], "DOM.resolveNode");
        real_group = Some(
            resolve["params"]["objectGroup"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
        reply_tx.send(json!({"id":resolve["id"],"sessionId":"renderer","result":{"object":{"objectId":"positive-root","subtype":"node"}}})).unwrap();
    }
    let result = tokio::time::timeout(Duration::from_secs(1), read)
        .await
        .unwrap()
        .unwrap();
    match stop {
        Stop::BeforeReservation => assert_eq!(result, Err(ObservationError::Cancelled)),
        Stop::DeadlineBeforeReservation => {
            assert_eq!(result, Err(ObservationError::DeadlineExceeded))
        }
        Stop::AdmissionRevoked => assert_eq!(result, Err(ObservationError::BackendFailure)),
        Stop::AfterReservation | Stop::MixedAcknowledgedAndAbandoned => {
            // Preserve ordinary select/admission race classification: both are
            // existing primary errors, neither is cleanup failure or success.
            assert!(matches!(
                result,
                Err(ObservationError::Cancelled | ObservationError::BackendFailure)
            ));
        }
        Stop::None => assert_eq!(result, Ok(Some(Vec::new()))),
    }
    let should_release = mixed || matches!(stop, Stop::None);
    if should_release {
        let release = tokio::time::timeout(Duration::from_secs(1), held_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(release["method"], "Runtime.releaseObjectGroup");
        assert_eq!(release["sessionId"], "renderer");
        assert_eq!(release["params"]["objectGroup"], real_group.unwrap());
        assert_eq!(
            ledger.snapshot().object_debt,
            1,
            "one real creator prevents the skip"
        );
        reply_tx
            .send(json!({"id":release["id"],"sessionId":"renderer","result":{}}))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while ledger.snapshot().outstanding_commands != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    } else {
        assert!(
            held_rx.try_recv().is_err(),
            "proven no submission must not mint empty release debt"
        );
    }
    assert_eq!(
        (
            ledger.snapshot().object_debt,
            ledger.snapshot().input_debt,
            ledger.snapshot().outstanding_commands
        ),
        (0, 0, 0)
    );
    assert!(!ledger.snapshot().integrity_lost);
    assert!(!journal.snapshot().mutation_dispatched);
    {
        let methods = log.lock().unwrap();
        assert_eq!(
            methods
                .iter()
                .filter(|r| r["method"] == "DOM.resolveNode")
                .count(),
            usize::from(should_release)
        );
        assert_eq!(
            methods
                .iter()
                .filter(|r| r["method"] == "Runtime.releaseObjectGroup")
                .count(),
            usize::from(should_release)
        );
        assert_eq!(
            methods
                .iter()
                .filter(|r| r["method"] == "Runtime.callFunctionOn")
                .count(),
            usize::from(matches!(stop, Stop::None))
        );
        assert!(!methods
            .iter()
            .any(|r| r["method"].as_str().unwrap().starts_with("Input.")));
    }
    drop(guard);
    transport.close().await;
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
}
#[tokio::test]
async fn stopped_after_world_before_reservation_does_not_enqueue_empty_cleanup() {
    boundary_case(Stop::BeforeReservation).await;
}
#[tokio::test]
async fn abandoned_resolve_reservation_does_not_enqueue_empty_cleanup() {
    boundary_case(Stop::AfterReservation).await;
}
#[tokio::test]
async fn mixed_acknowledged_and_abandoned_resolves_keep_exact_cleanup() {
    boundary_case(Stop::MixedAcknowledgedAndAbandoned).await;
}
#[tokio::test]
async fn unchanged_resolve_and_sample_keep_exact_cleanup_until_ack() {
    boundary_case(Stop::None).await;
}

#[tokio::test]
async fn revoked_submission_after_reservation_preserves_primary_without_empty_cleanup() {
    boundary_case(Stop::AdmissionRevoked).await;
}

#[tokio::test]
async fn original_deadline_after_world_before_reservation_has_no_empty_cleanup() {
    boundary_case(Stop::DeadlineBeforeReservation).await;
}
