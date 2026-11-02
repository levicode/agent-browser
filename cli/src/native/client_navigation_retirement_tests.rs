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

// Task-local only: hold the already-consumed original ACK until the caller
// cancels. No production scheduling, sleep, deadline or global hook is changed.
struct OriginalResponseGate {
    selected: std::sync::Mutex<Option<oneshot::Sender<()>>>,
    release: tokio::sync::Notify,
}
tokio::task_local! {
    static ORIGINAL_RESPONSE_GATE: Arc<OriginalResponseGate>;
}
pub(super) async fn pause_after_original_response() {
    if let Ok(gate) = ORIGINAL_RESPONSE_GATE.try_with(Arc::clone) {
        if let Some(selected) = gate.selected.lock().unwrap().take() {
            let _ = selected.send(());
        }
        gate.release.notified().await;
    }
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
    WrongScope,
    ReplacedAttachment,
    PreBaselineStopped,
    LateOtherLoader,
    InputDebt,
    IntegrityLost,
}
#[derive(Clone, Copy)]
enum Cause {
    Cancel,
    Deadline,
    CancelThenLoseReceiver,
    CancelCrossDeadline,
}
// Uses the real CDP reader, journal and retained producer. Its NativeOutcome
// projection exercises the private receipt, not the full public transport.
async fn run(reply: Reply, cause: Cause) -> (bool, u32, u32) {
    run_mode(reply, cause, false).await
}
async fn run_mode(reply: Reply, cause: Cause, post_ack: bool) -> (bool, u32, u32) {
    run_scheduled(reply, cause, post_ack, false).await
}
async fn run_scheduled(reply: Reply, cause: Cause, post_ack: bool, ack_cancel_race: bool) -> (bool, u32, u32) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let (seen_tx, seen_rx) = oneshot::channel();
    let (deadline_tx, deadline_rx) = oneshot::channel::<Instant>();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut navigate = None;
        let mut seen = Some(seen_tx);
        let mut stops = 0;
        let mut cleanup_release_deadline = Some(deadline_rx);
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
                    if post_ack {
                        socket.send(Message::Text(json!({"method":"Page.frameNavigated", "sessionId":"session", "params":{"frame":{"id":"frame","loaderId":"new"}}}).to_string())).await.unwrap();
                        if matches!(reply, Reply::PreBaselineStopped) {
                            socket.send(Message::Text(json!({"method":"Page.frameStoppedLoading", "sessionId":"session", "params":{"frameId":"frame"}}).to_string())).await.unwrap();
                        }
                        let mut result = success_response();
                        if matches!(reply, Reply::WrongLoader) {
                            result["loaderId"] = json!("foreign");
                        }
                        let ack = if matches!(reply, Reply::OriginalError) {
                            json!({"id":command["id"],"sessionId":"session","error":{"code":-32000,"message":"rejected"}})
                        } else {
                            json!({"id":command["id"],"sessionId":"session","result":result})
                        };
                        socket.send(Message::Text(ack.to_string())).await.unwrap();
                    }
                    seen.take().unwrap().send(()).unwrap();
                }
                "Page.stopLoading" => {
                    stops += 1;
                    assert_eq!(stops, 1, "cancellation cannot duplicate cleanup");
                    assert_eq!(command["params"], json!({}));
                    if matches!(cause, Cause::CancelCrossDeadline) {
                        // Mock response release is tied to the actual operation
                        // deadline, not an integration sleep or widened grace.
                        let deadline = cleanup_release_deadline.take().unwrap().await.unwrap();
                        tokio::time::sleep_until(deadline.into()).await;
                    }
                    let mut result = response();
                    if matches!(reply, Reply::WrongLoader) {
                        result["loaderId"] = json!("foreign");
                    }
                    if !post_ack && !matches!(reply, Reply::MissingOriginal) {
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
                    if matches!(reply, Reply::LateOtherLoader) {
                        socket.send(Message::Text(json!({"method":"Page.frameNavigated","sessionId":"session","params":{"frame":{"id":"frame","loaderId":"foreign"}}}).to_string())).await.unwrap();
                    }
                    if !matches!(reply, Reply::MissingStopped | Reply::PreBaselineStopped) {
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
    let mut page = BrowserExecutionLease {
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
            if matches!(cause, Cause::Deadline | Cause::CancelCrossDeadline) {
                500
            } else {
                10_000
            },
        )
        .unwrap();
    let original_deadline = operation.deadline;
    deadline_tx.send(original_deadline).unwrap();
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
    let (acknowledged_tx, acknowledged_rx) = oneshot::channel();
    let (selected_tx, selected_rx) = oneshot::channel();
    let race_gate = Arc::new(OriginalResponseGate {
        selected: std::sync::Mutex::new(Some(selected_tx)),
        release: tokio::sync::Notify::new(),
    });
    let producer_gate = race_gate.clone();
    let receive = tasks
        .start_operation(
            "scope".into(),
            targets,
            broker.clone(),
            journal.clone(),
            operation.cancellation.clone(),
            async move {
                let mut receipt = None;
                let mut acknowledged = None;
                let pending = trigger(
                    &page,
                    &operation,
                    "Page.navigate",
                    json!({"url":"https://example.test/never"}),
                    "frame",
                    Some("old"),
                    &mut events,
                    Some((&owner, &mut receipt)),
                    &mut acknowledged,
                );
                let mut result = if ack_cancel_race {
                    ORIGINAL_RESPONSE_GATE.scope(producer_gate, pending).await
                } else {
                    pending.await
                };
                if post_ack && !ack_cancel_race {
                    assert!(result.is_ok(), "fixture must reach successful original ACK");
                    // This is mock-only synchronization, not a production/test API
                    // barrier or a claim that the old 100ms fixture reaches ACK.
                    let residual_input = if matches!(reply, Reply::InputDebt) {
                        Some(owner_journal.ledger().reserve_command(
                            Some(&owner_journal), "Input.dispatchMouseEvent",
                            Some(&json!({"type":"mousePressed"})), Some("session"),
                        ).unwrap().submit().unwrap())
                    } else { None };
                    let mut cancel = operation.cancellation.clone();
                    acknowledged_tx.send(()).unwrap();
                    let reason = tokio::select! {
                        _ = cancel.changed() => acknowledged_interruption_reason(ProtocolError::Cancelled, Instant::now() >= operation.deadline),
                        _ = tokio::time::sleep_until(operation.deadline.into()) => ProtocolError::DeadlineExceeded,
                    };
                    // Actual production top-check yields its original interruption;
                    // the same witness cleanup remains eligible only for that class.
                    assert!(matches!(check(&page, &operation), Err(ProtocolError::Cancelled | ProtocolError::DeadlineExceeded)));
                    if matches!(reply, Reply::IntegrityLost) {
                        owner_journal.record_cleanup_disposition(CleanupDisposition::IntegrityLost);
                    }
                    if matches!(reply, Reply::WrongScope) { page.identity_scope = "foreign".into(); }
                    if matches!(reply, Reply::ReplacedAttachment) { page.targets.detach("target").unwrap(); }
                    if let Some(witness) = acknowledged.take() {
                        receipt = witness.retire(&page, &operation, &owner, &mut events).await;
                    }
                    result = Err(reason);
                    // The ledger retains the synthetic submitted obligation;
                    // dropping this local test handle does not acknowledge it.
                    drop(residual_input);
                }
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
    if ack_cancel_race {
        tokio::time::timeout(Duration::from_secs(1), selected_rx).await.unwrap().unwrap();
    } else if post_ack {
        tokio::time::timeout(Duration::from_secs(1), acknowledged_rx)
            .await
            .unwrap()
            .unwrap();
    }
    if !matches!(cause, Cause::Deadline) {
        if matches!(cause, Cause::CancelCrossDeadline) {
            assert!(Instant::now() < original_deadline);
        }
        broker.cancel(1, 1).unwrap();
        broker.cancel(1, 1).unwrap();
    }
    if ack_cancel_race { race_gate.release.notify_one(); }
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
        // This receiver is the internal retained producer, NOT public transport.
        // These controls do not model the separate wire receipt-grace outcome.
    }
    let confirmed = tokio::time::timeout(Duration::from_secs(4), finished_rx)
        .await
        .unwrap()
        .unwrap();
    if matches!(reply, Reply::IntegrityLost) {
        assert_eq!(tasks.drain().await, Err(ProtocolError::CleanupFailed));
    } else {
        tasks.drain().await.unwrap();
    }
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

fn success_response() -> Value {
    json!({"frameId":"frame", "loaderId":"new", "isDownload":false})
}
fn acknowledged_boundary() -> AcknowledgedBoundary {
    AcknowledgedBoundary::from_ack(
        &success_response(),
        "session",
        "frame",
        Some("old"),
        "https://example.test/never".to_owned(),
        0,
    )
    .unwrap()
}
fn current_loader(loader: &str) -> CdpEvent {
    event(
        "Page.frameNavigated",
        json!({"frame":{"id":"frame", "loaderId":loader}}),
    )
}
fn started_current() -> AcknowledgedBoundary {
    let mut proof = acknowledged_boundary();
    proof.observe(1, &started());
    proof.observe(2, &current_loader("new"));
    assert!(proof.ready());
    proof
}
#[test]
fn successful_ack_is_not_an_aborted_response_and_requires_exact_fresh_identity() {
    assert!(!boundary().aborted(&success_response()));
    assert!(AcknowledgedBoundary::from_ack(
        &response(),
        "session",
        "frame",
        Some("old"),
        "https://example.test/never".into(),
        0
    )
    .is_none());
    for (field, bad) in [
        ("frameId", json!("other")),
        ("frameId", json!("")),
        ("loaderId", json!("old")),
        ("loaderId", json!("")),
        ("loaderId", Value::Null),
        ("errorText", json!("net::ERR_ABORTED")),
        ("errorText", Value::Null),
        ("isDownload", json!(true)),
        ("isDownload", json!("false")),
    ] {
        let mut ack = success_response();
        ack[field] = bad;
        assert!(
            AcknowledgedBoundary::from_ack(
                &ack,
                "session",
                "frame",
                Some("old"),
                "https://example.test/never".into(),
                0
            )
            .is_none(),
            "accepted {field}"
        );
    }
    for field in ["frameId", "loaderId"] {
        let mut ack = success_response();
        ack.as_object_mut().unwrap().remove(field);
        assert!(AcknowledgedBoundary::from_ack(
            &ack,
            "session",
            "frame",
            Some("old"),
            "https://example.test/never".into(),
            0
        )
        .is_none());
    }
}
#[test]
fn post_ack_stop_needs_current_loader_and_only_a_post_baseline_stopped_event() {
    let stopped = event("Page.frameStoppedLoading", json!({"frameId":"frame"}));
    let mut proof = acknowledged_boundary();
    assert!(
        proof.begin_stop().is_none(),
        "ACK alone is not loader witness"
    );
    proof.observe(1, &started());
    assert!(
        proof.begin_stop().is_none(),
        "start alone is not current document witness"
    );
    proof.observe(2, &current_loader("new"));
    proof.observe(3, &stopped);
    assert!(!proof.terminal());
    proof.begin_stop().unwrap();
    assert!(!proof.terminal(), "pre-baseline stop was reused");
    assert!(proof.begin_stop().is_none(), "stop authority was renewed");
    proof.observe(4, &stopped);
    assert!(proof.terminal());
    // Natural completion also proves terminal, NOT that stop caused it.
}
#[test]
fn post_ack_previous_or_replacement_loader_permanently_invalidates_witness() {
    for loader in ["old", "replacement"] {
        for method in ["Page.lifecycleEvent", "Page.frameNavigated"] {
            let mut proof = started_current();
            proof.begin_stop().unwrap();
            let update = if method == "Page.frameNavigated" {
                event(method, json!({"frame":{"id":"frame", "loaderId":loader}}))
            } else {
                event(
                    "Page.lifecycleEvent",
                    json!({"frameId":"frame", "loaderId":loader, "name":"load"}),
                )
            };
            proof.observe(3, &update);
            proof.observe(4, &current_loader("new"));
            proof.observe(
                5,
                &event("Page.frameStoppedLoading", json!({"frameId":"frame"})),
            );
            assert!(proof.invalid);
            assert!(!proof.ready());
            assert!(
                !proof.terminal(),
                "reanimated witness for {method}/{loader}"
            );
        }
    }
}
#[test]
fn post_ack_pretrigger_or_second_start_and_wrong_url_are_not_authority() {
    let mut proof = acknowledged_boundary();
    proof.trigger_sequence = 1;
    proof.observe(1, &started());
    assert!(proof.invalid);
    for field in ["url", "loaderId"] {
        let mut proof = acknowledged_boundary();
        let mut changed = started();
        changed.params[field] = json!("foreign");
        proof.observe(1, &changed);
        assert!(proof.invalid);
    }
    let mut proof = started_current();
    proof.observe(3, &started());
    assert!(proof.invalid);
}
#[test]
fn post_ack_old_events_only_before_start_and_foreign_frame_stop_never_complete() {
    let mut proof = acknowledged_boundary();
    proof.observe(1, &current_loader("old"));
    proof.observe(2, &started());
    proof.observe(3, &current_loader("new"));
    assert!(proof.ready());
    proof.begin_stop().unwrap();
    proof.observe(
        4,
        &event("Page.frameStoppedLoading", json!({"frameId":"other"})),
    );
    assert!(!proof.terminal());
    let mut foreign = event("Page.frameStoppedLoading", json!({"frameId":"frame"}));
    foreign.session_id = Some("other".into());
    proof.observe(5, &foreign);
    assert!(!proof.terminal());
    proof.observe(
        6,
        &event("Page.frameStoppedLoading", json!({"frameId":"frame"})),
    );
    assert!(proof.terminal());
}
#[test]
fn post_ack_gap_detach_same_document_and_malformed_events_fail_closed() {
    for bad in [
        event("Page.frameDetached", json!({"frameId":"frame"})),
        event("Page.navigatedWithinDocument", json!({"frameId":"frame"})),
        event("Inspector.detached", json!({})),
        event("Target.detachedFromTarget", json!({"sessionId":"session"})),
        event("Page.lifecycleEvent", json!({"frameId":"frame"})),
    ] {
        let mut proof = started_current();
        proof.begin_stop().unwrap();
        proof.observe(3, &bad);
        proof.observe(
            4,
            &event("Page.frameStoppedLoading", json!({"frameId":"frame"})),
        );
        assert!(proof.invalid);
        assert!(!proof.terminal());
    }
    let mut proof = started_current();
    proof.begin_stop().unwrap();
    proof.observe(
        4,
        &event("Page.frameStoppedLoading", json!({"frameId":"frame"})),
    );
    assert!(proof.invalid);
    assert!(!proof.terminal());
}

#[tokio::test]
async fn post_ack_exact_original_and_stop_retire_in_the_original_producer() {
    for cause in [
        Cause::Cancel,
        Cause::Deadline,
        Cause::CancelThenLoseReceiver,
        Cause::CancelCrossDeadline,
    ] {
        let (confirmed, stops, debt) = run_mode(Reply::Complete, cause, true).await;
        assert!(confirmed);
        assert_eq!(stops, 1);
        assert_eq!(debt, 0);
    }
}
#[tokio::test]
async fn post_ack_wrong_loader_or_missing_stop_proof_stays_unknown() {
    for reply in [
        Reply::WrongLoader,
        Reply::StopError,
        Reply::MissingStop,
        Reply::MissingStopped,
    ] {
        let (confirmed, stops, debt) = run_mode(reply, Cause::Cancel, true).await;
        assert!(!confirmed, "accepted {reply:?}");
        assert_eq!(
            stops,
            if matches!(reply, Reply::WrongLoader) {
                0
            } else {
                1
            }
        );
        if matches!(reply, Reply::StopError | Reply::MissingStop) {
            assert!(debt > 0);
        }
    }
}

#[tokio::test]
async fn post_ack_wrong_scope_or_detached_attachment_cannot_send_stop() {
    for reply in [Reply::WrongScope, Reply::ReplacedAttachment] {
        let (confirmed, stops, _) = run_mode(reply, Cause::Cancel, true).await;
        assert!(!confirmed);
        assert_eq!(stops, 0);
    }
}

#[test]
fn post_ack_lifecycle_alone_and_optional_flags_do_not_grant_current_authority() {
    let mut ack = success_response();
    ack.as_object_mut().unwrap().remove("isDownload");
    let mut proof = AcknowledgedBoundary::from_ack(
        &ack,
        "session",
        "frame",
        Some("old"),
        "https://example.test/never".into(),
        0,
    )
    .unwrap();
    // Omitted optional flag is not evidence of no download: the later exact
    // frame commit remains mandatory. Malformed present values were rejected.
    proof.observe(1, &started());
    proof.observe(
        2,
        &event(
            "Page.lifecycleEvent",
            json!({"frameId":"frame","loaderId":"new","name":"init"}),
        ),
    );
    assert!(!proof.ready());
    assert!(proof.begin_stop().is_none());
    proof.observe(3, &current_loader("new"));
    assert!(proof.ready());
}
#[tokio::test]
async fn post_ack_prequeued_stop_replacement_and_residual_debt_are_not_receipts() {
    for reply in [
        Reply::PreBaselineStopped,
        Reply::LateOtherLoader,
        Reply::InputDebt,
        Reply::IntegrityLost,
    ] {
        let (confirmed, stops, debt) = run_mode(reply, Cause::Cancel, true).await;
        assert!(!confirmed, "accepted {reply:?}");
        assert_eq!(
            stops,
            if matches!(reply, Reply::IntegrityLost) {
                0
            } else {
                1
            }
        );
        if matches!(reply, Reply::InputDebt) {
            assert!(debt > 0);
        }
    }
}

#[test]
fn acknowledged_interruption_reason_freezes_deadline_without_reclassifying_other_failures() {
    assert_eq!(
        acknowledged_interruption_reason(ProtocolError::Cancelled, false),
        ProtocolError::Cancelled
    );
    assert_eq!(
        acknowledged_interruption_reason(ProtocolError::Cancelled, true),
        ProtocolError::DeadlineExceeded
    );
    for error in [
        ProtocolError::DeadlineExceeded,
        ProtocolError::StaleScope,
        ProtocolError::BrowserFailure,
        ProtocolError::CleanupFailed,
    ] {
        assert_eq!(acknowledged_interruption_reason(error.clone(), true), error);
    }
}

#[tokio::test]
async fn original_ack_selected_before_cancel_keeps_the_exact_terminal_proof() {
    let (confirmed, stops, debt) = run_scheduled(Reply::Complete, Cause::Cancel, true, true).await;
    assert!(confirmed);
    assert_eq!(stops, 1);
    assert_eq!(debt, 0);
}

#[tokio::test]
async fn ack_cancel_race_still_rejects_wrong_loader_error_and_missing_terminal_events() {
    for reply in [Reply::WrongLoader, Reply::OriginalError, Reply::StopError, Reply::PreBaselineStopped, Reply::LateOtherLoader] {
        let (confirmed, stops, _) = run_scheduled(reply, Cause::Cancel, true, true).await;
        assert!(!confirmed, "accepted {reply:?}");
        assert!(stops <= 1);
    }
}
