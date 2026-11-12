//! Additional source-only receipt/priority controls for the isolated candidate.
//! NOT_RUN: no native, fake-CDP socket, or browser execution has occurred locally.
//! Reader frames and task-result gates order actual terminal results; no sleeps,
//! synthetic command statuses, string-error classification, or post-error rereads.
//! Root-read coverage is the real ClientPage primitive + RetainedTasks boundary,
//! not full enrollment, ClientBrowser dispatch, daemon transport, or historical cause.

use super::super::cdp::client::NetworkCommandRetirement;
use super::super::client_blobs::BlobLimits;
use super::super::client_browser::ExecutionGate;
use super::super::client_debt::{OperationKey, OwnerCleanupCommand, OwnerDebtLedger};
use super::super::client_page::ClientPageState;
use super::super::client_protocol::{Effects, ScopeState, ServerMessage};
use super::super::client_targets::ClientTargets;
use super::super::client_tasks::RetainedTasks;
use super::super::client_transport::NativeOutcome;
use super::*;
use futures_util::{SinkExt, StreamExt};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

const WAIT: Duration = Duration::from_secs(2);
const SCOPE: &str = "network-retirement-scope";
const CONTEXT: &str = "network-retirement-context";
const ROOT_TARGET: &str = "root-target";
const ROOT_SESSION: &str = "root-session";
const CHILD_TARGET: &str = "popup-target";
const CHILD_SESSION: &str = "popup-session";

#[derive(Clone, Copy, Debug)]
enum TerminalCase {
    AuthDetached,
    DialogDetached,
    HardAckThenDetached,
    HardAckThenReplaced,
    DestroyedThenReplaced,
    DestroyedThenMarkerReplaced,
}

struct Peer {
    control: Arc<CdpClient>,
    client: Arc<CdpClient>,
    ledger: Arc<OwnerDebtLedger>,
    commands: mpsc::UnboundedReceiver<Value>,
    emit: mpsc::UnboundedSender<Value>,
    log: Arc<Mutex<Vec<Value>>>,
    reader: broadcast::Receiver<CdpEvent>,
    server: tokio::task::JoinHandle<()>,
    remote_eof: Option<oneshot::Sender<()>>,
}

async fn peer() -> Peer {
    peer_with_tracking(true).await
}

async fn peer_with_tracking(tracked: bool) -> Peer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let (observed, commands) = mpsc::unbounded_channel();
    let (emit, mut outgoing) = mpsc::unbounded_channel::<Value>();
    let log: Arc<Mutex<Vec<Value>>> = Arc::default();
    let captured = log.clone();
    let (remote_eof, mut close_from_peer) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        loop {
            tokio::select! {
                _ = &mut close_from_peer => {
                    socket.close(None).await.unwrap();
                    break;
                },
                next = outgoing.recv() => match next {
                    Some(value) => socket.send(Message::Text(value.to_string())).await.unwrap(),
                    None => break,
                },
                next = socket.next() => match next {
                    Some(Ok(Message::Text(text))) => {
                        let command: Value = serde_json::from_str(&text).unwrap();
                        { captured.lock().unwrap().push(command.clone()); }
                        observed.send(command.clone()).unwrap();
                        // Only these exact business requests are held. Cleanup
                        // receipts remain serviced on the same physical peer.
                        if command["method"] == "Runtime.evaluate"
                            || matches!(command["method"].as_str(), Some("Fetch.continueRequest" | "Fetch.continueWithAuth" | "Page.handleJavaScriptDialog")) {
                            continue;
                        }
                        let mut reply = json!({"id":command["id"],"result":{}});
                        if let Some(session) = command.get("sessionId") {
                            reply["sessionId"] = session.clone();
                        }
                        socket.send(Message::Text(reply.to_string())).await.unwrap();
                    },
                    Some(Ok(Message::Ping(bytes))) => socket.send(Message::Pong(bytes)).await.unwrap(),
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {},
                    Some(Err(error)) => panic!("controlled CDP peer failed: {error}"),
                },
            }
        }
    });
    let control = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
    let ledger = OwnerDebtLedger::new(1, SCOPE.into());
    ledger.bind_context(CONTEXT).unwrap();
    ledger
        .bind_session(CONTEXT, ROOT_TARGET, ROOT_SESSION)
        .unwrap();
    ledger
        .bind_session(CONTEXT, CHILD_TARGET, CHILD_SESSION)
        .unwrap();
    let client = if tracked {
        control.install_debt_ledger(ledger.clone()).unwrap();
        control.owner_view(ledger.clone()).unwrap()
    } else {
        control.clone()
    };
    let reader = client.subscribe();
    Peer {
        control,
        client,
        ledger,
        commands,
        emit,
        log,
        reader,
        server,
        remote_eof: Some(remote_eof),
    }
}

async fn next_command(peer: &mut Peer, method: &str, session: &str) -> Value {
    let command = tokio::time::timeout(WAIT, peer.commands.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(command["method"], method);
    assert_eq!(command["sessionId"], session);
    command
}

async fn reader_marker(peer: &mut Peer, marker: &str) {
    peer.emit
        .send(json!({"method":marker,"params":{}}))
        .unwrap();
    tokio::time::timeout(WAIT, async {
        loop {
            if peer.reader.recv().await.unwrap().method == marker {
                break;
            }
        }
    })
    .await
    .unwrap();
}

fn enroll(network: &Arc<ClientNetwork>, session: &str, root: &str, active: bool) {
    let sink = { network.future_session_sink.lock().unwrap().clone() };
    let entry = EnrolledSession {
        sink,
        application: ApplicationSession {
            session_id: session.into(),
            root_page_session: root.into(),
            active_page: active,
        },
        configuration_ready: tokio::sync::watch::channel(true).0,
    };
    {
        network
            .sessions
            .lock()
            .unwrap()
            .insert(session.into(), entry);
    }
}

async fn join_network_task(network: &Arc<ClientNetwork>) -> Result<(), ProtocolError> {
    // No std MutexGuard crosses an await. All expected task producers have
    // already been submitted; taking this one-owner JoinSet does not reorder
    // its task's real result classification.
    let mut tasks = { std::mem::take(&mut *network.tasks.lock().unwrap()) };
    assert_eq!(tasks.len(), 1);
    let outcome = tokio::time::timeout(WAIT, tasks.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(tasks.is_empty());
    outcome
}

async fn close_peer(peer: Peer) {
    peer.control.close().await;
    tokio::time::timeout(WAIT, peer.server)
        .await
        .unwrap()
        .unwrap();
}

async fn detach_child(peer: &mut Peer, marker: &str) {
    peer.emit
        .send(
            json!({"method":"Target.detachedFromTarget", "sessionId":ROOT_SESSION,
        "params":{"sessionId":CHILD_SESSION,"targetId":CHILD_TARGET}}),
        )
        .unwrap();
    reader_marker(peer, marker).await;
}

fn take_result_gate(network: &Arc<ClientNetwork>) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (entered, observed) = oneshot::channel();
    let (release, resume) = oneshot::channel();
    {
        *network.task_result_gate.lock().unwrap() = Some((entered, resume));
    }
    (observed, release)
}

async fn terminal_boundary(case: TerminalCase) {
    let mut peer = peer().await;
    let broker = Arc::new(ClientSession::new());
    let (sink, mut emitted) = ClientEventSink::test_channel(broker.clone());
    let scope = BlobScope {
        generation: 1,
        identity_scope: SCOPE.into(),
    };
    let blobs = Arc::new(BlobStore::new(BlobLimits::default()).unwrap());
    blobs.activate_scope(scope.clone()).unwrap();
    let network = Arc::new(ClientNetwork::new(
        peer.client.clone(),
        broker.clone(),
        sink,
        scope,
        blobs,
        Arc::new(super::super::client_ui::UiGate::default()),
        NetworkPolicy::default(),
    ));
    enroll(&network, ROOT_SESSION, ROOT_SESSION, true);
    enroll(&network, CHILD_SESSION, CHILD_SESSION, false);
    let targets = ClientTargets::new(CONTEXT.into(), SCOPE.into());
    for (target, session) in [(ROOT_TARGET, ROOT_SESSION), (CHILD_TARGET, CHILD_SESSION)] {
        assert!(targets
            .attached(CONTEXT, target.into(), session.into(), "page".into())
            .unwrap());
        targets.configured(target).unwrap();
        targets
            .resume_permit(target)
            .await
            .unwrap()
            .complete()
            .unwrap();
    }
    targets.bind_eval_owner(&peer.ledger, 1).unwrap();
    let root_attachment = targets.owned_target(ROOT_TARGET).unwrap();
    let gate = Arc::new(ExecutionGate::default());
    let page = BrowserExecutionLease {
        client: peer.client.clone(),
        page_session_id: ROOT_SESSION.into(),
        target_id: ROOT_TARGET.into(),
        identity_scope: SCOPE.into(),
        permit: gate.enter(false).unwrap(),
        targets: targets.clone(),
    };
    let operation = broker.admit(1, 1, 5_000).unwrap();
    assert!(broker.start(1, 1).unwrap());
    let original_deadline = operation.deadline;
    let cancellation = operation.cancellation.clone();
    let journal = peer
        .ledger
        .operation(
            OperationKey {
                generation: 1,
                operation_seq: 1,
            },
            ROOT_TARGET.into(),
            ROOT_SESSION.into(),
        )
        .unwrap();
    journal.bind_operation(&operation).unwrap();
    let retained = RetainedTasks::default();
    let (result_send, result_receive) = oneshot::channel();
    let (finish_send, finish_receive) = oneshot::channel();
    let result = retained
        .start_operation(
            SCOPE.into(),
            targets.clone(),
            broker.clone(),
            journal.clone(),
            cancellation.clone(),
            async move {
                let state = ClientPageState::new(SCOPE.into(), CONTEXT.into());
                let result = state
                    .execute(&page, &[], &operation, "page.url", &json!({}))
                    .await;
                result_send.send(result.clone()).unwrap();
                // Hold local producer custody until any late exact CDP reply has
                // settled. This gate neither changes nor retries the primitive.
                finish_receive.await.unwrap();
                // This adapter covers a known-submitted, non-mutating primitive,
                // not the whole ClientBrowser dispatcher. Match its interruption
                // entry disposition (client_browser.rs:4486-4498): real retained
                // settlement must normalize Unknown + zero mutation itself.
                let effects = match &result {
                    Err(ProtocolError::Cancelled | ProtocolError::DeadlineExceeded) => {
                        Effects::Unknown
                    }
                    _ => Effects::Completed,
                };
                drop(page);
                (
                    NativeOutcome {
                        result,
                        effects,
                        retention: None,
                    },
                    false,
                )
            },
        )
        .await
        .unwrap();
    let root_request = next_command(&mut peer, "Runtime.evaluate", ROOT_SESSION).await;
    assert_eq!(root_request["params"]["expression"], "location.href");
    assert!(root_request["params"].get("userGesture").is_none());
    assert_eq!(peer.ledger.snapshot().outstanding_commands, 1);
    assert_eq!(*cancellation.borrow(), CancelSignal::None);
    assert!(!journal.snapshot().submission_revoked);

    let positive = matches!(
        case,
        TerminalCase::AuthDetached | TerminalCase::DialogDetached
    );
    let (method, notice, terminal, params, decision) = match case {
        TerminalCase::AuthDetached => (
            "Fetch.authRequired",
            "network.auth",
            "Fetch.continueWithAuth",
            json!({"requestId":"receipt-auth", "request":{"url":"https://fixture.invalid/auth"},
                "authChallenge":{"source":"Server","origin":"https://fixture.invalid","scheme":"basic","realm":"fixed"}}),
            Decision::CancelAuth {},
        ),
        TerminalCase::DialogDetached => (
            "Page.javascriptDialogOpening",
            "dialog.opened",
            "Page.handleJavaScriptDialog",
            json!({"type":"confirm","message":"fixed controlled dialog"}),
            Decision::Dialog {
                accept: false,
                prompt_text: None,
            },
        ),
        _ => (
            "Fetch.requestPaused",
            "network.request",
            "Fetch.continueRequest",
            json!({"requestId":"receipt-request","request":{"url":"https://fixture.invalid/beacon","method":"POST","headers":{},"postData":"fixed"}}),
            Decision::Continue {
                overrides: Default::default(),
            },
        ),
    };
    // This gate is consumed only after the real callback terminal result has
    // been selected, not before its CDP await or before the error ACK.
    let result_gate = if positive {
        None
    } else {
        Some(take_result_gate(&network))
    };
    peer.emit
        .send(json!({"method":method,"sessionId":CHILD_SESSION,"params":params}))
        .unwrap();
    let event = tokio::time::timeout(WAIT, peer.reader.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.method, method);
    network.event(&event).unwrap();
    let event = tokio::time::timeout(WAIT, emitted.recv())
        .await
        .unwrap()
        .unwrap();
    let ServerMessage::Event {
        event,
        decision: Some(token),
        ..
    } = event
    else {
        panic!("expected actual native callback decision");
    };
    assert_eq!(event, notice);
    broker.resolve(1, &token.token, decision).unwrap();
    let command = next_command(&mut peer, terminal, CHILD_SESSION).await;
    assert_eq!(peer.client.pending_len().await, 2);
    assert_eq!(peer.ledger.snapshot().outstanding_commands, 2);
    let (key, original_occurrence) = {
        let pending = network.pending_interceptions.lock().unwrap();
        assert_eq!(pending.len(), 1);
        let (key, occurrence) = pending.iter().next().unwrap();
        (key.clone(), occurrence.clone())
    };
    let old_tenure = {
        network.sessions.lock().unwrap()[CHILD_SESSION]
            .configuration_ready
            .subscribe()
    };
    let dialog_status = if matches!(case, TerminalCase::DialogDetached) {
        Some(network.dialog_commands.lock().unwrap()[&key].status.clone())
    } else {
        None
    };
    let mut replacement_occurrence = None;
    if positive {
        detach_child(&mut peer, "Test.receiptChildDetached").await;
        assert_eq!(peer.ledger.snapshot().outstanding_commands, 1);
        assert!(network
            .session_tenure_live(CHILD_SESSION, &old_tenure)
            .unwrap());
        // The enrollment map is intentionally still old, exactly the original
        // reader-before-network-detach interval. The task must use its receipt.
    } else {
        if matches!(
            case,
            TerminalCase::DestroyedThenReplaced | TerminalCase::DestroyedThenMarkerReplaced
        ) {
            detach_child(&mut peer, "Test.receiptCapturedBeforeReplacement").await;
        } else {
            peer.emit
                .send(json!({"id":command["id"],"sessionId":CHILD_SESSION,
                "error":{"code":-32000,"message":"fixed hard callback failure"}}))
                .unwrap();
        }
        let (entered, release) = result_gate.unwrap();
        tokio::time::timeout(WAIT, entered).await.unwrap().unwrap();
        // Reaching the gate proves the real ErrorAck/Destroyed result has already
        // been returned by the typed CDP helper. Only now apply later lifecycle.
        if !matches!(
            case,
            TerminalCase::DestroyedThenReplaced | TerminalCase::DestroyedThenMarkerReplaced
        ) {
            detach_child(&mut peer, "Test.hardAckPrecededDetach").await;
        }
        if !matches!(case, TerminalCase::DestroyedThenMarkerReplaced) {
            network.detach_session(CHILD_SESSION).unwrap();
            assert!(!network.sessions.lock().unwrap().contains_key(CHILD_SESSION));
        }
        if matches!(
            case,
            TerminalCase::HardAckThenReplaced
                | TerminalCase::DestroyedThenReplaced
                | TerminalCase::DestroyedThenMarkerReplaced
        ) {
            if !matches!(case, TerminalCase::DestroyedThenMarkerReplaced) {
                enroll(&network, CHILD_SESSION, CHILD_SESSION, false);
            }
            let replacement = Arc::new(());
            {
                network
                    .pending_interceptions
                    .lock()
                    .unwrap()
                    .insert(key.clone(), replacement.clone());
            }
            assert!(!Arc::ptr_eq(&replacement, &original_occurrence));
            assert_eq!(
                network
                    .session_tenure_live(CHILD_SESSION, &old_tenure)
                    .unwrap(),
                matches!(case, TerminalCase::DestroyedThenMarkerReplaced),
                "marker-only ABA must keep the exact original session/watch"
            );
            replacement_occurrence = Some(replacement);
        }
        release.send(()).unwrap();
    }
    let network_outcome = join_network_task(&network).await;
    let selected_signal = *cancellation.borrow();
    let selected_health = broker.health().unwrap();
    let root_same = root_attachment.same_attachment(&targets.owned_target(ROOT_TARGET).unwrap());
    if positive {
        assert!(!network
            .pending_interceptions
            .lock()
            .unwrap()
            .contains_key(&key));
        assert!(!network.dialog_commands.lock().unwrap().contains_key(&key));
        if let Some(status) = dialog_status {
            assert_eq!(
                status.snapshot(),
                super::super::client_debt::CommandStatus::Destroyed
            );
            assert!(
                status
                    .wait_successful_ack(Instant::now() + WAIT)
                    .await
                    .is_err(),
                "reader destruction is never a fabricated success ACK"
            );
        }
        network.detach_session(CHILD_SESSION).unwrap();
    } else {
        let expected = replacement_occurrence
            .as_ref()
            .unwrap_or(&original_occurrence);
        assert!(
            Arc::ptr_eq(
                &network.pending_interceptions.lock().unwrap()[&key],
                expected
            ),
            "hard failure and stale receipt cannot remove another occurrence"
        );
    }
    assert_eq!(peer.ledger.snapshot().outstanding_commands, 1);
    targets.detach(CHILD_TARGET).unwrap();
    // Reply only to the original held commands. No URL replay or lease refresh.
    if positive
        || matches!(
            case,
            TerminalCase::DestroyedThenReplaced | TerminalCase::DestroyedThenMarkerReplaced
        )
    {
        peer.emit
            .send(json!({"id":command["id"],"sessionId":CHILD_SESSION,"result":{}}))
            .unwrap();
    }
    peer.emit
        .send(json!({"id":root_request["id"],"sessionId":ROOT_SESSION,
        "result":{"result":{"type":"string","value":"https://fixture.invalid/a"}}}))
        .unwrap();
    reader_marker(&mut peer, "Test.lateRepliesObserved").await;
    let primitive = tokio::time::timeout(WAIT, result_receive)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peer.ledger.snapshot().outstanding_commands, 0);
    if selected_signal == CancelSignal::None {
        assert!(!journal.snapshot().submission_revoked);
    }
    finish_send.send(()).unwrap();
    let settled = tokio::time::timeout(WAIT, result).await.unwrap().unwrap();
    tokio::time::timeout(WAIT, retained.drain())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(settled.result, primitive);
    assert_eq!(
        settled.effects,
        if matches!(
            &primitive,
            Err(ProtocolError::Cancelled | ProtocolError::DeadlineExceeded)
        ) {
            Effects::NotDispatched
        } else {
            Effects::Completed
        }
    );
    assert!(!journal.snapshot().mutation_dispatched);
    // Both clean completion and cancellation finish their local producer;
    // finish_local_producers revokes this journal, never another operation.
    assert!(journal.snapshot().submission_revoked);
    assert!(journal.snapshot().local_producers_finished);
    assert!(!journal.snapshot().integrity_lost);
    let debt = peer.ledger.snapshot();
    assert_eq!(
        (debt.outstanding_commands, debt.input_debt, debt.object_debt),
        (0, 0, 0)
    );
    assert!(!debt.integrity_lost);
    assert!(Instant::now() < original_deadline);
    let url_count = {
        peer.log
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c["method"] == "Runtime.evaluate")
            .count()
    };
    assert_eq!(url_count, 1, "fixed URL read must never replay");
    tokio::time::timeout(WAIT, network.close())
        .await
        .unwrap()
        .unwrap();
    peer.control.close().await;
    tokio::time::timeout(WAIT, peer.server)
        .await
        .unwrap()
        .unwrap();

    if positive {
        assert_eq!(network_outcome, Ok(()));
        assert_eq!(selected_health, (1, ScopeState::Usable));
        assert_eq!(selected_signal, CancelSignal::None);
        assert!(root_same);
        assert_eq!(primitive, Ok(json!({"url":"https://fixture.invalid/a"})));
    } else {
        assert_eq!(network_outcome, Err(ProtocolError::BrowserFailure));
        assert_eq!(selected_health, (1, ScopeState::Quarantined));
        assert_eq!(selected_signal, CancelSignal::SessionClosed);
        assert!(root_same);
        assert_eq!(primitive, Err(ProtocolError::Cancelled));
    }
}

#[tokio::test]
async fn auth_child_detach_before_enrollment_preserves_root_url() {
    terminal_boundary(TerminalCase::AuthDetached).await;
}
#[tokio::test]
async fn dialog_child_detach_reuses_exact_reservation_without_success_ack() {
    terminal_boundary(TerminalCase::DialogDetached).await;
}
#[tokio::test]
async fn hard_error_ack_before_later_detach_remains_quarantine() {
    terminal_boundary(TerminalCase::HardAckThenDetached).await;
}
#[tokio::test]
async fn hard_error_ack_before_same_key_replacement_preserves_new_marker() {
    terminal_boundary(TerminalCase::HardAckThenReplaced).await;
}
#[tokio::test]
async fn captured_retirement_cannot_remove_replacement_occurrence() {
    terminal_boundary(TerminalCase::DestroyedThenReplaced).await;
}

#[tokio::test]
async fn captured_retirement_cannot_remove_marker_only_aba() {
    terminal_boundary(TerminalCase::DestroyedThenMarkerReplaced).await;
}

#[tokio::test]
async fn invalid_interception_ack_retires_the_callback_without_quarantining() {
    let mut peer = peer().await;
    let broker = Arc::new(ClientSession::new());
    let (sink, mut emitted) = ClientEventSink::test_channel(broker.clone());
    let scope = BlobScope {
        generation: 1,
        identity_scope: SCOPE.into(),
    };
    let blobs = Arc::new(BlobStore::new(BlobLimits::default()).unwrap());
    blobs.activate_scope(scope.clone()).unwrap();
    let network = Arc::new(ClientNetwork::new(
        peer.client.clone(),
        broker.clone(),
        sink,
        scope,
        blobs,
        Arc::new(super::super::client_ui::UiGate::default()),
        NetworkPolicy::default(),
    ));
    enroll(&network, CHILD_SESSION, CHILD_SESSION, false);
    let operation = broker.admit(1, 1, 5_000).unwrap();
    assert!(broker.start(1, 1).unwrap());
    let _ = operation;
    let (entered, release) = take_result_gate(&network);
    peer.emit
        .send(json!({"method":"Fetch.requestPaused","sessionId":CHILD_SESSION,
            "params":{"requestId":"gone-interception","request":{"url":"https://fixture.invalid/beacon",
            "method":"POST","headers":{},"postData":"fixed"}}}))
        .unwrap();
    let event = tokio::time::timeout(WAIT, peer.reader.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.method, "Fetch.requestPaused");
    network.event(&event).unwrap();
    let event = tokio::time::timeout(WAIT, emitted.recv())
        .await
        .unwrap()
        .unwrap();
    let ServerMessage::Event {
        event,
        decision: Some(token),
        ..
    } = event
    else {
        panic!("expected actual request callback decision");
    };
    assert_eq!(event, "network.request");
    broker
        .resolve(
            1,
            &token.token,
            Decision::Continue {
                overrides: Default::default(),
            },
        )
        .unwrap();
    let command = next_command(&mut peer, "Fetch.continueRequest", CHILD_SESSION).await;
    // The browser itself dropped the interception: its frame detached before
    // the decision reached it. No request is left paused and the scope proof
    // is intact, so the callback retires instead of quarantining everything.
    peer.emit
        .send(json!({"id":command["id"],"sessionId":CHILD_SESSION,
            "error":{"code":-32000,"message":"Invalid InterceptionId."}}))
        .unwrap();
    tokio::time::timeout(WAIT, entered).await.unwrap().unwrap();
    release.send(()).unwrap();
    let outcome = join_network_task(&network).await;
    assert_eq!(outcome, Ok(()));
    assert_eq!(broker.health().unwrap(), (1, ScopeState::Usable));
    assert!(
        network.pending_interceptions.lock().unwrap().is_empty(),
        "the gone interception's occurrence must be retired"
    );
    assert_eq!(peer.ledger.snapshot().outstanding_commands, 0);
    close_peer(peer).await;
}

#[derive(Clone, Copy, Debug)]
enum LocalFailureCase {
    ForeignSessionThenDetach,
    InvalidEnvelopeThenDetach,
    InvalidEnvelopeThenReplacement,
}

async fn malformed_terminal_boundary(case: LocalFailureCase) {
    let mut peer = peer().await;
    let broker = Arc::new(ClientSession::new());
    let (sink, mut emitted) = ClientEventSink::test_channel(broker.clone());
    let scope = BlobScope {
        generation: 1,
        identity_scope: SCOPE.into(),
    };
    let blobs = Arc::new(BlobStore::new(BlobLimits::default()).unwrap());
    blobs.activate_scope(scope.clone()).unwrap();
    let network = Arc::new(ClientNetwork::new(
        peer.client.clone(),
        broker.clone(),
        sink,
        scope,
        blobs,
        Arc::new(super::super::client_ui::UiGate::default()),
        NetworkPolicy::default(),
    ));
    enroll(&network, CHILD_SESSION, CHILD_SESSION, false);
    // This focused control observes the real broker watch but does not pretend
    // a reader-poisoned ledger can settle a healthy root-read/RetainedTasks path.
    let operation = broker.admit(1, 1, 5_000).unwrap();
    assert!(broker.start(1, 1).unwrap());
    let original_deadline = operation.deadline;
    let cancellation = operation.cancellation.clone();
    let (entered, release) = take_result_gate(&network);
    peer.emit.send(json!({"method":"Fetch.requestPaused","sessionId":CHILD_SESSION,
        "params":{"requestId":"malformed-terminal","request":{"url":"https://fixture.invalid/beacon",
        "method":"POST","headers":{},"postData":"fixed"}}})).unwrap();
    let event = tokio::time::timeout(WAIT, peer.reader.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.method, "Fetch.requestPaused");
    network.event(&event).unwrap();
    let event = tokio::time::timeout(WAIT, emitted.recv())
        .await
        .unwrap()
        .unwrap();
    let ServerMessage::Event {
        event,
        decision: Some(token),
        ..
    } = event
    else {
        panic!("expected actual request callback decision");
    };
    assert_eq!(event, "network.request");
    broker
        .resolve(
            1,
            &token.token,
            Decision::Continue {
                overrides: Default::default(),
            },
        )
        .unwrap();
    let command = next_command(&mut peer, "Fetch.continueRequest", CHILD_SESSION).await;
    assert_eq!(peer.ledger.snapshot().outstanding_commands, 1);
    let (key, original_occurrence) = {
        let pending = network.pending_interceptions.lock().unwrap();
        assert_eq!(pending.len(), 1);
        let (key, occurrence) = pending.iter().next().unwrap();
        (key.clone(), occurrence.clone())
    };
    let old_tenure = {
        network.sessions.lock().unwrap()[CHILD_SESSION]
            .configuration_ready
            .subscribe()
    };
    let reply = match case {
        LocalFailureCase::ForeignSessionThenDetach => {
            json!({"id":command["id"],"sessionId":"foreign-session","result":{}})
        }
        LocalFailureCase::InvalidEnvelopeThenDetach
        | LocalFailureCase::InvalidEnvelopeThenReplacement => {
            json!({"id":command["id"],"sessionId":CHILD_SESSION,"result":[]})
        }
    };
    assert!(
        reply.get("error").is_none(),
        "exercise the prior no-error LocalFailure projection"
    );
    peer.emit.send(reply).unwrap();
    tokio::time::timeout(WAIT, entered).await.unwrap().unwrap();
    // The actual reader removed the waiter and returned LocalFailure. Neither
    // local invalidity nor a mismatched session is a validated success ACK.
    assert_eq!(peer.client.pending_len().await, 0);
    let poisoned = peer.ledger.snapshot();
    assert!(poisoned.integrity_lost);
    assert_eq!(
        poisoned.outstanding_commands, 1,
        "invalid ACK retains exact custody"
    );
    assert_eq!(*cancellation.borrow(), CancelSignal::None);
    assert_eq!(broker.health().unwrap(), (1, ScopeState::Usable));
    // Only AFTER the typed terminal result was captured do we apply destruction
    // and remove the async network table, reproducing the old normalization gap.
    detach_child(&mut peer, "Test.detachAfterLocalFailure").await;
    network.detach_session(CHILD_SESSION).unwrap();
    assert!(!network.sessions.lock().unwrap().contains_key(CHILD_SESSION));
    let expected_occurrence = if matches!(case, LocalFailureCase::InvalidEnvelopeThenReplacement) {
        enroll(&network, CHILD_SESSION, CHILD_SESSION, false);
        assert!(!network
            .session_tenure_live(CHILD_SESSION, &old_tenure)
            .unwrap());
        let replacement = Arc::new(());
        {
            network
                .pending_interceptions
                .lock()
                .unwrap()
                .insert(key.clone(), replacement.clone());
        }
        assert!(!Arc::ptr_eq(&replacement, &original_occurrence));
        replacement
    } else {
        original_occurrence
    };
    let after_detach = peer.ledger.snapshot();
    assert_eq!(
        after_detach.outstanding_commands, 0,
        "only exact reader detach clears that command"
    );
    assert!(
        after_detach.integrity_lost,
        "later detach never repairs invalid-ACK integrity"
    );
    release.send(()).unwrap();
    let outcome = join_network_task(&network).await;
    let selected_signal = *cancellation.borrow();
    let selected_health = broker.health().unwrap();
    let marker_preserved = {
        let pending = network.pending_interceptions.lock().unwrap();
        pending
            .get(&key)
            .is_some_and(|value| Arc::ptr_eq(value, &expected_occurrence))
    };
    assert_eq!(
        peer.ledger.snapshot(),
        after_detach,
        "classification cannot clear poisoned owner state"
    );
    assert!(Instant::now() < original_deadline);
    let terminal_count = {
        peer.log
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c["method"] == "Fetch.continueRequest")
            .count()
    };
    assert_eq!(terminal_count, 1, "no terminal command replay");
    tokio::time::timeout(WAIT, network.close())
        .await
        .unwrap()
        .unwrap();
    close_peer(peer).await;
    assert_eq!(outcome, Err(ProtocolError::BrowserFailure));
    assert_eq!(selected_signal, CancelSignal::SessionClosed);
    assert_eq!(selected_health, (1, ScopeState::Quarantined));
    assert!(
        marker_preserved,
        "hard LocalFailure must not clean an occurrence or replacement marker"
    );
}

#[tokio::test]
async fn foreign_session_success_shaped_ack_before_detach_remains_hard_failure() {
    malformed_terminal_boundary(LocalFailureCase::ForeignSessionThenDetach).await;
}
#[tokio::test]
async fn invalid_envelope_ack_before_detach_remains_hard_failure() {
    malformed_terminal_boundary(LocalFailureCase::InvalidEnvelopeThenDetach).await;
}
#[tokio::test]
async fn invalid_envelope_ack_before_replacement_preserves_new_marker() {
    malformed_terminal_boundary(LocalFailureCase::InvalidEnvelopeThenReplacement).await;
}

async fn actual_retirement(peer: &mut Peer) -> NetworkCommandRetirement {
    let client = peer.client.clone();
    let work = tokio::spawn(async move {
        client
            .send_network_task_command(
                "Fetch.continueRequest",
                json!({"requestId":"receipt-only"}),
                CHILD_SESSION,
            )
            .await
    });
    let command = next_command(peer, "Fetch.continueRequest", CHILD_SESSION).await;
    assert_eq!(peer.ledger.snapshot().outstanding_commands, 1);
    detach_child(peer, "Test.directReceiptDetached").await;
    let failure = match tokio::time::timeout(WAIT, work).await.unwrap().unwrap() {
        Err(failure) => failure,
        Ok(_) => panic!("exact reader detach must not produce a success ACK"),
    };
    let receipt = failure
        .into_retirement()
        .expect("healthy exact reader destruction receipt");
    assert_eq!(peer.ledger.snapshot().outstanding_commands, 0);
    // Finish actual retained reader bookkeeping; this late ACK cannot upgrade
    // the already-captured failure into success or alter the receipt's origin.
    peer.emit
        .send(json!({"id":command["id"],"sessionId":CHILD_SESSION,"result":{}}))
        .unwrap();
    reader_marker(peer, "Test.directReceiptLateAck").await;
    assert!(!peer.ledger.snapshot().integrity_lost);
    receipt
}

#[tokio::test]
async fn retirement_receipt_requires_exact_generation_scope_and_session() {
    for (generation, scope, session, allowed) in [
        (1, SCOPE, CHILD_SESSION, true),
        (2, SCOPE, CHILD_SESSION, false),
        (1, "foreign-scope", CHILD_SESSION, false),
        (1, SCOPE, "foreign-session", false),
    ] {
        let mut peer = peer().await;
        let receipt = actual_retirement(&mut peer).await;
        let accepted = peer
            .client
            .consume_network_retirement(receipt, generation, scope, session);
        close_peer(peer).await;
        assert_eq!(accepted, allowed);
    }
}

#[tokio::test]
async fn retirement_receipt_rejects_owner_retired_after_capture() {
    let mut peer = peer().await;
    let receipt = actual_retirement(&mut peer).await;
    // Exercise the existing lifecycle-owner entry point. This control does not
    // claim to run context-destruction enrollment; it tests receipt consumption.
    peer.ledger.retire_after_context_destroy(CONTEXT).unwrap();
    let accepted = peer
        .client
        .consume_network_retirement(receipt, 1, SCOPE, CHILD_SESSION);
    close_peer(peer).await;
    assert!(!accepted);
}

#[tokio::test]
async fn retirement_receipt_rejects_foreign_owner_with_same_textual_identity() {
    let mut original = peer().await;
    let foreign = peer().await;
    assert!(!Arc::ptr_eq(&original.ledger, &foreign.ledger));
    let receipt = actual_retirement(&mut original).await;
    let accepted = foreign
        .client
        .consume_network_retirement(receipt, 1, SCOPE, CHILD_SESSION);
    close_peer(original).await;
    close_peer(foreign).await;
    assert!(!accepted);
}

#[tokio::test]
async fn retirement_receipt_rejects_same_transport_replacement_owner() {
    let mut peer = peer().await;
    let receipt = actual_retirement(&mut peer).await;
    peer.ledger.retire_after_context_destroy(CONTEXT).unwrap();
    let replacement = OwnerDebtLedger::new(2, "replacement-scope".into());
    replacement.bind_context("replacement-context").unwrap();
    replacement
        .bind_session(
            "replacement-context",
            "replacement-target",
            "replacement-session",
        )
        .unwrap();
    let replacement_before = replacement.snapshot();
    assert!(
        peer.control
            .install_debt_ledger(replacement.clone())
            .is_err(),
        "context retirement without final auto-attach ACK is not replacement readiness"
    );
    assert_eq!(replacement.snapshot(), replacement_before);
    // Use the real closed cleanup API and the peer's exact success ACK, not a
    // forged readiness flag or raw transport owner replacement.
    peer.control
        .send_owner_cleanup(
            Some(peer.ledger.clone()),
            OwnerCleanupCommand::DisableAutoAttach,
            Instant::now() + WAIT,
        )
        .await
        .unwrap();
    let cleanup = tokio::time::timeout(WAIT, peer.commands.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cleanup["method"], "Target.setAutoAttach");
    assert_eq!(
        cleanup["params"],
        json!({"autoAttach":false,"waitForDebuggerOnStart":false,"flatten":true})
    );
    assert!(cleanup.get("sessionId").is_none());
    assert!(peer.ledger.replacement_ready());
    peer.control
        .install_debt_ledger(replacement.clone())
        .unwrap();
    assert!(Arc::ptr_eq(
        &peer.control.debt_ledger().unwrap(),
        &replacement
    ));
    assert!(
        Arc::ptr_eq(&peer.client.debt_ledger().unwrap(), &peer.ledger),
        "old view remains immutably bound to the original owner"
    );
    let accepted = peer
        .client
        .consume_network_retirement(receipt, 1, SCOPE, CHILD_SESSION);
    assert_eq!(
        replacement.snapshot(),
        replacement_before,
        "stale receipt consumption must not touch replacement custody"
    );
    assert_eq!(
        replacement.bound_context().as_deref(),
        Some("replacement-context")
    );
    close_peer(peer).await;
    assert!(!accepted);
}

#[tokio::test]
async fn untracked_reader_detach_cannot_mint_network_retirement() {
    let mut peer = peer_with_tracking(false).await;
    let client = peer.client.clone();
    let work = tokio::spawn(async move {
        client
            .send_network_task_command(
                "Fetch.continueRequest",
                json!({"requestId":"untracked"}),
                CHILD_SESSION,
            )
            .await
    });
    next_command(&mut peer, "Fetch.continueRequest", CHILD_SESSION).await;
    detach_child(&mut peer, "Test.untrackedDetach").await;
    let failure = match tokio::time::timeout(WAIT, work).await.unwrap().unwrap() {
        Err(failure) => failure,
        Ok(_) => panic!("detached untracked command cannot succeed"),
    };
    assert!(failure.into_retirement().is_none());
    assert_eq!(peer.ledger.snapshot().outstanding_commands, 0);
    close_peer(peer).await;
}

#[tokio::test]
async fn remote_eof_is_not_exact_command_retirement() {
    let mut peer = peer().await;
    let client = peer.client.clone();
    let work = tokio::spawn(async move {
        client
            .send_network_task_command(
                "Fetch.continueRequest",
                json!({"requestId":"eof"}),
                CHILD_SESSION,
            )
            .await
    });
    next_command(&mut peer, "Fetch.continueRequest", CHILD_SESSION).await;
    assert_eq!(peer.ledger.snapshot().outstanding_commands, 1);
    peer.remote_eof.take().unwrap().send(()).unwrap();
    let failure = match tokio::time::timeout(WAIT, work).await.unwrap().unwrap() {
        Err(failure) => failure,
        Ok(_) => panic!("EOF cannot be a success ACK"),
    };
    assert!(failure.into_retirement().is_none());
    let debt = peer.ledger.snapshot();
    assert!(debt.integrity_lost);
    assert_eq!(
        debt.outstanding_commands, 1,
        "EOF does not forgive remote debt"
    );
    close_peer(peer).await;
}

#[tokio::test]
async fn response_deadline_before_later_detach_never_acquires_retirement() {
    let mut peer = peer().await;
    let client = peer.client.clone();
    // Already-expired absolute wait deadline deterministically reaches the real
    // CommandWaitFailure::Deadline arm after actual submission; no sleep/race.
    let deadline = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .unwrap();
    let work = tokio::spawn(async move {
        client
            .send_network_task_command_with_deadline_for_test(
                "Fetch.continueRequest",
                json!({"requestId":"deadline"}),
                CHILD_SESSION,
                deadline,
            )
            .await
    });
    let command = next_command(&mut peer, "Fetch.continueRequest", CHILD_SESSION).await;
    let failure = match tokio::time::timeout(WAIT, work).await.unwrap().unwrap() {
        Err(failure) => failure,
        Ok(_) => panic!("held reply cannot beat an expired deadline"),
    };
    assert_eq!(peer.ledger.snapshot().outstanding_commands, 1);
    detach_child(&mut peer, "Test.detachAfterDeadline").await;
    assert!(
        failure.into_retirement().is_none(),
        "later destruction cannot rewrite captured deadline"
    );
    peer.emit
        .send(json!({"id":command["id"],"sessionId":CHILD_SESSION,"result":{}}))
        .unwrap();
    reader_marker(&mut peer, "Test.deadlineLateAck").await;
    let debt = peer.ledger.snapshot();
    assert_eq!(
        (debt.outstanding_commands, debt.input_debt, debt.object_debt),
        (0, 0, 0)
    );
    assert!(!debt.integrity_lost);
    close_peer(peer).await;
}
