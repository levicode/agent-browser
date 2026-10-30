//! Reader → network-task → broker → root-read boundary controls.
//! These are NOT_RUN source controls, not a reproduction of the historical run.
//! Only `child_detach_before_enrollment_keeps_root_url_usable` is EXPECTED_RED
//! on exact 2905: it asserts the desired safety property, not today's bug.
//! The test delays applying the network enrollment projection explicitly; it
//! does not claim to run the full enrollment supervisor or daemon transport.

use super::super::client_blobs::BlobLimits;
use super::super::client_browser::ExecutionGate;
use super::super::client_debt::{OperationKey, OwnerDebtLedger};
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
enum Boundary {
    ChildDetach,
    LiveChildError,
    RootDetach,
    ForeignDetachThenError,
    ReplacedTenureThenError,
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
}

async fn peer() -> Peer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let (observed, commands) = mpsc::unbounded_channel();
    let (emit, mut outgoing) = mpsc::unbounded_channel::<Value>();
    let log: Arc<Mutex<Vec<Value>>> = Arc::default();
    let captured = log.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        loop {
            tokio::select! {
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
                            || command["method"] == "Fetch.continueRequest" {
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
    control.install_debt_ledger(ledger.clone()).unwrap();
    // Match BrowserManager::bind_native_owner. A legacy client + installed
    // ledger would refuse ambient network commands before this race.
    let client = control.owner_view(ledger.clone()).unwrap();
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

async fn boundary(case: Boundary) {
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

    let mut network_outcome = None;
    let mut child_command = None;
    if !matches!(case, Boundary::RootDetach) {
        peer.emit
            .send(json!({
                "method":"Fetch.requestPaused", "sessionId":CHILD_SESSION,
                "params":{"requestId":"first-script-beacon","request":{
                    "url":"https://fixture.invalid/__pair_facts", "method":"POST", "headers":{},
                    "postData":"{\"kind\":\"popup\",\"phase\":\"first-script\"}"
                }}
            }))
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
            payload,
            decision: Some(decision),
            ..
        } = event
        else {
            panic!("expected real request decision");
        };
        assert_eq!(event, "network.request");
        assert!(payload["request"].get("postDataHandle").is_none());
        broker
            .resolve(
                1,
                &decision.token,
                Decision::Continue {
                    overrides: Default::default(),
                },
            )
            .unwrap();
        let command = next_command(&mut peer, "Fetch.continueRequest", CHILD_SESSION).await;
        assert_eq!(command["params"]["requestId"], "first-script-beacon");
        assert_eq!(peer.client.pending_len().await, 2);
        assert_eq!(peer.ledger.snapshot().outstanding_commands, 2);
        let old_tenure = {
            network.sessions.lock().unwrap()[CHILD_SESSION]
                .configuration_ready
                .subscribe()
        };
        match case {
            Boundary::ChildDetach => {
                peer.emit
                    .send(
                        json!({"method":"Target.detachedFromTarget","sessionId":ROOT_SESSION,
                    "params":{"sessionId":CHILD_SESSION,"targetId":CHILD_TARGET}}),
                    )
                    .unwrap();
                reader_marker(&mut peer, "Test.childDetachObserved").await;
                // This is the exact delayed-enrollment interval: reader already
                // destroyed child custody, but network projection is still old.
                assert!(network
                    .session_tenure_live(CHILD_SESSION, &old_tenure)
                    .unwrap());
                assert!(network.sessions.lock().unwrap().contains_key(CHILD_SESSION));
                assert_eq!(peer.ledger.snapshot().outstanding_commands, 1);
            }
            Boundary::ForeignDetachThenError => {
                peer.emit
                    .send(
                        json!({"method":"Target.detachedFromTarget","sessionId":CHILD_SESSION,
                    "params":{"sessionId":"foreign-session","targetId":"foreign-target"}}),
                    )
                    .unwrap();
                reader_marker(&mut peer, "Test.foreignDetachObserved").await;
                assert_eq!(peer.client.pending_len().await, 2);
                assert_eq!(peer.ledger.snapshot().outstanding_commands, 2);
            }
            Boundary::ReplacedTenureThenError => {
                // Textual-session replacement alone is NOT reader evidence that
                // the submitted command was destroyed. A hard Error ACK must
                // remain hard; do not broaden this into a new retirement grant.
                enroll(&network, CHILD_SESSION, CHILD_SESSION, false);
                assert!(!network
                    .session_tenure_live(CHILD_SESSION, &old_tenure)
                    .unwrap());
                assert_eq!(peer.client.pending_len().await, 2);
                assert_eq!(peer.ledger.snapshot().outstanding_commands, 2);
            }
            Boundary::LiveChildError => {}
            Boundary::RootDetach => unreachable!(),
        }
        if !matches!(case, Boundary::ChildDetach) {
            peer.emit
                .send(json!({"id":command["id"],"sessionId":CHILD_SESSION,
                "error":{"code":-32000,"message":"controlled live child failure"}}))
                .unwrap();
            reader_marker(&mut peer, "Test.childErrorObserved").await;
        }
        network_outcome = Some(join_network_task(&network).await);
        child_command = Some(command);
    } else {
        // No child callback is pending: its quarantine must not race the
        // existing exact-root detach BrowserFailure contract.
        peer.emit
            .send(
                json!({"method":"Target.detachedFromTarget","sessionId":CHILD_SESSION,
            "params":{"sessionId":ROOT_SESSION,"targetId":ROOT_TARGET}}),
            )
            .unwrap();
        reader_marker(&mut peer, "Test.rootDetachObserved").await;
        assert_eq!(peer.ledger.snapshot().outstanding_commands, 0);
    }
    // Capture actual branch consequences before any test cleanup or root ACK.
    let selected_signal = *cancellation.borrow();
    let selected_health = broker.health().unwrap();
    let root_same = root_attachment.same_attachment(&targets.owned_target(ROOT_TARGET).unwrap());
    if matches!(case, Boundary::ChildDetach) {
        network.detach_session(CHILD_SESSION).unwrap();
        targets.detach(CHILD_TARGET).unwrap();
    } else if matches!(case, Boundary::RootDetach) {
        network.detach_session(ROOT_SESSION).unwrap();
        targets.detach(ROOT_TARGET).unwrap();
        assert!(matches!(
            targets.owned_target(ROOT_TARGET),
            Err(ProtocolError::StaleReference)
        ));
    }
    // Exact late replies settle remote custody; they cannot revive abandoned
    // callers. There is never another URL command or renewed OperationLease.
    if let Some(command) = child_command {
        if matches!(case, Boundary::ChildDetach) {
            peer.emit
                .send(json!({"id":command["id"],"sessionId":CHILD_SESSION,"result":{}}))
                .unwrap();
        }
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

    match case {
        Boundary::ChildDetach => {
            // Desired regression assertion: EXPECTED_RED on exact 2905.
            assert_eq!(
                network_outcome,
                Some(Ok(())),
                "reader-proven child retirement must not poison root"
            );
            assert_eq!(selected_health, (1, ScopeState::Usable));
            assert_eq!(selected_signal, CancelSignal::None);
            assert!(root_same);
            assert_eq!(primitive, Ok(json!({"url":"https://fixture.invalid/a"})));
        }
        Boundary::RootDetach => {
            assert_eq!(selected_health, (1, ScopeState::Usable));
            assert_eq!(selected_signal, CancelSignal::None);
            assert_eq!(primitive, Err(ProtocolError::BrowserFailure));
        }
        Boundary::LiveChildError
        | Boundary::ForeignDetachThenError
        | Boundary::ReplacedTenureThenError => {
            assert_eq!(network_outcome, Some(Err(ProtocolError::BrowserFailure)));
            assert_eq!(selected_health, (1, ScopeState::Quarantined));
            assert_eq!(selected_signal, CancelSignal::SessionClosed);
            assert!(root_same);
            assert_eq!(primitive, Err(ProtocolError::Cancelled));
        }
    }
}

#[tokio::test]
async fn child_detach_before_enrollment_keeps_root_url_usable() {
    boundary(Boundary::ChildDetach).await;
}
#[tokio::test]
async fn live_child_continue_error_preserves_quarantine() {
    boundary(Boundary::LiveChildError).await;
}
#[tokio::test]
async fn exact_root_detach_preserves_browser_failure() {
    boundary(Boundary::RootDetach).await;
}
#[tokio::test]
async fn foreign_detach_cannot_excuse_child_continue_error() {
    boundary(Boundary::ForeignDetachThenError).await;
}
#[tokio::test]
async fn changed_network_tenure_cannot_excuse_hard_error_ack() {
    boundary(Boundary::ReplacedTenureThenError).await;
}
