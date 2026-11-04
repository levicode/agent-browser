//! Fresh regression for a selected page dialog whose real ACK outlives its
//! callback task. This fixture owns only a loopback WebSocket, never a browser.
use super::super::client_protocol::ServerMessage;
use super::*;
use futures_util::{SinkExt, StreamExt};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

struct DialogFixture {
    network: Arc<ClientNetwork>,
    ledger: Arc<super::super::client_debt::OwnerDebtLedger>,
    events: tokio::sync::mpsc::Receiver<ServerMessage>,
    commands: tokio::sync::mpsc::Receiver<Value>,
    release: Option<tokio::sync::oneshot::Sender<()>>,
    acknowledged: Option<tokio::sync::oneshot::Receiver<()>>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for DialogFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl DialogFixture {
    async fn finish(&mut self) {
        self.server.abort();
        let result = (&mut self.server).await;
        assert!(result.is_ok() || result.is_err_and(|error| error.is_cancelled()));
    }
}

#[derive(Clone, Copy)]
enum Ack {
    Success,
    Error,
    WrongSession,
    Malformed,
    SuccessWithNextDialog,
}

async fn fixture(ack: Ack) -> DialogFixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (commands, received) = tokio::sync::mpsc::channel(16);
    let (release, mut release_rx) = tokio::sync::oneshot::channel();
    let (acknowledged, ack_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        let mut held: Option<Value> = None;
        let mut selected = false;
        let mut release_consumed = false;
        let mut acknowledged = Some(acknowledged);
        loop {
            tokio::select! {
                result = &mut release_rx, if held.is_some() && !release_consumed => {
                    release_consumed = true;
                    if result.is_err() { continue; }
                    let command = held.take().unwrap();
                    let mut reply = json!({"id":command["id"],"sessionId":command["sessionId"],"result":{}});
                    match ack {
                        Ack::Success | Ack::SuccessWithNextDialog => {},
                        Ack::Error => { reply.as_object_mut().unwrap().remove("result"); reply["error"] = json!({"code":-32602,"message":"synthetic dialog failure"}); },
                        Ack::WrongSession => { reply["sessionId"] = json!("foreign"); },
                        Ack::Malformed => { reply["result"] = Value::Null; },
                    }
                    if socket.send(Message::Text(reply.to_string())).await.is_err() { break; }
                    acknowledged.take().unwrap().send(()).unwrap();
                }
                message = socket.next() => {
                    let Some(Ok(Message::Text(text))) = message else { break; };
                    let command: Value = serde_json::from_str(&text).unwrap();
                    if commands.send(command.clone()).await.is_err() { break; }
                    let mut reply = json!({"id":command["id"],"result":{}});
                    if let Some(session) = command.get("sessionId") { reply["sessionId"] = session.clone(); }
                    if command["method"] == "Page.handleJavaScriptDialog" {
                        if !selected {
                            selected = true;
                            held = Some(command);
                            continue;
                        }
                        // A second terminal command is not an idempotent ACK.
                        if !matches!(ack, Ack::SuccessWithNextDialog) {
                            reply.as_object_mut().unwrap().remove("result");
                            reply["error"] = json!({"code":-32602,"message":"No dialog is showing"});
                        }
                    }
                    if socket.send(Message::Text(reply.to_string())).await.is_err() { break; }
                }
            }
        }
    });
    let client = Arc::new(
        CdpClient::connect(&format!("ws://{address}"))
            .await
            .unwrap(),
    );
    let ledger =
        super::super::client_debt::OwnerDebtLedger::new(1, "dialog-retirement-fixture".into());
    ledger.bind_context("dialog-context").unwrap();
    ledger
        .bind_session("dialog-context", "dialog-page", "owned")
        .unwrap();
    client.install_debt_ledger(ledger.clone()).unwrap();
    let client = client.owner_view(ledger.clone()).unwrap();
    let broker = Arc::new(ClientSession::new());
    let (sink, events) = ClientEventSink::test_channel(broker.clone());
    let scope = BlobScope {
        generation: 1,
        identity_scope: "dialog-retirement-fixture".into(),
    };
    let blobs =
        Arc::new(BlobStore::new(super::super::client_blobs::BlobLimits::default()).unwrap());
    blobs.activate_scope(scope.clone()).unwrap();
    let network = Arc::new(ClientNetwork::new(
        client,
        broker,
        sink,
        scope,
        blobs,
        Arc::new(super::super::client_ui::UiGate::default()),
        NetworkPolicy::default(),
    ));
    network.sessions.lock().unwrap().insert(
        "owned".into(),
        EnrolledSession {
            sink: network.future_session_sink.lock().unwrap().clone(),
            application: ApplicationSession {
                session_id: "owned".into(),
                root_page_session: "owned".into(),
                active_page: true,
            },
            configuration_ready: tokio::sync::watch::channel(true).0,
        },
    );
    DialogFixture {
        network,
        ledger,
        events,
        commands: received,
        release: Some(release),
        acknowledged: Some(ack_rx),
        server,
    }
}

async fn selected_beforeunload(fixture: &mut DialogFixture) {
    fixture
        .network
        .event(&CdpEvent {
            method: "Page.javascriptDialogOpening".into(),
            session_id: Some("owned".into()),
            params: json!({"type":"beforeunload","message":"synthetic unsaved fixture"}),
        })
        .unwrap();
    let ServerMessage::Event {
        event,
        decision: Some(decision),
        ..
    } = tokio::time::timeout(Duration::from_secs(1), fixture.events.recv())
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("expected owned beforeunload decision");
    };
    assert_eq!(event, "dialog.opened");
    fixture
        .network
        .broker
        .resolve(
            1,
            &decision.token,
            Decision::Dialog {
                accept: false,
                prompt_text: None,
            },
        )
        .unwrap();
    let command = tokio::time::timeout(Duration::from_secs(1), fixture.commands.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(command["method"], "Page.handleJavaScriptDialog");
    assert_eq!(command["sessionId"], "owned");
    assert_eq!(command["params"], json!({"accept":false}));
    assert_eq!(fixture.ledger.snapshot().outstanding_commands, 1);
    assert!(!fixture.ledger.snapshot().integrity_lost);
}

#[tokio::test]
async fn selected_beforeunload_late_success_ack_retires_without_second_dismiss() {
    let mut fixture = fixture(Ack::Success).await;
    selected_beforeunload(&mut fixture).await;
    // Match current owner teardown: callback tasks are revoked/joined first.
    fixture.network.close().await.unwrap();
    fixture.release.take().unwrap().send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), fixture.acknowledged.take().unwrap())
        .await
        .unwrap()
        .unwrap();
    // The real owner-bound response reader, not this dropped callback waiter,
    // must account for the exact command before journal retirement is tested.
    wait_ledger(&fixture, false).await;
    assert_eq!(fixture.ledger.snapshot().outstanding_commands, 0);
    let result = fixture
        .network
        .release_borrowed_interception(
            &fixture.network.scope.identity_scope,
            "owned",
            Instant::now() + Duration::from_secs(1),
        )
        .await;
    let mut commands = Vec::new();
    while let Ok(command) = fixture.commands.try_recv() {
        commands.push(command);
    }
    let pending_empty = fixture
        .network
        .pending_interceptions
        .lock()
        .unwrap()
        .is_empty();
    fixture.finish().await;
    assert_eq!(
        result,
        Ok(()),
        "a real exact late ACK must not cause a duplicate dismissal"
    );
    assert!(!commands
        .iter()
        .any(|command| command["method"] == "Page.handleJavaScriptDialog"));
    assert!(pending_empty);
}

#[tokio::test]
async fn selected_beforeunload_missing_ack_never_becomes_successful_retirement() {
    let mut fixture = fixture(Ack::Success).await;
    selected_beforeunload(&mut fixture).await;
    fixture.network.close().await.unwrap();
    let result = fixture
        .network
        .release_borrowed_interception(
            &fixture.network.scope.identity_scope,
            "owned",
            Instant::now() + Duration::from_secs(1),
        )
        .await;
    let pending_empty = fixture
        .network
        .pending_interceptions
        .lock()
        .unwrap()
        .is_empty();
    let debt = fixture.ledger.snapshot();
    let mut redispatched = false;
    while let Ok(command) = fixture.commands.try_recv() {
        redispatched |= command["method"] == "Page.handleJavaScriptDialog";
    }
    fixture.finish().await;
    assert_eq!(result, Err(ProtocolError::CleanupFailed));
    assert!(!pending_empty);
    assert!(!redispatched);
    assert_eq!(debt.outstanding_commands, 1);
    assert!(!debt.integrity_lost);
}

async fn wait_ledger(fixture: &DialogFixture, integrity_lost: bool) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let state = fixture.ledger.snapshot();
            if (integrity_lost && state.integrity_lost)
                || (!integrity_lost && state.outstanding_commands == 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn rejected_ack(ack: Ack, integrity_lost: bool) {
    let mut fixture = fixture(ack).await;
    selected_beforeunload(&mut fixture).await;
    fixture.network.close().await.unwrap();
    fixture.release.take().unwrap().send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), fixture.acknowledged.take().unwrap())
        .await
        .unwrap()
        .unwrap();
    wait_ledger(&fixture, integrity_lost).await;
    let before = fixture.ledger.snapshot();
    let result = fixture
        .network
        .release_borrowed_interception(
            &fixture.network.scope.identity_scope,
            "owned",
            Instant::now() + Duration::from_secs(1),
        )
        .await;
    let mut redispatched = false;
    while let Ok(command) = fixture.commands.try_recv() {
        redispatched |= command["method"] == "Page.handleJavaScriptDialog";
    }
    let after = fixture.ledger.snapshot();
    let pending_empty = fixture
        .network
        .pending_interceptions
        .lock()
        .unwrap()
        .is_empty();
    fixture.finish().await;
    assert_eq!(result, Err(ProtocolError::CleanupFailed));
    assert!(
        !redispatched,
        "a selected dialog command cannot be retried after callback revocation"
    );
    assert!(!pending_empty);
    assert_eq!(after.integrity_lost, before.integrity_lost);
    assert!(after.outstanding_commands >= before.outstanding_commands);
}

#[tokio::test]
async fn selected_beforeunload_error_ack_is_not_successful_retirement() {
    rejected_ack(Ack::Error, false).await;
}
#[tokio::test]
async fn selected_beforeunload_wrong_session_ack_preserves_integrity_failure() {
    rejected_ack(Ack::WrongSession, true).await;
}
#[tokio::test]
async fn selected_beforeunload_malformed_ack_preserves_integrity_failure() {
    rejected_ack(Ack::Malformed, true).await;
}

#[tokio::test]
async fn selected_beforeunload_old_ack_cannot_retire_next_dialog_on_same_session() {
    let mut fixture = fixture(Ack::SuccessWithNextDialog).await;
    selected_beforeunload(&mut fixture).await;
    // First command executed, but its ACK is held. A new modal occurrence may
    // arrive on the same attachment before that callback waiter is scheduled.
    fixture
        .network
        .event(&CdpEvent {
            method: "Page.javascriptDialogOpening".into(),
            session_id: Some("owned".into()),
            params: json!({"type":"confirm","message":"next synthetic dialog"}),
        })
        .unwrap();
    let ServerMessage::Event {
        event,
        decision: Some(_),
        ..
    } = tokio::time::timeout(Duration::from_secs(1), fixture.events.recv())
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("expected next occurrence");
    };
    assert_eq!(event, "dialog.opened");
    fixture.network.close().await.unwrap();
    fixture.release.take().unwrap().send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), fixture.acknowledged.take().unwrap())
        .await
        .unwrap()
        .unwrap();
    wait_ledger(&fixture, false).await;
    let result = fixture
        .network
        .release_borrowed_interception(
            &fixture.network.scope.identity_scope,
            "owned",
            Instant::now() + Duration::from_secs(1),
        )
        .await;
    let mut next_dismissals = 0;
    while let Ok(command) = fixture.commands.try_recv() {
        if command["method"] == "Page.handleJavaScriptDialog" {
            next_dismissals += 1;
        }
    }
    let pending_empty = fixture
        .network
        .pending_interceptions
        .lock()
        .unwrap()
        .is_empty();
    fixture.finish().await;
    assert_eq!(result, Ok(()));
    assert_eq!(
        next_dismissals, 1,
        "only the new unselected occurrence needs cleanup"
    );
    assert!(pending_empty);
}

#[tokio::test]
async fn selected_beforeunload_late_success_ack_does_not_extend_expired_cleanup_budget() {
    let mut fixture = fixture(Ack::Success).await;
    selected_beforeunload(&mut fixture).await;
    fixture.network.close().await.unwrap();
    fixture.release.take().unwrap().send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), fixture.acknowledged.take().unwrap())
        .await
        .unwrap()
        .unwrap();
    wait_ledger(&fixture, false).await;
    let result = fixture
        .network
        .release_borrowed_interception(
            &fixture.network.scope.identity_scope,
            "owned",
            Instant::now(),
        )
        .await;
    let no_commands = fixture.commands.try_recv().is_err();
    let pending_empty = fixture
        .network
        .pending_interceptions
        .lock()
        .unwrap()
        .is_empty();
    fixture.finish().await;
    assert_eq!(result, Err(ProtocolError::CleanupFailed));
    assert!(no_commands);
    assert!(!pending_empty);
}

#[tokio::test]
async fn selected_beforeunload_cleanup_wait_is_woken_by_exact_late_success_ack() {
    let mut fixture = fixture(Ack::Success).await;
    selected_beforeunload(&mut fixture).await;
    fixture.network.close().await.unwrap();
    let network = fixture.network.clone();
    let deadline = Instant::now() + Duration::from_secs(1);
    let result = {
        let releasing =
            network.release_borrowed_interception(&network.scope.identity_scope, "owned", deadline);
        tokio::pin!(releasing);
        // Poll the actual cleanup future before releasing the real wire ACK.
        // No wall-clock sleep is used as an ownership or completion witness.
        assert!(futures_util::poll!(&mut releasing).is_pending());
        assert_eq!(fixture.ledger.snapshot().outstanding_commands, 1);
        fixture.release.take().unwrap().send(()).unwrap();
        tokio::time::timeout_at(deadline.into(), releasing)
            .await
            .unwrap()
    };
    let mut redispatched = false;
    while let Ok(command) = fixture.commands.try_recv() {
        redispatched |= command["method"] == "Page.handleJavaScriptDialog";
    }
    let state = fixture.ledger.snapshot();
    let pending_empty = fixture
        .network
        .pending_interceptions
        .lock()
        .unwrap()
        .is_empty();
    fixture.finish().await;
    assert_eq!(result, Ok(()));
    assert!(!redispatched);
    assert_eq!(state.outstanding_commands, 0);
    assert!(!state.integrity_lost);
    assert!(pending_empty);
}
