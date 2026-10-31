//! Layered ordinary owner retirement controls. No browser/CDP methods or page
//! initialization: an empty live WebSocket supplies only transport lifetime.
//! Exercises real prepare -> close worker -> Finished check -> owner finish ->
//! existing scope event gate. Does not model the enrollment supervisor itself.
use super::*;
use crate::native::client_blobs::BlobLimits;
use crate::native::client_browser::ExecutionGate;
use crate::native::client_enrollment::{ClientEnrollment, ScopeConfig, ScopeOwnership};
use crate::native::client_page::ClientPageState;
use crate::native::client_protocol::{Effects, ScopeState, ServerMessage};
use crate::native::client_targets::ClientTargets;
use futures_util::StreamExt;
use std::time::Duration;

struct Chain {
    client: Arc<CdpClient>,
    broker: Arc<ClientSession>,
    network: Arc<ClientNetwork>,
    owner: Arc<ClientEnrollment>,
    operation: OperationLease,
    global: ClientEventSink,
    events: Option<tokio::sync::mpsc::Receiver<ServerMessage>>,
    server: tokio::task::JoinHandle<()>,
}
impl Chain {
    async fn new() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(message) = ws.next().await {
                match message {
                    Ok(tokio_tungstenite::tungstenite::Message::Close(_)) | Err(_) => break,
                    // This chain is deliberately not a CDP responder. An
                    // accidental method call must fail, not get invented data.
                    Ok(tokio_tungstenite::tungstenite::Message::Text(_)) => {
                        panic!("unexpected CDP command")
                    }
                    _ => {}
                }
            }
        });
        let client = Arc::new(
            CdpClient::connect(&format!("ws://{address}"))
                .await
                .unwrap(),
        );
        let broker = Arc::new(ClientSession::new());
        let (global, events) = ClientEventSink::test_channel(broker.clone());
        let open = broker.admit(1, 1, 5000).unwrap();
        let scoped = global.stage_until_result(&open, "scope").unwrap();
        global
            .acknowledge_result_for_test(&ServerMessage::Result {
                id: "open".into(),
                generation: 1,
                operation_seq: 1,
                ok: true,
                data: Some(json!({"identityScope":"scope"})),
                error: None,
                effects: Effects::Completed,
                retention: None,
                recovery: None,
                scope_state: ScopeState::Usable,
            })
            .unwrap();
        let network = Arc::new(ClientNetwork::new(
            client.clone(),
            broker.clone(),
            scoped,
            BlobScope {
                generation: 1,
                identity_scope: "scope".into(),
            },
            Arc::new(BlobStore::new(BlobLimits::default()).unwrap()),
            Arc::new(super::super::client_ui::UiGate::default()),
            NetworkPolicy::default(),
        ));
        let owner = Self::owner(&client, &network);
        let operation = broker.admit(1, 2, 5000).unwrap();
        Self {
            client,
            broker,
            network,
            owner,
            operation,
            global,
            events: Some(events),
            server,
        }
    }
    fn owner(client: &Arc<CdpClient>, network: &Arc<ClientNetwork>) -> Arc<ClientEnrollment> {
        ClientEnrollment::new(
            client.clone(),
            ClientTargets::new("context".into(), "scope".into()),
            Arc::new(ClientPageState::new("scope".into(), "context".into())),
            network.clone(),
            Arc::new(ExecutionGate::default()),
            1,
            "unused-root".into(),
            ScopeConfig::default(),
            ScopeOwnership::IsolatedContext,
            None,
        )
    }
    async fn drain(&self) -> Result<(), ProtocolError> {
        self.owner.seal();
        let closed = self.network.close().await;
        self.owner.drain().await.unwrap();
        closed
    }
    async fn done(self) {
        self.client.close().await;
        tokio::time::timeout(Duration::from_secs(2), self.server)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn commanded_abort_join_retires_only_original_scope_callbacks() {
    let mut f = Chain::new().await;
    let receipt = f.owner.prepare_callback_retirement(&f.operation).unwrap();
    assert!(f.owner.prepare_callback_retirement(&f.operation).is_err());
    f.network
        .tasks
        .lock()
        .unwrap()
        .spawn(async { std::future::pending::<Result<(), ProtocolError>>().await });
    assert_eq!(f.drain().await, Ok(()));
    assert_eq!(receipt.finish(&f.owner, &f.operation), Ok(()));
    let event = f.events.as_mut().unwrap().try_recv().unwrap();
    match event {
        ServerMessage::Event {
            generation,
            event,
            payload,
            decision,
            ..
        } => {
            assert_eq!(generation, 1);
            assert_eq!(event, "scope.callbacks-retired");
            assert_eq!(payload["identityScope"], "scope");
            assert_eq!(payload["throughEventSequence"], 0);
            assert!(decision.is_none());
        }
        _ => panic!("expected existing retirement event"),
    }
    assert!(f.events.as_mut().unwrap().try_recv().is_err());
    f.done().await;
}

#[tokio::test(flavor = "current_thread")]
async fn inner_error_keeps_old_close_result_but_refuses_new_proof_with_original_reason() {
    let f = Chain::new().await;
    let receipt = f.owner.prepare_callback_retirement(&f.operation).unwrap();
    let (done, joined) = tokio::sync::oneshot::channel();
    f.network.tasks.lock().unwrap().spawn(async move {
        done.send(()).unwrap();
        Err(ProtocolError::DecisionKindMismatch)
    });
    // Current-thread scheduling: the worker returns Ready in this same poll
    // before this receiver can resume; no sleep/racy abort-vs-error assumption.
    joined.await.unwrap();
    assert_eq!(f.drain().await, Ok(()));
    assert_eq!(
        receipt.finish(&f.owner, &f.operation),
        Err(ProtocolError::DecisionKindMismatch)
    );
    f.done().await;
}

#[tokio::test(flavor = "current_thread")]
async fn prior_finished_close_cannot_be_borrowed_by_a_new_reset() {
    let f = Chain::new().await;
    assert_eq!(f.drain().await, Ok(()));
    assert!(f.owner.prepare_callback_retirement(&f.operation).is_err());
    assert!(f.network.prepare_callback_drain(&f.operation).is_err());
    f.done().await;
}

#[tokio::test(flavor = "current_thread")]
async fn same_scope_text_does_not_replace_original_owner_arc() {
    let f = Chain::new().await;
    let receipt = f.owner.prepare_callback_retirement(&f.operation).unwrap();
    let other = Chain::owner(&f.client, &f.network);
    other.seal();
    assert_eq!(f.drain().await, Ok(()));
    assert_eq!(
        receipt.finish(&other, &f.operation),
        Err(ProtocolError::StaleScope)
    );
    f.done().await;
}

#[tokio::test(flavor = "current_thread")]
async fn pending_original_scope_barrier_refuses_retirement() {
    let f = Chain::new().await;
    let receipt = f.owner.prepare_callback_retirement(&f.operation).unwrap();
    let other = f.broker.admit(1, 3, 5000).unwrap();
    let _pending = f.global.stage_until_result(&other, "scope").unwrap();
    assert_eq!(f.drain().await, Ok(()));
    assert_eq!(
        receipt.finish(&f.owner, &f.operation),
        Err(ProtocolError::StaleScope)
    );
    f.done().await;
}

#[tokio::test(flavor = "current_thread")]
async fn refused_event_queue_does_not_fabricate_a_local_only_proof() {
    let mut f = Chain::new().await;
    let receipt = f.owner.prepare_callback_retirement(&f.operation).unwrap();
    drop(f.events.take());
    assert_eq!(f.drain().await, Ok(()));
    assert!(receipt.finish(&f.owner, &f.operation).is_err());
    f.done().await;
}

#[tokio::test(flavor = "current_thread")]
async fn poisoned_observer_does_not_skip_original_blocking_reader_join() {
    let f = Chain::new().await;
    let receipt = f.owner.prepare_callback_retirement(&f.operation).unwrap();
    let evidence = f
        .network
        .callback_drain
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .clone();
    assert!(std::panic::catch_unwind(|| {
        let _guard = evidence.outcome.lock().unwrap();
        panic!("observer fault");
    })
    .is_err());
    let (release, blocked) = std::sync::mpsc::channel();
    let (entered, reader_started) = tokio::sync::oneshot::channel();
    f.network
        .blocking_reads
        .lock()
        .unwrap()
        .spawn_blocking(move || {
            entered.send(()).unwrap();
            blocked.recv().unwrap();
        });
    reader_started.await.unwrap();
    f.owner.seal();
    let network = f.network.clone();
    let closing = tokio::spawn(async move { network.close().await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !evidence.invalid.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!closing.is_finished());
    release.send(()).unwrap();
    assert_eq!(closing.await.unwrap(), Ok(()));
    f.owner.drain().await.unwrap();
    assert_eq!(
        receipt.finish(&f.owner, &f.operation),
        Err(ProtocolError::StaleScope)
    );
    f.done().await;
}

#[tokio::test(flavor = "current_thread")]
async fn same_client_foreign_network_is_refused_before_any_token_revocation() {
    let mut f = Chain::new().await;
    let receipt = f.owner.prepare_callback_retirement(&f.operation).unwrap();
    assert_eq!(f.drain().await, Ok(()));
    let operation = f.broker.admit(1, 3, 5000).unwrap();
    let foreign_sink = f.global.stage_until_result(&operation, "foreign").unwrap();
    f.global
        .acknowledge_result_for_test(&ServerMessage::Result {
            id: "foreign-open".into(),
            generation: 1,
            operation_seq: 3,
            ok: true,
            data: Some(json!({"identityScope":"foreign"})),
            error: None,
            effects: Effects::Completed,
            retention: None,
            recovery: None,
            scope_state: ScopeState::Usable,
        })
        .unwrap();
    let foreign = Arc::new(ClientNetwork::new(
        f.client.clone(),
        f.broker.clone(),
        foreign_sink,
        BlobScope {
            generation: 1,
            identity_scope: "foreign".into(),
        },
        Arc::new(BlobStore::new(BlobLimits::default()).unwrap()),
        Arc::new(super::super::client_ui::UiGate::default()),
        NetworkPolicy::default(),
    ));
    let lease = f
        .broker
        .decision_scoped(
            1,
            DecisionOwner::Scope,
            DecisionKind::Request,
            5000,
            None,
            Some("foreign".into()),
        )
        .unwrap();
    assert_eq!(
        foreign.retire_callbacks_after_owner_drain(&receipt),
        Err(ProtocolError::StaleScope)
    );
    assert_eq!(
        f.broker.decision_resource_scope(1, &lease.token),
        Ok("foreign".into())
    );
    assert!(f.events.as_mut().unwrap().try_recv().is_err());
    // The failed foreign invocation did not consume or rebind original proof.
    assert_eq!(receipt.finish(&f.owner, &f.operation), Ok(()));
    assert_eq!(
        f.broker.decision_resource_scope(1, &lease.token),
        Ok("foreign".into())
    );
    foreign.close().await.unwrap();
    f.done().await;
}
