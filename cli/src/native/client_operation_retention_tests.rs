//! Synthetic transport and retained-task proofs. No browser or renderer runs.
use super::*;
use crate::native::client_debt::{OperationKey, OwnerDebtLedger};
use crate::native::client_operation_state::OperationRetentionStatus;
use crate::native::client_session::{DecisionKind, DecisionOwner};
use crate::native::client_targets::ClientTargets;
use crate::native::client_tasks::RetainedTasks;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

struct ExactOwnerExecutor {
    broker: Arc<ClientSession>,
    tasks: RetainedTasks,
    targets: Arc<ClientTargets>,
    ledger: Arc<OwnerDebtLedger>,
    sink: OnceLock<ClientEventSink>,
    publications_retired: AtomicUsize,
    fresh_calls: AtomicUsize,
    shutdowns: AtomicUsize,
    release: Arc<tokio::sync::Notify>,
}
impl ExactOwnerExecutor {
    fn new(broker: Arc<ClientSession>) -> Self {
        Self {
            broker,
            tasks: RetainedTasks::default(),
            targets: ClientTargets::new("context".into(), "stable".into()),
            ledger: OwnerDebtLedger::new(1, "stable".into()),
            sink: OnceLock::new(),
            publications_retired: AtomicUsize::new(0),
            fresh_calls: AtomicUsize::new(0),
            shutdowns: AtomicUsize::new(0),
            release: Arc::new(tokio::sync::Notify::new()),
        }
    }
}
impl ClientExecutor for ExactOwnerExecutor {
    fn capabilities(&self) -> Vec<String> {
        vec![EXACT_OWNER_CONTINUATION.into()]
    }
    fn set_event_sink(&self, sink: ClientEventSink) -> Result<(), ProtocolError> {
        self.sink
            .set(sink)
            .map_err(|_| ProtocolError::InvalidArguments)
    }
    fn operation_retention_status(&self, key: OperationKey) -> OperationRetentionStatus {
        self.tasks.operation_retention_status(key)
    }
    fn cancel_operation_producer(&self, key: OperationKey) {
        self.tasks.cancel_operation_producer(key);
    }
    fn fix_operation_result(&self, key: OperationKey) {
        self.tasks.fix_operation_result(key);
    }
    async fn retire_operation_publication(&self, _key: OperationKey) -> Result<(), ProtocolError> {
        self.publications_retired.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn execute(
        &self,
        command: String,
        _: serde_json::Map<String, serde_json::Value>,
        lease: OperationLease,
    ) -> NativeOutcome {
        assert!(self.broker.start(lease.generation, lease.sequence).unwrap());
        if command == "fresh" {
            self.tasks.wait_application(&lease).await.unwrap();
            self.fresh_calls.fetch_add(1, Ordering::SeqCst);
            return NativeOutcome {
                retention: None,
                result: Ok(serde_json::json!({"fresh":true})),
                effects: Effects::Completed,
            };
        }
        let key = OperationKey {
            generation: lease.generation,
            operation_seq: lease.sequence,
        };
        let journal = self
            .ledger
            .operation(key, "target".into(), "session".into())
            .unwrap();
        journal.bind_operation(&lease).unwrap();
        let release = self.release.clone();
        let cancellation = lease.cancellation.clone();
        let receive = self
            .tasks
            .start_operation(
                "stable".into(),
                self.targets.clone(),
                self.broker.clone(),
                journal.clone(),
                cancellation,
                async move {
                    if command != "not-submitted" {
                        journal.mark_mutation_maybe_submitted().unwrap();
                    }
                    if command == "retiring" || command == "not-submitted" {
                        release.notified().await;
                    }
                    (
                        NativeOutcome {
                            retention: None,
                            result: Err(ProtocolError::DeadlineExceeded),
                            effects: Effects::Unknown,
                        },
                        false,
                    )
                },
            )
            .await
            .unwrap();
        receive.await.unwrap()
    }
    async fn shutdown(&self) -> Result<(), ProtocolError> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        self.tasks.seal().await;
        self.tasks.drain().await
    }
}
async fn frame<R: AsyncBufRead + Unpin>(peer: &mut R) -> serde_json::Value {
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(3), read_frame(peer))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
async fn request(
    peer: &mut tokio::io::BufReader<tokio::io::DuplexStream>,
    sequence: u64,
    command: &str,
    timeout: u64,
) {
    let mut bytes = serde_json::to_vec(
        &serde_json::json!({"type":"request","id":format!("r{sequence}"),"generation":1,
        "operationSeq":sequence,"timeoutMs":timeout,"command":command,"args":{}}),
    )
    .unwrap();
    bytes.push(b'\n');
    peer.get_mut().write_all(&bytes).await.unwrap();
}
async fn peer(
    negotiated: bool,
) -> (
    tokio::io::BufReader<tokio::io::DuplexStream>,
    Arc<ExactOwnerExecutor>,
    tokio::task::JoinHandle<bool>,
) {
    let broker = Arc::new(ClientSession::new());
    let executor = Arc::new(ExactOwnerExecutor::new(broker.clone()));
    let (peer, server) = tokio::io::duplex(16384);
    let (reader, writer) = tokio::io::split(server);
    let serving = tokio::spawn(serve_with_executor(
        tokio::io::BufReader::new(reader),
        writer,
        ClientMessage::Hello {
            id: "hello".into(),
            protocol: PROTOCOL.into(),
            required_capabilities: if negotiated {
                vec![EXACT_OWNER_CONTINUATION.into()]
            } else {
                vec![]
            },
        },
        broker,
        executor.clone(),
    ));
    let mut peer = tokio::io::BufReader::new(peer);
    assert_eq!(frame(&mut peer).await["type"], "ready");
    (peer, executor, serving)
}
#[tokio::test]
async fn negotiated_unknown_keeps_stable_owner_services_and_fresh_request_live() {
    let (mut peer, executor, serving) = peer(true).await;
    executor
        .broker
        .register_routes(1, 1, vec!["route-with-browser-callback".into()])
        .unwrap();
    request(&mut peer, 1, "uncertain", 1000).await;
    let unknown = frame(&mut peer).await;
    assert_eq!(unknown["effects"], "unknown");
    assert_eq!(unknown["scopeState"], "usable");
    assert_eq!(
        unknown["retention"],
        serde_json::json!({"version":1,"retiredOperationSeq":1,"producerState":"retired","inputDebt":0,"objectDebt":0})
    );
    assert_eq!(executor.broker.health().unwrap(), (1, ScopeState::Usable));
    assert_eq!(executor.shutdowns.load(Ordering::SeqCst), 0);
    assert_eq!(executor.publications_retired.load(Ordering::SeqCst), 1);
    // Existing resident event sink and route registry remain unchanged. These
    // model active recording/download/subscription producers, not restarts.
    for event in ["response", "download", "recording-frame"] {
        executor
            .sink
            .get()
            .unwrap()
            .emit(
                event.into(),
                serde_json::json!({"identityScope":"stable"}),
                None,
            )
            .unwrap();
        assert_eq!(frame(&mut peer).await["event"], event);
    }
    for kind in [
        DecisionKind::Request,
        DecisionKind::Authentication,
        DecisionKind::Dialog,
    ] {
        let decision = executor
            .broker
            .decision(
                1,
                DecisionOwner::Scope,
                kind,
                1000,
                if kind == DecisionKind::Request {
                    Some(1)
                } else {
                    None
                },
            )
            .unwrap();
        let selection = match kind {
            DecisionKind::Request => Decision::Abort {},
            DecisionKind::Authentication => Decision::CancelAuth {},
            DecisionKind::Dialog => Decision::Dialog {
                accept: false,
                prompt_text: None,
            },
            DecisionKind::InteropRetire | DecisionKind::InteropCreate => {
                unreachable!("this public callback matrix excludes private lifecycle decisions")
            }
        };
        executor
            .broker
            .resolve(1, &decision.token, selection)
            .unwrap();
        assert!(decision.outcome.await.is_ok());
    }
    request(&mut peer, 2, "fresh", 1000).await;
    let fresh = frame(&mut peer).await;
    assert_eq!(fresh["scopeState"], "usable");
    assert_eq!(fresh["data"]["fresh"], true);
    assert!(fresh.get("retention").is_none());
    assert_eq!(executor.fresh_calls.load(Ordering::SeqCst), 1);
    peer.get_mut().shutdown().await.unwrap();
    assert!(serving.await.unwrap());
}
#[tokio::test]
async fn unnegotiated_exact_proof_keeps_legacy_terminal_shape() {
    let (mut peer, executor, serving) = peer(false).await;
    request(&mut peer, 1, "uncertain", 1000).await;
    let unknown = frame(&mut peer).await;
    assert_eq!(unknown["scopeState"], "quarantined");
    assert!(unknown.get("retention").is_none());
    assert_eq!(executor.publications_retired.load(Ordering::SeqCst), 0);
    peer.get_mut().shutdown().await.unwrap();
    assert!(serving.await.unwrap());
}
#[tokio::test]
async fn grace_uses_retained_real_dispatch_marker_and_holds_fresh_application() {
    for dispatched in [true, false] {
        let (mut peer, executor, serving) = peer(true).await;
        request(
            &mut peer,
            1,
            if dispatched {
                "retiring"
            } else {
                "not-submitted"
            },
            100,
        )
        .await;
        let result = frame(&mut peer).await;
        assert_eq!(
            result["effects"],
            if dispatched {
                "unknown"
            } else {
                "not-dispatched"
            }
        );
        assert_eq!(result["scopeState"], "usable");
        if dispatched {
            assert_eq!(result["retention"]["producerState"], "retiring");
        } else {
            assert!(result.get("retention").is_none());
        }
        request(&mut peer, 2, "fresh", 1000).await;
        tokio::task::yield_now().await;
        assert_eq!(executor.fresh_calls.load(Ordering::SeqCst), 0);
        executor.release.notify_one();
        assert_eq!(frame(&mut peer).await["data"]["fresh"], true);
        assert_eq!(executor.fresh_calls.load(Ordering::SeqCst), 1);
        peer.get_mut().shutdown().await.unwrap();
        assert!(serving.await.unwrap());
    }
}
