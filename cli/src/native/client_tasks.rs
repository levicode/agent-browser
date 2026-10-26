//! Retained native command ownership, independent of an RPC receiver's lifetime.
//! Callers capture an execution permit before registration and keep it, UI
//! admission, and all resource leases inside the submitted future. Lifecycle
//! closes execution admission and drains those permits before draining this set.
use super::client_protocol::{Effects, ProtocolError};
use super::client_targets::ClientTargets;
use super::client_transport::NativeOutcome;
use futures_util::FutureExt;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinSet;

const MAX_RETAINED: usize = super::client_operation_state::MAX_RETAINED_OPERATIONS;

pub struct RetainedCompletion {
    pub identity_scope: String,
    pub cleanup_integrity_lost: bool,
    operation: Option<super::client_debt::OperationKey>,
}
#[derive(Default)]
struct Tasks {
    closing: bool,
    tasks: JoinSet<RetainedCompletion>,
    failures: Vec<RetainedCompletion>,
    unscoped_failure: bool,
}
#[derive(Default)]
pub struct RetainedTasks {
    inner: Mutex<Tasks>,
    operations: Arc<super::client_operation_state::OperationRegistry>,
}
impl Tasks {
    fn record(&mut self, result: Result<RetainedCompletion, tokio::task::JoinError>) {
        match result {
            Ok(result) if result.cleanup_integrity_lost => {
                self.failures.push(result);
            }
            Err(_) => self.unscoped_failure = true,
            _ => {}
        }
    }
}
impl RetainedTasks {
    pub(crate) fn begin_protected_cleanup(
        &self,
        key: super::client_debt::OperationKey,
    ) -> Option<std::time::Instant> {
        self.operations.begin_protected_cleanup(key)
    }
    pub(crate) fn operation_retention_status(
        &self,
        key: super::client_debt::OperationKey,
    ) -> super::client_operation_state::OperationRetentionStatus {
        self.operations.status(key)
    }

    pub(crate) fn cancel_operation_producer(&self, key: super::client_debt::OperationKey) {
        self.operations.retire(key);
    }

    pub(crate) fn fix_operation_result(&self, key: super::client_debt::OperationKey) {
        self.operations.fix_result(key);
    }

    pub(crate) fn prepare_eval_window(
        &self,
        journal: &super::client_debt::OperationJournalHandle,
        operation: &super::client_session::OperationLease,
        stamp: super::client_debt::EvalAuthorityStamp,
    ) -> Result<super::client_debt::EvalWindowHandle, ProtocolError> {
        self.operations
            .prepare_eval_window(journal, operation, stamp)
    }
    pub(crate) fn check_eval_dispatch(
        &self,
        permit: &super::client_debt::ReentrantEvalPermit,
    ) -> Result<(), ProtocolError> {
        self.operations.check_eval_dispatch(permit)
    }
    pub(crate) fn check_input_dispatch(
        &self,
        key: super::client_debt::OperationKey,
    ) -> Result<(), ProtocolError> {
        if self.operations.input_dispatch_ready(key)? {
            Ok(())
        } else {
            Err(ProtocolError::ScopeUnavailable)
        }
    }

    /// Owner services do not enter this gate. New application work waits only
    /// for positively retained local producers, under its own original budget.
    pub(crate) async fn wait_application(
        &self,
        operation: &super::client_session::OperationLease,
    ) -> Result<(), ProtocolError> {
        let mut cancellation = operation.cancellation.clone();
        loop {
            let changed = self.operations.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if *cancellation.borrow() != super::client_session::CancelSignal::None {
                return Err(ProtocolError::Cancelled);
            }
            if std::time::Instant::now() >= operation.deadline {
                return Err(ProtocolError::DeadlineExceeded);
            }
            if self.operations.application_ready()? {
                return Ok(());
            }
            tokio::select! { biased;
                _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                _ = tokio::time::sleep_until(operation.deadline.into()) => return Err(ProtocolError::DeadlineExceeded),
                _ = &mut changed => {},
            }
        }
    }

    pub(crate) async fn start_operation<F>(
        &self,
        identity_scope: String,
        targets: Arc<ClientTargets>,
        broker: Arc<super::client_session::ClientSession>,
        journal: super::client_debt::OperationJournalHandle,
        cancellation: tokio::sync::watch::Receiver<super::client_session::CancelSignal>,
        future: F,
    ) -> Result<oneshot::Receiver<NativeOutcome>, ProtocolError>
    where
        F: Future<Output = (NativeOutcome, bool)> + Send + 'static,
    {
        self.start_operation_prepared(
            identity_scope,
            targets,
            broker,
            journal,
            cancellation,
            || Ok(future),
        )
        .await
    }

    pub(crate) async fn start_operation_prepared<F, P>(
        &self,
        identity_scope: String,
        targets: Arc<ClientTargets>,
        broker: Arc<super::client_session::ClientSession>,
        journal: super::client_debt::OperationJournalHandle,
        cancellation: tokio::sync::watch::Receiver<super::client_session::CancelSignal>,
        prepare: P,
    ) -> Result<oneshot::Receiver<NativeOutcome>, ProtocolError>
    where
        F: Future<Output = (NativeOutcome, bool)> + Send + 'static,
        P: FnOnce() -> Result<F, ProtocolError>,
    {
        let operations = self.operations.clone();
        let task_targets = targets.clone();
        let key = journal.key();
        self.start_prepared_tracked(identity_scope, targets, Some(key), move || {
            operations.register(journal.clone())?;
            let future = match prepare() {
                Ok(future) => future,
                Err(error) => {
                    operations.abandon_unstarted(journal.key());
                    return Err(error);
                }
            };
            Ok(async move {
                let key = journal.key();
                operations.running(key);
                let monitor_registry = operations.clone();
                let monitor_targets = task_targets.clone();
                let mut cancellation = cancellation;
                let monitor_broker = broker.clone();
                let monitor = tokio::spawn(async move {
                    if *cancellation.borrow() == super::client_session::CancelSignal::None {
                        let _ = cancellation.changed().await;
                    }
                    if let Some(deadline) = monitor_registry.retire(key) {
                        tokio::time::sleep_until(deadline.into()).await;
                        if monitor_registry.expire(key, std::time::Instant::now()) {
                            monitor_targets.seal();
                            let _ = monitor_broker.quarantine();
                        }
                    }
                });
                let result = AssertUnwindSafe(journal.scope(future)).catch_unwind().await;
                let (mut outcome, dirty) = match result {
                    Ok(value) => value,
                    Err(_) => (
                        NativeOutcome {
                            retention: None,
                            result: Err(ProtocolError::BrowserFailure),
                            effects: Effects::Unknown,
                        },
                        true,
                    ),
                };
                // This timer owns no action work. Join it before publishing local
                // completion so an old deadline cannot quarantine a fresh owner.
                monitor.abort();
                let monitor_failed = match monitor.await {
                    Ok(()) => false,
                    Err(error) => !error.is_cancelled(),
                };
                let dirty = dirty || monitor_failed;
                let snapshot = journal.snapshot();
                let remote_only = !dirty
                    && !matches!(&outcome.result, Err(ProtocolError::CleanupFailed))
                    && journal.local_integrity_intact()
                    && journal.ledger().remote_eof_only();
                let already_dirty = dirty
                    || matches!(&outcome.result, Err(ProtocolError::CleanupFailed))
                    || snapshot.integrity_lost;
                let observe_inventory = super::client_settlement_trace::inventory_enabled();
                let (settlement, inventory) = if already_dirty && !observe_inventory {
                    (Ok(()), Default::default())
                } else {
                    task_targets.settlement_integrity_diagnostic(observe_inventory)
                };
                if settlement.is_err() {
                    super::client_settlement_trace::inventory_snapshot(
                        key.generation,
                        key.operation_seq,
                        super::client_settlement_trace::InventoryPoint::SettlementRefused,
                        inventory,
                    );
                }
                let dirty = already_dirty || settlement.is_err();
                if !dirty && outcome.result.is_err() {
                    // Executor entry and current debt count are not dispatch
                    // evidence. Preserve a completed prefix, but never invent a
                    // mutation while waiting for UI/geometry/quota admission.
                    if outcome.effects == Effects::Unknown && !snapshot.mutation_dispatched {
                        outcome.effects = Effects::NotDispatched;
                    } else if outcome.effects == Effects::NotDispatched
                        && snapshot.mutation_dispatched
                    {
                        outcome.effects = Effects::Unknown;
                    }
                }
                // Exact remote EOF will become Unknown in the retained result
                // wrapper even for a fixed read. Establish its existing bounded
                // retirement before finish_remote_eof seals the producer; after
                // that transition retire correctly refuses IntegrityLost.
                // This grants neither usable retention nor remote cleanup proof.
                if outcome.effects == Effects::Unknown || remote_only {
                    operations.retire(key);
                }
                let dirty = (if remote_only {
                    operations.finish_remote_eof(key)
                } else {
                    operations.finish(key, dirty)
                }) || dirty;
                if dirty {
                    task_targets.seal();
                    let _ = broker.quarantine();
                }
                if outcome.effects == Effects::Unknown && !dirty {
                    outcome.retention = operations.status(key).proof();
                }
                (outcome, dirty)
            })
        })
        .await
    }

    pub async fn start<F>(
        &self,
        identity_scope: String,
        targets: Arc<ClientTargets>,
        future: F,
    ) -> Result<oneshot::Receiver<NativeOutcome>, ProtocolError>
    where
        F: Future<Output = (NativeOutcome, bool)> + Send + 'static,
    {
        self.start_prepared(identity_scope, targets, || Ok(future))
            .await
    }

    /// Validate and acquire operation-specific admission only after retained
    /// capacity and shutdown checks, synchronously before spawning the owner.
    /// The closure must not await or start work before returning its future.
    pub async fn start_prepared<F, P>(
        &self,
        identity_scope: String,
        targets: Arc<ClientTargets>,
        prepare: P,
    ) -> Result<oneshot::Receiver<NativeOutcome>, ProtocolError>
    where
        F: Future<Output = (NativeOutcome, bool)> + Send + 'static,
        P: FnOnce() -> Result<F, ProtocolError>,
    {
        self.start_prepared_tracked(identity_scope, targets, None, prepare)
            .await
    }

    async fn start_prepared_tracked<F, P>(
        &self,
        identity_scope: String,
        targets: Arc<ClientTargets>,
        operation: Option<super::client_debt::OperationKey>,
        prepare: P,
    ) -> Result<oneshot::Receiver<NativeOutcome>, ProtocolError>
    where
        F: Future<Output = (NativeOutcome, bool)> + Send + 'static,
        P: FnOnce() -> Result<F, ProtocolError>,
    {
        let mut tasks = self.inner.lock().await;
        while let Some(result) = tasks.tasks.try_join_next() {
            tasks.record(result);
        }
        if tasks.closing
            || tasks.unscoped_failure
            || tasks.failures.iter().any(|failure| {
                !failure
                    .operation
                    .is_some_and(|key| self.operations.disconnected_failure_retired(key))
            })
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if tasks.tasks.len() >= MAX_RETAINED {
            return Err(ProtocolError::CapacityExceeded);
        }
        // No fallible admission remains after prepare returns. A validated
        // capture stays admitted if its later task fails; it is never revived.
        let future = prepare()?;
        let (send, receive) = oneshot::channel();
        // Registration and permanent shutdown linearize under this mutex.
        tasks.tasks.spawn(async move {
            let (mut outcome, cleanup_integrity_lost) =
                match AssertUnwindSafe(future).catch_unwind().await {
                    Ok(result) => result,
                    Err(_) => (
                        NativeOutcome {
                            retention: None,
                            result: Err(ProtocolError::BrowserFailure),
                            effects: Effects::Unknown,
                        },
                        true,
                    ),
                };
            let cleanup_integrity_lost = cleanup_integrity_lost
                || matches!(&outcome.result, Err(ProtocolError::CleanupFailed));
            if cleanup_integrity_lost {
                // Dispatch disposition cannot certify scope reuse after cleanup
                // loses integrity. Preserve any primary error, but never deliver
                // success alongside a sealed registry and a failed drain.
                outcome.effects = Effects::Unknown;
                if outcome.result.is_ok() {
                    outcome.result = Err(ProtocolError::CleanupFailed);
                }
                targets.seal();
            }
            // Any orphaned blob handles remain in the captured bounded BlobStore
            // scope journal until its retirement; they never transfer to another
            // scope and no completed mutation is replayed for a lost response.
            let _ = send.send(outcome);
            RetainedCompletion {
                identity_scope,
                cleanup_integrity_lost,
                operation,
            }
        });
        Ok(receive)
    }

    pub(crate) fn recovery_candidate(
        &self,
        key: super::client_debt::OperationKey,
    ) -> Option<super::client_operation_state::DisconnectedRecoveryProof> {
        self.operations.recovery_candidate(key)
    }
    /// Join all old local producers under the caller's existing lifecycle budget.
    /// A historical EOF failure is not erased, and unrelated local failures refuse.
    pub(crate) async fn drain_disconnected(
        &self,
        proof: &super::client_operation_state::DisconnectedRecoveryProof,
    ) -> Result<(), ProtocolError> {
        proof.check()?;
        let mut tasks = self.inner.lock().await;
        while let Some(result) = tasks.tasks.join_next().await {
            tasks.record(result);
        }
        if tasks.closing
            || tasks.unscoped_failure
            || tasks.failures.iter().any(|failure| {
                !failure.operation.is_some_and(|key| {
                    self.operations.disconnected_failure_retired(key)
                        || self.operations.disconnected_failure_matches(key, proof)
                }) || failure.identity_scope != proof.ledger().identity_scope()
                    && !failure
                        .operation
                        .is_some_and(|key| self.operations.disconnected_failure_retired(key))
            })
        {
            return Err(ProtocolError::CleanupFailed);
        }
        self.operations
            .recovery_candidate(proof.key())
            .ok_or(ProtocolError::CleanupFailed)?;
        Ok(())
    }
    pub(crate) fn retire_disconnected_owner(
        &self,
        proof: &super::client_operation_state::DisconnectedRecoveryProof,
    ) -> Result<(), ProtocolError> {
        self.operations.retire_disconnected_owner(proof)
    }
    /// Final cleanup of the current owner. Previously verified local retirements
    /// remain recorded; they are not live producers of this replacement scope.
    pub(crate) async fn drain_current(&self) -> Result<(), ProtocolError> {
        let mut tasks = self.inner.lock().await;
        while let Some(result) = tasks.tasks.join_next().await {
            tasks.record(result);
        }
        if tasks.unscoped_failure
            || tasks.failures.iter().any(|failure| {
                !failure
                    .operation
                    .is_some_and(|key| self.operations.disconnected_failure_retired(key))
            })
        {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
    pub async fn seal(&self) {
        self.inner.lock().await.closing = true;
    }

    /// JoinSet remains in owner storage if this wait is cancelled. All tasks
    /// are joined even when an earlier task reported cleanup failure.
    #[cfg(test)]
    pub async fn drain(&self) -> Result<(), ProtocolError> {
        let mut tasks = self.inner.lock().await;
        while let Some(result) = tasks.tasks.join_next().await {
            tasks.record(result);
        }
        if tasks.unscoped_failure || !tasks.failures.is_empty() {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::client_browser::ExecutionGate;
    use super::super::client_protocol::ScopeState;
    use super::super::client_session::ClientSession;
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    fn complete() -> NativeOutcome {
        NativeOutcome {
            retention: None,
            result: Ok(serde_json::Value::Null),
            effects: Effects::Completed,
        }
    }

    // Exercise the same retained result channel consumed by the transport. The
    // broker must settle the delivered effects, not a separately classified copy.
    async fn assert_retained_settlement(
        result: Result<serde_json::Value, ProtocolError>,
        effects: Effects,
        cleanup_integrity_lost: bool,
    ) {
        let tasks = RetainedTasks::default();
        let broker = ClientSession::new();
        let lease = broker.admit(1, 1, 1_000).unwrap();
        assert!(broker.start(1, 1).unwrap());
        let captured = ClientTargets::new("captured-context".into(), "captured-scope".into());
        let other = ClientTargets::new("other-context".into(), "other-scope".into());
        let expected_integrity_lost =
            cleanup_integrity_lost || matches!(&result, Err(ProtocolError::CleanupFailed));
        let expected_result = if expected_integrity_lost && result.is_ok() {
            Err(ProtocolError::CleanupFailed)
        } else {
            result.clone()
        };
        let expected_effects = if expected_integrity_lost {
            Effects::Unknown
        } else {
            effects
        };
        let expected_state = if expected_integrity_lost {
            ScopeState::Quarantined
        } else {
            ScopeState::Usable
        };
        let receive = tasks
            .start("captured-scope".into(), captured.clone(), async move {
                let _lease = lease;
                (
                    NativeOutcome {
                        retention: None,
                        result,
                        effects,
                    },
                    cleanup_integrity_lost,
                )
            })
            .await
            .unwrap();
        let outcome = receive.await.unwrap();
        let settled = broker.settle(1, 1, outcome.effects).unwrap();
        let health = broker.health().unwrap();
        let next_admission = broker.admit(1, 2, 1_000);
        let drained = tasks.drain().await;

        assert_eq!(
            outcome.result, expected_result,
            "primary error must survive; dirty success must not"
        );
        assert_eq!(
            outcome.effects, expected_effects,
            "retained delivery must reflect cleanup integrity"
        );
        assert_eq!(settled, expected_state);
        assert_eq!(health, (1, expected_state));
        assert_eq!(captured.inventory().is_err(), expected_integrity_lost);
        assert!(
            other.inventory().is_ok(),
            "only captured targets may be sealed"
        );
        if expected_integrity_lost {
            assert_eq!(next_admission.err(), Some(ProtocolError::ScopeUnavailable));
            assert_eq!(drained, Err(ProtocolError::CleanupFailed));
        } else {
            let _next = next_admission.unwrap();
            assert!(broker.start(1, 2).unwrap());
            assert_eq!(
                broker.settle(1, 2, Effects::NotDispatched).unwrap(),
                ScopeState::Usable
            );
            assert_eq!(drained, Ok(()));
        }
    }

    #[tokio::test]
    async fn retained_dirty_action_preflight_cleanup_failure_quarantines_broker() {
        assert_retained_settlement(
            Err(ProtocolError::CleanupFailed),
            Effects::NotDispatched,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn retained_dirty_strict_query_cancellation_quarantines_broker() {
        assert_retained_settlement(Err(ProtocolError::Cancelled), Effects::NotDispatched, true)
            .await;
    }

    #[tokio::test]
    async fn retained_dirty_strict_query_browser_failure_quarantines_broker() {
        assert_retained_settlement(
            Err(ProtocolError::BrowserFailure),
            Effects::NotDispatched,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn retained_dirty_strict_query_stale_reference_quarantines_broker() {
        assert_retained_settlement(
            Err(ProtocolError::StaleReference),
            Effects::NotDispatched,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn retained_dirty_completed_error_quarantines_broker() {
        assert_retained_settlement(Err(ProtocolError::BrowserFailure), Effects::Completed, true)
            .await;
    }

    #[tokio::test]
    async fn retained_cleanup_failure_error_without_dirty_flag_quarantines_broker() {
        for effects in [Effects::NotDispatched, Effects::Completed] {
            assert_retained_settlement(Err(ProtocolError::CleanupFailed), effects, false).await;
        }
    }

    #[tokio::test]
    async fn retained_dirty_success_becomes_cleanup_failure_and_quarantines_broker() {
        for effects in [Effects::NotDispatched, Effects::Completed] {
            assert_retained_settlement(Ok(serde_json::json!({"accepted": true})), effects, true)
                .await;
        }
    }

    #[tokio::test]
    async fn retained_clean_refusal_cancel_and_settled_prefix_errors_keep_broker_usable() {
        for (error, effects) in [
            (ProtocolError::PolicyDenied, Effects::NotDispatched),
            (ProtocolError::NotActionable, Effects::NotDispatched),
            (ProtocolError::Cancelled, Effects::NotDispatched),
            (ProtocolError::BrowserFailure, Effects::NotDispatched),
            (ProtocolError::StaleReference, Effects::NotDispatched),
            (ProtocolError::Cancelled, Effects::Completed),
            (ProtocolError::BrowserFailure, Effects::Completed),
            (ProtocolError::StaleReference, Effects::Completed),
        ] {
            assert_retained_settlement(Err(error), effects, false).await;
        }
    }

    #[tokio::test]
    async fn retained_clean_success_keeps_payload_effects_and_broker_usable() {
        for effects in [Effects::NotDispatched, Effects::Completed] {
            assert_retained_settlement(Ok(serde_json::json!({"accepted": true})), effects, false)
                .await;
        }
    }

    #[tokio::test]
    async fn lost_rpc_and_cancelled_drain_retain_execution_permit_until_cleanup() {
        let tasks = Arc::new(RetainedTasks::default());
        let gate = Arc::new(ExecutionGate::default());
        let permit = gate.enter(false).unwrap();
        let targets = ClientTargets::new("context".into(), "scope".into());
        let (release, waiting) = oneshot::channel();
        let receive = tasks
            .start("scope".into(), targets, async move {
                let _permit = permit;
                waiting.await.unwrap();
                (complete(), false)
            })
            .await
            .unwrap();
        drop(receive);
        gate.begin_transition().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), gate.drained())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), tasks.drain())
                .await
                .is_err()
        );
        release.send(()).unwrap();
        tasks.drain().await.unwrap();
        gate.drained().await.unwrap();
        gate.commit_transition().unwrap();
    }

    #[tokio::test]
    async fn cleanup_failure_still_joins_other_tasks_and_seals_only_captured_registry() {
        let tasks = RetainedTasks::default();
        let failed = ClientTargets::new("old-context".into(), "old".into());
        let other = ClientTargets::new("other-context".into(), "other".into());
        let finished = Arc::new(AtomicBool::new(false));
        let (release, waiting) = oneshot::channel();
        let flag = finished.clone();
        let second = tasks
            .start("other".into(), other.clone(), async move {
                waiting.await.unwrap();
                flag.store(true, Ordering::SeqCst);
                (complete(), false)
            })
            .await
            .unwrap();
        let first = tasks
            .start("old".into(), failed.clone(), async { (complete(), true) })
            .await
            .unwrap();
        first.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), tasks.drain())
                .await
                .is_err()
        );
        assert!(!finished.load(Ordering::SeqCst));
        release.send(()).unwrap();
        assert_eq!(tasks.drain().await, Err(ProtocolError::CleanupFailed));
        second.await.unwrap();
        assert!(finished.load(Ordering::SeqCst));
        assert!(failed.inventory().is_err());
        assert!(other.inventory().is_ok());
    }

    #[tokio::test]
    async fn retirement_rejects_late_registration_before_polling_browser_work() {
        let tasks = RetainedTasks::default();
        tasks.seal().await;
        let polled = Arc::new(AtomicBool::new(false));
        let marker = polled.clone();
        assert!(tasks
            .start(
                "scope".into(),
                ClientTargets::new("context".into(), "scope".into()),
                async move {
                    marker.store(true, Ordering::SeqCst);
                    (complete(), false)
                }
            )
            .await
            .is_err());
        assert!(!polled.load(Ordering::SeqCst));
        tasks.drain().await.unwrap();
    }
}

#[cfg(test)]
mod fixed_read_eof_tests {
    use super::*;
    use crate::native::cdp::client::CdpClient;
    use crate::native::client_debt::{OperationKey, OwnerDebtLedger};
    use crate::native::client_session::ClientSession;
    use std::time::Duration;

    // The loopback reader supplies EOF, never a test-written terminal flag.
    // This narrower retained-task test controls producer completion so cleanup
    // failure cannot accidentally be replaced by a successful fixed-read path.
    #[tokio::test]
    async fn fixed_read_eof_cleanup_failure_never_gains_recovery() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let (release, released) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            released.await.unwrap();
            socket.close(None).await.unwrap();
        });
        let client = CdpClient::connect(&endpoint).await.unwrap();
        let broker = Arc::new(ClientSession::new());
        let lease = broker.admit(1, 1, 5000).unwrap();
        assert!(broker.start(1, 1).unwrap());
        let key = OperationKey { generation: 1, operation_seq: 1 };
        let ledger = OwnerDebtLedger::unpublished(&lease, "fixed-read-owner".into(), false).unwrap();
        ledger.bind_context("borrowed-context").unwrap();
        ledger.bind_session("borrowed-context", "page", "session").unwrap();
        client.install_debt_ledger(ledger.clone()).unwrap();
        let journal = ledger.operation(key, "page".into(), "session".into()).unwrap();
        journal.bind_operation(&lease).unwrap();
        let targets = ClientTargets::new("borrowed-context".into(), "fixed-read-owner".into());
        targets.acknowledge_enrollment().unwrap();
        let tasks = RetainedTasks::default();
        let mut closed = client.remote_connection_closed();
        let receive = tasks.start_operation(
            "fixed-read-owner".into(), targets, broker.clone(), journal,
            lease.cancellation.clone(), async move {
                while !*closed.borrow_and_update() { closed.changed().await.unwrap(); }
                (NativeOutcome { retention: None, result: Err(ProtocolError::CleanupFailed), effects: Effects::NotDispatched }, false)
            },
        ).await.unwrap();
        release.send(()).unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(3), receive).await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(3), peer).await.unwrap().unwrap();
        assert_eq!(outcome.result, Err(ProtocolError::CleanupFailed));
        assert_eq!(outcome.effects, Effects::Unknown);
        broker.settle(1, 1, outcome.effects).unwrap();
        tasks.fix_operation_result(key);
        assert!(outcome.retention.is_none());
        assert!(tasks.recovery_candidate(key).is_none());
        assert_eq!(tasks.drain().await, Err(ProtocolError::CleanupFailed));
    }
}
