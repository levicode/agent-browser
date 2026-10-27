//! Bounded negotiated transport with independently serviced native control.
//! Only the owned executor advertises implemented browser capabilities.
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use super::client_protocol::*;
use super::client_session::{ClientSession, OperationLease};

#[cfg(feature = "acceptance-faults")]
pub(crate) use super::client_settlement_trace::SettlementPhase;
macro_rules! settlement_trace {
    ($sequence:expr, $phase:ident) => {
        #[cfg(feature = "acceptance-faults")]
        super::client_settlement_trace::record(
            $sequence,
            SettlementPhase::$phase,
            Default::default(),
        );
    };
}

/// Browser mechanics stay native. The reader only admits work and forwards
/// control; executors never own its lock or the output transport.
pub struct NativeOutcome {
    pub result: Result<serde_json::Value, ProtocolError>,
    pub effects: Effects,
    pub(crate) retention: Option<super::client_operation_state::OperationRetentionProof>,
}

pub trait ClientExecutor: Send + Sync + 'static {
    /// Move only independently finalized bytes for this failed request owner.
    /// The hook never stops, starts, waits for, or reads a producer.
    fn take_terminal_recording(
        &self,
        _key: super::client_debt::OperationKey,
        _scope: Option<&str>,
    ) -> Option<super::client_terminal_artifacts::FrozenRecordingBatch> {
        None
    }
    fn capabilities(&self) -> Vec<String>;
    /// Optional shortening-only deadline for a later RPC belonging to an exact
    /// retained native lifecycle. This synchronous hook may take only short
    /// metadata locks. Mismatch rejects admission; absence never grants ownership.
    /// Ordinary commands return Ok(None). Execute must revalidate
    /// identity/state. No browser work, waiting, or RPC lease fabrication here.
    fn admission_deadline_cap(
        &self,
        _generation: u64,
        _command: &str,
        _args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<std::time::Instant>, ProtocolError> {
        Ok(None)
    }
    /// Reuse the producer's exact cleanup clock; absence grants no longer wait.
    fn begin_trace_cleanup(
        &self,
        _key: super::client_debt::OperationKey,
    ) -> Option<std::time::Instant> {
        None
    }
    /// Reclaim an already-produced late image under its original owner scope.
    fn discard_trace_result(
        &self,
        _key: super::client_debt::OperationKey,
        _value: &serde_json::Value,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::CleanupFailed)
    }
    fn operation_retention_status(
        &self,
        _key: super::client_debt::OperationKey,
    ) -> super::client_operation_state::OperationRetentionStatus {
        super::client_operation_state::OperationRetentionStatus::NotRegistered
    }
    /// Short-lock cancellation hook fixes the native retirement deadline before
    /// the cleanup grace. It never drops or aborts the retained producer.
    fn disconnected_recovery_candidate(
        &self,
        _key: super::client_debt::OperationKey,
    ) -> Option<super::client_operation_state::DisconnectedRecoveryProof> {
        None
    }
    fn cancel_operation_producer(&self, _key: super::client_debt::OperationKey) {}
    fn fix_operation_result(&self, _key: super::client_debt::OperationKey) {}
    /// Independent publication retirement. The broker barrier is already set;
    /// implementations must not acquire lifecycle, action, input or owner locks.
    fn retire_operation_publication(
        &self,
        _key: super::client_debt::OperationKey,
    ) -> impl std::future::Future<Output = Result<(), ProtocolError>> + Send {
        async { Err(ProtocolError::UnsupportedCapability) }
    }

    fn set_event_sink(&self, _sink: ClientEventSink) -> Result<(), ProtocolError> {
        Ok(())
    }
    /// Called on the independent control lane. Implementations may only take
    /// short resource-store locks, never browser/action or lifecycle locks.
    /// A failure must leave no reservation. Default refuses unwired blob bodies.
    fn prepare_decision(
        &self,
        _generation: u64,
        _token: &str,
        decision: &Decision,
    ) -> Result<(), ProtocolError> {
        if decision.body_handle().is_some() {
            Err(ProtocolError::UnsupportedCapability)
        } else {
            Ok(())
        }
    }
    /// Rejected selection rolls back its reservation. Accepted selection already
    /// woke the native consumer, which atomically claims the reserved byte lease.
    fn finish_decision(&self, _token: &str, _accepted: bool) -> Result<(), ProtocolError> {
        Ok(())
    }
    fn execute(
        &self,
        command: String,
        args: serde_json::Map<String, serde_json::Value>,
        lease: OperationLease,
    ) -> impl std::future::Future<Output = NativeOutcome> + Send;
    /// Success proves resource teardown, not merely a cancellation request.
    fn shutdown(&self) -> impl std::future::Future<Output = Result<(), ProtocolError>> + Send;
}

const MAX_STAGED_EVENTS: usize = 64;
const MAX_STAGED_BYTES: usize = 4 * MAX_FRAME_BYTES;
#[derive(Default)]
struct EventOrder {
    sequence: u64,
    barriers: std::collections::HashMap<(u64, u64), std::sync::Arc<EventBarrier>>,
    scope_gates: std::collections::HashMap<(u64, String), std::sync::Weak<ScopeEmissionGate>>,
    staged_count: usize,
    staged_bytes: usize,
}
struct ScopeEmissionGate {
    closed: std::sync::atomic::AtomicBool,
}
struct EventBarrier {
    key: (u64, u64),
    identity_scope: String,
    recovery_owner: Option<std::sync::Arc<super::client_debt::OwnerDebtLedger>>,
    scope_gate: std::sync::Arc<ScopeEmissionGate>,
    deadline: std::time::Instant,
    state: std::sync::Mutex<EventBarrierState>,
    reopened_result: std::sync::Mutex<Option<super::client_restart::ReopenedResultIdentity>>,
    changed: tokio::sync::Notify,
}
/// Non-owning identity of one exact staging barrier; retaining a reopen proof
/// must not create a sink/barrier reference cycle.
#[derive(Clone)]
pub(super) struct ReopenedResultBinding(std::sync::Weak<EventBarrier>);
impl ReopenedResultBinding {
    pub(super) fn matches(&self, sink: &ClientEventSink) -> bool {
        self.0.upgrade().is_some_and(|barrier| {
            sink.barrier
                .as_ref()
                .is_some_and(|current| std::sync::Arc::ptr_eq(&barrier, current))
        })
    }
}
enum EventBarrierState {
    Holding(Vec<StagedEvent>),
    Live,
    Discarded,
}
struct StagedEvent {
    message: ServerMessage,
    bytes: usize,
    decision_deadline: Option<std::time::Instant>,
}
/// Native authority retirement only. Queue acceptance is not writer flush or
/// peer receipt, and local-only retirement makes no notification claim at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeCallbackRetirement {
    NoticeQueued,
    LocalOnlyTerminal,
}
/// Reliable bounded event lane. A replacement producer receives a distinct
/// operation-bound clone; old callback producers retain their live clone.
#[derive(Clone)]
pub struct ClientEventSink {
    sender: mpsc::Sender<ServerMessage>,
    broker: std::sync::Arc<ClientSession>,
    sequence: std::sync::Arc<std::sync::Mutex<EventOrder>>,
    open: std::sync::Arc<std::sync::atomic::AtomicBool>,
    barrier: Option<std::sync::Arc<EventBarrier>>,
    persistent_page_reopen: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl ClientEventSink {
    pub(crate) fn persistent_page_reopen_negotiated(&self) -> bool {
        self.persistent_page_reopen
            .load(std::sync::atomic::Ordering::Acquire)
    }
    #[cfg(test)]
    pub(crate) fn test_channel(
        broker: std::sync::Arc<ClientSession>,
    ) -> (Self, mpsc::Receiver<ServerMessage>) {
        let (sender, receiver) = mpsc::channel(64);
        (
            Self {
                sender,
                broker,
                sequence: Default::default(),
                open: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
                barrier: None,
                persistent_page_reopen: Default::default(),
            },
            receiver,
        )
    }
    #[cfg(test)]
    pub(crate) fn negotiate_reopen_for_test(&self) {
        self.persistent_page_reopen
            .store(true, std::sync::atomic::Ordering::Release);
    }
    /// Native lifecycle-only. No waiting task or action lock is held by the
    /// barrier: the actual result writer performs publication after flush.
    pub(crate) fn stage_until_result(
        &self,
        operation: &OperationLease,
        identity_scope: &str,
    ) -> Result<Self, ProtocolError> {
        let recovery_owner = self
            .broker
            .staged_recovery_owner(operation, identity_scope)?;
        if recovery_owner.is_some() {
            if !self.open.load(std::sync::atomic::Ordering::Acquire) {
                return Err(ProtocolError::ScopeUnavailable);
            }
        } else {
            self.check_open()?;
        }
        if identity_scope.is_empty()
            || identity_scope.len() > 256
            || identity_scope.chars().any(char::is_control)
        {
            return Err(ProtocolError::InvalidArguments);
        }
        if operation.is_callback || operation.sequence == 0 {
            return Err(ProtocolError::InvalidSequence);
        }
        if *operation.cancellation.borrow() != super::client_session::CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if std::time::Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        if self.broker.health()?.0 != operation.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        let mut order = self
            .sequence
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let key = (operation.generation, operation.sequence);
        if order.barriers.contains_key(&key) {
            return Err(ProtocolError::InvalidSequence);
        }
        if order.barriers.len() >= 64 {
            return Err(ProtocolError::CapacityExceeded);
        }
        order.scope_gates.retain(|_, gate| gate.strong_count() != 0);
        let scope_key = (operation.generation, identity_scope.to_owned());
        let scope_gate = match order
            .scope_gates
            .get(&scope_key)
            .and_then(std::sync::Weak::upgrade)
        {
            Some(gate) => {
                if gate.closed.load(std::sync::atomic::Ordering::Acquire) {
                    return Err(ProtocolError::StaleScope);
                }
                gate
            }
            None => {
                if order.scope_gates.len() >= 64 {
                    return Err(ProtocolError::CapacityExceeded);
                }
                let gate = std::sync::Arc::new(ScopeEmissionGate {
                    closed: std::sync::atomic::AtomicBool::new(false),
                });
                order
                    .scope_gates
                    .insert(scope_key, std::sync::Arc::downgrade(&gate));
                gate
            }
        };
        let barrier = std::sync::Arc::new(EventBarrier {
            key,
            identity_scope: identity_scope.into(),
            recovery_owner,
            scope_gate,
            deadline: operation.deadline,
            state: std::sync::Mutex::new(EventBarrierState::Holding(Vec::new())),
            reopened_result: std::sync::Mutex::new(None),
            changed: tokio::sync::Notify::new(),
        });
        order.barriers.insert(key, barrier.clone());
        Ok(Self {
            barrier: Some(barrier),
            ..self.clone()
        })
    }
    pub(crate) fn validate_stage(
        &self,
        source: &Self,
        operation: &OperationLease,
        identity_scope: &str,
    ) -> Result<(), ProtocolError> {
        let generation = self.check_open()?;
        if !std::sync::Arc::ptr_eq(&self.sequence, &source.sequence)
            || !std::sync::Arc::ptr_eq(&self.broker, &source.broker)
        {
            return Err(ProtocolError::StaleScope);
        }
        let barrier = self.barrier.as_ref().ok_or(ProtocolError::StaleScope)?;
        if generation != barrier.key.0
            || barrier.key != (operation.generation, operation.sequence)
            || barrier.identity_scope != identity_scope
        {
            return Err(ProtocolError::StaleScope);
        }
        if *operation.cancellation.borrow() != super::client_session::CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if std::time::Instant::now() >= barrier.deadline
            || std::time::Instant::now() >= operation.deadline
        {
            return Err(ProtocolError::DeadlineExceeded);
        }
        if !matches!(
            *barrier
                .state
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?,
            EventBarrierState::Holding(_)
        ) {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    pub(super) fn reopened_result_binding(&self) -> Result<ReopenedResultBinding, ProtocolError> {
        Ok(ReopenedResultBinding(std::sync::Arc::downgrade(
            self.barrier.as_ref().ok_or(ProtocolError::StaleScope)?,
        )))
    }

    /// Only the create-only reopen's typed owner proof can bind a command result
    /// without a public identityScope field. Confirmation is not publication.
    pub(super) fn confirm_reopened_result(
        &self,
        source: &Self,
        operation: &OperationLease,
        proof: &super::client_restart::ReopenedResultIdentity,
    ) -> Result<(), ProtocolError> {
        let barrier = self.barrier.as_ref().ok_or(ProtocolError::StaleScope)?;
        self.validate_stage(source, operation, &barrier.identity_scope)?;
        if !self.persistent_page_reopen_negotiated()
            || !proof.matches(
                self,
                operation.generation,
                operation.sequence,
                &barrier.identity_scope,
            )
        {
            return Err(ProtocolError::StaleScope);
        }
        let _order = self
            .sequence
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        self.check_open()?;
        if *operation.cancellation.borrow() != super::client_session::CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if std::time::Instant::now() >= barrier.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        let state = barrier
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if barrier
            .scope_gate
            .closed
            .load(std::sync::atomic::Ordering::Acquire)
            || !matches!(*state, EventBarrierState::Holding(_))
        {
            return Err(ProtocolError::StaleScope);
        }
        let mut confirmed = barrier
            .reopened_result
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if confirmed.is_some() {
            return Err(ProtocolError::InvalidSequence);
        }
        *confirmed = Some(proof.clone());
        Ok(())
    }

    pub(crate) fn is_publication_pending(&self) -> Result<bool, ProtocolError> {
        let generation = self.check_open()?;
        let Some(barrier) = &self.barrier else {
            return Ok(false);
        };
        if barrier.key.0 != generation {
            return Err(ProtocolError::StaleGeneration);
        }
        match &*barrier
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
        {
            EventBarrierState::Holding(_) => {
                if std::time::Instant::now() >= barrier.deadline {
                    return Err(ProtocolError::DeadlineExceeded);
                }
                Ok(true)
            }
            EventBarrierState::Live => Ok(false),
            EventBarrierState::Discarded => Err(ProtocolError::StaleScope),
        }
    }
    /// Called before acquiring any callback/UI admission lease. Native event
    /// bytes and decision tokens remain retained by the caller while waiting.
    pub(crate) async fn wait_publication(
        &self,
        deadline: std::time::Instant,
        mut cancellation: tokio::sync::watch::Receiver<super::client_session::CancelSignal>,
    ) -> Result<(), ProtocolError> {
        loop {
            if *cancellation.borrow() != super::client_session::CancelSignal::None {
                return Err(ProtocolError::Cancelled);
            }
            if std::time::Instant::now() >= deadline {
                return Err(ProtocolError::DeadlineExceeded);
            }
            let Some(barrier) = &self.barrier else {
                self.check_open()?;
                return Ok(());
            };
            let changed = barrier.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self.is_publication_pending()? {
                return Ok(());
            }
            tokio::select! {
                biased;
                _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                _ = tokio::time::sleep_until(std::cmp::min(deadline,barrier.deadline).into()) => return Err(ProtocolError::DeadlineExceeded),
                _ = changed => {},
            }
        }
    }
    fn check_open(&self) -> Result<u64, ProtocolError> {
        if !self.open.load(std::sync::atomic::Ordering::Acquire) {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let (generation, health) = self.broker.health()?;
        if let Some(barrier) = &self.barrier {
            if barrier
                .scope_gate
                .closed
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return Err(ProtocolError::StaleScope);
            }
            if barrier.recovery_owner.is_some() {
                self.broker.check_scoped_owner(
                    generation,
                    &barrier.identity_scope,
                    barrier.recovery_owner.as_ref(),
                )?;
                return Ok(generation);
            }
        }
        if health != ScopeState::Usable {
            return Err(ProtocolError::ScopeUnavailable);
        }
        Ok(generation)
    }
    fn enqueue_event(
        &self,
        order: &mut EventOrder,
        mut message: ServerMessage,
    ) -> Result<(), ProtocolError> {
        if order.sequence >= MAX_SAFE_SEQUENCE {
            return Err(ProtocolError::IdentifierExhausted);
        }
        order.sequence += 1;
        if let ServerMessage::Event { sequence, .. } = &mut message {
            *sequence = order.sequence;
        }
        self.sender
            .try_send(message)
            .map_err(|_| ProtocolError::CapacityExceeded)
    }
    /// Exact native reader EOF notice. False means not queued because the old
    /// scope is already quarantined; it never means peer delivery or recovery.
    /// Unlike ordinary publication this path cannot re-quarantine a replacement
    /// while an old watcher is finishing. Lifecycle still joins that watcher.
    pub(crate) fn emit_disconnected(
        &self,
        client: &std::sync::Arc<super::cdp::client::CdpClient>,
        targets: &std::sync::Arc<super::client_targets::ClientTargets>,
    ) -> Result<bool, ProtocolError> {
        let debt = client.debt_ledger().ok_or(ProtocolError::StaleScope)?;
        if !*client.remote_connection_closed().borrow() {
            return Err(ProtocolError::StaleScope);
        }
        targets.require_eval_owner(&debt)?;
        client.check_cleanup_owner(&Some(debt.clone()))?;
        let result = {
            let mut order = self
                .sequence
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            let (generation, health) = self.broker.health()?;
            if !debt.matches_owner(generation, &targets.identity_scope) {
                return Err(ProtocolError::StaleScope);
            }
            if health == ScopeState::Quarantined {
                return Ok(false);
            }
            if health != ScopeState::Usable || !self.open.load(std::sync::atomic::Ordering::Acquire)
            {
                return Err(ProtocolError::ScopeUnavailable);
            }
            self.enqueue_event(
                &mut order,
                ServerMessage::Event {
                    generation,
                    sequence: 0,
                    event: "browser.disconnected".into(),
                    payload: serde_json::json!({"reason":"browser-connection-closed"}),
                    decision: None,
                },
            )
        };
        if result.is_err() {
            let _ = self.broker.quarantine();
        }
        result.map(|()| true)
    }
    /// Private operation-owned rendezvous, never a reopened ordinary scope sink.
    /// The caller retains the original replacement supervisor and owner journal;
    /// the control lane only selects a bounded, one-use typed response.
    pub(crate) fn emit_interop_decision(
        &self,
        operation: &OperationLease,
        identity_scope: &str,
        kind: super::client_session::DecisionKind,
        lease: &super::client_session::DecisionLease,
        context_id: Option<&str>,
    ) -> Result<(), ProtocolError> {
        use super::client_session::DecisionKind;
        if self.barrier.is_some()
            || identity_scope.is_empty()
            || lease.generation != operation.generation
        {
            return Err(ProtocolError::StaleScope);
        }
        let phase = match (kind, context_id) {
            (DecisionKind::InteropRetire, Some(id))
                if !id.is_empty() && id.len() <= 1024 && !id.chars().any(char::is_control) =>
            {
                "retire"
            }
            (DecisionKind::InteropCreate, None) => "create",
            _ => return Err(ProtocolError::InvalidArguments),
        };
        self.broker
            .validate_interop_decision(operation, &lease.token, kind)?;
        let left = lease
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(ProtocolError::DecisionExpired);
        }
        let mut payload = serde_json::json!({
            "version": 1,
            "identityScope": identity_scope,
            "operationSeq": operation.sequence,
            "phase": phase,
        });
        if let Some(id) = context_id {
            payload["contextId"] = id.into();
        }
        self.emit(
            "scope.interop.replacement".into(),
            payload,
            Some(DecisionNotice {
                token: lease.token.clone(),
                timeout_ms: u64::try_from(left.as_millis())
                    .unwrap_or(MAX_TIMEOUT_MS)
                    .min(MAX_TIMEOUT_MS)
                    .max(1),
            }),
        )
    }

    pub fn emit(
        &self,
        event: String,
        payload: serde_json::Value,
        decision: Option<DecisionNotice>,
    ) -> Result<(), ProtocolError> {
        let generation = self.check_open()?;
        if let Some(barrier) = &self.barrier {
            if generation != barrier.key.0 {
                return Err(ProtocolError::StaleGeneration);
            }
            if payload
                .get("identityScope")
                .and_then(serde_json::Value::as_str)
                != Some(barrier.identity_scope.as_str())
            {
                return Err(ProtocolError::StaleScope);
            }
        }
        let decision_deadline = decision.as_ref().map(|notice| {
            std::time::Instant::now() + std::time::Duration::from_millis(notice.timeout_ms)
        });
        // Size against the largest sequence representation, allocated only at
        // real enqueue so staged events cannot invert live event ordering.
        let message = ServerMessage::Event {
            generation,
            sequence: MAX_SAFE_SEQUENCE,
            event,
            payload,
            decision,
        };
        let bytes = serde_json::to_vec(&message)
            .map_err(|_| ProtocolError::InvalidFrame)?
            .len();
        let result = (|| {
            if bytes > MAX_FRAME_BYTES {
                return Err(ProtocolError::CapacityExceeded);
            }
            let mut order = self
                .sequence
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            self.check_open()?;
            if let Some(barrier) = &self.barrier {
                if barrier
                    .scope_gate
                    .closed
                    .load(std::sync::atomic::Ordering::Acquire)
                {
                    return Err(ProtocolError::StaleScope);
                }
                let mut state = barrier
                    .state
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                match &mut *state {
                    EventBarrierState::Discarded => return Err(ProtocolError::StaleScope),
                    EventBarrierState::Holding(events) => {
                        if std::time::Instant::now() >= barrier.deadline {
                            return Err(ProtocolError::DeadlineExceeded);
                        }
                        if order.staged_count >= MAX_STAGED_EVENTS
                            || bytes > MAX_STAGED_BYTES.saturating_sub(order.staged_bytes)
                        {
                            return Err(ProtocolError::CapacityExceeded);
                        }
                        order.staged_count += 1;
                        order.staged_bytes += bytes;
                        events.push(StagedEvent {
                            message,
                            bytes,
                            decision_deadline,
                        });
                        return Ok(());
                    }
                    EventBarrierState::Live => {}
                }
            }
            self.enqueue_event(&mut order, message)
        })();
        if result.is_err() && result != Err(ProtocolError::StaleScope) {
            let _ = self.broker.quarantine();
        }
        result
    }
    pub(crate) fn same_client(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.broker, &other.broker)
            && std::sync::Arc::ptr_eq(&self.sequence, &other.sequence)
    }
    /// Caller has stopped enrollment intake, revoked exact-scope decision
    /// admission and joined every asynchronous event producer. This proves only
    /// callback authority retirement, not file/encoder/browser cleanup.
    pub(crate) fn retire_callbacks_after_terminal_drain(
        &self,
        proof: &super::client_enrollment::NativeTerminalProof,
    ) -> Result<NativeCallbackRetirement, ProtocolError> {
        proof.check_event_sink(self)?;
        proof.check_targets(proof.targets())?;
        self.retire_scope_callbacks_checked(
            proof.generation(),
            &proof.targets().identity_scope,
            Some(proof),
        )
    }
    pub(crate) fn retire_callbacks_after_final_local_drain(
        &self,
        proof: &super::client_enrollment::FinalLocalEofProof,
    ) -> Result<(), ProtocolError> {
        proof.check_event_sink(self)?;
        self.retire_scope_callbacks(proof.generation(), proof.identity_scope())
    }
    fn retire_scope_callbacks(&self, generation: u64, scope: &str) -> Result<(), ProtocolError> {
        self.retire_scope_callbacks_checked(generation, scope, None)
            .map(|_| ())
    }
    fn retire_scope_callbacks_checked(
        &self,
        generation: u64,
        scope: &str,
        terminal: Option<&super::client_enrollment::NativeTerminalProof>,
    ) -> Result<NativeCallbackRetirement, ProtocolError> {
        let barrier = self.barrier.as_ref().ok_or(ProtocolError::StaleScope)?;
        if barrier.key.0 != generation || barrier.identity_scope != scope {
            return Err(ProtocolError::StaleScope);
        }
        let result = (|| {
            let mut order = self
                .sequence
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            // Preserve the ordinary/final-local error contract. Only a checked
            // NativeTerminalProof may take the local-only retirement branch.
            if terminal.is_none() {
                self.check_open()?;
            }
            let (current, health) = self.broker.health()?;
            if current != generation {
                return Err(ProtocolError::StaleGeneration);
            }
            if !order
                .scope_gates
                .get(&(generation, scope.to_owned()))
                .and_then(std::sync::Weak::upgrade)
                .is_some_and(|gate| std::sync::Arc::ptr_eq(&gate, &barrier.scope_gate))
            {
                return Err(ProtocolError::StaleScope);
            }
            if barrier
                .scope_gate
                .closed
                .load(std::sync::atomic::Ordering::Acquire)
                || order
                    .barriers
                    .values()
                    .any(|pending| std::sync::Arc::ptr_eq(&pending.scope_gate, &barrier.scope_gate))
            {
                return Err(ProtocolError::StaleScope);
            }
            if !matches!(
                *barrier
                    .state
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?,
                EventBarrierState::Live
            ) {
                return Err(ProtocolError::StaleScope);
            }
            // Live is the existing witness that this exact scope's successful
            // result was flushed. It excludes the initial open=false state:
            // startup's sole open=true write precedes every production Live.
            // Under this same mutex, sealing the shared gate fences every old
            // scope clone, even if quarantine precedes close_publications.
            let local_only = !self.open.load(std::sync::atomic::Ordering::Acquire)
                || health == ScopeState::Quarantined;
            if health == ScopeState::Closed {
                return Err(ProtocolError::ScopeUnavailable);
            }
            if local_only {
                terminal
                    .ok_or(ProtocolError::ScopeUnavailable)?
                    .check_local_retirement_owner(&self.broker)?;
            }
            // Seal before enqueue. Queue failure must never reopen old producers
            // or be reclassified as successful local-only retirement.
            barrier
                .scope_gate
                .closed
                .store(true, std::sync::atomic::Ordering::Release);
            if local_only {
                return Ok(NativeCallbackRetirement::LocalOnlyTerminal);
            }
            let through = order.sequence;
            self.enqueue_event(&mut order, ServerMessage::Event {
                generation, sequence: MAX_SAFE_SEQUENCE,
                event: "scope.callbacks-retired".into(),
                payload: serde_json::json!({"identityScope":scope,"throughEventSequence":through}),
                decision: None,
            })
            .map(|()| NativeCallbackRetirement::NoticeQueued)
        })();
        if result.is_err() && result != Err(ProtocolError::StaleScope) {
            let _ = self.broker.quarantine();
        }
        result
    }
    #[cfg(test)]
    pub(crate) fn close_publications_for_test(&self) {
        self.close_publications();
    }
    #[cfg(test)]
    pub(crate) fn acknowledge_result_for_test(
        &self,
        message: &ServerMessage,
    ) -> Result<(), ProtocolError> {
        self.result_written(message)
    }
    /// Only called by the single writer AFTER write_all and flush succeeded.
    fn result_written(&self, message: &ServerMessage) -> Result<(), ProtocolError> {
        let ServerMessage::Result {
            generation,
            operation_seq,
            ok,
            data,
            effects,
            scope_state,
            ..
        } = message
        else {
            return Ok(());
        };
        let mut order = self
            .sequence
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let Some(barrier) = order.barriers.remove(&(*generation, *operation_seq)) else {
            return Ok(());
        };
        let mut state = barrier
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let EventBarrierState::Holding(events) =
            std::mem::replace(&mut *state, EventBarrierState::Discarded)
        else {
            return Err(ProtocolError::StaleScope);
        };
        // State is already Discarded until every checked enqueue succeeds.
        // Wake waiters on both success and every early-return failure below.
        barrier.changed.notify_waiters();
        order.staged_count -= events.len();
        order.staged_bytes -= events.iter().map(|event| event.bytes).sum::<usize>();
        if !ok || *scope_state != ScopeState::Usable || *effects != Effects::Completed {
            return Ok(());
        }
        let publication = Self {
            barrier: Some(barrier.clone()),
            ..self.clone()
        };
        match data.as_ref().and_then(|value| value.get("identityScope")) {
            Some(serde_json::Value::String(scope)) if scope == &barrier.identity_scope => {}
            None if data.is_some()
                && barrier
                    .reopened_result
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .as_ref()
                    .is_some_and(|proof| {
                        proof.matches(
                            &publication,
                            *generation,
                            *operation_seq,
                            &barrier.identity_scope,
                        )
                    }) => {}
            _ => return Err(ProtocolError::StaleScope),
        }
        self.check_open()?;
        if barrier
            .scope_gate
            .closed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(ProtocolError::StaleScope);
        }
        if std::time::Instant::now() >= barrier.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        for mut event in events {
            if let Some(deadline) = event.decision_deadline {
                let remaining = deadline
                    .checked_duration_since(std::time::Instant::now())
                    .ok_or(ProtocolError::DeadlineExceeded)?;
                let millis = u64::try_from(remaining.as_millis())
                    .map_err(|_| ProtocolError::CapacityExceeded)?;
                if millis == 0 {
                    return Err(ProtocolError::DeadlineExceeded);
                }
                if let ServerMessage::Event {
                    decision: Some(notice),
                    ..
                } = &mut event.message
                {
                    notice.timeout_ms = millis;
                }
            }
            self.enqueue_event(&mut order, event.message)?;
        }
        *state = EventBarrierState::Live;
        Ok(())
    }
    fn expire_publications(&self) -> Result<(), ProtocolError> {
        let order = self
            .sequence
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if order
            .barriers
            .values()
            .any(|barrier| std::time::Instant::now() >= barrier.deadline)
        {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(())
    }
    fn close_publications(&self) {
        self.open.store(false, std::sync::atomic::Ordering::Release);
        if let Ok(mut order) = self.sequence.lock() {
            for (_, barrier) in order.barriers.drain() {
                if let Ok(mut state) = barrier.state.lock() {
                    *state = EventBarrierState::Discarded;
                }
                barrier.changed.notify_waiters();
            }
            order.staged_bytes = 0;
            order.staged_count = 0;
        }
    }
}

/// Bound allocation while reading, including an unterminated hostile frame.
pub async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    #[cfg(feature = "acceptance-faults")]
    {
        read_frame_retained(reader, &mut Vec::new(), None).await
    }
    #[cfg(not(feature = "acceptance-faults"))]
    {
        read_frame_retained(reader, &mut Vec::new()).await
    }
}

// The transport select loop owns this buffer across timer/control/completion
// branches. fill_buf is cancellation-safe; consumed bytes must also survive
// cancellation of the future which is waiting for the remaining frame.
async fn read_frame_retained<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    frame: &mut Vec<u8>,
    #[cfg(feature = "acceptance-faults")] mut trace: Option<
        &mut super::client_settlement_trace::FrameTrace,
    >,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    loop {
        let available = match reader.fill_buf().await {
            Ok(available) => available,
            Err(_error) => {
                #[cfg(feature = "acceptance-faults")]
                if let Some(trace) = trace.as_deref_mut() {
                    trace.observe(
                        SettlementPhase::FrameIoError,
                        None,
                        Some(super::client_settlement_trace::IoClass::error(&_error)),
                    );
                }
                return Err(ProtocolError::InvalidFrame);
            }
        };
        if available.is_empty() {
            #[cfg(feature = "acceptance-faults")]
            if let Some(trace) = trace.as_deref_mut() {
                trace.observe(
                    if frame.is_empty() {
                        SettlementPhase::FrameCleanEof
                    } else {
                        SettlementPhase::FramePartialEof
                    },
                    None,
                    None,
                );
            }
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(ProtocolError::InvalidFrame)
            };
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let length = newline.unwrap_or(available.len());
        if frame.len() + length > MAX_FRAME_BYTES {
            #[cfg(feature = "acceptance-faults")]
            if let Some(trace) = trace.as_deref_mut() {
                trace.observe(
                    SettlementPhase::FrameOversize,
                    Some(frame.len() + length),
                    None,
                );
            }
            return Err(ProtocolError::InvalidFrame);
        }
        frame.extend_from_slice(&available[..length]);
        reader.consume(length + usize::from(newline.is_some()));
        #[cfg(feature = "acceptance-faults")]
        if let Some(trace) = trace.as_deref_mut() {
            trace.consumed(
                length + usize::from(newline.is_some()),
                if newline.is_some() { 0 } else { frame.len() },
            );
        }
        if newline.is_some() {
            #[cfg(feature = "acceptance-faults")]
            if let Some(trace) = trace.as_deref_mut() {
                trace.observe(SettlementPhase::FrameComplete, Some(frame.len() + 1), None);
            }
            return Ok(Some(std::mem::take(frame)));
        }
    }
}

struct Outgoing {
    control: mpsc::Sender<ServerMessage>,
    results: mpsc::Sender<ServerMessage>,
}

fn enqueue(sender: &Outgoing, message: ServerMessage, broker: &ClientSession) -> bool {
    let lane = if matches!(
        &message,
        ServerMessage::Result { .. } | ServerMessage::Closed { .. }
    ) {
        &sender.results
    } else {
        &sender.control
    };
    if lane.try_send(message).is_err() {
        let _ = broker.quarantine();
        return false;
    }
    true
}

pub async fn refuse<W: AsyncWrite + Unpin>(
    writer: &mut W,
    id: Option<String>,
    code: ProtocolError,
) {
    let message = ServerMessage::Error {
        id,
        error: WireError { code },
        scope_state: ScopeState::Closed,
    };
    if let Ok(mut bytes) = serde_json::to_vec(&message) {
        bytes.push(b'\n');
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            writer.write_all(&bytes).await?;
            writer.flush().await
        })
        .await;
    }
}

pub async fn serve<R, W>(
    reader: R,
    writer: W,
    hello: ClientMessage,
    #[cfg(feature = "acceptance-faults")] hello_frame_bytes: usize,
) -> bool
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let broker = std::sync::Arc::new(ClientSession::new());
    let executor = std::sync::Arc::new(super::client_browser::ClientBrowser::new(broker.clone()));
    #[cfg(feature = "acceptance-faults")]
    {
        serve_with_executor_inner(
            reader,
            writer,
            hello,
            broker,
            executor,
            Some(hello_frame_bytes),
        )
        .await
    }
    #[cfg(not(feature = "acceptance-faults"))]
    {
        serve_with_executor_inner(reader, writer, hello, broker, executor).await
    }
}

/// Reader/control work never takes the executor's browser lock. False means
/// cleanup is unproven and the daemon MUST retain its exclusive ownership gate.
#[cfg(test)]
pub async fn serve_with_executor<R, W, E>(
    reader: R,
    writer: W,
    hello: ClientMessage,
    broker: std::sync::Arc<ClientSession>,
    executor: std::sync::Arc<E>,
) -> bool
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
    E: ClientExecutor,
{
    #[cfg(feature = "acceptance-faults")]
    {
        serve_with_executor_inner(reader, writer, hello, broker, executor, None).await
    }
    #[cfg(not(feature = "acceptance-faults"))]
    {
        serve_with_executor_inner(reader, writer, hello, broker, executor).await
    }
}

async fn serve_with_executor_inner<R, W, E>(
    mut reader: R,
    mut writer: W,
    hello: ClientMessage,
    broker: std::sync::Arc<ClientSession>,
    executor: std::sync::Arc<E>,
    #[cfg(feature = "acceptance-faults")] hello_frame_bytes: Option<usize>,
) -> bool
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
    E: ClientExecutor,
{
    #[cfg(feature = "acceptance-faults")]
    let mut frame_trace = super::client_settlement_trace::FrameTrace::new(hello_frame_bytes);
    let outstanding = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        String,
        bool,
    >::new()));
    let (control, mut controls) = mpsc::channel::<ServerMessage>(64);
    let (results, mut results_rx) = mpsc::channel::<ServerMessage>(64);
    let sender = Outgoing { control, results };
    let sink_open = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let event_order = std::sync::Arc::new(std::sync::Mutex::new(EventOrder::default()));
    let sink = ClientEventSink {
        sender: sender.control.clone(),
        broker: broker.clone(),
        sequence: event_order.clone(),
        open: sink_open.clone(),
        barrier: None,
        persistent_page_reopen: Default::default(),
    };
    let (drain, mut drain_requested) = tokio::sync::oneshot::channel::<()>();
    let (failed, mut failure) = tokio::sync::oneshot::channel::<()>();
    let writing_ids = outstanding.clone();
    let writer_sink = sink.clone();
    let writer_task = tokio::spawn(async move {
        let mut control_open = true;
        let mut results_open = true;
        let mut draining = false;
        while control_open || results_open {
            let message = tokio::select! {
                biased;
                _ = &mut drain_requested, if !draining => { draining = true; controls.close(); results_rx.close(); continue; },
                next = controls.recv(), if control_open => match next {
                    Some(message) => message, None => { control_open = false; continue; }
                },
                next = results_rx.recv(), if results_open => match next {
                    Some(message) => message, None => { results_open = false; continue; }
                },
            };
            let Ok(mut bytes) = serde_json::to_vec(&message) else {
                break;
            };
            if bytes.len() > MAX_FRAME_BYTES {
                break;
            }
            bytes.push(b'\n');
            if !matches!(
                tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    writer.write_all(&bytes).await?;
                    writer.flush().await
                })
                .await,
                Ok(Ok(()))
            ) {
                break;
            }
            #[cfg(feature = "acceptance-faults")]
            match &message {
                ServerMessage::Result {
                    operation_seq,
                    generation,
                    effects,
                    scope_state,
                    error,
                    ..
                } => {
                    super::client_settlement_trace::record(
                        *operation_seq,
                        SettlementPhase::ResultFlushed,
                        super::client_settlement_trace::Facts {
                            generation: Some(*generation),
                            effects: Some(*effects),
                            scope_state: Some(*scope_state),
                            error: error.as_ref().map(|error| error.code.clone()),
                            accepted: None,
                            ..Default::default()
                        },
                    );
                }
                ServerMessage::ControlResult {
                    generation,
                    accepted,
                    scope_state,
                    error,
                    ..
                } => {
                    super::client_settlement_trace::record(
                        0,
                        SettlementPhase::ControlFlushed,
                        super::client_settlement_trace::Facts {
                            generation: Some(*generation),
                            effects: None,
                            scope_state: Some(*scope_state),
                            error: error.as_ref().map(|error| error.code.clone()),
                            accepted: Some(*accepted),
                            ..Default::default()
                        },
                    );
                }
                _ => {}
            }
            if writer_sink.result_written(&message).is_err() {
                let _ = writer_sink.broker.quarantine();
                break;
            }
            let id = match &message {
                ServerMessage::Ready { id, .. }
                | ServerMessage::Result { id, .. }
                | ServerMessage::ControlResult { id, .. }
                | ServerMessage::Closed { id, .. } => Some(id),
                ServerMessage::Error { id, .. } => id.as_ref(),
                ServerMessage::Event { .. } => None,
            };
            if let Some(id) = id {
                if let Ok(mut ids) = writing_ids.lock() {
                    ids.remove(id);
                }
            }
        }
        writer_sink.close_publications();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), writer.shutdown()).await;
        let _ = failed.send(());
    });
    let ClientMessage::Hello {
        id,
        protocol,
        required_capabilities,
    } = hello
    else {
        writer_task.abort();
        return false;
    };
    if let Ok(mut ids) = outstanding.lock() {
        ids.insert(id.clone(), false);
    }
    let terminal_close_negotiated = required_capabilities
        .iter()
        .any(|capability| capability == "terminal.close/1");
    let mut capabilities = executor.capabilities();
    if !capabilities
        .iter()
        .any(|capability| capability == "terminal.close/1")
    {
        capabilities.push("terminal.close/1".into());
    }
    let continuation_negotiated = required_capabilities
        .iter()
        .any(|capability| capability == EXACT_OWNER_CONTINUATION)
        && capabilities
            .iter()
            .any(|capability| capability == EXACT_OWNER_CONTINUATION);
    let recovery_negotiated = required_capabilities
        .iter()
        .any(|capability| capability == DISCONNECTED_RECOVERY)
        && capabilities
            .iter()
            .any(|capability| capability == DISCONNECTED_RECOVERY);
    sink.persistent_page_reopen.store(
        required_capabilities
            .iter()
            .any(|capability| capability == PERSISTENT_PAGE_REOPEN)
            && capabilities
                .iter()
                .any(|capability| capability == PERSISTENT_PAGE_REOPEN),
        std::sync::atomic::Ordering::Release,
    );
    let terminal_recording_negotiated = terminal_close_negotiated
        && required_capabilities
            .iter()
            .any(|capability| capability == super::client_protocol::TERMINAL_RECORDING_ARTIFACTS)
        && capabilities
            .iter()
            .any(|capability| capability == super::client_protocol::TERMINAL_RECORDING_ARTIFACTS);
    let supported: Vec<_> = capabilities.iter().map(String::as_str).collect();
    let validation = validate_hello(&protocol, &required_capabilities, &supported)
        .and_then(|()| executor.set_event_sink(sink.clone()));
    let valid = validation.is_ok();
    let ready = match validation {
        Ok(()) => ServerMessage::Ready {
            id,
            protocol: PROTOCOL.into(),
            session_id: broker.id.clone(),
            generation: 1,
            capabilities,
            limits: Limits {
                max_frame_bytes: MAX_FRAME_BYTES,
                max_pending_operations: 64,
                max_pending_decisions: 256,
                max_timeout_ms: MAX_TIMEOUT_MS,
            },
            scope_state: ScopeState::Usable,
        },
        Err(code) => ServerMessage::Error {
            id: Some(id),
            error: WireError { code },
            scope_state: ScopeState::Closed,
        },
    };
    let ready_queued = enqueue(&sender, ready, &broker);
    if valid && ready_queued {
        sink_open.store(true, std::sync::atomic::Ordering::Release);
    }
    let mut operations = tokio::task::JoinSet::<(u64, NativeOutcome)>::new();
    let mut pending = std::collections::HashMap::<u64, (String, u64, bool, Option<String>)>::new();
    let mut closing_id = None;
    let mut terminal_control = false;
    let mut terminal_recording = None;
    let mut terminal_sequence = 0u64;
    // Retained across both phases: cancelling a read must not discard its prefix.
    let mut incoming_frame = Vec::new();
    let mut timer = tokio::time::interval(std::time::Duration::from_millis(25));
    if valid && ready_queued {
        loop {
            #[cfg(feature = "acceptance-faults")]
            let reading =
                read_frame_retained(&mut reader, &mut incoming_frame, Some(&mut frame_trace));
            #[cfg(not(feature = "acceptance-faults"))]
            let reading = read_frame_retained(&mut reader, &mut incoming_frame);
            let frame = tokio::select! {
                frame = reading => frame,
                _ = &mut failure => { settlement_trace!(0, WriterFailed); break; },
                _ = timer.tick() => {
                    let _ = broker.expire_decisions();
                    if sink.expire_publications().is_err() { settlement_trace!(0, PublicationExpired); let _ = broker.quarantine(); break; }
                    if !broker.health().is_ok_and(|(_, state)| state == ScopeState::Usable) && !broker.recovery_available() {
                        if terminal_close_negotiated && !operations.is_empty() { continue; }
                        // Expired/consumed recovery keeps only negotiated terminal cleanup.
                        terminal_control = terminal_close_negotiated && recovery_negotiated;
                        settlement_trace!(0, HealthFailed); break;
                    }
                    // Keep ordinary notifications owned until the replacement
                    // is usable. Do not drain then lose them during recovery.
                    if broker.recovery_available() { continue; }
                    for (version,identity_scope) in broker.take_released_registry_events(16).unwrap_or_default() {
                        let mut payload=serde_json::json!({ "registryVersion": version });
                        if let Some(scope)=identity_scope { payload["identityScope"]=serde_json::json!(scope); }
                        if sink.emit("registry-released".into(), payload, None).is_err() { break; }
                    }
                    if !broker.health().is_ok_and(|(_, state)| state == ScopeState::Usable) && !broker.recovery_available() {
                        if terminal_close_negotiated && !operations.is_empty() { continue; }
                        // Expired/consumed recovery keeps only negotiated terminal cleanup.
                        terminal_control = terminal_close_negotiated && recovery_negotiated;
                        settlement_trace!(0, HealthFailed); break;
                    }
                    continue;
                },
                completion = operations.join_next(), if !operations.is_empty() => {
                    let Some(Ok((sequence, outcome))) = completion else { settlement_trace!(0, CompletionLost); break; };
                    settlement_trace!(sequence, CompletionJoined);
                    let Some((id, generation, callback, scope)) = pending.remove(&sequence) else { settlement_trace!(sequence, CompletionLost); break; };
                    let state = broker.settle_with_retention(generation, sequence, outcome.effects,
                        if continuation_negotiated { outcome.retention.as_ref() } else { None }).unwrap_or(ScopeState::Quarantined);
                    executor.fix_operation_result(super::client_debt::OperationKey { generation, operation_seq: sequence });
                    let unknown = outcome.effects == Effects::Unknown;
                    let recovery = if recovery_negotiated && !callback && unknown && state == ScopeState::Quarantined {
                        executor.disconnected_recovery_candidate(super::client_debt::OperationKey { generation, operation_seq: sequence })
                            .and_then(|proof| {
                                let descriptor = RecoveryDescriptor { version: 1, identity_scope: proof.ledger().identity_scope().to_owned() };
                                broker.offer_disconnected_recovery(proof).ok().map(|()| descriptor)
                            })
                    } else { None };
                    let recoverable = recovery.is_some();
                    if !recoverable && !callback && outcome.result.is_err() && state == ScopeState::Quarantined {
                        let batch = executor.take_terminal_recording(super::client_debt::OperationKey { generation, operation_seq: sequence }, scope.as_deref());
                        if terminal_recording_negotiated { terminal_recording = batch; }
                    }
                    let mut message = result_message(id, generation, sequence, outcome, state);
                    if let ServerMessage::Result { recovery: field, .. } = &mut message { *field = recovery; }
                    if !enqueue(&sender, message, &broker) { settlement_trace!(sequence, ResultQueueFailed); break; }
                    settlement_trace!(sequence, ResultQueued);
                    if !recoverable && ((unknown && state != ScopeState::Usable) || state == ScopeState::Quarantined) {
                        terminal_control = terminal_close_negotiated;
                        settlement_trace!(sequence, UnknownOutcome); break;
                    }
                    continue;
                },
            };
            let message = match frame {
                Ok(Some(bytes)) => {
                    let parsed = parse_frame(&bytes);
                    #[cfg(feature = "acceptance-faults")]
                    if parsed.is_err() {
                        frame_trace.observe(
                            SettlementPhase::FrameParseRefused,
                            Some(bytes.len() + 1),
                            None,
                        );
                    }
                    parsed
                }
                Ok(None) => {
                    settlement_trace!(0, ReaderEnded);
                    break;
                }
                Err(error) => Err(error),
            };
            let message = match message {
                Ok(message) => message,
                Err(code) => {
                    settlement_trace!(0, ReaderRefused);
                    let _ = broker.quarantine();
                    enqueue(
                        &sender,
                        ServerMessage::Error {
                            id: None,
                            error: WireError { code },
                            scope_state: ScopeState::Quarantined,
                        },
                        &broker,
                    );
                    break;
                }
            };
            #[cfg(feature = "acceptance-faults")]
            frame_trace.message(SettlementPhase::FrameDecoded, &message);
            let id = match &message {
                ClientMessage::Hello { id, .. }
                | ClientMessage::Request { id, .. }
                | ClientMessage::Cancel { id, .. }
                | ClientMessage::Decision { id, .. }
                | ClientMessage::Close { id, .. } => id,
            };
            let is_operation = matches!(&message, ClientMessage::Request { .. });
            let admitted = outstanding
                .lock()
                .map(|mut ids| {
                    if ids.contains_key(id)
                        || ids.values().filter(|kind| **kind == is_operation).count() >= 64
                    {
                        return false;
                    }
                    ids.insert(id.clone(), is_operation);
                    true
                })
                .unwrap_or(false);
            if !admitted {
                #[cfg(feature = "acceptance-faults")]
                frame_trace.message(SettlementPhase::FrameAdmissionRefused, &message);
                let _ = broker.quarantine();
                enqueue(
                    &sender,
                    ServerMessage::Error {
                        id: None,
                        error: WireError {
                            code: ProtocolError::InvalidFrame,
                        },
                        scope_state: ScopeState::Quarantined,
                    },
                    &broker,
                );
                break;
            }
            match message {
                ClientMessage::Request {
                    id,
                    generation,
                    operation_seq,
                    timeout_ms,
                    callback_token,
                    command,
                    args,
                } => {
                    if operation_seq <= super::client_protocol::MAX_SAFE_SEQUENCE {
                        terminal_sequence = terminal_sequence.max(operation_seq);
                    }
                    if matches!(
                        command.as_str(),
                        "recording.finalized.collect"
                            | "recording.finalized.read"
                            | "recording.finalized.release"
                    ) {
                        // Reserved terminal controls cannot enter ordinary
                        // broker admission or executor dispatch while usable.
                        let (current, state) =
                            broker.health().unwrap_or((1, ScopeState::Quarantined));
                        let error = if generation != current {
                            ProtocolError::StaleGeneration
                        } else if state != ScopeState::Usable {
                            ProtocolError::ScopeUnavailable
                        } else {
                            ProtocolError::UnsupportedCommand
                        };
                        if !enqueue(
                            &sender,
                            result_message(
                                id,
                                generation,
                                operation_seq,
                                NativeOutcome {
                                    result: Err(error),
                                    effects: Effects::NotDispatched,
                                    retention: None,
                                },
                                state,
                            ),
                            &broker,
                        ) {
                            break;
                        }
                        continue;
                    }
                    let admitted = if recovery_negotiated
                        && command == "scope.reconnect"
                        && callback_token.is_none()
                        && broker
                            .health()
                            .is_ok_and(|(_, state)| state == ScopeState::Quarantined)
                    {
                        broker.admit_disconnected_reconnect(
                            generation,
                            operation_seq,
                            timeout_ms,
                            args.get("identityScope")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or_default(),
                        )
                    } else {
                        broker.admit_callback_capped(
                            generation,
                            operation_seq,
                            timeout_ms,
                            callback_token.as_deref(),
                            executor.admission_deadline_cap(generation, &command, &args),
                        )
                    };
                    match admitted {
                        Ok(lease) => {
                            pending.insert(
                                operation_seq,
                                (
                                    id,
                                    generation,
                                    callback_token.is_some(),
                                    args.get("identityScope")
                                        .and_then(serde_json::Value::as_str)
                                        .map(str::to_owned),
                                ),
                            );
                            let executor = executor.clone();
                            let broker = broker.clone();
                            operations.spawn(async move {
                                (
                                    operation_seq,
                                    execute_bounded(
                                        executor,
                                        broker,
                                        command,
                                        args,
                                        lease,
                                        continuation_negotiated,
                                    )
                                    .await,
                                )
                            });
                        }
                        Err(code) => {
                            let state = broker
                                .health()
                                .map(|(_, state)| state)
                                .unwrap_or(ScopeState::Quarantined);
                            if !enqueue(
                                &sender,
                                result_message(
                                    id,
                                    generation,
                                    operation_seq,
                                    NativeOutcome {
                                        retention: None,
                                        result: Err(code),
                                        effects: Effects::NotDispatched,
                                    },
                                    state,
                                ),
                                &broker,
                            ) {
                                break;
                            }
                            if state == ScopeState::Quarantined && !broker.recovery_available() {
                                terminal_control = terminal_close_negotiated;
                                break;
                            }
                        }
                    }
                }
                ClientMessage::Close { id, generation }
                    if broker
                        .health()
                        .is_ok_and(|(current, _)| current == generation) =>
                {
                    settlement_trace!(0, CloseReceived);
                    // Claim terminal authority before any other admitted task
                    // can submit a new application command on this generation.
                    let _ = broker.quarantine();
                    sink.close_publications();
                    closing_id = Some(id);
                    terminal_control = terminal_close_negotiated;
                    break;
                }
                other => {
                    #[cfg(feature = "acceptance-faults")]
                    let cancel_sequence = match &other {
                        ClientMessage::Cancel { operation_seq, .. } => Some(*operation_seq),
                        _ => None,
                    };
                    let (response, close) = respond(&broker, other, executor.as_ref());
                    if !enqueue(&sender, response, &broker) || close {
                        settlement_trace!(0, ControlQueueFailed);
                        break;
                    }
                    #[cfg(feature = "acceptance-faults")]
                    if let Some(sequence) = cancel_sequence {
                        settlement_trace!(sequence, CancelQueued);
                    }
                }
            }
        }
    }
    settlement_trace!(0, ShutdownStarted);
    // Seal before cancelling native work. EOF never proves resource teardown.
    sink.close_publications();
    let _ = broker.quarantine();
    operations.abort_all();
    // Shutdown and control share one cutoff, never renewed by incoming traffic.
    // The executor starts even if the peer never asks for its receipt.
    let cutoff = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let shutdown = async {
        // Aborting schedules cancellation; joining proves execution guards dropped.
        let drained = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while operations.join_next().await.is_some() {}
        })
        .await
        .is_ok();
        drained
            && matches!(
                tokio::time::timeout_at(
                    cutoff.min(tokio::time::Instant::now() + std::time::Duration::from_secs(5)),
                    executor.shutdown()
                )
                .await,
                Ok(Ok(()))
            )
    };
    tokio::pin!(shutdown);
    let mut shutdown_outcome = None;
    let mut control_trusted = true;
    if terminal_control {
        loop {
            if shutdown_outcome.is_some() && closing_id.is_some() {
                break;
            }
            #[cfg(feature = "acceptance-faults")]
            let reading =
                read_frame_retained(&mut reader, &mut incoming_frame, Some(&mut frame_trace));
            #[cfg(not(feature = "acceptance-faults"))]
            let reading = read_frame_retained(&mut reader, &mut incoming_frame);
            let frame = tokio::select! {
                biased;
                outcome = &mut shutdown, if shutdown_outcome.is_none() => {
                    shutdown_outcome = Some(outcome);
                    continue;
                },
                _ = tokio::time::sleep_until(cutoff) => { break; },
                frame = reading => frame,
            };
            let message = match frame {
                Ok(Some(bytes)) => match parse_frame(&bytes) {
                    Ok(message) => message,
                    Err(_) => {
                        control_trusted = false;
                        break;
                    }
                },
                _ => {
                    control_trusted = false;
                    break;
                }
            };
            let generation = broker
                .health()
                .map(|(generation, _)| generation)
                .unwrap_or(1);
            // The terminal lane retains ordinary framing/correlation bounds.
            // Reject a duplicate without echoing its ID: a second Result could
            // steal the outstanding writer receipt for the original request.
            let repeated_close = matches!(&message, ClientMessage::Close { id, generation: requested }
                if *requested == generation && closing_id.as_ref() == Some(id));
            if !repeated_close {
                let id = match &message {
                    ClientMessage::Hello { id, .. }
                    | ClientMessage::Request { id, .. }
                    | ClientMessage::Cancel { id, .. }
                    | ClientMessage::Decision { id, .. }
                    | ClientMessage::Close { id, .. } => id,
                };
                let is_operation = matches!(&message, ClientMessage::Request { .. });
                let admitted = outstanding.lock().is_ok_and(|mut ids| {
                    if ids.contains_key(id)
                        || ids.values().filter(|kind| **kind == is_operation).count() >= 64
                    {
                        return false;
                    }
                    ids.insert(id.clone(), is_operation);
                    true
                });
                if !admitted {
                    let _ = sender.results.try_send(ServerMessage::Error {
                        id: None,
                        error: WireError {
                            code: ProtocolError::InvalidFrame,
                        },
                        scope_state: ScopeState::Quarantined,
                    });
                    control_trusted = false;
                    break;
                }
            }
            let response = match message {
                ClientMessage::Close {
                    id,
                    generation: requested,
                } if requested == generation => {
                    // Only one cleanup exchange owns the receipt. A repeated
                    // identical Close does not extend the cutoff or send twice.
                    if closing_id.as_ref().is_none_or(|owned| owned == &id) {
                        closing_id = Some(id);
                        terminal_recording.take();
                        continue;
                    }
                    ServerMessage::Error {
                        id: Some(id),
                        error: WireError {
                            code: ProtocolError::ScopeUnavailable,
                        },
                        scope_state: ScopeState::Quarantined,
                    }
                }
                ClientMessage::Cancel {
                    id,
                    generation: requested,
                    operation_seq,
                } => {
                    // Correlation only; never admit an operation or a callback.
                    let result = broker.cancel(requested, operation_seq);
                    ServerMessage::ControlResult {
                        id,
                        generation,
                        accepted: result.is_ok(),
                        error: result.err().map(|code| WireError { code }),
                        scope_state: ScopeState::Quarantined,
                    }
                }
                ClientMessage::Request {
                    id,
                    generation: requested,
                    operation_seq,
                    timeout_ms,
                    callback_token,
                    command,
                    args,
                } if terminal_recording_negotiated
                    && closing_id.is_none()
                    && matches!(
                        command.as_str(),
                        "recording.finalized.collect"
                            | "recording.finalized.read"
                            | "recording.finalized.release"
                    ) =>
                {
                    let result = if requested != generation {
                        Err(ProtocolError::StaleGeneration)
                    } else if operation_seq == 0
                        || operation_seq > super::client_protocol::MAX_SAFE_SEQUENCE
                    {
                        Err(ProtocolError::InvalidSequence)
                    } else if operation_seq <= terminal_sequence {
                        Err(ProtocolError::SequenceReused)
                    } else {
                        // Independent terminal correlation only. Never advance
                        // or reopen the ordinary broker's operation admission.
                        terminal_sequence = operation_seq;
                        if callback_token.is_some()
                            || timeout_ms == 0
                            || timeout_ms > super::client_protocol::MAX_TIMEOUT_MS
                        {
                            Err(ProtocolError::InvalidArguments)
                        } else {
                            terminal_recording
                                .as_mut()
                                .ok_or(ProtocolError::ScopeUnavailable)
                                .and_then(|batch| batch.command(requested, &command, args))
                        }
                    };
                    let effects = if result.is_ok() {
                        Effects::Completed
                    } else {
                        Effects::NotDispatched
                    };
                    result_message(
                        id,
                        requested,
                        operation_seq,
                        NativeOutcome {
                            result,
                            effects,
                            retention: None,
                        },
                        ScopeState::Quarantined,
                    )
                }
                ClientMessage::Request {
                    id,
                    generation: requested,
                    operation_seq,
                    ..
                } => result_message(
                    id,
                    requested,
                    operation_seq,
                    NativeOutcome {
                        retention: None,
                        result: Err(if requested == generation {
                            ProtocolError::ScopeUnavailable
                        } else {
                            ProtocolError::StaleGeneration
                        }),
                        effects: Effects::NotDispatched,
                    },
                    ScopeState::Quarantined,
                ),
                ClientMessage::Decision { id, .. } => ServerMessage::ControlResult {
                    id,
                    generation,
                    accepted: false,
                    error: Some(WireError {
                        code: ProtocolError::ScopeUnavailable,
                    }),
                    scope_state: ScopeState::Quarantined,
                },
                ClientMessage::Close { id, .. } => ServerMessage::Error {
                    id: Some(id),
                    error: WireError {
                        code: ProtocolError::StaleGeneration,
                    },
                    scope_state: ScopeState::Quarantined,
                },
                ClientMessage::Hello { .. } => {
                    control_trusted = false;
                    break;
                }
            };
            // Terminal refusals/ACKs cannot overtake the original Unknown.
            if sender.results.try_send(response).is_err() {
                control_trusted = false;
                break;
            }
        }
    }
    // EOF, cutoff or Close releases all unclaimed immutable byte custody.
    terminal_recording.take();
    let teardown_proven = match shutdown_outcome {
        Some(outcome) => outcome,
        None => shutdown.await,
    };
    if !control_trusted {
        closing_id = None;
    }
    #[cfg(feature = "acceptance-faults")]
    if teardown_proven {
        settlement_trace!(0, ShutdownProven);
    } else {
        settlement_trace!(0, ShutdownUnproven);
    }
    for (sequence, (id, generation, _callback, _scope)) in pending {
        let effects = if broker.has_started(sequence) {
            Effects::Unknown
        } else {
            Effects::NotDispatched
        };
        let _ = broker.settle(generation, sequence, effects);
        let _queued = enqueue(
            &sender,
            result_message(
                id,
                generation,
                sequence,
                NativeOutcome {
                    retention: None,
                    result: Err(ProtocolError::Cancelled),
                    effects,
                },
                ScopeState::Quarantined,
            ),
            &broker,
        );
        #[cfg(feature = "acceptance-faults")]
        if _queued {
            settlement_trace!(sequence, PendingResultQueued);
        } else {
            settlement_trace!(sequence, ResultQueueFailed);
        }
    }
    if teardown_proven {
        let _ = broker.mark_closed();
        if let Some(id) = closing_id {
            enqueue(
                &sender,
                ServerMessage::Closed {
                    id,
                    generation: broker
                        .health()
                        .map(|(generation, _)| generation)
                        .unwrap_or(1),
                    scope_state: ScopeState::Closed,
                },
                &broker,
            );
        }
    } else {
        // This terminal refusal follows every correlated outcome already
        // queued above. The priority control lane must not overtake an Unknown
        // result and erase its effects classification at the client.
        if sender
            .results
            .try_send(ServerMessage::Error {
                id: closing_id,
                error: WireError {
                    code: ProtocolError::CleanupFailed,
                },
                scope_state: ScopeState::Quarantined,
            })
            .is_err()
        {
            let _ = broker.quarantine();
        }
    }
    drop(sender);
    let _ = drain.send(());
    let mut writer_task = writer_task;
    if tokio::time::timeout(std::time::Duration::from_secs(2), &mut writer_task)
        .await
        .is_err()
    {
        writer_task.abort();
    }
    teardown_proven
}

fn result_message(
    id: String,
    generation: u64,
    operation_seq: u64,
    outcome: NativeOutcome,
    scope_state: ScopeState,
) -> ServerMessage {
    let (ok, data, error) = match outcome.result {
        Ok(data) => (true, Some(data), None),
        Err(code) => (false, None, Some(WireError { code })),
    };
    let retention = if outcome.effects == Effects::Unknown && scope_state == ScopeState::Usable {
        outcome.retention.as_ref().map(|proof| proof.descriptor())
    } else {
        None
    };
    ServerMessage::Result {
        id,
        generation,
        operation_seq,
        retention,
        recovery: None,
        ok,
        data,
        error,
        effects: outcome.effects,
        scope_state,
    }
}

async fn execute_bounded<E: ClientExecutor>(
    executor: std::sync::Arc<E>,
    broker: std::sync::Arc<ClientSession>,
    command: String,
    args: serde_json::Map<String, serde_json::Value>,
    lease: OperationLease,
    continuation_negotiated: bool,
) -> NativeOutcome {
    let trace_screenshot = command == "capture.screenshot"
        && args.get("purpose").and_then(serde_json::Value::as_str) == Some("trace");
    let key = super::client_debt::OperationKey {
        generation: lease.generation,
        operation_seq: lease.sequence,
    };
    let mut outcome = execute_until_deadline(
        executor.clone(),
        broker.clone(),
        command,
        args,
        lease,
        continuation_negotiated,
    )
    .await;
    if outcome.effects != Effects::Unknown || !continuation_negotiated {
        outcome.retention = None;
        return outcome;
    }
    let Some(proof) = outcome
        .retention
        .as_ref()
        .filter(|proof| proof.matches(key))
        .cloned()
    else {
        outcome.retention = None;
        return outcome;
    };
    let retirement_deadline = if trace_screenshot {
        proof.retirement_deadline().min(
            executor
                .begin_trace_cleanup(key)
                .unwrap_or_else(std::time::Instant::now),
        )
    } else {
        proof.retirement_deadline()
    };
    // This runs on the retained operation completion lane, never the control
    // reader. Events and exact native security fallback keep being serviced.
    let retirement = async {
        if std::time::Instant::now() >= retirement_deadline {
            return Err(ProtocolError::CleanupFailed);
        }
        broker.begin_operation_retirement(key, &proof)?;
        executor.retire_operation_publication(key).await?;
        if std::time::Instant::now() >= retirement_deadline {
            return Err(ProtocolError::CleanupFailed);
        }
        if matches!(
            executor.operation_retention_status(key),
            super::client_operation_state::OperationRetentionStatus::IntegrityLost(_)
        ) {
            return Err(ProtocolError::CleanupFailed);
        }
        broker.finish_operation_publication(key)
    };
    if !matches!(
        tokio::time::timeout_at(retirement_deadline.into(), retirement).await,
        Ok(Ok(()))
    ) {
        outcome.retention = None;
        if trace_screenshot {
            outcome.result = Err(ProtocolError::CleanupFailed);
        }
        let _ = broker.quarantine();
    }
    outcome
}

fn trace_receipt<E: ClientExecutor>(
    executor: &E,
    key: super::client_debt::OperationKey,
    cancellation: &tokio::sync::watch::Receiver<super::client_session::CancelSignal>,
    deadline: tokio::time::Instant,
    mut outcome: NativeOutcome,
) -> NativeOutcome {
    let stop = (*cancellation.borrow()).error().or_else(|| {
        (tokio::time::Instant::now() >= deadline).then_some(ProtocolError::DeadlineExceeded)
    });
    if let (Some(error), Ok(value)) = (stop, &outcome.result) {
        if executor.discard_trace_result(key, value).is_err() {
            outcome.result = Err(ProtocolError::CleanupFailed);
            outcome.effects = Effects::Unknown;
        } else {
            outcome.result = Err(error);
        }
        outcome.retention = None;
    }
    outcome
}

async fn execute_until_deadline<E: ClientExecutor>(
    executor: std::sync::Arc<E>,
    broker: std::sync::Arc<ClientSession>,
    command: String,
    args: serde_json::Map<String, serde_json::Value>,
    lease: OperationLease,
    continuation_negotiated: bool,
) -> NativeOutcome {
    let trace_screenshot = command == "capture.screenshot"
        && args.get("purpose").and_then(serde_json::Value::as_str) == Some("trace");
    let sequence = lease.sequence;
    let generation = lease.generation;
    let key = super::client_debt::OperationKey {
        generation,
        operation_seq: sequence,
    };
    let deadline = tokio::time::Instant::from_std(lease.deadline);
    let mut cancellation = lease.cancellation.clone();
    settlement_trace!(sequence, ExecuteStarted);
    let execution = executor.execute(command, args, lease);
    tokio::pin!(execution);
    tokio::select! {
        biased;
        outcome = &mut execution => {
            settlement_trace!(sequence, ExecuteReturned);
            return if trace_screenshot { trace_receipt(executor.as_ref(), key, &cancellation, deadline, outcome) } else { outcome };
        },
        _ = cancellation.changed() => { settlement_trace!(sequence, CancelObserved); },
        _ = tokio::time::sleep_until(deadline) => {
            settlement_trace!(sequence, DeadlineObserved);
            let _ = broker.expire(generation, sequence);
        },
    };
    // Keep the existing receipt decision point. A pending exact-owner proof
    // must reach publication retirement while restoration still owns its locks.
    // Raw supervision/restoration and retirement share the original absolute
    // cleanup clock; this receipt grace cannot renew that clock.
    let protected_cleanup_deadline = if trace_screenshot && continuation_negotiated {
        executor
            .begin_trace_cleanup(key)
            .map(tokio::time::Instant::from_std)
    } else {
        None
    };
    let receipt_deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(250);
    let grace_deadline = protected_cleanup_deadline
        .map_or(receipt_deadline, |cleanup| cleanup.min(receipt_deadline));
    executor.cancel_operation_producer(key);
    if let Ok(outcome) = tokio::time::timeout_at(grace_deadline, &mut execution).await {
        settlement_trace!(sequence, GraceReturned);
        return if trace_screenshot {
            trace_receipt(executor.as_ref(), key, &cancellation, deadline, outcome)
        } else {
            outcome
        };
    }
    settlement_trace!(sequence, GraceExpired);
    let status = executor.operation_retention_status(super::client_debt::OperationKey {
        generation,
        operation_seq: sequence,
    });
    let effects = match status.mutation_dispatched() {
        Some(false) => Effects::NotDispatched,
        Some(true) => Effects::Unknown,
        // An incapable executor or missing journal retains the legacy terminal
        // behavior. Executor entry is never promoted into reusable proof.
        None if !broker.has_started(sequence) => Effects::NotDispatched,
        None => Effects::Unknown,
    };
    let reason = if protected_cleanup_deadline
        .is_some_and(|cleanup| tokio::time::Instant::now() >= cleanup)
        && effects == Effects::Unknown
    {
        ProtocolError::CleanupFailed
    } else {
        (*cancellation.borrow())
            .error()
            .unwrap_or(ProtocolError::Cancelled)
    };
    NativeOutcome {
        retention: if effects == Effects::Unknown && reason != ProtocolError::CleanupFailed {
            status.proof()
        } else {
            None
        },
        result: Err(reason),
        effects,
    }
}

fn respond<E: ClientExecutor>(
    broker: &ClientSession,
    message: ClientMessage,
    executor: &E,
) -> (ServerMessage, bool) {
    let (generation, scope_state) = broker.health().unwrap_or((1, ScopeState::Quarantined));
    match message {
        ClientMessage::Request {
            id,
            generation: requested_generation,
            operation_seq,
            timeout_ms,
            callback_token,
            ..
        } => {
            let error = match broker.admit_callback(
                requested_generation,
                operation_seq,
                timeout_ms,
                callback_token.as_deref(),
            ) {
                Ok(_) => {
                    let _ =
                        broker.settle(requested_generation, operation_seq, Effects::NotDispatched);
                    ProtocolError::UnsupportedCommand
                }
                Err(error) => error,
            };
            (
                ServerMessage::Result {
                    recovery: None,
                    retention: None,
                    id,
                    generation,
                    operation_seq,
                    ok: false,
                    data: None,
                    error: Some(WireError { code: error }),
                    effects: Effects::NotDispatched,
                    scope_state,
                },
                false,
            )
        }
        ClientMessage::Cancel {
            id,
            generation: requested_generation,
            operation_seq,
        } => {
            settlement_trace!(operation_seq, CancelReceived);
            let result = broker.cancel(requested_generation, operation_seq);
            if result.is_ok() {
                executor.cancel_operation_producer(super::client_debt::OperationKey {
                    generation: requested_generation,
                    operation_seq,
                });
            }
            #[cfg(feature = "acceptance-faults")]
            super::client_settlement_trace::record(
                operation_seq,
                if result.is_ok() {
                    SettlementPhase::CancelAccepted
                } else {
                    SettlementPhase::CancelRejected
                },
                super::client_settlement_trace::Facts {
                    generation: Some(generation),
                    effects: None,
                    scope_state: Some(scope_state),
                    error: result.as_ref().err().cloned(),
                    accepted: Some(result.is_ok()),
                    ..Default::default()
                },
            );
            (
                ServerMessage::ControlResult {
                    id,
                    generation,
                    accepted: result.is_ok(),
                    error: result.err().map(|code| WireError { code }),
                    scope_state,
                },
                false,
            )
        }
        ClientMessage::Decision {
            id,
            generation: requested_generation,
            token,
            decision,
        } => {
            let prepared = decision
                .validate()
                .and_then(|()| executor.prepare_decision(requested_generation, &token, &decision));
            let result = match prepared {
                Err(error) => Err(error),
                Ok(()) => {
                    let result = broker.resolve(requested_generation, &token, decision);
                    if executor.finish_decision(&token, result.is_ok()).is_err() {
                        // A selected decision cannot be undone or reported as
                        // unselected. Preserve acceptance and quarantine scope.
                        let _ = broker.quarantine();
                    }
                    result
                }
            };
            let scope_state = broker
                .health()
                .map(|(_, state)| state)
                .unwrap_or(ScopeState::Quarantined);
            (
                ServerMessage::ControlResult {
                    id,
                    generation,
                    accepted: result.is_ok(),
                    error: result.err().map(|code| WireError { code }),
                    scope_state,
                },
                false,
            )
        }
        ClientMessage::Close {
            id,
            generation: requested_generation,
        } if requested_generation == generation => {
            let _ = broker.mark_closed();
            (
                ServerMessage::Closed {
                    id,
                    generation,
                    scope_state: ScopeState::Closed,
                },
                true,
            )
        }
        ClientMessage::Close { id, .. } => (
            ServerMessage::Error {
                id: Some(id),
                error: WireError {
                    code: ProtocolError::StaleGeneration,
                },
                scope_state,
            },
            false,
        ),
        ClientMessage::Hello { id, .. } => (
            ServerMessage::Error {
                id: Some(id),
                error: WireError {
                    code: ProtocolError::InvalidFrame,
                },
                scope_state,
            },
            true,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn publication_operation() -> (
        tokio::sync::watch::Sender<super::super::client_session::CancelSignal>,
        OperationLease,
    ) {
        let (sender, cancellation) =
            tokio::sync::watch::channel(super::super::client_session::CancelSignal::None);
        (
            sender,
            OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 7,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(5),
                cancellation,
            },
        )
    }
    fn publication_result(ok: bool) -> ServerMessage {
        result_message(
            "request".into(),
            1,
            7,
            NativeOutcome {
                retention: None,
                result: if ok {
                    Ok(serde_json::json!({"identityScope":"same-scope"}))
                } else {
                    Err(ProtocolError::Cancelled)
                },
                effects: if ok {
                    Effects::Completed
                } else {
                    Effects::NotDispatched
                },
            },
            ScopeState::Usable,
        )
    }
    fn live_scope_sink(sink: &ClientEventSink, sequence: u64, scope: &str) -> ClientEventSink {
        let (_sender, mut operation) = publication_operation();
        operation.sequence = sequence;
        let staged = sink.stage_until_result(&operation, scope).unwrap();
        sink.result_written(&result_message(
            "test".into(),
            1,
            sequence,
            NativeOutcome {
                retention: None,
                result: Ok(serde_json::json!({"identityScope":scope})),
                effects: Effects::Completed,
            },
            ScopeState::Usable,
        ))
        .unwrap();
        staged
    }
    #[test]
    fn terminal_callback_cut_requires_registered_gate_and_explicit_owner() {
        let (root, mut events) =
            ClientEventSink::test_channel(std::sync::Arc::new(ClientSession::new()));
        let old = live_scope_sink(&root, 7, "old");
        // Even a genuine published barrier cannot fence an unregistered scope
        // gate. This structural corruption grants no replacement authority.
        let key = (1, "old".to_owned());
        let registered = root
            .sequence
            .lock()
            .unwrap()
            .scope_gates
            .remove(&key)
            .unwrap();
        assert_eq!(
            old.retire_scope_callbacks(1, "old"),
            Err(ProtocolError::StaleScope)
        );
        root.sequence
            .lock()
            .unwrap()
            .scope_gates
            .insert(key, registered);
        root.close_publications();
        assert_eq!(
            old.retire_scope_callbacks_checked(1, "old", None),
            Err(ProtocolError::ScopeUnavailable)
        );
        assert!(!old
            .barrier
            .as_ref()
            .unwrap()
            .scope_gate
            .closed
            .load(std::sync::atomic::Ordering::Acquire));
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn terminal_callback_cut_never_treats_unpublished_false_as_terminal_proof() {
        let (root, mut events) =
            ClientEventSink::test_channel(std::sync::Arc::new(ClientSession::new()));
        let (_sender, operation) = publication_operation();
        let pending = root.stage_until_result(&operation, "old").unwrap();
        root.open.store(false, std::sync::atomic::Ordering::Release);
        assert_eq!(
            pending.retire_scope_callbacks_checked(1, "old", None),
            Err(ProtocolError::ScopeUnavailable)
        );
        root.close_publications();
        assert_eq!(
            pending.retire_scope_callbacks_checked(1, "old", None),
            Err(ProtocolError::ScopeUnavailable)
        );
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn terminal_callback_cut_fences_all_same_scope_clones_but_not_sibling() {
        let (root, mut events) =
            ClientEventSink::test_channel(std::sync::Arc::new(ClientSession::new()));
        let old = live_scope_sink(&root, 7, "old");
        let restarted = live_scope_sink(&root, 8, "old");
        let sibling = live_scope_sink(&root, 9, "other");
        assert!(old.same_client(&sibling));
        old.emit(
            "dialog".into(),
            serde_json::json!({"identityScope":"old"}),
            None,
        )
        .unwrap();
        restarted
            .emit(
                "response".into(),
                serde_json::json!({"identityScope":"old"}),
                None,
            )
            .unwrap();
        old.retire_scope_callbacks(1, "old").unwrap();
        assert!(matches!(
            events.try_recv().unwrap(),
            ServerMessage::Event { sequence: 1, .. }
        ));
        assert!(matches!(
            events.try_recv().unwrap(),
            ServerMessage::Event { sequence: 2, .. }
        ));
        match events.try_recv().unwrap() {
            ServerMessage::Event {
                sequence: 3,
                event,
                payload,
                decision: None,
                ..
            } => {
                assert_eq!(event, "scope.callbacks-retired");
                assert_eq!(
                    payload,
                    serde_json::json!({"identityScope":"old","throughEventSequence":2})
                );
            }
            _ => panic!("missing exact retirement proof"),
        }
        for sink in [&old, &restarted] {
            assert_eq!(
                sink.emit(
                    "late".into(),
                    serde_json::json!({"identityScope":"old"}),
                    None
                ),
                Err(ProtocolError::StaleScope)
            );
        }
        assert_eq!(
            old.retire_scope_callbacks(1, "old"),
            Err(ProtocolError::StaleScope)
        );
        sibling
            .emit(
                "live".into(),
                serde_json::json!({"identityScope":"other"}),
                None,
            )
            .unwrap();
        assert!(matches!(
            events.try_recv().unwrap(),
            ServerMessage::Event { sequence: 4, .. }
        ));
        let (_sender, mut op) = publication_operation();
        op.sequence = 10;
        assert!(matches!(
            root.stage_until_result(&op, "old"),
            Err(ProtocolError::StaleScope)
        ));
        assert_eq!(root.broker.health().unwrap().1, ScopeState::Usable);
    }
    #[test]
    fn terminal_callback_cut_rejects_root_wrong_scope_and_unpublished_replacement() {
        let (root, mut events) =
            ClientEventSink::test_channel(std::sync::Arc::new(ClientSession::new()));
        let old = live_scope_sink(&root, 7, "old");
        assert_eq!(
            root.retire_scope_callbacks(1, "old"),
            Err(ProtocolError::StaleScope)
        );
        assert_eq!(
            old.retire_scope_callbacks(1, "foreign"),
            Err(ProtocolError::StaleScope)
        );
        assert_eq!(
            old.retire_scope_callbacks(2, "old"),
            Err(ProtocolError::StaleScope)
        );
        let (_sender, mut op) = publication_operation();
        op.sequence = 8;
        let _replacement = root.stage_until_result(&op, "old").unwrap();
        assert_eq!(
            old.retire_scope_callbacks(1, "old"),
            Err(ProtocolError::StaleScope)
        );
        assert!(events.try_recv().is_err());
        old.emit(
            "still-live".into(),
            serde_json::json!({"identityScope":"old"}),
            None,
        )
        .unwrap();
    }
    #[test]
    fn terminal_callback_cut_queue_failure_seals_and_quarantines() {
        let (root, mut events) =
            ClientEventSink::test_channel(std::sync::Arc::new(ClientSession::new()));
        let old = live_scope_sink(&root, 7, "old");
        for _ in 0..64 {
            old.emit(
                "queued".into(),
                serde_json::json!({"identityScope":"old"}),
                None,
            )
            .unwrap();
        }
        assert_eq!(
            old.retire_scope_callbacks(1, "old"),
            Err(ProtocolError::CapacityExceeded)
        );
        assert_eq!(root.broker.health().unwrap().1, ScopeState::Quarantined);
        while let Ok(event) = events.try_recv() {
            assert!(
                !matches!(event,ServerMessage::Event {event,..} if event=="scope.callbacks-retired")
            );
        }
        assert!(old
            .barrier
            .as_ref()
            .unwrap()
            .scope_gate
            .closed
            .load(std::sync::atomic::Ordering::Acquire));
    }
    #[test]
    fn lifecycle_sink_waits_for_exact_result_and_preserves_old_live_sequence() {
        let (sink, mut rx) =
            ClientEventSink::test_channel(std::sync::Arc::new(ClientSession::new()));
        let (_sender, op) = publication_operation();
        let staged = sink.stage_until_result(&op, "same-scope").unwrap();
        staged.validate_stage(&sink, &op, "same-scope").unwrap();
        staged
            .emit(
                "new".into(),
                serde_json::json!({"identityScope":"same-scope"}),
                None,
            )
            .unwrap();
        sink.emit(
            "old".into(),
            serde_json::json!({"identityScope":"same-scope"}),
            None,
        )
        .unwrap();
        assert!(
            matches!(rx.try_recv().unwrap(), ServerMessage::Event { sequence:1, event, .. } if event=="old")
        );
        assert!(rx.try_recv().is_err());
        let wrong = result_message(
            "other".into(),
            1,
            8,
            NativeOutcome {
                retention: None,
                result: Ok(serde_json::json!({"identityScope":"same-scope"})),
                effects: Effects::Completed,
            },
            ScopeState::Usable,
        );
        sink.result_written(&wrong).unwrap();
        assert!(rx.try_recv().is_err());
        sink.result_written(&publication_result(true)).unwrap();
        assert!(
            matches!(rx.try_recv().unwrap(), ServerMessage::Event { sequence:2, event, .. } if event=="new")
        );
        staged
            .emit(
                "later".into(),
                serde_json::json!({"identityScope":"same-scope"}),
                None,
            )
            .unwrap();
        assert!(matches!(
            rx.try_recv().unwrap(),
            ServerMessage::Event { sequence: 3, .. }
        ));
        assert!(staged.validate_stage(&sink, &op, "same-scope").is_err());
    }
    #[test]
    fn failed_result_disconnect_and_foreign_stage_never_release_replacement_events() {
        for disconnect in [false, true] {
            let (sink, mut rx) =
                ClientEventSink::test_channel(std::sync::Arc::new(ClientSession::new()));
            let (_sender, op) = publication_operation();
            let staged = sink.stage_until_result(&op, "same-scope").unwrap();
            let (foreign, _) =
                ClientEventSink::test_channel(std::sync::Arc::new(ClientSession::new()));
            assert!(staged.validate_stage(&foreign, &op, "same-scope").is_err());
            let wrong = OperationLease {
                sequence: op.sequence + 1,
                cancellation: op.cancellation.clone(),
                is_callback: op.is_callback,
                generation: op.generation,
                deadline: op.deadline,
            };
            assert!(staged.validate_stage(&sink, &wrong, "same-scope").is_err());
            staged
                .emit(
                    "new".into(),
                    serde_json::json!({"identityScope":"same-scope"}),
                    None,
                )
                .unwrap();
            if disconnect {
                sink.close_publications();
            } else {
                sink.result_written(&publication_result(false)).unwrap();
            }
            assert!(rx.try_recv().is_err());
            assert!(staged
                .emit(
                    "late".into(),
                    serde_json::json!({"identityScope":"same-scope"}),
                    None
                )
                .is_err());
            assert_eq!(sink.sequence.lock().unwrap().staged_bytes, 0);
        }
    }
    #[test]
    fn staged_event_capacity_and_expiry_fail_closed_without_output() {
        let (sink, mut rx) =
            ClientEventSink::test_channel(std::sync::Arc::new(ClientSession::new()));
        let (_sender, op) = publication_operation();
        let staged = sink.stage_until_result(&op, "same-scope").unwrap();
        for _ in 0..MAX_STAGED_EVENTS {
            staged
                .emit(
                    "new".into(),
                    serde_json::json!({"identityScope":"same-scope"}),
                    None,
                )
                .unwrap();
        }
        assert_eq!(
            staged.emit(
                "overflow".into(),
                serde_json::json!({"identityScope":"same-scope"}),
                None
            ),
            Err(ProtocolError::CapacityExceeded)
        );
        assert!(rx.try_recv().is_err());
        let (sink, mut rx) =
            ClientEventSink::test_channel(std::sync::Arc::new(ClientSession::new()));
        let (_sender, op) = publication_operation();
        let staged = sink.stage_until_result(&op, "same-scope").unwrap();
        staged
            .emit(
                "expired-decision".into(),
                serde_json::json!({"identityScope":"same-scope"}),
                Some(DecisionNotice {
                    token: "synthetic".into(),
                    timeout_ms: 0,
                }),
            )
            .unwrap();
        assert_eq!(
            sink.result_written(&publication_result(true)),
            Err(ProtocolError::DeadlineExceeded)
        );
        assert!(rx.try_recv().is_err());
    }
    #[test]
    fn partial_release_capacity_failure_never_marks_barrier_live() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let (sink, mut rx) = ClientEventSink::test_channel(broker.clone());
        let (_sender, op) = publication_operation();
        let staged = sink.stage_until_result(&op, "same-scope").unwrap();
        for _ in 0..2 {
            staged
                .emit(
                    "new".into(),
                    serde_json::json!({"identityScope":"same-scope"}),
                    None,
                )
                .unwrap();
        }
        for _ in 0..63 {
            sink.emit("old".into(), serde_json::json!({}), None)
                .unwrap();
        }
        assert_eq!(
            sink.result_written(&publication_result(true)),
            Err(ProtocolError::CapacityExceeded)
        );
        assert!(matches!(
            *staged.barrier.as_ref().unwrap().state.lock().unwrap(),
            EventBarrierState::Discarded
        ));
        assert!(sink.sequence.lock().unwrap().barriers.is_empty());
        // The actual writer quarantines and seals on this exact error, so any
        // partially enqueued notices cannot grant an independently live scope.
        broker.quarantine().unwrap();
        sink.close_publications();
        assert_eq!(broker.health().unwrap().1, ScopeState::Quarantined);
        assert!(staged
            .emit(
                "late".into(),
                serde_json::json!({"identityScope":"same-scope"}),
                None
            )
            .is_err());
        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 64);
    }
    #[tokio::test]
    async fn pending_publication_wait_wakes_on_ack_discard_and_cancellation() {
        for success in [false, true] {
            let (sink, _rx) =
                ClientEventSink::test_channel(std::sync::Arc::new(ClientSession::new()));
            let (_sender, op) = publication_operation();
            let staged = sink.stage_until_result(&op, "same-scope").unwrap();
            assert!(staged.is_publication_pending().unwrap());
            let wait = {
                let staged = staged.clone();
                let cancellation = op.cancellation.clone();
                tokio::spawn(
                    async move { staged.wait_publication(op.deadline, cancellation).await },
                )
            };
            tokio::task::yield_now().await;
            assert!(!wait.is_finished());
            sink.result_written(&publication_result(success)).unwrap();
            let result = tokio::time::timeout(std::time::Duration::from_secs(1), wait)
                .await
                .unwrap()
                .unwrap();
            if success {
                assert!(result.is_ok());
            } else {
                assert_eq!(result, Err(ProtocolError::StaleScope));
            }
        }
        let (sink, _rx) = ClientEventSink::test_channel(std::sync::Arc::new(ClientSession::new()));
        let (sender, op) = publication_operation();
        let staged = sink.stage_until_result(&op, "same-scope").unwrap();
        sender.send_replace(super::super::client_session::CancelSignal::Requested);
        assert_eq!(
            staged.wait_publication(op.deadline, op.cancellation).await,
            Err(ProtocolError::Cancelled)
        );
    }
    struct TerminalCloseExecutor {
        broker: std::sync::Arc<ClientSession>,
        calls: std::sync::atomic::AtomicUsize,
        shutdown_started: tokio::sync::Notify,
        shutdown_release: tokio::sync::Notify,
        shutdown_done: tokio::sync::Notify,
        fail: bool,
    }
    impl ClientExecutor for TerminalCloseExecutor {
        fn capabilities(&self) -> Vec<String> {
            vec![]
        }
        fn prepare_decision(&self, _: u64, _: &str, _: &Decision) -> Result<(), ProtocolError> {
            panic!("terminal callback authority must never reach the executor");
        }
        async fn execute(
            &self,
            _: String,
            _: serde_json::Map<String, serde_json::Value>,
            lease: OperationLease,
        ) -> NativeOutcome {
            assert!(self.broker.start(lease.generation, lease.sequence).unwrap());
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            NativeOutcome {
                retention: None,
                result: Err(ProtocolError::BrowserFailure),
                effects: Effects::Unknown,
            }
        }
        async fn shutdown(&self) -> Result<(), ProtocolError> {
            self.shutdown_started.notify_one();
            self.shutdown_release.notified().await;
            self.shutdown_done.notify_one();
            if self.fail {
                Err(ProtocolError::CleanupFailed)
            } else {
                Ok(())
            }
        }
    }
    async fn terminal_close_peer(
        fail: bool,
    ) -> (
        tokio::io::BufReader<tokio::io::DuplexStream>,
        std::sync::Arc<TerminalCloseExecutor>,
        tokio::task::JoinHandle<bool>,
    ) {
        let broker = std::sync::Arc::new(ClientSession::new());
        let executor = std::sync::Arc::new(TerminalCloseExecutor {
            broker: broker.clone(),
            calls: std::sync::atomic::AtomicUsize::new(0),
            shutdown_started: tokio::sync::Notify::new(),
            shutdown_release: tokio::sync::Notify::new(),
            shutdown_done: tokio::sync::Notify::new(),
            fail,
        });
        let (peer, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let serving = tokio::spawn(serve_with_executor(
            tokio::io::BufReader::new(reader),
            writer,
            ClientMessage::Hello {
                id: "h".into(),
                protocol: PROTOCOL.into(),
                required_capabilities: vec!["terminal.close/1".into()],
            },
            broker,
            executor.clone(),
        ));
        let mut peer = tokio::io::BufReader::new(peer);
        let ready = settlement_frame(&mut peer).await;
        assert!(ready["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "terminal.close/1"));
        peer.get_mut().write_all(b"{\"type\":\"request\",\"id\":\"r\",\"generation\":1,\"operationSeq\":1,\"timeoutMs\":1000,\"command\":\"uncertain\",\"args\":{}}\n").await.unwrap();
        let result = settlement_frame(&mut peer).await;
        assert_eq!(result["id"], "r");
        assert_eq!(result["effects"], "unknown");
        assert_eq!(result["scopeState"], "quarantined");
        assert_eq!(result["error"]["code"], "browser-failure");
        executor.shutdown_started.notified().await;
        (peer, executor, serving)
    }
    #[tokio::test]
    async fn terminal_close_after_shutdown_uses_cached_proof_without_request_revival() {
        let (mut peer, executor, serving) = terminal_close_peer(false).await;
        executor.shutdown_release.notify_one();
        executor.shutdown_done.notified().await;
        peer.get_mut().write_all(b"{\"type\":\"request\",\"id\":\"late\",\"generation\":1,\"operationSeq\":2,\"timeoutMs\":1000,\"command\":\"scope.reconnect\",\"args\":{}}\n{\"type\":\"close\",\"id\":\"stale\",\"generation\":2}\n").await.unwrap();
        let refusal = settlement_frame(&mut peer).await;
        assert_eq!(refusal["id"], "late");
        assert_eq!(refusal["effects"], "not-dispatched");
        assert_eq!(refusal["scopeState"], "quarantined");
        let stale = settlement_frame(&mut peer).await;
        assert_eq!(stale["error"]["code"], "stale-generation");
        peer.get_mut().write_all(b"{\"type\":\"decision\",\"id\":\"d\",\"generation\":1,\"token\":\"retired\",\"decision\":{\"kind\":\"abort\"}}\n").await.unwrap();
        let decision = settlement_frame(&mut peer).await;
        assert_eq!(decision["type"], "control-result");
        assert_eq!(decision["id"], "d");
        assert_eq!(decision["accepted"], false);
        peer.get_mut()
            .write_all(b"{\"type\":\"close\",\"id\":\"z\",\"generation\":1}\n")
            .await
            .unwrap();
        let closed = settlement_frame(&mut peer).await;
        assert_eq!(closed["type"], "closed");
        assert_eq!(closed["id"], "z");
        assert_eq!(closed["generation"], 1);
        assert_eq!(executor.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(serving.await.unwrap());
    }
    #[tokio::test]
    async fn terminal_close_before_shutdown_preserves_partial_cancel_and_single_receipt() {
        let (mut peer, executor, serving) = terminal_close_peer(false).await;
        peer.get_mut()
            .write_all(b"{\"type\":\"cancel\",\"id\":\"c\",")
            .await
            .unwrap();
        peer.get_mut().write_all(b"\"generation\":1,\"operationSeq\":1}\n{\"type\":\"close\",\"id\":\"z\",\"generation\":1}\n{\"type\":\"close\",\"id\":\"z\",\"generation\":1}\n").await.unwrap();
        let ack = settlement_frame(&mut peer).await;
        assert_eq!(ack["type"], "control-result");
        assert_eq!(ack["id"], "c");
        assert_eq!(ack["accepted"], false);
        assert_eq!(ack["scopeState"], "quarantined");
        executor.shutdown_release.notify_one();
        let closed = settlement_frame(&mut peer).await;
        assert_eq!(closed["type"], "closed");
        assert_eq!(closed["id"], "z");
        assert!(read_frame(&mut peer).await.unwrap().is_none());
        assert!(serving.await.unwrap());
    }
    #[tokio::test]
    async fn terminal_close_cleanup_failure_is_correlated_after_unknown() {
        let (mut peer, executor, serving) = terminal_close_peer(true).await;
        peer.get_mut()
            .write_all(b"{\"type\":\"close\",\"id\":\"z\",\"generation\":1}\n")
            .await
            .unwrap();
        executor.shutdown_release.notify_one();
        let failure = settlement_frame(&mut peer).await;
        assert_eq!(failure["type"], "error");
        assert_eq!(failure["id"], "z");
        assert_eq!(failure["error"]["code"], "cleanup-failed");
        assert!(!serving.await.unwrap());
    }
    #[tokio::test]
    async fn terminal_close_malformed_input_cannot_authorize_success_receipt() {
        let (mut peer, executor, serving) = terminal_close_peer(false).await;
        peer.get_mut().write_all(b"invalid\n").await.unwrap();
        peer.get_mut().shutdown().await.unwrap();
        executor.shutdown_release.notify_one();
        assert!(read_frame(&mut peer).await.unwrap().is_none());
        assert!(serving.await.unwrap());
    }
    #[tokio::test]
    async fn terminal_close_eof_in_partial_frame_still_shuts_down_without_receipt() {
        let (mut peer, executor, serving) = terminal_close_peer(false).await;
        peer.get_mut()
            .write_all(b"{\"type\":\"close\",")
            .await
            .unwrap();
        peer.get_mut().shutdown().await.unwrap();
        executor.shutdown_release.notify_one();
        assert!(read_frame(&mut peer).await.unwrap().is_none());
        assert!(serving.await.unwrap());
    }

    #[tokio::test]
    async fn terminal_close_retains_partial_cancel_across_unknown_phase_change() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let (started, mut running) = tokio::sync::watch::channel(None);
        let executor = std::sync::Arc::new(DeadlineSettlementExecutor {
            broker: broker.clone(),
            started,
            responsive: false,
            shutdown_release: Some(tokio::sync::Notify::new()),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let (peer, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let (count, mut consumed) = tokio::sync::watch::channel(0usize);
        let serving = tokio::spawn(serve_with_executor(
            CountedReader {
                inner: tokio::io::BufReader::new(reader),
                consumed: count,
            },
            writer,
            ClientMessage::Hello {
                id: "h".into(),
                protocol: PROTOCOL.into(),
                required_capabilities: vec!["terminal.close/1".into()],
            },
            broker,
            executor.clone(),
        ));
        let mut peer = tokio::io::BufReader::new(peer);
        settlement_frame(&mut peer).await;
        let request = b"{\"type\":\"request\",\"id\":\"r\",\"generation\":1,\"operationSeq\":1,\"timeoutMs\":100,\"command\":\"wait-for-native-stop\",\"args\":{}}\n";
        let prefix = b"{\"type\":\"cancel\",\"id\":\"c\",";
        peer.get_mut().write_all(request).await.unwrap();
        running.wait_for(Option::is_some).await.unwrap();
        peer.get_mut().write_all(prefix).await.unwrap();
        consumed
            .wait_for(|count| *count >= request.len() + prefix.len())
            .await
            .unwrap();
        let unknown = settlement_frame(&mut peer).await;
        assert_eq!(unknown["id"], "r");
        assert_eq!(unknown["effects"], "unknown");
        peer.get_mut().write_all(b"\"generation\":1,\"operationSeq\":1}\n{\"type\":\"close\",\"id\":\"z\",\"generation\":1}\n").await.unwrap();
        let ack = settlement_frame(&mut peer).await;
        assert_eq!(ack["id"], "c");
        assert_eq!(ack["type"], "control-result");
        assert_eq!(ack["accepted"], false);
        executor.shutdown_release.as_ref().unwrap().notify_one();
        let closed = settlement_frame(&mut peer).await;
        assert_eq!(closed["type"], "closed");
        assert_eq!(closed["id"], "z");
        assert!(serving.await.unwrap());
    }
    #[tokio::test]
    async fn terminal_close_no_close_fixed_cutoff_never_implies_receipt() {
        let (mut peer, executor, serving) = terminal_close_peer(false).await;
        let began = tokio::time::Instant::now();
        executor.shutdown_release.notify_one();
        executor.shutdown_done.notified().await;
        // Cached successful shutdown does not itself produce Closed. Continual
        // requests are refused and cannot extend the original control cutoff.
        let mut sequence = 2;
        loop {
            let request = format!("{{\"type\":\"request\",\"id\":\"late{sequence}\",\"generation\":1,\"operationSeq\":{sequence},\"timeoutMs\":1000,\"command\":\"fresh\",\"args\":{{}}}}\n");
            if peer.get_mut().write_all(request.as_bytes()).await.is_err() {
                break;
            }
            match tokio::time::timeout(std::time::Duration::from_secs(12), read_frame(&mut peer))
                .await
                .unwrap()
                .unwrap()
            {
                None => break,
                Some(bytes) => {
                    let frame: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(frame["type"], "result");
                    assert_eq!(frame["effects"], "not-dispatched");
                }
            }
            sequence += 1;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(began.elapsed() < std::time::Duration::from_secs(12));
        assert!(serving.await.unwrap());
        assert_eq!(executor.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    struct FailingFrameWriter<W> {
        inner: W,
        frame_type: &'static [u8],
        failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    impl<W: AsyncWrite + Unpin> AsyncWrite for FailingFrameWriter<W> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if bytes
                .windows(self.frame_type.len())
                .any(|part| part == self.frame_type)
            {
                self.failed.store(true, std::sync::atomic::Ordering::SeqCst);
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "injected terminal frame write failure",
                )));
            }
            std::pin::Pin::new(&mut self.inner).poll_write(cx, bytes)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }
    async fn terminal_close_lost_frame(frame_type: &'static [u8], cancel: bool) {
        let broker = std::sync::Arc::new(ClientSession::new());
        let executor = std::sync::Arc::new(TerminalCloseExecutor {
            broker: broker.clone(),
            calls: std::sync::atomic::AtomicUsize::new(0),
            shutdown_started: tokio::sync::Notify::new(),
            shutdown_release: tokio::sync::Notify::new(),
            shutdown_done: tokio::sync::Notify::new(),
            fail: false,
        });
        let (peer, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let serving = tokio::spawn(serve_with_executor(
            tokio::io::BufReader::new(reader),
            FailingFrameWriter {
                inner: writer,
                frame_type,
                failed: failed.clone(),
            },
            ClientMessage::Hello {
                id: "h".into(),
                protocol: PROTOCOL.into(),
                required_capabilities: vec!["terminal.close/1".into()],
            },
            broker.clone(),
            executor.clone(),
        ));
        let mut peer = tokio::io::BufReader::new(peer);
        settlement_frame(&mut peer).await;
        peer.get_mut().write_all(b"{\"type\":\"request\",\"id\":\"r\",\"generation\":1,\"operationSeq\":1,\"timeoutMs\":1000,\"command\":\"uncertain\",\"args\":{}}\n").await.unwrap();
        let unknown = settlement_frame(&mut peer).await;
        assert_eq!(unknown["id"], "r");
        assert_eq!(unknown["effects"], "unknown");
        assert_eq!(unknown["error"]["code"], "browser-failure");
        executor.shutdown_started.notified().await;
        if cancel {
            peer.get_mut()
                .write_all(
                    b"{\"type\":\"cancel\",\"id\":\"c\",\"generation\":1,\"operationSeq\":1}\n",
                )
                .await
                .unwrap();
        }
        peer.get_mut()
            .write_all(b"{\"type\":\"close\",\"id\":\"z\",\"generation\":1}\n")
            .await
            .unwrap();
        executor.shutdown_release.notify_one();
        // The original precise Unknown reached the peer. Neither a lost cancel
        // ACK nor a failed Closed write can be substituted by the ensuing EOF.
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(&mut peer))
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
        assert!(failed.load(std::sync::atomic::Ordering::SeqCst));
        // The server's boolean is internal retained-owner proof, deliberately
        // distinct from the missing correlated wire receipt at this peer.
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), serving)
                .await
                .unwrap()
                .unwrap()
        );
        assert_eq!(executor.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn terminal_close_writer_failure_after_unknown_cannot_emit_closed() {
        terminal_close_lost_frame(b"\"type\":\"closed\"", false).await;
    }
    #[tokio::test]
    async fn terminal_close_missing_cancel_ack_preserves_unknown_without_cleanup_receipt() {
        terminal_close_lost_frame(b"\"type\":\"control-result\"", true).await;
    }
    struct PendingTerminalExecutor {
        broker: std::sync::Arc<ClientSession>,
        entered: tokio::sync::watch::Sender<usize>,
    }
    impl ClientExecutor for PendingTerminalExecutor {
        fn capabilities(&self) -> Vec<String> {
            vec![]
        }
        async fn execute(
            &self,
            command: String,
            _: serde_json::Map<String, serde_json::Value>,
            lease: OperationLease,
        ) -> NativeOutcome {
            if command != "not-started" {
                assert!(self.broker.start(lease.generation, lease.sequence).unwrap());
            }
            self.entered.send_modify(|count| *count += 1);
            if command == "terminal" {
                NativeOutcome {
                    retention: None,
                    result: Err(ProtocolError::BrowserFailure),
                    effects: Effects::Unknown,
                }
            } else {
                std::future::pending().await
            }
        }
        async fn shutdown(&self) -> Result<(), ProtocolError> {
            Ok(())
        }
    }
    #[tokio::test]
    async fn terminal_close_preserves_each_pending_started_classification_before_receipt() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let (entered, mut running) = tokio::sync::watch::channel(0usize);
        let executor = std::sync::Arc::new(PendingTerminalExecutor {
            broker: broker.clone(),
            entered,
        });
        let (peer, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let serving = tokio::spawn(serve_with_executor(
            tokio::io::BufReader::new(reader),
            writer,
            ClientMessage::Hello {
                id: "h".into(),
                protocol: PROTOCOL.into(),
                required_capabilities: vec!["terminal.close/1".into()],
            },
            broker,
            executor,
        ));
        let mut peer = tokio::io::BufReader::new(peer);
        settlement_frame(&mut peer).await;
        for (sequence, command) in [(1, "started"), (2, "not-started"), (3, "terminal")] {
            let request = format!("{{\"type\":\"request\",\"id\":\"r{sequence}\",\"generation\":1,\"operationSeq\":{sequence},\"timeoutMs\":5000,\"command\":\"{command}\",\"args\":{{}}}}\n");
            peer.get_mut().write_all(request.as_bytes()).await.unwrap();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                running.wait_for(|count| *count >= sequence),
            )
            .await
            .unwrap()
            .unwrap();
        }
        let original = settlement_frame(&mut peer).await;
        assert_eq!(original["id"], "r3");
        assert_eq!(original["effects"], "unknown");
        assert_eq!(original["error"]["code"], "browser-failure");
        peer.get_mut()
            .write_all(b"{\"type\":\"close\",\"id\":\"z\",\"generation\":1}\n")
            .await
            .unwrap();
        let mut outcomes = std::collections::HashMap::new();
        for _ in 0..2 {
            let result = settlement_frame(&mut peer).await;
            assert_eq!(result["type"], "result");
            assert_eq!(result["scopeState"], "quarantined");
            assert_eq!(result["error"]["code"], "cancelled");
            outcomes.insert(
                result["id"].as_str().unwrap().to_owned(),
                result["effects"].as_str().unwrap().to_owned(),
            );
        }
        assert_eq!(outcomes.get("r1").map(String::as_str), Some("unknown"));
        assert_eq!(
            outcomes.get("r2").map(String::as_str),
            Some("not-dispatched")
        );
        let closed = settlement_frame(&mut peer).await;
        assert_eq!(closed["type"], "closed");
        assert_eq!(closed["id"], "z");
        assert!(serving.await.unwrap());
    }

    struct PublishingExecutor {
        sink: std::sync::Mutex<Option<ClientEventSink>>,
    }
    impl ClientExecutor for PublishingExecutor {
        fn capabilities(&self) -> Vec<String> {
            vec![]
        }
        fn set_event_sink(&self, sink: ClientEventSink) -> Result<(), ProtocolError> {
            *self.sink.lock().unwrap() = Some(sink);
            Ok(())
        }
        async fn execute(
            &self,
            _: String,
            _: serde_json::Map<String, serde_json::Value>,
            lease: OperationLease,
        ) -> NativeOutcome {
            let sink = self.sink.lock().unwrap().clone().unwrap();
            let staged = sink.stage_until_result(&lease, "same-scope").unwrap();
            staged
                .emit(
                    "new".into(),
                    serde_json::json!({"identityScope":"same-scope"}),
                    None,
                )
                .unwrap();
            sink.emit(
                "old".into(),
                serde_json::json!({"identityScope":"same-scope"}),
                None,
            )
            .unwrap();
            NativeOutcome {
                retention: None,
                result: Ok(serde_json::json!({"identityScope":"same-scope"})),
                effects: Effects::Completed,
            }
        }
        async fn shutdown(&self) -> Result<(), ProtocolError> {
            Ok(())
        }
    }
    #[tokio::test]
    async fn actual_result_writer_flushes_ack_before_replacement_event() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let executor = std::sync::Arc::new(PublishingExecutor {
            sink: std::sync::Mutex::new(None),
        });
        let (client, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let task = tokio::spawn(serve_with_executor(
            tokio::io::BufReader::new(reader),
            writer,
            ClientMessage::Hello {
                id: "h".into(),
                protocol: PROTOCOL.into(),
                required_capabilities: vec![],
            },
            broker,
            executor,
        ));
        let mut client = tokio::io::BufReader::new(client);
        read_frame(&mut client).await.unwrap();
        client.get_mut().write_all(b"{\"type\":\"request\",\"id\":\"r\",\"generation\":1,\"operationSeq\":7,\"timeoutMs\":5000,\"command\":\"test\",\"args\":{}}\n").await.unwrap();
        let mut frames = Vec::new();
        for _ in 0..3 {
            let bytes =
                tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(&mut client))
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            frames.push(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap());
        }
        assert_eq!(frames[0]["event"], "old");
        assert_eq!(frames[1]["type"], "result");
        assert_eq!(frames[2]["event"], "new");
        assert_eq!(frames[0]["sequence"], 1);
        assert_eq!(frames[2]["sequence"], 2);
        drop(client);
        assert!(task.await.unwrap());
    }
    #[derive(Default)]
    struct FlushGate {
        result_seen: std::sync::atomic::AtomicBool,
        released: std::sync::atomic::AtomicBool,
        waker: std::sync::Mutex<Option<std::task::Waker>>,
    }
    struct GatedWriter<W> {
        inner: W,
        gate: std::sync::Arc<FlushGate>,
        gated_type: &'static [u8],
    }
    impl<W: AsyncWrite + Unpin> AsyncWrite for GatedWriter<W> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let result = std::pin::Pin::new(&mut self.inner).poll_write(cx, bytes);
            if let std::task::Poll::Ready(Ok(count)) = result {
                if bytes[..count]
                    .windows(self.gated_type.len())
                    .any(|part| part == self.gated_type)
                {
                    self.gate
                        .result_seen
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
            result
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let mut waker = self.gate.waker.lock().unwrap();
            if self
                .gate
                .result_seen
                .load(std::sync::atomic::Ordering::SeqCst)
                && !self.gate.released.load(std::sync::atomic::Ordering::SeqCst)
            {
                *waker = Some(cx.waker().clone());
                return std::task::Poll::Pending;
            }
            drop(waker);
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }
    #[tokio::test]
    async fn result_bytes_without_flush_ack_do_not_release_staged_events() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let executor = std::sync::Arc::new(PublishingExecutor {
            sink: std::sync::Mutex::new(None),
        });
        let (client, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let gate = std::sync::Arc::new(FlushGate::default());
        let task = tokio::spawn(serve_with_executor(
            tokio::io::BufReader::new(reader),
            GatedWriter {
                inner: writer,
                gate: gate.clone(),
                gated_type: b"\"type\":\"result\"",
            },
            ClientMessage::Hello {
                id: "h".into(),
                protocol: PROTOCOL.into(),
                required_capabilities: vec![],
            },
            broker,
            executor,
        ));
        let mut client = tokio::io::BufReader::new(client);
        read_frame(&mut client).await.unwrap();
        client.get_mut().write_all(b"{\"type\":\"request\",\"id\":\"r\",\"generation\":1,\"operationSeq\":7,\"timeoutMs\":5000,\"command\":\"test\",\"args\":{}}\n").await.unwrap();
        read_frame(&mut client).await.unwrap(); // Old producer remains live.
        let result = read_frame(&mut client).await.unwrap().unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&result).unwrap()["type"],
            "result"
        );
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            read_frame(&mut client)
        )
        .await
        .is_err());
        {
            let mut waker = gate.waker.lock().unwrap();
            gate.released
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(waker) = waker.take() {
                waker.wake();
            }
        }
        let event =
            tokio::time::timeout(std::time::Duration::from_secs(1), read_frame(&mut client))
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&event).unwrap()["event"],
            "new"
        );
        drop(client);
        assert!(task.await.unwrap());
    }
    struct UnknownCleanupExecutor {
        shutdown_reached: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    }
    impl ClientExecutor for UnknownCleanupExecutor {
        fn capabilities(&self) -> Vec<String> {
            vec![]
        }
        async fn execute(
            &self,
            _: String,
            _: serde_json::Map<String, serde_json::Value>,
            _: OperationLease,
        ) -> NativeOutcome {
            NativeOutcome {
                retention: None,
                result: Err(ProtocolError::BrowserFailure),
                effects: Effects::Unknown,
            }
        }
        async fn shutdown(&self) -> Result<(), ProtocolError> {
            if let Some(sender) = self.shutdown_reached.lock().unwrap().take() {
                let _ = sender.send(());
            }
            Err(ProtocolError::CleanupFailed)
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn terminal_cleanup_refusal_cannot_overtake_correlated_unknown_result() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let (shutdown_send, shutdown_receive) = tokio::sync::oneshot::channel();
        let executor = std::sync::Arc::new(UnknownCleanupExecutor {
            shutdown_reached: std::sync::Mutex::new(Some(shutdown_send)),
        });
        let (client, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let gate = std::sync::Arc::new(FlushGate::default());
        let task = tokio::spawn(serve_with_executor(
            tokio::io::BufReader::new(reader),
            GatedWriter {
                inner: writer,
                gate: gate.clone(),
                gated_type: b"\"type\":\"ready\"",
            },
            ClientMessage::Hello {
                id: "h".into(),
                protocol: PROTOCOL.into(),
                required_capabilities: vec![],
            },
            broker,
            executor,
        ));
        let mut client = tokio::io::BufReader::new(client);
        read_frame(&mut client).await.unwrap().unwrap();
        // Hold the writer on Ready's flush so both terminal messages queue
        // before it can choose a lane. Reader/control processing stays live.
        client.get_mut().write_all(b"{\"type\":\"request\",\"id\":\"r\",\"generation\":1,\"operationSeq\":7,\"timeoutMs\":5000,\"command\":\"test\",\"args\":{}}\n").await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), shutdown_receive)
            .await
            .unwrap()
            .unwrap();
        // On this current-thread runtime shutdown returns and the serve task
        // synchronously queues its refusal before yielding to this receiver.
        {
            let mut waker = gate.waker.lock().unwrap();
            gate.released
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(waker) = waker.take() {
                waker.wake();
            }
        }
        let mut messages = Vec::new();
        for _ in 0..2 {
            let bytes =
                tokio::time::timeout(std::time::Duration::from_secs(1), read_frame(&mut client))
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            messages.push(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap());
        }
        assert_eq!(messages[0]["type"], "result");
        assert_eq!(messages[0]["id"], "r");
        assert_eq!(messages[0]["operationSeq"], 7);
        assert_eq!(messages[0]["effects"], "unknown");
        assert_eq!(messages[0]["error"]["code"], "browser-failure");
        assert_eq!(messages[0]["scopeState"], "quarantined");
        assert_eq!(messages[1]["type"], "error");
        assert_eq!(messages[1]["error"]["code"], "cleanup-failed");
        assert!(!task.await.unwrap(), "terminal cleanup is still unproven");
    }

    struct StalledExecutor {
        broker: std::sync::Arc<ClientSession>,
        cleanup_succeeds: bool,
    }
    impl ClientExecutor for StalledExecutor {
        fn capabilities(&self) -> Vec<String> {
            vec![]
        }
        async fn execute(
            &self,
            _: String,
            _: serde_json::Map<String, serde_json::Value>,
            lease: OperationLease,
        ) -> NativeOutcome {
            self.broker.start(lease.generation, lease.sequence).unwrap();
            std::future::pending().await
        }
        async fn shutdown(&self) -> Result<(), ProtocolError> {
            if self.cleanup_succeeds {
                Ok(())
            } else {
                Err(ProtocolError::CleanupFailed)
            }
        }
    }

    #[test]
    fn event_sequence_is_publication_order_and_overflow_quarantines() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let (sender, mut receiver) = mpsc::channel(64);
        let sink = ClientEventSink {
            sender,
            broker: broker.clone(),
            sequence: Default::default(),
            open: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            barrier: None,
            persistent_page_reopen: Default::default(),
        };
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let sink = sink.clone();
                std::thread::spawn(move || {
                    sink.emit("test".into(), serde_json::json!({}), None)
                        .unwrap()
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        for expected in 1..=16 {
            assert!(
                matches!(receiver.try_recv().unwrap(), ServerMessage::Event { sequence, .. } if sequence == expected)
            );
        }
        for _ in 0..64 {
            sink.emit("test".into(), serde_json::json!({}), None)
                .unwrap();
        }
        assert_eq!(
            sink.emit("test".into(), serde_json::json!({}), None),
            Err(ProtocolError::CapacityExceeded)
        );
        assert_eq!(broker.health().unwrap().1, ScopeState::Quarantined);
    }

    #[tokio::test]
    async fn stalled_executor_keeps_control_live_and_unknown_never_usable() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let executor = std::sync::Arc::new(StalledExecutor {
            broker: broker.clone(),
            cleanup_succeeds: true,
        });
        let (client, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let hello = ClientMessage::Hello {
            id: "h".into(),
            protocol: PROTOCOL.into(),
            required_capabilities: vec![],
        };
        let task = tokio::spawn(serve_with_executor(
            tokio::io::BufReader::new(reader),
            writer,
            hello,
            broker,
            executor,
        ));
        let mut client = tokio::io::BufReader::new(client);
        read_frame(&mut client).await.unwrap();
        client.get_mut().write_all(b"{\"type\":\"request\",\"id\":\"r\",\"generation\":1,\"operationSeq\":1,\"timeoutMs\":1000,\"command\":\"test\",\"args\":{}}\n").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        client
            .get_mut()
            .write_all(b"{\"type\":\"cancel\",\"id\":\"c\",\"generation\":1,\"operationSeq\":1}\n")
            .await
            .unwrap();
        let frame = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            read_frame(&mut client),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let control: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(control["type"], "control-result");
        assert_eq!(control["accepted"], true);
        let frame =
            tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(&mut client))
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        let terminal: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(terminal["effects"], "unknown");
        assert_eq!(terminal["scopeState"], "quarantined");
        assert!(task.await.unwrap());
    }

    #[tokio::test]
    async fn failed_cleanup_never_emits_closed_or_releases_ownership_proof() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let executor = std::sync::Arc::new(StalledExecutor {
            broker: broker.clone(),
            cleanup_succeeds: false,
        });
        let (client, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let task = tokio::spawn(serve_with_executor(
            tokio::io::BufReader::new(reader),
            writer,
            ClientMessage::Hello {
                id: "h".into(),
                protocol: PROTOCOL.into(),
                required_capabilities: vec![],
            },
            broker,
            executor,
        ));
        let mut client = tokio::io::BufReader::new(client);
        read_frame(&mut client).await.unwrap();
        client
            .get_mut()
            .write_all(b"{\"type\":\"close\",\"id\":\"z\",\"generation\":1}\n")
            .await
            .unwrap();
        let frame = read_frame(&mut client).await.unwrap().unwrap();
        let terminal: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(terminal["type"], "error");
        assert_eq!(terminal["error"]["code"], "cleanup-failed");
        assert_eq!(terminal["scopeState"], "quarantined");
        assert!(!task.await.unwrap());
    }

    // Report bytes actually consumed, not merely written to the peer. This lets
    // completion deterministically cancel a read after its prefix is consumed.
    struct CountedReader<R> {
        inner: R,
        consumed: tokio::sync::watch::Sender<usize>,
    }
    impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for CountedReader<R> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
    impl<R: AsyncBufRead + Unpin> AsyncBufRead for CountedReader<R> {
        fn poll_fill_buf(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<&[u8]>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_fill_buf(cx)
        }
        fn consume(mut self: std::pin::Pin<&mut Self>, amount: usize) {
            std::pin::Pin::new(&mut self.inner).consume(amount);
            self.consumed.send_modify(|count| *count += amount);
        }
    }
    struct GatedReadExecutor {
        broker: std::sync::Arc<ClientSession>,
        finish: tokio::sync::Notify,
    }
    impl ClientExecutor for GatedReadExecutor {
        fn capabilities(&self) -> Vec<String> {
            vec![]
        }
        async fn execute(
            &self,
            _: String,
            _: serde_json::Map<String, serde_json::Value>,
            lease: OperationLease,
        ) -> NativeOutcome {
            self.broker.start(lease.generation, lease.sequence).unwrap();
            self.finish.notified().await;
            NativeOutcome {
                retention: None,
                result: Ok(serde_json::Value::Null),
                effects: Effects::NotDispatched,
            }
        }
        async fn shutdown(&self) -> Result<(), ProtocolError> {
            Ok(())
        }
    }
    #[tokio::test]
    async fn operation_completion_preserves_consumed_partial_control_frame() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let executor = std::sync::Arc::new(GatedReadExecutor {
            broker: broker.clone(),
            finish: tokio::sync::Notify::new(),
        });
        let (peer, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let (count, mut consumed) = tokio::sync::watch::channel(0usize);
        let serving = tokio::spawn(serve_with_executor(
            CountedReader {
                inner: tokio::io::BufReader::new(reader),
                consumed: count,
            },
            writer,
            ClientMessage::Hello {
                id: "h".into(),
                protocol: PROTOCOL.into(),
                required_capabilities: vec![],
            },
            broker,
            executor.clone(),
        ));
        let mut peer = tokio::io::BufReader::new(peer);
        read_frame(&mut peer).await.unwrap().unwrap();
        let request = b"{\"type\":\"request\",\"id\":\"r\",\"generation\":1,\"operationSeq\":1,\"timeoutMs\":5000,\"command\":\"test\",\"args\":{}}\n";
        let prefix = b"{\"type\":\"cancel\",\"id\":\"c\",";
        peer.get_mut().write_all(request).await.unwrap();
        peer.get_mut().write_all(prefix).await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            consumed.wait_for(|count| *count >= request.len() + prefix.len()),
        )
        .await
        .unwrap()
        .unwrap();
        executor.finish.notify_one();
        let first = tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(&mut peer))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let first: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(first["type"], "result");
        assert_eq!(first["id"], "r");
        // Receiving the result proves the competing completion branch ran.
        peer.get_mut()
            .write_all(b"\"generation\":1,\"operationSeq\":1}\n")
            .await
            .unwrap();
        let reply = tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(&mut peer))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let reply: serde_json::Value = serde_json::from_slice(&reply).unwrap();
        peer.get_mut().shutdown().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), serving)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply["type"], "control-result");
        assert_eq!(reply["id"], "c");
        assert_eq!(reply["accepted"], false);
        assert_eq!(reply["error"]["code"], "operation-missing");
    }

    struct TraceCleanupExecutor {
        broker: std::sync::Arc<ClientSession>,
        journal: super::super::client_debt::OperationJournalHandle,
        blobs: super::super::client_blobs::BlobStore,
        after_stop: std::time::Duration,
        late_success: bool,
        finished: std::sync::atomic::AtomicBool,
    }
    impl ClientExecutor for TraceCleanupExecutor {
        fn capabilities(&self) -> Vec<String> {
            vec![]
        }
        fn begin_trace_cleanup(
            &self,
            key: super::super::client_debt::OperationKey,
        ) -> Option<std::time::Instant> {
            (key == self.journal.key()).then(|| self.journal.begin_protected_cleanup())
        }
        fn discard_trace_result(
            &self,
            key: super::super::client_debt::OperationKey,
            value: &serde_json::Value,
        ) -> Result<(), ProtocolError> {
            self.blobs
                .discard_trace_image(key.generation, value)
                .map_err(|_| ProtocolError::CleanupFailed)
        }
        async fn execute(
            &self,
            _: String,
            _: serde_json::Map<String, serde_json::Value>,
            lease: OperationLease,
        ) -> NativeOutcome {
            assert!(self.broker.start(lease.generation, lease.sequence).unwrap());
            let image = if self.late_success {
                let scope = super::super::client_blobs::BlobScope {
                    generation: lease.generation,
                    identity_scope: "trace-scope".into(),
                };
                self.blobs.activate_scope(scope.clone()).unwrap();
                let producer = self.blobs.reserve_producer(scope).unwrap();
                let image = self.blobs.finish_producer(producer, vec![1, 2, 3]).unwrap();
                assert_eq!(self.blobs.charged_for_test(), (3, 1));
                Some(serde_json::json!({"identityScope":"trace-scope","handle":image.handle}))
            } else {
                None
            };
            let mut cancellation = lease.cancellation;
            while *cancellation.borrow() == super::super::client_session::CancelSignal::None {
                cancellation.changed().await.unwrap();
            }
            let error = (*cancellation.borrow()).error().unwrap();
            tokio::time::sleep(self.after_stop).await;
            self.finished
                .store(true, std::sync::atomic::Ordering::SeqCst);
            NativeOutcome {
                retention: None,
                result: image.map_or_else(|| Err(error), Ok),
                effects: Effects::Completed,
            }
        }
        async fn shutdown(&self) -> Result<(), ProtocolError> {
            Ok(())
        }
    }
    fn trace_executor(
        broker: std::sync::Arc<ClientSession>,
        lease: &OperationLease,
        after_stop: std::time::Duration,
        late_success: bool,
    ) -> std::sync::Arc<TraceCleanupExecutor> {
        let ledger = super::super::client_debt::OwnerDebtLedger::new(1, "trace-scope".into());
        let journal = ledger
            .operation(
                super::super::client_debt::OperationKey {
                    generation: 1,
                    operation_seq: 1,
                },
                "target".into(),
                "session".into(),
            )
            .unwrap();
        journal.bind_operation(lease).unwrap();
        std::sync::Arc::new(TraceCleanupExecutor {
            broker,
            journal,
            blobs: super::super::client_blobs::BlobStore::new(Default::default()).unwrap(),
            after_stop,
            late_success,
            finished: std::sync::atomic::AtomicBool::new(false),
        })
    }
    async fn trace_cleanup_case(
        trace: bool,
        after_stop: std::time::Duration,
        late_success: bool,
    ) -> (NativeOutcome, bool) {
        let broker = std::sync::Arc::new(ClientSession::new());
        let lease = broker.admit(1, 1, 20).unwrap();
        let executor = trace_executor(broker.clone(), &lease, after_stop, late_success);
        let outcome = execute_bounded(
            executor.clone(),
            broker,
            if trace {
                "capture.screenshot"
            } else {
                "browser.perform"
            }
            .into(),
            if trace {
                serde_json::from_value(serde_json::json!({"purpose":"trace"})).unwrap()
            } else {
                Default::default()
            },
            lease,
            true,
        )
        .await;
        assert_eq!(
            executor.blobs.charged_for_test(),
            (0, 0),
            "late receipt must release the actual producer charge"
        );
        executor.blobs.check_budget_integrity().unwrap();
        (
            outcome,
            executor.finished.load(std::sync::atomic::Ordering::SeqCst),
        )
    }
    #[tokio::test]
    async fn trace_cleanup_waits_for_original_producer_without_continuation() {
        // Complete cleanup before the original receipt decision point.
        let (outcome, finished) =
            trace_cleanup_case(true, std::time::Duration::from_millis(100), false).await;
        assert!(finished);
        assert_eq!(outcome.result, Err(ProtocolError::DeadlineExceeded));
        assert_eq!(outcome.effects, Effects::Completed);
        assert!(outcome.retention.is_none());
    }
    #[tokio::test]
    async fn trace_cleanup_never_publishes_success_after_success_deadline() {
        let (outcome, finished) =
            trace_cleanup_case(true, std::time::Duration::from_millis(100), true).await;
        assert!(finished);
        assert_eq!(outcome.result, Err(ProtocolError::DeadlineExceeded));
        assert!(outcome.retention.is_none());
    }
    #[tokio::test]
    async fn trace_pending_without_proof_keeps_unknown_and_does_not_extend_input_grace() {
        let (outcome, finished) = trace_cleanup_case(
            true,
            super::super::client_protected_read::CLEANUP_TIMEOUT
                + std::time::Duration::from_millis(200),
            false,
        )
        .await;
        assert!(!finished);
        assert_eq!(outcome.effects, Effects::Unknown);
        assert!(outcome.result.is_err());
        let (input, finished) =
            trace_cleanup_case(false, std::time::Duration::from_millis(350), false).await;
        assert!(!finished);
        assert_eq!(input.effects, Effects::Unknown);
    }
    #[tokio::test]
    async fn trace_receipt_reuses_an_earlier_cleanup_clock_without_proof() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let lease = broker.admit(1, 1, 500).unwrap();
        let executor = trace_executor(
            broker.clone(),
            &lease,
            std::time::Duration::from_millis(2_700),
            false,
        );
        let limit = executor.journal.begin_protected_cleanup();
        let outcome = execute_bounded(
            executor.clone(),
            broker,
            "capture.screenshot".into(),
            serde_json::from_value(serde_json::json!({"purpose":"trace"})).unwrap(),
            lease,
            true,
        )
        .await;
        assert_eq!(executor.journal.begin_protected_cleanup(), limit);
        assert_eq!(outcome.effects, Effects::Unknown);
        assert!(
            !executor.finished.load(std::sync::atomic::Ordering::SeqCst),
            "a pending producer without a usable proof cannot extend receipt grace"
        );
    }
    #[tokio::test]
    async fn trace_cancellation_uses_cleanup_clock_and_discards_late_image() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let lease = broker.admit(1, 1, 5_000).unwrap();
        let executor = trace_executor(
            broker.clone(),
            &lease,
            std::time::Duration::from_millis(100),
            true,
        );
        let cancel = broker.clone();
        let control = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            cancel.cancel(1, 1).unwrap();
        });
        let outcome = execute_bounded(
            executor.clone(),
            broker,
            "capture.screenshot".into(),
            serde_json::from_value(serde_json::json!({"purpose":"trace"})).unwrap(),
            lease,
            true,
        )
        .await;
        control.await.unwrap();
        assert_eq!(outcome.result, Err(ProtocolError::Cancelled));
        assert_eq!(executor.blobs.charged_for_test(), (0, 0));
        assert!(outcome.retention.is_none());
    }

    // These tests use the production reader, admission, execute_bounded,
    // completion, control lane, and result writer. The executable proxy's
    // process-global stdin/stdout are not injectable here, so they deliberately
    // do not claim coverage of the proxy or the TypeScript client.
    struct DeadlineSettlementExecutor {
        broker: std::sync::Arc<ClientSession>,
        started: tokio::sync::watch::Sender<Option<std::time::Instant>>,
        responsive: bool,
        shutdown_release: Option<tokio::sync::Notify>,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl ClientExecutor for DeadlineSettlementExecutor {
        fn capabilities(&self) -> Vec<String> {
            vec![]
        }
        async fn execute(
            &self,
            command: String,
            _: serde_json::Map<String, serde_json::Value>,
            lease: OperationLease,
        ) -> NativeOutcome {
            assert!(self.broker.start(lease.generation, lease.sequence).unwrap());
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if command == "fresh" {
                return NativeOutcome {
                    retention: None,
                    result: Ok(serde_json::json!({"fresh": true})),
                    effects: Effects::Completed,
                };
            }
            assert_eq!(command, "wait-for-native-stop");
            self.started.send_replace(Some(lease.deadline));
            if !self.responsive {
                return std::future::pending().await;
            }
            // Only the production deadline/cancel path wakes this executor.
            // It has no independent timeout that could substitute for the
            // native 250 ms cleanup grace or produce its own settlement.
            let mut cancellation = lease.cancellation.clone();
            while *cancellation.borrow() == super::super::client_session::CancelSignal::None {
                cancellation.changed().await.unwrap();
            }
            let reason = (*cancellation.borrow()).error().unwrap();
            NativeOutcome {
                retention: None,
                result: Err(reason),
                effects: Effects::NotDispatched,
            }
        }
        async fn shutdown(&self) -> Result<(), ProtocolError> {
            if let Some(release) = &self.shutdown_release {
                release.notified().await;
            }
            Ok(())
        }
    }

    async fn settlement_frame<R: AsyncBufRead + Unpin>(reader: &mut R) -> serde_json::Value {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(reader))
            .await
            .expect("settlement frame must arrive within the bounded test wait")
            .unwrap()
            .expect("settlement must not be replaced by EOF");
        serde_json::from_slice(&frame).unwrap()
    }

    #[derive(Clone, Copy, Debug)]
    enum DeadlineCancelOrder {
        CancelFirst,
        ResultFirst,
        PartialCancelAcrossResult,
    }

    async fn exercise_deadline_cancel_order(order: DeadlineCancelOrder) {
        let broker = std::sync::Arc::new(ClientSession::new());
        let (started, mut running) = tokio::sync::watch::channel(None);
        let executor = std::sync::Arc::new(DeadlineSettlementExecutor {
            broker: broker.clone(),
            started,
            responsive: true,
            shutdown_release: None,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let (peer, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let (count, mut consumed) = tokio::sync::watch::channel(0usize);
        let serving = tokio::spawn(serve_with_executor(
            CountedReader {
                inner: tokio::io::BufReader::new(reader),
                consumed: count,
            },
            writer,
            ClientMessage::Hello {
                id: "h".into(),
                protocol: PROTOCOL.into(),
                required_capabilities: vec![],
            },
            broker.clone(),
            executor.clone(),
        ));
        let mut peer = tokio::io::BufReader::new(peer);
        assert_eq!(settlement_frame(&mut peer).await["type"], "ready");
        let request = b"{\"type\":\"request\",\"id\":\"r\",\"generation\":1,\"operationSeq\":1,\"timeoutMs\":1000,\"command\":\"wait-for-native-stop\",\"args\":{}}\n";
        let prefix = b"{\"type\":\"cancel\",\"id\":\"c\",";
        let suffix = b"\"generation\":1,\"operationSeq\":1}\n";
        peer.get_mut().write_all(request).await.unwrap();
        let deadline = *tokio::time::timeout(
            std::time::Duration::from_secs(2),
            running.wait_for(Option::is_some),
        )
        .await
        .unwrap()
        .unwrap();

        if matches!(order, DeadlineCancelOrder::PartialCancelAcrossResult) {
            peer.get_mut().write_all(prefix).await.unwrap();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                consumed.wait_for(|count| *count >= request.len() + prefix.len()),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(std::time::Instant::now() < deadline.unwrap());
        }
        let (result, ack) = if matches!(order, DeadlineCancelOrder::CancelFirst) {
            assert!(std::time::Instant::now() < deadline.unwrap());
            peer.get_mut().write_all(prefix).await.unwrap();
            peer.get_mut().write_all(suffix).await.unwrap();
            let ack = settlement_frame(&mut peer).await;
            let result = settlement_frame(&mut peer).await;
            (result, ack)
        } else {
            // The complete original response proves the native completion and
            // writer ran before the control suffix is made readable.
            let result = settlement_frame(&mut peer).await;
            if matches!(order, DeadlineCancelOrder::ResultFirst) {
                peer.get_mut().write_all(prefix).await.unwrap();
            }
            peer.get_mut().write_all(suffix).await.unwrap();
            (result, settlement_frame(&mut peer).await)
        };
        let cancelled = matches!(order, DeadlineCancelOrder::CancelFirst);
        assert_eq!(result["type"], "result", "{order:?}: {result}");
        assert_eq!(result["id"], "r");
        assert_eq!(result["operationSeq"], 1);
        assert_eq!(result["ok"], false);
        assert_eq!(result["effects"], "not-dispatched");
        assert_eq!(result["scopeState"], "usable");
        assert_eq!(
            result["error"]["code"],
            if cancelled {
                "cancelled"
            } else {
                "deadline-exceeded"
            }
        );
        assert_eq!(ack["type"], "control-result", "{order:?}: {ack}");
        assert_eq!(ack["id"], "c");
        assert_eq!(ack["generation"], 1);
        assert_eq!(ack["accepted"], cancelled);
        assert_eq!(ack["scopeState"], "usable");
        if !cancelled {
            assert_eq!(ack["error"]["code"], "operation-missing");
        }
        peer.get_mut().write_all(b"{\"type\":\"request\",\"id\":\"fresh\",\"generation\":1,\"operationSeq\":2,\"timeoutMs\":1000,\"command\":\"fresh\",\"args\":{}}\n").await.unwrap();
        let fresh = settlement_frame(&mut peer).await;
        assert_eq!(fresh["type"], "result");
        assert_eq!(fresh["id"], "fresh");
        assert_eq!(fresh["operationSeq"], 2);
        assert_eq!(fresh["ok"], true);
        assert_eq!(fresh["effects"], "completed");
        assert_eq!(fresh["scopeState"], "usable");
        assert_eq!(fresh["data"]["fresh"], true);
        assert_eq!(executor.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        peer.get_mut()
            .write_all(b"{\"type\":\"close\",\"id\":\"z\",\"generation\":1}\n")
            .await
            .unwrap();
        assert_eq!(settlement_frame(&mut peer).await["type"], "closed");
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), serving)
                .await
                .unwrap()
                .unwrap()
        );
        assert_eq!(broker.health().unwrap().1, ScopeState::Closed);
    }

    #[tokio::test]
    async fn settlement_deadline_acknowledges_late_complete_cancel_before_reuse() {
        exercise_deadline_cancel_order(DeadlineCancelOrder::ResultFirst).await;
    }

    #[tokio::test]
    async fn settlement_deadline_preserves_partial_cancel_until_late_ack_before_reuse() {
        exercise_deadline_cancel_order(DeadlineCancelOrder::PartialCancelAcrossResult).await;
    }

    #[tokio::test]
    async fn settlement_deadline_early_cancel_ack_precedes_clean_result_and_reuse() {
        exercise_deadline_cancel_order(DeadlineCancelOrder::CancelFirst).await;
    }

    #[tokio::test]
    async fn settlement_deadline_unknown_flushes_before_shutdown_without_fabricated_late_ack() {
        let broker = std::sync::Arc::new(ClientSession::new());
        let (started, _running) = tokio::sync::watch::channel(None);
        let executor = std::sync::Arc::new(DeadlineSettlementExecutor {
            broker: broker.clone(),
            started,
            responsive: false,
            shutdown_release: Some(tokio::sync::Notify::new()),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let (peer, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let serving = tokio::spawn(serve_with_executor(
            tokio::io::BufReader::new(reader),
            writer,
            ClientMessage::Hello {
                id: "h".into(),
                protocol: PROTOCOL.into(),
                required_capabilities: vec![],
            },
            broker.clone(),
            executor.clone(),
        ));
        let mut peer = tokio::io::BufReader::new(peer);
        assert_eq!(settlement_frame(&mut peer).await["type"], "ready");
        peer.get_mut().write_all(b"{\"type\":\"request\",\"id\":\"r\",\"generation\":1,\"operationSeq\":1,\"timeoutMs\":100,\"command\":\"wait-for-native-stop\",\"args\":{}}\n").await.unwrap();
        let result = settlement_frame(&mut peer).await;
        assert_eq!(result["type"], "result");
        assert_eq!(result["id"], "r");
        assert_eq!(result["operationSeq"], 1);
        assert_eq!(result["ok"], false);
        assert_eq!(result["error"]["code"], "deadline-exceeded");
        assert_eq!(result["effects"], "unknown");
        assert_eq!(result["scopeState"], "quarantined");
        assert_eq!(broker.health().unwrap().1, ScopeState::Quarantined);
        // Shutdown is held after the truthful Unknown result. A late control
        // write must not invent receipt, successful cancellation, or reuse.
        peer.get_mut()
            .write_all(b"{\"type\":\"cancel\",\"id\":\"c\",\"generation\":1,\"operationSeq\":1}\n")
            .await
            .unwrap();
        executor.shutdown_release.as_ref().unwrap().notify_one();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(&mut peer))
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), serving)
                .await
                .unwrap()
                .unwrap()
        );
        assert_eq!(executor.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(broker.health().unwrap().1, ScopeState::Closed);
        assert!(broker.admit(1, 2, 1000).is_err());
    }

    async fn read_unobserved_retained_frame<R: AsyncBufRead + Unpin>(
        reader: &mut R,
        frame: &mut Vec<u8>,
    ) -> Result<Option<Vec<u8>>, ProtocolError> {
        #[cfg(feature = "acceptance-faults")]
        {
            read_frame_retained(reader, frame, None).await
        }
        #[cfg(not(feature = "acceptance-faults"))]
        {
            read_frame_retained(reader, frame).await
        }
    }

    #[tokio::test]
    async fn retained_frame_state_preserves_bounds_and_resets_only_at_newline() {
        let mut frame = b"prefix".to_vec();
        let mut bytes = &b"-suffix\nnext\n"[..];
        assert_eq!(
            read_unobserved_retained_frame(&mut bytes, &mut frame)
                .await
                .unwrap(),
            Some(b"prefix-suffix".to_vec())
        );
        assert!(frame.is_empty());
        assert_eq!(
            read_unobserved_retained_frame(&mut bytes, &mut frame)
                .await
                .unwrap(),
            Some(b"next".to_vec())
        );
        assert_eq!(
            read_unobserved_retained_frame(&mut bytes, &mut frame)
                .await
                .unwrap(),
            None
        );
        frame = vec![b'a'; MAX_FRAME_BYTES];
        assert!(read_unobserved_retained_frame(&mut &b"b\n"[..], &mut frame)
            .await
            .is_err());
        frame = b"incomplete".to_vec();
        assert!(read_unobserved_retained_frame(&mut &b""[..], &mut frame)
            .await
            .is_err());
    }

    #[cfg(feature = "acceptance-faults")]
    struct TraceMemoryReader {
        bytes: Vec<u8>,
        offset: usize,
        pending: bool,
        error: Option<std::io::ErrorKind>,
    }
    #[cfg(feature = "acceptance-faults")]
    impl tokio::io::AsyncRead for TraceMemoryReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::other("unused read seam")))
        }
    }
    #[cfg(feature = "acceptance-faults")]
    impl AsyncBufRead for TraceMemoryReader {
        fn poll_fill_buf(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<&[u8]>> {
            let reader = self.get_mut();
            if reader.offset < reader.bytes.len() {
                return std::task::Poll::Ready(Ok(&reader.bytes[reader.offset..]));
            }
            if reader.pending {
                return std::task::Poll::Pending;
            }
            if let Some(kind) = reader.error {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    kind,
                    "https://do-not-capture.invalid/?token=private-error",
                )));
            }
            std::task::Poll::Ready(Ok(&[]))
        }
        fn consume(self: std::pin::Pin<&mut Self>, amount: usize) {
            self.get_mut().offset += amount;
        }
    }

    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn acceptance_phase_retained_frame_counts_survive_cancelled_future() {
        use super::super::client_settlement_trace::FrameTrace;
        use std::future::Future;
        let mut reader = TraceMemoryReader {
            bytes: b"prefix".to_vec(),
            offset: 0,
            pending: true,
            error: None,
        };
        let mut frame = Vec::new();
        let mut trace = FrameTrace::new(Some(7));
        let mut waiting = Box::pin(read_frame_retained(
            &mut reader,
            &mut frame,
            Some(&mut trace),
        ));
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(waiting);
        assert_eq!(frame, b"prefix");
        assert_eq!(trace.test_state(), (13, 6, 0, None));
        reader.bytes.extend_from_slice(b"-suffix\nnext\n");
        reader.pending = false;
        assert_eq!(
            read_frame_retained(&mut reader, &mut frame, Some(&mut trace))
                .await
                .unwrap(),
            Some(b"prefix-suffix".to_vec())
        );
        assert_eq!(
            trace.test_state(),
            (21, 0, 1, Some(SettlementPhase::FrameComplete))
        );
        assert_eq!(
            read_frame_retained(&mut reader, &mut frame, Some(&mut trace))
                .await
                .unwrap(),
            Some(b"next".to_vec())
        );
        assert_eq!(
            trace.test_state(),
            (26, 0, 2, Some(SettlementPhase::FrameComplete))
        );
        assert_eq!(
            read_frame_retained(&mut reader, &mut frame, Some(&mut trace))
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            trace.test_state(),
            (26, 0, 2, Some(SettlementPhase::FrameCleanEof))
        );
    }

    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn acceptance_phase_retained_frame_eof_io_and_oversize_preserve_errors() {
        use super::super::client_settlement_trace::FrameTrace;
        for (bytes, error, phase, consumed) in [
            (
                b"partial".to_vec(),
                None,
                SettlementPhase::FramePartialEof,
                7,
            ),
            (
                b"part".to_vec(),
                Some(std::io::ErrorKind::Interrupted),
                SettlementPhase::FrameIoError,
                4,
            ),
            (
                vec![b'x'; MAX_FRAME_BYTES + 1],
                None,
                SettlementPhase::FrameOversize,
                0,
            ),
        ] {
            let mut reader = TraceMemoryReader {
                bytes,
                offset: 0,
                pending: false,
                error,
            };
            let mut frame = Vec::new();
            let mut trace = FrameTrace::new(Some(9));
            assert_eq!(
                read_frame_retained(&mut reader, &mut frame, Some(&mut trace)).await,
                Err(ProtocolError::InvalidFrame)
            );
            assert_eq!(trace.test_state(), (9 + consumed, consumed, 0, Some(phase)));
            assert_eq!(reader.offset as u64, consumed);
        }
        let mut bytes = &b"invalid-complete-frame\n"[..];
        let mut frame = Vec::new();
        let mut trace = FrameTrace::new(Some(9));
        let complete = read_frame_retained(&mut bytes, &mut frame, Some(&mut trace))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(trace.test_state().3, Some(SettlementPhase::FrameComplete));
        assert!(parse_frame(&complete).is_err());
        assert!(frame.is_empty());
    }

    #[tokio::test]
    async fn rejects_unterminated_oversize_and_invalid_utf8() {
        let bytes = vec![b'a'; MAX_FRAME_BYTES + 1];
        assert!(read_frame(&mut &bytes[..]).await.is_err());
        assert!(parse_frame(&[0xff]).is_err());
        assert!(read_frame(&mut &b"partial"[..]).await.is_err());
    }
    struct BlobExecutor {
        store: super::super::client_blobs::BlobStore,
        scope: super::super::client_blobs::BlobScope,
    }
    impl ClientExecutor for BlobExecutor {
        fn capabilities(&self) -> Vec<String> {
            vec![]
        }
        fn prepare_decision(
            &self,
            generation: u64,
            token: &str,
            decision: &Decision,
        ) -> Result<(), ProtocolError> {
            if generation != self.scope.generation {
                return Err(ProtocolError::StaleGeneration);
            }
            if let Some(handle) = decision.body_handle() {
                self.store
                    .reserve(&self.scope, handle, token)
                    .map_err(|_| ProtocolError::InvalidArguments)?;
            }
            Ok(())
        }
        fn finish_decision(&self, token: &str, accepted: bool) -> Result<(), ProtocolError> {
            if !accepted {
                self.store
                    .rollback(token)
                    .map_err(|_| ProtocolError::CleanupFailed)?;
            }
            Ok(())
        }
        async fn execute(
            &self,
            _: String,
            _: serde_json::Map<String, serde_json::Value>,
            _: OperationLease,
        ) -> NativeOutcome {
            NativeOutcome {
                retention: None,
                result: Err(ProtocolError::UnsupportedCommand),
                effects: Effects::NotDispatched,
            }
        }
        async fn shutdown(&self) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn body_reservation_precedes_selection_and_rejection_restores_handle() {
        use super::super::client_blobs::{BlobLimits, BlobScope, BlobStore};
        use super::super::client_session::{DecisionKind, DecisionOutcome, DecisionOwner};
        let broker = ClientSession::new();
        let executor = BlobExecutor {
            store: BlobStore::new(BlobLimits::default()).unwrap(),
            scope: BlobScope {
                generation: 1,
                identity_scope: "owned".into(),
            },
        };
        executor
            .store
            .activate_scope(executor.scope.clone())
            .unwrap();
        let body = executor
            .store
            .insert_sealed(executor.scope.clone(), b"synthetic")
            .unwrap();
        let decision = || Decision::Fulfill {
            status: 200,
            headers: vec![],
            body_base64: None,
            body_handle: Some(body.handle.clone()),
        };
        let message = |token: String| ClientMessage::Decision {
            id: "control".into(),
            generation: 1,
            token,
            decision: decision(),
        };
        let (rejected, _) = respond(&broker, message("missing".into()), &executor);
        assert!(matches!(
            rejected,
            ServerMessage::ControlResult {
                accepted: false,
                ..
            }
        ));
        // Rollback after rejected token leaves the same sealed handle usable.
        let lease = broker
            .decision(1, DecisionOwner::Scope, DecisionKind::Request, 1000, None)
            .unwrap();
        let (selected, _) = respond(&broker, message(lease.token.clone()), &executor);
        assert!(matches!(
            selected,
            ServerMessage::ControlResult { accepted: true, .. }
        ));
        assert!(matches!(
            lease.outcome.await.unwrap(),
            DecisionOutcome::Selected(_)
        ));
        let other = executor
            .store
            .insert_sealed(executor.scope.clone(), b"other")
            .unwrap();
        let replay = ClientMessage::Decision {
            id: "replay".into(),
            generation: 1,
            token: lease.token.clone(),
            decision: Decision::Fulfill {
                status: 200,
                headers: vec![],
                body_base64: None,
                body_handle: Some(other.handle.clone()),
            },
        };
        let (rejected, _) = respond(&broker, replay, &executor);
        assert!(matches!(
            rejected,
            ServerMessage::ControlResult {
                accepted: false,
                ..
            }
        ));
        executor
            .store
            .release(&executor.scope, &other.handle)
            .unwrap();
        // Selection wakes consumers before finish returns; reservation already
        // blocks release and native consumer alone can atomically claim bytes.
        assert!(executor
            .store
            .release(&executor.scope, &body.handle)
            .is_err());
        let bytes = executor
            .store
            .commit(&executor.scope, &body.handle, &lease.token)
            .unwrap();
        assert_eq!(bytes.bytes(), b"synthetic");
        assert!(executor
            .store
            .commit(&executor.scope, &body.handle, &lease.token)
            .is_err());
    }

    #[tokio::test]
    async fn unwired_blob_body_does_not_consume_decision_token() {
        use super::super::client_session::{DecisionKind, DecisionOwner};
        let broker = std::sync::Arc::new(ClientSession::new());
        let executor = StalledExecutor {
            broker: broker.clone(),
            cleanup_succeeds: true,
        };
        let lease = broker
            .decision(1, DecisionOwner::Scope, DecisionKind::Request, 1000, None)
            .unwrap();
        let message = ClientMessage::Decision {
            id: "control".into(),
            generation: 1,
            token: lease.token.clone(),
            decision: Decision::Fulfill {
                status: 200,
                headers: vec![],
                body_base64: None,
                body_handle: Some("sealed-body".into()),
            },
        };
        let (rejected, _) = respond(&broker, message, &executor);
        assert!(matches!(
            rejected,
            ServerMessage::ControlResult {
                accepted: false,
                error: Some(WireError {
                    code: ProtocolError::UnsupportedCapability
                }),
                ..
            }
        ));
        broker.resolve(1, &lease.token, Decision::Abort {}).unwrap();
    }

    #[test]
    fn unavailable_browser_commands_never_claim_execution() {
        let broker = ClientSession::new();
        let message = ClientMessage::Request {
            id: "r".into(),
            generation: 1,
            operation_seq: 1,
            timeout_ms: 1000,
            command: "click".into(),
            callback_token: None,
            args: Default::default(),
        };
        let executor = StalledExecutor {
            broker: std::sync::Arc::new(ClientSession::new()),
            cleanup_succeeds: true,
        };
        let (reply, _) = respond(&broker, message, &executor);
        assert!(matches!(
            reply,
            ServerMessage::Result {
                effects: Effects::NotDispatched,
                ok: false,
                ..
            }
        ));
    }
    mod terminal_artifact_tests {
        include!("client_transport_terminal_artifact_tests.rs");
    }
    mod interop_replacement_emission_tests {
        include!("client_interop_replacement_emission_tests.rs");
    }
}

#[cfg(test)]
#[path = "client_operation_retention_tests.rs"]
mod operation_retention_tests;

#[cfg(test)]
#[path = "client_preparation_admission_tests.rs"]
mod preparation_admission_tests;
