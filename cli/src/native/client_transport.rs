//! Bounded negotiated transport with independently serviced native control.
//! Only the owned executor advertises implemented browser capabilities.
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use super::client_protocol::*;
use super::client_session::{ClientSession, OperationLease};

// Acceptance-only diagnostics: closed phases and native operation sequence only.
// Never serialize requests, IDs, browser values, or error descriptions.
#[cfg(feature = "acceptance-faults")]
#[derive(Debug)]
enum SettlementPhase {
    ExecuteStarted,
    ExecuteReturned,
    CancelObserved,
    DeadlineObserved,
    GraceReturned,
    GraceExpired,
    CompletionJoined,
    ResultQueued,
    ResultFlushed,
    ControlFlushed,
    CancelReceived,
    CancelAccepted,
    CancelRejected,
    CancelQueued,
    ReaderEnded,
    ReaderRefused,
    WriterFailed,
    PublicationExpired,
    HealthFailed,
    CompletionLost,
    ResultQueueFailed,
    UnknownOutcome,
    CloseReceived,
    ControlQueueFailed,
    ShutdownStarted,
    ShutdownProven,
    ShutdownUnproven,
    PendingResultQueued,
}
macro_rules! settlement_trace {
    ($sequence:expr, $phase:ident) => {
        #[cfg(feature = "acceptance-faults")]
        eprintln!(
            "native-settlement sequence={} phase={:?}",
            $sequence,
            SettlementPhase::$phase
        );
    };
}

/// Browser mechanics stay native. The reader only admits work and forwards
/// control; executors never own its lock or the output transport.
pub struct NativeOutcome {
    pub result: Result<serde_json::Value, ProtocolError>,
    pub effects: Effects,
}

pub trait ClientExecutor: Send + Sync + 'static {
    fn capabilities(&self) -> Vec<String>;
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
    scope_gate: std::sync::Arc<ScopeEmissionGate>,
    deadline: std::time::Instant,
    state: std::sync::Mutex<EventBarrierState>,
    changed: tokio::sync::Notify,
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
/// Reliable bounded event lane. A replacement producer receives a distinct
/// operation-bound clone; old callback producers retain their live clone.
#[derive(Clone)]
pub struct ClientEventSink {
    sender: mpsc::Sender<ServerMessage>,
    broker: std::sync::Arc<ClientSession>,
    sequence: std::sync::Arc<std::sync::Mutex<EventOrder>>,
    open: std::sync::Arc<std::sync::atomic::AtomicBool>,
    barrier: Option<std::sync::Arc<EventBarrier>>,
}
impl ClientEventSink {
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
            },
            receiver,
        )
    }
    /// Native lifecycle-only. No waiting task or action lock is held by the
    /// barrier: the actual result writer performs publication after flush.
    pub(crate) fn stage_until_result(
        &self,
        operation: &OperationLease,
        identity_scope: &str,
    ) -> Result<Self, ProtocolError> {
        self.check_open()?;
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
            scope_gate,
            deadline: operation.deadline,
            state: std::sync::Mutex::new(EventBarrierState::Holding(Vec::new())),
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
    ) -> Result<(), ProtocolError> {
        proof.check_event_sink(self)?;
        proof.check_targets(proof.targets())?;
        self.retire_scope_callbacks(proof.generation(), &proof.targets().identity_scope)
    }
    fn retire_scope_callbacks(&self, generation: u64, scope: &str) -> Result<(), ProtocolError> {
        let barrier = self.barrier.as_ref().ok_or(ProtocolError::StaleScope)?;
        if barrier.key.0 != generation || barrier.identity_scope != scope {
            return Err(ProtocolError::StaleScope);
        }
        let result = (|| {
            let mut order = self
                .sequence
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if self.check_open()? != generation {
                return Err(ProtocolError::StaleGeneration);
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
            // Seal before enqueue. Queue failure must never reopen old producers.
            barrier
                .scope_gate
                .closed
                .store(true, std::sync::atomic::Ordering::Release);
            let through = order.sequence;
            self.enqueue_event(&mut order, ServerMessage::Event {
                generation, sequence: MAX_SAFE_SEQUENCE,
                event: "scope.callbacks-retired".into(),
                payload: serde_json::json!({"identityScope":scope,"throughEventSequence":through}),
                decision: None,
            })
        })();
        if result.is_err() && result != Err(ProtocolError::StaleScope) {
            let _ = self.broker.quarantine();
        }
        result
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
        if data
            .as_ref()
            .and_then(|value| value.get("identityScope"))
            .and_then(serde_json::Value::as_str)
            != Some(barrier.identity_scope.as_str())
        {
            return Err(ProtocolError::StaleScope);
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
    read_frame_retained(reader, &mut Vec::new()).await
}

// The transport select loop owns this buffer across timer/control/completion
// branches. fill_buf is cancellation-safe; consumed bytes must also survive
// cancellation of the future which is waiting for the remaining frame.
async fn read_frame_retained<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    frame: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|_| ProtocolError::InvalidFrame)?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(ProtocolError::InvalidFrame)
            };
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let length = newline.unwrap_or(available.len());
        if frame.len() + length > MAX_FRAME_BYTES {
            return Err(ProtocolError::InvalidFrame);
        }
        frame.extend_from_slice(&available[..length]);
        reader.consume(length + usize::from(newline.is_some()));
        if newline.is_some() {
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

pub async fn serve<R, W>(reader: R, writer: W, hello: ClientMessage) -> bool
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let broker = std::sync::Arc::new(ClientSession::new());
    let executor = std::sync::Arc::new(super::client_browser::ClientBrowser::new(broker.clone()));
    serve_with_executor(reader, writer, hello, broker, executor).await
}

/// Reader/control work never takes the executor's browser lock. False means
/// cleanup is unproven and the daemon MUST retain its exclusive ownership gate.
pub async fn serve_with_executor<R, W, E>(
    mut reader: R,
    mut writer: W,
    hello: ClientMessage,
    broker: std::sync::Arc<ClientSession>,
    executor: std::sync::Arc<E>,
) -> bool
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
    E: ClientExecutor,
{
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
                ServerMessage::Result { operation_seq, .. } => {
                    settlement_trace!(*operation_seq, ResultFlushed);
                }
                ServerMessage::ControlResult { .. } => {
                    settlement_trace!(0, ControlFlushed);
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
    let capabilities = executor.capabilities();
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
    let mut pending = std::collections::HashMap::<u64, (String, u64)>::new();
    let mut closing_id = None;
    let mut timer = tokio::time::interval(std::time::Duration::from_millis(25));
    if valid && ready_queued {
        let mut incoming_frame = Vec::new();
        loop {
            let frame = tokio::select! {
                frame = read_frame_retained(&mut reader, &mut incoming_frame) => frame,
                _ = &mut failure => { settlement_trace!(0, WriterFailed); break; },
                _ = timer.tick() => {
                    let _ = broker.expire_decisions();
                    if sink.expire_publications().is_err() { settlement_trace!(0, PublicationExpired); let _ = broker.quarantine(); break; }
                    if !broker.health().is_ok_and(|(_, state)| state == ScopeState::Usable) { settlement_trace!(0, HealthFailed); break; }
                    for (version,identity_scope) in broker.take_released_registry_events(16).unwrap_or_default() {
                        let mut payload=serde_json::json!({ "registryVersion": version });
                        if let Some(scope)=identity_scope { payload["identityScope"]=serde_json::json!(scope); }
                        if sink.emit("registry-released".into(), payload, None).is_err() { break; }
                    }
                    if !broker.health().is_ok_and(|(_, state)| state == ScopeState::Usable) { settlement_trace!(0, HealthFailed); break; }
                    continue;
                },
                completion = operations.join_next(), if !operations.is_empty() => {
                    let Some(Ok((sequence, outcome))) = completion else { settlement_trace!(0, CompletionLost); break; };
                    settlement_trace!(sequence, CompletionJoined);
                    let Some((id, generation)) = pending.remove(&sequence) else { settlement_trace!(sequence, CompletionLost); break; };
                    let state = broker.settle(generation, sequence, outcome.effects).unwrap_or(ScopeState::Quarantined);
                    let unknown = outcome.effects == Effects::Unknown;
                    if !enqueue(&sender, result_message(id, generation, sequence, outcome, state), &broker) { settlement_trace!(sequence, ResultQueueFailed); break; }
                    settlement_trace!(sequence, ResultQueued);
                    if unknown { settlement_trace!(sequence, UnknownOutcome); break; }
                    continue;
                },
            };
            let message = match frame {
                Ok(Some(bytes)) => parse_frame(&bytes),
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
                    match broker.admit_callback(
                        generation,
                        operation_seq,
                        timeout_ms,
                        callback_token.as_deref(),
                    ) {
                        Ok(lease) => {
                            pending.insert(operation_seq, (id, generation));
                            let executor = executor.clone();
                            let broker = broker.clone();
                            operations.spawn(async move {
                                (
                                    operation_seq,
                                    execute_bounded(executor, broker, command, args, lease).await,
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
                                        result: Err(code),
                                        effects: Effects::NotDispatched,
                                    },
                                    state,
                                ),
                                &broker,
                            ) {
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
                    closing_id = Some(id);
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
    // Aborting schedules cancellation; joining proves execution guards dropped.
    let drained = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while operations.join_next().await.is_some() {}
    })
    .await
    .is_ok();
    let teardown_proven = if drained {
        matches!(
            tokio::time::timeout(std::time::Duration::from_secs(5), executor.shutdown()).await,
            Ok(Ok(()))
        )
    } else {
        false
    };
    #[cfg(feature = "acceptance-faults")]
    if teardown_proven {
        settlement_trace!(0, ShutdownProven);
    } else {
        settlement_trace!(0, ShutdownUnproven);
    }
    for (sequence, (id, generation)) in pending {
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
    ServerMessage::Result {
        id,
        generation,
        operation_seq,
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
) -> NativeOutcome {
    let sequence = lease.sequence;
    let generation = lease.generation;
    let deadline = tokio::time::Instant::from_std(lease.deadline);
    let mut cancellation = lease.cancellation.clone();
    settlement_trace!(sequence, ExecuteStarted);
    let execution = executor.execute(command, args, lease);
    tokio::pin!(execution);
    let reason = tokio::select! {
        biased;
        outcome = &mut execution => { settlement_trace!(sequence, ExecuteReturned); return outcome; },
        _ = cancellation.changed() => { settlement_trace!(sequence, CancelObserved); ProtocolError::Cancelled },
        _ = tokio::time::sleep_until(deadline) => { settlement_trace!(sequence, DeadlineObserved); ProtocolError::DeadlineExceeded },
    };
    let _ = broker.cancel(generation, sequence);
    if let Ok(outcome) =
        tokio::time::timeout(std::time::Duration::from_millis(250), &mut execution).await
    {
        settlement_trace!(sequence, GraceReturned);
        return outcome;
    }
    settlement_trace!(sequence, GraceExpired);
    NativeOutcome {
        result: Err(reason),
        effects: if broker.has_started(sequence) {
            Effects::Unknown
        } else {
            Effects::NotDispatched
        },
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
            #[cfg(feature = "acceptance-faults")]
            if result.is_ok() {
                settlement_trace!(operation_seq, CancelAccepted);
            } else {
                settlement_trace!(operation_seq, CancelRejected);
            }
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
                result: Ok(serde_json::json!({"identityScope":scope})),
                effects: Effects::Completed,
            },
            ScopeState::Usable,
        ))
        .unwrap();
        staged
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

    #[tokio::test]
    async fn retained_frame_state_preserves_bounds_and_resets_only_at_newline() {
        let mut frame = b"prefix".to_vec();
        let mut bytes = &b"-suffix\nnext\n"[..];
        assert_eq!(
            read_frame_retained(&mut bytes, &mut frame).await.unwrap(),
            Some(b"prefix-suffix".to_vec())
        );
        assert!(frame.is_empty());
        assert_eq!(
            read_frame_retained(&mut bytes, &mut frame).await.unwrap(),
            Some(b"next".to_vec())
        );
        assert_eq!(
            read_frame_retained(&mut bytes, &mut frame).await.unwrap(),
            None
        );
        frame = vec![b'a'; MAX_FRAME_BYTES];
        assert!(read_frame_retained(&mut &b"b\n"[..], &mut frame)
            .await
            .is_err());
        frame = b"incomplete".to_vec();
        assert!(read_frame_retained(&mut &b""[..], &mut frame)
            .await
            .is_err());
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
}
