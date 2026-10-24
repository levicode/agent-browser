use std::collections::HashMap;
use std::io::Write;
use std::net::Shutdown;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;

use super::super::client_debt::{
    current_operation, CommandReservation, CommandStatus, CommandStatusHandle, OwnerCleanupCommand,
    OwnerDebtLedger, ReservedDisposal, SubmittedCommand, WorkerStartupProof,
    WorkerStartupStatusProvenance,
};
use super::super::client_protocol::ProtocolError;
use super::types::{CdpCommand, CdpError, CdpEvent, CdpMessage};

type TrackedResponses = Arc<std::sync::Mutex<HashMap<u64, SubmittedCommand>>>;
type DebtOwner = Arc<std::sync::Mutex<Option<Arc<OwnerDebtLedger>>>>;
struct DisposalWork {
    command: ReservedDisposal,
    _bytes: EventBudgetLease,
}

struct PendingResponse {
    sender: oneshot::Sender<CommandReply>,
    session: Option<String>,
}
type PendingMap = Arc<Mutex<HashMap<u64, PendingResponse>>>;

// Only the real reader constructs ErrorAck. Local decoder failures retain their
// old public String projection, but cannot masquerade as a remote error ACK.
#[derive(Debug)]
enum CommandReply {
    Success(Value),
    ErrorAck(CdpError),
    LocalFailure(CdpMessage),
}
enum CommandWaitFailure {
    ChannelClosed,
    Deadline,
}
enum WorkerStartupReply {
    Success,
    ErrorAck(CdpError),
    ChannelClosed,
    ResponseDeadline,
    Deadline,
    Cancelled,
    Unknown(CdpMessage),
}
impl WorkerStartupReply {
    fn error(&self, method: &str) -> Option<String> {
        Some(match self {
            Self::Success => return None,
            Self::ErrorAck(error) => format!("CDP error ({method}): {error}"),
            Self::ChannelClosed => "CDP response channel closed".into(),
            Self::ResponseDeadline => format!("CDP command timed out: {method}"),
            Self::Deadline => "Native initialization deadline expired".into(),
            Self::Cancelled => "Native initialization cancelled".into(),
            Self::Unknown(response) => match &response.error {
                Some(error) => format!("CDP error ({method}): {error}"),
                None => format!("Unverified CDP response ({method})"),
            },
        })
    }
}

#[derive(Debug)]
pub(crate) enum ServiceWorkerStartupOutcome {
    Ready(Option<WorkerStartupRetirement>),
    Retired(WorkerStartupRetirement),
}
/// Local decisions only; an in-flight publication is distinct from detach.
#[derive(Debug)]
pub(crate) enum WorkerStartupDecision {
    ReadyCommitted(Option<super::super::client_settlement_trace::DiagnosticAttachment>),
    RetiredCommitted,
    AwaitDetach(WorkerStartupRetirement),
    AwaitPublication(WorkerStartupRetirement),
}

/// A candidate, not enrollment completion or script success. Only the fixed
/// startup batch can mint this original-owner receipt. It cannot be cloned.
pub(crate) struct WorkerStartupRetirement {
    owner: Arc<OwnerDebtLedger>,
    session: String,
    statuses: Vec<(CommandStatusHandle, CommandStatus)>,
    deadline: std::time::Instant,
    initialization: Option<(
        std::time::Instant,
        watch::Receiver<super::super::client_session::CancelSignal>,
    )>,
    provenance: WorkerStartupStatusProvenance,
}
impl std::fmt::Debug for WorkerStartupRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerStartupRetirement")
            .finish_non_exhaustive()
    }
}
impl WorkerStartupRetirement {
    pub(crate) fn all_acknowledged(&self) -> bool {
        self.provenance == WorkerStartupStatusProvenance::AllAcknowledged
    }
    fn check_operation(
        &self,
        operation: &super::super::client_session::OperationLease,
    ) -> Result<(), ProtocolError> {
        self.check_bound()?;
        if *operation.cancellation.borrow() != super::super::client_session::CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if std::time::Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(())
    }
    pub(crate) fn deadline(&self) -> std::time::Instant {
        self.initialization
            .as_ref()
            .map_or(self.deadline, |(deadline, _)| self.deadline.min(*deadline))
    }
    pub(crate) fn check_bound(&self) -> Result<(), ProtocolError> {
        if self
            .initialization
            .as_ref()
            .is_some_and(|(_, cancellation)| {
                *cancellation.borrow() != super::super::client_session::CancelSignal::None
            })
        {
            return Err(ProtocolError::Cancelled);
        }
        if std::time::Instant::now() >= self.deadline() {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(())
    }
    pub(crate) async fn cancelled(&mut self) {
        if let Some((_, cancellation)) = &mut self.initialization {
            if *cancellation.borrow() == super::super::client_session::CancelSignal::None {
                let _ = cancellation.changed().await;
            }
        } else {
            std::future::pending::<()>().await;
        }
    }
}

/// Only read-side EOF or peer-reset evidence may preserve EOF-only integrity.
/// Timeouts, local/resource failures, and ambiguous aborts are not remote EOF.
fn is_remote_eof_error(error: &tokio_tungstenite::tungstenite::Error) -> bool {
    use tokio_tungstenite::tungstenite::error::ProtocolError as WebSocketProtocolError;
    use tokio_tungstenite::tungstenite::Error as WebSocketError;
    match error {
        WebSocketError::Io(error) => matches!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
        ),
        WebSocketError::ConnectionClosed
        | WebSocketError::Protocol(WebSocketProtocolError::ResetWithoutClosingHandshake) => true,
        _ => false,
    }
}

/// Detachment terminates only waiters on that exact session. Dropping a sender
/// is a transport failure, never a fabricated reply or remote command ACK.
/// Reader-owned command/debt tracking deliberately remains untouched: a late
/// reply must still settle its original provenance and cannot revive its caller.
async fn retire_detached_waiters(pending: &PendingMap, event: &CdpEvent) {
    if event.method != "Target.detachedFromTarget" {
        return;
    }
    let Some(session) = event
        .params
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|session| !session.is_empty())
    else {
        return;
    };
    pending
        .lock()
        .await
        .retain(|_, waiter| waiter.session.as_deref() != Some(session));
}
async fn within_initialization<T>(
    budget: Option<(
        std::time::Instant,
        watch::Receiver<super::super::client_session::CancelSignal>,
    )>,
    future: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    if let Some((deadline, mut cancellation)) = budget {
        if *cancellation.borrow() != super::super::client_session::CancelSignal::None {
            return Err("Native initialization cancelled".into());
        }
        tokio::select! {
            biased;
            _ = cancellation.changed() => Err("Native initialization cancelled".into()),
            _ = tokio::time::sleep_until(deadline.into()) => Err("Native initialization deadline expired".into()),
            result = future => result,
        }
    } else {
        future.await
    }
}
type WsTx = Arc<
    Mutex<
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            Message,
        >,
    >,
>;

/// Sessions whose events go to one private receiver instead of the broadcast.
type PrivateSessions = Arc<std::sync::Mutex<HashMap<String, mpsc::Sender<CdpEvent>>>>;

/// Events buffered for a private session receiver that has fallen behind.
/// Newer events are dropped once it is full; a screencast consumer that
/// cannot keep up should lose frames, not stall the reader.
const PRIVATE_SESSION_BUFFER: usize = 16;

/// Lossless taps for events that must each get a reply (paused requests,
/// auth challenges, targets waiting for the debugger). Unlike the bounded
/// broadcast, a tap never drops an event when its reader falls behind.
type MethodTaps =
    Arc<std::sync::Mutex<Vec<(&'static [&'static str], mpsc::UnboundedSender<CdpEvent>)>>>;

/// Bounded control-event subscriptions fail closed rather than silently losing a
/// paused request. The consumer must quarantine its owned scope on overflow.
type BoundedMethodTaps = Arc<std::sync::Mutex<HashMap<u64, BoundedMethodRoute>>>;
struct BoundedMethodRoute {
    methods: &'static [&'static str],
    sender: mpsc::Sender<BoundedCdpEvent>,
    received: Arc<AtomicU64>,
    budget: Arc<EventBudget>,
    failed: Arc<AtomicBool>,
    max_event_bytes: usize,
}
#[derive(Debug)]
struct EventBudget {
    used: AtomicUsize,
    maximum: usize,
}
#[derive(Debug)]
struct EventCharge {
    budget: Arc<EventBudget>,
    bytes: usize,
}
impl Drop for EventCharge {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
/// Retain this lease whenever processing copies event data beyond recv().
/// It accounts encoded bytes, not exact allocator overhead; event count and
/// transport frame limits independently bound object/parse overhead.
#[derive(Clone, Debug)]
pub struct EventBudgetLease {
    _charge: Arc<EventCharge>,
}
#[derive(Debug)]
pub struct BoundedCdpEvent {
    event: CdpEvent,
    charge: EventBudgetLease,
    sequence: u64,
}
impl BoundedCdpEvent {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn budget_lease(&self) -> EventBudgetLease {
        self.charge.clone()
    }
}
impl std::ops::Deref for BoundedCdpEvent {
    type Target = CdpEvent;
    fn deref(&self) -> &CdpEvent {
        &self.event
    }
}
impl EventBudget {
    fn reserve(self: &Arc<Self>, bytes: usize) -> Option<EventBudgetLease> {
        #[allow(deprecated)]
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .ok()?;
        Some(EventBudgetLease {
            _charge: Arc::new(EventCharge {
                budget: self.clone(),
                bytes,
            }),
        })
    }
}
/// Exact subscription-tenure watermark. It proves reader admission only,
/// never renderer quiescence or application configuration completion.
#[derive(Clone)]
pub struct BoundedEventWatermark {
    routes: std::sync::Weak<std::sync::Mutex<HashMap<u64, BoundedMethodRoute>>>,
    id: u64,
    received: Arc<AtomicU64>,
    failed: Arc<AtomicBool>,
}
impl BoundedEventWatermark {
    pub(crate) fn same_subscription(&self, other: &Self) -> bool {
        self.id == other.id
            && std::sync::Weak::ptr_eq(&self.routes, &other.routes)
            && Arc::ptr_eq(&self.received, &other.received)
            && Arc::ptr_eq(&self.failed, &other.failed)
    }
    pub fn received(&self) -> Result<u64, &'static str> {
        self.with_received(|received| received)
    }
    /// Synchronous publication fence against this exact reader subscription.
    /// The closure must not await or acquire the enrollment index: callers hold
    /// index -> routes and publish_bounded never takes the index.
    pub(crate) fn with_received<T>(
        &self,
        publish: impl FnOnce(u64) -> T,
    ) -> Result<T, &'static str> {
        let routes = self.routes.upgrade().ok_or("control event stream closed")?;
        let routes = routes.lock().map_err(|_| "control event stream poisoned")?;
        let route = routes.get(&self.id).ok_or("control event stream closed")?;
        if self.failed.load(Ordering::SeqCst) || !Arc::ptr_eq(&route.received, &self.received) {
            return Err("control event stream unavailable");
        }
        Ok(publish(self.received.load(Ordering::SeqCst)))
    }
}
pub struct BoundedMethodEvents {
    receiver: mpsc::Receiver<BoundedCdpEvent>,
    failed: Arc<AtomicBool>,
    routes: BoundedMethodTaps,
    id: u64,
    received: Arc<AtomicU64>,
}
impl BoundedMethodEvents {
    pub fn watermark(&self) -> BoundedEventWatermark {
        BoundedEventWatermark {
            routes: Arc::downgrade(&self.routes),
            id: self.id,
            received: self.received.clone(),
            failed: self.failed.clone(),
        }
    }
    /// Terminal subscription count, not a live watermark. Only a closed, empty,
    /// non-overflowed receiver can expose this immutable final receipt boundary.
    pub(crate) fn terminal_received(&self) -> Result<u64, &'static str> {
        if !self.receiver.is_closed()
            || !self.receiver.is_empty()
            || self.failed.load(Ordering::SeqCst)
        {
            return Err("control event stream not cleanly drained");
        }
        Ok(self.received.load(Ordering::SeqCst))
    }
    pub async fn recv(&mut self) -> Result<BoundedCdpEvent, &'static str> {
        if self.failed.load(Ordering::SeqCst) {
            return Err("control event overflow");
        }
        let event = self
            .receiver
            .recv()
            .await
            .ok_or("control event stream closed")?;
        if self.failed.load(Ordering::SeqCst) {
            return Err("control event overflow");
        }
        Ok(event)
    }
}
impl Drop for BoundedMethodEvents {
    fn drop(&mut self) {
        self.routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}
fn publish_bounded(taps: &BoundedMethodTaps, event: &CdpEvent, bytes: usize) {
    taps.lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|_, route| {
            if !route.methods.contains(&event.method.as_str()) {
                return true;
            }
            if bytes > route.max_event_bytes {
                route.failed.store(true, Ordering::SeqCst);
                return false;
            }
            let Some(charge) = route.budget.reserve(bytes) else {
                route.failed.store(true, Ordering::SeqCst);
                return false;
            };
            #[allow(deprecated)]
            let Ok(previous) =
                route
                    .received
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                        value.checked_add(1)
                    })
            else {
                route.failed.store(true, Ordering::SeqCst);
                return false;
            };
            match route.sender.try_send(BoundedCdpEvent {
                event: event.clone(),
                charge,
                sequence: previous + 1,
            }) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    route.failed.store(true, Ordering::SeqCst);
                    false
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        });
}

/// Interval between WebSocket ping frames sent to keep the connection alive
/// through intermediate proxies (reverse proxies, load balancers, service meshes).
const WS_KEEPALIVE_INTERVAL_SECS: u64 = 30;
const TRANSPORT_CLOSE_TIMEOUT: Duration = Duration::from_millis(500);
const CONNECTION_CLOSED_ERROR: &str = "CDP connection closed";

fn normalize_websocket_root_path(url: &str) -> String {
    let Some(scheme_end) = url.find("://").map(|index| index + 3) else {
        return url.to_string();
    };
    let authority = &url[scheme_end..];
    let Some(query_offset) = authority.find('?') else {
        return url.to_string();
    };
    if authority[..query_offset].contains('/') {
        return url.to_string();
    }
    let query_index = scheme_end + query_offset;
    format!("{}/{}", &url[..query_index], &url[query_index..])
}

/// Raw incoming CDP message (text) broadcast to all subscribers.
/// Used by the inspect proxy to forward responses and events to DevTools.
#[derive(Debug, Clone)]
pub struct RawCdpMessage {
    pub text: String,
    pub session_id: Option<String>,
}

#[derive(Deserialize)]
struct CdpIdEnvelope {
    id: Option<u64>,
    #[serde(rename = "result")]
    _result: Option<IgnoredAny>,
    #[serde(rename = "error")]
    _error: Option<IgnoredAny>,
    #[serde(rename = "method")]
    _method: Option<IgnoredAny>,
    #[serde(rename = "params")]
    _params: Option<IgnoredAny>,
    #[serde(rename = "sessionId")]
    _session_id: Option<IgnoredAny>,
}

fn sanitize_lone_surrogates(msg: &str) -> Option<String> {
    const ESCAPE_LEN: usize = 6;
    const HIGH_START: u32 = 0xD800;
    const LOW_START: u32 = 0xDC00;
    const SURROGATE_END: u32 = 0xE000;

    let read_escape = |bytes: &[u8], at: usize| -> Option<u32> {
        let end = at.checked_add(ESCAPE_LEN)?;
        if end > bytes.len() || bytes[at] != b'\\' || bytes[at + 1] != b'u' {
            return None;
        }
        let hex = &bytes[at + 2..end];
        if !hex.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()
    };

    let bytes = msg.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() && bytes[i + 1] != b'u' {
            i += 2;
            continue;
        }

        let Some(unit) = read_escape(bytes, i) else {
            i += 1;
            continue;
        };

        let is_high = (HIGH_START..LOW_START).contains(&unit);
        let is_low = (LOW_START..SURROGATE_END).contains(&unit);
        let paired = is_high
            && read_escape(bytes, i + ESCAPE_LEN)
                .is_some_and(|next| (LOW_START..SURROGATE_END).contains(&next));

        if paired {
            i += ESCAPE_LEN * 2;
            continue;
        }

        if is_high || is_low {
            let buf = out.get_or_insert_with(String::new);
            buf.push_str(&msg[copied..i]);
            buf.push(char::REPLACEMENT_CHARACTER);
            copied = i + ESCAPE_LEN;
        }
        i += ESCAPE_LEN;
    }

    if let Some(buf) = out.as_mut() {
        buf.push_str(&msg[copied..]);
    }

    out
}

fn extract_command_id(msg: &str) -> Option<u64> {
    let envelope: CdpIdEnvelope = serde_json::from_str(msg).ok()?;
    envelope.id.filter(|id| *id > 0)
}

/// A handle is either the legacy physical owner or an immutable native-owner
/// view. Views share one reader/writer/task set and cannot close that transport.
pub struct CdpClient {
    transport: Arc<CdpTransport>,
    owner: Option<Arc<OwnerDebtLedger>>,
}

struct CdpTransport {
    ws_tx: WsTx,
    socket: socket2::Socket,
    closed: Arc<AtomicBool>,
    close_complete: AtomicBool,
    remote_closed: watch::Receiver<bool>,
    close_lock: Mutex<()>,
    cancel_tx: watch::Sender<bool>,
    next_id: Arc<AtomicU64>,
    pending: PendingMap,
    tracked_responses: TrackedResponses,
    debt_owner: DebtOwner,
    event_tx: broadcast::Sender<CdpEvent>,
    raw_tx: broadcast::Sender<RawCdpMessage>,
    reader_handle: Mutex<Option<JoinHandle<()>>>,
    keepalive_handle: Mutex<Option<JoinHandle<()>>>,
    disposal_handle: Mutex<Option<JoinHandle<()>>>,
    private_sessions: PrivateSessions,
    method_taps: MethodTaps,
    bounded_method_taps: BoundedMethodTaps,
    next_tap_id: AtomicU64,
    #[cfg(test)]
    worker_startup_decision_gate:
        std::sync::Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
}

/// Removes a pending entry if `send_command` is cancelled mid-await (e.g. an
/// outer timeout on the liveness probe), so a command whose response never
/// comes can't leak until the connection closes (#1528). Normal exits disarm
/// it via `done`.
struct PendingGuard {
    pending: PendingMap,
    id: u64,
    done: bool,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let pending = self.pending.clone();
        let id = self.id;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                pending.lock().await.remove(&id);
            });
        }
    }
}

/// A submitted command keeps its waiter guard until its real response is read.
/// Dropping the waiter never removes the reader-owned submission/debt record.
struct CommandResponse {
    receiver: oneshot::Receiver<CommandReply>,
    guard: PendingGuard,
}

impl CdpClient {
    pub async fn connect(url: &str) -> Result<Self, String> {
        Self::connect_with_headers(url, None).await
    }

    pub async fn connect_with_headers(
        url: &str,
        headers: Option<Vec<(String, String)>>,
    ) -> Result<Self, String> {
        Self::connect_with_headers_and_limit(url, headers, None).await
    }

    /// Negotiated owners bound transport allocation before JSON parsing. Legacy
    /// connections retain their existing unlimited-message behavior.
    pub async fn connect_with_headers_and_limit(
        url: &str,
        headers: Option<Vec<(String, String)>>,
        message_limit: Option<usize>,
    ) -> Result<Self, String> {
        if message_limit.is_some_and(|limit| !(1024..=512 * 1024 * 1024).contains(&limit)) {
            return Err("Invalid native transport limit".into());
        }
        let normalized_url = normalize_websocket_root_path(url);
        let mut request = normalized_url
            .as_str()
            .into_client_request()
            .map_err(|e| format!("Invalid WebSocket URL: {}", e))?;

        if let Some(hdrs) = headers {
            let req_headers = request.headers_mut();
            for (key, value) in hdrs {
                if let (Ok(name), Ok(val)) = (
                    key.parse::<tokio_tungstenite::tungstenite::http::header::HeaderName>(),
                    value.parse::<tokio_tungstenite::tungstenite::http::header::HeaderValue>(),
                ) {
                    req_headers.insert(name, val);
                }
            }
        }

        let ws_config = WebSocketConfig {
            max_message_size: message_limit,
            max_frame_size: message_limit,
            ..Default::default()
        };

        Self::connect_request(request, ws_config, None).await
    }

    async fn connect_request(
        request: Request<()>,
        ws_config: WebSocketConfig,
        connector: Option<Connector>,
    ) -> Result<Self, String> {
        let (ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(
            request,
            Some(ws_config),
            false,
            connector,
        )
        .await
        .map_err(|e| format!("CDP WebSocket connect failed: {}", e))?;

        enable_tcp_keepalive(ws_stream.get_ref());
        let tcp_stream = underlying_tcp_stream(ws_stream.get_ref())
            .ok_or_else(|| "Unsupported CDP stream type".to_string())?;
        let socket = socket2::SockRef::from(tcp_stream)
            .try_clone()
            .map_err(|error| format!("Failed to duplicate CDP socket: {}", error))?;

        let (ws_tx, mut ws_rx) = ws_stream.split();
        let ws_tx = Arc::new(Mutex::new(ws_tx));

        let next_id = Arc::new(AtomicU64::new(1));
        let (disposal_tx, mut disposal_rx) = mpsc::channel::<DisposalWork>(32);
        let disposal_budget = Arc::new(EventBudget {
            used: AtomicUsize::new(0),
            maximum: 32 * 1024,
        });
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let tracked_responses: TrackedResponses = Arc::default();
        let debt_owner: DebtOwner = Arc::default();
        let tracked_reader = tracked_responses.clone();
        let debt_reader = debt_owner.clone();
        let (event_tx, _) = broadcast::channel(4096);
        let (raw_tx, _) = broadcast::channel(4096);
        let closed = Arc::new(AtomicBool::new(false));
        let (remote_closed_tx, remote_closed) = watch::channel(false);

        let private_sessions: PrivateSessions = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let method_taps: MethodTaps = Arc::new(std::sync::Mutex::new(Vec::new()));

        let bounded_method_taps: BoundedMethodTaps =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let bounded_taps_clone = bounded_method_taps.clone();

        let pending_clone = pending.clone();
        let event_tx_clone = event_tx.clone();
        let raw_tx_clone = raw_tx.clone();
        let closed_reader = closed.clone();
        let private_clone = private_sessions.clone();
        let taps_clone = method_taps.clone();

        // Notify used to stop the keepalive task when the reader loop exits.
        let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
        let reader_cancel_tx = cancel_tx.clone();
        let mut disposal_cancel = cancel_rx.clone();
        let disposal_ws = ws_tx.clone();
        let disposal_closed = closed.clone();
        let disposal_tracked = tracked_responses.clone();
        let disposal_next = next_id.clone();
        // No Arc<CdpClient> is captured. The owning client closes/cancels and
        // joins this bounded one-shot lane with its reader and keepalive.
        let disposal_handle = tokio::spawn(async move {
            loop {
                let work = tokio::select! {
                    biased;
                    _ = disposal_cancel.changed() => break,
                    work = disposal_rx.recv() => match work { Some(work) => work, None => break },
                };
                let write_deadline = tokio::time::Instant::now() + Duration::from_millis(250);
                let mut tx = tokio::select! {
                    biased;
                    _ = disposal_cancel.changed() => break,
                    _ = tokio::time::sleep_until(write_deadline) => continue,
                    tx = disposal_ws.lock() => tx,
                };
                if disposal_closed.load(Ordering::SeqCst) {
                    break;
                }
                #[allow(deprecated)]
                let Ok(id) = disposal_next
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
                else {
                    break;
                };
                let DisposalWork { command, _bytes } = work;
                let envelope = CdpCommand {
                    id,
                    method: command.method.into(),
                    params: Some(command.params),
                    session_id: command.session,
                };
                let Ok(json) = serde_json::to_string(&envelope) else {
                    continue;
                };
                let Ok(submitted) = command.reservation.submit() else {
                    continue;
                };
                disposal_tracked
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .insert(id, submitted);
                // Never await a response here, nor retry a failed/maybe write.
                let _ = tokio::select! {
                    biased;
                    _ = disposal_cancel.changed() => break,
                    _ = tokio::time::sleep_until(write_deadline) => continue,
                    sent = tx.send(Message::Text(json)) => sent,
                };
            }
        });

        let reader_handle = tokio::spawn(async move {
            while let Some(msg) = ws_rx.next().await {
                // Accept both Text and Binary frames — remote CDP proxies
                // (e.g. Browserless) may send responses as Binary frames.
                let msg = match msg {
                    Ok(Message::Text(text)) => text,
                    Ok(Message::Binary(data)) => match String::from_utf8(data) {
                        Ok(text) => text,
                        Err(_) => {
                            if let Some(ledger) = debt_reader
                                .lock()
                                .unwrap_or_else(|error| error.into_inner())
                                .as_ref()
                            {
                                ledger.connection_lost();
                            }
                            continue;
                        }
                    },
                    Ok(Message::Close(frame)) => {
                        if std::env::var("AGENT_BROWSER_DEBUG").is_ok() {
                            let reason = frame
                                .as_ref()
                                .map(|f| format!("code={}, reason={}", f.code, f.reason))
                                .unwrap_or_else(|| "no frame".to_string());
                            let _ =
                                writeln!(std::io::stderr(), "[cdp] WebSocket Close: {}", reason);
                        }
                        break;
                    }
                    Ok(Message::Pong(_)) => continue,
                    Ok(_) => continue,
                    Err(e) => {
                        // Network EOF/reset can end an intact reader. Invalid
                        // UTF-8, protocol framing, and capacity failures cannot
                        // be laundered into EOF-only evidence by that same end.
                        if !is_remote_eof_error(&e) {
                            if let Some(ledger) = debt_reader
                                .lock()
                                .unwrap_or_else(|error| error.into_inner())
                                .as_ref()
                            {
                                ledger.connection_lost();
                            }
                        }
                        if std::env::var("AGENT_BROWSER_DEBUG").is_ok() {
                            let _ = writeln!(std::io::stderr(), "[cdp] WebSocket Error: {}", e);
                        }
                        break;
                    }
                };

                // Broadcast raw message for inspect proxy subscribers before typed parse,
                // so messages with negative IDs (used by the inspect proxy) are still delivered.
                if raw_tx_clone.receiver_count() > 0 {
                    let session_id = serde_json::from_str::<serde_json::Value>(&msg)
                        .ok()
                        .and_then(|v| v.get("sessionId")?.as_str().map(String::from));
                    let _ = raw_tx_clone.send(RawCdpMessage {
                        text: msg.clone(),
                        session_id,
                    });
                }

                let parsed: CdpMessage = match serde_json::from_str(&msg) {
                    Ok(parsed) => parsed,
                    Err(_) => {
                        let repaired = sanitize_lone_surrogates(&msg);
                        let candidate = repaired.as_deref().unwrap_or(&msg);
                        match serde_json::from_str(candidate) {
                            Ok(parsed) => parsed,
                            Err(error) => {
                                // Even an uncorrelated malformed frame damages
                                // the stream. A missing/unknown ID is no pardon.
                                if let Some(ledger) = debt_reader
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner())
                                    .as_ref()
                                {
                                    ledger.connection_lost();
                                }
                                if let Some(id) = extract_command_id(candidate) {
                                    if let Some(tracked) = tracked_reader
                                        .lock()
                                        .unwrap_or_else(|error| error.into_inner())
                                        .remove(&id)
                                    {
                                        tracked.malformed_response();
                                    }
                                    let waiter = pending_clone.lock().await.remove(&id);
                                    if let Some(tx) = waiter {
                                        let _ = tx.sender.send(CommandReply::LocalFailure(
                                            CdpMessage {
                                                id: Some(id),
                                                result: None,
                                                error: Some(CdpError {
                                                    code: None,
                                                    message: format!(
                                                        "Malformed CDP response: {}",
                                                        error
                                                    ),
                                                    data: None,
                                                }),
                                                method: None,
                                                params: None,
                                                session_id: None,
                                            },
                                        ));
                                    }
                                }
                                continue;
                            }
                        }
                    }
                };

                let valid_envelope = if parsed.id.is_some() {
                    parsed.method.is_none()
                        && parsed.params.is_none()
                        && match (&parsed.result, &parsed.error) {
                            (Some(Value::Object(_)), None) => true,
                            (None, Some(error)) => error.code.is_some(),
                            _ => false,
                        }
                } else {
                    parsed
                        .method
                        .as_ref()
                        .is_some_and(|method| !method.is_empty())
                        && parsed.result.is_none()
                        && parsed.error.is_none()
                        && parsed.params.as_ref().is_none_or(Value::is_object)
                };
                if !valid_envelope {
                    if let Some(ledger) = debt_reader
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .as_ref()
                    {
                        ledger.connection_lost();
                    }
                }

                if let Some(id) = parsed.id {
                    let waiter = pending_clone.lock().await.remove(&id);
                    // Parse/correlate/settle before waiter delivery. Queue only
                    // exact disposal work, never the old application's next step.
                    let tracked = tracked_reader
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .remove(&id);
                    let disposals = tracked
                        .map_or_else(Vec::new, |tracked| tracked.settle_for_delivery(&parsed));
                    // Delivery itself is the authority: is_closed() alone races
                    // receiver cancellation between inspection and send.
                    let abandoned = waiter.is_none_or(|tx| {
                        let reply = if valid_envelope && tx.session == parsed.session_id {
                            match parsed.error {
                                Some(error) => CommandReply::ErrorAck(error),
                                None => CommandReply::Success(parsed.result.unwrap_or(Value::Null)),
                            }
                        } else {
                            CommandReply::LocalFailure(parsed)
                        };
                        tx.sender.send(reply).is_err()
                    });
                    for disposal in disposals {
                        if disposal.needed_after_delivery(abandoned) {
                            if let Ok(command) = disposal.reserve() {
                                let bytes = serde_json::to_vec(&command.params)
                                    .map_or(usize::MAX, |value| value.len())
                                    .saturating_add(command.session.as_ref().map_or(0, String::len))
                                    .saturating_add(128);
                                if let Some(charge) = disposal_budget.reserve(bytes) {
                                    // Full/stopped queue drops only an unsubmitted
                                    // reservation. Exact object/group debt remains.
                                    let _ = disposal_tx.try_send(DisposalWork {
                                        command,
                                        _bytes: charge,
                                    });
                                }
                            }
                        }
                    }
                } else if let Some(ref method) = parsed.method {
                    // Event
                    let event = CdpEvent {
                        method: method.clone(),
                        params: parsed.params.clone().unwrap_or(Value::Null),
                        session_id: parsed.session_id.clone(),
                    };
                    let eval_publication = debt_reader
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .as_ref()
                        .and_then(|ledger| ledger.observe_event_for_publication(&event));
                    let routed = event.session_id.as_deref().is_some_and(|sid| {
                        let mut routes = private_clone.lock().unwrap_or_else(|e| e.into_inner());
                        match routes.get(sid) {
                            Some(tx) => match tx.try_send(event.clone()) {
                                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    routes.remove(sid);
                                    false
                                }
                            },
                            None => false,
                        }
                    });
                    publish_bounded(&bounded_taps_clone, &event, msg.len());
                    if let Some(publication) = eval_publication {
                        publication.complete();
                    }
                    // Register the lifecycle watermark before waking a failed
                    // caller, so a following operation cannot outrun admission.
                    retire_detached_waiters(&pending_clone, &event).await;
                    if !routed {
                        let mut taps = taps_clone.lock().unwrap_or_else(|e| e.into_inner());
                        taps.retain(|(methods, tx)| {
                            !methods.contains(&event.method.as_str())
                                || tx.send(event.clone()).is_ok()
                        });
                        drop(taps);
                        let _ = event_tx_clone.send(event);
                    }
                }
            }

            // Reader loop exited (connection closed or error). Drop all pending
            // command senders so callers get an immediate channel-closed error
            // instead of waiting for the 30-second timeout.
            // Publish terminal classification before dropping bounded senders:
            // a receiver on another runtime thread may wake immediately on EOF.
            // Local teardown sets closed first and never grants remote-loss proof.
            {
                // Serialize classification with local close and owner install.
                // A remote watcher must never see EOF before its ledger cause.
                let owner = debt_reader
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                let remote = !closed_reader.swap(true, Ordering::SeqCst);
                if let Some(ledger) = owner.as_ref() {
                    if remote {
                        ledger.observe_remote_eof();
                    } else {
                        ledger.connection_lost();
                    }
                }
                if remote {
                    remote_closed_tx.send_replace(true);
                }
            }
            bounded_taps_clone
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            tracked_reader
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clear();
            pending_clone.lock().await.clear();

            // Stop the keepalive task because the connection is gone.
            let _ = reader_cancel_tx.send(true);
        });

        // Spawn a keepalive task that sends WebSocket Ping frames at a regular
        // interval. This prevents intermediate proxies (Envoy, nginx, OpenResty,
        // cloud load balancers) from closing idle WebSocket connections. If the
        // send fails, the connection is dead and we stop pinging.
        let keepalive_tx = ws_tx.clone();
        let closed_keepalive = closed.clone();
        let keepalive_handle = tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(WS_KEEPALIVE_INTERVAL_SECS);
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = cancel_rx.changed() => break,
                }
                let mut tx = keepalive_tx.lock().await;
                if closed_keepalive.load(Ordering::SeqCst) {
                    break;
                }
                if tx.send(Message::Ping(Vec::new())).await.is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            owner: None,
            transport: Arc::new(CdpTransport {
                ws_tx,
                socket,
                closed,
                close_complete: AtomicBool::new(false),
                remote_closed,
                close_lock: Mutex::new(()),
                cancel_tx,
                next_id,
                pending,
                tracked_responses,
                debt_owner,
                event_tx,
                raw_tx,
                reader_handle: Mutex::new(Some(reader_handle)),
                keepalive_handle: Mutex::new(Some(keepalive_handle)),
                disposal_handle: Mutex::new(Some(disposal_handle)),
                private_sessions,
                method_taps,
                bounded_method_taps,
                next_tap_id: AtomicU64::new(1),
                #[cfg(test)]
                worker_startup_decision_gate: std::sync::Mutex::new(None),
            }),
        })
    }

    /// Evidence of underlying CDP connection loss, never local close or RPC EOF.
    pub fn remote_connection_closed(&self) -> watch::Receiver<bool> {
        self.transport.remote_closed.clone()
    }

    fn ensure_open(&self) -> Result<(), String> {
        if self.transport.closed.load(Ordering::SeqCst) {
            Err(CONNECTION_CLOSED_ERROR.to_string())
        } else {
            Ok(())
        }
    }

    async fn abort_task(handle: &Mutex<Option<JoinHandle<()>>>) {
        let Some(task) = handle.lock().await.take() else {
            return;
        };
        task.abort();
        let _ = tokio::time::timeout(TRANSPORT_CLOSE_TIMEOUT, task).await;
    }

    pub async fn close(&self) {
        // A captured runtime view never owns the connection or its tasks.
        if self.owner.is_some() {
            return;
        }
        let _close_guard = self.transport.close_lock.lock().await;
        if self.transport.close_complete.load(Ordering::SeqCst) {
            return;
        }
        {
            let owner = self
                .transport
                .debt_owner
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            self.transport.closed.store(true, Ordering::SeqCst);
            if let Some(ledger) = owner.as_ref() {
                ledger.connection_lost();
            }
        }

        let _ = self.transport.cancel_tx.send(true);
        Self::abort_task(&self.transport.keepalive_handle).await;
        Self::abort_task(&self.transport.disposal_handle).await;

        let _ = tokio::time::timeout(TRANSPORT_CLOSE_TIMEOUT, async {
            let mut ws_tx = self.transport.ws_tx.lock().await;
            let _ = ws_tx.close().await;
        })
        .await;

        let _ = self.transport.socket.shutdown(Shutdown::Both);
        Self::abort_task(&self.transport.reader_handle).await;
        if let Some(ledger) = self.debt_ledger() {
            ledger.connection_lost();
        }
        self.transport
            .tracked_responses
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        self.transport.pending.lock().await.clear();
        self.transport.close_complete.store(true, Ordering::SeqCst);
    }

    /// Install only on the concentrated owner path. Real lifecycle replacement
    /// cannot reset old obligations; it requires their exact prior retirement.
    pub(crate) fn install_debt_ledger(
        &self,
        ledger: Arc<OwnerDebtLedger>,
    ) -> Result<(), ProtocolError> {
        if self.owner.is_some() {
            return Err(ProtocolError::StaleScope);
        }
        // Legacy raw/inspect writes have no reservation. Native adoption must
        // serialize with their final managed-owner check under writer ownership.
        let _writer = self
            .transport
            .ws_tx
            .try_lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let mut owner = self
            .transport
            .debt_owner
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if let Some(previous) = owner.as_ref() {
            if Arc::ptr_eq(previous, &ledger) {
                return Ok(());
            }
            if previous.same_owner(&ledger) {
                return Err(ProtocolError::StaleScope);
            }
            let old = previous.snapshot();
            if old.outstanding_commands != 0
                || old.object_debt != 0
                || !previous.replacement_ready()
            {
                return Err(ProtocolError::ScopeUnavailable);
            }
        }
        *owner = Some(ledger);
        Ok(())
    }
    pub(crate) fn debt_ledger(&self) -> Option<Arc<OwnerDebtLedger>> {
        self.owner.clone().or_else(|| {
            self.transport
                .debt_owner
                .lock()
                .ok()
                .and_then(|owner| owner.clone())
        })
    }
    pub(crate) fn cleanup_diagnostics(
        &self,
    ) -> Option<Arc<super::super::client_settlement_trace::CleanupDiagnostics>> {
        self.debt_ledger()
            .map(|owner| owner.cleanup_diagnostics.clone())
    }
    pub(crate) fn cleanup_observer(
        &self,
    ) -> Option<super::super::client_settlement_trace::CleanupObserver> {
        self.cleanup_diagnostics().and_then(|cell| cell.observer())
    }
    /// Constructed only by the native lifecycle owner, never by a callback.
    pub(crate) fn owner_view(
        &self,
        ledger: Arc<OwnerDebtLedger>,
    ) -> Result<Arc<Self>, ProtocolError> {
        if self.owner.is_some() {
            return Err(ProtocolError::StaleScope);
        }
        self.check_cleanup_owner(&Some(ledger.clone()))?;
        Ok(Arc::new(Self {
            transport: self.transport.clone(),
            owner: Some(ledger),
        }))
    }
    pub(crate) fn check_cleanup_owner(
        &self,
        expected: &Option<Arc<OwnerDebtLedger>>,
    ) -> Result<(), ProtocolError> {
        if self.owner.as_ref().is_some_and(|bound| {
            expected
                .as_ref()
                .is_none_or(|expected| !Arc::ptr_eq(bound, expected))
        }) {
            return Err(ProtocolError::StaleScope);
        }
        let current = self
            .transport
            .debt_owner
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        match (expected, current.as_ref()) {
            (None, None) => Ok(()),
            (Some(expected), Some(current)) if Arc::ptr_eq(expected, current) => Ok(()),
            _ => Err(ProtocolError::StaleScope),
        }
    }
    /// One pre-bound, native lifecycle obligation. Its envelope cannot be
    /// broadened by a method string, session ID or task-local category override.
    pub(crate) async fn send_owner_cleanup(
        &self,
        expected: Option<Arc<OwnerDebtLedger>>,
        command: OwnerCleanupCommand,
        deadline: std::time::Instant,
    ) -> Result<Value, String> {
        let diagnostics = expected
            .as_ref()
            .and_then(|owner| owner.cleanup_diagnostics.observer());
        let result = async {
            self.check_cleanup_owner(&expected)
                .map_err(|_| "Native cleanup owner changed".to_string())?;
            if std::time::Instant::now() >= deadline {
                return Err("Native cleanup deadline expired".into());
            }
            let reservation = expected
                .as_ref()
                .map(|ledger| ledger.reserve_owner_cleanup(command))
                .transpose()
                .map_err(|_| "Native cleanup admission refused".to_string())?;
            let (method, params) = command.envelope();
            tokio::time::timeout_at(
                deadline.into(),
                self.send_reserved_command_bound(
                    method,
                    params,
                    None,
                    reservation,
                    Some((expected, deadline)),
                ),
            )
            .await
            .map_err(|_| "Native cleanup deadline expired".to_string())?
        }
        .await;
        super::super::client_settlement_trace::observe_cleanup(
            &diagnostics,
            super::super::client_settlement_trace::CleanupComponent::Release,
            &result,
        );
        result
    }
    /// Called only from native cleanup owners after selecting their exact retained
    /// resource. No generic envelope, inherited category, or renewed app budget.
    pub(crate) async fn send_scope_cleanup(
        &self,
        command: super::super::client_debt::ScopeCleanupCommand,
        deadline: std::time::Instant,
    ) -> Result<Value, String> {
        let expected = self.debt_ledger();
        let diagnostics = expected
            .as_ref()
            .and_then(|owner| owner.cleanup_diagnostics.observer());
        let component = command.diagnostic_component();
        let result = async {
            self.check_cleanup_owner(&expected)
                .map_err(|_| "Native cleanup owner changed".to_string())?;
            if expected.is_some() && self.owner.is_none() {
                return Err("Native cleanup requires an owner-bound view".into());
            }
            let (method, params, session) = command
                .envelope()
                .map_err(|_| "Invalid native cleanup identity".to_string())?;
            if std::time::Instant::now() >= deadline {
                return Err("Native cleanup deadline expired".into());
            }
            let reservation = expected
                .as_ref()
                .map(|ledger| {
                    ledger.reserve_scope_cleanup(method, &params, session.as_deref(), deadline)
                })
                .transpose()
                .map_err(|_| "Native cleanup admission refused".to_string())?;
            tokio::time::timeout_at(
                deadline.into(),
                self.send_reserved_command_bound(
                    method,
                    Some(params),
                    session.as_deref(),
                    reservation,
                    Some((expected, deadline)),
                ),
            )
            .await
            .map_err(|_| "Native cleanup deadline expired".to_string())?
        }
        .await;
        super::super::client_settlement_trace::observe_cleanup(&diagnostics, component, &result);
        result
    }
    pub(crate) fn reserve_tracked_command(
        &self,
        method: &str,
        params: Option<&Value>,
        session: Option<&str>,
    ) -> Result<Option<CommandReservation>, String> {
        let Some(ledger) = self.debt_ledger() else {
            return Ok(None);
        };
        let journal = current_operation();
        self.check_cleanup_owner(&Some(ledger.clone()))
            .map_err(|_| "Native CDP owner changed".to_string())?;
        // Legacy handles cease being ambient native-service authority when a
        // managed owner is installed. Operation journals remain exact-bound.
        if self.owner.is_none() && journal.is_none() {
            return Err("Native CDP requires an owner-bound view".into());
        }
        ledger
            .reserve_command(journal.as_ref(), method, params, session)
            .map(Some)
            .map_err(|_| "Native CDP command admission refused".to_string())
    }
    fn next_command_id(&self) -> Result<u64, String> {
        #[allow(deprecated)]
        self.transport
            .next_id
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
            .map_err(|_| "CDP command identifier exhausted".to_string())
    }
    fn track_submission(
        &self,
        id: u64,
        reservation: Option<CommandReservation>,
    ) -> Result<(), String> {
        let current = self
            .transport
            .debt_owner
            .lock()
            .map_err(|_| "Native CDP owner unavailable".to_string())?;
        match (current.as_ref(), reservation.as_ref()) {
            (None, None) if self.owner.is_none() => {}
            (Some(current), Some(reservation))
                if reservation.belongs_to(current)
                    && self
                        .owner
                        .as_ref()
                        .is_none_or(|bound| Arc::ptr_eq(bound, current)) => {}
            _ => return Err("Native CDP reservation owner changed".into()),
        }
        if let Some(reservation) = reservation {
            let submitted = reservation
                .submit()
                .map_err(|_| "Native CDP command admission revoked".to_string())?;
            self.transport
                .tracked_responses
                .lock()
                .map_err(|_| "Native CDP correlation unavailable".to_string())?
                .insert(id, submitted);
        }
        Ok(())
    }
    pub async fn send_command(
        &self,
        method: &str,
        params: Option<Value>,
        session_id: Option<&str>,
    ) -> Result<Value, String> {
        let reservation = self.reserve_tracked_command(method, params.as_ref(), session_id)?;
        self.send_reserved_command(method, params, session_id, reservation)
            .await
    }

    /// Service-worker renderer domains may not acknowledge enable until the
    /// browser-side resume is dispatched. The caller must already hold its
    /// resume permit and have acknowledged every mandatory security setting.
    /// Submit this fixed sequence in order, then observe every submitted reply
    /// under the original operation bound before publishing readiness.
    pub(crate) async fn initialize_service_worker_domains(
        &self,
        session: &str,
        network_params: Value,
        bypass_service_worker: bool,
        deadline: std::time::Instant,
    ) -> Result<ServiceWorkerStartupOutcome, String> {
        if session.is_empty() {
            return Err("Service-worker initialization requires an exact session".into());
        }
        let expected = self.debt_ledger();
        let mut responses = Vec::with_capacity(4);
        let mut errors = Vec::new();
        for (method, params) in [
            Some(("Network.enable", network_params)),
            bypass_service_worker.then(|| {
                (
                    "Network.setBypassServiceWorker",
                    serde_json::json!({"bypass":true}),
                )
            }),
            Some(("Runtime.enable", serde_json::json!({}))),
            Some(("Runtime.runIfWaitingForDebugger", serde_json::json!({}))),
        ]
        .into_iter()
        .flatten()
        {
            let submission = async {
                if std::time::Instant::now() >= deadline {
                    return Err("Service-worker initialization deadline expired".into());
                }
                self.check_cleanup_owner(&expected)
                    .map_err(|_| "Native CDP owner changed".to_string())?;
                let reservation =
                    self.reserve_tracked_command(method, Some(&params), Some(session))?;
                let status = reservation.as_ref().map(CommandReservation::status);
                let budget = reservation
                    .as_ref()
                    .and_then(CommandReservation::initialization_budget);
                let response = within_initialization(
                    budget.clone(),
                    self.submit_reserved_command_bound(
                        method,
                        Some(params),
                        Some(session),
                        reservation,
                        Some((expected.clone(), deadline)),
                    ),
                )
                .await?;
                Ok((response, budget, status))
            };
            let submitted = tokio::time::timeout_at(deadline.into(), submission)
                .await
                .map_err(|_| "Service-worker initialization deadline expired".to_string())
                .and_then(|result| result);
            match submitted {
                Ok((response, budget, status)) => {
                    responses.push((method, response, budget, status))
                }
                Err(error) => {
                    errors.push(format!("{method}: {error}"));
                    break;
                }
            }
        }
        let submitted_count = responses.len();
        let complete = submitted_count == 3 + usize::from(bypass_service_worker);
        let initialization = responses
            .first()
            .and_then(|(_, _, budget, _)| budget.clone());
        let same_budget =
            responses
                .iter()
                .all(|(_, _, budget, _)| match (&initialization, budget) {
                    (None, None) => true,
                    (Some((a, x)), Some((b, y))) => a == b && x.same_channel(y),
                    _ => false,
                });
        // Every submitted sibling is joined, including after a local submission
        // failure. Reader-owned debt and Destroyed's causal cutoff are unchanged.
        let results = futures_util::future::join_all(responses.into_iter().map(
            |(method, response, budget, status)| async move {
                let reply = async {
                    match self.await_command_reply(response, Some(deadline)).await {
                        Ok(CommandReply::Success(_)) => WorkerStartupReply::Success,
                        Ok(CommandReply::ErrorAck(error)) => WorkerStartupReply::ErrorAck(error),
                        Ok(CommandReply::LocalFailure(response)) => WorkerStartupReply::Unknown(response),
                        Err(CommandWaitFailure::ChannelClosed) => WorkerStartupReply::ChannelClosed,
                        Err(CommandWaitFailure::Deadline) => WorkerStartupReply::ResponseDeadline,
                    }
                };
                let reply = if let Some((bound, mut cancellation)) = budget {
                    if *cancellation.borrow() != super::super::client_session::CancelSignal::None {
                        WorkerStartupReply::Cancelled
                    } else {
                        // A cancellation racing a buffered error ACK may be
                        // the reported hard failure. Neither outcome can retire.
                        tokio::select! { biased;
                            _ = cancellation.changed() => WorkerStartupReply::Cancelled,
                            _ = tokio::time::sleep_until(bound.into()) => WorkerStartupReply::Deadline,
                            reply = reply => reply,
                        }
                    }
                } else { reply.await };
                (method, reply, status)
            }
        )).await;
        #[cfg(test)]
        {
            let gate = self
                .transport
                .worker_startup_decision_gate
                .lock()
                .unwrap()
                .take();
            if let Some((entered, release)) = gate {
                let _ = entered.send(());
                let _ = tokio::time::timeout_at(deadline.into(), release).await;
            }
        }
        let mut disqualifying_failure = !errors.is_empty() || !complete;
        let mut eligible = errors.is_empty() && complete && same_budget;
        let mut destroyed = false;
        let mut statuses = Vec::with_capacity(4);
        for (method, reply, status) in results {
            if let Some(error) = reply.error(method) {
                errors.push(format!("{method}: {error}"));
            }
            let required = match reply {
                WorkerStartupReply::Success => CommandStatus::Acknowledged,
                WorkerStartupReply::ChannelClosed => {
                    destroyed = true;
                    CommandStatus::Destroyed
                }
                _ => {
                    eligible = false;
                    disqualifying_failure = true;
                    continue;
                }
            };
            if let Some(status) = status.filter(|status| status.snapshot() == required) {
                statuses.push((status, required));
            } else {
                eligible = false;
            }
        }
        // Preserve every delivered real error/local failure before considering
        // retirement or a later owner/connection change.
        if disqualifying_failure {
            return Err(errors.join("; "));
        }
        if self.check_cleanup_owner(&expected).is_err() {
            errors.push("Native CDP owner changed".into());
            eligible = false;
        }
        if let Err(error) = self.ensure_open() {
            errors.push(error);
            eligible = false;
        }
        if initialization.as_ref().is_some_and(|(_, cancel)| {
            *cancel.borrow() != super::super::client_session::CancelSignal::None
        }) {
            errors.push("Native initialization cancelled".into());
            eligible = false;
        }
        if std::time::Instant::now()
            >= initialization
                .as_ref()
                .map_or(deadline, |(bound, _)| deadline.min(*bound))
        {
            errors.push("Native initialization deadline expired".into());
            eligible = false;
        }
        if expected.is_some() && statuses.len() != submitted_count {
            errors.push("Service-worker startup reservation lost".into());
            eligible = false;
        }
        if !same_budget {
            errors.push("Service-worker startup initialization budget changed".into());
        }
        if errors.is_empty() && complete {
            return Ok(ServiceWorkerStartupOutcome::Ready(expected.map(|owner| {
                WorkerStartupRetirement {
                    owner,
                    session: session.into(),
                    statuses,
                    deadline,
                    initialization,
                    provenance: WorkerStartupStatusProvenance::AllAcknowledged,
                }
            })));
        }
        if eligible && destroyed {
            if let Some(owner) = expected {
                return Ok(ServiceWorkerStartupOutcome::Retired(
                    WorkerStartupRetirement {
                        owner,
                        session: session.into(),
                        statuses,
                        deadline,
                        initialization,
                        provenance: WorkerStartupStatusProvenance::IncludesDestroyed,
                    },
                ));
            }
        }
        Err(errors.join("; "))
    }

    /// Synchronous owner/status fence shared by normal Ready completion and
    /// exact retirement. Caller holds the enrollment index; no I/O runs here.
    fn with_worker_startup_proof<T>(
        &self,
        retirement: &WorkerStartupRetirement,
        targets: &Arc<super::super::client_targets::ClientTargets>,
        operation: &super::super::client_session::OperationLease,
        binding: (&str, &str),
        commit: impl FnOnce(bool) -> Result<T, ProtocolError>,
    ) -> Result<WorkerStartupProof<T>, ProtocolError> {
        let (target, session) = binding;
        retirement.check_bound()?;
        if retirement.session != session || retirement.deadline != operation.deadline {
            return Err(ProtocolError::StaleScope);
        }
        targets.require_eval_owner(&retirement.owner)?;
        let current = self
            .transport
            .debt_owner
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if self.transport.closed.load(Ordering::SeqCst)
            || current
                .as_ref()
                .is_none_or(|owner| !Arc::ptr_eq(owner, &retirement.owner))
            || self
                .owner
                .as_ref()
                .is_some_and(|owner| !Arc::ptr_eq(owner, &retirement.owner))
        {
            return Err(ProtocolError::StaleScope);
        }
        retirement.owner.with_worker_startup_proof(
            operation.generation,
            targets,
            (target, session),
            &retirement.statuses,
            retirement.provenance,
            commit,
        )
    }

    /// Retains the same all-ACK receipt across publication and applied detach.
    /// The caller emits the existing lifecycle observation after index unlock.
    pub(crate) fn try_finish_acknowledged_worker_startup(
        &self,
        receipt: WorkerStartupRetirement,
        targets: &Arc<super::super::client_targets::ClientTargets>,
        permit: &mut super::super::client_targets::ResumePermit,
        operation: &super::super::client_session::OperationLease,
        target: &str,
        session: &str,
    ) -> Result<WorkerStartupDecision, ProtocolError> {
        if !receipt.all_acknowledged() {
            return Err(ProtocolError::StaleScope);
        }
        let committed = self.with_worker_startup_proof(
            &receipt,
            targets,
            operation,
            (target, session),
            |bound| {
                if !bound {
                    return Ok(None);
                }
                permit
                    .complete_acknowledged_worker_startup(targets, target, session, || {
                        receipt.check_operation(operation)
                    })
                    .map(Some)
            },
        )?;
        match committed {
            WorkerStartupProof::Committed(Some(observed)) => {
                Ok(WorkerStartupDecision::ReadyCommitted(observed))
            }
            WorkerStartupProof::Committed(None) => Ok(WorkerStartupDecision::AwaitDetach(receipt)),
            WorkerStartupProof::AwaitPublication => {
                Ok(WorkerStartupDecision::AwaitPublication(receipt))
            }
        }
    }

    /// Consumes either trusted provenance only after applied exact detach.
    /// Permit Drop must occur after all index/owner/ledger/target guards leave.
    pub(crate) fn finish_retired_worker_startup(
        &self,
        retirement: WorkerStartupRetirement,
        targets: &Arc<super::super::client_targets::ClientTargets>,
        permit: &mut super::super::client_targets::ResumePermit,
        operation: &super::super::client_session::OperationLease,
        target: &str,
        session: &str,
    ) -> Result<WorkerStartupDecision, ProtocolError> {
        let decision = self.with_worker_startup_proof(
            &retirement,
            targets,
            operation,
            (target, session),
            |bound| {
                if bound {
                    return Err(ProtocolError::StaleScope);
                }
                permit.finish_retired_worker_startup(targets, target, session, || {
                    retirement.check_operation(operation)
                })
            },
        )?;
        Ok(match decision {
            WorkerStartupProof::Committed(()) => WorkerStartupDecision::RetiredCommitted,
            WorkerStartupProof::AwaitPublication => {
                WorkerStartupDecision::AwaitPublication(retirement)
            }
        })
    }

    /// Registers the existing ledger notification before checking its condition.
    /// No index/owner/ledger/targets guard may be held across this wait. Every
    /// caller must retry its full final proof after waking; this grants no commit.
    pub(crate) async fn wait_worker_startup_publication(
        &self,
        retirement: &mut WorkerStartupRetirement,
        operation: &super::super::client_session::OperationLease,
    ) -> Result<(), ProtocolError> {
        let notifier = retirement.owner.worker_startup_publication_notifier();
        let mut cancellation = operation.cancellation.clone();
        loop {
            let changed = notifier.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            retirement.check_operation(operation)?;
            self.check_cleanup_owner(&Some(retirement.owner.clone()))
                .map_err(|_| ProtocolError::StaleScope)?;
            self.ensure_open().map_err(|_| ProtocolError::StaleScope)?;
            if !retirement.owner.worker_startup_publication_pending()? {
                return Ok(());
            }
            let deadline = retirement.deadline().min(operation.deadline);
            tokio::select! { biased;
                _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                _ = retirement.cancelled() => return Err(ProtocolError::Cancelled),
                _ = tokio::time::sleep_until(deadline.into()) => return Err(ProtocolError::DeadlineExceeded),
                _ = changed => {},
            }
        }
    }

    pub(crate) async fn send_reserved_command(
        &self,
        method: &str,
        params: Option<Value>,
        session_id: Option<&str>,
        reservation: Option<CommandReservation>,
    ) -> Result<Value, String> {
        if reservation
            .as_ref()
            .is_some_and(CommandReservation::is_owner_cleanup)
        {
            return Err("Native cleanup requires its bound lifecycle envelope".into());
        }
        if reservation.as_ref().is_some_and(|reservation| {
            !reservation.matches_envelope(method, params.as_ref(), session_id)
        }) {
            return Err("Native CDP reservation envelope changed".into());
        }
        let budget = reservation
            .as_ref()
            .and_then(CommandReservation::initialization_budget);
        within_initialization(
            budget,
            self.send_reserved_command_bound(method, params, session_id, reservation, None),
        )
        .await
    }
    /// Fixed cleanup for an interrupted navigation in the existing producer.
    /// Preserve its journal/input debt and check the absolute cleanup bound
    /// again under websocket ownership, never borrow a new application lease.
    pub(crate) async fn stop_retiring_navigation(
        &self,
        session: &str,
        key: super::super::client_debt::OperationKey,
        deadline: std::time::Instant,
    ) -> Result<super::super::client_debt::CommandStatusHandle, String> {
        use super::super::client_debt::{command_scope, CommandCategory};
        let journal = current_operation().ok_or("Native navigation cleanup has no producer")?;
        let expected = self
            .debt_ledger()
            .ok_or("Native navigation cleanup has no owner")?;
        let state = journal.snapshot();
        if journal.key() != key
            || !Arc::ptr_eq(&journal.ledger(), &expected)
            || !state.submission_revoked
            || state.integrity_lost
            || std::time::Instant::now() >= deadline
        {
            return Err("Native navigation cleanup authority expired".into());
        }
        let params = serde_json::json!({});
        let reservation = command_scope(CommandCategory::CleanupInput, false, async {
            self.reserve_tracked_command("Page.stopLoading", Some(&params), Some(session))
        })
        .await?
        .ok_or("Native navigation cleanup is not tracked")?;
        let status = reservation.status();
        tokio::time::timeout_at(
            deadline.into(),
            self.send_reserved_command_bound(
                "Page.stopLoading",
                Some(params),
                Some(session),
                Some(reservation),
                Some((Some(expected), deadline)),
            ),
        )
        .await
        .map_err(|_| "Native navigation cleanup deadline expired".to_owned())??;
        Ok(status)
    }
    async fn send_reserved_command_bound(
        &self,
        method: &str,
        params: Option<Value>,
        session_id: Option<&str>,
        reservation: Option<CommandReservation>,
        cleanup_owner: Option<(Option<Arc<OwnerDebtLedger>>, std::time::Instant)>,
    ) -> Result<Value, String> {
        let response = self
            .submit_reserved_command_bound(method, params, session_id, reservation, cleanup_owner)
            .await?;
        self.await_command_response(method, response, None).await
    }

    async fn submit_reserved_command_bound(
        &self,
        method: &str,
        params: Option<Value>,
        session_id: Option<&str>,
        reservation: Option<CommandReservation>,
        owner_deadline: Option<(Option<Arc<OwnerDebtLedger>>, std::time::Instant)>,
    ) -> Result<CommandResponse, String> {
        let id = self.next_command_id()?;

        let cmd = CdpCommand {
            id,
            method: method.to_string(),
            params,
            session_id: session_id.filter(|s| !s.is_empty()).map(|s| s.to_string()),
        };

        let json = serde_json::to_string(&cmd)
            .map_err(|e| format!("Failed to serialize CDP command: {}", e))?;

        let (tx, rx) = oneshot::channel();

        // Cleans up the pending entry if this future is cancelled mid-await (#1528).
        let mut guard = PendingGuard {
            pending: self.transport.pending.clone(),
            id,
            done: false,
        };

        {
            let mut ws_tx = self.transport.ws_tx.lock().await;
            self.ensure_open()?;
            let mut pending = self.transport.pending.lock().await;
            if let Some((expected, deadline)) = &owner_deadline {
                self.check_cleanup_owner(expected)
                    .map_err(|_| "Native cleanup owner changed".to_string())?;
                if std::time::Instant::now() >= *deadline {
                    return Err("Native cleanup deadline expired".into());
                }
            }
            self.track_submission(id, reservation)?;
            pending.insert(
                id,
                PendingResponse {
                    sender: tx,
                    session: cmd.session_id.clone(),
                },
            );
            drop(pending);
            if let Err(error) = ws_tx.send(Message::Text(json)).await {
                self.transport.pending.lock().await.remove(&id);
                guard.done = true;
                return Err(format!("Failed to send CDP command: {}", error));
            }
        }

        Ok(CommandResponse {
            receiver: rx,
            guard,
        })
    }

    async fn await_command_response(
        &self,
        method: &str,
        response: CommandResponse,
        deadline: Option<std::time::Instant>,
    ) -> Result<Value, String> {
        match self.await_command_reply(response, deadline).await {
            Ok(CommandReply::Success(value)) => Ok(value),
            Ok(CommandReply::ErrorAck(error)) => Err(format!("CDP error ({}): {}", method, error)),
            Ok(CommandReply::LocalFailure(response)) => match response.error {
                Some(error) => Err(format!("CDP error ({}): {}", method, error)),
                None => Ok(response.result.unwrap_or(Value::Null)),
            },
            Err(CommandWaitFailure::ChannelClosed) => Err("CDP response channel closed".into()),
            Err(CommandWaitFailure::Deadline) => Err(format!("CDP command timed out: {}", method)),
        }
    }
    async fn await_command_reply(
        &self,
        response: CommandResponse,
        deadline: Option<std::time::Instant>,
    ) -> Result<CommandReply, CommandWaitFailure> {
        let CommandResponse {
            receiver,
            mut guard,
        } = response;
        let received = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline.into(), receiver).await,
            None => tokio::time::timeout(Duration::from_secs(30), receiver).await,
        };
        match received {
            Ok(Ok(reply)) => {
                guard.done = true;
                Ok(reply)
            }
            Ok(Err(_)) => {
                guard.done = true;
                Err(CommandWaitFailure::ChannelClosed)
            }
            Err(_) => {
                if deadline.is_none() {
                    guard.done = true;
                    self.transport.pending.lock().await.remove(&guard.id);
                }
                Err(CommandWaitFailure::Deadline)
            }
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<CdpEvent> {
        self.transport.event_tx.subscribe()
    }

    /// Deliver every event whose method is in `methods` to the returned
    /// receiver without loss. The events still reach the broadcast. Dropping
    /// the receiver ends the tap on the next matching event.
    pub fn subscribe_methods(
        &self,
        methods: &'static [&'static str],
    ) -> mpsc::UnboundedReceiver<CdpEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.transport
            .method_taps
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((methods, tx));
        rx
    }

    /// A bounded, independently observed control lane. Unlike the legacy
    /// lossless tap, exhaustion is explicit and requires scope teardown.
    pub fn subscribe_bounded_methods(
        &self,
        methods: &'static [&'static str],
        capacity: usize,
        max_event_bytes: usize,
    ) -> Result<BoundedMethodEvents, &'static str> {
        self.subscribe_bounded_methods_with_budget(
            methods,
            capacity,
            max_event_bytes,
            capacity
                .saturating_mul(max_event_bytes)
                .min(256 * 1024 * 1024),
        )
    }

    /// Encoded-byte budget covers queued AND leased in-flight events. Overflow
    /// is terminal: no consumer may continue after losing a required event.
    pub fn subscribe_bounded_methods_with_budget(
        &self,
        methods: &'static [&'static str],
        capacity: usize,
        max_event_bytes: usize,
        max_in_flight_bytes: usize,
    ) -> Result<BoundedMethodEvents, &'static str> {
        if methods.is_empty()
            || capacity == 0
            || capacity > 256
            || max_event_bytes == 0
            || max_event_bytes > 128 * 1024 * 1024
            || max_in_flight_bytes < max_event_bytes
            || max_in_flight_bytes > 256 * 1024 * 1024
        {
            return Err("invalid control event bounds");
        }
        #[allow(deprecated)] // Keep compatibility with older stable toolchains.
        let id = self
            .transport
            .next_tap_id
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
            .map_err(|_| "control subscription ids exhausted")?;
        let (sender, receiver) = mpsc::channel(capacity);
        let failed = Arc::new(AtomicBool::new(false));
        let received = Arc::new(AtomicU64::new(0));
        self.transport
            .bounded_method_taps
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                id,
                BoundedMethodRoute {
                    methods,
                    sender,
                    received: received.clone(),
                    failed: failed.clone(),
                    max_event_bytes,
                    budget: Arc::new(EventBudget {
                        used: AtomicUsize::new(0),
                        maximum: max_in_flight_bytes,
                    }),
                },
            );
        Ok(BoundedMethodEvents {
            receiver,
            received,
            failed,
            routes: self.transport.bounded_method_taps.clone(),
            id,
        })
    }

    /// Deliver every event carrying `session_id` to the returned receiver
    /// instead of the broadcast, so a high-volume session (a screencast) is
    /// neither cloned to every subscriber nor able to overflow their buffers.
    /// Events without a session id are unaffected. Call
    /// [`unsubscribe_session`](Self::unsubscribe_session) when done; a dropped
    /// receiver also ends the route on the next event for that session.
    pub fn subscribe_session(&self, session_id: &str) -> mpsc::Receiver<CdpEvent> {
        let (tx, rx) = mpsc::channel(PRIVATE_SESSION_BUFFER);
        self.transport
            .private_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session_id.to_string(), tx);
        rx
    }

    pub fn unsubscribe_session(&self, session_id: &str) {
        self.transport
            .private_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(session_id);
    }

    /// Subscribe to all raw incoming CDP messages (responses + events).
    /// Used by the inspect proxy to forward traffic to the DevTools frontend.
    pub fn subscribe_raw(&self) -> broadcast::Receiver<RawCdpMessage> {
        self.transport.raw_tx.subscribe()
    }

    /// Create a lightweight handle for the inspect WebSocket proxy.
    /// Contains only what's needed to forward messages bidirectionally.
    pub fn inspect_handle(&self) -> InspectProxyHandle {
        InspectProxyHandle {
            ws_tx: self.transport.ws_tx.clone(),
            raw_tx: self.transport.raw_tx.clone(),
            closed: self.transport.closed.clone(),
            debt_owner: self.transport.debt_owner.clone(),
        }
    }

    pub async fn send_command_typed<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: &P,
        session_id: Option<&str>,
    ) -> Result<R, String> {
        let params_value = serde_json::to_value(params)
            .map_err(|e| format!("Failed to serialize params: {}", e))?;
        let result = self
            .send_command(method, Some(params_value), session_id)
            .await?;
        serde_json::from_value(result)
            .map_err(|e| format!("Failed to deserialize CDP response for {}: {}", method, e))
    }

    pub async fn send_command_no_params(
        &self,
        method: &str,
        session_id: Option<&str>,
    ) -> Result<Value, String> {
        self.send_command(method, None, session_id).await
    }

    /// Send a CDP command without waiting for its response.
    ///
    /// This is useful for best-effort commands where Chrome may not emit a
    /// response for every target session, but the command still needs to be
    /// written before the caller can continue processing events.
    pub async fn send_command_no_wait(
        &self,
        method: &str,
        params: Option<Value>,
        session_id: Option<&str>,
    ) -> Result<(), String> {
        let reservation = self.reserve_tracked_command(method, params.as_ref(), session_id)?;
        let budget = reservation
            .as_ref()
            .and_then(CommandReservation::initialization_budget);
        within_initialization(budget, async {
            let id = self.next_command_id()?;
            let cmd = CdpCommand {
                id,
                method: method.to_string(),
                params,
                session_id: session_id.filter(|s| !s.is_empty()).map(|s| s.to_string()),
            };

            let json = serde_json::to_string(&cmd)
                .map_err(|e| format!("Failed to serialize CDP command: {}", e))?;

            let mut ws_tx = self.transport.ws_tx.lock().await;
            self.ensure_open()?;
            self.track_submission(id, reservation)?;
            ws_tx
                .send(Message::Text(json))
                .await
                .map_err(|e| format!("Failed to send CDP command: {}", e))
        })
        .await
    }

    /// Send raw JSON through the WebSocket without tracking a response.
    /// Used by the inspect proxy to forward DevTools frontend messages.
    pub async fn send_raw(&self, json: String) -> Result<(), String> {
        if self.debt_ledger().is_some() {
            return Err("Raw CDP writes are not admitted by the native owner".to_string());
        }
        let mut ws_tx = self.transport.ws_tx.lock().await;
        self.ensure_open()?;
        if self
            .transport
            .debt_owner
            .lock()
            .map_err(|_| "Native owner unavailable")?
            .is_some()
        {
            return Err("Raw CDP writes are not admitted by the native owner".into());
        }
        ws_tx
            .send(Message::Text(json))
            .await
            .map_err(|e| format!("Failed to send raw CDP message: {}", e))
    }

    #[cfg(test)]
    pub(crate) fn hold_worker_startup_decision(
        &self,
    ) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered, observed) = oneshot::channel();
        let (release, waiting) = oneshot::channel();
        *self.transport.worker_startup_decision_gate.lock().unwrap() = Some((entered, waiting));
        (observed, release)
    }

    /// Test-only: count of in-flight commands still awaiting a response, so a
    /// test can assert a cancelled command left no orphaned entry (#1528).
    #[cfg(test)]
    pub(crate) async fn pending_len(&self) -> usize {
        self.transport.pending.lock().await.len()
    }
}

/// Lightweight handle for the inspect WebSocket proxy, holding only
/// the cloneable parts of CdpClient needed for bidirectional message forwarding.
pub struct InspectProxyHandle {
    debt_owner: DebtOwner,
    ws_tx: WsTx,
    raw_tx: broadcast::Sender<RawCdpMessage>,
    closed: Arc<AtomicBool>,
}

impl InspectProxyHandle {
    pub async fn send_raw(&self, json: String) -> Result<(), String> {
        let mut ws_tx = self.ws_tx.lock().await;
        if self
            .debt_owner
            .lock()
            .map_err(|_| "Native owner unavailable")?
            .is_some()
        {
            return Err("Raw CDP writes are not admitted by the native owner".into());
        }
        if self.closed.load(Ordering::SeqCst) {
            return Err(CONNECTION_CLOSED_ERROR.to_string());
        }
        ws_tx
            .send(Message::Text(json))
            .await
            .map_err(|e| format!("Failed to send raw CDP message: {}", e))
    }

    pub fn subscribe_raw(&self) -> broadcast::Receiver<RawCdpMessage> {
        self.raw_tx.subscribe()
    }
}

/// Enable TCP SO_KEEPALIVE on the underlying socket of a WebSocket connection.
/// This is best-effort: failures are silently ignored since the WebSocket-level
/// Ping keepalive provides the primary connection liveness mechanism.
fn enable_tcp_keepalive(stream: &tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>) {
    let Some(tcp_stream) = underlying_tcp_stream(stream) else {
        return;
    };

    // SockRef borrows the fd without taking ownership.
    let sock = socket2::SockRef::from(tcp_stream);
    let keepalive = socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(30));

    // with_interval sets TCP_KEEPINTVL — the time between probes after the
    // first keepalive probe goes unanswered. Available on most platforms
    // (Linux, macOS, Windows, FreeBSD, etc.) but not OpenBSD or Haiku.
    #[cfg(not(any(target_os = "openbsd", target_os = "haiku")))]
    let keepalive = keepalive.with_interval(std::time::Duration::from_secs(10));

    let _ = sock.set_tcp_keepalive(&keepalive);
}

fn underlying_tcp_stream(
    stream: &tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
) -> Option<&tokio::net::TcpStream> {
    match stream {
        tokio_tungstenite::MaybeTlsStream::Plain(stream) => Some(stream),
        tokio_tungstenite::MaybeTlsStream::Rustls(stream) => Some(stream.get_ref().0),
        _ => None,
    }
}

#[cfg(test)]
#[path = "owner_lifecycle_tests.rs"]
mod owner_lifecycle_tests;

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn dropped_waiter_keeps_reader_debt_and_late_handle_gets_one_original_session_release() {
        use super::super::super::client_debt::{OperationKey, OwnerDebtLedger};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (seen_tx, seen_rx) = oneshot::channel();
        let (late_tx, late_rx) = oneshot::channel();
        let log = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
        let requests = log.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let first: Value =
                serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap())
                    .unwrap();
            requests.lock().unwrap().push(first.clone());
            seen_tx.send(()).unwrap();
            late_rx.await.unwrap();
            socket.send(Message::Text(json!({"id":first["id"],"sessionId":"page","result":{"object":{"objectId":"late-object"}}}).to_string())).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                let Ok(text) = message.to_text() else {
                    continue;
                };
                let request: Value = serde_json::from_str(text).unwrap();
                requests.lock().unwrap().push(request.clone());
                assert_eq!(request["method"], "Runtime.releaseObject");
                assert_eq!(request["params"]["objectId"], "late-object");
                assert_eq!(request["sessionId"], "page");
                socket
                    .send(Message::Text(
                        json!({"id":request["id"],"sessionId":"page","result":{}}).to_string(),
                    ))
                    .await
                    .unwrap();
            }
        });
        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        let ledger = OwnerDebtLedger::new(1, "scope".into());
        client.install_debt_ledger(ledger.clone()).unwrap();
        let journal = ledger
            .operation(
                OperationKey {
                    generation: 1,
                    operation_seq: 1,
                },
                "target".into(),
                "page".into(),
            )
            .unwrap();
        let sender = client.clone();
        let task = tokio::spawn(async move {
            journal
                .scope(sender.send_command(
                    "DOM.resolveNode",
                    Some(json!({"backendNodeId":1})),
                    Some("page"),
                ))
                .await
        });
        seen_rx.await.unwrap();
        task.abort();
        let _ = task.await;
        assert!(client.transport.pending.lock().await.is_empty());
        assert_eq!(ledger.snapshot().object_debt, 1);
        late_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while ledger.snapshot().object_debt != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(log.lock().unwrap().len(), 2);
        assert!(!ledger.snapshot().integrity_lost);
        client.close().await;
        server.abort();
    }

    use super::*;
    use base64::Engine;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use serde_json::json;
    use std::io::Read;
    use std::net::TcpListener as StdTcpListener;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    async fn service_worker_test_peer() -> (
        Arc<CdpClient>,
        mpsc::UnboundedReceiver<Value>,
        mpsc::UnboundedSender<Value>,
        JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let (requests, seen) = mpsc::unbounded_channel();
        let (replies, mut responses) = mpsc::unbounded_channel::<Value>();
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            loop {
                tokio::select! {
                    message = socket.next() => match message {
                        Some(Ok(Message::Text(text))) => {
                            requests.send(serde_json::from_str(&text).unwrap()).unwrap();
                        }
                        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                        _ => {}
                    },
                    Some(response) = responses.recv() => {
                        socket.send(Message::Text(response.to_string())).await.unwrap();
                    }
                }
            }
        });
        let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
        (client, seen, replies, peer)
    }

    fn service_worker_test_owner(
        client: &CdpClient,
        deadline: std::time::Instant,
    ) -> (
        Arc<CdpClient>,
        Arc<OwnerDebtLedger>,
        watch::Sender<crate::native::client_session::CancelSignal>,
    ) {
        use crate::native::client_session::{CancelSignal, OperationLease};
        let (cancel, cancellation) = watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline,
            cancellation,
        };
        let ledger =
            OwnerDebtLedger::unpublished(&operation, "worker-owner".into(), false).unwrap();
        ledger.bind_context("worker-context").unwrap();
        ledger
            .bind_session("worker-context", "worker-target", "worker-session")
            .unwrap();
        client.install_debt_ledger(ledger.clone()).unwrap();
        (client.owner_view(ledger.clone()).unwrap(), ledger, cancel)
    }

    async fn service_worker_request(requests: &mut mpsc::UnboundedReceiver<Value>) -> Value {
        tokio::time::timeout(Duration::from_secs(2), requests.recv())
            .await
            .expect("worker command was blocked waiting for an earlier ACK")
            .unwrap()
    }

    fn service_worker_response(request: &Value, fail: bool) -> Value {
        let mut response = json!({"id":request["id"], "sessionId":request["sessionId"]});
        if fail {
            response["error"] = json!({"code":-32000,"message":"observation failed"});
        } else {
            response["result"] = json!({});
        }
        response
    }

    #[tokio::test]
    async fn service_worker_startup_serial_enables_cannot_reach_resume_without_ack() {
        let (client, mut requests, replies, peer) = service_worker_test_peer().await;
        let sender = client.clone();
        let serial = tokio::spawn(async move {
            for method in [
                "Network.enable",
                "Runtime.enable",
                "Runtime.runIfWaitingForDebugger",
            ] {
                sender
                    .send_command(method, Some(json!({})), Some("worker-session"))
                    .await?;
            }
            Ok::<_, String>(())
        });
        for method in [
            "Network.enable",
            "Runtime.enable",
            "Runtime.runIfWaitingForDebugger",
        ] {
            let request = service_worker_request(&mut requests).await;
            assert_eq!(request["method"], method);
            assert_eq!(client.pending_len().await, 1);
            assert!(requests.try_recv().is_err());
            assert!(!serial.is_finished());
            replies
                .send(service_worker_response(&request, false))
                .unwrap();
        }
        serial.await.unwrap().unwrap();
        client.close().await;
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn service_worker_startup_submits_in_order_then_joins_every_real_ack() {
        for bypass in [false, true] {
            let methods = if bypass {
                vec![
                    "Network.enable",
                    "Network.setBypassServiceWorker",
                    "Runtime.enable",
                    "Runtime.runIfWaitingForDebugger",
                ]
            } else {
                vec![
                    "Network.enable",
                    "Runtime.enable",
                    "Runtime.runIfWaitingForDebugger",
                ]
            };
            for failed_method in std::iter::once(None).chain(methods.iter().copied().map(Some)) {
                let (client, mut requests, replies, peer) = service_worker_test_peer().await;
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let (view, ledger, _cancel) = service_worker_test_owner(&client, deadline);
                let network_params =
                    json!({"maxTotalBufferSize":1048576,"maxResourceBufferSize":65536});
                let expected_params = network_params.clone();
                let startup = tokio::spawn(async move {
                    view.initialize_service_worker_domains(
                        "worker-session",
                        network_params,
                        bypass,
                        deadline,
                    )
                    .await
                });
                let mut sent = Vec::new();
                for method in &methods {
                    let request = service_worker_request(&mut requests).await;
                    assert_eq!(request["method"], *method);
                    assert_eq!(request["sessionId"], "worker-session");
                    assert_eq!(
                        request["params"],
                        match *method {
                            "Network.enable" => expected_params.clone(),
                            "Network.setBypassServiceWorker" => json!({"bypass":true}),
                            _ => json!({}),
                        }
                    );
                    sent.push(request);
                }
                for pair in sent.windows(2) {
                    assert_ne!(pair[0]["id"], pair[1]["id"]);
                }
                assert_eq!(client.pending_len().await, methods.len());
                assert_eq!(
                    ledger.snapshot().outstanding_commands,
                    u32::try_from(methods.len()).unwrap()
                );
                assert!(
                    requests.try_recv().is_err(),
                    "duplicate worker resume/domain enable"
                );
                assert!(!startup.is_finished(), "submission is not readiness");
                // Hold Runtime.enable last. Errors from any other command must
                // not cause an early return/drop of this submitted sibling.
                let held = methods.len() - 2;
                for (index, request) in sent.iter().enumerate() {
                    if index != held {
                        replies
                            .send(service_worker_response(
                                request,
                                failed_method == request["method"].as_str(),
                            ))
                            .unwrap();
                    }
                }
                tokio::time::timeout(Duration::from_secs(2), async {
                    while client.pending_len().await != 1 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert!(
                    !startup.is_finished(),
                    "an error dropped an already submitted sibling"
                );
                assert_eq!(ledger.snapshot().outstanding_commands, 1);
                replies
                    .send(service_worker_response(
                        &sent[held],
                        failed_method == Some("Runtime.enable"),
                    ))
                    .unwrap();
                let result = startup.await.unwrap();
                if let Some(method) = failed_method {
                    let error = result.unwrap_err();
                    assert!(
                        error.contains(method) && error.contains("observation failed"),
                        "{error}"
                    );
                } else {
                    assert!(matches!(
                        result.unwrap(),
                        ServiceWorkerStartupOutcome::Ready(Some(_))
                    ));
                }
                assert_eq!(client.pending_len().await, 0);
                assert_eq!(ledger.snapshot().outstanding_commands, 0);
                assert!(requests.try_recv().is_err());
                client.close().await;
                peer.await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn service_worker_startup_submission_failure_drains_sent_command_without_resume() {
        let (client, mut requests, replies, peer) = service_worker_test_peer().await;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let (view, ledger, _cancel) = service_worker_test_owner(&client, deadline);
        // Network.enable gets the last usable ID. Runtime.enable fails locally
        // before sending, so no subsequent resume may be attempted.
        client
            .transport
            .next_id
            .store(u64::MAX - 1, Ordering::SeqCst);
        let startup = tokio::spawn(async move {
            view.initialize_service_worker_domains("worker-session", json!({}), false, deadline)
                .await
        });
        let network = service_worker_request(&mut requests).await;
        assert_eq!(network["method"], "Network.enable");
        assert!(!startup.is_finished());
        assert_eq!(client.pending_len().await, 1);
        assert_eq!(ledger.snapshot().outstanding_commands, 1);
        replies
            .send(service_worker_response(&network, false))
            .unwrap();
        let error = startup.await.unwrap().unwrap_err();
        assert!(error.contains("Runtime.enable") && error.contains("identifier exhausted"));
        assert!(requests.try_recv().is_err());
        assert_eq!(ledger.snapshot().outstanding_commands, 0);
        client.close().await;
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn service_worker_startup_checks_session_owner_retirement_and_original_deadline() {
        for change in [
            "empty",
            "foreign-session",
            "owner",
            "retired",
            "cancelled",
            "expired",
            "deadline",
        ] {
            let (client, mut requests, _replies, peer) = service_worker_test_peer().await;
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let (view, ledger, cancel) = service_worker_test_owner(&client, deadline);
            let session = match change {
                "empty" => "",
                "foreign-session" => "different-worker",
                _ => "worker-session",
            };
            let command_deadline = match change {
                "deadline" => std::time::Instant::now() + Duration::from_millis(10),
                "expired" => std::time::Instant::now() - Duration::from_secs(1),
                _ => deadline,
            };
            let writer = client.transport.ws_tx.lock().await;
            let mut startup = Box::pin(view.initialize_service_worker_domains(
                session,
                json!({}),
                false,
                command_deadline,
            ));
            if matches!(change, "empty" | "foreign-session" | "expired") {
                assert!(startup.await.is_err());
            } else {
                assert!(futures_util::poll!(startup.as_mut()).is_pending());
                assert_eq!(ledger.snapshot().outstanding_commands, 1);
                match change {
                    "owner" => {
                        // Model stale transport ownership while a reservation is
                        // waiting; the writer-side exact-owner check must reject it.
                        *client.transport.debt_owner.lock().unwrap() =
                            Some(OwnerDebtLedger::new(1, "replacement".into()));
                    }
                    "retired" => ledger
                        .retire_after_context_destroy("worker-context")
                        .unwrap(),
                    "cancelled" => cancel
                        .send(crate::native::client_session::CancelSignal::Requested)
                        .unwrap(),
                    "deadline" => tokio::time::sleep_until(command_deadline.into()).await,
                    _ => unreachable!(),
                }
                drop(writer);
                assert!(startup.await.is_err(), "{change} admitted worker startup");
                assert_eq!(ledger.snapshot().outstanding_commands, 0);
                assert!(requests.try_recv().is_err());
                client.close().await;
                peer.await.unwrap();
                continue;
            }
            drop(writer);
            assert_eq!(ledger.snapshot().outstanding_commands, 0);
            assert!(requests.try_recv().is_err());
            client.close().await;
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn service_worker_startup_cancel_drop_or_deadline_preserves_debt_until_late_acks() {
        for completion in ["drop", "cancel", "deadline"] {
            let (client, mut requests, replies, peer) = service_worker_test_peer().await;
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let (view, ledger, cancel) = service_worker_test_owner(&client, deadline);
            // The supplied operation bound is shorter than the owner's bootstrap
            // budget; waiting for responses must not renew either one.
            let response_deadline = if completion == "deadline" {
                std::time::Instant::now() + Duration::from_secs(1)
            } else {
                deadline
            };
            let startup = tokio::spawn(async move {
                view.initialize_service_worker_domains(
                    "worker-session",
                    json!({}),
                    false,
                    response_deadline,
                )
                .await
            });
            let mut sent = Vec::new();
            for _ in 0..3 {
                sent.push(service_worker_request(&mut requests).await);
            }
            match completion {
                "cancel" => {
                    cancel
                        .send(crate::native::client_session::CancelSignal::Requested)
                        .unwrap();
                    assert!(startup.await.unwrap().unwrap_err().contains("cancelled"));
                }
                "deadline" => {
                    let result = tokio::time::timeout_at(
                        (response_deadline + Duration::from_millis(250)).into(),
                        startup,
                    )
                    .await
                    .expect("worker response wait renewed its operation deadline");
                    assert!(result.unwrap().unwrap_err().contains("timed out"));
                }
                _ => {
                    startup.abort();
                    assert!(startup.await.unwrap_err().is_cancelled());
                }
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                while client.pending_len().await != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(ledger.snapshot().outstanding_commands, 3);
            assert_eq!(client.transport.tracked_responses.lock().unwrap().len(), 3);
            for request in &sent {
                replies
                    .send(service_worker_response(request, false))
                    .unwrap();
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                while ledger.snapshot().outstanding_commands != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(client
                .transport
                .tracked_responses
                .lock()
                .unwrap()
                .is_empty());
            assert!(!ledger.snapshot().integrity_lost);
            assert!(requests.try_recv().is_err());
            client.close().await;
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn service_worker_startup_deadline_does_not_wait_for_pending_cleanup_lock() {
        let (client, mut requests, replies, peer) = service_worker_test_peer().await;
        let owner_deadline = std::time::Instant::now() + Duration::from_secs(5);
        let (view, ledger, _cancel) = service_worker_test_owner(&client, owner_deadline);
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let startup = tokio::spawn(async move {
            view.initialize_service_worker_domains("worker-session", json!({}), false, deadline)
                .await
        });
        let mut sent = Vec::new();
        for _ in 0..3 {
            sent.push(service_worker_request(&mut requests).await);
        }
        // Hold the existing pending map across the operation deadline. The
        // caller must finish while Drop's asynchronous cleanup remains blocked.
        let pending = client.transport.pending.lock().await;
        assert_eq!(pending.len(), 3);
        let result =
            tokio::time::timeout_at((deadline + Duration::from_millis(250)).into(), startup)
                .await
                .expect("expired startup awaited the pending-map cleanup lock")
                .unwrap();
        assert!(result.unwrap_err().contains("timed out"));
        assert_eq!(pending.len(), 3);
        assert_eq!(ledger.snapshot().outstanding_commands, 3);
        assert_eq!(client.transport.tracked_responses.lock().unwrap().len(), 3);
        drop(pending);
        tokio::time::timeout(Duration::from_secs(2), async {
            while client.pending_len().await != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(ledger.snapshot().outstanding_commands, 3);
        for request in &sent {
            replies
                .send(service_worker_response(request, false))
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while ledger.snapshot().outstanding_commands != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(client
            .transport
            .tracked_responses
            .lock()
            .unwrap()
            .is_empty());
        assert!(!ledger.snapshot().integrity_lost);
        assert!(requests.try_recv().is_err());
        client.close().await;
        peer.await.unwrap();
    }

    // These characterize the reader/debt boundary of a main-script failure.
    // The peer models an exact detach before renderer-domain ACKs;
    // this does not establish the observed HTTP 500 event sequence. No HTTP
    // fixture, coordinator quarantine, or ResumePermit is exercised.
    async fn service_worker_retirement_batch(
        view: Arc<CdpClient>,
        requests: &mut mpsc::UnboundedReceiver<Value>,
        deadline: std::time::Instant,
    ) -> (
        JoinHandle<Result<ServiceWorkerStartupOutcome, String>>,
        Vec<Value>,
    ) {
        let startup = tokio::spawn(async move {
            view.initialize_service_worker_domains("worker-session", json!({}), false, deadline)
                .await
        });
        let mut sent = Vec::new();
        for method in [
            "Network.enable",
            "Runtime.enable",
            "Runtime.runIfWaitingForDebugger",
        ] {
            let request = service_worker_request(requests).await;
            assert_eq!(request["method"], method);
            assert_eq!(request["sessionId"], "worker-session");
            sent.push(request);
        }
        assert!(!startup.is_finished());
        assert!(requests.try_recv().is_err());
        (startup, sent)
    }

    async fn service_worker_retirement_event(
        replies: &mpsc::UnboundedSender<Value>,
        events: &mut broadcast::Receiver<CdpEvent>,
        event: Value,
    ) {
        replies.send(event.clone()).unwrap();
        let observed = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .expect("reader did not publish the lifecycle barrier")
            .unwrap();
        assert_eq!(Some(observed.method.as_str()), event["method"].as_str());
        assert_eq!(observed.params, event["params"]);
        assert_eq!(observed.session_id.as_deref(), event["sessionId"].as_str());
    }

    #[tokio::test]
    async fn service_worker_startup_exact_detach_creates_retired_candidate_without_an_ack() {
        let (client, mut requests, replies, peer) = service_worker_test_peer().await;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let (view, ledger, _cancel) = service_worker_test_owner(&client, deadline);
        let mut events = client.subscribe();
        let (startup, sent) = service_worker_retirement_batch(view, &mut requests, deadline).await;
        assert_eq!(ledger.snapshot().outstanding_commands, 3);
        // Resume succeeded, but the main script never created a renderer able
        // to acknowledge Network.enable or Runtime.enable.
        replies
            .send(service_worker_response(&sent[2], false))
            .unwrap();
        service_worker_retirement_event(
            &replies,
            &mut events,
            json!({"method":"Target.detachedFromTarget", "sessionId":"worker-session",
                "params":{"sessionId":"foreign-session","targetId":"foreign-target"}}),
        )
        .await;
        assert_eq!(client.pending_len().await, 2);
        assert_eq!(ledger.snapshot().outstanding_commands, 2);
        assert!(
            !startup.is_finished(),
            "the parent envelope is not the detached child"
        );
        service_worker_retirement_event(
            &replies,
            &mut events,
            json!({"method":"Target.detachedFromTarget", "sessionId":"parent-session",
                "params":{"sessionId":"worker-session","targetId":"worker-target"}}),
        )
        .await;
        let outcome = tokio::time::timeout(Duration::from_secs(2), startup)
            .await
            .expect("exact detach must wake startup before its deadline")
            .unwrap()
            .unwrap();
        let ServiceWorkerStartupOutcome::Retired(retirement) = outcome else {
            panic!("Destroyed waiters must not be advertised as Ready")
        };
        assert!(Arc::ptr_eq(&retirement.owner, &ledger));
        assert_eq!(retirement.session, "worker-session");
        assert_eq!(retirement.statuses.len(), 3);
        assert_eq!(
            retirement
                .statuses
                .iter()
                .filter(|(_, expected)| *expected == CommandStatus::Destroyed)
                .count(),
            2
        );
        assert_eq!(
            retirement
                .statuses
                .iter()
                .filter(|(_, expected)| *expected == CommandStatus::Acknowledged)
                .count(),
            1
        );
        assert!(retirement
            .statuses
            .iter()
            .all(|(status, expected)| status.snapshot() == *expected));
        assert_eq!(client.pending_len().await, 0);
        assert_eq!(ledger.snapshot().outstanding_commands, 0);
        assert!(!ledger.snapshot().integrity_lost);
        assert_eq!(client.transport.tracked_responses.lock().unwrap().len(), 2);
        // Debt retirement is not a fabricated ACK. Reader correlation remains
        // until late replies arrive, without reviving or replaying startup.
        for request in &sent[..2] {
            replies
                .send(service_worker_response(request, false))
                .unwrap();
        }
        service_worker_retirement_event(
            &replies,
            &mut events,
            json!({"method":"Test.workerLateReplies", "params":{}}),
        )
        .await;
        assert!(client
            .transport
            .tracked_responses
            .lock()
            .unwrap()
            .is_empty());
        assert_eq!(ledger.snapshot().outstanding_commands, 0);
        assert!(!ledger.snapshot().integrity_lost);
        assert!(requests.try_recv().is_err());
        client.close().await;
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn service_worker_retirement_malformed_or_unverified_reply_is_not_an_error_ack_or_retirement(
    ) {
        for malformed in [true, false] {
            let (client, mut requests, replies, peer) = service_worker_test_peer().await;
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let (view, _ledger, _cancel) = service_worker_test_owner(&client, deadline);
            let mut events = client.subscribe();
            let (startup, sent) =
                service_worker_retirement_batch(view, &mut requests, deadline).await;
            let response = if malformed {
                json!({"id":sent[0]["id"],"sessionId":"worker-session","error":{"code":"not-an-integer","message":"synthetic"}})
            } else {
                json!({"id":sent[0]["id"],"sessionId":"worker-session","result":{},"error":{"code":-32000,"message":"synthetic ambiguous envelope"}})
            };
            replies.send(response).unwrap();
            service_worker_retirement_event(
                &replies,
                &mut events,
                json!({"method":"Test.workerMalformedBarrier","params":{}}),
            )
            .await;
            service_worker_retirement_event(&replies, &mut events,
                json!({"method":"Target.detachedFromTarget","params":{"sessionId":"worker-session","targetId":"worker-target"}})).await;
            let error = tokio::time::timeout(Duration::from_secs(2), startup)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert!(error.contains("Network.enable:"), "{error}");
            assert!(
                error.contains(if malformed {
                    "Malformed CDP response"
                } else {
                    "synthetic ambiguous envelope"
                }),
                "{error}"
            );
            assert!(requests.try_recv().is_err());
            client.close().await;
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn service_worker_retirement_wrong_session_ancestor_or_target_destroyed_is_insufficient()
    {
        for event in [
            json!({"method":"Target.detachedFromTarget","sessionId":"worker-session","params":{"sessionId":"other-session"}}),
            json!({"method":"Target.detachedFromTarget","params":{"sessionId":"parent-session"}}),
            json!({"method":"Target.targetDestroyed","params":{"targetId":"worker-target"}}),
        ] {
            let (client, mut requests, replies, peer) = service_worker_test_peer().await;
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let (view, _ledger, cancel) = service_worker_test_owner(&client, deadline);
            let mut events = client.subscribe();
            let (mut startup, _sent) =
                service_worker_retirement_batch(view, &mut requests, deadline).await;
            service_worker_retirement_event(&replies, &mut events, event).await;
            assert_eq!(client.pending_len().await, 3);
            assert!(
                tokio::time::timeout(Duration::from_millis(10), &mut startup)
                    .await
                    .is_err()
            );
            cancel
                .send(crate::native::client_session::CancelSignal::Requested)
                .unwrap();
            assert!(startup.await.unwrap().unwrap_err().contains("cancelled"));
            assert!(requests.try_recv().is_err());
            client.close().await;
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn service_worker_retirement_final_consumer_rechecks_original_owner_generation_and_bound()
    {
        use crate::native::client_targets::ClientTargets;
        for scenario in [
            "exact",
            "owner-replaced",
            "generation-replaced",
            "cancelled",
            "sealed",
        ] {
            let (client, mut requests, replies, peer) = service_worker_test_peer().await;
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let (view, ledger, cancel) = service_worker_test_owner(&client, deadline);
            let targets = ClientTargets::new("worker-context".into(), "worker-owner".into());
            targets.bind_eval_owner(&ledger, 1).unwrap();
            targets
                .attached(
                    "worker-context",
                    "worker-target".into(),
                    "worker-session".into(),
                    "service_worker".into(),
                )
                .unwrap();
            let mut permit = targets
                .service_worker_startup_permit("worker-target", "worker-session")
                .await
                .unwrap();
            let mut events = client.subscribe();
            let (startup, _sent) =
                service_worker_retirement_batch(view.clone(), &mut requests, deadline).await;
            service_worker_retirement_event(&replies,&mut events,
                json!({"method":"Target.detachedFromTarget","params":{"sessionId":"worker-session","targetId":"worker-target"}})).await;
            let ServiceWorkerStartupOutcome::Retired(retirement) = startup.await.unwrap().unwrap()
            else {
                panic!("expected candidate");
            };
            targets
                .observe_worker_detach("worker-target", "worker-session")
                .unwrap();
            targets.detach("worker-target").unwrap();
            match scenario {
                "owner-replaced" => {
                    *client.transport.debt_owner.lock().unwrap() =
                        Some(OwnerDebtLedger::new(2, "other".into()))
                }
                "cancelled" => {
                    cancel
                        .send(crate::native::client_session::CancelSignal::Requested)
                        .unwrap();
                }
                "sealed" => targets.seal(),
                _ => {}
            }
            let result = view.finish_retired_worker_startup(
                retirement,
                &targets,
                &mut permit,
                &crate::native::client_session::OperationLease {
                    is_callback: false,
                    generation: if scenario == "generation-replaced" {
                        2
                    } else {
                        1
                    },
                    sequence: 0,
                    deadline,
                    cancellation: cancel.subscribe(),
                },
                "worker-target",
                "worker-session",
            );
            assert_eq!(
                result.is_ok(),
                scenario == "exact",
                "{scenario}: {result:?}"
            );
            drop(permit);
            assert_eq!(
                targets.check_settlement_integrity().is_ok(),
                scenario == "exact",
                "{scenario}"
            );
            assert!(targets.owned_target("worker-target").is_err());
            assert!(requests.try_recv().is_err());
            client.close().await;
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn service_worker_retirement_final_lock_rechecks_operation_and_bootstrap_bounds() {
        use crate::native::client_session::{CancelSignal, OperationLease};
        use crate::native::client_targets::ClientTargets;
        for scenario in [
            "published-cancel",
            "published-deadline",
            "bootstrap-cancel",
            "bootstrap-deadline",
        ] {
            let (client, mut requests, replies, peer) = service_worker_test_peer().await;
            let now = std::time::Instant::now();
            let deadline = now
                + if scenario == "published-deadline" {
                    Duration::from_millis(500)
                } else {
                    Duration::from_secs(5)
                };
            let bootstrap_deadline = if scenario == "bootstrap-deadline" {
                now + Duration::from_millis(500)
            } else {
                deadline
            };
            let published = scenario.starts_with("published-");
            let (view, ledger, bootstrap_cancel) = if published {
                let ledger = OwnerDebtLedger::new(1, "worker-owner".into());
                ledger.bind_context("worker-context").unwrap();
                ledger
                    .bind_session("worker-context", "worker-target", "worker-session")
                    .unwrap();
                client.install_debt_ledger(ledger.clone()).unwrap();
                let (cancel, _) = watch::channel(CancelSignal::None);
                (client.owner_view(ledger.clone()).unwrap(), ledger, cancel)
            } else {
                service_worker_test_owner(&client, bootstrap_deadline)
            };
            let targets = ClientTargets::new("worker-context".into(), "worker-owner".into());
            targets.bind_eval_owner(&ledger, 1).unwrap();
            targets
                .attached(
                    "worker-context",
                    "worker-target".into(),
                    "worker-session".into(),
                    "service_worker".into(),
                )
                .unwrap();
            let mut permit = targets
                .service_worker_startup_permit("worker-target", "worker-session")
                .await
                .unwrap();
            let mut events = client.subscribe();
            let (startup, _) =
                service_worker_retirement_batch(view.clone(), &mut requests, deadline).await;
            service_worker_retirement_event(&replies,&mut events,
                json!({"method":"Target.detachedFromTarget","params":{"sessionId":"worker-session","targetId":"worker-target"}})).await;
            let ServiceWorkerStartupOutcome::Retired(retirement) = startup.await.unwrap().unwrap()
            else {
                panic!("expected original batch receipt");
            };
            assert_eq!(retirement.initialization.is_none(), published, "{scenario}");
            targets
                .observe_worker_detach("worker-target", "worker-session")
                .unwrap();
            targets.detach("worker-target").unwrap();
            let (operation_cancel, cancellation) = watch::channel(CancelSignal::None);
            let operation = OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 0,
                deadline,
                cancellation,
            };
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let mut finisher = None;
            targets.with_worker_retirement_lock_for_test(entered_tx, || {
                let held_targets = targets.clone();
                finisher = Some(std::thread::spawn(move || {
                    let result = view.finish_retired_worker_startup(
                        retirement,
                        &held_targets,
                        &mut permit,
                        &operation,
                        "worker-target",
                        "worker-session",
                    );
                    drop(permit);
                    result
                }));
                // The real receipt passed its earlier checks and holds owner
                // plus ledger. The last targets mutex remains owned by us.
                entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                assert!(!finisher.as_ref().unwrap().is_finished());
                match scenario {
                    "published-cancel" => {
                        operation_cancel.send(CancelSignal::Requested).unwrap();
                    }
                    "bootstrap-cancel" => {
                        bootstrap_cancel.send(CancelSignal::Requested).unwrap();
                    }
                    _ => std::thread::sleep(
                        bootstrap_deadline
                            .min(deadline)
                            .saturating_duration_since(std::time::Instant::now())
                            + Duration::from_millis(5),
                    ),
                }
            });
            let result = finisher.unwrap().join().unwrap();
            assert_eq!(
                result.map(|_| ()),
                Err(if scenario.ends_with("cancel") {
                    ProtocolError::Cancelled
                } else {
                    ProtocolError::DeadlineExceeded
                }),
                "{scenario}"
            );
            assert!(targets.check_settlement_integrity().is_err());
            assert_eq!(ledger.snapshot().outstanding_commands, 0);
            assert!(requests.try_recv().is_err());
            client.close().await;
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn service_worker_all_ack_final_lock_rechecks_operation_and_bootstrap_bounds() {
        use crate::native::client_session::{CancelSignal, OperationLease};
        use crate::native::client_targets::ClientTargets;
        for retire in [false, true] {
            for scenario in [
                "published-cancel",
                "published-deadline",
                "bootstrap-cancel",
                "bootstrap-deadline",
            ] {
                let (client, mut requests, replies, peer) = service_worker_test_peer().await;
                let now = std::time::Instant::now();
                let deadline = now
                    + if scenario == "published-deadline" {
                        Duration::from_millis(500)
                    } else {
                        Duration::from_secs(5)
                    };
                let bootstrap_deadline = if scenario == "bootstrap-deadline" {
                    now + Duration::from_millis(500)
                } else {
                    deadline
                };
                let published = scenario.starts_with("published-");
                let (view, ledger, bootstrap_cancel) = if published {
                    let ledger = OwnerDebtLedger::new(1, "worker-owner".into());
                    ledger.bind_context("worker-context").unwrap();
                    ledger
                        .bind_session("worker-context", "worker-target", "worker-session")
                        .unwrap();
                    client.install_debt_ledger(ledger.clone()).unwrap();
                    let (cancel, _) = watch::channel(CancelSignal::None);
                    (client.owner_view(ledger.clone()).unwrap(), ledger, cancel)
                } else {
                    service_worker_test_owner(&client, bootstrap_deadline)
                };
                let targets = ClientTargets::new("worker-context".into(), "worker-owner".into());
                targets.bind_eval_owner(&ledger, 1).unwrap();
                targets
                    .attached(
                        "worker-context",
                        "worker-target".into(),
                        "worker-session".into(),
                        "service_worker".into(),
                    )
                    .unwrap();
                let mut permit = targets
                    .service_worker_startup_permit("worker-target", "worker-session")
                    .await
                    .unwrap();
                let mut events = client.subscribe();
                let (startup, sent) =
                    service_worker_retirement_batch(view.clone(), &mut requests, deadline).await;
                for request in &sent {
                    replies
                        .send(service_worker_response(request, false))
                        .unwrap();
                }
                let ServiceWorkerStartupOutcome::Ready(Some(retirement)) =
                    startup.await.unwrap().unwrap()
                else {
                    panic!("expected all-success batch receipt");
                };
                assert!(retirement.all_acknowledged());
                assert!(retirement
                    .statuses
                    .iter()
                    .all(
                        |(status, expected)| *expected == CommandStatus::Acknowledged
                            && status.snapshot() == CommandStatus::Acknowledged
                    ));
                if retire {
                    service_worker_retirement_event(&replies,&mut events,
                    json!({"method":"Target.detachedFromTarget","params":{"sessionId":"worker-session","targetId":"worker-target"}})).await;
                }
                assert!(retirement
                    .statuses
                    .iter()
                    .all(|(status, expected)| status.snapshot() == *expected));
                assert_eq!(retirement.initialization.is_none(), published, "{scenario}");
                if retire {
                    targets
                        .observe_worker_detach("worker-target", "worker-session")
                        .unwrap();
                    targets.detach("worker-target").unwrap();
                }
                let (operation_cancel, cancellation) = watch::channel(CancelSignal::None);
                let operation = OperationLease {
                    is_callback: false,
                    generation: 1,
                    sequence: 0,
                    deadline,
                    cancellation,
                };
                let (entered_tx, entered_rx) = std::sync::mpsc::channel();
                let mut finisher = None;
                targets.with_worker_retirement_lock_for_test(entered_tx, || {
                    let held_targets = targets.clone();
                    finisher = Some(std::thread::spawn(move || {
                        let result = if retire {
                            view.finish_retired_worker_startup(
                                retirement,
                                &held_targets,
                                &mut permit,
                                &operation,
                                "worker-target",
                                "worker-session",
                            )
                        } else {
                            view.try_finish_acknowledged_worker_startup(
                                retirement,
                                &held_targets,
                                &mut permit,
                                &operation,
                                "worker-target",
                                "worker-session",
                            )
                        };
                        drop(permit);
                        result
                    }));
                    // The real receipt passed its earlier checks and holds owner
                    // plus ledger. The last targets mutex remains owned by us.
                    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    assert!(!finisher.as_ref().unwrap().is_finished());
                    match scenario {
                        "published-cancel" => {
                            operation_cancel.send(CancelSignal::Requested).unwrap();
                        }
                        "bootstrap-cancel" => {
                            bootstrap_cancel.send(CancelSignal::Requested).unwrap();
                        }
                        _ => std::thread::sleep(
                            bootstrap_deadline
                                .min(deadline)
                                .saturating_duration_since(std::time::Instant::now())
                                + Duration::from_millis(5),
                        ),
                    }
                });
                let result = finisher.unwrap().join().unwrap();
                assert_eq!(
                    result.map(|_| ()),
                    Err(if scenario.ends_with("cancel") {
                        ProtocolError::Cancelled
                    } else {
                        ProtocolError::DeadlineExceeded
                    }),
                    "{scenario}"
                );
                assert!(targets.check_settlement_integrity().is_err());
                assert_eq!(ledger.snapshot().outstanding_commands, 0);
                assert!(requests.try_recv().is_err());
                client.close().await;
                peer.await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn service_worker_all_ack_consumer_rejects_owner_replaced_while_waiting() {
        use crate::native::client_session::{CancelSignal, OperationLease};
        use crate::native::client_targets::ClientTargets;
        let (client, mut requests, replies, peer) = service_worker_test_peer().await;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let ledger = OwnerDebtLedger::new(1, "worker-owner".into());
        ledger.bind_context("worker-context").unwrap();
        ledger
            .bind_session("worker-context", "worker-target", "worker-session")
            .unwrap();
        client.install_debt_ledger(ledger.clone()).unwrap();
        let view = client.owner_view(ledger.clone()).unwrap();
        let targets = ClientTargets::new("worker-context".into(), "worker-owner".into());
        targets.bind_eval_owner(&ledger, 1).unwrap();
        targets
            .attached(
                "worker-context",
                "worker-target".into(),
                "worker-session".into(),
                "service_worker".into(),
            )
            .unwrap();
        let mut permit = targets
            .service_worker_startup_permit("worker-target", "worker-session")
            .await
            .unwrap();
        let (startup, sent) =
            service_worker_retirement_batch(view.clone(), &mut requests, deadline).await;
        for request in &sent {
            replies
                .send(service_worker_response(request, false))
                .unwrap();
        }
        let ServiceWorkerStartupOutcome::Ready(Some(receipt)) = startup.await.unwrap().unwrap()
        else {
            panic!("expected all-success receipt");
        };
        assert!(receipt.initialization.is_none());
        let mut events = client.subscribe();
        service_worker_retirement_event(&replies, &mut events,
            json!({"method":"Target.detachedFromTarget","params":{"sessionId":"worker-session","targetId":"worker-target"}})).await;
        assert!(receipt.statuses.iter().all(|(status, expected)| *expected
            == CommandStatus::Acknowledged
            && status.snapshot() == *expected));
        targets
            .observe_worker_detach("worker-target", "worker-session")
            .unwrap();
        targets.detach("worker-target").unwrap();
        let (cancel, cancellation) = watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 0,
            deadline,
            cancellation,
        };
        let replacement = OwnerDebtLedger::new(2, "replacement-owner".into());
        // The consumer cannot pass this actual owner fence until released.
        // Once it holds that guard, owner replacement instead waits for it;
        // the final-target-lock cases separately exercise cancellation there.
        let finisher = {
            let mut owner = client.transport.debt_owner.lock().unwrap();
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let held_targets = targets.clone();
            let finisher = std::thread::spawn(move || {
                entered_tx.send(()).unwrap();
                let result = view.finish_retired_worker_startup(
                    receipt,
                    &held_targets,
                    &mut permit,
                    &operation,
                    "worker-target",
                    "worker-session",
                );
                drop(permit);
                result
            });
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(!finisher.is_finished());
            *owner = Some(replacement.clone());
            finisher
        };
        assert_eq!(
            finisher.join().unwrap().map(|_| ()),
            Err(ProtocolError::StaleScope)
        );
        assert!(targets.check_settlement_integrity().is_err());
        assert_eq!(ledger.snapshot().outstanding_commands, 0);
        assert_eq!(replacement.snapshot().outstanding_commands, 0);
        assert!(!replacement.snapshot().integrity_lost);
        assert!(requests.try_recv().is_err());
        drop(cancel);
        client.close().await;
        peer.await.unwrap();
    }

    async fn worker_startup_reader_publication_case(
        retired: bool,
        detach_during_publication: bool,
        interruption: Option<&str>,
    ) {
        use crate::native::client_session::{CancelSignal, OperationLease};
        use crate::native::client_targets::ClientTargets;
        let (client, mut requests, replies, peer) = service_worker_test_peer().await;
        let deadline = std::time::Instant::now()
            + if interruption == Some("deadline") {
                Duration::from_millis(500)
            } else {
                Duration::from_secs(5)
            };
        let (view, ledger, bootstrap_cancel) = if interruption == Some("bootstrap-cancel") {
            service_worker_test_owner(&client, deadline)
        } else {
            let ledger = OwnerDebtLedger::new(1, "worker-owner".into());
            ledger.bind_context("worker-context").unwrap();
            ledger
                .bind_session("worker-context", "worker-target", "worker-session")
                .unwrap();
            client.install_debt_ledger(ledger.clone()).unwrap();
            let (cancel, _) = watch::channel(CancelSignal::None);
            (client.owner_view(ledger.clone()).unwrap(), ledger, cancel)
        };
        ledger
            .bind_session("worker-context", "other-target", "other-session")
            .unwrap();
        let targets = ClientTargets::new("worker-context".into(), "worker-owner".into());
        targets.bind_eval_owner(&ledger, 1).unwrap();
        targets
            .attached(
                "worker-context",
                "worker-target".into(),
                "worker-session".into(),
                "service_worker".into(),
            )
            .unwrap();
        let mut permit = targets
            .service_worker_startup_permit("worker-target", "worker-session")
            .await
            .unwrap();
        let (startup, sent) =
            service_worker_retirement_batch(view.clone(), &mut requests, deadline).await;
        if retired {
            replies
                .send(service_worker_response(&sent[2], false))
                .unwrap();
            let mut events = client.subscribe();
            service_worker_retirement_event(&replies, &mut events,
                json!({"method":"Target.detachedFromTarget","params":{"sessionId":"worker-session","targetId":"worker-target"}})).await;
        } else {
            for request in &sent {
                replies
                    .send(service_worker_response(request, false))
                    .unwrap();
            }
        }
        let outcome = startup.await.unwrap().unwrap();
        let receipt = match outcome {
            ServiceWorkerStartupOutcome::Ready(Some(receipt)) if !retired => receipt,
            ServiceWorkerStartupOutcome::Retired(receipt) if retired => receipt,
            other => panic!("unexpected startup provenance: {other:?}"),
        };
        assert_eq!(receipt.all_acknowledged(), !retired);
        assert!(ledger
            .capture_eval_revision("other-session", "other-target")
            .is_ok());
        if !retired {
            assert!(ledger
                .capture_eval_revision("worker-session", "worker-target")
                .is_ok());
        }
        let methods: &'static [&'static str] = if detach_during_publication {
            &["Target.detachedFromTarget"]
        } else {
            &["Runtime.executionContextsCleared"]
        };
        let mut events = client.subscribe_bounded_methods(methods, 4, 65536).unwrap();
        let watermark = events.watermark();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_at_deadline = interruption == Some("deadline");
        let held = std::thread::spawn(move || {
            watermark
                .with_received(|received| {
                    entered_tx.send(received).unwrap();
                    if release_at_deadline {
                        assert!(matches!(
                            release_rx.recv_timeout(
                                deadline.saturating_duration_since(std::time::Instant::now())
                            ),
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                        ));
                        assert!(std::time::Instant::now() >= deadline);
                        true
                    } else {
                        release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                        false
                    }
                })
                .unwrap()
        });
        assert_eq!(entered_rx.recv_timeout(Duration::from_secs(2)).unwrap(), 0);
        replies.send(if detach_during_publication {
            json!({"method":"Target.detachedFromTarget","params":{"sessionId":"worker-session","targetId":"worker-target"}})
        } else {
            json!({"method":"Runtime.executionContextsCleared","sessionId":"other-session","params":{}})
        }).unwrap();
        // The only newly injected lifecycle event is observed by the real
        // reader before it blocks on routes. No pending flag or hook is added.
        tokio::time::timeout(Duration::from_secs(2), async {
            while ledger
                .capture_eval_revision("other-session", "other-target")
                .is_ok()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!ledger.snapshot().integrity_lost);
        assert_eq!(ledger.snapshot().outstanding_commands, 0);
        assert!(receipt
            .statuses
            .iter()
            .all(|(status, expected)| status.snapshot() == *expected));
        assert!(!*client.remote_connection_closed().borrow());
        let (cancel, cancellation) = watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 0,
            deadline,
            cancellation,
        };
        let decision = if retired {
            view.finish_retired_worker_startup(
                receipt,
                &targets,
                &mut permit,
                &operation,
                "worker-target",
                "worker-session",
            )
        } else {
            view.try_finish_acknowledged_worker_startup(
                receipt,
                &targets,
                &mut permit,
                &operation,
                "worker-target",
                "worker-session",
            )
        };
        let original_error = decision.as_ref().err().cloned();
        let receipt_retained = matches!(&decision, Ok(WorkerStartupDecision::AwaitPublication(_)));
        let readiness_before_release = targets.check_settlement_integrity();
        assert!(!targets
            .owned_target("worker-target")
            .unwrap()
            .capture_ready());
        let mut release = Some(release_tx);
        let mut wait_error = None;
        let mut after_publication = "not-run";
        if let Ok(WorkerStartupDecision::AwaitPublication(mut receipt)) = decision {
            {
                let waiting = view.wait_worker_startup_publication(&mut receipt, &operation);
                tokio::pin!(waiting);
                assert!(matches!(
                    futures_util::poll!(waiting.as_mut()),
                    std::task::Poll::Pending
                ));
                // The wait is now actually registered while publication is
                // blocked. Completion must notify; an earlier observe is past.
                match interruption {
                    Some("cancel") => {
                        cancel.send_replace(CancelSignal::Requested);
                    }
                    Some("bootstrap-cancel") => {
                        bootstrap_cancel.send_replace(CancelSignal::Requested);
                    }
                    Some("owner") => {
                        *client.transport.debt_owner.lock().unwrap() =
                            Some(OwnerDebtLedger::new(2, "replacement".into()));
                    }
                    Some("integrity") => ledger.connection_lost(),
                    Some("deadline") | None => {}
                    Some(other) => panic!("unknown test interruption {other}"),
                }
                if matches!(interruption, None | Some("owner")) {
                    release.take().unwrap().send(()).unwrap();
                }
                wait_error = waiting.await.err();
            }
            if interruption.is_none() && wait_error.is_none() {
                after_publication = match if retired {
                    view.finish_retired_worker_startup(
                        receipt,
                        &targets,
                        &mut permit,
                        &operation,
                        "worker-target",
                        "worker-session",
                    )
                } else {
                    view.try_finish_acknowledged_worker_startup(
                        receipt,
                        &targets,
                        &mut permit,
                        &operation,
                        "worker-target",
                        "worker-session",
                    )
                } {
                    Ok(WorkerStartupDecision::ReadyCommitted(_)) => "ready",
                    Ok(WorkerStartupDecision::AwaitDetach(_)) => "await-detach",
                    // Low-level tests deliberately do not apply enrollment's
                    // exact detach proof or mutate the targets directly.
                    Err(ProtocolError::StaleScope) if retired => "unapplied-detach-rejected",
                    other => panic!("unexpected post-publication decision {other:?}"),
                };
            }
        }
        if !release_at_deadline {
            if let Some(release) = release.take() {
                release.send(()).unwrap();
            }
        }
        assert_eq!(held.join().unwrap(), release_at_deadline);
        drop(release);
        let event = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.method, methods[0]);
        assert_eq!(ledger.snapshot().outstanding_commands, 0);
        assert!(
            requests.try_recv().is_err(),
            "startup batch must never replay"
        );
        if interruption.is_none() {
            assert!(!ledger.snapshot().integrity_lost);
        }
        assert!(!targets
            .owned_target("worker-target")
            .unwrap()
            .capture_ready());
        drop(permit);
        let capture_ready = targets
            .owned_target("worker-target")
            .map(|target| target.capture_ready());
        drop(cancel);
        drop(bootstrap_cancel);
        client.close().await;
        let peer = peer.await;
        eprintln!("reader-publication retired={retired} detach={detach_during_publication} interruption={interruption:?}: original_error={original_error:?}; receipt_retained={receipt_retained}; readiness_before_release={readiness_before_release:?}; after={after_publication}; wait_error={wait_error:?}; peer={peer:?}");
        assert_eq!(
            original_error, None,
            "healthy reader publication must retain the original startup receipt"
        );
        assert!(receipt_retained);
        // This is pending readiness, not an independent integrity assertion.
        assert_eq!(
            readiness_before_release,
            Err(ProtocolError::ScopeUnavailable)
        );
        match interruption {
            Some("cancel" | "bootstrap-cancel") => {
                assert_eq!(wait_error, Some(ProtocolError::Cancelled))
            }
            Some("deadline") => assert_eq!(wait_error, Some(ProtocolError::DeadlineExceeded)),
            Some("owner" | "integrity") => assert_eq!(wait_error, Some(ProtocolError::StaleScope)),
            None => {
                assert_eq!(wait_error, None);
                assert_eq!(
                    after_publication,
                    if retired {
                        "unapplied-detach-rejected"
                    } else if detach_during_publication {
                        "await-detach"
                    } else {
                        "ready"
                    }
                );
            }
            _ => unreachable!(),
        }
        assert_eq!(
            capture_ready,
            if interruption.is_none() && !retired && !detach_during_publication {
                Ok(true)
            } else {
                Err(ProtocolError::StaleScope)
            }
        );
        peer.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn service_worker_all_ack_reader_publication_retains_startup_receipt() {
        worker_startup_reader_publication_case(false, true, None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn service_worker_other_owned_publication_rechecks_normal_ready() {
        worker_startup_reader_publication_case(false, false, None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn service_worker_retired_reader_publication_retains_original_proof() {
        worker_startup_reader_publication_case(true, false, None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn service_worker_publication_wait_preserves_bounds_and_owner() {
        for retired in [false, true] {
            for interruption in [
                "cancel",
                "bootstrap-cancel",
                "deadline",
                "owner",
                "integrity",
            ] {
                worker_startup_reader_publication_case(retired, false, Some(interruption)).await;
            }
        }
    }

    #[tokio::test]
    async fn service_worker_startup_connection_loss_does_not_prove_worker_retirement() {
        let (client, mut requests, _replies, peer) = service_worker_test_peer().await;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let (view, ledger, _cancel) = service_worker_test_owner(&client, deadline);
        let (startup, _sent) = service_worker_retirement_batch(view, &mut requests, deadline).await;
        assert_eq!(ledger.snapshot().outstanding_commands, 3);
        // Close the actual peer socket, without sending a detach or a reply.
        peer.abort();
        assert!(peer.await.unwrap_err().is_cancelled());
        let error = tokio::time::timeout(Duration::from_secs(2), startup)
            .await
            .expect("reader EOF must wake submitted startup waiters")
            .unwrap()
            .unwrap_err();
        for method in [
            "Network.enable",
            "Runtime.enable",
            "Runtime.runIfWaitingForDebugger",
        ] {
            assert!(
                error.contains(&format!("{method}: CDP response channel closed")),
                "{error}"
            );
        }
        assert_eq!(client.pending_len().await, 0);
        assert!(client
            .transport
            .tracked_responses
            .lock()
            .unwrap()
            .is_empty());
        assert_eq!(ledger.snapshot().outstanding_commands, 3);
        assert!(ledger.snapshot().integrity_lost);
        assert!(requests.try_recv().is_err());
        client.close().await;
    }

    #[tokio::test]
    async fn service_worker_startup_replacement_detach_cannot_settle_original_owner_debt() {
        let (client, mut requests, replies, peer) = service_worker_test_peer().await;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let (view, ledger, _cancel) = service_worker_test_owner(&client, deadline);
        let mut events = client.subscribe();
        let (startup, sent) =
            service_worker_retirement_batch(view.clone(), &mut requests, deadline).await;
        let replacement = OwnerDebtLedger::new(2, "replacement-owner".into());
        replacement.bind_context("replacement-context").unwrap();
        replacement
            .bind_session("replacement-context", "worker-target", "worker-session")
            .unwrap();
        assert!(client.install_debt_ledger(replacement.clone()).is_err());
        // Fault injection only: normal owner adoption above rejects old debt.
        // Model a stale view after transport ownership changes, without editing
        // any ledger or command state. Reused labels cannot confer authority.
        *client.transport.debt_owner.lock().unwrap() = Some(replacement.clone());
        service_worker_retirement_event(
            &replies,
            &mut events,
            json!({"method":"Target.detachedFromTarget",
                "params":{"sessionId":"worker-session","targetId":"worker-target"}}),
        )
        .await;
        let error = tokio::time::timeout(Duration::from_secs(2), startup)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.contains("CDP response channel closed"), "{error}");
        assert_eq!(client.pending_len().await, 0);
        assert_eq!(ledger.snapshot().outstanding_commands, 3);
        assert_eq!(replacement.snapshot().outstanding_commands, 0);
        assert!(!ledger.snapshot().integrity_lost);
        assert!(!replacement.snapshot().integrity_lost);
        assert_eq!(client.transport.tracked_responses.lock().unwrap().len(), 3);
        assert!(view.check_cleanup_owner(&Some(ledger.clone())).is_err());
        let error = view
            .initialize_service_worker_domains("worker-session", json!({}), false, deadline)
            .await
            .unwrap_err();
        assert!(error.contains("Native CDP owner changed"), "{error}");
        assert!(requests.try_recv().is_err());
        // Late replies are correlated to the original SubmittedCommand ledger,
        // not the owner currently installed on the transport.
        for request in &sent {
            replies
                .send(service_worker_response(request, false))
                .unwrap();
        }
        service_worker_retirement_event(
            &replies,
            &mut events,
            json!({"method":"Test.workerLateReplies", "params":{}}),
        )
        .await;
        assert_eq!(ledger.snapshot().outstanding_commands, 0);
        assert_eq!(replacement.snapshot().outstanding_commands, 0);
        assert!(client
            .transport
            .tracked_responses
            .lock()
            .unwrap()
            .is_empty());
        assert!(!ledger.snapshot().integrity_lost);
        assert!(!replacement.snapshot().integrity_lost);
        assert!(requests.try_recv().is_err());
        client.close().await;
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn service_worker_startup_error_ack_is_not_pardoned_by_sibling_detachment() {
        let (client, mut requests, replies, peer) = service_worker_test_peer().await;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let (view, ledger, _cancel) = service_worker_test_owner(&client, deadline);
        let mut events = client.subscribe();
        let (startup, sent) = service_worker_retirement_batch(view, &mut requests, deadline).await;
        replies
            .send(service_worker_response(&sent[1], true))
            .unwrap();
        replies
            .send(service_worker_response(&sent[2], false))
            .unwrap();
        service_worker_retirement_event(
            &replies,
            &mut events,
            json!({"method":"Test.workerErrorAck", "params":{}}),
        )
        .await;
        assert_eq!(client.pending_len().await, 1);
        assert_eq!(ledger.snapshot().outstanding_commands, 1);
        assert!(
            !startup.is_finished(),
            "an error must not abandon a submitted sibling"
        );
        service_worker_retirement_event(
            &replies,
            &mut events,
            json!({"method":"Target.detachedFromTarget",
                "params":{"sessionId":"worker-session","targetId":"worker-target"}}),
        )
        .await;
        let error = tokio::time::timeout(Duration::from_secs(2), startup)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(
            error.contains("Network.enable: CDP response channel closed"),
            "{error}"
        );
        assert!(
            error.contains("Runtime.enable:") && error.contains("observation failed"),
            "{error}"
        );
        assert_eq!(ledger.snapshot().outstanding_commands, 0);
        assert!(!ledger.snapshot().integrity_lost);
        assert_eq!(client.transport.tracked_responses.lock().unwrap().len(), 1);
        // An acknowledged protocol error plus a destroyed sibling also has no
        // debt. Empty debt alone must never classify startup as benign retirement.
        replies
            .send(service_worker_response(&sent[0], false))
            .unwrap();
        service_worker_retirement_event(
            &replies,
            &mut events,
            json!({"method":"Test.workerLateReplies", "params":{}}),
        )
        .await;
        assert!(client
            .transport
            .tracked_responses
            .lock()
            .unwrap()
            .is_empty());
        assert_eq!(ledger.snapshot().outstanding_commands, 0);
        assert!(!ledger.snapshot().integrity_lost);
        assert!(requests.try_recv().is_err());
        client.close().await;
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn navigation_stop_requires_exact_retiring_journal_and_original_writer_deadline() {
        use crate::native::client_debt::OperationKey;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                assert!(!message.is_text(), "expired/unbound cleanup sent CDP");
            }
        });
        let client = CdpClient::connect(&endpoint).await.unwrap();
        let ledger = OwnerDebtLedger::new(1, "owner".into());
        client.install_debt_ledger(ledger.clone()).unwrap();
        let key = OperationKey {
            generation: 1,
            operation_seq: 1,
        };
        let journal = ledger
            .operation(key, "target".into(), "session".into())
            .unwrap();
        let limit = std::time::Instant::now() + Duration::from_secs(1);
        assert!(client
            .stop_retiring_navigation("session", key, limit)
            .await
            .is_err());
        assert!(
            journal
                .scope(client.stop_retiring_navigation("session", key, limit))
                .await
                .is_err(),
            "active application journal is not retirement authority"
        );
        journal.revoke_application_submission();
        assert!(journal
            .scope(client.stop_retiring_navigation(
                "session",
                OperationKey {
                    generation: 1,
                    operation_seq: 2
                },
                limit
            ))
            .await
            .is_err());
        let foreign = OwnerDebtLedger::new(1, "foreign".into());
        let foreign_journal = foreign
            .operation(key, "target".into(), "session".into())
            .unwrap();
        foreign_journal.revoke_application_submission();
        assert!(foreign_journal
            .scope(client.stop_retiring_navigation("session", key, limit))
            .await
            .is_err());
        let writer = client.transport.ws_tx.lock().await;
        let deadline = std::time::Instant::now() + Duration::from_millis(10);
        let mut stop =
            Box::pin(journal.scope(client.stop_retiring_navigation("session", key, deadline)));
        assert!(futures_util::poll!(stop.as_mut()).is_pending());
        assert_eq!(ledger.snapshot().outstanding_commands, 1);
        tokio::time::sleep_until(deadline.into()).await;
        drop(writer);
        assert!(stop.await.is_err());
        assert_eq!(ledger.snapshot().outstanding_commands, 0);
        assert_eq!(
            journal.snapshot().input_debt,
            0,
            "unsent cleanup reservation must be abandoned"
        );
        client.close().await;
        tokio::time::timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn owner_cleanup_rechecks_exact_ledger_and_deadline_after_writer_wait() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut commands = Vec::new();
            while let Some(Ok(message)) = socket.next().await {
                match message {
                    Message::Text(text) => {
                        let request: Value = serde_json::from_str(&text).unwrap();
                        assert_eq!(request["method"], "Target.setAutoAttach");
                        assert_eq!(request["params"]["autoAttach"], false);
                        socket
                            .send(Message::Text(
                                json!({"id":request["id"],"result":{}}).to_string(),
                            ))
                            .await
                            .unwrap();
                        commands.push(text);
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            commands
        });
        let client = CdpClient::connect(&endpoint).await.unwrap();
        let old = OwnerDebtLedger::new(1, "old-owner".into());
        old.bind_context("old-context").unwrap();
        client.install_debt_ledger(old.clone()).unwrap();
        old.retire_after_context_destroy("old-context").unwrap();
        let replacement = OwnerDebtLedger::new(1, "replacement-owner".into());
        replacement.bind_context("replacement-context").unwrap();
        client
            .send_owner_cleanup(
                Some(old.clone()),
                OwnerCleanupCommand::DisableAutoAttach,
                std::time::Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap();
        let writer = client.transport.ws_tx.lock().await;
        let mut cancelled = Box::pin(client.send_owner_cleanup(
            Some(old.clone()),
            OwnerCleanupCommand::CloseBrowser,
            std::time::Instant::now() + Duration::from_secs(2),
        ));
        assert!(futures_util::poll!(cancelled.as_mut()).is_pending());
        assert_eq!(old.snapshot().outstanding_commands, 1);
        assert!(
            client.install_debt_ledger(replacement.clone()).is_err(),
            "in-flight final cleanup must prevent owner replacement"
        );
        drop(cancelled);
        assert_eq!(old.snapshot().outstanding_commands, 0);
        assert!(
            client.install_debt_ledger(replacement.clone()).is_err(),
            "writer ownership is the adoption barrier"
        );
        drop(writer);
        client.install_debt_ledger(replacement.clone()).unwrap();
        assert!(client
            .send_owner_cleanup(
                Some(old.clone()),
                OwnerCleanupCommand::CloseBrowser,
                std::time::Instant::now() + Duration::from_secs(2)
            )
            .await
            .is_err());
        assert!(old
            .reserve_owner_cleanup(OwnerCleanupCommand::DisableAutoAttach)
            .is_err());
        assert!(
            client
                .send_owner_cleanup(
                    None,
                    OwnerCleanupCommand::CloseBrowser,
                    std::time::Instant::now() + Duration::from_secs(2)
                )
                .await
                .is_err(),
            "unbound legacy cleanup cannot act on a concentrated owner"
        );
        replacement
            .retire_after_context_destroy("replacement-context")
            .unwrap();
        let writer = client.transport.ws_tx.lock().await;
        let deadline = std::time::Instant::now() + Duration::from_millis(10);
        let mut expired = Box::pin(client.send_owner_cleanup(
            Some(replacement.clone()),
            OwnerCleanupCommand::DisableAutoAttach,
            deadline,
        ));
        assert!(futures_util::poll!(expired.as_mut()).is_pending());
        tokio::time::sleep_until(deadline.into()).await;
        drop(writer);
        assert!(
            expired.await.is_err(),
            "writer wait must not renew final cleanup deadline"
        );
        assert!(
            client
                .send_owner_cleanup(
                    Some(replacement.clone()),
                    OwnerCleanupCommand::DisableAutoAttach,
                    std::time::Instant::now() + Duration::from_secs(2)
                )
                .await
                .is_err(),
            "expired final cleanup is not renewed"
        );
        let cleanup = replacement
            .reserve_owner_cleanup(OwnerCleanupCommand::CloseBrowser)
            .unwrap();
        assert!(
            client
                .send_reserved_command(
                    "Runtime.evaluate",
                    Some(json!({"expression":"must_not_run()"})),
                    Some("page"),
                    Some(cleanup)
                )
                .await
                .is_err(),
            "generic reserved send broadened a final-cleanup capability"
        );
        client.close().await;
        assert!(
            peer.await.unwrap().len() == 1,
            "only the acknowledged phase-two proof may submit bytes"
        );
    }

    #[test]
    fn eof_error_classifier_rejects_unknown_local_and_timeout_failures() {
        use std::io::ErrorKind;
        use tokio_tungstenite::tungstenite::error::ProtocolError as WebSocketProtocolError;
        use tokio_tungstenite::tungstenite::Error as WebSocketError;
        for kind in [ErrorKind::UnexpectedEof, ErrorKind::ConnectionReset] {
            assert!(is_remote_eof_error(&WebSocketError::Io(
                std::io::Error::from(kind)
            )));
        }
        for kind in [
            ErrorKind::Other,
            ErrorKind::TimedOut,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::InvalidData,
            ErrorKind::WouldBlock,
            ErrorKind::Interrupted,
        ] {
            assert!(!is_remote_eof_error(&WebSocketError::Io(
                std::io::Error::from(kind)
            )));
        }
        assert!(is_remote_eof_error(&WebSocketError::ConnectionClosed));
        assert!(is_remote_eof_error(&WebSocketError::Protocol(
            WebSocketProtocolError::ResetWithoutClosingHandshake
        )));
        assert!(!is_remote_eof_error(&WebSocketError::AlreadyClosed));
    }

    fn borrowed_eof_ledger() -> Arc<OwnerDebtLedger> {
        use super::super::super::client_session::{CancelSignal, OperationLease};
        let (_cancel, cancellation) = watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline: std::time::Instant::now() + Duration::from_secs(30),
            cancellation,
        };
        let ledger = OwnerDebtLedger::unpublished(&operation, "scope".into(), false).unwrap();
        ledger.bind_context("borrowed-context").unwrap();
        ledger
            .bind_session("borrowed-context", "target", "page")
            .unwrap();
        ledger
            .allow_initialization_script("inert authorization")
            .unwrap();
        ledger
    }

    #[tokio::test]
    async fn remote_connection_loss_is_distinct_from_local_close() {
        for remote in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let (release, released) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                if remote {
                    released.await.unwrap();
                    socket
                        .send(Message::Text(
                            json!({
                                "method":"Target.detachedFromTarget",
                                "params":{"sessionId":"page"}
                            })
                            .to_string(),
                        ))
                        .await
                        .unwrap();
                    socket.close(None).await.unwrap();
                } else {
                    while let Some(message) = socket.next().await {
                        if matches!(message, Ok(Message::Close(_)) | Err(_)) {
                            break;
                        }
                    }
                }
            });
            let client = CdpClient::connect(&url).await.unwrap();
            let ledger = borrowed_eof_ledger();
            client.install_debt_ledger(ledger.clone()).unwrap();
            let mut loss = client.remote_connection_closed();
            let mut events = client
                .subscribe_bounded_methods(&["Target.attachedToTarget"], 4, 65536)
                .unwrap();
            assert!(!*loss.borrow());
            if remote {
                release.send(()).unwrap();
                let end = tokio::time::timeout(Duration::from_secs(2), events.recv())
                    .await
                    .unwrap();
                assert!(matches!(end, Err("control event stream closed")));
                assert!(*loss.borrow(), "terminal classification precedes tap EOF");
                assert!(
                    ledger.check_final_local_eof(1, "scope").is_ok(),
                    "ledger EOF-only classification must also precede tap EOF"
                );
                assert!(ledger.snapshot().integrity_lost);
                assert!(!ledger.replacement_ready());
                assert_eq!(ledger.bound_context().as_deref(), Some("borrowed-context"));
                tokio::time::timeout(Duration::from_secs(2), loss.wait_for(|value| *value))
                    .await
                    .unwrap()
                    .unwrap();
            } else {
                drop(release);
                client.close().await;
                assert!(
                    !*loss.borrow(),
                    "local teardown is not replacement authority"
                );
                assert!(ledger.check_final_local_eof(1, "scope").is_err());
            }
            client.close().await;
            server.await.unwrap();
            assert_eq!(*loss.borrow(), remote);
            assert!(ledger.check_final_local_eof(1, "scope").is_err());
        }
    }

    #[tokio::test]
    async fn reader_eof_cannot_launder_uncorrelated_malformed_frames_or_live_session() {
        for (frame, detach) in [
            (Some(Message::Text("{broken".into())), true),
            (Some(Message::Text(r#"{"method":42}"#.into())), true),
            (
                Some(Message::Text(r#"{"id":999,"result":null}"#.into())),
                true,
            ),
            (Some(Message::Text("{}".into())), true),
            (Some(Message::Binary(vec![0xff])), true),
            (None, false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let (release, released) = oneshot::channel();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                released.await.unwrap();
                if let Some(frame) = frame {
                    socket.send(frame).await.unwrap();
                }
                if detach {
                    socket
                        .send(Message::Text(
                            json!({
                                "method":"Target.detachedFromTarget",
                                "params":{"sessionId":"page"}
                            })
                            .to_string(),
                        ))
                        .await
                        .unwrap();
                }
                socket.close(None).await.unwrap();
            });
            let client = CdpClient::connect(&url).await.unwrap();
            let ledger = borrowed_eof_ledger();
            client.install_debt_ledger(ledger.clone()).unwrap();
            let loss = client.remote_connection_closed();
            let mut events = client
                .subscribe_bounded_methods(&["Target.attachedToTarget"], 4, 65536)
                .unwrap();
            release.send(()).unwrap();
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(2), events.recv())
                    .await
                    .unwrap(),
                Err("control event stream closed")
            ));
            assert!(*loss.borrow());
            assert_eq!(ledger.snapshot().outstanding_commands, 0);
            assert!(ledger.snapshot().integrity_lost);
            assert!(ledger.check_final_local_eof(1, "scope").is_err());
            client.close().await;
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn negotiated_receive_limit_closes_oversized_response_without_reuse() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let request = ws.next().await.unwrap().unwrap().into_text().unwrap();
            let request: Value = serde_json::from_str(&request).unwrap();
            ws.send(Message::Text(
                json!({"id":request["id"],"result":{"data":"x".repeat(4096)}}).to_string(),
            ))
            .await
            .unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(2), ws.next()).await;
        });
        let client = CdpClient::connect_with_headers_and_limit(&url, None, Some(1024))
            .await
            .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            client.send_command_no_params("Browser.getVersion", None),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        assert_eq!(client.pending_len().await, 0);
        assert_eq!(
            client
                .send_command_no_params("Browser.getVersion", None)
                .await
                .unwrap_err(),
            CONNECTION_CLOSED_ERROR
        );
        client.close().await;
        server.await.unwrap();
    }

    fn bounded_fixture(
        capacity: usize,
        max_event_bytes: usize,
    ) -> (BoundedMethodTaps, BoundedMethodEvents) {
        let routes = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let (sender, receiver) = mpsc::channel(capacity);
        let failed = Arc::new(AtomicBool::new(false));
        let received = Arc::new(AtomicU64::new(0));
        routes.lock().unwrap().insert(
            1,
            BoundedMethodRoute {
                methods: &["Fetch.requestPaused"],
                sender,
                received: received.clone(),
                failed: failed.clone(),
                max_event_bytes,
                budget: Arc::new(EventBudget {
                    used: AtomicUsize::new(0),
                    maximum: capacity * max_event_bytes,
                }),
            },
        );
        let events = BoundedMethodEvents {
            receiver,
            received,
            failed,
            routes: routes.clone(),
            id: 1,
        };
        (routes, events)
    }
    fn paused_event() -> CdpEvent {
        CdpEvent {
            method: "Fetch.requestPaused".into(),
            params: json!({"requestId":"synthetic"}),
            session_id: Some("owned".into()),
        }
    }
    #[test]
    fn eval_publication_completion_preserves_exact_route_and_identity_failures() {
        use super::super::super::client_debt::{OperationKey, OwnerDebtLedger};
        for mode in [
            "normal",
            "oversize",
            "budget",
            "full",
            "closed",
            "removed",
            "poisoned",
            "exhausted",
            "unmatched",
            "destroyed-no-route",
            "abandoned-after-publish",
        ] {
            let ledger = OwnerDebtLedger::new(7, "scope".into());
            let _journal = ledger
                .operation(
                    OperationKey {
                        generation: 7,
                        operation_seq: 1,
                    },
                    "target".into(),
                    "page".into(),
                )
                .unwrap();
            let (routes, mut events) = bounded_fixture(1, 100);
            routes.lock().unwrap().get_mut(&1).unwrap().methods = &["Page.frameNavigated"];
            let watermark = events.watermark();
            let event = CdpEvent {
                method: if mode == "destroyed-no-route" {
                    "Target.targetDestroyed"
                } else {
                    "Page.frameNavigated"
                }
                .into(),
                params: json!({"targetId":"target","frame":{"id":"frame","loaderId":"next"}}),
                session_id: Some("page".into()),
            };
            match mode {
                "full" => publish_bounded(&routes, &event, 30),
                "budget" => {
                    routes
                        .lock()
                        .unwrap()
                        .get_mut(&1)
                        .unwrap()
                        .budget
                        .used
                        .store(100, Ordering::SeqCst);
                }
                "closed" => events.receiver.close(),
                "removed" => routes.lock().unwrap().clear(),
                "poisoned" => {
                    let routes = routes.clone();
                    assert!(std::panic::catch_unwind(move || {
                        let _guard = routes.lock().unwrap();
                        panic!("synthetic route poison");
                    })
                    .is_err());
                }
                "exhausted" => events.received.store(u64::MAX, Ordering::SeqCst),
                "unmatched" => {
                    routes.lock().unwrap().get_mut(&1).unwrap().methods = &["Fetch.requestPaused"]
                }
                _ => {}
            }
            let publication = ledger.observe_event_for_publication(&event).unwrap();
            assert!(ledger.capture_eval_revision("page", "target").is_err());
            publish_bounded(&routes, &event, if mode == "oversize" { 101 } else { 30 });
            if mode == "abandoned-after-publish" {
                drop(publication);
                assert!(ledger.capture_eval_revision("page", "target").is_err());
            } else {
                publication.complete();
                if mode == "destroyed-no-route" {
                    assert_eq!(watermark.received(), Ok(0));
                    assert!(
                        ledger.capture_eval_revision("page", "target").is_err(),
                        "missing target identity is not repaired by zero matching subscriptions"
                    );
                } else {
                    assert!(ledger.capture_eval_revision("page", "target").is_ok());
                    if mode == "normal" {
                        assert_eq!(watermark.received(), Ok(1));
                    } else if mode == "unmatched" {
                        assert_eq!(watermark.received(), Ok(0));
                    } else {
                        assert!(
                            watermark.received().is_err(),
                            "completion cannot repair {mode} subscription"
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn exact_tap_watermark_includes_queued_events_and_sequence_survives_recv() {
        let (routes, mut events) = bounded_fixture(4, 100);
        let watermark = events.watermark();
        assert_eq!(watermark.received(), Ok(0));
        publish_bounded(&routes, &paused_event(), 30);
        publish_bounded(&routes, &paused_event(), 30);
        assert_eq!(watermark.received(), Ok(2));
        let first = events.recv().await.unwrap();
        assert_eq!(first.sequence(), 1);
        assert_eq!(watermark.received(), Ok(2));
        assert_eq!(events.recv().await.unwrap().sequence(), 2);
        drop(events);
        assert!(watermark.received().is_err());
        // An old in-flight charge never revives a retired subscription.
        assert_eq!(first.sequence(), 1);
    }
    #[test]
    fn exact_tap_watermark_fails_on_overflow_disconnect_and_counter_exhaustion() {
        for mode in 0..3 {
            let (routes, events) = bounded_fixture(1, 100);
            let watermark = events.watermark();
            match mode {
                0 => {
                    publish_bounded(&routes, &paused_event(), 30);
                    publish_bounded(&routes, &paused_event(), 30);
                }
                1 => routes.lock().unwrap().clear(),
                _ => {
                    events.received.store(u64::MAX, Ordering::SeqCst);
                    publish_bounded(&routes, &paused_event(), 30);
                }
            }
            assert!(watermark.received().is_err());
        }
    }
    #[test]
    fn exact_tap_watermark_rejects_same_id_replaced_subscription() {
        let (routes, events) = bounded_fixture(1, 100);
        let watermark = events.watermark();
        routes.lock().unwrap().get_mut(&1).unwrap().received = Arc::new(AtomicU64::new(0));
        assert!(watermark.received().is_err());
    }
    #[test]
    fn exact_tap_publication_fence_retains_reader_admission_lock() {
        let (routes, events) = bounded_fixture(2, 100);
        let watermark = events.watermark();
        publish_bounded(&routes, &paused_event(), 30);
        watermark
            .with_received(|received| {
                assert_eq!(received, 1);
                assert!(
                    routes.try_lock().is_err(),
                    "reader admission must remain fenced through publish"
                );
            })
            .unwrap();
        publish_bounded(&routes, &paused_event(), 30);
        assert_eq!(watermark.received(), Ok(2));
        drop(events);
        let mut published = false;
        assert!(watermark.with_received(|_| published = true).is_err());
        assert!(!published);
    }
    #[tokio::test]
    async fn terminal_receipt_count_requires_closed_empty_exact_receiver_without_overflow() {
        let (routes, mut events) = bounded_fixture(2, 100);
        let live = events.watermark();
        assert!(events.terminal_received().is_err());
        publish_bounded(&routes, &paused_event(), 30);
        assert!(events.terminal_received().is_err());
        routes.lock().unwrap().clear();
        assert!(
            live.received().is_err(),
            "live watermark must remain revoked"
        );
        assert!(
            events.terminal_received().is_err(),
            "queued event is not applied proof"
        );
        assert_eq!(events.recv().await.unwrap().sequence(), 1);
        assert_eq!(
            events.recv().await.unwrap_err(),
            "control event stream closed"
        );
        assert_eq!(events.terminal_received(), Ok(1));

        let (routes, mut overflowed) = bounded_fixture(1, 100);
        publish_bounded(&routes, &paused_event(), 30);
        publish_bounded(&routes, &paused_event(), 30);
        assert!(overflowed.terminal_received().is_err());
        while overflowed.receiver.try_recv().is_ok() {}
        assert!(overflowed.receiver.is_closed());
        assert!(overflowed.receiver.is_empty());
        assert!(
            overflowed.terminal_received().is_err(),
            "empty overflow is not clean EOF"
        );
    }

    #[tokio::test]
    async fn bounded_control_overflow_never_delivers_partial_history_as_complete() {
        let (routes, mut events) = bounded_fixture(1, 100);
        publish_bounded(&routes, &paused_event(), 50);
        publish_bounded(&routes, &paused_event(), 50);
        assert_eq!(events.recv().await.unwrap_err(), "control event overflow");
        assert!(routes.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn bounded_control_size_limit_and_subscription_drop_are_explicit() {
        let (routes, mut events) = bounded_fixture(1, 100);
        publish_bounded(&routes, &paused_event(), 101);
        assert_eq!(events.recv().await.unwrap_err(), "control event overflow");
        let (routes, events) = bounded_fixture(1, 100);
        drop(events);
        assert!(routes.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn bounded_control_filters_unrelated_events_without_consuming_capacity() {
        let (routes, mut events) = bounded_fixture(1, 100);
        let mut unrelated = paused_event();
        unrelated.method = "Page.frameNavigated".into();
        publish_bounded(&routes, &unrelated, 1000);
        publish_bounded(&routes, &paused_event(), 50);
        assert_eq!(events.recv().await.unwrap().method, "Fetch.requestPaused");
    }

    #[tokio::test]
    async fn bounded_event_budget_remains_charged_after_receive_and_lease_clone() {
        let (routes, mut events) = bounded_fixture(4, 100);
        let budget = Arc::new(EventBudget {
            used: AtomicUsize::new(0),
            maximum: 100,
        });
        routes.lock().unwrap().get_mut(&1).unwrap().budget = budget.clone();
        publish_bounded(&routes, &paused_event(), 60);
        let event = events.recv().await.unwrap();
        let lease = event.budget_lease();
        drop(event);
        assert_eq!(budget.used.load(Ordering::Acquire), 60);
        publish_bounded(&routes, &paused_event(), 60);
        assert_eq!(events.recv().await.unwrap_err(), "control event overflow");
        drop(lease);
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
    }
    #[tokio::test]
    async fn bounded_event_budget_reclaims_released_events_and_accepts_large_original_body() {
        let (routes, mut events) = bounded_fixture(4, 2 * 1024 * 1024);
        let budget = Arc::new(EventBudget {
            used: AtomicUsize::new(0),
            maximum: 2 * 1024 * 1024,
        });
        routes.lock().unwrap().get_mut(&1).unwrap().budget = budget.clone();
        let mut original = paused_event();
        original.params["request"] = json!({"postData":"x".repeat(1536*1024)});
        for _ in 0..3 {
            publish_bounded(&routes, &original, 1600 * 1024);
            let event = events.recv().await.unwrap();
            assert_eq!(
                event.params["request"]["postData"].as_str().unwrap().len(),
                1536 * 1024
            );
            assert_eq!(budget.used.load(Ordering::Acquire), 1600 * 1024);
            drop(event);
            assert_eq!(budget.used.load(Ordering::Acquire), 0);
        }
    }

    const TEST_CERT_DER: &str = "MIIBPDCB46ADAgECAgkA9xwXmIhbzQIwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgzMDA1NTU0NFoXDTM2MDgyNzA1NTU0NFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQdmPO0sXXFRmVn7+8MViXGom2rYy8aV3Oc0pNZhUmFGaPl4MRFzc1G0yaV/WRBPF/BUh2LGsXCvUsn7NqaYkFaMeMBwwGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49BAMCA0gAMEUCIQC32oureGNAupABEmonQPAQBD7OdJjXmUxoVQNr0UB+6AIgb23GMwxTjwHyLG4tZcJST7r3cCW8K/Y+1h618j2f+Uw=";
    const TEST_KEY_DER: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIVZST8Vhc5f3OW+4kF78f8o1nQCRwjW/Yo8CXQ35Y9uhRANCAARB2Y87SxdcVGZWfv7wxWJcaibatjLxpXc5zSk1mFSYUZo+XgxEXNzUbTJpX9ZEE8X8FSHYsaxcK9Syfs2ppiQV";

    #[test]
    fn repairs_only_unpaired_surrogate_escapes() {
        let msg = r#"{"id":1,"result":{"high":"\ud800","low":"\udfff","pair":"\ud83d\ude00","escaped":"\\ud800","text":"café 中文"}}"#;
        let repaired = sanitize_lone_surrogates(msg).expect("lone surrogates should be repaired");
        let parsed: CdpMessage = serde_json::from_str(&repaired).expect("repaired message");
        let result = parsed.result.expect("result");

        assert_eq!(result["high"], "\u{fffd}");
        assert_eq!(result["low"], "\u{fffd}");
        assert_eq!(result["pair"], "😀");
        assert_eq!(result["escaped"], r"\ud800");
        assert_eq!(result["text"], "café 中文");
    }

    #[test]
    fn extracts_only_positive_top_level_command_ids() {
        assert_eq!(
            extract_command_id(r#"{"id":7,"result":{"value":"\ud800"}}"#),
            Some(7)
        );
        assert_eq!(
            extract_command_id(r#"{"result":{"id":42,"value":"\ud800"}}"#),
            None
        );
        assert_eq!(
            extract_command_id(r#"{"id":-1,"result":{"value":"\ud800"}}"#),
            None
        );
        assert_eq!(
            extract_command_id(r#"{"method":"Fetch.requestPaused","params":{"value":"\ud800"}}"#),
            None
        );
        assert_eq!(extract_command_id(r#"{"id":0,"result":{}}"#), None);
    }

    #[tokio::test]
    async fn repairs_response_and_event_then_processes_next_command() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

            let first = ws.next().await.unwrap().unwrap().into_text().unwrap();
            let first_id = serde_json::from_str::<Value>(&first).unwrap()["id"]
                .as_u64()
                .unwrap();
            ws.send(Message::Text(format!(
                r#"{{"id":{first_id},"result":{{"value":"\ud800"}}}}"#
            )))
            .await
            .unwrap();
            ws.send(Message::Text(
                r#"{"method":"Fetch.requestPaused","params":{"requestId":"r1","request":{"url":"https://example.test/\udfff"}},"sessionId":"s1"}"#.to_string(),
            ))
            .await
            .unwrap();

            let second = ws.next().await.unwrap().unwrap().into_text().unwrap();
            let second_id = serde_json::from_str::<Value>(&second).unwrap()["id"]
                .as_u64()
                .unwrap();
            ws.send(Message::Text(
                json!({"id": second_id, "result": {"value": "ok"}}).to_string(),
            ))
            .await
            .unwrap();
        });

        let client = CdpClient::connect(&url).await.unwrap();
        let mut events = client.subscribe();

        let first = tokio::time::timeout(
            Duration::from_secs(1),
            client.send_command_no_params("Accessibility.getFullAXTree", None),
        )
        .await
        .expect("surrogate response should complete")
        .unwrap();
        assert_eq!(first["value"], "\u{fffd}");

        let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("surrogate event should arrive")
            .unwrap();
        assert_eq!(event.method, "Fetch.requestPaused");
        assert_eq!(
            event.params["request"]["url"],
            "https://example.test/\u{fffd}"
        );

        let second = client
            .send_command_no_params("Browser.getVersion", None)
            .await
            .unwrap();
        assert_eq!(second["value"], "ok");

        client.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn detached_waiters_match_only_exact_nonempty_session_not_parent_or_other_events() {
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let mut receivers = Vec::new();
        for (id, session) in [(1, Some("page")), (2, Some("sibling")), (3, None)] {
            let (sender, receiver) = oneshot::channel();
            pending.lock().await.insert(
                id,
                PendingResponse {
                    sender,
                    session: session.map(str::to_owned),
                },
            );
            receivers.push(receiver);
        }
        for (method, params) in [
            ("Target.detachedFromTarget", json!({})),
            ("Target.detachedFromTarget", json!({"sessionId":null})),
            ("Target.detachedFromTarget", json!({"sessionId":""})),
            ("Target.detachedFromTarget", json!({"sessionId":"foreign"})),
            ("Target.targetDestroyed", json!({"sessionId":"page"})),
            (
                "Runtime.executionContextDestroyed",
                json!({"sessionId":"page"}),
            ),
        ] {
            retire_detached_waiters(
                &pending,
                &CdpEvent {
                    method: method.into(),
                    params,
                    session_id: Some("page".into()),
                },
            )
            .await;
            assert_eq!(pending.lock().await.len(), 3);
            assert!(receivers.iter_mut().all(|receiver| matches!(
                receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            )));
        }
        // The envelope is the parent's routing session, not the detached child.
        retire_detached_waiters(
            &pending,
            &CdpEvent {
                method: "Target.detachedFromTarget".into(),
                params: json!({"sessionId":"page"}),
                session_id: Some("sibling".into()),
            },
        )
        .await;
        assert!(matches!(
            receivers[0].try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert!(receivers[1..].iter_mut().all(|receiver| matches!(
            receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        )));
        assert_eq!(pending.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn real_detachment_wakes_held_mutating_evaluation_without_ack_replay_or_erased_mutation()
    {
        use super::super::super::client_debt::{OperationKey, OwnerDebtLedger};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (seen_tx, seen_rx) = oneshot::channel();
        let (detach_tx, detach_rx) = oneshot::channel();
        let (late_tx, late_rx) = oneshot::channel();
        let (late_seen_tx, late_seen_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let request: Value =
                serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
            assert_eq!(request["method"], "Runtime.evaluate");
            assert_eq!(request["sessionId"], "page");
            seen_tx.send(()).unwrap();
            detach_rx.await.unwrap();
            ws.send(Message::Text(
                json!({"method":"Target.detachedFromTarget","params":{"sessionId":"page"}})
                    .to_string(),
            ))
            .await
            .unwrap();
            late_rx.await.unwrap();
            // A late reply still reaches original tracked debt, never its failed caller.
            ws.send(Message::Text(
                json!({"id":request["id"],"sessionId":"page","result":{"result":{"value":7}}})
                    .to_string(),
            ))
            .await
            .unwrap();
            ws.send(Message::Text(
                json!({"method":"Test.lateReplyBarrier","params":{}}).to_string(),
            ))
            .await
            .unwrap();
            late_seen_tx.send(()).unwrap();
            while let Some(Ok(message)) = ws.next().await {
                match message {
                    Message::Close(_) => break,
                    Message::Ping(bytes) => {
                        ws.send(Message::Pong(bytes)).await.unwrap();
                    }
                    Message::Text(_) => panic!("evaluation must never replay"),
                    _ => {}
                }
            }
        });
        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        let ledger = OwnerDebtLedger::new(1, "scope".into());
        client.install_debt_ledger(ledger.clone()).unwrap();
        let journal = ledger
            .operation(
                OperationKey {
                    generation: 1,
                    operation_seq: 1,
                },
                "target".into(),
                "page".into(),
            )
            .unwrap();
        let mut events = client.subscribe();
        let sender = client.clone();
        let task_journal = journal.clone();
        let task = tokio::spawn(async move {
            task_journal.scope(sender.send_command("Runtime.evaluate", Some(json!({"expression":"globalThis.count = (globalThis.count ?? 0) + 1; new Promise(() => {})", "awaitPromise":true,"returnByValue":true})), Some("page"))).await
        });
        seen_rx.await.unwrap();
        assert!(journal.snapshot().mutation_dispatched);
        assert_eq!(client.pending_len().await, 1);
        detach_tx.send(()).unwrap();
        let failure = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("exact detach must wake the pending evaluation, not wait for its 30s timeout")
            .unwrap()
            .unwrap_err();
        assert!(failure.contains("response channel closed"), "{failure}");
        assert!(
            journal.snapshot().mutation_dispatched,
            "destruction is not proof the evaluation never mutated"
        );
        assert_eq!(client.pending_len().await, 0);
        assert_eq!(
            client.transport.tracked_responses.lock().unwrap().len(),
            1,
            "waiter failure must not discard late-reply accounting"
        );
        assert_eq!(
            events.recv().await.unwrap().method,
            "Target.detachedFromTarget"
        );
        late_tx.send(()).unwrap();
        late_seen_rx.await.unwrap();
        assert_eq!(events.recv().await.unwrap().method, "Test.lateReplyBarrier");
        assert!(journal.snapshot().mutation_dispatched);
        assert!(client
            .transport
            .tracked_responses
            .lock()
            .unwrap()
            .is_empty());
        client.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_response_fails_only_its_top_level_pending_command() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

            let first = ws.next().await.unwrap().unwrap().into_text().unwrap();
            let first_id = serde_json::from_str::<Value>(&first).unwrap()["id"]
                .as_u64()
                .unwrap();
            ws.send(Message::Text(format!(
                r#"{{"id":{first_id},"result":{{"value":"\ud800"}},"method":42}}"#
            )))
            .await
            .unwrap();

            let second = ws.next().await.unwrap().unwrap().into_text().unwrap();
            let second_id = serde_json::from_str::<Value>(&second).unwrap()["id"]
                .as_u64()
                .unwrap();
            ws.send(Message::Text(format!(
                r#"{{"result":{{"id":{second_id},"value":"\ud800"}},"method":42}}"#
            )))
            .await
            .unwrap();
            ws.send(Message::Text(
                json!({"id": second_id, "result": {"value": "still-open"}}).to_string(),
            ))
            .await
            .unwrap();
        });

        let client = CdpClient::connect(&url).await.unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            client.send_command_no_params("Broken.response", None),
        )
        .await
        .expect("malformed response should not time out")
        .unwrap_err();
        assert!(error.contains("Malformed CDP response"), "{error}");

        let result = client
            .send_command_no_params("Browser.getVersion", None)
            .await
            .unwrap();
        assert_eq!(result["value"], "still-open");

        client.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn close_releases_pending_and_rejects_all_write_paths() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (command_seen_tx, command_seen_rx) = oneshot::channel();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _ = ws.next().await;
            let _ = command_seen_tx.send(());
            while ws.next().await.is_some() {}
        });

        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        let inspect = client.inspect_handle();
        let command_client = client.clone();
        let command = tokio::spawn(async move {
            command_client
                .send_command_no_params("Never.responds", None)
                .await
        });

        command_seen_rx.await.unwrap();
        assert_eq!(client.pending_len().await, 1);
        client.close().await;

        let command_error = tokio::time::timeout(Duration::from_secs(1), command)
            .await
            .expect("pending command should be released")
            .unwrap()
            .unwrap_err();
        assert_eq!(command_error, "CDP response channel closed");
        assert_eq!(client.pending_len().await, 0);

        assert_eq!(
            client
                .send_command_no_params("Browser.getVersion", None)
                .await
                .unwrap_err(),
            CONNECTION_CLOSED_ERROR
        );
        assert_eq!(
            client
                .send_command_no_wait("Browser.getVersion", None, None)
                .await
                .unwrap_err(),
            CONNECTION_CLOSED_ERROR
        );
        assert_eq!(
            client.send_raw("{}".to_string()).await.unwrap_err(),
            CONNECTION_CLOSED_ERROR
        );
        assert_eq!(
            inspect.send_raw("{}".to_string()).await.unwrap_err(),
            CONNECTION_CLOSED_ERROR
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_close_sends_close_and_forces_tcp_eof_with_inspect_alive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let close = tokio::time::timeout(Duration::from_secs(1), ws.next())
                .await
                .expect("server should receive close")
                .expect("stream should yield close")
                .expect("close frame should parse");
            assert!(matches!(close, Message::Close(_)));

            let mut byte = [0u8; 1];
            let count = tokio::time::timeout(Duration::from_secs(1), ws.get_mut().read(&mut byte))
                .await
                .expect("server should observe TCP shutdown")
                .expect("server TCP read should succeed");
            assert_eq!(count, 0);
        });

        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        let inspect = client.inspect_handle();
        let close_a = {
            let client = client.clone();
            tokio::spawn(async move { client.close().await })
        };
        let close_b = {
            let client = client.clone();
            tokio::spawn(async move { client.close().await })
        };

        tokio::time::timeout(Duration::from_secs(2), async {
            close_a.await.unwrap();
            close_b.await.unwrap();
            client.close().await;
        })
        .await
        .expect("concurrent close should be bounded");

        server.await.unwrap();
        drop(inspect);
    }

    #[tokio::test]
    async fn close_is_bounded_when_the_sink_is_busy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (accepted_tx, accepted_rx) = oneshot::channel();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _ = accepted_tx.send(());
            while ws.next().await.is_some() {}
        });

        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        accepted_rx.await.unwrap();
        let sink_guard = client.transport.ws_tx.lock().await;
        let close_client = client.clone();
        tokio::time::timeout(Duration::from_secs(1), async move {
            close_client.close().await;
        })
        .await
        .expect("close should not wait indefinitely for the sink");
        drop(sink_guard);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rustls_close_forces_underlying_tcp_eof() {
        let certificate = CertificateDer::from(
            base64::engine::general_purpose::STANDARD
                .decode(TEST_CERT_DER)
                .unwrap(),
        );
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            base64::engine::general_purpose::STANDARD
                .decode(TEST_KEY_DER)
                .unwrap(),
        ));
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], key)
                .unwrap(),
        );

        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let connection = rustls::ServerConnection::new(server_config).unwrap();
            let tls = rustls::StreamOwned::new(connection, stream);
            let mut ws = tokio_tungstenite::tungstenite::accept(tls).unwrap();
            assert!(matches!(ws.read().unwrap(), Message::Close(_)));

            let mut byte = [0u8; 1];
            let count = ws
                .get_mut()
                .get_mut()
                .read(&mut byte)
                .expect("server TCP read should succeed");
            assert_eq!(count, 0);
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let request = format!("wss://127.0.0.1:{port}")
            .into_client_request()
            .unwrap();
        let config = WebSocketConfig {
            max_message_size: None,
            max_frame_size: None,
            ..Default::default()
        };
        let client =
            CdpClient::connect_request(request, config, Some(Connector::Rustls(client_config)))
                .await
                .unwrap();

        client.close().await;
        server.join().unwrap();
    }

    #[test]
    fn normalizes_only_root_websocket_queries() {
        assert_eq!(
            normalize_websocket_root_path("wss://browser.example?token=a%2Fb"),
            "wss://browser.example/?token=a%2Fb"
        );
        assert_eq!(
            normalize_websocket_root_path("ws://[::1]:9222?token=test"),
            "ws://[::1]:9222/?token=test"
        );
        assert_eq!(
            normalize_websocket_root_path("wss://user:pass@browser.example?token=test"),
            "wss://user:pass@browser.example/?token=test"
        );
        assert_eq!(
            normalize_websocket_root_path("wss://browser.example?"),
            "wss://browser.example/?"
        );
        assert_eq!(
            normalize_websocket_root_path("wss://browser.example/?token=a%2Fb"),
            "wss://browser.example/?token=a%2Fb"
        );
        assert_eq!(
            normalize_websocket_root_path("wss://browser.example/cdp?token=a%2Fb"),
            "wss://browser.example/cdp?token=a%2Fb"
        );
    }

    #[tokio::test]
    async fn root_websocket_url_with_query_sends_slash_request_target() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (path_tx, path_rx) = oneshot::channel();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut path_tx = Some(path_tx);
            // The upstream callback trait requires its unboxed HTTP error response.
            #[allow(clippy::result_large_err)]
            let _ = tokio_tungstenite::accept_hdr_async(
                stream,
                move |
                    request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                    response: tokio_tungstenite::tungstenite::handshake::server::Response,
                | {
                    if let Some(tx) = path_tx.take() {
                        let path = request
                            .uri()
                            .path_and_query()
                            .map(|value| value.as_str().to_string())
                            .unwrap_or_default();
                        let _ = tx.send(path);
                    }
                    Ok(response)
                },
            )
            .await
            .unwrap();
        });

        let url = format!("ws://127.0.0.1:{}?token=a%2Fb&scope=browser%20test", port);
        let _client = CdpClient::connect(&url).await.unwrap();

        assert_eq!(path_rx.await.unwrap(), "/?token=a%2Fb&scope=browser%20test");
        server.await.unwrap();
    }
    /// Events on a privately subscribed session reach only that receiver;
    /// everything else still reaches broadcast subscribers.
    #[tokio::test]
    async fn private_session_events_bypass_the_broadcast() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (ready_tx, ready_rx) = oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            ready_rx.await.unwrap();
            for (method, session) in [
                ("Page.screencastFrame", Some("S-REC")),
                ("Page.screencastFrame", Some("S-PAGE")),
                ("Target.detachedFromTarget", None),
            ] {
                let mut msg = serde_json::json!({ "method": method, "params": {} });
                if let Some(sid) = session {
                    msg["sessionId"] = serde_json::json!(sid);
                }
                ws.send(Message::Text(msg.to_string())).await.unwrap();
            }
            // Keep the connection open until the client is done reading.
            let _ = ws.next().await;
        });

        let client = CdpClient::connect(&format!("ws://127.0.0.1:{}", port))
            .await
            .unwrap();
        let mut broadcast_rx = client.subscribe();
        let mut private_rx = client.subscribe_session("S-REC");
        ready_tx.send(()).unwrap();

        let wait = std::time::Duration::from_secs(2);
        let first = tokio::time::timeout(wait, broadcast_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.session_id.as_deref(), Some("S-PAGE"));
        let second = tokio::time::timeout(wait, broadcast_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.method, "Target.detachedFromTarget");

        let private = tokio::time::timeout(wait, private_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(private.session_id.as_deref(), Some("S-REC"));
        assert!(
            private_rx.try_recv().is_err(),
            "only S-REC events are routed privately"
        );

        client.unsubscribe_session("S-REC");
        drop(client);
        server.abort();
    }

    #[tokio::test]
    async fn method_tap_keeps_every_event_when_the_broadcast_lags() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            ready_rx.await.unwrap();
            for i in 0..7000 {
                let method = if i % 7 == 0 {
                    "Fetch.requestPaused"
                } else {
                    "Network.dataReceived"
                };
                let msg = serde_json::json!({ "method": method, "params": { "n": i } });
                ws.send(Message::Text(msg.to_string())).await.unwrap();
            }
            let _ = ws.next().await;
        });

        let client = CdpClient::connect(&format!("ws://127.0.0.1:{}", port))
            .await
            .unwrap();
        let mut broadcast_rx = client.subscribe();
        let mut tap = client.subscribe_methods(&["Fetch.requestPaused"]);
        ready_tx.send(()).unwrap();

        let wait = std::time::Duration::from_secs(5);
        for expected in (0..7000).step_by(7) {
            let event = tokio::time::timeout(wait, tap.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(event.method, "Fetch.requestPaused");
            assert_eq!(event.params["n"], expected);
        }
        assert!(matches!(
            broadcast_rx.recv().await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));

        drop(client);
        server.abort();
    }
}
