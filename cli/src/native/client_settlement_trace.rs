//! Closed-schema diagnostics. No payload or arbitrary strings.
//! Acceptance phases remain opt-in behind their feature. Production cleanup
//! capture has its own explicit environment opt-in and no protocol authority.
//! The existing runner-owned append file is shared by the real proxy and daemon.
//! Lock contention drops observations, never waits. Missing records are unknown.
use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use serde::Serialize;

use super::client_protocol::{ClientMessage, Effects, ProtocolError, ScopeState};
// Acceptance-only diagnostics: closed phases and native operation sequence only.
// Never serialize requests, IDs, browser values, or error descriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub(crate) enum SettlementPhase {
    CleanupStarted,
    CleanupFirstFailure,
    CleanupResult,
    InventorySnapshot,
    TargetAttribution,
    TargetLifecycle,
    TargetInventory,
    TargetInventorySummary,
    TargetObservationLost,
    ScreenshotFirstFailure,
    FrameInventoryRejection,
    ReadonlyPrepareFailure,
    ServiceWorkerAdmission,
    ServiceWorkerCausal,
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
    CaptureLimitReached,
    CaptureStarted,
    ProxyDaemonSpawned,
    PrefaceReturned,
    CopyStarted,
    CopyReturned,
    SocketWriteEntered,
    SocketWriteReturned,
    SocketReadEntered,
    SocketReadReturned,
    InputHalfCloseEntered,
    InputHalfCloseReturned,
    OutputFlushEntered,
    OutputFlushReturned,
    ProxySummary,
    FrameComplete,
    FrameCleanEof,
    FramePartialEof,
    FrameIoError,
    FrameOversize,
    FrameParseRefused,
    FrameDecoded,
    FrameAdmissionRefused,
    FrameSummary,
    DetailLimit,
}

pub(crate) use SettlementPhase as Phase;

const PATH_ENV: &str = "AGENT_BROWSER_ACCEPTANCE_PHASE_FILE";
const CLEANUP_PATH_ENV: &str = "AGENT_BROWSER_CLEANUP_DIAGNOSTIC_FILE";
const MAX_RECORDS: usize = 2048;
const MAX_BYTES: usize = 256 * 1024;
const MAX_RECORD_BYTES: usize = 512;
const SAFE_INTEGER: u64 = (1 << 53) - 1;
const SOCKET_DETAIL_CALLS: u64 = 64;
const FRAME_DETAIL_RECORDS: u64 = 128;
const LIMIT_PHASE: &[u8] = b"\"phase\":\"CaptureLimitReached\"";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Source {
    Native,
    Proxy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Leg {
    ToNative,
    FromNative,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum IoClass {
    Ok,
    Eof,
    Interrupted,
    WouldBlock,
    BrokenPipe,
    ConnectionReset,
    ConnectionAborted,
    NotConnected,
    TimedOut,
    UnexpectedEof,
    WriteZero,
    Other,
}

impl IoClass {
    pub(crate) fn error(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::Interrupted => Self::Interrupted,
            io::ErrorKind::WouldBlock => Self::WouldBlock,
            io::ErrorKind::BrokenPipe => Self::BrokenPipe,
            io::ErrorKind::ConnectionReset => Self::ConnectionReset,
            io::ErrorKind::ConnectionAborted => Self::ConnectionAborted,
            io::ErrorKind::NotConnected => Self::NotConnected,
            io::ErrorKind::TimedOut => Self::TimedOut,
            io::ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            io::ErrorKind::WriteZero => Self::WriteZero,
            _ => Self::Other,
        }
    }
    pub(crate) fn result<T>(result: &io::Result<T>) -> Self {
        result
            .as_ref()
            .map(|_| Self::Ok)
            .unwrap_or_else(Self::error)
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum MessageKind {
    Hello,
    Request,
    Cancel,
    Decision,
    Close,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Facts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sw: Option<sw_causal::Row>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment_ordinal: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_ordinal: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ordinal: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<DiagnosticTargetKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_origin: Option<DiagnosticTargetOrigin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_attachment_ordinal: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_attachment_ordinal: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_stage: Option<DiagnosticTargetStage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_purpose: Option<DiagnosticTargetPurpose>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_classification: Option<DiagnosticTargetClassification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_configured: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_resumed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_sampled: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_observed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_ordinal: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admission_step: Option<WorkerAdmissionStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admission_state: Option<WorkerAdmissionState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiting_for_debugger: Option<WorkerDebuggerWait>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_point: Option<InventoryPoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_observed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_sealed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_integrity_lost: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_reservations: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_unconfigured: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screenshot_stage: Option<ScreenshotStage>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "pass")]
    pub frame_pass: Option<FrameInventoryPass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_mismatch: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservations: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<[u16; 7]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event: Option<InventoryRevisionEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_target: Option<InventoryRevisionTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_phase: Option<ScreenshotCapturePhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_after_failure: Option<InventoryAfterFailure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack: Option<ReadonlyAck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wake_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<ReadonlyWindow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zero_input: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<ReadonlyCleanup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_owner: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_attempt: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_lifecycle: Option<CleanupLifecycle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_component: Option<CleanupComponent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_result: Option<CleanupResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effects: Option<Effects>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_state: Option<ScopeState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daemon_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leg: Option<Leg>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io: Option<IoClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calls: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outstanding: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_kind: Option<MessageKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed_known: Option<bool>,
}

impl Facts {
    fn clamp(&mut self, overflow: &mut bool) {
        for value in [
            &mut self.generation,
            &mut self.attachment_ordinal,
            &mut self.inventory_ordinal,
            &mut self.target_ordinal,
            &mut self.parent_attachment_ordinal,
            &mut self.root_attachment_ordinal,
            &mut self.cleanup_owner,
            &mut self.cleanup_attempt,
            &mut self.length,
            &mut self.total,
            &mut self.calls,
            &mut self.pending_bytes,
            &mut self.frame_bytes,
            &mut self.consumed_bytes,
        ]
        .into_iter()
        .flatten()
        {
            *value = bounded(*value, overflow);
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    schema_version: u8,
    source: Source,
    pid: u32,
    record: u64,
    operation_seq: u64,
    phase: Phase,
    dropped_before: u64,
    emitted_before: u64,
    suppressed_before: u64,
    overflow: bool,
    #[serde(flatten)]
    facts: Facts,
}

#[derive(Default)]
struct Counters {
    attempted: AtomicU64,
    emitted: AtomicU64,
    dropped: AtomicU64,
    suppressed: AtomicU64,
    overflow: AtomicBool,
}

fn bounded(value: u64, overflow: &mut bool) -> u64 {
    *overflow |= value > SAFE_INTEGER;
    value.min(SAFE_INTEGER)
}

// Keep the established atomic API for older supported compilers. Recent Rust
// renamed fetch_update to try_update; switching would raise the compiler floor.
#[allow(deprecated)]
fn increment(value: &AtomicU64, amount: u64, overflow: &AtomicBool) -> u64 {
    value
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
            let sum = old.saturating_add(amount);
            if sum > SAFE_INTEGER {
                overflow.store(true, Ordering::Relaxed);
            }
            Some(sum.min(SAFE_INTEGER))
        })
        .unwrap_or_else(|old| old)
}

struct Capture {
    source: Source,
    sink: Mutex<AppendSink>,
    counters: Counters,
}
static SINK: OnceLock<Option<Capture>> = OnceLock::new();

pub(super) fn initialize() {
    initialize_source(Source::Native);
}
pub(crate) fn initialize_proxy() {
    initialize_source(Source::Proxy);
}

fn initialize_source(source: Source) {
    // Only initialization opens the file. An absent start marker means capture
    // unavailable, never that the process performed no operations.
    let mut created = false;
    let capture = SINK.get_or_init(|| {
        created = true;
        let path = PathBuf::from(std::env::var_os(PATH_ENV)?);
        Some(Capture {
            source,
            sink: Mutex::new(AppendSink::open(&path, MAX_RECORDS, MAX_BYTES).ok()?),
            counters: Counters::default(),
        })
    });
    if created && capture.is_some() {
        record_source(source, 0, Phase::CaptureStarted, Facts::default());
    }
}

fn capture(source: Source) -> Option<&'static Capture> {
    SINK.get()?
        .as_ref()
        .filter(|capture| capture.source == source)
}

pub(super) fn record(operation_seq: u64, phase: Phase, facts: Facts) {
    record_source(Source::Native, operation_seq, phase, facts);
}

pub(crate) fn proxy_record(phase: Phase, facts: Facts) {
    record_source(Source::Proxy, 0, phase, facts);
}

fn record_source(source: Source, operation_seq: u64, phase: Phase, facts: Facts) {
    let Some(capture) = capture(source) else {
        return;
    };
    record_capture(capture, operation_seq, phase, facts);
}

fn record_capture(capture: &Capture, operation_seq: u64, phase: Phase, mut facts: Facts) {
    let source = capture.source;
    let counters = &capture.counters;
    let ordinal = increment(&counters.attempted, 1, &counters.overflow);
    let mut overflow = counters.overflow.load(Ordering::Relaxed);
    let operation_seq = bounded(operation_seq, &mut overflow);
    facts.clamp(&mut overflow);
    if overflow {
        counters.overflow.store(true, Ordering::Relaxed);
    }
    let record = Record {
        schema_version: 2,
        source,
        pid: std::process::id(),
        record: ordinal,
        operation_seq,
        phase,
        dropped_before: 0,
        emitted_before: 0,
        suppressed_before: 0,
        overflow,
        facts,
    };
    emit(&capture.sink, record, counters);
}

// This cell is diagnostic data only: it owns no client, task, native identity,
// resource or authority. Hooks are atomics-only; cleanup never performs file I/O.
// An attempt is activated only by a native lifecycle owner and is never used to
// admit, retry, retire or classify the product result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CleanupLifecycle {
    ScopeEnd,
    Restart,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub(crate) enum CleanupComponent {
    Callback = 1,
    Dialog,
    Interception,
    Script,
    Detach,
    Recording,
    Upload,
    Containment,
    Release,
    Input,
    Download,
    Blob,
    EnrollmentFallback,
    RetainedTaskFallback,
    OwnerFallback,
}
impl CleanupComponent {
    fn from_code(value: u8) -> Option<Self> {
        use CleanupComponent::*;
        [
            Callback,
            Dialog,
            Interception,
            Script,
            Detach,
            Recording,
            Upload,
            Containment,
            Release,
            Input,
            Download,
            Blob,
            EnrollmentFallback,
            RetainedTaskFallback,
            OwnerFallback,
        ]
        .into_iter()
        .find(|component| *component as u8 == value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CleanupResult {
    Passed,
    Failed,
}

static CLEANUP_SINK: OnceLock<Option<Capture>> = OnceLock::new();
static CLEANUP_OWNERS: AtomicU64 = AtomicU64::new(0);
const MAX_CLEANUP_ATTEMPT: u64 = SAFE_INTEGER >> 8;

pub(super) fn initialize_cleanup() {
    let mut created = false;
    let capture = CLEANUP_SINK.get_or_init(|| {
        created = true;
        cleanup_capture(
            std::env::var_os(CLEANUP_PATH_ENV)
                .map(PathBuf::from)
                .as_deref(),
        )
    });
    if created {
        if let Some(capture) = capture {
            record_capture(capture, 0, Phase::CaptureStarted, Facts::default());
        }
    }
}
fn cleanup_capture(path: Option<&Path>) -> Option<Capture> {
    Some(Capture {
        source: Source::Native,
        sink: Mutex::new(AppendSink::open(path?, MAX_RECORDS, MAX_BYTES).ok()?),
        counters: Counters::default(),
    })
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum InventoryPoint {
    RestartBegin,
    RestartReady,
    SettlementRefused,
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct InventorySnapshot {
    pub observed: bool,
    pub sealed: bool,
    pub integrity_lost: bool,
    pub reservations: usize,
    pub unconfigured: usize,
    pub attachments: Option<DiagnosticTargetInventory>,
}

pub(crate) const TARGET_SAMPLE_LIMIT: usize = 16;
pub(crate) const TARGET_ORDINAL_LIMIT: u64 = 65_535;
static TARGET_ORDINALS: AtomicU64 = AtomicU64::new(0);
static ATTACHMENT_ORDINALS: AtomicU64 = AtomicU64::new(0);
static INVENTORY_ORDINALS: AtomicU64 = AtomicU64::new(0);

macro_rules! diagnostic_enum {
    ($name:ident { $first:ident $(, $other:ident)* $(,)? }) => {
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
        #[serde(rename_all = "kebab-case")]
        pub(crate) enum $name { #[default] $first, $($other,)* }
    };
}
diagnostic_enum!(DiagnosticTargetKind {
    Other,
    Page,
    Iframe,
    Worker,
    SharedWorker,
    ServiceWorker,
    Browser,
    BrowserUi,
    Tab,
    Webview,
    BackgroundPage
});
diagnostic_enum!(DiagnosticTargetOrigin {
    Unclassified,
    InitialDiscovery,
    AutoAttach
});
diagnostic_enum!(DiagnosticTargetPurpose {
    Unclassified,
    Application,
    StateBootstrap
});
diagnostic_enum!(DiagnosticTargetClassification {
    PendingReservation,
    UnreservedApplication,
    ReservedApplication,
    ReservedBootstrap,
    ReservationRemainder
});
diagnostic_enum!(DiagnosticTargetStage {
    Registered,
    ConfigureStarted,
    ConfigureAck,
    ConfigureFailed,
    Resumed,
    Detached,
    RestartRetiring,
    PurposeAssigned
});

impl DiagnosticTargetKind {
    pub(crate) fn from_native(kind: &str) -> Self {
        match kind {
            "page" => Self::Page,
            "iframe" => Self::Iframe,
            "worker" => Self::Worker,
            "shared_worker" => Self::SharedWorker,
            "service_worker" => Self::ServiceWorker,
            "browser" => Self::Browser,
            "browser_ui" => Self::BrowserUi,
            "tab" => Self::Tab,
            "webview" => Self::Webview,
            "background_page" => Self::BackgroundPage,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DiagnosticAttachment {
    pub attachment: u64,
    pub target: u64,
    pub generation: u64,
    pub kind: DiagnosticTargetKind,
    pub origin: DiagnosticTargetOrigin,
    pub parent: u64,
    pub root: u64,
    pub stage: DiagnosticTargetStage,
    pub purpose: DiagnosticTargetPurpose,
    pub classification: DiagnosticTargetClassification,
    pub configured: bool,
    pub resumed: bool,
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DiagnosticTargetInventory {
    pub observed: bool,
    pub count: usize,
    pub attachments: [Option<DiagnosticAttachment>; TARGET_SAMPLE_LIMIT],
}
pub(crate) fn next_target_ordinal() -> Option<u64> {
    next_cleanup_ordinal(&TARGET_ORDINALS, TARGET_ORDINAL_LIMIT)
}
pub(crate) fn next_attachment_ordinal() -> Option<u64> {
    next_cleanup_ordinal(&ATTACHMENT_ORDINALS, TARGET_ORDINAL_LIMIT)
}

pub(crate) fn target_observation_lost(generation: u64, sequence: u64) {
    if let Some(capture) = CLEANUP_SINK.get().and_then(Option::as_ref) {
        record_capture(
            capture,
            sequence,
            Phase::TargetObservationLost,
            Facts {
                generation: Some(generation),
                ..Facts::default()
            },
        );
    }
}
pub(crate) fn target_lifecycle(
    generation: u64,
    sequence: u64,
    target: DiagnosticAttachment,
    error: Option<ProtocolError>,
) {
    if let Some(capture) = CLEANUP_SINK.get().and_then(Option::as_ref) {
        target_lifecycle_into(capture, generation, sequence, target, error);
    }
}
fn target_lifecycle_into(
    capture: &Capture,
    generation: u64,
    sequence: u64,
    target: DiagnosticAttachment,
    error: Option<ProtocolError>,
) {
    target_attribution_into(capture, generation, sequence, None, target);
    record_capture(
        capture,
        sequence,
        Phase::TargetLifecycle,
        Facts {
            generation: Some(generation),
            attachment_ordinal: Some(target.attachment),
            target_stage: Some(target.stage),
            target_purpose: Some(target.purpose),
            target_classification: Some(target.classification),
            target_configured: Some(target.configured),
            target_resumed: Some(target.resumed),
            error,
            ..Facts::default()
        },
    );
}
fn target_attribution_into(
    capture: &Capture,
    generation: u64,
    sequence: u64,
    point: Option<InventoryPoint>,
    target: DiagnosticAttachment,
) {
    target_attribution_record(
        capture,
        generation,
        sequence,
        point.map(|point| (point, 0)),
        target,
    );
}
fn target_attribution_record(
    capture: &Capture,
    generation: u64,
    sequence: u64,
    inventory: Option<(InventoryPoint, u64)>,
    target: DiagnosticAttachment,
) {
    record_capture(
        capture,
        sequence,
        Phase::TargetAttribution,
        Facts {
            generation: Some(generation),
            inventory_point: inventory.map(|v| v.0),
            inventory_ordinal: inventory.map(|v| v.1),
            attachment_ordinal: Some(target.attachment),
            target_ordinal: Some(target.target),
            target_kind: Some(target.kind),
            target_origin: Some(target.origin),
            parent_attachment_ordinal: Some(target.parent),
            root_attachment_ordinal: Some(target.root),
            ..Facts::default()
        },
    );
}
// Independent of a cleanup attempt: record the actual refused settlement before
// quarantine mutates the registry. Only bounded facts reach the opt-in sink.
pub(crate) fn inventory_enabled() -> bool {
    CLEANUP_SINK.get().and_then(Option::as_ref).is_some()
}

// Independent of operation and cleanup ownership. These observations never admit,
// resume or retry a target. In particular enter is not a wire-submission receipt.
const MAX_DIAGNOSTIC_WORKERS: u64 = 8;
const MAX_WORKER_RECORDS: u64 = 32;
static DIAGNOSTIC_WORKERS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WorkerAdmissionStep {
    OwnedAttachment,
    AuxiliaryClassification,
    Register,
    Purpose,
    ConfigGate,
    NetworkEnable,
    NetworkBypass,
    FetchEnable,
    RuntimeEnable,
    RecursiveAutoattach,
    Configured,
    ResumePermit,
    ResumeDebugger,
    ConfigurationCommitted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum WorkerAdmissionState {
    Enter,
    Done,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkerDebuggerWait {
    True,
    False,
    Unknown,
}
impl From<Option<bool>> for WorkerDebuggerWait {
    fn from(value: Option<bool>) -> Self {
        match value {
            Some(true) => Self::True,
            Some(false) => Self::False,
            None => Self::Unknown,
        }
    }
}
impl Serialize for WorkerDebuggerWait {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::True => serializer.serialize_bool(true),
            Self::False => serializer.serialize_bool(false),
            Self::Unknown => serializer.serialize_str("unknown"),
        }
    }
}
/// Stack-owned, scalar-only observation of one authorized service-worker attachment.
/// The ordinal is process-local diagnostic data, never a target/session identity.
pub(crate) struct ServiceWorkerAdmission {
    generation: u64,
    ordinal: u8,
    waiting: WorkerDebuggerWait,
    records: AtomicU64,
}
impl ServiceWorkerAdmission {
    pub(crate) fn start(generation: u64, waiting: Option<bool>) -> Option<Self> {
        let capture = CLEANUP_SINK.get().and_then(Option::as_ref)?;
        Self::start_into(capture, &DIAGNOSTIC_WORKERS, generation, waiting)
    }
    fn start_into(
        capture: &Capture,
        workers: &AtomicU64,
        generation: u64,
        waiting: Option<bool>,
    ) -> Option<Self> {
        let ordinal = increment(workers, 1, &capture.counters.overflow);
        if ordinal >= MAX_DIAGNOSTIC_WORKERS {
            Self::limit(capture, ordinal == MAX_DIAGNOSTIC_WORKERS);
            return None;
        }
        let result = Self {
            generation,
            ordinal: (ordinal + 1) as u8,
            waiting: waiting.into(),
            records: AtomicU64::new(0),
        };
        result.record_into(
            capture,
            WorkerAdmissionStep::OwnedAttachment,
            WorkerAdmissionState::Done,
        );
        Some(result)
    }
    fn limit(capture: &Capture, first: bool) {
        increment(&capture.counters.suppressed, 1, &capture.counters.overflow);
        if first {
            record_capture(capture, 0, Phase::CaptureLimitReached, Facts::default());
        }
    }
    fn record_into(
        &self,
        capture: &Capture,
        step: WorkerAdmissionStep,
        state: WorkerAdmissionState,
    ) {
        let ordinal = increment(&self.records, 1, &capture.counters.overflow);
        if ordinal >= MAX_WORKER_RECORDS {
            Self::limit(capture, ordinal == MAX_WORKER_RECORDS);
            return;
        }
        record_capture(
            capture,
            0,
            Phase::ServiceWorkerAdmission,
            Facts {
                generation: Some(self.generation),
                worker_ordinal: Some(self.ordinal),
                admission_step: Some(step),
                admission_state: Some(state),
                waiting_for_debugger: Some(self.waiting),
                ..Facts::default()
            },
        );
    }
    fn record(trace: Option<&Self>, step: WorkerAdmissionStep, state: WorkerAdmissionState) {
        if let (Some(trace), Some(capture)) = (trace, CLEANUP_SINK.get().and_then(Option::as_ref)) {
            trace.record_into(capture, step, state);
        }
    }
    pub(crate) async fn observe<T, E>(
        trace: Option<&Self>,
        step: WorkerAdmissionStep,
        future: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        Self::record(trace, step, WorkerAdmissionState::Enter);
        let result = future.await;
        // For RPC steps only successful completion of the original await is done.
        Self::record(
            trace,
            step,
            if result.is_ok() {
                WorkerAdmissionState::Done
            } else {
                WorkerAdmissionState::Failed
            },
        );
        result
    }
    pub(crate) fn observe_sync<T, E>(
        trace: Option<&Self>,
        step: WorkerAdmissionStep,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        Self::record(trace, step, WorkerAdmissionState::Enter);
        let result = action();
        Self::record(
            trace,
            step,
            if result.is_ok() {
                WorkerAdmissionState::Done
            } else {
                WorkerAdmissionState::Failed
            },
        );
        result
    }
}

/// Closed call-site evidence for optional trace screenshots, not protocol authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ScreenshotStage {
    PrepareScope,
    PreparePermit,
    PreparePolicy,
    PrepareOwner,
    PrepareFence,
    RunScope,
    DebtAdmission,
    UiAdmission,
    PublicationAdmission,
    ProducerReservation,
    InitialFrames,
    FrameInventoryFence,
    ProtectedBarrier,
    AnimationStabilization,
    ProtectedFrames,
    Geometry,
    TraceMetadata,
    Capture,
    Restoration,
    FinalGeometry,
    FinalBarrier,
    FinalFrames,
    FinalViewport,
    BlobPublication,
    Publication,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ScreenshotCapturePhase {
    NotEntered,
    Admission,
    IndependentCoverage,
    SourceProtection,
    RawCapture,
    PostCaptureValidation,
}
/// Comparison with a later, best-effort inventory read. Never the atomic reject snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum InventoryAfterFailure {
    NotSampled,
    Unavailable,
    Unchanged,
    Changed,
}
pub(crate) struct ScreenshotFailure {
    pub stage: ScreenshotStage,
    pub capture_phase: ScreenshotCapturePhase,
    pub inventory_after_failure: InventoryAfterFailure,
    pub error: ProtocolError,
}
pub(crate) fn screenshot_failure(generation: u64, sequence: u64, failure: ScreenshotFailure) {
    if let Some(capture) = CLEANUP_SINK.get().and_then(Option::as_ref) {
        screenshot_failure_into(capture, generation, sequence, failure);
    }
}
fn screenshot_failure_into(
    capture: &Capture,
    generation: u64,
    sequence: u64,
    failure: ScreenshotFailure,
) {
    record_capture(
        capture,
        sequence,
        Phase::ScreenshotFirstFailure,
        Facts {
            generation: Some(generation),
            screenshot_stage: Some(failure.stage),
            capture_phase: Some(failure.capture_phase),
            inventory_after_failure: Some(failure.inventory_after_failure),
            error: Some(failure.error),
            ..Facts::default()
        },
    );
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReadonlyAck {
    None,
    Current,
    Retired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReadonlyWindow {
    NotEntered,
    Entered,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReadonlyCleanup {
    FailureObserved,
    NotObserved,
}
pub(crate) struct ReadonlyPrepareFailure {
    pub entry_us: u64,
    pub ack_us: Option<u64>,
    pub ack: ReadonlyAck,
    pub wake_us: Option<u64>,
    pub fail_us: Option<u64>,
    pub window: ReadonlyWindow,
    pub deadline: bool,
    pub zero_input: bool,
    pub cleanup: ReadonlyCleanup,
    pub error: ProtocolError,
}
pub(crate) fn readonly_prepare_failure(
    generation: u64,
    sequence: u64,
    failure: ReadonlyPrepareFailure,
) {
    if let Some(capture) = CLEANUP_SINK.get().and_then(Option::as_ref) {
        readonly_prepare_failure_into(capture, generation, sequence, failure);
    }
}
fn readonly_prepare_failure_into(
    capture: &Capture,
    generation: u64,
    sequence: u64,
    failure: ReadonlyPrepareFailure,
) {
    record_capture(
        capture,
        sequence,
        Phase::ReadonlyPrepareFailure,
        Facts {
            generation: Some(generation),
            entry_us: Some(failure.entry_us),
            ack_us: failure.ack_us,
            ack: Some(failure.ack),
            wake_us: failure.wake_us,
            fail_us: failure.fail_us,
            window: Some(failure.window),
            deadline: Some(failure.deadline),
            zero_input: Some(failure.zero_input),
            cleanup: Some(failure.cleanup),
            error: Some(failure.error),
            ..Facts::default()
        },
    );
}
// One atomic frame-inventory rejection, emitted only after its screenshot settles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum FrameInventoryPass {
    Initial,
    Protected,
    Final,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum InventoryRevisionEvent {
    Attach,
    Detach,
    Info,
    Navigate,
    SameDocument,
    FrameDetach,
    Unknown,
    None,
}
impl InventoryRevisionEvent {
    pub(crate) fn index(self) -> usize {
        match self {
            Self::Attach => 0,
            Self::Detach => 1,
            Self::Info => 2,
            Self::Navigate => 3,
            Self::SameDocument => 4,
            Self::FrameDetach => 5,
            Self::Unknown | Self::None => 6,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum InventoryRevisionTarget {
    Same,
    Other,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FrameInventoryRejection {
    pub pass: FrameInventoryPass,
    pub sealed: bool,
    pub revision_mismatch: bool,
    pub reservations: bool,
    pub delta: Option<u16>,
    pub events: Option<[u16; 7]>,
    pub exact: bool,
    pub last_event: InventoryRevisionEvent,
    pub last_target: InventoryRevisionTarget,
}
pub(crate) fn frame_inventory_rejection(
    generation: u64,
    sequence: u64,
    failure: FrameInventoryRejection,
) {
    if let Some(capture) = CLEANUP_SINK.get().and_then(Option::as_ref) {
        frame_inventory_rejection_into(capture, generation, sequence, failure);
    }
}
fn frame_inventory_rejection_into(
    capture: &Capture,
    generation: u64,
    sequence: u64,
    failure: FrameInventoryRejection,
) {
    record_capture(
        capture,
        sequence,
        Phase::FrameInventoryRejection,
        Facts {
            generation: Some(generation),
            frame_pass: Some(failure.pass),
            sealed: Some(failure.sealed),
            revision_mismatch: Some(failure.revision_mismatch),
            reservations: Some(failure.reservations),
            delta: failure.delta,
            events: failure.events,
            exact: Some(failure.exact),
            last_event: Some(failure.last_event),
            last_target: Some(failure.last_target),
            ..Facts::default()
        },
    );
}
pub(crate) fn inventory_snapshot(
    generation: u64,
    sequence: u64,
    point: InventoryPoint,
    snapshot: InventorySnapshot,
) {
    if let Some(capture) = CLEANUP_SINK.get().and_then(Option::as_ref) {
        inventory_snapshot_into(capture, generation, sequence, point, snapshot);
    }
}
fn inventory_snapshot_into(
    capture: &Capture,
    generation: u64,
    sequence: u64,
    point: InventoryPoint,
    snapshot: InventorySnapshot,
) {
    let inventory_ordinal = snapshot
        .attachments
        .map(|_| next_cleanup_ordinal(&INVENTORY_ORDINALS, TARGET_ORDINAL_LIMIT).unwrap_or(0));
    record_capture(
        capture,
        sequence,
        Phase::InventorySnapshot,
        Facts {
            generation: Some(generation),
            inventory_ordinal,
            inventory_point: Some(point),
            inventory_observed: Some(
                snapshot.observed && snapshot.reservations <= 8192 && snapshot.unconfigured <= 8192,
            ),
            inventory_sealed: Some(snapshot.sealed),
            inventory_integrity_lost: Some(snapshot.integrity_lost),
            inventory_reservations: Some(snapshot.reservations.min(8192) as u64),
            inventory_unconfigured: Some(snapshot.unconfigured.min(8192) as u64),
            ..Facts::default()
        },
    );
    if let Some(targets) = snapshot.attachments {
        let sampled = targets.attachments.iter().flatten().count();
        record_capture(
            capture,
            sequence,
            Phase::TargetInventorySummary,
            Facts {
                generation: Some(generation),
                inventory_point: Some(point),
                inventory_ordinal,
                target_count: Some(targets.count.min(8192) as u64),
                target_sampled: Some(sampled as u64),
                target_observed: Some(
                    targets.observed
                        && targets.count <= TARGET_SAMPLE_LIMIT
                        && sampled == targets.count,
                ),
                ..Facts::default()
            },
        );
        for target in targets.attachments.into_iter().flatten() {
            target_attribution_record(
                capture,
                generation,
                sequence,
                Some((point, inventory_ordinal.unwrap_or(0))),
                target,
            );
            record_capture(
                capture,
                sequence,
                Phase::TargetInventory,
                Facts {
                    generation: Some(generation),
                    inventory_point: Some(point),
                    inventory_ordinal,
                    attachment_ordinal: Some(target.attachment),
                    target_purpose: Some(target.purpose),
                    target_classification: Some(target.classification),
                    target_configured: Some(target.configured),
                    target_resumed: Some(target.resumed),
                    ..Facts::default()
                },
            );
        }
    }
}
// Exhaustion disables observation instead of aliasing a previous identity.
#[allow(deprecated)]
fn next_cleanup_ordinal(counter: &AtomicU64, limit: u64) -> Option<u64> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
            (old < limit).then(|| old + 1)
        })
        .ok()
        .map(|old| old + 1)
}
pub(crate) struct CleanupDiagnostics {
    generation: u64,
    owner: u64,
    attempts: AtomicU64,
    // attempt in the upper bits, first component in the low byte; one CAS binds
    // the component to its exact attempt even across a later lifecycle boundary.
    active: AtomicU64,
}
impl CleanupDiagnostics {
    pub(crate) fn new(generation: u64) -> Arc<Self> {
        Arc::new(Self {
            generation,
            owner: next_cleanup_ordinal(&CLEANUP_OWNERS, SAFE_INTEGER).unwrap_or(0),
            attempts: AtomicU64::new(0),
            active: AtomicU64::new(0),
        })
    }
    pub(crate) fn begin(
        self: &Arc<Self>,
        lifecycle: CleanupLifecycle,
        sequence: u64,
    ) -> Option<CleanupAttempt> {
        self.begin_enabled(
            lifecycle,
            sequence,
            CLEANUP_SINK.get().is_some_and(Option::is_some),
        )
    }
    fn begin_enabled(
        self: &Arc<Self>,
        lifecycle: CleanupLifecycle,
        sequence: u64,
        enabled: bool,
    ) -> Option<CleanupAttempt> {
        if !enabled || self.owner == 0 {
            return None;
        }
        let ordinal = next_cleanup_ordinal(&self.attempts, MAX_CLEANUP_ATTEMPT)?;
        self.active
            .compare_exchange(0, ordinal << 8, Ordering::Relaxed, Ordering::Relaxed)
            .ok()?;
        Some(CleanupAttempt {
            cell: self.clone(),
            ordinal,
            lifecycle,
            sequence,
        })
    }
    pub(crate) fn observer(self: &Arc<Self>) -> Option<CleanupObserver> {
        let ordinal = self.active.load(Ordering::Relaxed) >> 8;
        (ordinal != 0).then(|| CleanupObserver {
            cell: self.clone(),
            ordinal,
        })
    }
    fn failure_for(&self, ordinal: u64, component: CleanupComponent) {
        let active = self.active.load(Ordering::Relaxed);
        if ordinal != 0 && active >> 8 == ordinal && active & 255 == 0 {
            let _ = self.active.compare_exchange(
                active,
                active | component as u64,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
    }
    #[cfg(test)]
    fn failure(&self, component: CleanupComponent) {
        self.failure_for(self.active.load(Ordering::Relaxed) >> 8, component);
    }
}
#[derive(Clone)]
pub(crate) struct CleanupObserver {
    cell: Arc<CleanupDiagnostics>,
    ordinal: u64,
}
impl CleanupObserver {
    pub(crate) fn failure(&self, component: CleanupComponent) {
        self.cell.failure_for(self.ordinal, component);
    }
    pub(crate) fn observe<T, E>(&self, component: CleanupComponent, result: &Result<T, E>) {
        if result.is_err() {
            self.failure(component);
        }
    }
}
pub(crate) fn observe_cleanup<T, E>(
    observer: &Option<CleanupObserver>,
    component: CleanupComponent,
    result: &Result<T, E>,
) {
    if let Some(observer) = observer {
        observer.observe(component, result);
    }
}
pub(crate) struct CleanupAttempt {
    cell: Arc<CleanupDiagnostics>,
    ordinal: u64,
    lifecycle: CleanupLifecycle,
    sequence: u64,
}
impl CleanupAttempt {
    pub(crate) fn observer(&self) -> CleanupObserver {
        CleanupObserver {
            cell: self.cell.clone(),
            ordinal: self.ordinal,
        }
    }
    // The caller has already settled its cleanup obligations and saved the
    // original product result. Sink failures cannot change either. A hung or
    // killed attempt has no completed snapshot and must remain unknown.
    pub(crate) fn finish<T>(self, result: &Result<T, ProtocolError>) {
        self.finish_into(result, CLEANUP_SINK.get().and_then(Option::as_ref));
    }
    fn finish_into<T>(self, result: &Result<T, ProtocolError>, capture: Option<&Capture>) {
        let state = self.cell.active.swap(0, Ordering::Relaxed);
        if state >> 8 != self.ordinal {
            return;
        }
        let Some(capture) = capture else {
            return;
        };
        let facts = || Facts {
            generation: Some(self.cell.generation),
            cleanup_owner: Some(self.cell.owner),
            cleanup_attempt: Some(self.ordinal),
            cleanup_lifecycle: Some(self.lifecycle),
            ..Facts::default()
        };
        record_capture(capture, self.sequence, Phase::CleanupStarted, facts());
        if let Some(component) = CleanupComponent::from_code((state & 255) as u8) {
            record_capture(
                capture,
                self.sequence,
                Phase::CleanupFirstFailure,
                Facts {
                    cleanup_component: Some(component),
                    ..facts()
                },
            );
        }
        record_capture(
            capture,
            self.sequence,
            Phase::CleanupResult,
            Facts {
                cleanup_result: Some(if result.is_ok() {
                    CleanupResult::Passed
                } else {
                    CleanupResult::Failed
                }),
                error: result.as_ref().err().cloned(),
                ..facts()
            },
        );
    }
}

impl CleanupAttempt {
    fn clear_abandoned(&self, mut state: u64) {
        // At most one same-attempt transition can race us: zero component to
        // first component. Two CAS attempts suffice; never clear a newer run.
        for _ in 0..2 {
            if state >> 8 != self.ordinal {
                return;
            }
            match self
                .cell
                .active
                .compare_exchange(state, 0, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(current) => state = current,
            }
        }
    }
}
impl Drop for CleanupAttempt {
    fn drop(&mut self) {
        // Losing a waiter loses observation only. Retained cleanup is neither
        // cancelled nor prolonged, and an old observer cannot tag a later run.
        self.clear_abandoned(self.cell.active.load(Ordering::Relaxed));
    }
}

fn suppress(source: Source) {
    if let Some(capture) = capture(source) {
        increment(&capture.counters.suppressed, 1, &capture.counters.overflow);
    }
}

fn emit(sink: &Mutex<AppendSink>, mut record: Record, counters: &Counters) {
    let Ok(mut sink) = sink.try_lock() else {
        increment(&counters.dropped, 1, &counters.overflow);
        return;
    };
    record.dropped_before = counters.dropped.load(Ordering::Relaxed);
    record.emitted_before = counters.emitted.load(Ordering::Relaxed);
    record.suppressed_before = counters.suppressed.load(Ordering::Relaxed);
    record.overflow |= counters.overflow.load(Ordering::Relaxed);
    match sink.append(&record) {
        Ok(Appended::Record) => {
            increment(&counters.emitted, 1, &counters.overflow);
        }
        Ok(Appended::Limit) => {
            increment(&counters.emitted, 1, &counters.overflow);
            increment(&counters.dropped, 1, &counters.overflow);
        }
        _ => {
            increment(&counters.dropped, 1, &counters.overflow);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Appended {
    Record,
    Limit,
    Dropped,
}
struct AppendSink {
    file: File,
    max_records: usize,
    max_bytes: usize,
    stopped: bool,
}

impl AppendSink {
    fn open(path: &Path, max_records: usize, max_bytes: usize) -> io::Result<Self> {
        if !path.is_absolute() || !std::fs::symlink_metadata(path)?.is_file() {
            return Err(io::Error::other(
                "capture needs an existing absolute regular file",
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("capture needs a regular file"));
        }
        Ok(Self {
            file,
            max_records,
            max_bytes,
            stopped: false,
        })
    }

    fn append(&mut self, record: &Record) -> io::Result<Appended> {
        if self.stopped {
            return Ok(Appended::Dropped);
        }
        self.file.try_lock().map_err(io::Error::other)?;
        let result = self.append_locked(record);
        let unlocked = self.file.unlock();
        match result {
            Ok(appended) => unlocked.map(|()| appended),
            Err(error) => Err(error),
        }
    }

    fn append_locked(&mut self, record: &Record) -> io::Result<Appended> {
        let mut line = serde_json::to_vec(record).map_err(io::Error::other)?;
        line.push(b'\n');
        if line.len() > MAX_RECORD_BYTES {
            return Ok(Appended::Dropped);
        }
        self.file.seek(SeekFrom::Start(0))?;
        let mut prior = Vec::new();
        Read::by_ref(&mut self.file)
            .take(self.max_bytes as u64 + 1)
            .read_to_end(&mut prior)?;
        if prior.len() > self.max_bytes
            || (!prior.is_empty() && !prior.ends_with(b"\n"))
            || prior
                .windows(LIMIT_PHASE.len())
                .any(|part| part == LIMIT_PHASE)
        {
            self.stopped = true;
            return Ok(Appended::Dropped);
        }
        let count = prior.iter().filter(|byte| **byte == b'\n').count();
        let limited = count.saturating_add(1) >= self.max_records
            || prior
                .len()
                .saturating_add(line.len())
                .saturating_add(MAX_RECORD_BYTES)
                > self.max_bytes;
        if limited {
            let marker = Record {
                schema_version: 2,
                source: record.source,
                pid: record.pid,
                record: record.record,
                operation_seq: 0,
                phase: Phase::CaptureLimitReached,
                dropped_before: record.dropped_before,
                emitted_before: record.emitted_before,
                suppressed_before: record.suppressed_before,
                overflow: record.overflow,
                facts: Facts::default(),
            };
            line = serde_json::to_vec(&marker).map_err(io::Error::other)?;
            line.push(b'\n');
        }
        if count >= self.max_records || prior.len().saturating_add(line.len()) > self.max_bytes {
            self.stopped = true;
            return Ok(Appended::Dropped);
        }
        // Any partial append makes this artifact terminally incomplete. Never
        // repair, truncate, reopen or retry it after a write failure.
        if let Err(error) = self.file.write_all(&line) {
            self.stopped = true;
            return Err(error);
        }
        self.stopped = limited;
        Ok(if limited {
            Appended::Limit
        } else {
            Appended::Record
        })
    }
}

#[derive(Default)]
struct LegCounters {
    calls: AtomicU64,
    total: AtomicU64,
    outstanding: AtomicBool,
    overflow: AtomicBool,
}
static TO_NATIVE: LegCounters = LegCounters {
    calls: AtomicU64::new(0),
    total: AtomicU64::new(0),
    outstanding: AtomicBool::new(false),
    overflow: AtomicBool::new(false),
};
static FROM_NATIVE: LegCounters = LegCounters {
    calls: AtomicU64::new(0),
    total: AtomicU64::new(0),
    outstanding: AtomicBool::new(false),
    overflow: AtomicBool::new(false),
};
impl LegCounters {
    fn entered(&self) -> u64 {
        let ordinal = increment(&self.calls, 1, &self.overflow);
        self.outstanding.store(true, Ordering::Relaxed);
        ordinal
    }
    fn returned(&self, result: &io::Result<usize>) {
        if let Ok(length) = result {
            increment(&self.total, *length as u64, &self.overflow);
        }
        self.outstanding.store(false, Ordering::Relaxed);
    }
}
impl Leg {
    fn counters(self) -> &'static LegCounters {
        match self {
            Self::ToNative => &TO_NATIVE,
            Self::FromNative => &FROM_NATIVE,
        }
    }
}
thread_local! { static ACTIVE_LEG: Cell<Option<Leg>> = const { Cell::new(None) }; }

pub(crate) struct CopyGuard {
    leg: Leg,
    previous: Option<Leg>,
}
impl CopyGuard {
    pub(crate) fn start(leg: Leg) -> Self {
        let previous = ACTIVE_LEG.with(|active| active.replace(Some(leg)));
        proxy_record(Phase::CopyStarted, leg_facts(leg));
        Self { leg, previous }
    }
    pub(crate) fn returned(&self, result: &io::Result<u64>) {
        let mut facts = leg_facts(self.leg);
        facts.io = Some(IoClass::result(result));
        facts.length = result.as_ref().ok().copied();
        proxy_record(Phase::CopyReturned, facts);
    }
}
impl Drop for CopyGuard {
    fn drop(&mut self) {
        ACTIVE_LEG.with(|active| active.set(self.previous));
        proxy_record(Phase::ProxySummary, leg_facts(self.leg));
    }
}

fn leg_facts(leg: Leg) -> Facts {
    let counters = leg.counters();
    if counters.overflow.load(Ordering::Relaxed) {
        if let Some(capture) = capture(Source::Proxy) {
            capture.counters.overflow.store(true, Ordering::Relaxed);
        }
    }
    Facts {
        leg: Some(leg),
        total: Some(counters.total.load(Ordering::Relaxed)),
        calls: Some(counters.calls.load(Ordering::Relaxed)),
        outstanding: Some(counters.outstanding.load(Ordering::Relaxed)),
        ..Default::default()
    }
}

pub(crate) struct SocketCall {
    leg: Leg,
    detailed: bool,
}
pub(crate) fn socket_enter(leg: Leg, length: usize) -> Option<SocketCall> {
    if capture(Source::Proxy).is_none() || ACTIVE_LEG.with(|active| active.get()) != Some(leg) {
        return None;
    }
    let counters = leg.counters();
    let ordinal = counters.entered();
    let detailed = ordinal < SOCKET_DETAIL_CALLS;
    if detailed {
        let mut facts = leg_facts(leg);
        facts.length = Some(length as u64);
        proxy_record(
            match leg {
                Leg::ToNative => Phase::SocketWriteEntered,
                Leg::FromNative => Phase::SocketReadEntered,
            },
            facts,
        );
    } else {
        suppress(Source::Proxy);
        if ordinal == SOCKET_DETAIL_CALLS {
            proxy_record(Phase::DetailLimit, leg_facts(leg));
        }
    }
    Some(SocketCall { leg, detailed })
}

pub(crate) fn socket_return(call: Option<SocketCall>, result: &io::Result<usize>) {
    let Some(call) = call else {
        return;
    };
    let counters = call.leg.counters();
    counters.returned(result);
    if !call.detailed {
        suppress(Source::Proxy);
        return;
    }
    let mut facts = leg_facts(call.leg);
    facts.length = result.as_ref().ok().map(|length| *length as u64);
    facts.io = Some(match (call.leg, result) {
        (Leg::FromNative, Ok(0)) => IoClass::Eof,
        _ => IoClass::result(result),
    });
    proxy_record(
        match call.leg {
            Leg::ToNative => Phase::SocketWriteReturned,
            Leg::FromNative => Phase::SocketReadReturned,
        },
        facts,
    );
}

pub(super) struct FrameTrace {
    consumed: u64,
    pending: u64,
    frames: u64,
    details: u64,
    seed_known: bool,
    overflow: bool,
    #[cfg(test)]
    last_phase: Option<Phase>,
}
impl FrameTrace {
    pub(super) fn new(hello_bytes: Option<usize>) -> Self {
        Self {
            consumed: hello_bytes.unwrap_or(0) as u64,
            pending: 0,
            frames: 0,
            details: 0,
            seed_known: hello_bytes.is_some(),
            overflow: false,
            #[cfg(test)]
            last_phase: None,
        }
    }
    #[cfg(test)]
    pub(super) fn test_state(&self) -> (u64, u64, u64, Option<Phase>) {
        (self.consumed, self.pending, self.frames, self.last_phase)
    }
    pub(super) fn consumed(&mut self, bytes: usize, pending: usize) {
        self.consumed = bounded(
            self.consumed.saturating_add(bytes as u64),
            &mut self.overflow,
        );
        self.pending = bounded(pending as u64, &mut self.overflow);
    }
    fn facts(&self) -> Facts {
        if self.overflow {
            if let Some(capture) = capture(Source::Native) {
                capture.counters.overflow.store(true, Ordering::Relaxed);
            }
        }
        Facts {
            consumed_bytes: Some(self.consumed),
            pending_bytes: Some(self.pending),
            calls: Some(self.frames),
            seed_known: Some(self.seed_known),
            ..Default::default()
        }
    }
    pub(super) fn observe(
        &mut self,
        phase: Phase,
        frame_bytes: Option<usize>,
        io: Option<IoClass>,
    ) {
        if matches!(phase, Phase::FrameComplete) {
            self.frames = bounded(self.frames.saturating_add(1), &mut self.overflow);
        }
        let mut facts = self.facts();
        facts.frame_bytes = frame_bytes.map(|bytes| bytes as u64);
        facts.io = io;
        self.detail(0, phase, facts);
    }
    pub(super) fn message(&mut self, phase: Phase, message: &ClientMessage) {
        let (sequence, facts) = self.message_facts(message);
        self.detail(sequence, phase, facts);
    }
    fn message_facts(&self, message: &ClientMessage) -> (u64, Facts) {
        let (kind, sequence, generation) = match message {
            ClientMessage::Hello { .. } => (MessageKind::Hello, 0, None),
            ClientMessage::Request {
                operation_seq,
                generation,
                ..
            } => (MessageKind::Request, *operation_seq, Some(*generation)),
            ClientMessage::Cancel {
                operation_seq,
                generation,
                ..
            } => (MessageKind::Cancel, *operation_seq, Some(*generation)),
            ClientMessage::Decision { generation, .. } => {
                (MessageKind::Decision, 0, Some(*generation))
            }
            ClientMessage::Close { generation, .. } => (MessageKind::Close, 0, Some(*generation)),
        };
        let mut facts = self.facts();
        facts.message_kind = Some(kind);
        facts.generation = generation;
        (sequence, facts)
    }
    fn detail(&mut self, sequence: u64, phase: Phase, facts: Facts) {
        #[cfg(test)]
        {
            self.last_phase = Some(phase);
        }
        if self.details < FRAME_DETAIL_RECORDS {
            self.details += 1;
            record(sequence, phase, facts);
        } else {
            suppress(Source::Native);
            if self.details == FRAME_DETAIL_RECORDS {
                self.details += 1;
                record(0, Phase::DetailLimit, self.facts());
            }
        }
    }
}
impl Drop for FrameTrace {
    fn drop(&mut self) {
        record(0, Phase::FrameSummary, self.facts());
    }
}

// These original acceptance-phase contracts remain feature-only. Production
// cleanup coverage lives in cleanup_diagnostic_tests below.
#[cfg(all(test, feature = "acceptance-faults"))]
mod tests {
    use super::*;

    #[test]
    fn service_worker_admission_is_closed_process_local_and_bounded() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let capture = cleanup_capture(Some(file.path())).unwrap();
        let workers = AtomicU64::new(0);
        for index in 0..10 {
            let waiting = [Some(true), Some(false), None][index % 3];
            let trace = ServiceWorkerAdmission::start_into(&capture, &workers, 7, waiting);
            assert_eq!(trace.is_some(), index < 8);
        }
        let text = std::fs::read_to_string(file.path()).unwrap();
        let values: Vec<serde_json::Value> = text
            .lines()
            .map(|line| {
                assert!(line.len() < MAX_RECORD_BYTES);
                serde_json::from_str(line).unwrap()
            })
            .collect();
        assert_eq!(values.len(), 9);
        for (index, value) in values[..8].iter().enumerate() {
            assert_eq!(value["phase"], "ServiceWorkerAdmission");
            assert_eq!(value["operationSeq"], 0);
            assert_eq!(value["workerOrdinal"], index + 1);
            assert_eq!(value["generation"], 7);
            assert_eq!(value["admissionStep"], "owned-attachment");
            assert_eq!(value["admissionState"], "done");
            assert_eq!(
                value["waitingForDebugger"],
                [
                    serde_json::json!(true),
                    serde_json::json!(false),
                    serde_json::json!("unknown")
                ][index % 3]
            );
            let keys: Vec<_> = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                keys,
                [
                    "admissionState",
                    "admissionStep",
                    "droppedBefore",
                    "emittedBefore",
                    "generation",
                    "operationSeq",
                    "overflow",
                    "phase",
                    "pid",
                    "record",
                    "schemaVersion",
                    "source",
                    "suppressedBefore",
                    "waitingForDebugger",
                    "workerOrdinal"
                ]
            );
        }
        assert_eq!(values[8]["phase"], "CaptureLimitReached");
        assert_eq!(values[8]["suppressedBefore"], 1);
    }

    #[test]
    fn service_worker_admission_never_exceeds_thirty_two_observations() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let capture = cleanup_capture(Some(file.path())).unwrap();
        let trace =
            ServiceWorkerAdmission::start_into(&capture, &AtomicU64::new(0), 1, None).unwrap();
        for _ in 0..40 {
            trace.record_into(
                &capture,
                WorkerAdmissionStep::NetworkEnable,
                WorkerAdmissionState::Enter,
            );
        }
        let text = std::fs::read_to_string(file.path()).unwrap();
        let values: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            values
                .iter()
                .filter(|value| value["phase"] == "ServiceWorkerAdmission")
                .count(),
            32
        );
        assert_eq!(
            values
                .iter()
                .filter(|value| value["phase"] == "CaptureLimitReached")
                .count(),
            1
        );
        assert!(values.iter().all(|value| value["operationSeq"] == 0));
    }

    #[tokio::test]
    async fn service_worker_observer_preserves_success_failure_and_pending_futures() {
        assert_eq!(
            ServiceWorkerAdmission::observe(None, WorkerAdmissionStep::NetworkEnable, async {
                Ok::<_, u8>(41)
            })
            .await,
            Ok(41)
        );
        assert_eq!(
            ServiceWorkerAdmission::observe(None, WorkerAdmissionStep::FetchEnable, async {
                Err::<u8, _>(42)
            })
            .await,
            Err(42)
        );
        assert_eq!(
            ServiceWorkerAdmission::observe_sync(None, WorkerAdmissionStep::Configured, || Err::<
                u8,
                _,
            >(
                43
            )),
            Err(43)
        );
        let pending = ServiceWorkerAdmission::observe(
            None,
            WorkerAdmissionStep::RuntimeEnable,
            std::future::pending::<Result<(), u8>>(),
        );
        tokio::pin!(pending);
        tokio::select! {
            biased;
            _ = &mut pending => panic!("observer completed an unacknowledged command"),
            _ = std::future::ready(()) => {}
        }
    }

    fn sample(ordinal: u64) -> Record {
        Record {
            schema_version: 2,
            source: Source::Native,
            pid: 7,
            record: ordinal,
            operation_seq: 11,
            phase: Phase::ResultFlushed,
            dropped_before: 0,
            emitted_before: 0,
            suppressed_before: 0,
            overflow: false,
            facts: Facts {
                generation: Some(1),
                effects: Some(Effects::NotDispatched),
                scope_state: Some(ScopeState::Usable),
                error: Some(ProtocolError::DeadlineExceeded),
                accepted: None,
                ..Default::default()
            },
        }
    }

    #[test]
    fn acceptance_phase_schema_contains_only_closed_facts() {
        let value = serde_json::to_value(sample(0)).unwrap();
        let keys: Vec<_> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "droppedBefore",
                "effects",
                "emittedBefore",
                "error",
                "generation",
                "operationSeq",
                "overflow",
                "phase",
                "pid",
                "record",
                "schemaVersion",
                "scopeState",
                "source",
                "suppressedBefore"
            ]
        );
        assert_eq!(value["effects"], "not-dispatched");
        assert_eq!(value["error"], "deadline-exceeded");
        let mut ack = sample(1);
        ack.phase = Phase::CancelRejected;
        ack.facts.effects = None;
        ack.facts.accepted = Some(false);
        ack.facts.error = Some(ProtocolError::OperationMissing);
        let ack = serde_json::to_value(ack).unwrap();
        assert_eq!(ack["accepted"], false);
        assert_eq!(ack["error"], "operation-missing");
        assert!(ack.get("effects").is_none());
    }

    #[test]
    fn acceptance_phase_shared_file_record_bound_is_global_and_marked_once() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut first = AppendSink::open(file.path(), 3, 4096).unwrap();
        let mut second = AppendSink::open(file.path(), 3, 4096).unwrap();
        assert_eq!(first.append(&sample(0)).unwrap(), Appended::Record);
        assert_eq!(second.append(&sample(1)).unwrap(), Appended::Record);
        assert_eq!(first.append(&sample(2)).unwrap(), Appended::Limit);
        assert_eq!(second.append(&sample(3)).unwrap(), Appended::Dropped);
        let contents = std::fs::read_to_string(file.path()).unwrap();
        assert_eq!(contents.lines().count(), 3);
        assert_eq!(contents.matches("CaptureLimitReached").count(), 1);
        for line in contents.lines() {
            serde_json::from_str::<serde_json::Value>(line).unwrap();
        }
    }

    #[test]
    fn acceptance_phase_byte_bound_is_global_and_never_truncates_a_record() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut first = AppendSink::open(file.path(), 100, 1024).unwrap();
        let mut second = AppendSink::open(file.path(), 100, 1024).unwrap();
        let mut reached_limit = false;
        for ordinal in 0..100 {
            let sink = if ordinal % 2 == 0 {
                &mut first
            } else {
                &mut second
            };
            if sink.append(&sample(ordinal)).unwrap() != Appended::Record {
                reached_limit = true;
                break;
            }
        }
        assert!(reached_limit);
        let contents = std::fs::read(file.path()).unwrap();
        assert!(contents.len() <= 1024);
        assert!(contents.ends_with(b"\n"));
        assert_eq!(
            String::from_utf8_lossy(&contents)
                .matches("CaptureLimitReached")
                .count(),
            1
        );
        assert_eq!(second.append(&sample(101)).unwrap(), Appended::Dropped);
        assert_eq!(std::fs::read(file.path()).unwrap(), contents);
    }

    #[test]
    fn acceptance_phase_refuses_unowned_paths_or_incomplete_existing_records() {
        assert!(AppendSink::open(Path::new("relative.jsonl"), MAX_RECORDS, MAX_BYTES).is_err());
        let directory = tempfile::tempdir().unwrap();
        assert!(AppendSink::open(directory.path(), MAX_RECORDS, MAX_BYTES).is_err());
        assert!(AppendSink::open(
            &directory.path().join("missing.jsonl"),
            MAX_RECORDS,
            MAX_BYTES
        )
        .is_err());
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"partial").unwrap();
        let mut sink = AppendSink::open(file.path(), MAX_RECORDS, MAX_BYTES).unwrap();
        assert_eq!(sink.append(&sample(0)).unwrap(), Appended::Dropped);
        assert_eq!(std::fs::read(file.path()).unwrap(), b"partial");
    }

    #[cfg(unix)]
    #[test]
    fn acceptance_phase_refuses_symlink_and_fifo_targets_without_opening_them() {
        use std::os::unix::ffi::OsStrExt;
        let directory = tempfile::tempdir().unwrap();
        let target = tempfile::NamedTempFile::new().unwrap();
        let link = directory.path().join("phase-link");
        std::os::unix::fs::symlink(target.path(), &link).unwrap();
        assert!(AppendSink::open(&link, MAX_RECORDS, MAX_BYTES).is_err());
        let fifo = directory.path().join("phase-fifo");
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // A private test FIFO with no peer would block an ordinary write open.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(AppendSink::open(&fifo, MAX_RECORDS, MAX_BYTES).is_err());
        assert!(std::fs::read(target.path()).unwrap().is_empty());
    }

    #[test]
    fn acceptance_phase_contention_drops_without_waiting_and_marks_next_record() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let sink = Mutex::new(AppendSink::open(file.path(), MAX_RECORDS, MAX_BYTES).unwrap());
        let counters = Counters::default();
        let held = sink.lock().unwrap();
        emit(&sink, sample(0), &counters);
        assert_eq!(counters.dropped.load(Ordering::Relaxed), 1);
        drop(held);
        emit(&sink, sample(1), &counters);
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(file.path()).unwrap()).unwrap();
        assert_eq!(value["record"], 1);
        assert_eq!(value["droppedBefore"], 1);
    }

    #[test]
    fn acceptance_phase_file_lock_and_write_failures_only_drop_capture() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let other = OpenOptions::new()
            .read(true)
            .write(true)
            .open(file.path())
            .unwrap();
        other.lock().unwrap();
        let sink = Mutex::new(AppendSink::open(file.path(), MAX_RECORDS, MAX_BYTES).unwrap());
        let counters = Counters::default();
        emit(&sink, sample(0), &counters);
        assert_eq!(counters.dropped.load(Ordering::Relaxed), 1);
        other.unlock().unwrap();
        let read_only = Mutex::new(AppendSink {
            file: File::open(file.path()).unwrap(),
            max_records: MAX_RECORDS,
            max_bytes: MAX_BYTES,
            stopped: false,
        });
        emit(&read_only, sample(1), &counters);
        assert_eq!(counters.dropped.load(Ordering::Relaxed), 2);
        assert!(std::fs::read(file.path()).unwrap().is_empty());
    }

    #[test]
    fn acceptance_phase_scalar_counters_preserve_short_zero_and_error_results() {
        let counters = LegCounters::default();
        let results = [
            Ok(3),
            Err(io::Error::from(io::ErrorKind::Interrupted)),
            Ok(0),
            Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            Ok(2),
        ];
        for (ordinal, result) in results.iter().enumerate() {
            assert_eq!(counters.entered(), ordinal as u64);
            assert!(counters.outstanding.load(Ordering::Relaxed));
            let before = result.as_ref().map(|n| *n).map_err(|e| e.kind());
            counters.returned(result);
            assert_eq!(result.as_ref().map(|n| *n).map_err(|e| e.kind()), before);
            assert!(!counters.outstanding.load(Ordering::Relaxed));
        }
        assert_eq!(counters.calls.load(Ordering::Relaxed), 5);
        assert_eq!(counters.total.load(Ordering::Relaxed), 5);
        for _ in 0..SOCKET_DETAIL_CALLS {
            counters.entered();
            counters.returned(&Ok(1));
        }
        assert_eq!(
            counters.total.load(Ordering::Relaxed),
            5 + SOCKET_DETAIL_CALLS
        );
        assert_eq!(
            IoClass::result(&Err::<(), _>(io::Error::other(
                "https://secret.invalid/path?token=do-not-serialize"
            ))),
            IoClass::Other
        );
    }

    #[test]
    fn acceptance_phase_saturates_safe_integer_counters_and_facts() {
        let counter = AtomicU64::new(SAFE_INTEGER - 1);
        let overflow = AtomicBool::new(false);
        assert_eq!(increment(&counter, u64::MAX, &overflow), SAFE_INTEGER - 1);
        assert_eq!(counter.load(Ordering::Relaxed), SAFE_INTEGER);
        assert!(overflow.load(Ordering::Relaxed));
        let mut facts = Facts {
            generation: Some(u64::MAX),
            total: Some(u64::MAX),
            ..Default::default()
        };
        let mut clipped = false;
        facts.clamp(&mut clipped);
        assert!(clipped);
        assert_eq!(facts.generation, Some(SAFE_INTEGER));
        assert_eq!(facts.total, Some(SAFE_INTEGER));
    }

    #[test]
    fn acceptance_phase_proxy_and_frame_shapes_are_closed_and_payload_free() {
        let mut record = sample(1);
        record.source = Source::Proxy;
        record.phase = Phase::SocketWriteReturned;
        record.facts = Facts {
            leg: Some(Leg::ToNative),
            io: Some(IoClass::Ok),
            length: Some(3),
            total: Some(7),
            calls: Some(2),
            outstanding: Some(false),
            ..Default::default()
        };
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["source"], "proxy");
        assert_eq!(value["leg"], "to-native");
        assert_eq!(value["io"], "ok");
        assert!(value.get("generation").is_none());
        let mut frame = FrameTrace::new(Some(15));
        frame.consumed(9, 9);
        assert_eq!(frame.test_state(), (24, 9, 0, None));
        frame.consumed(2, 0);
        frame.observe(Phase::FrameComplete, Some(11), None);
        assert_eq!(frame.test_state(), (26, 0, 1, Some(Phase::FrameComplete)));
        for _ in 0..FRAME_DETAIL_RECORDS * 2 {
            frame.observe(Phase::FrameCleanEof, None, None);
        }
        assert_eq!(frame.details, FRAME_DETAIL_RECORDS + 1);
        assert_eq!(frame.facts().consumed_bytes, Some(26));
        assert!(serde_json::to_vec(&record).unwrap().len() < MAX_RECORD_BYTES);
    }

    #[test]
    fn acceptance_phase_largest_summary_and_detail_fit_record_bound() {
        let mut record = sample(SAFE_INTEGER);
        record.pid = u32::MAX;
        record.operation_seq = SAFE_INTEGER;
        record.dropped_before = SAFE_INTEGER;
        record.emitted_before = SAFE_INTEGER;
        record.suppressed_before = SAFE_INTEGER;
        record.overflow = true;
        for facts in [
            Facts {
                leg: Some(Leg::FromNative),
                io: Some(IoClass::ConnectionAborted),
                length: Some(SAFE_INTEGER),
                total: Some(SAFE_INTEGER),
                calls: Some(SAFE_INTEGER),
                outstanding: Some(false),
                ..Default::default()
            },
            Facts {
                generation: Some(SAFE_INTEGER),
                message_kind: Some(MessageKind::Decision),
                consumed_bytes: Some(SAFE_INTEGER),
                pending_bytes: Some(SAFE_INTEGER),
                calls: Some(SAFE_INTEGER),
                seed_known: Some(false),
                ..Default::default()
            },
        ] {
            record.phase = Phase::FrameAdmissionRefused;
            record.facts = facts;
            assert!(serde_json::to_vec(&record).unwrap().len() < MAX_RECORD_BYTES);
        }
    }

    #[test]
    fn acceptance_phase_decoded_message_and_io_error_never_serialize_secrets() {
        let sentinel = "private-token-https://secret.invalid/path-command";
        let trace = FrameTrace::new(Some(123));
        let message = ClientMessage::Request {
            id: sentinel.into(),
            generation: 1,
            operation_seq: 10,
            timeout_ms: 2000,
            callback_token: Some(sentinel.into()),
            command: sentinel.into(),
            args: serde_json::json!({"key": sentinel})
                .as_object()
                .unwrap()
                .clone(),
        };
        let (sequence, facts) = trace.message_facts(&message);
        let mut record = sample(0);
        record.operation_seq = sequence;
        record.phase = Phase::FrameDecoded;
        record.facts = facts;
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains(sentinel));
        assert!(!json.contains("private"));
        assert!(!json.contains("https"));
        assert!(!json.contains("command"));
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["messageKind"], "request");
        assert_eq!(value["operationSeq"], 10);
        assert_eq!(value["generation"], 1);
        record.phase = Phase::FrameIoError;
        record.operation_seq = 0;
        record.facts = trace.facts();
        record.facts.io = Some(IoClass::error(&io::Error::new(
            io::ErrorKind::BrokenPipe,
            sentinel,
        )));
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("broken-pipe"));
        assert!(!json.contains(sentinel));
    }

    #[test]
    fn acceptance_phase_write_failure_stops_without_repair_or_retry() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut sink = AppendSink {
            file: File::open(file.path()).unwrap(),
            max_records: MAX_RECORDS,
            max_bytes: MAX_BYTES,
            stopped: false,
        };
        assert!(sink.append(&sample(0)).is_err());
        assert!(sink.stopped);
        assert_eq!(sink.append(&sample(1)).unwrap(), Appended::Dropped);
        assert!(std::fs::read(file.path()).unwrap().is_empty());
    }
}

#[cfg(test)]
#[path = "client_cleanup_diagnostic_tests.rs"]
mod cleanup_tests;

/// Temporary SW-only evidence. No business state, authorization, payloads or
/// deadlines. Remove this module and its call sites with the diagnostic patch.
pub(crate) mod sw_causal {
    use super::*;
    use std::collections::hash_map::RandomState;
    use std::hash::BuildHasher;
    use std::sync::atomic::AtomicI64;

    const MAX_TRACES: u64 = 8;
    const MAX_TRACE_RECORDS: u64 = 32;
    const MAX_POINTS: u64 = 64;
    static TRACES: AtomicU64 = AtomicU64::new(0);
    static POINTS: AtomicU64 = AtomicU64::new(0);
    static ORDER: AtomicU64 = AtomicU64::new(0);
    static HASHER: OnceLock<RandomState> = OnceLock::new();
    tokio::task_local! { static ACTIVE: Arc<Trace>; }

    #[derive(Clone, Copy)]
    #[repr(u8)]
    pub(crate) enum Stage {
        Initialize = 1,
        Prepare,
        AutoAttach,
        Permit,
        ConfigCommitted,
        Batch,
        Ready,
        Retirement,
    }
    // All fields are closed integers/fixed arrays. h=1 means run-local hash:
    // collisions are NOT excluded, so identity equality is not proof.
    #[derive(Default, Serialize)]
    pub(crate) struct Row {
        o: u64,
        k: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        n: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        g: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        h: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        s: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        t: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        st: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        m: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        so: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ro: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        c: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        f: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        e: Option<[u32; 2]>,
        #[serde(skip_serializing_if = "Option::is_none")]
        v: Option<[u32; 2]>,
        #[serde(skip_serializing_if = "Option::is_none")]
        a: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        b: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        w: Option<[Option<u64>; 3]>,
        #[serde(skip_serializing_if = "Option::is_none")]
        d: Option<u64>,
    }
    #[derive(Default)]
    struct Command {
        used: AtomicBool,
        id: AtomicU64,
        session: AtomicU64,
        submitted: AtomicU64,
        replied: AtomicU64,
        code: AtomicI64,
        flags: AtomicU64,
    }
    pub(crate) struct Trace {
        n: u64,
        records: AtomicU64,
        ended: AtomicBool,
        stage: AtomicU64,
        evaluated: AtomicU64,
        values: AtomicU64,
        gate_order: AtomicU64,
        known: AtomicU64,
        scalars: [AtomicU64; 3],
        commands: [Command; 6],
        cause: AtomicU64,
        decision_read: AtomicU64,
    }
    fn capture() -> Option<&'static Capture> {
        CLEANUP_SINK.get().and_then(Option::as_ref)
    }
    fn order(c: &Capture) -> u64 {
        let previous = ORDER.fetch_add(1, Ordering::Relaxed);
        if previous >= SAFE_INTEGER {
            c.counters.overflow.store(true, Ordering::Relaxed);
            SAFE_INTEGER
        } else {
            previous + 1
        }
    }
    fn hash(value: &str) -> Option<u64> {
        HASHER
            .get()
            .map(|hasher| hasher.hash_one(value) & SAFE_INTEGER)
    }
    pub(crate) fn enabled() -> bool {
        capture().is_some() && TRACES.load(Ordering::Relaxed) != 0
    }
    fn current() -> Option<Arc<Trace>> {
        ACTIVE.try_with(Arc::clone).ok()
    }
    fn split(value: u64) -> [u32; 2] {
        [value as u32, (value >> 32) as u32]
    }
    fn emit_into(c: &Capture, row: Row, error: Option<ProtocolError>) {
        record_capture(
            c,
            0,
            Phase::ServiceWorkerCausal,
            Facts {
                sw: Some(row),
                error,
                ..Facts::default()
            },
        );
    }
    fn limited(c: &Capture) {
        increment(&c.counters.suppressed, 1, &c.counters.overflow);
    }
    impl Trace {
        fn new(n: u64) -> Self {
            Self {
                n,
                records: AtomicU64::new(0),
                ended: AtomicBool::new(false),
                stage: AtomicU64::new(Stage::Initialize as u64),
                evaluated: AtomicU64::new(0),
                values: AtomicU64::new(0),
                gate_order: AtomicU64::new(0),
                decision_read: AtomicU64::new(0),
                cause: AtomicU64::new(0),
                known: AtomicU64::new(0),
                scalars: std::array::from_fn(|_| AtomicU64::new(0)),
                commands: std::array::from_fn(|_| Command::default()),
            }
        }
        fn emit(&self, mut row: Row, error: Option<ProtocolError>) {
            if let Some(c) = capture() {
                self.emit_into(c, &mut row, error);
            }
        }
        fn emit_into(&self, c: &Capture, row: &mut Row, error: Option<ProtocolError>) {
            if self.records.fetch_add(1, Ordering::Relaxed) >= MAX_TRACE_RECORDS {
                limited(c);
                return;
            }
            row.n = Some(self.n);
            emit_into(c, std::mem::take(row), error);
        }
        fn snapshot(&self, c: &Capture, kind: u8) -> Row {
            let known = self.known.load(Ordering::Relaxed);
            Row {
                o: order(c),
                k: kind,
                st: Some(self.stage.load(Ordering::Relaxed) as u8),
                e: Some(split(self.evaluated.load(Ordering::Relaxed))),
                v: Some(split(self.values.load(Ordering::Relaxed))),
                b: (self.cause.load(Ordering::Relaxed) != 0)
                    .then(|| self.cause.load(Ordering::Relaxed)),
                a: (self.gate_order.load(Ordering::Relaxed) != 0)
                    .then(|| self.gate_order.load(Ordering::Relaxed)),
                w: Some(std::array::from_fn(|i| {
                    (known & (1 << i) != 0).then(|| self.scalars[i].load(Ordering::Relaxed))
                })),
                ..Row::default()
            }
        }
        fn summaries(&self, c: &Capture) {
            for (index, command) in self.commands.iter().enumerate() {
                if !command.used.load(Ordering::Relaxed) {
                    continue;
                }
                let f = command.flags.load(Ordering::Acquire);
                let mut row = Row {
                    o: order(c),
                    k: 3,
                    m: Some(index as u8 + 1),
                    id: (f & 1 != 0).then(|| command.id.load(Ordering::Relaxed)),
                    so: (f & 4 != 0).then(|| command.submitted.load(Ordering::Relaxed)),
                    ro: (f & 8 != 0).then(|| command.replied.load(Ordering::Relaxed)),
                    c: (f & 64 != 0).then(|| command.code.load(Ordering::Relaxed)),
                    s: (f & 16384 != 0).then(|| command.session.load(Ordering::Relaxed)),
                    h: Some(1),
                    f: Some(f),
                    ..Row::default()
                };
                self.emit_into(c, &mut row, None);
            }
        }
    }
    pub(crate) fn begin(generation: u64, target: &str, session: &str) -> Option<Arc<Trace>> {
        let c = capture()?;
        HASHER.get_or_init(RandomState::new);
        let n = TRACES.fetch_add(1, Ordering::Relaxed);
        if n >= MAX_TRACES {
            limited(c);
            return None;
        }
        let trace = Arc::new(Trace::new(n + 1));
        trace.emit(
            Row {
                o: order(c),
                k: 1,
                g: Some(generation),
                h: Some(1),
                s: hash(session),
                t: hash(target),
                ..Row::default()
            },
            None,
        );
        Some(trace)
    }
    pub(crate) async fn scope<T>(
        trace: Option<Arc<Trace>>,
        future: impl std::future::Future<Output = T>,
    ) -> T {
        match trace {
            Some(trace) => ACTIVE.scope(trace, future).await,
            None => future.await,
        }
    }
    pub(crate) fn stage(stage: Stage) {
        let _ = ACTIVE.try_with(|t| t.stage.store(stage as u64, Ordering::Relaxed));
    }
    pub(crate) fn result<T>(stage: Stage, result: &Result<T, ProtocolError>) {
        self::stage(stage);
        if let (Some(t), Some(c)) = (current(), capture()) {
            t.emit(
                Row {
                    o: order(c),
                    k: 2,
                    st: Some(stage as u8),
                    f: Some(u64::from(result.is_ok())),
                    ..Row::default()
                },
                result.as_ref().err().cloned(),
            );
        }
    }
    /// In-lock hook: only diagnostic atomics, no sink access, I/O, or lock.
    /// Preserve short circuiting by wrapping only the expression already run.
    pub(crate) fn test(bit: u8, value: bool) -> bool {
        let _ = ACTIVE.try_with(|t| {
            let mask = 1u64 << bit;
            t.evaluated.fetch_or(mask, Ordering::Relaxed);
            if value {
                t.values.fetch_or(mask, Ordering::Relaxed);
            } else {
                t.values.fetch_and(!mask, Ordering::Relaxed);
            }
            if let Some(c) = capture() {
                t.gate_order.store(order(c), Ordering::Relaxed);
            }
        });
        value
    }
    pub(crate) fn scalar(slot: u8, value: u64) {
        let _ = ACTIVE.try_with(|t| {
            if let Some(cell) = t.scalars.get(usize::from(slot)) {
                cell.store(value, Ordering::Relaxed);
                t.known.fetch_or(1 << slot, Ordering::Relaxed);
            }
        });
    }
    /// Closed call-site number for an actual typed ? failure; no formatted text.
    pub(crate) fn checked<T>(
        code: u8,
        result: Result<T, ProtocolError>,
    ) -> Result<T, ProtocolError> {
        if result.is_err() {
            let _ = ACTIVE.try_with(|t| {
                let _ = t.cause.compare_exchange(
                    0,
                    u64::from(code),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            });
        }
        result
    }
    pub(crate) fn reset_gate() {
        let _ = ACTIVE.try_with(|t| {
            t.evaluated.fetch_and((1 << 13) - 1, Ordering::Relaxed);
            t.values.fetch_and((1 << 13) - 1, Ordering::Relaxed);
            t.known.store(0, Ordering::Relaxed);
            t.gate_order.store(0, Ordering::Relaxed);
        });
    }
    /// Called under the ORIGINAL ledger guard, ordered with reader unbinding.
    pub(crate) fn unbound(value: bool) -> bool {
        let _ = ACTIVE.try_with(|t| {
            if let Some(c) = capture() {
                t.decision_read.store(order(c), Ordering::Relaxed);
            }
        });
        value
    }
    pub(crate) fn gate_result<T>(result: &Result<T, ProtocolError>) {
        if let (Some(t), Some(c)) = (current(), capture()) {
            t.emit(t.snapshot(c, 5), result.as_ref().err().cloned());
        }
    }
    // k=4 fixed batch outcome: 1 disqualifying,2 ErrorAck/no receipt,
    // 3 ErrorAck/receipt,4 Ready,5 Retired,6 final failure. No string parsing.
    pub(crate) fn batch(outcome: u8, submitted: usize, expected: usize, flags: u64) {
        if let (Some(t), Some(c)) = (current(), capture()) {
            t.emit(
                Row {
                    o: order(c),
                    k: 4,
                    st: Some(outcome),
                    a: Some(submitted as u64),
                    b: Some(expected as u64),
                    f: Some(flags),
                    d: (t.decision_read.load(Ordering::Relaxed) != 0)
                        .then(|| t.decision_read.load(Ordering::Relaxed)),
                    e: Some(split(t.evaluated.load(Ordering::Relaxed))),
                    v: Some(split(t.values.load(Ordering::Relaxed))),
                    ..Row::default()
                },
                None,
            );
        }
    }
    pub(crate) fn finish(outcome: u8, error: Option<ProtocolError>) {
        if let (Some(t), Some(c)) = (current(), capture()) {
            t.finish_into(c, outcome, error);
        }
    }
    impl Trace {
        fn finish_into(&self, c: &Capture, outcome: u8, error: Option<ProtocolError>) {
            if self.ended.swap(true, Ordering::Relaxed) {
                return;
            }
            self.summaries(c);
            let mut row = self.snapshot(c, 6);
            row.f = Some(u64::from(outcome));
            self.emit_into(c, &mut row, error);
            // Snapshot AFTER prior attempts. Concurrent later work and a missing
            // last marker remain unknown; never add a wait or retry for logging.
            let mut row = Row {
                o: order(c),
                k: 7,
                a: Some(c.counters.attempted.load(Ordering::Relaxed)),
                b: Some(self.records.load(Ordering::Relaxed)),
                ..Row::default()
            };
            self.emit_into(c, &mut row, None);
        }
    }
    pub(crate) struct Point(Row);
    pub(crate) fn mark(
        kind: u8,
        session: Option<&str>,
        target: Option<&str>,
        a: Option<u64>,
        b: Option<u64>,
    ) -> Option<Point> {
        let c = capture()?;
        if !matches!(kind, 20..=26 | 40..=43)
            || (kind == 24 && current().is_none())
            || TRACES.load(Ordering::Relaxed) == 0
        {
            return None;
        }
        if POINTS.fetch_add(1, Ordering::Relaxed) >= MAX_POINTS {
            limited(c);
            return None;
        }
        Some(Point(Row {
            o: order(c),
            k: kind,
            n: current().map(|t| t.n),
            h: Some(1),
            s: session.and_then(hash),
            t: target.and_then(hash),
            a,
            b,
            ..Row::default()
        }))
    }
    pub(crate) fn publish(point: Option<Point>) {
        publish_error(point, None);
    }
    pub(crate) fn publish_error(point: Option<Point>, error: Option<ProtocolError>) {
        if let (Some(Point(row)), Some(c)) = (point, capture()) {
            emit_into(c, row, error);
        }
    }
    pub(crate) fn point(
        kind: u8,
        session: Option<&str>,
        target: Option<&str>,
        a: Option<u64>,
        b: Option<u64>,
    ) {
        publish(mark(kind, session, target, a, b));
    }
    #[derive(Clone)]
    pub(crate) struct CommandToken {
        trace: Arc<Trace>,
        slot: usize,
    }
    pub(crate) fn command(method: &str, session: Option<&str>) -> Option<CommandToken> {
        let trace = current()?;
        let slot = match method {
            "Fetch.enable" => 0,
            "Target.setAutoAttach" => 1,
            "Network.enable" => 2,
            "Network.setBypassServiceWorker" => 3,
            "Runtime.enable" => 4,
            "Runtime.runIfWaitingForDebugger" => 5,
            _ => return None,
        };
        if trace.commands[slot].used.swap(true, Ordering::Relaxed) {
            trace.commands[slot].flags.fetch_or(128, Ordering::Relaxed);
            return None;
        }
        if let Some(session_hash) = session.and_then(hash) {
            trace.commands[slot]
                .session
                .store(session_hash, Ordering::Relaxed);
            trace.commands[slot]
                .flags
                .fetch_or(16384, Ordering::Relaxed);
        }
        Some(CommandToken { trace, slot })
    }
    impl CommandToken {
        pub(crate) fn id(&self, id: u64) {
            let c = &self.trace.commands[self.slot];
            c.id.store(id, Ordering::Relaxed);
            c.flags.fetch_or(1, Ordering::Release);
        }
        pub(crate) fn tracked(&self) {
            self.trace.commands[self.slot]
                .flags
                .fetch_or(2, Ordering::Release);
        }
        pub(crate) fn submitted(&self) {
            if let Some(c) = capture() {
                self.submitted_into(c);
            }
        }
        fn submitted_into(&self, capture: &Capture) {
            let c = &self.trace.commands[self.slot];
            c.submitted.store(order(capture), Ordering::Relaxed);
            c.flags.fetch_or(4, Ordering::Release);
        }
        pub(crate) fn local_failure(&self) {
            self.trace.commands[self.slot]
                .flags
                .fetch_or(256, Ordering::Release);
        }
        pub(crate) fn reply(
            &self,
            valid: bool,
            exact: bool,
            code: Option<i64>,
            error: bool,
            status: Option<u8>,
        ) {
            if let Some(c) = capture() {
                self.reply_into(c, valid, exact, code, error, status);
            }
        }
        fn reply_into(
            &self,
            capture: &Capture,
            valid: bool,
            exact: bool,
            code: Option<i64>,
            error: bool,
            status: Option<u8>,
        ) {
            let c = &self.trace.commands[self.slot];
            c.replied.store(order(capture), Ordering::Relaxed);
            if let Some(code) = code {
                c.code.store(code, Ordering::Relaxed);
            }
            let flags = 8
                | (u64::from(valid) << 4)
                | (u64::from(exact) << 5)
                | (u64::from(code.is_some()) << 6)
                | (u64::from(error) << 9)
                | status.map_or(0, |status| 1024 | (u64::from(status) << 11));
            c.flags.fetch_or(flags, Ordering::Release);
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        fn values(path: &Path) -> Vec<serde_json::Value> {
            std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .map(|line| {
                    assert!(line.len() < MAX_RECORD_BYTES);
                    serde_json::from_str(line).unwrap()
                })
                .collect()
        }
        fn token(trace: &Arc<Trace>, slot: usize, id: u64) -> CommandToken {
            trace.commands[slot].used.store(true, Ordering::Relaxed);
            let token = CommandToken {
                trace: trace.clone(),
                slot,
            };
            token.id(id);
            token.tracked();
            token
        }
        #[test]
        fn sw_causal_success_real_emit_control_and_final_counts() {
            fn send_sync<T: Send + Sync>() {}
            send_sync::<Trace>();
            send_sync::<CommandToken>();
            let file = tempfile::NamedTempFile::new().unwrap();
            let capture = cleanup_capture(Some(file.path())).unwrap();
            let trace = Arc::new(Trace::new(1));
            for slot in 0..6 {
                let token = token(&trace, slot, 100 + slot as u64);
                token.submitted_into(&capture);
                token.reply_into(&capture, true, true, None, false, Some(2));
            }
            trace.finish_into(&capture, 1, None);
            let rows = values(file.path());
            assert_eq!(rows.len(), 8);
            for (i, row) in rows.iter().enumerate() {
                assert_eq!(row["record"], i as u64);
                assert_eq!(row["emittedBefore"], i as u64);
                assert_eq!(row["droppedBefore"], 0);
                assert_eq!(row["suppressedBefore"], 0);
                assert_eq!(row["overflow"], false);
            }
            for (slot, row) in rows.iter().take(6).enumerate() {
                assert_eq!(row["sw"]["id"], 100 + slot as u64);
                assert_eq!(row["sw"]["m"], slot as u64 + 1);
                assert!(row["sw"]["ro"].as_u64().unwrap() > row["sw"]["so"].as_u64().unwrap());
                assert!(row["sw"]["c"].is_null());
            }
            assert_eq!(rows[7]["sw"]["k"], 7);
            assert_eq!(rows[7]["sw"]["a"], 7);
            trace.finish_into(&capture, 3, Some(ProtocolError::BrowserFailure));
            assert_eq!(values(file.path()).len(), 8);
        }
        #[test]
        fn sw_causal_typed_error_retained_through_real_emit_contention() {
            let file = tempfile::NamedTempFile::new().unwrap();
            let capture = cleanup_capture(Some(file.path())).unwrap();
            let trace = Arc::new(Trace::new(1));
            let token = token(&trace, 2, 987);
            token.submitted_into(&capture);
            let held = capture.sink.lock().unwrap();
            token.reply_into(&capture, true, true, Some(-32000), true, Some(2));
            trace.emit_into(
                &capture,
                &mut Row {
                    o: order(&capture),
                    k: 2,
                    ..Row::default()
                },
                None,
            );
            assert_eq!(capture.counters.dropped.load(Ordering::Relaxed), 1);
            drop(held);
            trace.finish_into(&capture, 3, Some(ProtocolError::BrowserFailure));
            let rows = values(file.path());
            assert_eq!(rows.len(), 3);
            assert_eq!(rows[0]["sw"]["id"], 987);
            assert_eq!(rows[0]["sw"]["c"], -32000);
            assert_eq!(rows[0]["droppedBefore"], 1);
            assert_eq!(rows[2]["sw"]["a"], 3);
            assert_eq!(rows[2]["droppedBefore"], 1);
            // A final contended emit is itself missing, not a false all-clear.
            let held = capture.sink.lock().unwrap();
            emit_into(
                &capture,
                Row {
                    o: order(&capture),
                    k: 7,
                    ..Row::default()
                },
                None,
            );
            drop(held);
            assert_eq!(capture.counters.dropped.load(Ordering::Relaxed), 2);
            assert_eq!(values(file.path()).len(), 3);
            emit_into(
                &capture,
                Row {
                    o: order(&capture),
                    k: 7,
                    a: Some(capture.counters.attempted.load(Ordering::Relaxed)),
                    ..Row::default()
                },
                None,
            );
            let rows = values(file.path());
            assert_eq!(rows.last().unwrap()["droppedBefore"], 2);
            assert_eq!(rows.last().unwrap()["sw"]["a"], 5);
        }
        #[tokio::test]
        async fn sw_causal_short_circuit_unknown_and_typed_result_are_preserved() {
            let file = tempfile::NamedTempFile::new().unwrap();
            let capture = cleanup_capture(Some(file.path())).unwrap();
            let trace = Arc::new(Trace::new(1));
            scope(Some(trace.clone()), async {
                assert!(!(test(16, false) && test(17, true)));
                let original: Result<(), ProtocolError> = Err(ProtocolError::Cancelled);
                assert_eq!(checked(32, original.clone()), original);
                let _ = checked(33, Err::<(), _>(ProtocolError::DeadlineExceeded));
                scalar(0, 19);
            })
            .await;
            let row = trace.snapshot(&capture, 5);
            assert_eq!(row.e, Some([1 << 16, 0]));
            assert_eq!(row.v, Some([0, 0]));
            assert_eq!(row.w, Some([Some(19), None, None]));
            assert_eq!(row.b, Some(32));
        }
        #[test]
        fn sw_causal_reply_and_lifecycle_origin_order_is_not_file_order() {
            // Synthetic fact-storage test only, not a browser retirement proof.
            let file = tempfile::NamedTempFile::new().unwrap();
            let capture = cleanup_capture(Some(file.path())).unwrap();
            for detach_first in [false, true] {
                let trace = Arc::new(Trace::new(1));
                let token = token(&trace, 4, 42);
                token.submitted_into(&capture);
                let earlier_detach = detach_first.then(|| order(&capture));
                token.reply_into(&capture, true, true, Some(-32000), true, Some(2));
                let reply = trace.commands[4].replied.load(Ordering::Relaxed);
                let decision = order(&capture);
                let detach = earlier_detach.unwrap_or_else(|| order(&capture));
                // Deliberately emit the later-created summary before lifecycle.
                trace.finish_into(&capture, 3, Some(ProtocolError::BrowserFailure));
                emit_into(
                    &capture,
                    Row {
                        o: detach,
                        k: 40,
                        ..Row::default()
                    },
                    None,
                );
                assert!(reply < decision);
                assert_eq!(detach < decision, detach_first);
            }
            let rows = values(file.path());
            assert!(rows.iter().any(|row| row["sw"]["k"] == 40));
            // targetDestroyed is a distinct closed kind and never exact detach.
            emit_into(
                &capture,
                Row {
                    o: order(&capture),
                    k: 41,
                    ..Row::default()
                },
                None,
            );
            assert_eq!(values(file.path()).last().unwrap()["sw"]["k"], 41);
        }
        #[test]
        fn sw_causal_record_cap_suppression_and_maximum_rows_use_real_emit() {
            let file = tempfile::NamedTempFile::new().unwrap();
            let capture = cleanup_capture(Some(file.path())).unwrap();
            let trace = Trace::new(MAX_TRACES);
            for _ in 0..MAX_TRACE_RECORDS + 1 {
                trace.emit_into(
                    &capture,
                    &mut Row {
                        o: SAFE_INTEGER,
                        k: 5,
                        n: Some(SAFE_INTEGER),
                        st: Some(9),
                        e: Some([u32::MAX; 2]),
                        v: Some([u32::MAX; 2]),
                        a: Some(SAFE_INTEGER),
                        b: Some(255),
                        w: Some([Some(SAFE_INTEGER); 3]),
                        ..Row::default()
                    },
                    Some(ProtocolError::DeadlineExceeded),
                );
            }
            assert_eq!(values(file.path()).len(), MAX_TRACE_RECORDS as usize);
            assert_eq!(capture.counters.suppressed.load(Ordering::Relaxed), 1);
            emit_into(
                &capture,
                Row {
                    o: SAFE_INTEGER,
                    k: 3,
                    m: Some(6),
                    id: Some(u64::MAX),
                    so: Some(SAFE_INTEGER),
                    ro: Some(SAFE_INTEGER),
                    c: Some(i64::MIN),
                    f: Some(32767),
                    s: Some(SAFE_INTEGER),
                    h: Some(1),
                    ..Row::default()
                },
                None,
            );
            let rows = values(file.path());
            assert_eq!(rows.len(), MAX_TRACE_RECORDS as usize + 1);
            assert_eq!(rows.last().unwrap()["suppressedBefore"], 1);
        }
    }
}
