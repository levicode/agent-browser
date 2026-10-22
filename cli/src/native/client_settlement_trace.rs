//! Acceptance-only, closed-schema diagnostics. No payload or arbitrary strings.
//! The existing runner-owned append file is shared by the real proxy and daemon.
//! Lock contention drops observations, never waits. Missing records are unknown.
use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use serde::Serialize;

use super::client_protocol::{ClientMessage, Effects, ProtocolError, ScopeState};
// Acceptance-only diagnostics: closed phases and native operation sequence only.
// Never serialize requests, IDs, browser values, or error descriptions.
#[cfg(feature = "acceptance-faults")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub(crate) enum SettlementPhase {
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
    pub generation: Option<u64>,
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

fn record_source(source: Source, operation_seq: u64, phase: Phase, mut facts: Facts) {
    let Some(capture) = capture(source) else {
        return;
    };
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

#[cfg(test)]
mod tests {
    use super::*;

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
