//! Acceptance-only closed-schema capture, independent of daemon stderr.
//! The runner must precreate an empty, absolute regular file and pass its path
//! as AGENT_BROWSER_ACCEPTANCE_PHASE_FILE. No directory creation or truncation.
//! Records are appended immediately: there is no background buffer that can
//! lose the terminal phase at process exit. Contended locks drop, never wait.
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use serde::Serialize;

use super::client_protocol::{Effects, ProtocolError, ScopeState};
use super::client_transport::SettlementPhase;

const PATH_ENV: &str = "AGENT_BROWSER_ACCEPTANCE_PHASE_FILE";
const MAX_RECORDS: usize = 2048;
const MAX_BYTES: usize = 256 * 1024;
const MAX_RECORD_BYTES: usize = 512;
const LIMIT_PHASE: &[u8] = b"\"phase\":\"CaptureLimitReached\"";

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Facts {
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
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    schema_version: u8,
    pid: u32,
    record: u64,
    operation_seq: u64,
    phase: SettlementPhase,
    dropped_before: u64,
    #[serde(flatten)]
    facts: Facts,
}

static SINK: OnceLock<Option<Mutex<AppendSink>>> = OnceLock::new();
static RECORD: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);

// Called once at daemon startup, before accepting protocol operations. Record
// emission never waits for OnceLock initialization or opens an artifact file.
pub(super) fn initialize() {
    SINK.get_or_init(|| {
        let path = PathBuf::from(std::env::var_os(PATH_ENV)?);
        AppendSink::open(&path, MAX_RECORDS, MAX_BYTES)
            .ok()
            .map(Mutex::new)
    });
}

pub(super) fn record(operation_seq: u64, phase: SettlementPhase, facts: Facts) {
    let Some(Some(sink)) = SINK.get() else {
        return;
    };
    let record = Record {
        schema_version: 1,
        pid: std::process::id(),
        record: RECORD.fetch_add(1, Ordering::Relaxed),
        operation_seq,
        phase,
        dropped_before: 0,
        facts,
    };
    emit(sink, record, &DROPPED);
}

fn emit(sink: &Mutex<AppendSink>, mut record: Record, dropped: &AtomicU64) {
    let Ok(mut sink) = sink.try_lock() else {
        dropped.fetch_add(1, Ordering::Relaxed);
        return;
    };
    // This cumulative marker and per-process ordinal gaps make capture loss
    // explicit on the next successful append. A missing final record alone
    // never proves that its phase did not occur.
    record.dropped_before = dropped.load(Ordering::Relaxed);
    if !matches!(sink.append(&record), Ok(true)) {
        dropped.fetch_add(1, Ordering::Relaxed);
    }
}

struct AppendSink {
    file: File,
    max_records: usize,
    max_bytes: usize,
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
            // Do not block opening a replaced FIFO or follow a replaced link.
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
        })
    }

    fn append(&mut self, record: &Record) -> io::Result<bool> {
        // Never wait for another process: a contended capture is explicitly
        // counted as dropped. The shared lock makes both caps global across
        // all dedicated daemons that inherit this runner artifact path.
        self.file.try_lock().map_err(io::Error::other)?;
        let result = self.append_locked(record);
        let unlocked = self.file.unlock();
        match result {
            Ok(appended) => unlocked.map(|()| appended),
            Err(error) => Err(error),
        }
    }

    fn append_locked(&mut self, record: &Record) -> io::Result<bool> {
        let mut line = serde_json::to_vec(record).map_err(io::Error::other)?;
        line.push(b'\n');
        if line.len() > MAX_RECORD_BYTES {
            return Ok(false);
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
            return Ok(false);
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
                schema_version: 1,
                pid: record.pid,
                record: record.record,
                operation_seq: 0,
                phase: SettlementPhase::CaptureLimitReached,
                dropped_before: record.dropped_before,
                facts: Facts::default(),
            };
            line = serde_json::to_vec(&marker).map_err(io::Error::other)?;
            line.push(b'\n');
        }
        if count >= self.max_records || prior.len().saturating_add(line.len()) > self.max_bytes {
            return Ok(false);
        }
        self.file.write_all(&line)?;
        Ok(!limited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ordinal: u64) -> Record {
        Record {
            schema_version: 1,
            pid: 7,
            record: ordinal,
            operation_seq: 11,
            phase: SettlementPhase::ResultFlushed,
            dropped_before: 0,
            facts: Facts {
                generation: Some(1),
                effects: Some(Effects::NotDispatched),
                scope_state: Some(ScopeState::Usable),
                error: Some(ProtocolError::DeadlineExceeded),
                accepted: None,
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
                "error",
                "generation",
                "operationSeq",
                "phase",
                "pid",
                "record",
                "schemaVersion",
                "scopeState"
            ]
        );
        assert_eq!(value["effects"], "not-dispatched");
        assert_eq!(value["error"], "deadline-exceeded");
        let mut ack = sample(1);
        ack.phase = SettlementPhase::CancelRejected;
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
        assert!(first.append(&sample(0)).unwrap());
        assert!(second.append(&sample(1)).unwrap());
        assert!(!first.append(&sample(2)).unwrap());
        assert!(!second.append(&sample(3)).unwrap());
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
            if !sink.append(&sample(ordinal)).unwrap() {
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
        assert!(!second.append(&sample(101)).unwrap());
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
        assert!(!sink.append(&sample(0)).unwrap());
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
        let dropped = AtomicU64::new(0);
        let held = sink.lock().unwrap();
        emit(&sink, sample(0), &dropped);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        drop(held);
        emit(&sink, sample(1), &dropped);
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
        let dropped = AtomicU64::new(0);
        emit(&sink, sample(0), &dropped);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        other.unlock().unwrap();
        let read_only = Mutex::new(AppendSink {
            file: File::open(file.path()).unwrap(),
            max_records: MAX_RECORDS,
            max_bytes: MAX_BYTES,
        });
        emit(&read_only, sample(1), &dropped);
        assert_eq!(dropped.load(Ordering::Relaxed), 2);
        assert!(std::fs::read(file.path()).unwrap().is_empty());
    }
}
