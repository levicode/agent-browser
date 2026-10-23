//! Source-authored coverage for the default-off production cleanup carrier.
//! These tests use local sinks and never change the process-wide environment.
use super::*;
use serde_json::{json, Value};

fn records(file: &tempfile::NamedTempFile) -> Vec<Value> {
    std::fs::read_to_string(file.path())
        .unwrap()
        .lines()
        .map(|line| {
            assert!(line.len() < MAX_RECORD_BYTES);
            serde_json::from_str(line).unwrap()
        })
        .collect()
}
fn attempt(cell: &Arc<CleanupDiagnostics>, sequence: u64) -> CleanupAttempt {
    cell.begin_enabled(CleanupLifecycle::ScopeEnd, sequence, true)
        .unwrap()
}
fn keys(record: &Value) -> Vec<&str> {
    record
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

#[test]
fn disabled_cleanup_capture_has_zero_output_and_no_active_attempt() {
    let file = tempfile::NamedTempFile::new().unwrap();
    assert!(cleanup_capture(None).is_none());
    let cell = CleanupDiagnostics::new(1);
    assert!(cell
        .begin_enabled(CleanupLifecycle::ScopeEnd, 4, false)
        .is_none());
    cell.failure(CleanupComponent::Dialog);
    assert_eq!(cell.active.load(Ordering::Relaxed), 0);
    assert_eq!(cell.attempts.load(Ordering::Relaxed), 0);
    assert!(std::fs::read(file.path()).unwrap().is_empty());
}

#[test]
fn cleanup_snapshot_schema_separates_first_obligation_from_original_result() {
    use crate::native::client_debt::OwnerDebtLedger;
    let file = tempfile::NamedTempFile::new().unwrap();
    let capture = cleanup_capture(Some(file.path())).unwrap();
    record_capture(&capture, 0, Phase::CaptureStarted, Facts::default());
    let owner = OwnerDebtLedger::new(7, "never-emit-native-scope".into());
    let before = owner.snapshot();
    // Ordinary body/earlier cleanup errors cannot consume a lifecycle cell.
    owner
        .cleanup_diagnostics
        .failure(CleanupComponent::Recording);
    let active = attempt(&owner.cleanup_diagnostics, 19);
    owner.cleanup_diagnostics.failure(CleanupComponent::Dialog);
    owner
        .cleanup_diagnostics
        .failure(CleanupComponent::Containment);
    let original: Result<Value, ProtocolError> = Err(ProtocolError::StaleReference);
    active.finish_into(&original, Some(&capture));
    assert_eq!(original, Err(ProtocolError::StaleReference));
    assert_eq!(owner.snapshot(), before);
    let rows = records(&file);
    assert_eq!(rows.len(), 4);
    let base = [
        "droppedBefore",
        "emittedBefore",
        "operationSeq",
        "overflow",
        "phase",
        "pid",
        "record",
        "schemaVersion",
        "source",
        "suppressedBefore",
    ];
    assert_eq!(keys(&rows[0]), base);
    assert_eq!(rows[0]["operationSeq"], 0);
    assert_eq!(
        keys(&rows[1]),
        [
            "cleanupAttempt",
            "cleanupLifecycle",
            "cleanupOwner",
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
            "suppressedBefore"
        ]
    );
    assert_eq!(
        keys(&rows[2]),
        [
            "cleanupAttempt",
            "cleanupComponent",
            "cleanupLifecycle",
            "cleanupOwner",
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
            "suppressedBefore"
        ]
    );
    assert_eq!(
        keys(&rows[3]),
        [
            "cleanupAttempt",
            "cleanupLifecycle",
            "cleanupOwner",
            "cleanupResult",
            "droppedBefore",
            "emittedBefore",
            "error",
            "generation",
            "operationSeq",
            "overflow",
            "phase",
            "pid",
            "record",
            "schemaVersion",
            "source",
            "suppressedBefore"
        ]
    );
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["record"], index);
        assert_eq!(row["emittedBefore"], index);
        assert_eq!(row["droppedBefore"], 0);
        assert_eq!(row["suppressedBefore"], 0);
        assert_eq!(row["source"], "native");
        assert_eq!(row["schemaVersion"], 2);
        if index > 0 {
            assert_eq!(row["generation"], 7);
            assert_eq!(row["cleanupOwner"], owner.cleanup_diagnostics.owner);
            assert_eq!(row["cleanupAttempt"], 1);
            assert_eq!(row["cleanupLifecycle"], "scope-end");
            assert_eq!(row["operationSeq"], 19);
        }
    }
    assert_eq!(rows[1]["phase"], "CleanupStarted");
    assert_eq!(rows[2]["phase"], "CleanupFirstFailure");
    assert_eq!(rows[2]["cleanupComponent"], "dialog");
    assert_eq!(rows[3]["phase"], "CleanupResult");
    assert_eq!(rows[3]["cleanupResult"], "failed");
    assert_eq!(rows[3]["error"], "stale-reference");
    assert!(!std::fs::read_to_string(file.path())
        .unwrap()
        .contains("never-emit"));
}

#[test]
fn each_attempt_and_owner_are_independent_and_success_does_not_invent_cleanup_failure() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let capture = cleanup_capture(Some(file.path())).unwrap();
    let first = CleanupDiagnostics::new(1);
    let second = CleanupDiagnostics::new(1);
    assert_ne!(first.owner, second.owner);
    let a = attempt(&first, 1);
    let b = attempt(&second, 1);
    first.failure(CleanupComponent::Script);
    second.failure(CleanupComponent::Detach);
    a.finish_into(&Err::<(), _>(ProtocolError::CleanupFailed), Some(&capture));
    b.finish_into(&Err::<(), _>(ProtocolError::CleanupFailed), Some(&capture));
    first.failure(CleanupComponent::Dialog); // No active lifecycle.
    let c = first
        .begin_enabled(CleanupLifecycle::Restart, 2, true)
        .unwrap();
    c.finish_into(&Err::<(), _>(ProtocolError::NotActionable), Some(&capture));
    let d = attempt(&first, 3);
    d.finish_into(&Ok(()), Some(&capture));
    let rows = records(&file);
    assert_eq!(rows.len(), 10);
    assert_eq!(rows[1]["cleanupComponent"], "script");
    assert_eq!(rows[4]["cleanupComponent"], "detach");
    assert_eq!(rows[6]["cleanupAttempt"], 2);
    assert_eq!(rows[6]["cleanupLifecycle"], "restart");
    assert_eq!(rows[7]["error"], "not-actionable");
    assert_eq!(rows[9]["cleanupResult"], "passed");
    assert!(rows[9].get("error").is_none());
    assert_eq!(
        rows.iter()
            .filter(|row| row["phase"] == "CleanupFirstFailure")
            .count(),
        2
    );
}

#[test]
fn dropped_waiter_and_old_completion_cannot_tag_a_later_attempt() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let capture = cleanup_capture(Some(file.path())).unwrap();
    let cell = CleanupDiagnostics::new(1);
    assert!(cell.observer().is_none());
    let abandoned = attempt(&cell, 1);
    let old_observer = cell.observer().unwrap();
    drop(abandoned);
    assert_eq!(cell.active.load(Ordering::Relaxed), 0);
    assert!(records(&file).is_empty());
    let current = attempt(&cell, 2);
    old_observer.failure(CleanupComponent::Dialog);
    cell.observer()
        .unwrap()
        .failure(CleanupComponent::Recording);
    current.finish_into(&Err::<(), _>(ProtocolError::CleanupFailed), Some(&capture));
    let rows = records(&file);
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[1]["cleanupComponent"], "recording");
    assert_eq!(rows[1]["cleanupAttempt"], 2);
    assert_eq!(rows[1]["operationSeq"], 2);
}

#[test]
fn abandoned_attempt_clear_tolerates_first_failure_race_without_clearing_next_attempt() {
    let cell = CleanupDiagnostics::new(1);
    let abandoned = attempt(&cell, 1);
    let before_publication = cell.active.load(Ordering::Relaxed);
    cell.observer().unwrap().failure(CleanupComponent::Dialog);
    // Deterministically publish the component between Drop's load and CAS.
    abandoned.clear_abandoned(before_publication);
    assert_eq!(cell.active.load(Ordering::Relaxed), 0);
    let next = attempt(&cell, 2);
    let next_state = cell.active.load(Ordering::Relaxed);
    drop(abandoned);
    assert_eq!(cell.active.load(Ordering::Relaxed), next_state);
    drop(next);
    assert_eq!(cell.active.load(Ordering::Relaxed), 0);
}

#[test]
fn simultaneous_obligations_keep_one_first_component_without_authority_state_changes() {
    use crate::native::client_debt::OwnerDebtLedger;
    let file = tempfile::NamedTempFile::new().unwrap();
    let capture = cleanup_capture(Some(file.path())).unwrap();
    let owner = OwnerDebtLedger::new(1, "private-owner".into());
    let before = owner.snapshot();
    let a = attempt(&owner.cleanup_diagnostics, 1);
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let threads: Vec<_> = [CleanupComponent::Dialog, CleanupComponent::Callback]
        .into_iter()
        .map(|component| {
            let cell = owner.cleanup_diagnostics.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                cell.failure(component);
            })
        })
        .collect();
    barrier.wait();
    for thread in threads {
        thread.join().unwrap();
    }
    a.finish_into(&Err::<(), _>(ProtocolError::CleanupFailed), Some(&capture));
    let rows = records(&file);
    assert_eq!(rows.len(), 3);
    assert!([json!("dialog"), json!("callback")].contains(&rows[1]["cleanupComponent"]));
    assert_eq!(owner.snapshot(), before);
}

#[test]
fn bounds_contention_and_write_failure_do_not_change_terminal_owner_or_result() {
    use crate::native::client_debt::OwnerDebtLedger;
    let owner = OwnerDebtLedger::new(1, "never-emit-scope".into());
    owner.bind_context("never-emit-context").unwrap();
    owner
        .retire_after_context_destroy("never-emit-context")
        .unwrap();
    let terminal = owner.snapshot();
    let replacement_ready = owner.replacement_ready();
    let original: Result<(), ProtocolError> = Err(ProtocolError::Cancelled);
    let file = tempfile::NamedTempFile::new().unwrap();
    let capture = Capture {
        source: Source::Native,
        sink: Mutex::new(AppendSink::open(file.path(), 2, 4096).unwrap()),
        counters: Counters::default(),
    };
    let a = attempt(&owner.cleanup_diagnostics, 1);
    owner
        .cleanup_diagnostics
        .failure(CleanupComponent::Recording);
    a.finish_into(&original, Some(&capture));
    let rows = records(&file);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["phase"], "CaptureLimitReached");
    assert!(rows[1].get("cleanupOwner").is_none());
    assert_eq!(rows[1]["operationSeq"], 0);
    let before = std::fs::read(file.path()).unwrap();
    attempt(&owner.cleanup_diagnostics, 2).finish_into(&original, Some(&capture));
    assert_eq!(std::fs::read(file.path()).unwrap(), before);
    let file = tempfile::NamedTempFile::new().unwrap();
    let read_only = Capture {
        source: Source::Native,
        sink: Mutex::new(AppendSink {
            file: File::open(file.path()).unwrap(),
            max_records: MAX_RECORDS,
            max_bytes: MAX_BYTES,
            stopped: false,
        }),
        counters: Counters::default(),
    };
    attempt(&owner.cleanup_diagnostics, 3).finish_into(&original, Some(&read_only));
    assert!(read_only.sink.lock().unwrap().stopped);
    assert!(std::fs::read(file.path()).unwrap().is_empty());
    let capture = cleanup_capture(Some(file.path())).unwrap();
    let held = capture.sink.lock().unwrap();
    attempt(&owner.cleanup_diagnostics, 4).finish_into(&original, Some(&capture));
    drop(held);
    assert_eq!(capture.counters.dropped.load(Ordering::Relaxed), 2);
    assert!(std::fs::read(file.path()).unwrap().is_empty());
    assert_eq!(original, Err(ProtocolError::Cancelled));
    assert_eq!(owner.snapshot(), terminal);
    assert_eq!(owner.replacement_ready(), replacement_ready);
}

#[test]
fn cleanup_sink_refuses_unsafe_destinations_and_preserves_partial_artifact() {
    assert!(cleanup_capture(Some(Path::new("relative"))).is_none());
    let directory = tempfile::tempdir().unwrap();
    assert!(cleanup_capture(Some(directory.path())).is_none());
    assert!(cleanup_capture(Some(&directory.path().join("missing"))).is_none());
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"incomplete").unwrap();
    let capture = cleanup_capture(Some(file.path())).unwrap();
    attempt(&CleanupDiagnostics::new(1), 1).finish_into(&Ok(()), Some(&capture));
    assert_eq!(std::fs::read(file.path()).unwrap(), b"incomplete");
    #[cfg(unix)]
    {
        let link = directory.path().join("symlink");
        std::os::unix::fs::symlink(file.path(), &link).unwrap();
        assert!(cleanup_capture(Some(&link)).is_none());
    }
}

#[test]
fn cleanup_ordinals_never_alias_and_maximum_scalar_records_fit_the_record_bound() {
    let counter = AtomicU64::new(MAX_CLEANUP_ATTEMPT - 1);
    assert_eq!(
        next_cleanup_ordinal(&counter, MAX_CLEANUP_ATTEMPT),
        Some(MAX_CLEANUP_ATTEMPT)
    );
    assert_eq!(next_cleanup_ordinal(&counter, MAX_CLEANUP_ATTEMPT), None);
    let cell = CleanupDiagnostics::new(1);
    cell.attempts.store(MAX_CLEANUP_ATTEMPT, Ordering::Relaxed);
    assert!(cell
        .begin_enabled(CleanupLifecycle::ScopeEnd, 1, true)
        .is_none());
    for (phase, component, result, error) in [
        (
            Phase::CleanupFirstFailure,
            Some(CleanupComponent::RetainedTaskFallback),
            None,
            None,
        ),
        (
            Phase::CleanupResult,
            None,
            Some(CleanupResult::Failed),
            Some(ProtocolError::RedirectBodyUnavailable),
        ),
    ] {
        let record = Record {
            schema_version: 2,
            source: Source::Native,
            pid: u32::MAX,
            record: SAFE_INTEGER,
            operation_seq: SAFE_INTEGER,
            phase,
            dropped_before: SAFE_INTEGER,
            emitted_before: SAFE_INTEGER,
            suppressed_before: SAFE_INTEGER,
            overflow: true,
            facts: Facts {
                generation: Some(SAFE_INTEGER),
                cleanup_owner: Some(SAFE_INTEGER),
                cleanup_attempt: Some(MAX_CLEANUP_ATTEMPT),
                cleanup_lifecycle: Some(CleanupLifecycle::ScopeEnd),
                cleanup_component: component,
                cleanup_result: result,
                error,
                ..Facts::default()
            },
        };
        assert!(serde_json::to_vec(&record).unwrap().len() < MAX_RECORD_BYTES);
    }
}

#[tokio::test]
async fn actual_cleanup_command_errors_record_closed_components_without_native_payloads() {
    use crate::native::cdp::client::CdpClient;
    use crate::native::client_debt::{OwnerDebtLedger, ScopeCleanupCommand};
    use futures_util::{SinkExt, StreamExt};
    use std::time::{Duration, Instant};
    use tokio_tungstenite::tungstenite::Message;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut methods = Vec::new();
        while let Some(Ok(message)) = socket.next().await {
            if !message.is_text() {
                continue;
            }
            let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
            methods.push(request["method"].as_str().unwrap().to_owned());
            socket.send(Message::Text(json!({"id":request["id"],"sessionId":request["sessionId"],"error":{"code":-32000,"message":"private-browser-error"}}).to_string())).await.unwrap();
            if methods.len() == 5 {
                break;
            }
        }
        methods
    });
    let raw = CdpClient::connect(&format!("ws://{address}"))
        .await
        .unwrap();
    let owner = OwnerDebtLedger::new(3, "private-scope".into());
    raw.install_debt_ledger(owner.clone()).unwrap();
    let client = raw.owner_view(owner.clone()).unwrap();
    let file = tempfile::NamedTempFile::new().unwrap();
    let capture = cleanup_capture(Some(file.path())).unwrap();
    let commands = [
        (
            ScopeCleanupCommand::DismissDialog {
                session: "private-session".into(),
            },
            "dialog",
        ),
        (
            ScopeCleanupCommand::DisableFetch {
                session: "private-session".into(),
            },
            "interception",
        ),
        (
            ScopeCleanupCommand::RemoveScript {
                session: "private-session".into(),
                identifier: "private-script".into(),
            },
            "script",
        ),
        (
            ScopeCleanupCommand::Detach {
                session: "private-session".into(),
                parent: None,
            },
            "detach",
        ),
        (
            ScopeCleanupCommand::DisableAutoAttach { session: None },
            "release",
        ),
    ];
    for (index, (command, component)) in commands.into_iter().enumerate() {
        let a = attempt(&owner.cleanup_diagnostics, index as u64 + 1);
        let result = client
            .send_scope_cleanup(command, Instant::now() + Duration::from_secs(1))
            .await;
        assert!(result.is_err());
        assert!(result
            .as_ref()
            .unwrap_err()
            .contains("private-browser-error"));
        // Public conversion remains outside the diagnostic path, unchanged.
        a.finish_into(&Err::<(), _>(ProtocolError::CleanupFailed), Some(&capture));
        let rows = records(&file);
        assert_eq!(rows[index * 3 + 1]["cleanupComponent"], component);
    }
    let methods = tokio::time::timeout(Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        methods,
        [
            "Page.handleJavaScriptDialog",
            "Fetch.disable",
            "Page.removeScriptToEvaluateOnNewDocument",
            "Target.detachFromTarget",
            "Target.setAutoAttach"
        ]
    );
    assert!(!std::fs::read_to_string(file.path())
        .unwrap()
        .contains("private-"));
    client.close().await;
}
