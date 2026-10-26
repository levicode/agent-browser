//! Real CLI -> isolated proxy -> daemon coverage, with no browser requests.
//! A startup marker proves capture enablement only, never lifecycle cleanup.
#![cfg(unix)]

use serde_json::{json, Value};
use std::io::Read;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_agent-browser");
const CAPTURE_ENV: &str = "AGENT_BROWSER_CLEANUP_DIAGNOSTIC_FILE";
const OUTPUT_LIMIT: u64 = 64 * 1024;

async fn transport(root: &Path, capture: Option<(&str, &Path)>) -> Result<(), String> {
    let home = root.join("home");
    let sockets = root.join("sockets");
    std::fs::create_dir_all(&home).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&sockets).map_err(|error| error.to_string())?;
    let mut command = Command::new(BIN);
    command
        .args([
            "--session",
            "cleanup-capture",
            "session",
            "connect",
            "--json",
        ])
        .current_dir(root)
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("TMPDIR", root)
        .env("AGENT_BROWSER_SOCKET_DIR", &sockets)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some((key, value)) = capture {
        command.env(key, value);
    }
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let mut output = BufReader::new(child.stdout.take().unwrap().take(OUTPUT_LIMIT));
    let exchange = async {
        let hello = json!({
            "type": "hello", "id": "hello", "protocol": "agent-browser-session/1",
            "requiredCapabilities": [],
        });
        let input = child.stdin.as_mut().unwrap();
        input
            .write_all(format!("{hello}\n").as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        input.flush().await.map_err(|error| error.to_string())?;
        let mut line = String::new();
        output
            .read_line(&mut line)
            .await
            .map_err(|error| error.to_string())?;
        let ready: Value = serde_json::from_str(&line).map_err(|error| error.to_string())?;
        if ready["type"] != "ready"
            || ready["id"] != "hello"
            || ready["protocol"] != "agent-browser-session/1"
        {
            return Err("Missing original ready receipt".into());
        }
        let generation = ready["generation"].as_u64().ok_or("Missing generation")?;
        let close = json!({"type": "close", "id": "close", "generation": generation});
        let input = child.stdin.as_mut().unwrap();
        input
            .write_all(format!("{close}\n").as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        input.flush().await.map_err(|error| error.to_string())?;
        line.clear();
        output
            .read_line(&mut line)
            .await
            .map_err(|error| error.to_string())?;
        let closed: Value = serde_json::from_str(&line).map_err(|error| error.to_string())?;
        if closed
            != json!({"type": "closed", "id": "close", "generation": generation, "scopeState": "closed"})
        {
            return Err("Missing original closed receipt".into());
        }
        drop(child.stdin.take());
        let status = child.wait().await.map_err(|error| error.to_string())?;
        if !status.success() {
            return Err(format!("Proxy did not exit successfully: {status}"));
        }
        // Do not use the closed scalar alone as evidence of transport retirement.
        if sockets.join("cleanup-capture.pid").exists()
            || sockets.join("cleanup-capture.sock").exists()
        {
            return Err("Dedicated daemon transport remains present".into());
        }
        Ok(())
    };
    let result = match tokio::time::timeout(Duration::from_secs(15), exchange).await {
        Ok(result) => result,
        Err(_) => Err("CLI-to-daemon exchange exceeded its fixed deadline".into()),
    };
    if result.is_err() {
        drop(child.stdin.take());
        let _ = child.start_kill();
        // Only the exact spawned proxy is killed. A failed exchange is not
        // daemon-exit proof; the caller retains its isolated directory below.
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    }
    result
}

async fn checked_transport(directory: TempDir, capture: Option<(&str, &Path)>) -> TempDir {
    if let Err(error) = transport(directory.path(), capture).await {
        let retained = directory.keep();
        panic!(
            "{error}; unresolved test directory retained at {}",
            retained.display()
        );
    }
    directory
}

/// This no-browser exchange emits exactly startup and the joined shutdown
/// checkpoint. Validate every JSONL record; never trim away an unknown suffix.
fn validate_capture(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > 512 || !bytes.ends_with(b"\n") {
        return Err("Capture must be bounded complete JSONL".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    let records = text
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    if records.len() != 2 {
        return Err("Expected exactly startup and shutdown records".into());
    }
    let pid = records[0]["pid"]
        .as_u64()
        .filter(|pid| *pid > 0)
        .ok_or("Missing native PID")?;
    let expected = capture_records(pid);
    if records != expected {
        return Err("Unexpected capture payload, phase, counter or owner".into());
    }
    Ok(())
}

fn capture_records(pid: u64) -> Vec<Value> {
    vec![
        json!({"schemaVersion":2,"source":"native","pid":pid,"record":0,
            "operationSeq":0,"phase":"CaptureStarted","droppedBefore":0,
            "emittedBefore":0,"suppressedBefore":0,"overflow":false}),
        json!({"schemaVersion":2,"source":"native","pid":pid,"record":1,
            "operationSeq":0,"phase":"TerminalCleanupCheckpoint","droppedBefore":0,
            "emittedBefore":1,"suppressedBefore":0,"overflow":false,
            "terminalCleanupStage":"shutdown-joins","terminalCleanupOk":true}),
    ]
}

#[test]
fn capture_jsonl_requires_both_exact_correlated_records() {
    fn encode(records: &[Value]) -> Vec<u8> {
        records
            .iter()
            .map(|record| format!("{record}\n"))
            .collect::<String>()
            .into_bytes()
    }
    let records = capture_records(123);
    let valid = encode(&records);
    assert!(validate_capture(&valid).is_ok());
    assert!(validate_capture(&encode(&records[..1])).is_err());
    assert!(validate_capture(&encode(&records[1..])).is_err());
    assert!(validate_capture(&valid[..valid.len() - 1]).is_err());
    let mut malformed = valid.clone();
    malformed.extend_from_slice(b"invalid\n");
    assert!(validate_capture(&malformed).is_err());
    let mut extra = records.clone();
    extra.push(records[1].clone());
    assert!(validate_capture(&encode(&extra)).is_err());
    for (key, wrong) in [
        ("pid", json!(124)),
        ("record", json!(2)),
        ("emittedBefore", json!(0)),
        ("operationSeq", json!(1)),
        ("phase", json!("CaptureStarted")),
        ("terminalCleanupStage", json!("final-commit")),
        ("terminalCleanupOk", json!(false)),
        ("droppedBefore", json!(1)),
        ("suppressedBefore", json!(1)),
        ("overflow", json!(true)),
        ("unexpected", json!("not admitted")),
    ] {
        let mut changed = records.clone();
        changed[1][key] = wrong;
        assert!(validate_capture(&encode(&changed)).is_err(), "{key}");
    }
    assert!(validate_capture(&encode(&capture_records(0))).is_err());
    let mut reversed = records.clone();
    reversed.reverse();
    assert!(validate_capture(&encode(&reversed)).is_err());
    let mut extra_startup_field = records.clone();
    extra_startup_field[0]["unexpected"] = json!(true);
    assert!(validate_capture(&encode(&extra_startup_field)).is_err());
    assert!(validate_capture(&vec![b' '; 513]).is_err());
}

#[tokio::test]
async fn cleanup_capture_survives_the_real_production_proxy() {
    let directory = tempfile::tempdir().unwrap();
    let capture = directory.path().join("capture.jsonl");
    std::fs::write(&capture, []).unwrap();
    let _directory = checked_transport(directory, Some((CAPTURE_ENV, &capture))).await;
    let mut bytes = Vec::new();
    std::fs::File::open(&capture)
        .unwrap()
        .take(513)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 512, "Unexpected startup capture size");
    validate_capture(&bytes).expect("Native startup and joined shutdown JSONL are required");
}

#[tokio::test]
async fn cleanup_capture_is_absent_by_default_and_lookalikes_stay_scrubbed() {
    for key in [None, Some("AGENT_BROWSER_CLEANUP_DIAGNOSTIC_FILE_EXTRA")] {
        let directory = tempfile::tempdir().unwrap();
        let capture = directory.path().join("capture.jsonl");
        std::fs::write(&capture, []).unwrap();
        let _directory =
            checked_transport(directory, key.map(|key| (key, capture.as_path()))).await;
        assert_eq!(std::fs::metadata(capture).unwrap().len(), 0);
    }
}

#[tokio::test]
async fn invalid_capture_values_cannot_change_the_transport_outcome() {
    for value in ["", "false", "missing.jsonl"] {
        let directory = tempfile::tempdir().unwrap();
        let directory = checked_transport(directory, Some((CAPTURE_ENV, Path::new(value)))).await;
        for name in ["false", "missing.jsonl"] {
            assert!(!directory.path().join(name).exists());
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.jsonl");
    let _directory = checked_transport(directory, Some((CAPTURE_ENV, &missing))).await;
    assert!(
        !missing.exists(),
        "Diagnostics must not create a destination"
    );
}
