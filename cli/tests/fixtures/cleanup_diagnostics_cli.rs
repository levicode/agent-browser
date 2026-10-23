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
    let record: Value = serde_json::from_slice(&bytes).expect("Native CaptureStarted is required");
    assert_eq!(record.as_object().unwrap().len(), 10);
    assert_eq!(record["schemaVersion"], 2);
    assert_eq!(record["source"], "native");
    assert!(record["pid"].as_u64().is_some_and(|pid| pid > 0));
    assert_eq!(record["phase"], "CaptureStarted");
    for key in [
        "record",
        "operationSeq",
        "droppedBefore",
        "emittedBefore",
        "suppressedBefore",
    ] {
        assert_eq!(record[key], 0);
    }
    assert_eq!(record["overflow"], false);
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
