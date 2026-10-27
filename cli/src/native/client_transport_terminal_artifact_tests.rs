// Terminal framing/correlation tests only. The separate ClientBrowser producer
// tests obtain real encoded video; these author immutable store bytes directly.
use super::super::super::client_blobs::{BlobLimits, BlobScope, BlobStore};
use super::super::super::client_terminal_artifacts::FrozenRecordingBatch;
use super::*;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

struct Executor {
    broker: Arc<ClientSession>,
    store: Arc<BlobStore>,
    batch: Mutex<Option<FrozenRecordingBatch>>,
    calls: std::sync::atomic::AtomicUsize,
    failure_effects: Effects,
}
impl Executor {
    fn new(broker: Arc<ClientSession>) -> Self {
        let store = Arc::new(
            BlobStore::new(BlobLimits {
                max_blob_bytes: 16,
                max_total_bytes: 32,
                max_handles: 2,
            })
            .unwrap(),
        );
        let scope = BlobScope {
            generation: 1,
            identity_scope: "frozen-owner".into(),
        };
        store.activate_scope(scope.clone()).unwrap();
        let authority = store.begin_artifact_attempt(&scope).unwrap();
        let mut reservation = store.reserve_artifact(&authority, &scope).unwrap();
        store.shrink_artifact(&mut reservation, 3).unwrap();
        store.revoke_scope(&scope).unwrap();
        let frozen = store
            .freeze_finalized_artifacts(&authority, 1, vec![(reservation, b"abc".to_vec())])
            .unwrap();
        let batch = FrozenRecordingBatch::new(
            super::super::super::client_debt::OperationKey {
                generation: 1,
                operation_seq: 1,
            },
            scope.identity_scope,
            frozen
                .into_iter()
                .map(|blob| (blob, "2026-10-26T00:00:00.000Z".into(), 1))
                .collect(),
        );
        Self {
            broker,
            store,
            batch: Mutex::new(Some(batch)),
            calls: Default::default(),
            failure_effects: Effects::Unknown,
        }
    }
}
impl ClientExecutor for Executor {
    fn capabilities(&self) -> Vec<String> {
        vec![super::super::super::client_protocol::TERMINAL_RECORDING_ARTIFACTS.into()]
    }
    fn take_terminal_recording(
        &self,
        key: super::super::super::client_debt::OperationKey,
        scope: Option<&str>,
    ) -> Option<FrozenRecordingBatch> {
        assert_eq!(scope, Some("frozen-owner"));
        let mut slot = self.batch.lock().unwrap();
        if slot.as_ref().is_some_and(|batch| batch.key() == key) {
            slot.take()
        } else {
            None
        }
    }
    async fn execute(
        &self,
        command: String,
        _args: serde_json::Map<String, Value>,
        lease: OperationLease,
    ) -> NativeOutcome {
        assert!(matches!(command.as_str(), "fixture.fail" | "browser.perform" | "capture.screenshot" | "page.navigate"));
        assert!(self.broker.start(lease.generation, lease.sequence).unwrap());
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.failure_effects != Effects::Unknown {
            self.broker.quarantine().unwrap();
        }
        NativeOutcome {
            result: Err(ProtocolError::BrowserFailure),
            effects: self.failure_effects,
            retention: None,
        }
    }
    async fn shutdown(&self) -> Result<(), ProtocolError> {
        self.batch.lock().unwrap().take();
        self.store.close().map_err(|_| ProtocolError::CleanupFailed)
    }
}
async fn write(client: &mut tokio::io::BufReader<tokio::io::DuplexStream>, value: Value) {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    client.get_mut().write_all(&bytes).await.unwrap();
}
async fn read(client: &mut tokio::io::BufReader<tokio::io::DuplexStream>) -> Value {
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(client))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
fn request(id: &str, sequence: u64, command: &str, args: Value) -> Value {
    json!({"type":"request","id":id,"generation":1,"operationSeq":sequence,"timeoutMs":1000,"command":command,"args":args})
}
fn identity() -> Value {
    json!({"identityScope":"frozen-owner","failedOperationSeq":1})
}
async fn fixture(
    gate: Option<Arc<FlushGate>>,
) -> (
    tokio::io::BufReader<tokio::io::DuplexStream>,
    tokio::task::JoinHandle<bool>,
    Arc<Executor>,
) {
    fixture_with_failure(gate, "fixture.fail", Effects::Unknown).await
}
async fn fixture_with_failure(
    gate: Option<Arc<FlushGate>>,
    command: &str,
    effects: Effects,
) -> (
    tokio::io::BufReader<tokio::io::DuplexStream>,
    tokio::task::JoinHandle<bool>,
    Arc<Executor>,
) {
    let broker = Arc::new(ClientSession::new());
    let mut executor = Executor::new(broker.clone());
    executor.failure_effects = effects;
    let executor = Arc::new(executor);
    let (client, server) = tokio::io::duplex(8192);
    let (reader, writer) = tokio::io::split(server);
    let hello = ClientMessage::Hello {
        id: "hello".into(),
        protocol: PROTOCOL.into(),
        required_capabilities: vec![
            "terminal.close/1".into(),
            super::super::super::client_protocol::TERMINAL_RECORDING_ARTIFACTS.into(),
        ],
    };
    let task = if let Some(gate) = gate {
        tokio::spawn(serve_with_executor(
            tokio::io::BufReader::new(reader),
            GatedWriter {
                inner: writer,
                gate,
                gated_type: b"\"id\":\"held-read\"",
            },
            hello,
            broker,
            executor.clone(),
        ))
    } else {
        tokio::spawn(serve_with_executor(
            tokio::io::BufReader::new(reader),
            writer,
            hello,
            broker,
            executor.clone(),
        ))
    };
    let mut client = tokio::io::BufReader::new(client);
    assert_eq!(read(&mut client).await["type"], "ready");
    write(
        &mut client,
        request("failure", 1, command, json!({"identityScope":"frozen-owner"})),
    )
    .await;
    let failure = read(&mut client).await;
    assert_eq!(failure["effects"], serde_json::to_value(effects).unwrap());
    assert_eq!(failure["scopeState"], "quarantined");
    (client, task, executor)
}
#[tokio::test]
async fn terminal_artifact_duplicate_id_under_writer_backpressure_never_steals_original_receipt() {
    let gate = Arc::new(FlushGate::default());
    let (mut client, task, executor) = fixture(Some(gate.clone())).await;
    write(
        &mut client,
        request("collect", 2, "recording.finalized.collect", identity()),
    )
    .await;
    let manifest = read(&mut client).await["data"].clone();
    let mut args = identity();
    args["token"] = manifest["token"].clone();
    args["handle"] = manifest["segments"][0]["handle"].clone();
    args["offset"] = json!(0);
    args["maxBytes"] = json!(3);
    write(
        &mut client,
        request("held-read", 3, "recording.finalized.read", args.clone()),
    )
    .await;
    // Bytes are readable, but the real writer has not flushed or released ID.
    let original = read(&mut client).await;
    assert_eq!(original["id"], "held-read");
    assert_eq!(original["ok"], true);
    assert!(gate.result_seen.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(executor.store.charged_for_test(), (3, 1));
    write(
        &mut client,
        request("held-read", 1, "recording.finalized.read", args),
    )
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while executor.store.charged_for_test() != (0, 0) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("duplicate ID did not terminate exact batch custody");
    gate.released
        .store(true, std::sync::atomic::Ordering::SeqCst);
    if let Some(waker) = gate.waker.lock().unwrap().take() {
        waker.wake();
    }
    let refusal = read(&mut client).await;
    assert_eq!(refusal["type"], "error");
    assert_eq!(refusal["error"]["code"], "invalid-frame");
    assert!(refusal.get("id").is_none());
    assert!(
        read_frame(&mut client).await.unwrap().is_none(),
        "duplicate fabricated another Result or Closed"
    );
    // Resource teardown is separately proven; untrusted correlation has no
    // Closed receipt. Preserve the existing serve return-value semantics.
    assert!(task.await.unwrap());
    assert_eq!(executor.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}
#[tokio::test]
async fn terminal_artifact_foreign_generation_reused_sequence_callback_and_schema_are_not_admitted()
{
    let (mut client, task, executor) = fixture(None).await;
    let mut frames = vec![
        request(
            "foreign-generation",
            2,
            "recording.finalized.collect",
            identity(),
        ),
        request("reused", 1, "recording.finalized.collect", identity()),
        request("callback", 3, "recording.finalized.collect", identity()),
        request("timeout", 4, "recording.finalized.collect", identity()),
        request("schema", 5, "recording.finalized.collect", identity()),
    ];
    frames[0]["generation"] = json!(2);
    frames[2]["callbackToken"] = json!("foreign-callback");
    frames[3]["timeoutMs"] = json!(0);
    frames[4]["args"]["unexpected"] = json!(true);
    for frame in frames {
        let id = frame["id"].clone();
        write(&mut client, frame).await;
        let result = read(&mut client).await;
        assert_eq!(result["id"], id);
        assert_eq!(result["ok"], false);
        assert_eq!(result["effects"], "not-dispatched");
    }
    write(
        &mut client,
        request("valid", 6, "recording.finalized.collect", identity()),
    )
    .await;
    assert_eq!(read(&mut client).await["ok"], true);
    write(
        &mut client,
        request(
            "ordinary",
            7,
            "page.evaluate",
            json!({"expression":"sideEffect()"}),
        ),
    )
    .await;
    let denied = read(&mut client).await;
    assert_eq!(denied["error"]["code"], "scope-unavailable");
    write(
        &mut client,
        json!({"type":"close","id":"close","generation":1}),
    )
    .await;
    assert_eq!(read(&mut client).await["type"], "closed");
    assert!(task.await.unwrap());
    assert_eq!(executor.store.charged_for_test(), (0, 0));
    assert_eq!(executor.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}
#[tokio::test]
async fn terminal_artifact_traffic_never_renews_original_ten_second_cutoff() {
    let (mut client, task, executor) = fixture(None).await;
    let started = std::time::Instant::now();
    let traffic = async {
        for sequence in 2..100u64 {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let frame = request(
                &format!("collect-{sequence}"),
                sequence,
                "recording.finalized.collect",
                identity(),
            );
            let mut bytes = serde_json::to_vec(&frame).unwrap();
            bytes.push(b'\n');
            if client.get_mut().write_all(&bytes).await.is_err() {
                break;
            }
            match read_frame(&mut client).await.unwrap() {
                Some(frame) => {
                    let frame: Value = serde_json::from_slice(&frame).unwrap();
                    assert_eq!(frame["ok"], true);
                }
                None => break,
            }
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(12), traffic)
        .await
        .expect("traffic renewed terminal cutoff");
    assert!(started.elapsed() >= std::time::Duration::from_secs(9));
    assert!(task.await.unwrap());
    assert_eq!(executor.store.charged_for_test(), (0, 0));
    assert_eq!(executor.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn terminal_artifact_commands_never_enter_ordinary_executor_dispatch() {
    let broker = Arc::new(ClientSession::new());
    let executor = Arc::new(Executor::new(broker.clone()));
    let (client, server) = tokio::io::duplex(8192);
    let (reader, writer) = tokio::io::split(server);
    let task = tokio::spawn(serve_with_executor(
        tokio::io::BufReader::new(reader),
        writer,
        ClientMessage::Hello {
            id: "hello".into(),
            protocol: PROTOCOL.into(),
            required_capabilities: vec![
                "terminal.close/1".into(),
                super::super::super::client_protocol::TERMINAL_RECORDING_ARTIFACTS.into(),
            ],
        },
        broker,
        executor.clone(),
    ));
    let mut client = tokio::io::BufReader::new(client);
    assert_eq!(read(&mut client).await["type"], "ready");
    for (index, command) in [
        "recording.finalized.collect",
        "recording.finalized.read",
        "recording.finalized.release",
    ]
    .into_iter()
    .enumerate()
    {
        write(
            &mut client,
            request(
                &format!("ordinary-{index}"),
                index as u64 + 1,
                command,
                identity(),
            ),
        )
        .await;
        let result = read(&mut client).await;
        assert_eq!(result["error"]["code"], "unsupported-command");
        assert_eq!(result["effects"], "not-dispatched");
        assert_eq!(result["scopeState"], "usable");
    }
    assert_eq!(executor.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    write(
        &mut client,
        json!({"type":"close","id":"close","generation":1}),
    )
    .await;
    assert_eq!(read(&mut client).await["type"], "closed");
    assert!(task.await.unwrap());
    assert_eq!(executor.store.charged_for_test(), (0, 0));
}

// Framing/admission coverage, not recording-producer evidence.
#[tokio::test]
async fn terminal_action_capture_and_connection_failures_preserve_scoped_artifact_lane() {
    for command in ["browser.perform", "capture.screenshot", "page.navigate"] {
        for effects in [Effects::Unknown, Effects::Completed, Effects::NotDispatched] {
            let (mut client, task, executor) = fixture_with_failure(None, command, effects).await;
            write(&mut client, request("collect", 2, "recording.finalized.collect", identity())).await;
            let manifest = read(&mut client).await;
            assert_eq!(manifest["ok"], true);
            assert_eq!(manifest["scopeState"], "quarantined");
            assert_eq!(manifest["data"]["identityScope"], "frozen-owner");
            write(&mut client, request("denied", 3, "recording.stop", json!({"identityScope":"frozen-owner"}))).await;
            let denied = read(&mut client).await;
            assert_eq!(denied["ok"], false);
            assert_eq!(denied["effects"], "not-dispatched");
            assert_eq!(executor.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            write(&mut client, json!({"type":"close","id":"close","generation":1})).await;
            assert_eq!(read(&mut client).await["type"], "closed");
            assert!(task.await.unwrap());
            assert_eq!(executor.store.charged_for_test(), (0, 0));
        }
    }
}
