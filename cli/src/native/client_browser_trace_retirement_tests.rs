//! Real framed Observe -> Trace; only a finite CDP peer is synthetic.
//! No renderer, timer override, production change, or replacement executor.
use super::*;
use crate::native::client_capture::{retained_capture_test, CaptureReason};
use crate::native::client_debt::OperationKey;
use crate::native::client_protocol::EXACT_OWNER_CONTINUATION;
use tokio::sync::mpsc;

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("finite trace fixture did not reach its next protocol event")
}

async fn stopped<T>(mut task: tokio::task::JoinHandle<T>) -> Result<T, String> {
    match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
        Ok(result) => result.map_err(|error| format!("fixture task failed: {error}")),
        Err(_) => {
            // Only this test's task is cancelled, and cancellation is joined.
            task.abort();
            match task.await {
                Err(error) if error.is_cancelled() => {
                    Err("fixture task did not stop normally".into())
                }
                Err(error) => Err(format!("fixture task failed during shutdown: {error}")),
                Ok(value) => Ok(value),
            }
        }
    }
}

fn trace_framed(browser: Arc<ClientBrowser>, broker: Arc<ClientSession>) -> FramedFixture {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let (reader, writer) = tokio::io::split(server);
    let server = tokio::spawn(serve_with_executor(
        tokio::io::BufReader::new(reader),
        writer,
        ClientMessage::Hello {
            id: "fixture-hello".into(),
            protocol: PROTOCOL.into(),
            required_capabilities: vec![EXACT_OWNER_CONTINUATION.into()],
        },
        broker,
        browser,
    ));
    FramedFixture {
        stream: tokio::io::BufReader::new(client),
        server,
        sequence: 0,
        event_sequence: 0,
        scope: None,
        registry: 0,
        decisions: 0,
    }
}

// Reuse the existing lifecycle peer without duplicating its enrollment protocol.
// Unrecognized commands and every lifecycle event pass through unchanged.
async fn trace_peer(
    hold_remove: bool,
    post_ack_failure: bool,
) -> (
    String,
    mpsc::UnboundedReceiver<Value>,
    mpsc::UnboundedSender<Value>,
    Arc<Mutex<Vec<Value>>>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let (backend, _, lifecycle) = peer(false).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let (seen, requests) = mpsc::unbounded_channel();
    let (release, mut replies) = mpsc::unbounded_channel::<Value>();
    let log = Arc::new(Mutex::new(Vec::new()));
    let recorded = log.clone();
    let relay = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut client = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut backend, _) = tokio_tungstenite::connect_async(&backend).await.unwrap();
        let mut capture_seen = false;
        loop {
            tokio::select! {
                Some(reply) = replies.recv() => {
                    client.send(Message::Text(reply.to_string())).await.unwrap();
                }
                message = backend.next() => {
                    let Some(Ok(message)) = message else { break };
                    if client.send(message).await.is_err() { break; }
                }
                message = client.next() => {
                    let Some(Ok(message)) = message else { break };
                    let Message::Text(text) = message else {
                        if backend.send(message).await.is_err() { break; }
                        continue;
                    };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    recorded.lock().unwrap().push(request.clone());
                    let method = request["method"].as_str().unwrap();
                    let remove = method == "Runtime.callFunctionOn"
                        && request["params"]["functionDeclaration"] == "function(){return this.remove()}";
                    if method == "Page.captureScreenshot" || (hold_remove && remove) {
                        capture_seen |= method == "Page.captureScreenshot";
                        seen.send(request).unwrap();
                        continue;
                    }
                    // Only the real post-ACK verification can reach this branch.
                    // Before capture, the same source-mask guard remains successful.
                    if post_ack_failure && capture_seen && method == "Runtime.callFunctionOn"
                        && request["params"]["functionDeclaration"] == "function(){return this.verify()}" {
                        capture_seen = false;
                        client.send(Message::Text(reply(&request, json!({"result":{"value":false}})).to_string())).await.unwrap();
                        continue;
                    }
                    let Some(result) = observation_reply(&request) else {
                        if backend.send(Message::Text(text)).await.is_err() { break; }
                        continue;
                    };
                    client.send(Message::Text(reply(&request, result).to_string())).await.unwrap();
                }
            }
        }
    });
    (endpoint, requests, release, log, relay, lifecycle)
}

fn reply(request: &Value, result: Value) -> Value {
    assert_eq!(request["sessionId"], "session-1");
    json!({"id":request["id"],"sessionId":request["sessionId"],"result":result})
}

// Root-only reduction of tree_observe_with_hidden_iframe's real DOM/AX protocol.
// Keep real source-holder creation, verification, removal and release separate.
fn observation_reply(request: &Value) -> Option<Value> {
    let value = match request["method"].as_str().unwrap() {
        "Page.getLayoutMetrics" => {
            json!({"cssVisualViewport":{"clientWidth":10,"clientHeight":10,"offsetX":0,"offsetY":0,"scale":1},"cssLayoutViewport":{"clientWidth":10,"clientHeight":10}})
        }
        "Page.createIsolatedWorld" => json!({"executionContextId":1}),
        "Animation.getPlaybackRate" => json!({"playbackRate":1}),
        "Animation.enable" | "Animation.setPlaybackRate" | "Animation.disable" => json!({}),
        "DOM.getDocument" => json!({"root":{"nodeType":9,"backendNodeId":1}}),
        "Accessibility.getFullAXTree" => {
            json!({"nodes":[{"nodeId":"document","backendDOMNodeId":1,"role":{"type":"role","value":"RootWebArea"}}]})
        }
        "DOM.resolveNode" => json!({"object":{"objectId":"node-1","subtype":"node"}}),
        "DOMSnapshot.captureSnapshot" => {
            json!({"strings":["frame-session-1"],"documents":[{"frameId":0,"nodes":{"nodeType":[9],"backendNodeId":[1]}}]})
        }
        "Runtime.getProperties" => {
            json!({"result":[{"name":"focused","value":{"type":"object","subtype":"null","value":null}}]})
        }
        "Runtime.evaluate"
            if request["params"]["objectGroup"]
                .as_str()
                .is_some_and(|g| g.starts_with("capture-source-")) =>
        {
            json!({"result":{"type":"object","objectId":"source-holder"}})
        }
        "Runtime.callFunctionOn" => {
            let declaration = request["params"]["functionDeclaration"].as_str().unwrap();
            if declaration.contains("Array.from(result)") {
                json!({"result":{"objectId":"security"}})
            } else if declaration.contains("const read=") {
                let values = request["params"]["arguments"].as_array().unwrap().iter().skip(2).map(|argument| {
                    assert_eq!(argument["objectId"], "node-1");
                    json!({"attributes":{},"labels":[],"states":{},"rect":null,"author":{"nodeType":9,"visible":true}})
                }).collect::<Vec<_>>();
                json!({"result":{"value":values}})
            } else if declaration.contains("frameOwner") {
                json!({"result":{"value":{"connected":true,"frameOwner":false}}})
            } else if declaration
                == "function(selector,...nodes){return this.install(selector,nodes)}"
            {
                // Source protection includes document roots, not only elements.
                assert_eq!(request["params"]["objectId"], "source-holder");
                assert_eq!(request["params"]["returnByValue"], true);
                assert_eq!(
                    request["params"]["arguments"],
                    json!([
                        {"value":FIXTURE_SECURE_SELECTOR}, {"objectId":"node-1"}
                    ])
                );
                let sequence = request["params"]["objectGroup"]
                    .as_str()
                    .and_then(|group| group.strip_prefix("capture-source-"))
                    .and_then(|group| group.strip_suffix("-frame-session-1"))
                    .and_then(|sequence| sequence.parse::<u64>().ok())
                    .expect("install must belong to this native source-mask group");
                assert!(sequence > 0);
                json!({"result":{"type":"boolean","value":true}})
            } else {
                assert!(
                    declaration == "function(){return this.verify()}"
                        || declaration == "function(){return this.remove()}"
                        || declaration.contains("documentElement")
                        || declaration.contains("nodeType"),
                    "unmodeled call: {declaration}"
                );
                json!({"result":{"value":true}})
            }
        }
        "Runtime.releaseObject" | "Runtime.releaseObjectGroup" => json!({}),
        _ => return None,
    };
    Some(value)
}

async fn result_frame(fixture: &mut FramedFixture, sequence: u64) -> Value {
    for _ in 0..32 {
        let frame = bounded(fixture.read()).await.unwrap();
        assert_eq!(frame["generation"], 1);
        if frame["type"] == "result" {
            assert_eq!(frame["operationSeq"], sequence);
            return frame;
        }
        assert_eq!(frame["type"], "event");
        assert_eq!(frame["sequence"], fixture.event_sequence + 1);
        fixture.event_sequence += 1;
        validate_fixture_notice(&frame).unwrap();
    }
    panic!("trace result missing within finite event bound")
}

fn uncorrelated_cleanup_failure(frame: &Value) -> bool {
    frame
        == &json!({
            "type":"error",
            "error":{"code":"cleanup-failed"},
            "scopeState":"quarantined"
        })
}

async fn terminal_failure_frame(fixture: &mut FramedFixture) {
    for _ in 0..32 {
        let frame = bounded(fixture.read()).await.unwrap();
        if frame["type"] == "error" {
            assert!(
                uncorrelated_cleanup_failure(&frame),
                "unexpected terminal: {frame}"
            );
            return;
        }
        assert_eq!(frame["generation"], 1);
        assert_eq!(frame["type"], "event");
        assert_eq!(frame["sequence"], fixture.event_sequence + 1);
        fixture.event_sequence += 1;
        validate_fixture_notice(&frame).unwrap();
    }
    panic!("trace terminal failure missing within finite event bound")
}

#[test]
fn trace_terminal_failure_rejects_correlated_or_reusable_shapes() {
    let terminal = serde_json::to_value(crate::native::client_protocol::ServerMessage::Error {
        id: None,
        error: crate::native::client_protocol::WireError {
            code: ProtocolError::CleanupFailed,
        },
        scope_state: ScopeState::Quarantined,
    })
    .unwrap();
    assert!(uncorrelated_cleanup_failure(&terminal));
    for (field, value) in [
        ("type", json!("result")),
        ("type", json!("closed")),
        ("id", json!("after-trace")),
        ("id", Value::Null),
        ("generation", json!(1)),
        ("generation", Value::Null),
        ("operationSeq", json!(7)),
        ("ok", json!(false)),
        ("data", json!({})),
        ("retention", json!({})),
        ("scopeState", json!("usable")),
        ("scopeState", json!("closed")),
        ("error", json!({"code":"scope-unavailable"})),
    ] {
        let mut invalid = terminal.clone();
        invalid[field] = value;
        assert!(
            !uncorrelated_cleanup_failure(&invalid),
            "terminal fixture accepted an invalid {field}: {invalid}"
        );
    }
}

async fn trace_retirement_case(raw_ack: bool) {
    trace_timing_case(raw_ack, false).await;
}

async fn trace_timing_case(raw_ack: bool, post_ack_failure: bool) {
    let (endpoint, mut requests, release, log, relay, lifecycle) =
        trace_peer(raw_ack && !post_ack_failure, post_ack_failure).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture = trace_framed(browser.clone(), broker.clone());
    let test: Result<(), String> = async {
        fixture.ready().await?;
        let opened = fixture.command("scope.open", fixture_scope_open("connect", Some(&endpoint)), 5).await?;
        let scope = opened["identityScope"].as_str().unwrap().to_owned();
        fixture.scope = Some(scope.clone());
        fixture.command("scope.configure", fixture_configuration(&scope, None), 5).await?;
        fixture.command("network.routes.replace", fixture_routes(&scope), 5).await?;
        fixture.registry = 1;
        fixture.command("page.activate", json!({"identityScope":scope}), 5).await?;
        let observed = fixture.command("browser.observe", json!({"identityScope":scope,
            "testIdAttribute":"data-testid","secureFieldSelector":FIXTURE_SECURE_SELECTOR,
            "options":{"pixels":false,"pixelFallback":false,"comparable":false}}), 5).await?;
        assert_eq!(observed["root"]["role"], "document");
        assert!(observed["revision"].is_string());
        assert!(observed["viewportRef"]["id"].is_string());
        assert!(!log.lock().unwrap().iter().any(|r| r["method"] == "Page.captureScreenshot"));
        let page = browser.page_lease(false).await.map_err(|e| format!("page: {e:?}"))?;
        let client = page.client.clone();
        let targets = page.targets.clone();
        drop(page);
        let ui = browser.owner.lock().await.as_ref().unwrap().ui.clone();
        fixture.sequence += 1;
        let sequence = fixture.sequence;
        let key = OperationKey { generation: 1, operation_seq: sequence };
        let publication_fence = browser.observation.publication_fence().unwrap();
        let (_registration, retained) = retained_capture_test::register(&client, sequence);
        let mut png = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgba8(10, 10).write_to(&mut png, image::ImageFormat::Png).unwrap();
        let png = base64::engine::general_purpose::STANDARD.encode(png.into_inner());
        fixture.write(json!({"type":"request","id":"trace","generation":1,
            "operationSeq":sequence,"timeoutMs":1000,"command":"capture.screenshot",
            "args":{"identityScope":scope,"secureFieldSelector":FIXTURE_SECURE_SELECTOR,"purpose":"trace"}})).await?;
        let screenshot = bounded(requests.recv()).await.unwrap();
        assert_eq!(screenshot["method"], "Page.captureScreenshot");
        if post_ack_failure {
            release.send(reply(&screenshot, json!({"data":png}))).unwrap();
            let result = result_frame(&mut fixture, sequence).await;
            assert_eq!(result["id"], "trace");
            assert_eq!(result["ok"], false);
            assert_eq!(result["error"]["code"], "policy-denied");
            assert_eq!(result["scopeState"], "usable");
            assert!(result.get("data").is_none());
            fixture.command("scope.end", json!({"identityScope":scope}), 5).await?;
        } else {
        assert!(matches!(bounded(retained).await.unwrap(), CaptureReason::Deadline | CaptureReason::Cancelled));
        if raw_ack {
            release.send(reply(&screenshot, json!({"data":png}))).unwrap();
            let remove = bounded(requests.recv()).await.unwrap();
            assert_eq!(remove["params"]["functionDeclaration"], "function(){return this.remove()}");
            // Retirement advances this existing fence only after outer grace.
            // It then awaits the publication mutex still owned by restoration:
            // waiting for a wire result before this ACK would manufacture failure.
            bounded(async {
                while browser.observation.publication_fence().unwrap() == publication_fence {
                    tokio::task::yield_now().await;
                }
            }).await;
            let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let admission = ui.enter(false, false, Instant::now() + Duration::from_secs(5), cancellation);
            tokio::pin!(admission);
            assert!(futures_util::poll!(admission.as_mut()).is_pending(), "restore still owns exclusive UI");
            assert!(matches!(browser.operation_retention_status(key),
                crate::native::client_operation_state::OperationRetentionStatus::KnownRetiring { .. }));
            release.send(reply(&remove, json!({"result":{"type":"boolean","value":true}}))).unwrap();
            drop(bounded(admission).await.map_err(|e| format!("UI not released: {e:?}"))?);
            let result = result_frame(&mut fixture, sequence).await;
            assert_eq!(result["id"], "trace");
            assert_eq!(result["ok"], false);
            assert_eq!(result["error"]["code"], "deadline-exceeded");
            assert_eq!(result["effects"], "unknown");
            assert_eq!(result["scopeState"], "usable");
            assert_eq!(result["retention"]["retiredOperationSeq"], sequence);
            assert_eq!(result["retention"]["producerState"], "retiring");
            // Raw success was acknowledged; only the held source holder remains.
            assert_eq!(result["retention"]["inputDebt"], 0);
            assert!(result["retention"]["objectDebt"].as_u64().unwrap() > 0);
            assert!(result.get("data").is_none());
            let fresh = fixture.command("browser.observe", json!({"identityScope":scope,
                "testIdAttribute":"data-testid","secureFieldSelector":FIXTURE_SECURE_SELECTOR,
                "options":{"pixels":false,"pixelFallback":false,"comparable":false}}), 5).await?;
            assert_eq!(fresh["root"]["role"], "document");
            assert_ne!(fresh["revision"], observed["revision"]);
            assert_eq!(broker.health().unwrap().1, ScopeState::Usable);
            fixture.command("scope.end", json!({"identityScope":scope}), 5).await?;
        } else {
            // No reply, including after the raw drain: this must not regain authority.
            let result = result_frame(&mut fixture, sequence).await;
            assert_eq!(result["id"], "trace");
            assert_eq!(result["ok"], false);
            assert_eq!(result["effects"], "unknown");
            assert!(result.get("data").is_none());
            bounded(async {
                while broker.health().unwrap().1 != ScopeState::Quarantined {
                    tokio::task::yield_now().await;
                }
            }).await;
            assert!(targets.inventory().is_err());
            fixture.sequence += 1;
            assert!(matches!(
                broker.admit(1, fixture.sequence, 1000),
                Err(ProtocolError::ScopeUnavailable)
            ));
            // No terminal.close/1 was negotiated: the legacy transport ends
            // with an uncorrelated cleanup error, not a new operation result.
            // Keep result_frame's generation/sequence checks for the trace.
            terminal_failure_frame(&mut fixture).await;
            assert!(bounded(read_frame(&mut fixture.stream)).await.unwrap().is_none());
            assert!(matches!(bounded(browser.page_lease(false)).await, Err(ProtocolError::ScopeUnavailable)));
        }
        }
        assert_eq!(log.lock().unwrap().iter().filter(|r| r["method"] == "Page.captureScreenshot").count(), 1);
        Ok(())
    }.await;
    // Same real EOF/shutdown path as FramedFixture::finish, with owned handles
    // retained so a failed teardown cannot detach tasks or hide peer panics.
    drop(fixture.stream);
    let cleanup = stopped(fixture.server).await;
    let relay_stopped = stopped(relay).await;
    let lifecycle_stopped = stopped(lifecycle).await;
    let cleanup = cleanup.unwrap();
    relay_stopped.unwrap();
    lifecycle_stopped.unwrap();
    test.unwrap();
    if raw_ack {
        assert!(cleanup, "native fixture shutdown was not proven");
    } else {
        assert!(!cleanup, "unacknowledged raw capture cannot prove cleanup");
    }
}

#[tokio::test]
async fn trace_raw_ack_then_restore_past_transport_grace_preserves_owner() {
    trace_retirement_case(true).await;
}

#[tokio::test]
async fn trace_unacknowledged_raw_capture_cannot_regain_owner() {
    trace_retirement_case(false).await;
}

// Isolate the process-wide production sink without changing global env in a
// parallel test process. The child still runs the existing full framed fixture.
#[tokio::test]
async fn trace_timing_success_ack_and_real_restoration_emit_original_sink() {
    const CHILD: &str = "AGENT_BROWSER_CAPTURE_TIMING_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        crate::native::client_settlement_trace::initialize_cleanup();
        trace_retirement_case(true).await;
        trace_timing_case(true, true).await;
        return;
    }
    let file = tempfile::NamedTempFile::new().unwrap();
    let name = "native::client_browser::state_lifecycle_tests::restart_transport_tests::trace_retirement_tests::trace_timing_success_ack_and_real_restoration_emit_original_sink";
    for enabled in [false, true] {
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", name, "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .env_remove("AGENT_BROWSER_ACCEPTANCE_PHASE_FILE")
            .env_remove("AGENT_BROWSER_CLEANUP_DIAGNOSTIC_FILE")
            .kill_on_drop(true);
        if enabled {
            command.env("AGENT_BROWSER_CLEANUP_DIAGNOSTIC_FILE", file.path());
        }
        let mut child = command.spawn().unwrap();
        let status = match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
            Ok(status) => status.unwrap(),
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                panic!("diagnostic child watchdog");
            }
        };
        assert!(status.success(), "diagnostic child failed: {status}");
        let bytes = std::fs::read_to_string(file.path()).unwrap();
        if !enabled {
            assert!(bytes.is_empty(), "opt-out must write zero records");
            continue;
        }
        let rows = bytes
            .lines()
            .map(|line| {
                assert!(line.len() < 512);
                serde_json::from_str::<Value>(line).unwrap()
            })
            .collect::<Vec<_>>();
        let failures = rows
            .iter()
            .filter(|row| row["phase"] == "ScreenshotFirstFailure")
            .collect::<Vec<_>>();
        assert_eq!(
            failures.len(),
            2,
            "late-ACK and post-capture failures must each emit once"
        );
        let late = failures
            .iter()
            .find(|row| row["capturePhase"] == "raw-capture")
            .unwrap();
        let timing = late["timing"].as_array().unwrap();
        assert_eq!(timing.len(), 8);
        for value in &timing[..6] {
            assert!(value.as_u64().is_some_and(|value| value <= 60_000_000));
        }
        assert_eq!(timing[6], 1, "only the exact real success ACK is positive");
        assert_eq!(timing[7], false);
        assert!(timing[3].as_u64().unwrap() >= timing[0].as_u64().unwrap());
        assert!(timing[4].as_u64().unwrap() >= timing[3].as_u64().unwrap());
        assert!(timing[5].as_u64().unwrap() >= timing[4].as_u64().unwrap());
        let post = failures
            .iter()
            .find(|row| row["capturePhase"] == "post-capture-validation")
            .unwrap();
        assert_eq!(post["error"], "policy-denied");
        let timing = post["timing"].as_array().unwrap();
        assert_eq!(timing.len(), 8);
        for index in [0, 1, 2, 4, 5] {
            assert!(timing[index]
                .as_u64()
                .is_some_and(|value| value <= 60_000_000));
        }
        assert!(
            timing[3].is_null(),
            "successful raw capture must not invent an interruption"
        );
        assert_eq!(timing[6], 1);
        assert_eq!(timing[7], false);
        assert!(timing[2].as_u64().unwrap() < timing[0].as_u64().unwrap());
        assert!(timing[4].as_u64().unwrap() >= timing[2].as_u64().unwrap());
        assert!(timing[5].as_u64().unwrap() >= timing[4].as_u64().unwrap());
    }
}
