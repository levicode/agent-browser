//! Real framed Observe -> pointer -> Trace. Prior no-Observe RED remains separate evidence.
//! The finite peer models source-holder ownership, not renderer pixel fidelity.
//! An internal raw subscriber proves transport visibility, not public DevTools reachability.
use super::*;
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Immediate,
    NativeDeadline,
    ClientCancel,
}

struct Peer {
    endpoint: String,
    log: Arc<Mutex<Vec<Value>>>,
    early_restore: Arc<AtomicBool>,
    terminal_sent: Arc<AtomicBool>,
    restoration_acked: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
    protected_png: String,
}

fn png(color: [u8; 4]) -> String {
    let mut bytes = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(10, 10, image::Rgba(color)))
        .write_to(&mut bytes, image::ImageFormat::Png)
        .unwrap();
    base64::engine::general_purpose::STANDARD.encode(bytes.into_inner())
}

async fn peer(case: Case) -> Peer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let recorded = log.clone();
    let early_restore = Arc::new(AtomicBool::new(false));
    let early = early_restore.clone();
    let terminal_sent = Arc::new(AtomicBool::new(false));
    let terminal = terminal_sent.clone();
    let restoration_acked = Arc::new(AtomicBool::new(false));
    let restored = restoration_acked.clone();
    let protected_png = png([0, 0, 0, 255]);
    let protected = protected_png.clone();
    // Synthetic marker only; no real private pixels exist in this test.
    let unprotected = png([255, 0, 255, 255]);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let target = json!({"targetId":"host-page","type":"page","browserContextId":"host-context","url":"about:blank","title":""});
        let frame = "frame-host-session";
        let mut loader = "host-loader";
        let mut source_holder = false;
        let (mut removed, mut released, mut rate_restored) = (false, false, false);
        let mut captures = 0;
        let mut held: Option<Value> = None;
        let (release_tx, mut release_rx) = mpsc::unbounded_channel::<()>();
        let mut release_job = None;
        loop {
            tokio::select! {
                signal = release_rx.recv(), if held.is_some() => {
                    signal.expect("release owner remains alive");
                    let request = held.take().unwrap();
                    terminal.store(true, Ordering::Release);
                    let data = if source_holder { &protected } else { &unprotected };
                    if socket.send(Message::Text(json!({"id":request["id"],"sessionId":request["sessionId"],"result":{"data":data}}).to_string())).await.is_err() { break; }
                }
                message = socket.next() => {
                    let Some(Ok(Message::Text(text))) = message else { break; };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    recorded.lock().unwrap().push(request.clone());
                    let method = request["method"].as_str().unwrap();
                    let session = request["sessionId"].as_str().unwrap_or("");
                    let rejected = false;
                    let result = match method {
                        "Browser.getVersion" => json!({"protocolVersion":"1.3","product":"Synthetic Chromium/1.0","revision":"synthetic","userAgent":"Synthetic Chromium Linux","jsVersion":"synthetic"}),
                        "Target.getBrowserContexts" => json!({"browserContextIds":[],"defaultBrowserContextId":"host-context"}),
                        "Target.getTargets" => json!({"targetInfos":[target.clone()]}),
                        "Target.getTargetInfo" => { assert_eq!(request["params"]["targetId"], "host-page"); json!({"targetInfo":target.clone()}) },
                        "Target.attachToTarget" => { assert_eq!(request["params"]["targetId"], "host-page"); json!({"sessionId":"host-session"}) },
                        "Page.getFrameTree" => json!({"frameTree":{"frame":{"id":frame,"loaderId":loader,"url":"about:blank"}}}),
                        "Page.navigate" => { assert_eq!(request["params"]["url"], "about:blank"); loader="activation-loader"; json!({"frameId":frame,"loaderId":loader}) },
                        "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":format!("script-{}",request["id"])}),
                        "Page.createIsolatedWorld" => { assert_eq!(request["params"]["frameId"], frame); json!({"executionContextId":1}) },
                        "Page.getLayoutMetrics" => json!({"cssVisualViewport":{"clientWidth":10,"clientHeight":10,"scale":1,"offsetX":0,"offsetY":0},"cssLayoutViewport":{"clientWidth":10,"clientHeight":10}}),
                        "DOM.getDocument" => json!({"root":{"nodeType":9,"backendNodeId":1}}),
                        "DOMSnapshot.captureSnapshot" => json!({"strings":[frame],"documents":[{"frameId":0,"nodes":{"nodeType":[9],"backendNodeId":[1]}}]}),
                        "Animation.getPlaybackRate" => json!({"playbackRate":1}),
                        "Animation.setPlaybackRate" => {
                            if request["params"]["playbackRate"].as_f64().is_some_and(|rate| rate.is_finite() && rate == 1.0) {
                                if held.is_some() { early.store(true, Ordering::Release); }
                            } else { assert_eq!(request["params"]["playbackRate"].as_f64(), Some(0.0)); rate_restored = false; }
                            json!({})
                        }
                        "Runtime.evaluate" if request["params"]["expression"] == "location.href" => json!({"result":{"type":"string","value":"about:blank"}}),
                        "Runtime.evaluate" => {
                            assert_eq!(session, "host-session");
                            assert_eq!(request["params"]["contextId"], 1);
                            assert!(request["params"]["objectGroup"].as_str().unwrap().starts_with("capture-source-"));
                            source_holder = true;
                            removed = false; released = false;
                            json!({"result":{"type":"object","objectId":"source-holder"}})
                        }
                        "Runtime.callFunctionOn" => {
                            let declaration = request["params"]["functionDeclaration"].as_str().unwrap();
                            if request["params"]["objectId"] == "source-holder" {
                                match declaration {
                                    "function(){return this.verify()}" => assert!(source_holder),
                                    "function(){return this.remove()}" => { if held.is_some() { early.store(true, Ordering::Release); } source_holder = false; },
                                    "function(selector,...nodes){return this.install(selector,nodes)}" => { assert!(source_holder); },
                                    other => panic!("unmodeled source-holder call: {other}"),
                                }
                            }
                            observation_reply(&request).expect("known Observe/source-mask protocol")
                        }
                        "Runtime.releaseObjectGroup" => {
                            let group=request["params"]["objectGroup"].as_str().unwrap();
                            if group.starts_with("capture-source-") { assert!(!source_holder); }
                            json!({})
                        }
                        "Page.captureScreenshot" => {
                            captures += 1;
                            assert_eq!(captures, 1, "no retry/warmup permitted");
                            assert!(source_holder);
                            assert_eq!(request["params"], json!({"format":"png","fromSurface":true}));
                            if case != Case::Immediate {
                                assert!(held.is_none());
                                held=Some(request.clone());
                                let release=release_tx.clone();
                                release_job=Some(tokio::spawn(async move {
                                    // Scheduling a late peer reply is NOT a larger operation budget.
                                    // Start after capture receipt, so this is beyond original 1s + 250ms.
                                    tokio::time::sleep(Duration::from_millis(1600)).await;
                                    release.send(()).unwrap();
                                }));
                                continue;
                            }
                            json!({"data":protected})
                        }
                        "Accessibility.getFullAXTree" => { assert_eq!(session, "host-session"); assert_eq!(request["params"]["frameId"], frame); observation_reply(&request).unwrap() },
                        "DOM.resolveNode" => { assert_eq!(session, "host-session"); assert_eq!(request["params"]["backendNodeId"], 1); assert_eq!(request["params"]["executionContextId"], 1); observation_reply(&request).unwrap() },
                        "Runtime.getProperties"|"Runtime.releaseObject" => { assert_eq!(session, "host-session"); observation_reply(&request).expect("known Observe method") },
                        "Input.dispatchMouseEvent" => { assert_eq!(session, "host-session"); assert!(matches!(request["params"]["type"].as_str(), Some("mouseMoved"|"mousePressed"|"mouseReleased"))); json!({}) },
                        "Page.enable"|"Runtime.enable"|"Network.enable"|"WebMCP.enable"|"DOM.enable"|"DOM.disable"|"Network.disable"|"Network.setBypassServiceWorker"|"Fetch.enable"|"Fetch.disable"|"Page.setLifecycleEventsEnabled"|"Target.setDiscoverTargets"|"Target.setAutoAttach"|"Runtime.runIfWaitingForDebugger"|"Page.removeScriptToEvaluateOnNewDocument"|"Emulation.setEmulatedMedia"|"Target.detachFromTarget"|"Browser.setDownloadBehavior"|"Animation.enable"|"Animation.disable" => json!({}),
                        other => panic!("unmodeled trace/borrowed cleanup CDP command: {other}: {request}"),
                    };
                    let mut response=if rejected {json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic rate restoration refusal"}})} else {json!({"id":request["id"],"result":result})};
                    if !session.is_empty() { response["sessionId"]=session.into(); }
                    if socket.send(Message::Text(response.to_string())).await.is_err() { break; }
                    if !rejected {
                        if method == "Runtime.callFunctionOn" && request["params"]["functionDeclaration"] == "function(){return this.remove()}" { removed = true; }
                        if method == "Runtime.releaseObjectGroup" && request["params"]["objectGroup"].as_str().is_some_and(|g| g.starts_with("capture-source-")) { released = true; }
                        if method == "Animation.setPlaybackRate" && request["params"]["playbackRate"].as_f64().is_some_and(|rate| rate.is_finite() && rate == 1.0) { rate_restored = true; }
                        restored.store(removed && released && rate_restored, Ordering::Release);
                    }
                    if method == "Page.navigate" {
                        for event in [json!({"method":"Page.frameNavigated","sessionId":session,"params":{"frame":{"id":frame,"loaderId":loader,"url":"about:blank","securityOrigin":"null"}}}),json!({"method":"Page.lifecycleEvent","sessionId":session,"params":{"frameId":frame,"loaderId":loader,"name":"DOMContentLoaded"}})] {
                            socket.send(Message::Text(event.to_string())).await.unwrap();
                        }
                    }
                    if method == "Target.detachFromTarget" && !rejected {
                        assert_eq!(request["params"]["sessionId"], "host-session");
                        socket.send(Message::Text(json!({"method":"Target.detachedFromTarget","params":{"sessionId":"host-session","targetId":"host-page"}}).to_string())).await.unwrap();
                    }
                }
            }
        }
        if let Some(job) = release_job {
            job.await.unwrap();
        }
    });
    Peer {
        endpoint,
        log,
        early_restore,
        terminal_sent,
        restoration_acked,
        task,
        protected_png,
    }
}

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
            json!({"strings":["frame-host-session"],"documents":[{"frameId":0,"nodes":{"nodeType":[9],"backendNodeId":[1]}}]})
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
                    .and_then(|group| group.strip_suffix("-frame-host-session"))
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

fn required_capabilities() -> Vec<String> {
    // Exact e2e 5adcc packages/web/src/native/capabilities.ts REQUIRED_CAPABILITIES.
    [
        "operation.continue-exact-owner/1",
        "scope.reconnect-quarantined/1",
        "terminal.close/1",
        "browser.scope/1",
        "browser.lifecycle/1",
        "browser.evaluate/1",
        "browser.page/1",
        "browser.observe/1",
        "browser.query/1",
        "browser.actions/1",
        "browser.network/1",
        "browser.fixture-read-fields/1",
        "browser.dialog/1",
        "browser.download/1",
        "browser.capture/1",
        "browser.state/1",
        "browser.recording/1",
        "browser.blobs/1",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

async fn trace_and_control(
    fixture: &mut FramedFixture,
    trace_id: &str,
    cancel_id: Option<&str>,
) -> (Value, Option<Value>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut result = None;
        let mut control = None;
        for _ in 0..64 {
            let frame = fixture.read().await.expect("trace/control stream ended");
            assert_eq!(frame["generation"], 1);
            match frame["type"].as_str() {
                Some("result") => {
                    assert_eq!(frame["id"], trace_id);
                    assert!(result.is_none());
                    result = Some(frame);
                }
                Some("control-result") => {
                    assert_eq!(frame["id"].as_str(), cancel_id);
                    assert!(control.is_none());
                    assert!(frame["accepted"].is_boolean());
                    control = Some(frame);
                }
                Some("event") => {
                    validate_fixture_notice(&frame).unwrap();
                    let sequence = frame["sequence"].as_u64().unwrap();
                    assert_eq!(sequence, fixture.event_sequence + 1);
                    fixture.event_sequence = sequence;
                }
                other => panic!("unexpected trace/control frame: {other:?}: {frame}"),
            }
            if result.is_some() && (cancel_id.is_none() || control.is_some()) {
                return (result.unwrap(), control);
            }
        }
        panic!("trace/control frame count exhausted")
    })
    .await
    .expect("trace/control result stalled")
}

async fn run(case: Case) {
    use crate::native::client_capture::{retained_capture_test, CaptureReason};
    let peer = peer(case).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture =
        FramedFixture::with_capabilities(broker, browser.clone(), required_capabilities());
    let ready = tokio::time::timeout(Duration::from_secs(2), fixture.read())
        .await
        .expect("hello timeout")
        .unwrap();
    assert_eq!(ready["type"], "ready");
    assert_eq!(ready["id"], "fixture-hello");
    assert_eq!(ready["protocol"], PROTOCOL);
    assert_eq!(ready["generation"], 1);
    assert_eq!(ready["scopeState"], "usable");
    for required in required_capabilities() {
        assert!(
            ready["capabilities"]
                .as_array()
                .unwrap()
                .contains(&json!(required)),
            "ready omitted required capability"
        );
    }
    let opened = fixture
        .command(
            "scope.open",
            json!({"source":"connect","context":"persistent","endpoint":peer.endpoint}),
            10,
        )
        .await
        .unwrap();
    let scope = opened["identityScope"].as_str().unwrap().to_owned();
    fixture.scope = Some(scope.clone());
    fixture
        .command("scope.configure", fixture_configuration(&scope, None), 10)
        .await
        .unwrap();
    fixture
        .command("network.routes.replace", fixture_routes(&scope), 10)
        .await
        .unwrap();
    fixture.registry = 1;
    fixture
        .command("page.activate", json!({"identityScope":scope}), 10)
        .await
        .unwrap();
    {
        let page = browser.page_lease(false).await.unwrap();
        assert_eq!(
            browser
                .observation
                .capture_sequence_for_test(&page, 1)
                .unwrap(),
            None
        );
    }
    let observed = fixture
        .command(
            "browser.observe",
            json!({"identityScope":scope,
        "testIdAttribute":"data-testid", "secureFieldSelector":FIXTURE_SECURE_SELECTOR,
        "options":{}}),
            10,
        )
        .await
        .unwrap();
    let observed_sequence = fixture.sequence;
    assert_eq!(observed["root"]["role"], "document");
    assert!(observed["revision"].is_string());
    assert!(observed["viewportRef"]["id"].is_string());
    assert!(!peer
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["method"] == "Page.captureScreenshot"));
    {
        let page = browser.page_lease(false).await.unwrap();
        assert_eq!(
            browser
                .observation
                .capture_sequence_for_test(&page, 1)
                .unwrap(),
            Some(observed_sequence)
        );
    }
    // Original recovered P04: observe -> direct point tap -> optional trace.
    fixture
        .command(
            "browser.pointer",
            json!({"identityScope":scope,"point":{"x":1,"y":1},"action":{"kind":"tap"}}),
            10,
        )
        .await
        .unwrap();
    let input_types: Vec<String> = peer
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["method"] == "Input.dispatchMouseEvent")
        .map(|r| r["params"]["type"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(input_types, ["mouseMoved", "mousePressed", "mouseReleased"]);
    let (client, targets, blobs) = {
        let page = browser.page_lease(false).await.unwrap();
        assert_eq!(
            browser
                .observation
                .capture_sequence_for_test(&page, 1)
                .unwrap(),
            Some(observed_sequence)
        );
        let owner = browser.owner.lock().await;
        let owner = owner.as_ref().unwrap();
        assert!(!owner.owns_context);
        (
            page.client.clone(),
            page.targets.clone(),
            owner.runtime.as_ref().unwrap().blobs.clone(),
        )
    };
    let ledger = client.debt_ledger().unwrap();
    assert_eq!(ledger.snapshot().outstanding_commands, 0);
    assert!(!ledger.snapshot().integrity_lost);
    let mut raw = client.subscribe_raw();
    fixture.sequence += 1;
    let sequence = fixture.sequence;
    assert!(sequence > observed_sequence);
    let (_registration, retained) = retained_capture_test::register(&client, sequence);
    let started = Instant::now();
    let trace_id = "observe-trace";
    fixture
        .write(
            json!({"type":"request","id":trace_id,"generation":1,"operationSeq":sequence,
        "timeoutMs":1000,"command":"capture.screenshot","args":{"identityScope":scope,
        "secureFieldSelector":FIXTURE_SECURE_SELECTOR,"purpose":"trace"}}),
        )
        .await
        .unwrap();
    let cancel_id = if case == Case::ClientCancel {
        // Same original1s budget. Native deadline may win this race: record
        // accepted=false truthfully, do not claim an isolated cancellation cause.
        // This is a real client control frame, never native signal injection.
        tokio::time::sleep_until((started + Duration::from_millis(1000)).into()).await;
        fixture
            .write(
                json!({"type":"cancel","id":"trace-cancel","generation":1,"operationSeq":sequence}),
            )
            .await
            .unwrap();
        Some("trace-cancel")
    } else {
        None
    };
    let retained_entered = if case == Case::Immediate {
        None
    } else {
        Some(
            tokio::time::timeout(Duration::from_secs(2), retained)
                .await
                .expect("fixture never entered active-retirement raw branch")
                .expect("retained witness lost"),
        )
    };
    if let Some(reason) = retained_entered {
        assert!(matches!(
            reason,
            CaptureReason::Deadline | CaptureReason::Cancelled
        ));
    }
    let (result, cancel_ack) = trace_and_control(&mut fixture, trace_id, cancel_id).await;
    let result_elapsed = started.elapsed();
    let capture = peer
        .log
        .lock()
        .unwrap()
        .iter()
        .find(|r| r["method"] == "Page.captureScreenshot")
        .unwrap()
        .clone();
    let raw_image = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let message = match raw.recv().await {
                Ok(message) => message,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                Err(error) => panic!("raw evidence lost: {error}"),
            };
            let value: Value = serde_json::from_str(&message.text).unwrap();
            if value["id"] == capture["id"] && value["sessionId"] == capture["sessionId"] {
                return Some(
                    value["result"]["data"]
                        .as_str()
                        .expect("capture PNG")
                        .to_owned(),
                );
            }
        }
    })
    .await
    .ok()
    .flatten();
    if raw_image.is_some() {
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            while ledger.snapshot().outstanding_commands != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
    }
    let before_close = ledger.snapshot();
    let inventory_ok = targets.inventory().is_ok();
    if case == Case::Immediate {
        fixture
            .command(
                "blob.release",
                json!({"identityScope":scope,"handle":result["data"]["handle"]}),
                1,
            )
            .await
            .unwrap();
    }
    let end = fixture
        .command("scope.end", json!({"identityScope":scope}), 10)
        .await;
    let cleanup = fixture.finish().await;
    tokio::time::timeout(Duration::from_secs(3), peer.task)
        .await
        .expect("peer transport did not close")
        .unwrap();
    let log = peer.log.lock().unwrap();
    assert_eq!(
        log.iter()
            .filter(|r| r["method"] == "Page.captureScreenshot")
            .count(),
        1
    );
    assert!(!log.iter().any(|r| matches!(
        r["method"].as_str(),
        Some("Browser.close" | "Target.closeTarget" | "Target.disposeBrowserContext")
    )));
    blobs.check_budget_integrity().unwrap();
    let early_restore = peer.early_restore.load(Ordering::Acquire);
    // Evidence comes BEFORE desired-contract assertions. No assumed quarantine.
    eprintln!("P04_OBSERVE_TRACE_EVIDENCE case={case:?} observe_sequence={observed_sequence} trace_sequence={sequence} retained_entered={retained_entered:?} elapsed_ms={} result={result} cancel_ack={cancel_ack:?} early_restore={early_restore} raw_seen={} protected_raw={} inventory_ok={inventory_ok} debt={before_close:?} end={end:?} cleanup={cleanup:?}",
        result_elapsed.as_millis(), raw_image.is_some(), raw_image.as_deref() == Some(peer.protected_png.as_str()));
    if case == Case::Immediate {
        assert_eq!(result["ok"], true);
        assert_eq!(result["scopeState"], "usable");
        assert_eq!(raw_image.as_deref(), Some(peer.protected_png.as_str()));
        assert!(end.is_ok() && cleanup.is_ok());
    } else {
        let contract = result["ok"] == false
            && result.get("data").is_none()
            && !early_restore
            && raw_image.as_deref() == Some(peer.protected_png.as_str())
            && matches!(
                result["error"]["code"].as_str(),
                Some("cancelled" | "deadline-exceeded")
            )
            && result["effects"] == "unknown"
            && result["scopeState"] == "usable"
            && result
                .get("retention")
                .is_some_and(|value| !value.is_null())
            && inventory_ok
            && !before_close.integrity_lost
            && before_close.outstanding_commands == 0
            && end.is_ok()
            && cleanup.is_ok();
        assert!(
            contract,
            "P04_OBSERVE_TRACE_SOURCE_OWNERSHIP_AND_CLEAN_CLOSE_CONTRACT"
        );
    }
}

#[tokio::test]
async fn observe_pointer_trace_immediate_positive() {
    run(Case::Immediate).await;
}
#[tokio::test]
async fn observe_pointer_trace_native_deadline_records_then_checks_contract() {
    run(Case::NativeDeadline).await;
}
#[tokio::test]
async fn observe_pointer_trace_client_cancel_ack_records_then_checks_contract() {
    run(Case::ClientCancel).await;
}

#[test]
fn observe_peer_ax_schema_and_omitted_flags_match_real_protocol() {
    let value = observation_reply(&json!({"method":"Accessibility.getFullAXTree"})).unwrap();
    let tree: crate::native::cdp::types::GetFullAXTreeResult =
        serde_json::from_value(value).unwrap();
    assert_eq!(tree.nodes.len(), 1);
    assert_eq!(
        tree.nodes[0].role.as_ref().unwrap().value,
        Some(json!("RootWebArea"))
    );
    let request: crate::native::client_observation_dispatch::ObserveRequest = serde_json::from_value(json!({
        "testIdAttribute":"data-testid","secureFieldSelector":FIXTURE_SECURE_SELECTOR,"options":{}
    })).unwrap();
    assert!(
        !request.options.pixels && !request.options.pixel_fallback && !request.options.comparable
    );
    for (value, expected) in [
        (json!(1), Some(1.0)),
        (json!(1.0), Some(1.0)),
        (json!(0), Some(0.0)),
        (json!(0.0), Some(0.0)),
        (json!("1"), None),
        (Value::Null, None),
    ] {
        assert_eq!(value.as_f64().filter(|rate| rate.is_finite()), expected);
    }
}
