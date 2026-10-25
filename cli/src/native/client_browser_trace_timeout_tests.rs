//! Real framed ClientBrowser -> Trace dispatch -> borrowed scope.end.
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
    LateCharacterization,
    LateContract,
    PendingClose,
    LateUnnegotiated,
    RestoreRejected,
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

// CDP playbackRate is numeric: restoration serializes the stored f64 as 1.0.
// This finite peer accepts exactly its modeled frozen/restored values, not others.
fn fixture_playback_rate(value: &Value) -> Option<f64> {
    let rate = value.as_f64()?;
    (rate.is_finite() && (rate == 0.0 || rate == 1.0)).then_some(rate)
}

fn check_numeric_peer_contract() {
    assert_eq!(fixture_playback_rate(&json!(0)), Some(0.0));
    assert_eq!(fixture_playback_rate(&json!(0.0)), Some(0.0));
    assert_eq!(fixture_playback_rate(&json!(1)), Some(1.0));
    assert_eq!(fixture_playback_rate(&json!(1.0)), Some(1.0));
    for text in ["-1", "0.5", "2", "\"1\"", "null", "true", "{}", "[]"] {
        let value: Value = serde_json::from_str(text).unwrap();
        assert_eq!(fixture_playback_rate(&value), None);
    }
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
                    let mut rejected = false;
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
                        "DOMSnapshot.captureSnapshot" => json!({"strings":[frame],"documents":[{"frameId":0,"nodes":{"nodeType":[],"backendNodeId":[]}}]}),
                        "Animation.getPlaybackRate" => json!({"playbackRate":1}),
                        "Animation.setPlaybackRate" => {
                            if fixture_playback_rate(&request["params"]["playbackRate"]) == Some(1.0) {
                                if held.is_some() { early.store(true, Ordering::Release); }
                                rejected = case == Case::RestoreRejected;
                            } else { assert_eq!(fixture_playback_rate(&request["params"]["playbackRate"]), Some(0.0)); }
                            json!({})
                        }
                        "Runtime.evaluate" if request["params"]["expression"] == "location.href" => json!({"result":{"type":"string","value":"about:blank"}}),
                        "Runtime.evaluate" => {
                            assert_eq!(session, "host-session");
                            assert_eq!(request["params"]["contextId"], 1);
                            assert!(request["params"]["objectGroup"].as_str().unwrap().starts_with("capture-source-"));
                            source_holder = true;
                            json!({"result":{"type":"object","objectId":"source-holder"}})
                        }
                        "Runtime.callFunctionOn" => {
                            assert_eq!(request["params"]["objectId"], "source-holder");
                            match request["params"]["functionDeclaration"].as_str().unwrap() {
                                "function(){return this.verify()}" => assert!(source_holder),
                                "function(){return this.remove()}" => { if held.is_some() { early.store(true, Ordering::Release); } source_holder=false; },
                                other => panic!("unmodeled source-holder function: {other}"),
                            }
                            json!({"result":{"type":"boolean","value":true}})
                        }
                        "Runtime.releaseObjectGroup" => {
                            let group=request["params"]["objectGroup"].as_str().unwrap();
                            assert!(group.starts_with("capture-"));
                            if group.starts_with("capture-source-") { assert!(!source_holder); }
                            json!({})
                        }
                        "Page.captureScreenshot" => {
                            captures += 1;
                            assert_eq!(captures, 1, "no retry/warmup permitted");
                            assert!(source_holder);
                            assert_eq!(request["params"], json!({"format":"png","fromSurface":true}));
                            if case != Case::Immediate && case != Case::RestoreRejected {
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
                        "Page.enable"|"Runtime.enable"|"Network.enable"|"WebMCP.enable"|"DOM.enable"|"DOM.disable"|"Network.disable"|"Network.setBypassServiceWorker"|"Fetch.enable"|"Fetch.disable"|"Page.setLifecycleEventsEnabled"|"Target.setDiscoverTargets"|"Target.setAutoAttach"|"Runtime.runIfWaitingForDebugger"|"Page.removeScriptToEvaluateOnNewDocument"|"Emulation.setEmulatedMedia"|"Target.detachFromTarget"|"Browser.setDownloadBehavior"|"Animation.enable"|"Animation.disable" => json!({}),
                        other => panic!("unmodeled trace/borrowed cleanup CDP command: {other}: {request}"),
                    };
                    let mut response=if rejected {json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic rate restoration refusal"}})} else {json!({"id":request["id"],"result":result})};
                    if !session.is_empty() { response["sessionId"]=session.into(); }
                    if socket.send(Message::Text(response.to_string())).await.is_err() { break; }
                    if !rejected {
                        if method == "Runtime.callFunctionOn" && request["params"]["functionDeclaration"] == "function(){return this.remove()}" { removed = true; }
                        if method == "Runtime.releaseObjectGroup" && request["params"]["objectGroup"].as_str().is_some_and(|g| g.starts_with("capture-source-")) { released = true; }
                        if method == "Animation.setPlaybackRate" && fixture_playback_rate(&request["params"]["playbackRate"]) == Some(1.0) { rate_restored = true; }
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

async fn next_result(fixture: &mut FramedFixture, id: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        for _ in 0..32 {
            let message = fixture.read().await.unwrap();
            if message["type"] == "result" {
                assert_eq!(message["id"], id);
                return message;
            }
            assert_eq!(message["type"], "event");
            validate_fixture_notice(&message).unwrap();
            let sequence = message["sequence"].as_u64().expect("event sequence");
            assert_eq!(sequence, fixture.event_sequence + 1);
            fixture.event_sequence = sequence;
        }
        panic!("bounded result channel did not yield expected result");
    })
    .await
    .expect("trace result supervisor stalled")
}

async fn run(case: Case) {
    check_numeric_peer_contract();
    let peer = peer(case).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let capabilities = if case == Case::LateUnnegotiated {
        vec!["terminal.close/1".into()]
    } else {
        vec![
            "terminal.close/1".into(),
            crate::native::client_protocol::EXACT_OWNER_CONTINUATION.into(),
        ]
    };
    let mut fixture = FramedFixture::with_capabilities(broker, browser.clone(), capabilities);
    let ready = tokio::time::timeout(Duration::from_secs(2), fixture.read())
        .await
        .expect("hello stalled")
        .unwrap();
    assert_eq!(ready["type"], "ready");
    assert_eq!(ready["scopeState"], "usable");
    assert!(
        ready["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == crate::native::client_protocol::EXACT_OWNER_CONTINUATION),
        "server must support continuation even when this client does not request it"
    );
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
    let (client, targets, blobs) = {
        let owner = browser.owner.lock().await;
        let owner = owner.as_ref().unwrap();
        assert!(!owner.owns_context);
        let runtime = owner.runtime.as_ref().unwrap();
        (
            owner.manager.client.clone(),
            owner.targets.clone(),
            runtime.blobs.clone(),
        )
    };
    let ledger = client.debt_ledger().unwrap();
    assert!(!ledger.snapshot().integrity_lost);
    let mut raw = client.subscribe_raw();
    fixture.sequence += 1;
    let id = format!("trace-{}", fixture.sequence);
    fixture.write(json!({"type":"request","id":id,"generation":1,"operationSeq":fixture.sequence,"timeoutMs":1000,"command":"capture.screenshot","args":{"identityScope":scope,"secureFieldSelector":FIXTURE_SECURE_SELECTOR,"purpose":"trace"}})).await.unwrap();
    let mut pending_end = None;
    let mut pending_clean_before_terminal = false;
    let result = if case == Case::PendingClose {
        // Drive scope.end while capture is still in its retained cleanup window.
        tokio::time::timeout(Duration::from_secs(1), async {
            while !peer
                .log
                .lock()
                .unwrap()
                .iter()
                .any(|r| r["method"] == "Page.captureScreenshot")
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("fixture never reached capture");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(
            !peer.terminal_sent.load(Ordering::Acquire),
            "fixture scheduling missed pending-close window"
        );
        fixture.sequence += 1;
        let end_id = format!("pending-end-{}", fixture.sequence);
        fixture.write(json!({"type":"request","id":end_id,"generation":1,"operationSeq":fixture.sequence,"timeoutMs":10000,"command":"scope.end","args":{"identityScope":scope}})).await.unwrap();
        let mut trace_result = None;
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut frames = 0;
            while trace_result.is_none() || pending_end.is_none() {
                frames += 1;
                assert!(frames <= 32, "pending close frame bound");
                let message = fixture.read().await.unwrap();
                if message["type"] == "event" {
                    validate_fixture_notice(&message).unwrap();
                    let seq = message["sequence"].as_u64().unwrap();
                    assert_eq!(seq, fixture.event_sequence + 1);
                    fixture.event_sequence = seq;
                } else {
                    assert_eq!(message["type"], "result");
                    if message["id"] == id {
                        assert!(trace_result.is_none(), "duplicate trace result");
                        trace_result = Some(message);
                    } else {
                        assert_eq!(message["id"], end_id);
                        assert!(pending_end.is_none(), "duplicate scope.end result");
                        pending_clean_before_terminal = message["ok"] == true
                            && (!peer.terminal_sent.load(Ordering::Acquire)
                                || !peer.restoration_acked.load(Ordering::Acquire));
                        pending_end = Some(message);
                    }
                }
            }
        })
        .await
        .expect("pending scope.end result supervisor stalled");
        trace_result.unwrap()
    } else {
        next_result(&mut fixture, &id).await
    };
    let capture = peer
        .log
        .lock()
        .unwrap()
        .iter()
        .find(|request| request["method"] == "Page.captureScreenshot")
        .expect("trace must reach actual capture dispatch")
        .clone();
    // Read the exact internal raw transport reply, even when the RPC waiter retired.
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
    // raw_tx is broadcast before reader debt settlement. Observe, do not manufacture,
    // the ACK transition. This is a test watchdog, not an operation/cleanup budget.
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
        let handle = result["data"]["handle"]
            .as_str()
            .expect("positive must publish image");
        // Release through public command, not by erasing the producer ledger.
        fixture
            .command(
                "blob.release",
                json!({"identityScope":scope,"handle":handle}),
                1,
            )
            .await
            .unwrap();
    }
    let end = if let Some(message) = pending_end {
        if message["ok"] == true && message["scopeState"] == "usable" {
            Ok(message["data"].clone())
        } else {
            Err(format!("pending scope.end rejected: {message}"))
        }
    } else {
        fixture
            .command("scope.end", json!({"identityScope":scope}), 10)
            .await
    };
    let cleanup = fixture.finish().await;
    let peer_result = tokio::time::timeout(Duration::from_secs(3), peer.task)
        .await
        .expect("peer did not see transport close");
    peer_result.unwrap();
    let commands = peer.log.lock().unwrap().clone();
    assert_eq!(
        commands
            .iter()
            .filter(|r| r["method"] == "Page.captureScreenshot")
            .count(),
        1
    );
    assert!(commands
        .iter()
        .any(|r| r["method"] == "Runtime.callFunctionOn"
            && r["params"]["functionDeclaration"] == "function(){return this.remove()}"));
    assert!(commands
        .iter()
        .any(|r| r["method"] == "Animation.setPlaybackRate"
            && fixture_playback_rate(&r["params"]["playbackRate"]) == Some(1.0)));
    assert!(!commands.iter().any(|r| matches!(
        r["method"].as_str(),
        Some("Browser.close" | "Target.closeTarget" | "Target.disposeBrowserContext")
    )));
    blobs.check_budget_integrity().unwrap();
    // The scope may have retired; no test-side blob insertion/removal is used.
    eprintln!(
        "trace case={case:?} result={result} early_restore={} inventory_ok={inventory_ok} debt={before_close:?} end={end:?} cleanup={cleanup:?}",
        peer.early_restore.load(Ordering::Acquire)
    );
    match case {
        Case::Immediate => {
            assert_eq!(result["ok"], true);
            assert_eq!(result["scopeState"], "usable");
            assert_eq!(raw_image.as_deref(), Some(peer.protected_png.as_str()));
            assert!(end.is_ok());
            assert!(cleanup.is_ok());
        }
        Case::RestoreRejected => {
            assert_eq!(
                raw_image.as_deref(),
                Some(peer.protected_png.as_str()),
                "negative control must first receive a successful protected capture"
            );
            assert_eq!(
                result["error"]["code"], "cleanup-failed",
                "negative control must fail specifically during restoration"
            );
            assert_eq!(result["ok"], false);
            assert!(result.get("data").is_none());
            assert!(end.is_err());
            assert!(cleanup.is_err());
        }
        Case::LateCharacterization => {
            assert_eq!(result["ok"], false);
            assert!(
                peer.early_restore.load(Ordering::Acquire),
                "old-code characterization must observe preterminal restoration"
            );
            assert!(!inventory_ok);
            assert!(end.is_err());
        }
        Case::LateUnnegotiated => {
            assert_eq!(result["ok"], false);
            assert_ne!(
                result["scopeState"], "usable",
                "unnegotiated Unknown must remain conservative"
            );
            assert_eq!(result["effects"], "unknown");
            assert!(
                result.get("retention").is_none(),
                "unnegotiated result must not publish retention"
            );
            assert!(end.is_err());
        }
        Case::PendingClose => {
            let contract = result["ok"] == false
                && result.get("data").is_none()
                && !pending_clean_before_terminal
                && !peer.early_restore.load(Ordering::Acquire)
                && raw_image.as_deref() == Some(peer.protected_png.as_str())
                && end.is_ok()
                && cleanup.is_ok();
            assert!(contract, "P04_PENDING_CLOSE_TERMINAL_OWNERSHIP_CONTRACT");
        }
        Case::LateContract => {
            let contract = result["ok"] == false
                && result.get("data").is_none()
                && matches!(
                    result["error"]["code"].as_str(),
                    Some("deadline-exceeded" | "cancelled")
                )
                && !peer.early_restore.load(Ordering::Acquire)
                && raw_image.as_deref() == Some(peer.protected_png.as_str())
                && inventory_ok
                && !before_close.integrity_lost
                && before_close.outstanding_commands == 0
                && result["scopeState"] == "usable"
                && result["effects"] == "unknown"
                && result
                    .get("retention")
                    .is_some_and(|value| !value.is_null())
                && end.is_ok()
                && cleanup.is_ok();
            assert!(
                contract,
                "P04_OPTIONAL_TIMEOUT_RETAINED_CONTINUATION_CONTRACT"
            );
        }
    }
}

#[tokio::test]
async fn trace_timeout_immediate_positive_closes_borrowed_scope() {
    run(Case::Immediate).await;
}
#[tokio::test]
async fn trace_timeout_late_reply_characterizes_existing_quarantine() {
    run(Case::LateCharacterization).await;
}
#[tokio::test]
async fn trace_timeout_late_reply_keeps_source_until_terminal_and_closes_scope() {
    run(Case::LateContract).await;
}
#[tokio::test]
async fn trace_timeout_rate_restore_rejection_remains_hard_failure() {
    run(Case::RestoreRejected).await;
}

#[tokio::test]
async fn trace_timeout_without_continuation_negotiation_stays_quarantined() {
    run(Case::LateUnnegotiated).await;
}

#[tokio::test]
async fn trace_timeout_pending_scope_end_waits_for_terminal_cleanup() {
    run(Case::PendingClose).await;
}
