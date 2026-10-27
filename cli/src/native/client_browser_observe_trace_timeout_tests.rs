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
    OptionalRawHeld,
    OptionalRawNeverAck,
    MetadataReleaseHeld,
    SemanticGeometryReleaseHeld,
    SemanticFrameOwnerReleaseHeld,
    OptionalMaskHeld,
    OptionalWrongSessionHeld,
    OptionalMalformedHeld,
    SemanticCorruption,
    OptionalRestoreFailure,
}

struct Peer {
    endpoint: String,
    log: Arc<Mutex<Vec<Value>>>,
    early_restore: Arc<AtomicBool>,
    terminal_sent: Arc<AtomicBool>,
    restoration_acked: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
    protected_png: String,
    release: mpsc::UnboundedSender<()>,
    disconnect: tokio::sync::oneshot::Sender<()>,
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
    let (release_tx, mut release_rx) = mpsc::unbounded_channel::<()>();
    let peer_release = release_tx.clone();
    let (disconnect, mut disconnect_rx) = tokio::sync::oneshot::channel();
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
        let mut readonly_held_once = false;
        let mut release_job = None;
        loop {
            tokio::select! {
                // Test peer teardown only. EOF is not a synthetic capture ACK
                // and supplies no protection-restoration or clean-close proof.
                _ = &mut disconnect_rx => break,
                signal = release_rx.recv(), if held.is_some() => {
                    signal.expect("release owner remains alive");
                    let request = held.take().unwrap();
                    let raw = request["method"] == "Page.captureScreenshot";
                    if raw { terminal.store(true, Ordering::Release); }
                    let data = if source_holder { &protected } else { &unprotected };
                    let result = if raw {
                        if case == Case::OptionalMalformedHeld { json!({"data":42}) } else { json!({"data":data}) }
                    } else { observation_reply(&request).expect("known held readonly command") };
                    let session = if raw && case == Case::OptionalWrongSessionHeld { json!("wrong-session") } else { request["sessionId"].clone() };
                    if socket.send(Message::Text(json!({"id":request["id"],"sessionId":session,"result":result}).to_string())).await.is_err() { break; }
                }
                message = socket.next() => {
                    let Some(Ok(Message::Text(text))) = message else { break; };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    recorded.lock().unwrap().push(request.clone());
                    let method = request["method"].as_str().unwrap();
                    let session = request["sessionId"].as_str().unwrap_or("");
                    let rejected = case == Case::OptionalRestoreFailure && method == "Animation.setPlaybackRate"
                        && request["params"]["playbackRate"].as_f64() == Some(1.0);
                    let result = match method {
                        "Browser.getVersion" => json!({"protocolVersion":"1.3","product":"Synthetic Chromium/1.0","revision":"synthetic","userAgent":"Synthetic Chromium Linux","jsVersion":"synthetic"}),
                        "Target.getBrowserContexts" => json!({"browserContextIds":[],"defaultBrowserContextId":"host-context"}),
                        "Target.getTargets" => json!({"targetInfos":[target.clone()]}),
                        "Target.getTargetInfo" => { assert_eq!(request["params"]["targetId"], "host-page"); json!({"targetInfo":target.clone()}) },
                        "Target.attachToTarget" => { assert_eq!(request["params"]["targetId"], "host-page"); json!({"sessionId":"host-session"}) },
                        "Page.getFrameTree" => {
                            let mut root=json!({"frame":{"id":frame,"loaderId":loader,"url":"about:blank"}});
                            if case == Case::SemanticFrameOwnerReleaseHeld { root["childFrames"]=json!([{"frame":{"id":"child-frame","parentId":frame,"loaderId":"child-doc","url":"about:blank"}}]); }
                            json!({"frameTree":root})
                        },
                        "Page.navigate" => { assert_eq!(request["params"]["url"], "about:blank"); loader="activation-loader"; json!({"frameId":frame,"loaderId":loader}) },
                        "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":format!("script-{}",request["id"])}),
                        "Page.createIsolatedWorld" => {
                            if case == Case::SemanticFrameOwnerReleaseHeld && request["params"]["frameId"] == "child-frame" { json!({"executionContextId":2}) }
                            else { assert_eq!(request["params"]["frameId"], frame); json!({"executionContextId":1}) }
                        },
                        "Page.getLayoutMetrics" => json!({"cssVisualViewport":{"clientWidth":10,"clientHeight":10,"scale":1,"offsetX":0,"offsetY":0},"cssLayoutViewport":{"clientWidth":10,"clientHeight":10}}),
                        "DOM.getDocument" => if case == Case::SemanticFrameOwnerReleaseHeld { json!({"root":{"nodeType":9,"backendNodeId":1,"childNodeCount":1,"children":[{"nodeType":1,"backendNodeId":2,"localName":"iframe","attributes":["id","child"],"childNodeCount":0,"children":[]}]}}) } else if case == Case::SemanticGeometryReleaseHeld { json!({"root":{"nodeType":9,"backendNodeId":1,"childNodeCount":1,"children":[{"nodeType":1,"backendNodeId":2,"localName":"button","attributes":[],"childNodeCount":0,"children":[]}]}}) } else { json!({"root":{"nodeType":9,"backendNodeId":1}}) },
                        "DOM.getFrameOwner" if case == Case::SemanticFrameOwnerReleaseHeld => { assert_eq!(request["params"]["frameId"], "child-frame"); json!({"backendNodeId":2}) },
                        "DOM.describeNode" if case == Case::SemanticFrameOwnerReleaseHeld => {
                            match request["params"]["backendNodeId"].as_u64().unwrap() {
                                2 => json!({"node":{"nodeType":1,"backendNodeId":2,"contentDocument":{"nodeType":9,"backendNodeId":3}}}),
                                3 => json!({"node":{"nodeType":9,"backendNodeId":3,"childNodeCount":0,"children":[]}}),
                                other => panic!("unexpected child document backend {other}"),
                            }
                        },
                        "DOMSnapshot.captureSnapshot" => {
                            if case == Case::OptionalMaskHeld { assert!(held.replace(request.clone()).is_none()); continue; }
                            json!({"strings":[frame],"documents":[{"frameId":0,"nodes":{"nodeType":[9],"backendNodeId":[1]}}]})
                        },
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
                            if case == Case::SemanticFrameOwnerReleaseHeld {
                                semantic_frame_reply(&request).unwrap_or_else(|| observation_reply(&request).expect("known semantic frame protocol"))
                            } else if case == Case::SemanticGeometryReleaseHeld {
                                semantic_geometry_reply(&request).unwrap_or_else(|| observation_reply(&request).expect("known semantic geometry protocol"))
                            } else if case == Case::SemanticCorruption && declaration.contains("const read=") {
                                json!({"result":{"value":[]}})
                            } else { observation_reply(&request).expect("known Observe/source-mask protocol") }
                        }
                        "Runtime.releaseObjectGroup" => {
                            let group=request["params"]["objectGroup"].as_str().unwrap();
                            if group.starts_with("capture-source-") { assert!(!source_holder); }
                            if ((case == Case::MetadataReleaseHeld && group.starts_with("native-metadata-"))
                                || (case == Case::SemanticGeometryReleaseHeld && group.starts_with("native-semantic-box-"))
                                || (case == Case::SemanticFrameOwnerReleaseHeld && group.starts_with("native-frame-owner-"))) && !readonly_held_once {
                                readonly_held_once = true;
                                assert!(held.replace(request.clone()).is_none());
                                continue;
                            }
                            json!({})
                        }
                        "Page.captureScreenshot" => {
                            captures += 1;
                            assert_eq!(captures, 1, "no retry/warmup permitted");
                            assert!(source_holder);
                            assert_eq!(request["params"], json!({"format":"png","fromSurface":true}));
                            if !matches!(case, Case::Immediate | Case::OptionalRestoreFailure) {
                                assert!(held.is_none());
                                held=Some(request.clone());
                                let release=release_tx.clone();
                                if matches!(case, Case::NativeDeadline | Case::ClientCancel) { release_job=Some(tokio::spawn(async move {
                                    // Scheduling a late peer reply is NOT a larger operation budget.
                                    // Start after capture receipt, so this is beyond original 1s + 250ms.
                                    tokio::time::sleep(Duration::from_millis(1600)).await;
                                    release.send(()).unwrap();
                                })); }
                                continue;
                            }
                            json!({"data":protected})
                        }
                        "Accessibility.getFullAXTree" => { assert_eq!(session, "host-session"); if case == Case::SemanticFrameOwnerReleaseHeld { semantic_frame_reply(&request).unwrap() } else { assert_eq!(request["params"]["frameId"], frame); if case == Case::SemanticGeometryReleaseHeld { semantic_geometry_reply(&request).unwrap() } else { observation_reply(&request).unwrap() } } },
                        "DOM.resolveNode" => { assert_eq!(session, "host-session"); if case == Case::SemanticFrameOwnerReleaseHeld { semantic_frame_reply(&request).unwrap() } else { assert_eq!(request["params"]["executionContextId"], 1); if case == Case::SemanticGeometryReleaseHeld { semantic_geometry_reply(&request).unwrap() } else { assert_eq!(request["params"]["backendNodeId"], 1); observation_reply(&request).unwrap() } } },
                        "DOM.getBoxModel" if case == Case::SemanticGeometryReleaseHeld => json!({"model":{"border":[1,1,5,1,5,5,1,5]}}),
                        "DOM.getBoxModel" if case == Case::SemanticFrameOwnerReleaseHeld => json!({"model":{"border":[0,0,6,0,6,6,0,6],"content":[0,0,6,0,6,6,0,6]}}),
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
        release: peer_release,
        disconnect,
    }
}

// Same-process child document: no detached-target or renderer enrollment is
// fabricated. Inventory must preserve both native documents with owner debt.
fn semantic_frame_reply(request: &Value) -> Option<Value> {
    match request["method"].as_str()? {
        "Accessibility.getFullAXTree" => {
            if request["params"]["frameId"] == "child-frame" {
                Some(
                    json!({"nodes":[{"nodeId":"child-document","backendDOMNodeId":3,"role":{"type":"role","value":"RootWebArea"}}]}),
                )
            } else {
                Some(json!({"nodes":[
                    {"nodeId":"document","backendDOMNodeId":1,"childIds":["iframe"],"role":{"type":"role","value":"RootWebArea"}},
                    {"nodeId":"iframe","parentId":"document","backendDOMNodeId":2,"role":{"type":"role","value":"Iframe"}}
                ]}))
            }
        }
        "DOM.resolveNode" => {
            let backend = request["params"]["backendNodeId"].as_u64().unwrap();
            assert!(matches!(backend, 1..=3));
            assert_eq!(
                request["params"]["executionContextId"],
                if backend == 3 { 2 } else { 1 }
            );
            let group = request["params"]["objectGroup"].as_str().unwrap();
            Some(
                json!({"object":{"type":"object","subtype":"node","objectId":format!("{group}-node-{backend}")}}),
            )
        }
        "Runtime.callFunctionOn" => {
            let declaration = request["params"]["functionDeclaration"].as_str()?;
            if declaration == crate::native::client_observation::FRAME_OWNER_GEOMETRY {
                Some(json!({"result":{"value":{"x":0,"y":0,"selector":"#child"}}}))
            } else if declaration.contains("const read=") {
                let values=request["params"]["arguments"].as_array().unwrap().iter().skip(2).map(|argument| {
                    if argument["objectId"].as_str().unwrap().ends_with("node-2") {
                        json!({"attributes":{"id":"child"},"labels":[],"states":{},"rect":{"x":0,"y":0,"width":6,"height":6},"author":{"tag":"iframe","nodeType":1,"visible":true}})
                    } else { json!({"attributes":{},"labels":[],"states":{},"rect":null,"author":{"nodeType":9,"visible":true}}) }
                }).collect::<Vec<_>>();
                Some(json!({"result":{"value":values}}))
            } else if request["params"]["objectGroup"]
                .as_str()
                .is_some_and(|group| group.starts_with("native-semantic-box-"))
            {
                if declaration.contains("frameOwner") {
                    Some(
                        json!({"result":{"value":{"connected":true,"frameOwner":true,"width":6,"height":6}}}),
                    )
                } else {
                    Some(json!({"result":{"value":true}}))
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

// A complete native semantic tree with an actual element rectangle, ensuring
// browser.observe reaches semantic BOX_PROOF rather than the document-only path.
fn semantic_geometry_reply(request: &Value) -> Option<Value> {
    match request["method"].as_str()? {
        "Accessibility.getFullAXTree" => Some(json!({"nodes":[
            {"nodeId":"document","backendDOMNodeId":1,"childIds":["button"],"role":{"type":"role","value":"RootWebArea"}},
            {"nodeId":"button","parentId":"document","backendDOMNodeId":2,"role":{"type":"role","value":"button"},"name":{"type":"computedString","value":"Submit"}}
        ]})),
        "DOM.resolveNode" => {
            let backend = request["params"]["backendNodeId"].as_u64().unwrap();
            assert!(matches!(backend, 1 | 2));
            let group = request["params"]["objectGroup"].as_str().unwrap();
            Some(json!({"object":{"objectId":format!("{group}-node-{backend}"),"subtype":"node"}}))
        }
        "Runtime.callFunctionOn" => {
            let declaration = request["params"]["functionDeclaration"].as_str()?;
            if declaration.contains("const read=") {
                let values = request["params"]["arguments"].as_array().unwrap().iter().skip(2).map(|argument| {
                    let object = argument["objectId"].as_str().unwrap();
                    if object.ends_with("node-2") {
                        json!({"attributes":{},"labels":[],"states":{},"rect":{"x":1,"y":1,"width":4,"height":4},"author":{"tag":"button","nodeType":1,"visible":true,"action":true}})
                    } else {
                        assert!(object.ends_with("node-1"));
                        json!({"attributes":{},"labels":[],"states":{},"rect":null,"author":{"nodeType":9,"visible":true}})
                    }
                }).collect::<Vec<_>>();
                Some(json!({"result":{"value":values}}))
            } else if declaration.starts_with("function(expression, data, labels, safeNames, secureSelector, protectedAncestors, ...elements)") {
                let args = request["params"]["arguments"].as_array().unwrap();
                assert_eq!(args.len(), 7);
                assert!(args[6]["objectId"].as_str().unwrap().ends_with("node-2"));
                assert_eq!(args[0]["value"]["query"]["value"]["value"], "Submit");
                assert!(request["params"]["objectGroup"].as_str().unwrap().starts_with("native-query-"));
                Some(json!({"result":{"value":{"indices":[0],"redacted":[]}}}))
            } else if request["params"]["objectGroup"]
                .as_str()
                .is_some_and(|group| group.starts_with("native-semantic-box-"))
            {
                if declaration.contains("frameOwner") {
                    Some(json!({"result":{"value":{"connected":true,"frameOwner":false}}}))
                } else {
                    Some(json!({"result":{"value":true}}))
                }
            } else {
                None
            }
        }
        _ => None,
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
        "DOM.resolveNode" => {
            let group = request["params"]["objectGroup"].as_str().unwrap_or("");
            let object = if group.starts_with("native-") {
                format!("{group}-node-1")
            } else {
                "node-1".into()
            };
            json!({"object":{"objectId":object,"subtype":"node"}})
        }
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
                json!({"result":{"objectId":format!("{}-security", request["params"]["objectGroup"].as_str().unwrap())}})
            } else if declaration.contains("const read=") {
                let values = request["params"]["arguments"].as_array().unwrap().iter().skip(2).map(|argument| {
                    assert!(argument["objectId"].as_str().unwrap().ends_with("node-1"));
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

// I10/#17: exercise the actual framed transport, ClientBrowser result bridge,
// retained operation registry and CDP reader. A held ACK is never a fake clean
// restoration. The peer is protocol proof, not a renderer/pixel-fidelity test.
async fn optional_fixture(case: Case) -> (Peer, Arc<ClientBrowser>, FramedFixture, String) {
    let peer = peer(case).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture =
        FramedFixture::with_capabilities(broker, browser.clone(), required_capabilities());
    fixture.ready().await.unwrap();
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
    (peer, browser, fixture, scope)
}

async fn optional_request(
    fixture: &mut FramedFixture,
    scope: &str,
    id: &str,
    pixels: bool,
    timeout: u64,
) -> Instant {
    fixture.sequence += 1;
    let started = Instant::now();
    fixture
        .write(
            json!({"type":"request","id":id,"generation":1,"operationSeq":fixture.sequence,
        "timeoutMs":timeout,"command":"browser.observe","args":{"identityScope":scope,
        "testIdAttribute":"data-testid","secureFieldSelector":FIXTURE_SECURE_SELECTOR,
        "options":{"pixels":pixels}}}),
        )
        .await
        .unwrap();
    started
}

async fn optional_result(fixture: &mut FramedFixture, id: &str) -> Value {
    trace_and_control(fixture, id, None).await.0
}

async fn peer_reached(peer: &Peer, method: &str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !peer
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|request| request["method"] == method)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("real held command not submitted");
}

async fn optional_finish(peer: Peer, fixture: FramedFixture) -> Result<(), String> {
    let cleanup = tokio::time::timeout(Duration::from_secs(10), fixture.finish())
        .await
        .expect("retained native shutdown stalled");
    tokio::time::timeout(Duration::from_secs(2), peer.task)
        .await
        .expect("peer not joined")
        .unwrap();
    cleanup
}

async fn optional_finish_failed(peer: Peer, fixture: FramedFixture, browser: &ClientBrowser) {
    let cleanup = tokio::time::timeout(Duration::from_secs(10), fixture.finish())
        .await
        .expect("retained native shutdown stalled");
    assert!(
        cleanup.is_err(),
        "unresolved protection must not report clean shutdown"
    );
    {
        let owner = browser.owner.lock().await;
        let owner = owner
            .as_ref()
            .expect("failed borrowed scope lost its owner");
        assert!(owner
            .targets
            .protected_read_residual
            .replacement_safe()
            .is_err());
    }
    // Production deliberately retains this borrowed connection with failed
    // protection custody. Only the independent test peer closes its socket.
    peer.disconnect.send(()).expect("test peer already gone");
    tokio::time::timeout(Duration::from_secs(2), peer.task)
        .await
        .expect("disconnected test peer not joined")
        .unwrap();
}

#[tokio::test]
async fn i10_t01_metadata_release_ack_is_not_the_eighty_ms_tree_deadline() {
    let (peer, browser, mut fixture, scope) = optional_fixture(Case::MetadataReleaseHeld).await;
    let client = browser.page_lease(false).await.unwrap().client;
    let ledger = client.debt_ledger().unwrap();
    let started = optional_request(&mut fixture, &scope, "readonly-debt-tree", false, 80).await;
    let result = tokio::time::timeout_at(
        (started + Duration::from_millis(80)).into(),
        optional_result(&mut fixture, "readonly-debt-tree"),
    )
    .await
    .expect("metadata ACK consumed the original deadline");
    assert_eq!(result["ok"], true);
    assert_eq!(result["effects"], "completed");
    assert_eq!(result["data"]["root"]["role"], "document");
    assert!(result["data"].get("pixels").is_none());
    assert!(
        ledger.snapshot().object_debt > 0,
        "held disposal was not accounted"
    );
    assert!(ledger.snapshot().outstanding_commands > 0);
    assert!(!ledger.snapshot().integrity_lost);
    let old = browser.refs.lock().unwrap().ref_ids();
    assert!(!old.is_empty());
    // A second operation has different metadata group identity. Its release
    // cannot borrow or discharge the old held release receipt.
    let next = fixture.command("browser.observe", json!({"identityScope":scope,
        "testIdAttribute":"data-testid","secureFieldSelector":FIXTURE_SECURE_SELECTOR,"options":{}}), 1).await.unwrap();
    assert_ne!(next["revision"], result["data"]["revision"]);
    assert!(ledger.snapshot().object_debt > 0);
    let groups = peer
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request["method"] == "Runtime.releaseObjectGroup")
        .filter_map(|request| request["params"]["objectGroup"].as_str())
        .filter(|group| group.starts_with("native-metadata-"))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(groups.len(), 2);
    assert_ne!(groups[0], groups[1]);
    peer.release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while ledger.snapshot().object_debt != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("matching late release ACK did not discharge exact debt");
    assert_eq!(browser.refs.lock().unwrap().ref_ids().len(), old.len());
    assert!(!peer
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|request| request["method"] == "Page.captureScreenshot"));
    optional_finish(peer, fixture).await.unwrap();
}

#[tokio::test]
async fn i10_t02_mask_probe_no_ack_returns_tree_without_late_screenshot() {
    let (peer, browser, mut fixture, scope) = optional_fixture(Case::OptionalMaskHeld).await;
    let client = browser.page_lease(false).await.unwrap().client;
    let started = optional_request(&mut fixture, &scope, "mask-debt-tree", true, 80).await;
    let result = tokio::time::timeout_at(
        (started + Duration::from_millis(80)).into(),
        optional_result(&mut fixture, "mask-debt-tree"),
    )
    .await
    .expect("mask probe consumed immutable tree deadline");
    assert_eq!(
        result["ok"],
        true,
        "result={result} elapsed={:?}",
        started.elapsed()
    );
    assert!(result["data"].get("pixels").is_none());
    assert!(!browser.refs.lock().unwrap().ref_ids().is_empty());
    peer_reached(&peer, "DOMSnapshot.captureSnapshot").await;
    peer.release.send(()).unwrap();
    // A same-transport roundtrip fences processing of the real late value ACK.
    client
        .send_command_no_params("Browser.getVersion", None)
        .await
        .unwrap();
    assert!(!peer
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|request| request["method"] == "Page.captureScreenshot"));
    optional_finish(peer, fixture).await.unwrap();
}

#[tokio::test]
async fn i10_t03_t04_raw_no_ack_publishes_tree_retains_join_blocks_input_then_recovers() {
    use crate::native::client_debt::OperationKey;
    let (peer, browser, mut fixture, scope) = optional_fixture(Case::OptionalRawHeld).await;
    let client = browser.page_lease(false).await.unwrap().client;
    let ledger = client.debt_ledger().unwrap();
    let started = optional_request(&mut fixture, &scope, "raw-debt-tree", true, 80).await;
    let sequence = fixture.sequence;
    let result = tokio::time::timeout_at(
        (started + Duration::from_millis(80)).into(),
        optional_result(&mut fixture, "raw-debt-tree"),
    )
    .await
    .expect("raw ACK/join consumed immutable tree deadline");
    assert_eq!(result["ok"], true);
    assert_eq!(result["effects"], "completed");
    assert!(
        result.get("retention").is_none(),
        "successful semantics are not an Unknown continuation"
    );
    assert!(result["data"].get("pixels").is_none());
    peer_reached(&peer, "Page.captureScreenshot").await;
    let (journal, fixed) = browser
        .tasks
        .operation_journal_result_for_test(OperationKey {
            generation: 1,
            operation_seq: sequence,
        })
        .expect("old producer must remain registered");
    assert!(
        fixed,
        "wire publication fixes the immutable result, not local cleanup"
    );
    assert!(!journal.snapshot().local_producers_finished);
    assert!(ledger.snapshot().outstanding_commands > 0);
    assert!(!peer.early_restore.load(Ordering::Acquire));
    assert!(!peer.terminal_sent.load(Ordering::Acquire));
    fixture.sequence += 1;
    fixture.write(json!({"type":"request","id":"unsafe-input","generation":1,"operationSeq":fixture.sequence,
        "timeoutMs":30,"command":"browser.pointer","args":{"identityScope":scope,"point":{"x":1,"y":1},"action":{"kind":"tap"}}})).await.unwrap();
    let refused = optional_result(&mut fixture, "unsafe-input").await;
    assert_eq!(refused["ok"], false);
    assert!(!peer
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|request| request["method"] == "Input.dispatchMouseEvent"));
    assert!(!peer.early_restore.load(Ordering::Acquire));
    let retained_refs = browser.refs.lock().unwrap().ref_ids();
    assert!(!retained_refs.is_empty());
    peer.release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !journal.snapshot().local_producers_finished {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("late raw ACK did not join its exact producer");
    assert!(peer.restoration_acked.load(Ordering::Acquire));
    assert!(!ledger.snapshot().integrity_lost);
    assert_eq!(browser.refs.lock().unwrap().ref_ids(), retained_refs);
    fixture
        .command(
            "browser.pointer",
            json!({"identityScope":scope,"point":{"x":1,"y":1},"action":{"kind":"tap"}}),
            1,
        )
        .await
        .unwrap();
    assert_eq!(
        peer.log
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request["method"] == "Input.dispatchMouseEvent")
            .count(),
        3
    );
    assert_eq!(
        peer.log
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request["method"] == "Page.captureScreenshot")
            .count(),
        1
    );
    optional_finish(peer, fixture).await.unwrap();
}

#[tokio::test]
async fn i10_t03_permanent_raw_no_ack_keeps_tree_but_never_claims_clean_custody() {
    use crate::native::client_debt::OperationKey;
    let (peer, browser, mut fixture, scope) = optional_fixture(Case::OptionalRawNeverAck).await;
    let started = optional_request(&mut fixture, &scope, "permanent-raw-tree", true, 80).await;
    let sequence = fixture.sequence;
    let result = tokio::time::timeout_at(
        (started + Duration::from_millis(80)).into(),
        optional_result(&mut fixture, "permanent-raw-tree"),
    )
    .await
    .expect("permanent raw debt delayed immutable tree");
    assert_eq!(result["ok"], true);
    assert!(result["data"].get("pixels").is_none());
    let (journal, fixed) = browser
        .tasks
        .operation_journal_result_for_test(OperationKey {
            generation: 1,
            operation_seq: sequence,
        })
        .unwrap();
    assert!(fixed && !journal.snapshot().local_producers_finished);
    tokio::time::timeout(Duration::from_secs(4), async {
        while !journal.snapshot().local_producers_finished {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("bounded raw custody did not reach an honest terminal disposition");
    assert!(journal.snapshot().integrity_lost);
    assert!(!peer.early_restore.load(Ordering::Acquire));
    assert!(!peer.terminal_sent.load(Ordering::Acquire));
    assert!(!peer
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|request| request["params"]["functionDeclaration"]
            == "function(){return this.remove()}"));
    optional_finish_failed(peer, fixture, &browser).await;
}

#[tokio::test]
async fn i10_t05_wrong_session_or_malformed_late_raw_ack_never_becomes_pixels() {
    use crate::native::client_debt::OperationKey;
    for case in [Case::OptionalWrongSessionHeld, Case::OptionalMalformedHeld] {
        let (peer, browser, mut fixture, scope) = optional_fixture(case).await;
        let started = optional_request(&mut fixture, &scope, "invalid-late-raw", true, 80).await;
        let sequence = fixture.sequence;
        let result = tokio::time::timeout_at(
            (started + Duration::from_millis(80)).into(),
            optional_result(&mut fixture, "invalid-late-raw"),
        )
        .await
        .unwrap();
        assert_eq!(result["ok"], true);
        assert!(result["data"].get("pixels").is_none());
        let (journal, _) = browser
            .tasks
            .operation_journal_result_for_test(OperationKey {
                generation: 1,
                operation_seq: sequence,
            })
            .unwrap();
        peer.release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(4), async {
            while !journal.snapshot().local_producers_finished {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!peer.early_restore.load(Ordering::Acquire));
        if case == Case::OptionalWrongSessionHeld {
            assert!(journal.snapshot().integrity_lost);
        }
        assert_eq!(
            peer.log
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request["method"] == "Page.captureScreenshot")
                .count(),
            1
        );
        if case == Case::OptionalWrongSessionHeld {
            optional_finish_failed(peer, fixture, &browser).await;
        } else {
            // Malformed pixels are not publishable, but their correctly
            // correlated ACK ends raw custody and permits actual restoration.
            assert!(!journal.snapshot().integrity_lost);
            assert!(peer.restoration_acked.load(Ordering::Acquire));
            optional_finish(peer, fixture).await.unwrap();
        }
    }
}

#[tokio::test]
async fn i10_t05_shared_semantic_corruption_never_enters_optional_success() {
    let (peer, browser, mut fixture, scope) = optional_fixture(Case::SemanticCorruption).await;
    optional_request(&mut fixture, &scope, "broken-semantic", true, 80).await;
    let result = optional_result(&mut fixture, "broken-semantic").await;
    assert_eq!(result["ok"], false);
    assert!(result.get("data").is_none());
    assert!(browser.refs.lock().unwrap().ref_ids().is_empty());
    assert!(!peer
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|request| request["method"] == "Page.captureScreenshot"));
    optional_finish(peer, fixture).await.unwrap();
}

#[tokio::test]
async fn i10_t06_client_cancel_before_optional_cutoff_keeps_old_published_refs() {
    let (peer, browser, mut fixture, scope) = optional_fixture(Case::OptionalRawHeld).await;
    fixture
        .command(
            "browser.observe",
            json!({"identityScope":scope,"testIdAttribute":"data-testid",
        "secureFieldSelector":FIXTURE_SECURE_SELECTOR,"options":{}}),
            1,
        )
        .await
        .unwrap();
    let before = browser.refs.lock().unwrap().ref_ids();
    optional_request(&mut fixture, &scope, "cancel-before-cutoff", true, 1000).await;
    peer_reached(&peer, "Page.captureScreenshot").await;
    fixture.write(json!({"type":"cancel","id":"cancel-optional","generation":1,"operationSeq":fixture.sequence})).await.unwrap();
    peer.release.send(()).unwrap();
    let (result, cancel) = trace_and_control(
        &mut fixture,
        "cancel-before-cutoff",
        Some("cancel-optional"),
    )
    .await;
    assert_eq!(cancel.unwrap()["accepted"], true);
    assert_eq!(result["ok"], false);
    assert!(result.get("data").is_none());
    assert_eq!(browser.refs.lock().unwrap().ref_ids(), before);
    assert_eq!(
        peer.log
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request["method"] == "Page.captureScreenshot")
            .count(),
        1
    );
    optional_finish(peer, fixture).await.unwrap();
}

#[tokio::test]
async fn i10_t05_failed_optional_restore_emits_completed_quarantined_tree() {
    let (peer, browser, mut fixture, scope) = optional_fixture(Case::OptionalRestoreFailure).await;
    let started =
        optional_request(&mut fixture, &scope, "failed-restore-safe-tree", true, 80).await;
    let result = tokio::time::timeout_at(
        (started + Duration::from_millis(80)).into(),
        optional_result(&mut fixture, "failed-restore-safe-tree"),
    )
    .await
    .expect("failed optional cleanup erased the on-time immutable tree");
    assert_eq!(result["ok"], true);
    assert_eq!(result["effects"], "completed");
    assert_eq!(result["scopeState"], "quarantined");
    assert_eq!(result["data"]["root"]["role"], "document");
    assert!(result["data"].get("pixels").is_none());
    assert!(result.get("retention").is_none());
    assert!(!browser.refs.lock().unwrap().ref_ids().is_empty());
    assert!(
        browser.broker.admit(1, fixture.sequence + 1, 80).is_err(),
        "immutable publication must not restore new operation admission"
    );
    assert!(!peer
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|request| request["method"] == "Input.dispatchMouseEvent"));
    optional_finish_failed(peer, fixture, &browser).await;
}

#[tokio::test]
async fn i10_t06_new_observe_after_tree_publication_cannot_receive_late_old_pixels_or_refs() {
    let (peer, browser, mut fixture, scope) = optional_fixture(Case::OptionalRawHeld).await;
    let started = optional_request(&mut fixture, &scope, "old-sealed-tree", true, 80).await;
    let first = tokio::time::timeout_at(
        (started + Duration::from_millis(80)).into(),
        optional_result(&mut fixture, "old-sealed-tree"),
    )
    .await
    .unwrap();
    assert_eq!(first["ok"], true);
    assert!(first["data"].get("pixels").is_none());
    peer_reached(&peer, "Page.captureScreenshot").await;
    optional_request(&mut fixture, &scope, "newer-tree", false, 1000).await;
    peer.release.send(()).unwrap();
    let newer = optional_result(&mut fixture, "newer-tree").await;
    assert_eq!(newer["ok"], true);
    assert!(newer["data"].get("pixels").is_none());
    assert_ne!(newer["data"]["revision"], first["data"]["revision"]);
    let viewport = &newer["data"]["viewportRef"];
    let page_session = browser.page_lease(false).await.unwrap().page_session_id;
    {
        let refs = browser.refs.lock().unwrap();
        // Viewport authority is separate from DOM-node membership. Check the
        // same full capability used by point actions, not the DOM-only map.
        assert!(refs.matches_viewport_reference(
            &scope,
            1,
            &page_session,
            viewport["id"].as_str().unwrap(),
            viewport["revision"].as_str().unwrap(),
        ));
        let root = newer["data"]["root"]["ref"]["id"]
            .as_str()
            .unwrap()
            .trim_start_matches('@');
        let revision = newer["data"]["revision"].as_str().unwrap().parse().unwrap();
        assert!(refs.get(root).unwrap().is_current_observed(revision));
        let old_revision = first["data"]["revision"].as_str().unwrap().parse().unwrap();
        assert!(!refs.get(root).unwrap().is_current_observed(old_revision));
    }
    assert!(peer.restoration_acked.load(Ordering::Acquire));
    assert_eq!(
        peer.log
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request["method"] == "Page.captureScreenshot")
            .count(),
        1
    );
    optional_finish(peer, fixture).await.unwrap();
}

#[tokio::test]
async fn i10_t08_healthy_optional_image_remains_available_with_complete_tree() {
    let (peer, _browser, mut fixture, scope) = optional_fixture(Case::Immediate).await;
    let started = optional_request(&mut fixture, &scope, "healthy-optional-image", true, 80).await;
    let result = tokio::time::timeout_at(
        (started + Duration::from_millis(80)).into(),
        optional_result(&mut fixture, "healthy-optional-image"),
    )
    .await
    .expect("healthy optional image exceeded unchanged budget");
    assert_eq!(result["ok"], true);
    assert_eq!(result["effects"], "completed");
    assert_eq!(result["data"]["root"]["role"], "document");
    assert_eq!(result["data"]["pixels"]["width"], 10);
    assert_eq!(result["data"]["pixels"]["height"], 10);
    assert!(result["data"]["pixels"]["sha256"]
        .as_str()
        .is_some_and(|digest| digest.len() == 64));
    assert!(peer.restoration_acked.load(Ordering::Acquire));
    fixture
        .command(
            "blob.release",
            json!({"identityScope":scope,"handle":result["data"]["pixels"]["handle"]}),
            1,
        )
        .await
        .unwrap();
    optional_finish(peer, fixture).await.unwrap();
}

#[tokio::test]
async fn i10_t08_healthy_optional_pixels_after_old_cleanup_cutoff_still_publish() {
    let (peer, _browser, mut fixture, scope) = optional_fixture(Case::OptionalRawHeld).await;
    let started = optional_request(&mut fixture, &scope, "late-healthy-optional", true, 1000).await;
    peer_reached(&peer, "Page.captureScreenshot").await;
    let result = {
        let pending = optional_result(&mut fixture, "late-healthy-optional");
        tokio::pin!(pending);
        // The old 20% reserve would omit an otherwise valid image near800ms.
        // Keep the real raw ACK held beyond it, within this caller's unchanged1s.
        tokio::select! {
            result = &mut pending => panic!("healthy optional availability was cut off early: {result}"),
            _ = tokio::time::sleep_until((started + Duration::from_millis(850)).into()) => {}
        }
        assert!(!peer.early_restore.load(Ordering::Acquire));
        tokio::time::sleep_until((started + Duration::from_millis(900)).into()).await;
        peer.release.send(()).unwrap();
        tokio::time::timeout_at((started + Duration::from_millis(1000)).into(), pending)
            .await
            .expect("valid late image missed unchanged deadline")
    };
    assert_eq!(result["ok"], true);
    assert_eq!(result["data"]["root"]["role"], "document");
    assert_eq!(result["data"]["pixels"]["width"], 10);
    assert_eq!(result["data"]["pixels"]["height"], 10);
    assert!(peer.restoration_acked.load(Ordering::Acquire));
    assert!(!peer.early_restore.load(Ordering::Acquire));
    fixture
        .command(
            "blob.release",
            json!({"identityScope":scope,"handle":result["data"]["pixels"]["handle"]}),
            1,
        )
        .await
        .unwrap();
    optional_finish(peer, fixture).await.unwrap();
}

#[tokio::test]
async fn readonly_semantic_geometry_held_ack_publishes_complete_observe_within_eighty_ms() {
    let (peer, browser, mut fixture, scope) =
        optional_fixture(Case::SemanticGeometryReleaseHeld).await;
    let client = browser.page_lease(false).await.unwrap().client;
    let ledger = client.debt_ledger().unwrap();
    let started = optional_request(&mut fixture, &scope, "geometry-debt-tree", false, 80).await;
    let result = tokio::time::timeout_at(
        (started + Duration::from_millis(80)).into(),
        optional_result(&mut fixture, "geometry-debt-tree"),
    )
    .await
    .expect("readonly geometry ACK consumed original Observe deadline");
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["effects"], "completed");
    assert_eq!(result["data"]["root"]["role"], "document");
    let button = result["data"]["root"]["children"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["role"] == "button")
        .expect("actual semantic button missing");
    assert_eq!(button["name"], "Submit");
    assert_eq!(button["rect"]["width"], 4.0);
    assert!(result["data"].get("pixels").is_none());
    assert!(ledger.snapshot().object_debt > 0);
    assert!(!ledger.snapshot().integrity_lost);
    let held = peer
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|request| {
            request["method"] == "Runtime.releaseObjectGroup"
                && request["params"]["objectGroup"]
                    .as_str()
                    .is_some_and(|group| group.starts_with("native-semantic-box-"))
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(held.len(), 1, "semantic geometry path was not reached");
    assert!(!peer
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|request| request["method"] == "Runtime.releaseObject"));
    peer.release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while ledger.snapshot().object_debt != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!browser.refs.lock().unwrap().ref_ids().is_empty());
    optional_finish(peer, fixture).await.unwrap();
}

#[tokio::test]
async fn readonly_frame_owner_held_ack_publishes_both_documents_within_eighty_ms() {
    let (peer, browser, mut fixture, scope) =
        optional_fixture(Case::SemanticFrameOwnerReleaseHeld).await;
    let client = browser.page_lease(false).await.unwrap().client;
    let ledger = client.debt_ledger().unwrap();
    let started = optional_request(&mut fixture, &scope, "frame-debt-tree", false, 80).await;
    let result = tokio::time::timeout_at(
        (started + Duration::from_millis(80)).into(),
        optional_result(&mut fixture, "frame-debt-tree"),
    )
    .await
    .expect("readonly frame owner ACK consumed original Observe deadline");
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["effects"], "completed");
    let mut pending = vec![&result["data"]["root"]];
    let mut documents = 0;
    while let Some(node) = pending.pop() {
        documents += usize::from(node["role"] == "document");
        if let Some(children) = node["children"].as_array() {
            pending.extend(children);
        }
    }
    assert_eq!(
        documents, 2,
        "semantic child document was discarded: {result}"
    );
    assert!(result["data"].get("pixels").is_none());
    assert!(ledger.snapshot().object_debt > 0);
    assert!(!ledger.snapshot().integrity_lost);
    let held = peer
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|request| {
            request["method"] == "Runtime.releaseObjectGroup"
                && request["params"]["objectGroup"]
                    .as_str()
                    .is_some_and(|group| group.starts_with("native-frame-owner-"))
        })
        .cloned()
        .collect::<Vec<_>>();
    assert!(!held.is_empty());
    assert!(!peer
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|request| request["method"] == "Runtime.releaseObject"));
    peer.release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while ledger.snapshot().object_debt != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!browser.refs.lock().unwrap().ref_ids().is_empty());
    optional_finish(peer, fixture).await.unwrap();
}

// The RPC label does not turn a temporary semantic rectangle into an action
// handle or mask polygon. These are real framed commands with an actual ACK held.
async fn readonly_semantic_bounds_command(command: &str) {
    let (peer, browser, mut fixture, scope) =
        optional_fixture(Case::SemanticGeometryReleaseHeld).await;
    let client = browser.page_lease(false).await.unwrap().client;
    let ledger = client.debt_ledger().unwrap();
    fixture.sequence += 1;
    let mut args = json!({"identityScope":scope,"testIdAttribute":"data-testid",
        "secureFieldSelector":FIXTURE_SECURE_SELECTOR});
    if command == "browser.query" {
        args["expression"] = json!({"kind":"query","query":{"kind":"text",
            "value":{"kind":"string","value":"Submit","exact":true}}});
    } else {
        assert_eq!(command, "browser.trace");
        args["options"] = json!({});
    }
    let started = Instant::now();
    fixture
        .write(json!({"type":"request","id":"readonly-semantic-bounds",
        "generation":1,"operationSeq":fixture.sequence,"timeoutMs":80,
        "command":command,"args":args}))
        .await
        .unwrap();
    let result = tokio::time::timeout_at(
        (started + Duration::from_millis(80)).into(),
        optional_result(&mut fixture, "readonly-semantic-bounds"),
    )
    .await
    .expect("semantic bounds waited for readonly disposal ACK");
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["effects"], "completed");
    assert_eq!(result["scopeState"], "usable");
    assert!(result["data"].get("pixels").is_none());
    let node = if command == "browser.query" {
        assert_eq!(result["data"]["nodes"].as_array().unwrap().len(), 1);
        &result["data"]["nodes"][0]
    } else {
        assert_eq!(result["data"]["root"]["role"], "document");
        result["data"]["root"]["children"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["role"] == "button")
            .unwrap()
    };
    assert_eq!(node["name"], "Submit");
    assert_eq!(node["rect"]["width"], 4.0);
    assert!(ledger.snapshot().object_debt > 0);
    assert!(!ledger.snapshot().integrity_lost);
    let held = peer
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|request| {
            request["method"] == "Runtime.releaseObjectGroup"
                && request["params"]["objectGroup"]
                    .as_str()
                    .is_some_and(|group| group.starts_with("native-semantic-box-"))
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0]["sessionId"], "host-session");
    if command == "browser.trace" {
        assert!(
            browser.refs.lock().unwrap().ref_ids().is_empty(),
            "trace rectangles are not published action references"
        );
    } else {
        let id = node["ref"]["id"].as_str().unwrap().trim_start_matches('@');
        assert!(browser.refs.lock().unwrap().get(id).is_some());
    }
    assert!(!peer
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|request| request["method"] == "Page.captureScreenshot"
            || request["method"] == "Input.dispatchMouseEvent"));
    peer.release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while ledger.snapshot().object_debt != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    optional_finish(peer, fixture).await.unwrap();
}

#[tokio::test]
async fn query_semantic_bounds_returns_before_exact_readonly_release_ack() {
    readonly_semantic_bounds_command("browser.query").await;
}
#[tokio::test]
async fn trace_semantic_bounds_returns_before_exact_readonly_release_ack_without_action_refs() {
    readonly_semantic_bounds_command("browser.trace").await;
}
