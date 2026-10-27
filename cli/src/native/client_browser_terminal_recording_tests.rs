//! Real managed failed replacement and terminal frozen-artifact production.
//! Only CDP responses are scripted. Recording state, journals, attachments,
//! encoder children, private files and quota reservations are production-owned.
use super::*;
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio_tungstenite::tungstenite::Message;

struct Peer {
    endpoint: String,
    requests: Arc<Mutex<Vec<Value>>>,
    failure_armed: Arc<AtomicBool>,
    failure_reached: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}
fn reply(request: &Value, error: bool) -> Value {
    let mut result = if error {
        json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic replacement refusal"}})
    } else {
        json!({"id":request["id"],"result":{}})
    };
    if let Some(session) = request.get("sessionId") {
        result["sessionId"] = session.clone();
    }
    result
}
async fn peer(
    clean_stop: bool,
    held_create: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    failure: Option<&'static str>,
) -> Peer {
    peer_with_interop(clean_stop, held_create, failure, None).await
}

async fn peer_with_interop(
    clean_stop: bool,
    mut held_create: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    failure: Option<&'static str>,
    interop_context: Option<Arc<AtomicBool>>,
) -> Peer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = requests.clone();
    let failure_armed = Arc::new(AtomicBool::new(false));
    let armed = failure_armed.clone();
    let failure_reached = Arc::new(AtomicBool::new(false));
    let reached = failure_reached.clone();
    let mut jpeg = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
        320,
        200,
        image::Rgb([23, 41, 89]),
    ))
    .write_to(&mut jpeg, image::ImageFormat::Jpeg)
    .unwrap();
    let image = base64::engine::general_purpose::STANDARD.encode(jpeg.get_ref());
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut page = None;
        let mut attaches = 0;
        let mut contexts = 0;
        let mut loader = "initial-loader";
        let mut isolated_world: Option<(&str, i64)> = None;
        loop {
            let incoming = socket.next().await;
            let Some(Ok(Message::Text(text))) = incoming else {
                break;
            };
            let request: Value = serde_json::from_str(&text).unwrap();
            log.lock().unwrap().push(request.clone());
            let method = request["method"].as_str().unwrap();
            let session = request["sessionId"].as_str().unwrap_or("");
            if let Some(present) = &interop_context {
                // Script the external peer's context creation/close only. The
                // production constructor must still inventory, verify and attach.
                page = present.load(Ordering::SeqCst).then(|| {
                    json!({"targetId":"page-1","type":"page","browserContextId":"synthetic-context","url":"about:blank","title":""})
                });
            }
            let mut after = Vec::new();
            let mut error = false;
            let result = match method {
                "Browser.getVersion" => {
                    json!({"protocolVersion":"1.3","product":"Synthetic Chromium/1.0",
                    "revision":"synthetic-revision","userAgent":"Synthetic Chromium Linux","jsVersion":"synthetic-js"})
                }
                "Target.getBrowserContexts" => {
                    let present = interop_context.as_ref().expect("unexpected context inventory");
                    json!({"browserContextIds":if present.load(Ordering::SeqCst) {
                        vec!["synthetic-context"]
                    } else { Vec::<&str>::new() }})
                }
                "Target.createBrowserContext" => {
                    contexts += 1;
                    error = contexts == 2;
                    if contexts == 2 {
                        if let Some((reached, release)) = held_create.take() {
                            let _ = reached.send(());
                            let _ = release.await;
                        }
                    }
                    assert!(contexts <= 2, "replacement was replayed");
                    json!({"browserContextId":"synthetic-context"})
                }
                "Target.createTarget" => {
                    assert!(page.is_none(), "unexpected new application page");
                    page = Some(
                        json!({"targetId":"page-1","type":"page","browserContextId":"synthetic-context","url":"about:blank","title":""}),
                    );
                    json!({"targetId":"page-1"})
                }
                "Target.attachToTarget" => {
                    assert_eq!(request["params"]["targetId"], "page-1");
                    attaches += 1;
                    assert!(attaches <= 2, "recorder attach was replayed");
                    json!({"sessionId":if attaches == 1 { "session-1" } else { "capture-1" }})
                }
                "Target.getTargets" => {
                    json!({"targetInfos":page.iter().cloned().collect::<Vec<_>>()})
                }
                "Target.getTargetInfo" => {
                    json!({"targetInfo":page.as_ref().expect("requested gone target")})
                }
                "Target.closeTarget" => {
                    page = None;
                    after.push(json!({"method":"Target.detachedFromTarget","params":{"targetId":"page-1","sessionId":"session-1"}}));
                    json!({"success":true})
                }
                "Target.disposeBrowserContext" => {
                    if let Some(present) = &interop_context {
                        assert_eq!(request["params"]["browserContextId"], "synthetic-context");
                        present.store(false, Ordering::SeqCst);
                    }
                    page = None;
                    json!({})
                }
                "Page.getFrameTree" => {
                    assert_eq!(session, "session-1");
                    assert!(page.is_some(), "frame tree belongs to a live fixture page");
                    json!({"frameTree":{"frame":{"id":"frame-session-1","loaderId":loader,
                    "url":"about:blank","securityOrigin":"null"}}})
                }
                "Page.createIsolatedWorld" => {
                    // Real managed recording admission enumerates its one owned
                    // document before geometry. Do not substitute a ready frame.
                    assert_eq!(session, "session-1");
                    assert_eq!(
                        page.as_ref().expect("world requested for gone page")["browserContextId"],
                        "synthetic-context"
                    );
                    assert_eq!(
                        request["params"],
                        json!({
                            "frameId":"frame-session-1", "worldName":"agent-browser-native-observation"
                        })
                    );
                    let context = if loader == "initial-loader" { 7 } else { 8 };
                    isolated_world = Some((loader, context));
                    json!({"executionContextId":context})
                }
                "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":"synthetic-script"}),
                "Runtime.evaluate" => {
                    assert_eq!(session, "session-1");
                    assert!(page.is_some(), "evaluation belongs to a live fixture page");
                    assert_eq!(request["params"]["returnByValue"], true);
                    if let Some(context) = request["params"].get("contextId") {
                        assert_eq!(isolated_world, Some((loader, context.as_i64().unwrap())));
                    }
                    match request["params"]["expression"].as_str().unwrap_or("") {
                        "[window.innerWidth, window.innerHeight]" => {
                            json!({"result":{"type":"object","value":[320,200]}})
                        }
                        "document.title" => {
                            json!({"result":{"type":"string","value":"recording-survived"}})
                        }
                        "location.href" => {
                            json!({"result":{"type":"string","value":"about:blank"}})
                        }
                        other => panic!("unmodeled recording Runtime.evaluate expression: {other}"),
                    }
                }
                "Page.navigate" => {
                    assert_eq!(session, "session-1");
                    // page.activate need not navigate. Arm this fault only after
                    // the test joined its real first recording, not via loader text.
                    if armed.load(Ordering::SeqCst) && failure.is_some() {
                        assert!(!reached.swap(true, Ordering::SeqCst), "failed navigation was replayed");
                        if failure == Some("disconnect") {
                            let _ = socket.close(None).await;
                            return;
                        }
                        error = true;
                        json!({})
                    } else {
                    loader = "activated-loader";
                    isolated_world = None;
                    after.push(json!({"method":"Page.frameNavigated","sessionId":session,"params":{"frame":{
                        "id":"frame-session-1","loaderId":loader,"url":"about:blank","securityOrigin":"null"}}}));
                    if interop_context.is_some() {
                        after.push(json!({"method":"Page.lifecycleEvent","sessionId":session,"params":{
                            "frameId":"frame-session-1","loaderId":loader,"name":"DOMContentLoaded"}}));
                    }
                    after.push(
                        json!({"method":"Page.lifecycleEvent","sessionId":session,"params":{
                        "frameId":"frame-session-1","loaderId":loader,"name":"load"}}),
                    );
                    json!({"frameId":"frame-session-1","loaderId":loader})
                    }
                }
                "Page.getLayoutMetrics" => {
                    json!({"cssLayoutViewport":{"pageX":0,"pageY":0,"clientWidth":320,"clientHeight":200},
                    "cssVisualViewport":{"pageX":0,"pageY":0,"offsetX":0,"offsetY":0,"clientWidth":320,"clientHeight":200,"scale":1}})
                }
                "Page.captureScreenshot" => json!({"data":image}),
                "Page.startScreencast" | "Page.stopScreencast" => {
                    assert_eq!(session, "capture-1");
                    error = method == "Page.stopScreencast" && !clean_stop;
                    json!({})
                }
                "Target.detachFromTarget" => {
                    assert_eq!(request["params"]["sessionId"], "capture-1");
                    json!({})
                }
                "Page.enable"
                | "Runtime.enable"
                | "Network.enable"
                | "WebMCP.enable"
                | "DOM.enable"
                | "DOM.disable"
                | "Network.setBypassServiceWorker"
                | "Fetch.enable"
                | "Fetch.disable"
                | "Browser.setDownloadBehavior"
                | "Browser.close"
                | "Page.setLifecycleEventsEnabled"
                | "Emulation.setEmulatedMedia"
                | "Target.setDiscoverTargets"
                | "Page.removeScriptToEvaluateOnNewDocument"
                | "Target.setAutoAttach"
                | "Runtime.runIfWaitingForDebugger"
                | "Emulation.setDeviceMetricsOverride" => json!({}),
                other => panic!("unmodeled recording CDP method {other}: {request}"),
            };
            let mut response = reply(&request, error);
            if !error {
                response["result"] = result;
            }
            if socket
                .send(Message::Text(response.to_string()))
                .await
                .is_err()
            {
                return;
            }
            for event in after {
                if socket.send(Message::Text(event.to_string())).await.is_err() {
                    return;
                }
            }
        }
    });
    Peer {
        endpoint,
        requests,
        failure_armed,
        failure_reached,
        task,
    }
}
async fn setup(fixture: &mut FramedFixture, endpoint: &str) -> Result<String, String> {
    fixture.ready().await?;
    let opened = fixture
        .command(
            "scope.open",
            fixture_scope_open("connect", Some(endpoint)),
            5,
        )
        .await?;
    let scope = opened["identityScope"]
        .as_str()
        .ok_or("missing scope")?
        .to_owned();
    fixture.scope = Some(scope.clone());
    fixture
        .command("scope.configure", fixture_configuration(&scope, None), 5)
        .await?;
    fixture
        .command("network.routes.replace", fixture_routes(&scope), 5)
        .await?;
    fixture.registry = 1;
    // Activation is separately acknowledged before the tested recorder attempt.
    fixture
        .command("page.activate", json!({"identityScope":scope}), 5)
        .await?;
    Ok(scope)
}

#[derive(Default)]
struct TerminalNotices {
    disconnect_expected: bool,
    disconnected: bool,
    callbacks_retired: bool,
}
fn terminal_notice_kind(frame: &Value) -> &'static str {
    match frame["event"].as_str() {
        Some("browser.disconnected") => "browser-disconnected",
        Some("scope.callbacks-retired") => "callbacks-retired",
        Some("app.log" | "app.navigation" | "registry-released") => "application",
        _ => "other",
    }
}
fn validate_terminal_notice(
    frame: &Value,
    scope: &str,
    generation: u64,
    through: u64,
    notices: &mut TerminalNotices,
) -> Result<(), String> {
    if scope.is_empty() || scope.len() > 128 { return Err("terminal notice without exact scope".into()); }
    let next = through.checked_add(1).filter(|next| *next <= crate::native::client_protocol::MAX_SAFE_SEQUENCE)
        .ok_or("terminal notice sequence exhausted")?;
    if frame["type"] != "event" || frame["generation"] != generation || frame["sequence"] != next {
        return Err("wrong terminal notice generation/order".into());
    }
    match frame["event"].as_str() {
        Some("browser.disconnected") => {
            if !notices.disconnect_expected || notices.disconnected || frame != &json!({
                "type":"event", "generation":generation, "sequence":next,
                "event":"browser.disconnected", "payload":{"reason":"browser-connection-closed"}
            }) {
                return Err("invalid, unexpected or repeated native disconnect notice".into());
            }
            notices.disconnected = true;
        }
        Some("scope.callbacks-retired") => {
            if scope.is_empty() || notices.callbacks_retired || frame != &json!({
                "type":"event", "generation":generation, "sequence":next,
                "event":"scope.callbacks-retired", "payload":{"identityScope":scope,"throughEventSequence":through}
            }) {
                return Err("invalid or repeated terminal callback retirement".into());
            }
            notices.callbacks_retired = true;
        }
        _ => {
            validate_fixture_notice(frame)?;
            let payload = &frame["payload"];
            let expected = match frame["event"].as_str() {
                Some("registry-released") => {
                    // Transport registry retirement may predate scope binding.
                    // Its optional scope cannot be invented or ignored if present.
                    let mut expected = json!({"registryVersion":payload["registryVersion"]});
                    if let Some(identity) = payload.get("identityScope") {
                        if identity != scope { return Err("wrong registry notice scope".into()); }
                        expected["identityScope"] = json!(scope);
                    }
                    expected
                }
                Some("app.log") => json!({"identityScope":scope,"source":payload["source"],
                    "level":payload["level"],"text":payload["text"]}),
                Some("app.navigation") => {
                    if !payload["initiatedByOperation"].is_boolean() {
                        return Err("invalid navigation initiation flag".into());
                    }
                    let mut expected = json!({"identityScope":scope,"kind":payload["kind"],
                        "url":payload["url"],"initiatedByOperation":payload["initiatedByOperation"]});
                    if let Some(name) = payload.get("frameName") { expected["frameName"] = name.clone(); }
                    expected
                }
                _ => return Err("unknown terminal application notice".into()),
            };
            if frame != &json!({"type":"event","generation":generation,"sequence":next,
                "event":frame["event"],"payload":expected}) {
                return Err("invalid terminal application notice shape or scope".into());
            }
        }
    }
    Ok(())
}

async fn receive_result(
    fixture: &mut FramedFixture,
    notices: &mut TerminalNotices,
    id: &str,
    sequence: u64,
    generation: u64,
) -> Result<Value, String> {
    for _ in 0..64 {
        let frame = tokio::time::timeout(Duration::from_secs(5), fixture.read())
            .await
            .map_err(|_| "terminal result timed out")??;
        if frame["generation"] != generation {
            return Err("wrong terminal generation".into());
        }
        if frame["type"] == "result" {
            if frame["id"] != id || frame["operationSeq"] != sequence {
                return Err("wrong terminal correlation".into());
            }
            return Ok(frame);
        }
        validate_terminal_notice(&frame, fixture.scope.as_deref().ok_or("terminal notice without scope")?, generation, fixture.event_sequence, notices)
            .map_err(|cause| format!("{cause}; kind={}; generationMatches={}; sequenceMatches={}; decisionAbsent={}",
                terminal_notice_kind(&frame), frame["generation"] == generation,
                frame["sequence"] == fixture.event_sequence + 1, frame.get("decision").is_none()))?;
        fixture.event_sequence += 1;
    }
    Err("terminal notice bound exceeded".into())
}
async fn command(fixture: &mut FramedFixture, notices: &mut TerminalNotices, name: &str, args: Value) -> Result<Value, String> {
    fixture.sequence += 1;
    let id = format!("terminal-{}", fixture.sequence);
    fixture
        .write(
            json!({"type":"request","id":id,"generation":1,"operationSeq":fixture.sequence,
        "timeoutMs":1000,"command":name,"args":args}),
        )
        .await?;
    receive_result(fixture, notices, &id, fixture.sequence, 1).await
}
fn completed(frame: Value) -> Result<Value, String> {
    if frame["ok"] != true
        || frame["effects"] != "completed"
        || frame["scopeState"] != "quarantined"
        || frame.get("retention").is_some()
        || frame.get("recovery").is_some()
    {
        return Err(format!(
            "terminal artifact result violated its closed contract: {frame}"
        ));
    }
    frame
        .get("data")
        .cloned()
        .ok_or("artifact result omitted data".into())
}
async fn decode_video(bytes: &[u8]) -> Result<(), String> {
    let directory =
        std::env::temp_dir().join(format!("native-terminal-video-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).map_err(|_| "decode directory")?;
    let file = directory.join("video.webm");
    let result = async {
        std::fs::write(&file, bytes).map_err(|_| "decode video write")?;
        let output = tokio::process::Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-show_entries",
                "stream=codec_name,width,height",
                "-of",
                "json",
            ])
            .arg(&file)
            .output()
            .await
            .map_err(|_| "ffprobe required")?;
        if !output.status.success() {
            return Err("frozen actual recording failed ffprobe".into());
        }
        let facts: Value = serde_json::from_slice(&output.stdout).map_err(|_| "ffprobe JSON")?;
        if facts["streams"][0]["codec_name"] != "vp8"
            || facts["streams"][0]["width"] != 320
            || facts["streams"][0]["height"] != 200
        {
            return Err("frozen recording dimensions/codec changed".into());
        }
        let output = tokio::process::Command::new("ffmpeg")
            .args(["-v", "error", "-i"])
            .arg(&file)
            .args([
                "-frames:v",
                "1",
                "-f",
                "image2pipe",
                "-vcodec",
                "png",
                "pipe:1",
            ])
            .output()
            .await
            .map_err(|_| "ffmpeg decode required")?;
        if !output.status.success() {
            return Err("frozen recording first frame failed decode".into());
        }
        let image = image::load_from_memory(&output.stdout)
            .map_err(|_| "decoded PNG")?
            .to_rgb8();
        let pixel = image.get_pixel(160, 100).0;
        if pixel
            .iter()
            .zip([23u8, 41, 89])
            .any(|(actual, expected)| actual.abs_diff(expected) > 25)
        {
            return Err("frozen recording lost actual first frame".into());
        }
        Ok(())
    }
    .await;
    let cleanup =
        std::fs::remove_dir_all(directory).map_err(|_| "decode directory cleanup".to_string());
    result.and(cleanup)
}

async fn run(negotiated: bool, clean_stop: bool) {
    run_with_failure(negotiated, clean_stop, "scope.reset").await;
}

async fn run_with_failure(negotiated: bool, clean_stop: bool, failed_command: &str) {
    let native_command = if failed_command == "connection" { "page.navigate" } else { failed_command };
    let failure = match failed_command {
        "page.navigate" => Some("navigation"),
        "connection" => Some("disconnect"),
        _ => None,
    };
    let peer = peer(clean_stop, None, failure).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut capabilities = vec!["terminal.close/1".into()];
    if negotiated {
        capabilities
            .push(super::super::super::client_protocol::TERMINAL_RECORDING_ARTIFACTS.into());
    }
    let mut fixture =
        FramedFixture::with_capabilities(broker.clone(), browser.clone(), capabilities);
    let mut notices = TerminalNotices { disconnect_expected: failed_command == "connection", ..Default::default() };
    let proof: Result<(), String> = async {
        let scope = setup(&mut fixture, &peer.endpoint).await?;
        {
            let page = browser
                .page_lease(false)
                .await
                .map_err(|_| "managed page")?;
            let ledger = page.client.debt_ledger().ok_or("managed ledger missing")?;
            if !ledger.matches_owner(1, &scope) {
                return Err("wrong managed ledger".into());
            }
        } // No page permit remains to block the genuine reset gate drain.
        fixture
            .command("recording.start", json!({"identityScope":scope}), 5)
            .await?;
        let actions = browser
            .owner
            .lock()
            .await
            .as_ref()
            .and_then(|owner| owner.runtime.as_ref())
            .ok_or("recording runtime missing")?
            .actions
            .clone();
        let charged = browser.blobs.charged_for_test();
        if actions
            .freeze_finalized_recording(
                &scope,
                super::super::super::client_debt::OperationKey {
                    generation: 1,
                    operation_seq: fixture.sequence,
                },
                &browser.blobs,
            )
            .is_some()
            || browser.blobs.charged_for_test() != charged
            || charged.1 != 1
        {
            return Err("active recording was frozen or quota moved".into());
        }
        let mut failure_args = json!({"identityScope":scope});
        if native_command == "page.navigate" {
            // Finish the actual managed recorder through its production
            // lifecycle hook, not a fabricated clean ledger or byte seed.
            actions.recording_page_closing(&scope, &browser.blobs).await.map_err(|e| format!("real segment finalization: {e:?}"))?;
            failure_args["url"] = json!("about:blank");
            failure_args["waitUntil"] = json!("load");
            peer.failure_armed.store(true, Ordering::SeqCst);
        }
        let reset = command(&mut fixture, &mut notices, native_command, failure_args).await?;
        let failed = fixture.sequence;
        if native_command == "page.navigate" && !peer.failure_reached.load(Ordering::SeqCst) {
            return Err("real navigation did not reach its armed CDP fault".into());
        }
        if reset["ok"] != false
            || reset["error"]["code"]
                != if clean_stop {
                    "browser-failure"
                } else {
                    "cleanup-failed"
                }
            || reset["effects"] != "unknown"
            || reset["scopeState"] != "quarantined"
        {
            return Err(format!(
                "replacement did not fail at actual context creation: {reset}"
            ));
        }
        if broker.health().map_err(|_| "health")?.1 != ScopeState::Quarantined {
            return Err("failed reset became usable".into());
        }
        let denied = command(&mut fixture, &mut notices, "page.title", json!({"identityScope":scope})).await?;
        if denied["ok"] != false
            || denied["effects"] != "not-dispatched"
            || denied["error"]["code"] != "scope-unavailable"
        {
            return Err("ordinary terminal admission was relaxed".into());
        }
        let identity = json!({"identityScope":scope,"failedOperationSeq":failed});
        let collected = command(
            &mut fixture, &mut notices,
            "recording.finalized.collect",
            identity.clone(),
        )
        .await?;
        if !negotiated {
            if collected["ok"] != false || collected["effects"] != "not-dispatched" {
                return Err("unnegotiated terminal artifact accepted".into());
            }
            return Ok(());
        }
        let manifest = completed(collected)?;
        if manifest["identityScope"] != scope
            || manifest["failedOperationSeq"] != failed
            || manifest["segments"].as_array().map(Vec::len) != Some(1)
        {
            return Err("terminal manifest did not preserve exact failed attempt".into());
        }
        let segment = &manifest["segments"][0];
        if segment["ordinal"] != 1
            || segment["mediaType"] != "video/webm"
            || chrono::DateTime::parse_from_rfc3339(
                segment["startedAt"]
                    .as_str()
                    .ok_or("start instant missing")?,
            )
            .is_err()
        {
            return Err("terminal segment metadata changed".into());
        }
        let mut base = identity.clone();
        base["token"] = manifest["token"].clone();
        base["handle"] = segment["handle"].clone();
        for mutation in [
            "identityScope",
            "failedOperationSeq",
            "token",
            "handle",
            "unexpected",
        ] {
            let mut wrong = base.clone();
            wrong[mutation] = if mutation == "failedOperationSeq" {
                json!(failed + 1)
            } else {
                json!("foreign")
            };
            let denied = command(&mut fixture, &mut notices, "recording.finalized.release", wrong).await?;
            if denied["ok"] != false || denied["effects"] != "not-dispatched" {
                return Err(format!("foreign {mutation} consumed a frozen artifact"));
            }
        }
        let repeated = completed(
            command(
                &mut fixture, &mut notices,
                "recording.finalized.collect",
                identity.clone(),
            )
            .await?,
        )?;
        if repeated != manifest {
            return Err("collect changed its fixed manifest".into());
        }
        let mut bytes = Vec::new();
        loop {
            let mut read = base.clone();
            read["offset"] = json!(bytes.len());
            read["maxBytes"] = json!(262144);
            let chunk = completed(command(&mut fixture, &mut notices, "recording.finalized.read", read).await?)?;
            bytes.extend(
                base64::engine::general_purpose::STANDARD
                    .decode(chunk["base64"].as_str().ok_or("chunk missing")?)
                    .map_err(|_| "base64")?,
            );
            if chunk["nextOffset"] != bytes.len() {
                return Err("chunk offset mismatch".into());
            }
            if chunk["eof"] == true {
                break;
            }
        }
        use sha2::{Digest, Sha256};
        if segment["size"] != bytes.len()
            || segment["sha256"] != format!("{:x}", Sha256::digest(&bytes))
        {
            return Err("frozen bytes failed integrity".into());
        }
        for _ in 0..2 {
            let released = completed(
                command(&mut fixture, &mut notices, "recording.finalized.release", base.clone()).await?,
            )?;
            if released != json!({"released":true}) {
                return Err("release receipt changed".into());
            }
        }
        if browser.blobs.charged_for_test() != (0, 0) {
            return Err("terminal release retained quota".into());
        }
        let mut read = base;
        read["offset"] = json!(0);
        read["maxBytes"] = json!(1);
        if command(&mut fixture, &mut notices, "recording.finalized.read", read).await?["ok"] != false {
            return Err("released bytes were resurrected".into());
        }
        if failed_command == "connection" {
            // Accepted at most once by the closed decoder, and required for this
            // explicit EOF fixture; not a substitute for its failed-result proof.
            if !notices.disconnected { return Err("EOF fixture omitted its exact disconnect notice".into()); }
            eprintln!("terminal recording EOF notices: disconnectOnce=true, callbacksRetired={}", notices.callbacks_retired);
        }
        // Decode only after transfer/release so it cannot extend the native cutoff.
        decode_video(&bytes).await?;
        let log = peer.requests.lock().unwrap();
        for (method, count) in [
            ("Page.startScreencast", 1),
            ("Page.stopScreencast", 1),
            ("Page.captureScreenshot", 1),
            ("Target.createBrowserContext", if clean_stop && failed_command == "scope.reset" { 2 } else { 1 }),
        ] {
            if log
                .iter()
                .filter(|request| request["method"] == method)
                .count()
                != count
            {
                return Err(format!("unexpected {method} replay/count"));
            }
        }
        if log.iter().any(|request| {
            request["method"]
                .as_str()
                .is_some_and(|method| method.starts_with("Input."))
        }) {
            return Err("terminal collection issued input".into());
        }
        Ok(())
    }
    .await;
    // Failed replacement remains Unknown, including any cleanup failure. Join
    // the real owner; do not claim artifact delivery proves its Closed receipt.
    let cleanup = fixture.finish().await;
    peer.task.abort();
    let _ = peer.task.await;
    assert_eq!(
        browser.blobs.charged_for_test(),
        (0, 0),
        "quota after terminal owner join; cleanup={cleanup:?}; proof={proof:?}"
    );
    proof.unwrap();
}
#[tokio::test]
#[ignore = "hosted ffmpeg/ffprobe; actual managed recording, failed replacement and terminal framed transfer"]
async fn failed_replacement_exports_only_finalized_recording_without_reopening_scope() {
    run(true, true).await;
}
#[tokio::test]
#[ignore = "hosted ffmpeg; same actual recording failure without negotiated terminal artifact authority"]
async fn failed_replacement_without_capability_never_exports_frozen_recording() {
    run(false, true).await;
}

#[tokio::test]
#[ignore = "hosted ffmpeg/ffprobe; actual stop error retains independently finalized bytes without clearing cleanup failure"]
async fn failed_replacement_with_stop_error_exports_verified_bytes_without_reopening() {
    run(true, false).await;
}

#[tokio::test]
#[ignore = "hosted ffmpeg/ffprobe; direct recording.stop fails after actual encoder completion and transfers only immutable bytes"]
async fn failed_stop_exports_verified_bytes_without_repeating_stop_or_new_session() {
    run_with_failure(true, false, "recording.stop").await;
}

#[tokio::test]
#[ignore = "hosted ffmpeg/ffprobe; real finalized segment survives actual failed Page.navigate receipt and framed terminal transfer"]
async fn failed_navigation_exports_real_previous_segment_without_reopening_scope() {
    run_with_failure(true, true, "page.navigate").await;
}

#[tokio::test]
#[ignore = "hosted ffmpeg/ffprobe; real CDP socket EOF during navigation retains a previously finalized real segment under the failed receipt"]
async fn failed_cdp_connection_exports_real_previous_segment_without_reconnect() {
    run_with_failure(true, true, "connection").await;
}

#[tokio::test]
#[ignore = "hosted ffmpeg; explicit Close races actual retained replacement failure before its outcome"]
async fn close_before_failed_replacement_result_releases_late_unclaimed_frozen_quota() {
    let (reached, wait_reached) = tokio::sync::oneshot::channel();
    let (release, wait_release) = tokio::sync::oneshot::channel();
    let peer = peer(true, Some((reached, wait_release)), None).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture = FramedFixture::with_capabilities(
        broker,
        browser.clone(),
        vec![
            "terminal.close/1".into(),
            super::super::super::client_protocol::TERMINAL_RECORDING_ARTIFACTS.into(),
        ],
    );
    let mut release = Some(release);
    let proof:Result<(),String>=async {
        let scope=setup(&mut fixture,&peer.endpoint).await?;
        fixture.command("recording.start",json!({"identityScope":scope}),5).await?;
        fixture.sequence+=1;
        fixture.write(json!({"type":"request","id":"held-reset","generation":1,"operationSeq":fixture.sequence,
            "timeoutMs":1000,"command":"scope.reset","args":{"identityScope":scope}})).await?;
        tokio::time::timeout(Duration::from_secs(2),wait_reached).await.map_err(|_|"second real create not reached")?.map_err(|_|"peer stopped")?;
        fixture.write(json!({"type":"close","id":"close-before-reset","generation":1})).await?;
        tokio::time::timeout(Duration::from_secs(1),async {
            while !browser.gate.state.lock().unwrap().closed {tokio::task::yield_now().await;}
        }).await.map_err(|_|"explicit Close never sealed actual gate")?;
        // Shutdown's first clear has run; its retained supervisor is still
        // awaiting this exact create ACK. The producer freezes only afterward.
        release.take().unwrap().send(()).map_err(|_|"retained reset dropped its actual create waiter")?;
        let drained=tokio::time::timeout(Duration::from_secs(12),async {
            let mut frames=Vec::new();
            for _ in 0..32 {
                let Some(bytes)=read_frame(&mut fixture.stream).await.map_err(|_|"terminal framing")? else {return Ok::<_,String>(frames);};
                frames.push(serde_json::from_slice::<Value>(&bytes).map_err(|_|"terminal JSON")?);
            }
            Err("terminal frame bound".into())
        }).await.map_err(|_|"explicit Close did not finish its original cleanup bound")??;
        if drained.iter().any(|frame|frame["type"]=="result" && frame["ok"]==true) {return Err("Close race published a successful operation".into());}
        if browser.terminal_recording.lock().unwrap().is_some() || browser.blobs.charged_for_test()!=(0,0) {
            return Err("joined late freeze outlived terminal cleanup receipt".into());
        }
        Ok(())
    }.await;
    if let Some(release) = release.take() {
        let _ = release.send(());
    }
    let cleanup = fixture.finish().await;
    peer.task.abort();
    let _ = peer.task.await;
    assert!(
        browser.terminal_recording.lock().unwrap().is_none(),
        "late batch after join; cleanup={cleanup:?}; proof={proof:?}"
    );
    assert_eq!(browser.blobs.charged_for_test(), (0, 0));
    proof.unwrap();
}

#[tokio::test]
async fn poisoned_terminal_recording_custody_never_proves_closed() {
    // Cleanup-state test only: authored bytes are not recording producer proof.
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let blobs = browser.blobs.clone();
    let scope = super::super::super::client_blobs::BlobScope {
        generation: 1,
        identity_scope: "poisoned-owner".into(),
    };
    blobs.activate_scope(scope.clone()).unwrap();
    let authority = blobs.begin_artifact_attempt(&scope).unwrap();
    let mut reservation = blobs.reserve_artifact(&authority, &scope).unwrap();
    blobs.shrink_artifact(&mut reservation, 3).unwrap();
    let frozen = blobs
        .freeze_finalized_artifacts(&authority, 1, vec![(reservation, b"abc".to_vec())])
        .unwrap();
    *browser.terminal_recording.lock().unwrap() = Some(
        super::super::super::client_terminal_artifacts::FrozenRecordingBatch::new(
            super::super::super::client_debt::OperationKey {
                generation: 1,
                operation_seq: 1,
            },
            scope.identity_scope,
            frozen
                .into_iter()
                .map(|blob| (blob, "2026-10-26T00:00:00.000Z".into(), 1))
                .collect(),
        ),
    );
    let slot = browser.terminal_recording.clone();
    assert!(std::thread::spawn(move || {
        let _held = slot.lock().unwrap();
        panic!("synthetic terminal custody poison");
    })
    .join()
    .is_err());
    let mut fixture =
        FramedFixture::with_capabilities(broker, browser.clone(), vec!["terminal.close/1".into()]);
    fixture.ready().await.unwrap();
    fixture
        .write(json!({"type":"close","id":"poison-close","generation":1}))
        .await
        .unwrap();
    let response = fixture.read().await.unwrap();
    assert_eq!(response["type"], "error");
    assert_eq!(response["id"], "poison-close");
    assert_eq!(response["error"]["code"], "cleanup-failed");
    assert!(
        read_frame(&mut fixture.stream).await.unwrap().is_none(),
        "poisoned custody falsely emitted Closed"
    );
    assert!(fixture.finish().await.is_err());
    assert_eq!(
        blobs.charged_for_test(),
        (3, 1),
        "poison was silently treated as successful quota cleanup"
    );
    drop(browser);
    assert_eq!(
        blobs.charged_for_test(),
        (0, 0),
        "final owner drop lost original charge accounting"
    );
}


#[test]
fn terminal_recording_notice_requires_exact_eof_and_callback_shapes() {
    let disconnect = json!({"type":"event","generation":1,"sequence":4,
        "event":"browser.disconnected","payload":{"reason":"browser-connection-closed"}});
    // The old application-only helper rejects the production EOF shape.
    assert!(validate_fixture_notice(&disconnect).is_err());
    let mut notices = TerminalNotices { disconnect_expected: true, ..Default::default() };
    assert_eq!(validate_terminal_notice(&disconnect, "scope", 1, 3, &mut notices), Ok(()));
    assert!(notices.disconnected);
    let retirement = json!({"type":"event","generation":1,"sequence":5,
        "event":"scope.callbacks-retired","payload":{"identityScope":"scope","throughEventSequence":4}});
    assert!(validate_fixture_notice(&retirement).is_err());
    assert_eq!(validate_terminal_notice(&retirement, "scope", 1, 4, &mut notices), Ok(()));
    assert!(notices.callbacks_retired);
    let mut unexpected = TerminalNotices::default();
    assert!(validate_terminal_notice(&disconnect, "scope", 1, 3, &mut unexpected).is_err());
    assert!(!unexpected.disconnected);
    for payload in [json!({"registryVersion":1}), json!({"registryVersion":1,"identityScope":"scope"})] {
        let registry = json!({"type":"event","generation":1,"sequence":4,"event":"registry-released","payload":payload});
        assert_eq!(validate_terminal_notice(&registry, "scope", 1, 3, &mut TerminalNotices::default()), Ok(()));
    }
    for (event, payload) in [
        ("app.log", json!({"identityScope":"scope","source":"console","level":"info","text":"fixture"})),
        ("app.navigation", json!({"identityScope":"scope","kind":"main","url":"about:blank","initiatedByOperation":true})),
        ("app.navigation", json!({"identityScope":"scope","kind":"frame","url":"about:blank","initiatedByOperation":false,"frameName":"fixture"})),
    ] {
        let frame = json!({"type":"event","generation":1,"sequence":4,"event":event,"payload":payload});
        assert_eq!(validate_terminal_notice(&frame, "scope", 1, 3, &mut TerminalNotices::default()), Ok(()));
    }
    let mut duplicate = disconnect.clone(); duplicate["sequence"] = json!(6);
    assert!(validate_terminal_notice(&duplicate, "scope", 1, 5, &mut notices).is_err());
}

#[test]
fn terminal_recording_notice_rejects_foreign_extra_duplicate_and_out_of_order_events() {
    let disconnect = json!({"type":"event","generation":1,"sequence":4,
        "event":"browser.disconnected","payload":{"reason":"browser-connection-closed"}});
    for (field, value) in [
        ("event", json!("unexpected.event")), ("generation", json!(2)), ("sequence", json!(3)),
        ("decision", json!({"token":"not-allowed"})), ("extra", json!(true)),
        ("payload", json!({"reason":"unproven-transport-error"})),
        ("payload", json!({"reason":"browser-connection-closed","identityScope":"foreign"})),
    ] {
        let mut invalid = disconnect.clone(); invalid[field] = value;
        let mut notices = TerminalNotices { disconnect_expected: true, ..Default::default() };
        assert!(validate_terminal_notice(&invalid, "scope", 1, 3, &mut notices).is_err(), "accepted {field}");
        assert!(!notices.disconnected && !notices.callbacks_retired);
    }
    for (event, payload) in [
        ("registry-released", json!({"registryVersion":1,"identityScope":"foreign"})),
        ("registry-released", json!({"registryVersion":1,"identityScope":null})),
        ("registry-released", json!({"registryVersion":1,"extra":true})),
        ("app.log", json!({"source":"console","level":"info","text":"fixture"})),
        ("app.log", json!({"identityScope":"foreign","source":"console","level":"info","text":"fixture"})),
        ("app.navigation", json!({"identityScope":"scope","kind":"main","url":"about:blank"})),
        ("app.navigation", json!({"identityScope":"foreign","kind":"main","url":"about:blank","initiatedByOperation":true})),
        ("app.navigation", json!({"identityScope":"scope","kind":"main","url":"about:blank","initiatedByOperation":true,"extra":true})),
    ] {
        let frame = json!({"type":"event","generation":1,"sequence":4,"event":event,"payload":payload});
        assert!(validate_terminal_notice(&frame, "scope", 1, 3, &mut TerminalNotices::default()).is_err(), "accepted {event}");
    }
    let retirement = json!({"type":"event","generation":1,"sequence":4,
        "event":"scope.callbacks-retired","payload":{"identityScope":"scope","throughEventSequence":3}});
    for payload in [json!({"identityScope":"foreign","throughEventSequence":3}),
        json!({"identityScope":"scope","throughEventSequence":2}),
        json!({"identityScope":"scope","throughEventSequence":3,"extra":true})] {
        let mut invalid = retirement.clone(); invalid["payload"] = payload;
        assert!(validate_terminal_notice(&invalid, "scope", 1, 3, &mut TerminalNotices::default()).is_err());
    }
    let mut notices = TerminalNotices::default();
    assert_eq!(validate_terminal_notice(&retirement, "scope", 1, 3, &mut notices), Ok(()));
    let repeated = json!({"type":"event","generation":1,"sequence":5,
        "event":"scope.callbacks-retired","payload":{"identityScope":"scope","throughEventSequence":4}});
    assert!(validate_terminal_notice(&repeated, "scope", 1, 4, &mut notices).is_err());
    assert!(validate_terminal_notice(&disconnect, "", 1, 3, &mut TerminalNotices::default()).is_err());
    assert!(validate_terminal_notice(&disconnect, "scope", 1, u64::MAX, &mut TerminalNotices::default()).is_err());
}

include!("client_interop_phase_one_failure_tests.rs");
include!("client_interop_replacement_recording_tests.rs");
