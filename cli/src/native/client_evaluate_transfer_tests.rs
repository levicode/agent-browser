//! Framed end-to-end coverage for the negotiated `page.evaluate` blob
//! transport. Only CDP bytes are scripted; the real framed reader/writer,
//! ClientBrowser executor, debt admission and blob store run unmodified.

use super::*;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

const STAGED_SOURCE_BYTES: usize = 3 * 1024 * 1024;
const STAGED_RESULT_BYTES: usize = 4 * 1024 * 1024;

fn page_info() -> Value {
    json!({"targetId":"application","type":"page","browserContextId":"persistent-context","url":"about:blank","title":""})
}

/// One scripted persistent page. `Runtime.evaluate` answers small evaluations
/// inline and, when the wrapper expression carries the result marker, returns a
/// value that cannot fit one protocol frame.
async fn peer() -> (String, Arc<Mutex<Vec<Value>>>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let recorded = log.clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        socket.set_nodelay(true).unwrap();
        let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        while let Some(Ok(Message::Text(text))) = socket.next().await {
            let request: Value = serde_json::from_str(&text).unwrap();
            recorded.lock().unwrap().push(request.clone());
            let method = request["method"].as_str().unwrap();
            let session = request["sessionId"].as_str().unwrap_or_default();
            let mut after = Vec::new();
            let result = match method {
                "Target.getBrowserContexts" => json!({
                    "browserContextIds":["foreign-context"],
                    "defaultBrowserContextId":"persistent-context"
                }),
                "Target.getTargets" => json!({"targetInfos":[page_info()]}),
                "Target.getTargetInfo" => json!({"targetInfo":page_info()}),
                "Target.attachToTarget" => {
                    assert_eq!(request["params"]["targetId"], "application");
                    json!({"sessionId":"initial-session"})
                }
                "Target.setAutoAttach" | "Target.setDiscoverTargets" => json!({}),
                "Target.closeTarget" => {
                    assert_eq!(request["params"]["targetId"], "application");
                    after.push(json!({"method":"Target.detachedFromTarget","params":{
                        "sessionId":"initial-session","targetId":"application"
                    }}));
                    json!({"success":true})
                }
                "Target.detachFromTarget" => {
                    after.push(json!({"method":"Target.detachedFromTarget","params":{
                        "sessionId":request["params"]["sessionId"]
                    }}));
                    json!({})
                }
                "Browser.getVersion" => json!({"product":"Synthetic Chrome/1"}),
                "Page.getFrameTree" => json!({"frameTree":{"frame":{
                    "id":format!("frame-{session}"),
                    "loaderId":"blank-loader",
                    "url":"about:blank",
                    "securityOrigin":"null"
                }}}),
                "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":"init-script"}),
                "Page.navigate" => {
                    let frame = format!("frame-{session}");
                    after.push(json!({"method":"Page.frameNavigated","sessionId":session,"params":{
                        "frame":{"id":frame,"loaderId":"fresh-loader","url":"about:blank","securityOrigin":"null"}
                    }}));
                    after.push(
                        json!({"method":"Page.lifecycleEvent","sessionId":session,"params":{
                            "frameId":frame,"loaderId":"fresh-loader","name":"DOMContentLoaded"
                        }}),
                    );
                    json!({"frameId":frame,"loaderId":"fresh-loader"})
                }
                "Runtime.evaluate" => {
                    let expression = request["params"]["expression"].as_str().unwrap();
                    match expression {
                        "document.title" => json!({"result":{"type":"string","value":"synthetic"}}),
                        "location.href" => {
                            json!({"result":{"type":"string","value":"about:blank"}})
                        }
                        _ => {
                            assert!(
                                expression.starts_with("(async()=>{const value=await ("),
                                "unmodeled evaluate expression"
                            );
                            if expression.contains("STAGED-REQUEST-MARKER") {
                                assert!(
                                    expression.len() > STAGED_SOURCE_BYTES,
                                    "staged source never reached CDP whole"
                                );
                            }
                            let value = if expression.contains("STAGED-RESULT-MARKER") {
                                "r".repeat(STAGED_RESULT_BYTES)
                            } else {
                                "small".to_string()
                            };
                            json!({"result":{"type":"object","value":{
                                "value":{"ok":true,"value":value}
                            }}})
                        }
                    }
                }
                "Runtime.releaseObject" | "Runtime.releaseObjectGroup" => json!({}),
                "Network.disable" => json!({}),
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
                | "Page.setLifecycleEventsEnabled"
                | "Emulation.setEmulatedMedia"
                | "Emulation.setDeviceMetricsOverride"
                | "Runtime.runIfWaitingForDebugger"
                | "Page.removeScriptToEvaluateOnNewDocument" => json!({}),
                other => panic!("unmodeled CDP method {other}: {request}"),
            };
            let mut reply = json!({"id":request["id"],"result":result});
            if let Some(session) = request.get("sessionId") {
                reply["sessionId"] = session.clone();
            }
            if socket.send(Message::Text(reply.to_string())).await.is_err() {
                return;
            }
            for event in after {
                if socket.send(Message::Text(event.to_string())).await.is_err() {
                    return;
                }
            }
        }
    });
    (endpoint, log, server)
}

async fn open_scope(fixture: &mut FramedFixture, endpoint: &str) -> Result<String, String> {
    fixture.ready().await?;
    let mut args = fixture_scope_open("connect", Some(endpoint));
    args["context"] = "persistent".into();
    let opened = fixture.command("scope.open", args, 5).await?;
    let scope = opened["identityScope"]
        .as_str()
        .ok_or("evaluate fixture scope")?
        .to_owned();
    fixture.scope = Some(scope.clone());
    fixture
        .command("scope.configure", fixture_configuration(&scope, None), 5)
        .await?;
    fixture
        .command("network.routes.replace", fixture_routes(&scope), 5)
        .await?;
    fixture.registry = 1;
    fixture
        .command("page.activate", json!({"identityScope":scope}), 5)
        .await?;
    Ok(scope)
}

async fn staged_blob(
    fixture: &mut FramedFixture,
    scope: &str,
    bytes: &[u8],
) -> Result<String, String> {
    let sha256 = {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(bytes))
    };
    let created = fixture
        .command(
            "blob.create",
            json!({"identityScope":scope,"size":bytes.len(),"sha256":sha256}),
            5,
        )
        .await?;
    let handle = created["handle"]
        .as_str()
        .ok_or("create omitted handle")?
        .to_owned();
    let max_chunk = created["maxChunkBytes"]
        .as_u64()
        .ok_or("create omitted chunk")? as usize;
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + max_chunk).min(bytes.len());
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes[offset..end]);
        let written = fixture
            .command(
                "blob.write",
                json!({"identityScope":scope,"handle":handle,"offset":offset,"base64":encoded}),
                5,
            )
            .await?;
        if written["nextOffset"] != json!(end) {
            return Err("blob.write advanced an unexpected offset".into());
        }
        offset = end;
    }
    let sealed = fixture
        .command(
            "blob.seal",
            json!({"identityScope":scope,"handle":handle}),
            5,
        )
        .await?;
    if sealed["size"] != json!(bytes.len()) {
        return Err("sealed request blob changed size".into());
    }
    Ok(handle)
}

async fn read_blob(
    fixture: &mut FramedFixture,
    scope: &str,
    handle: &str,
    max_chunk: usize,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut offset = 0;
    loop {
        let chunk = fixture
            .command(
                "blob.read",
                json!({"identityScope":scope,"handle":handle,"offset":offset,"maxBytes":max_chunk}),
                5,
            )
            .await?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(chunk["base64"].as_str().ok_or("read omitted bytes")?)
            .map_err(|_| "read was not base64")?;
        bytes.extend(decoded);
        offset = chunk["nextOffset"]
            .as_u64()
            .ok_or("read omitted the next offset")? as usize;
        if chunk["eof"].as_bool().unwrap_or(false) {
            return Ok(bytes);
        }
        if offset == 0 {
            return Err("blob.read did not advance".into());
        }
    }
}

/// These framed fixtures drive the full executor future by hand. Run them on an
/// explicitly sized thread so the deep async state machine never depends on the
/// test harness's default 2 MiB stack.
fn run_on_stack(future: impl std::future::Future<Output = ()> + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(future);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn negotiated_evaluate_stages_oversized_requests_and_results_through_blobs() {
    run_on_stack(async {
        let (endpoint, log, peer) = peer().await;
        let broker = Arc::new(ClientSession::new());
        let browser = Arc::new(ClientBrowser::new(broker.clone()));
        let mut fixture = FramedFixture::with_capabilities(
            broker,
            browser.clone(),
            vec![crate::native::client_protocol::EVALUATE_BLOBS.into()],
        );
        let proof: Result<(), String> = async {
            let scope = open_scope(&mut fixture, &endpoint).await?;

            if !browser
                .event_sink
                .get()
                .is_some_and(|sink| sink.evaluate_blobs_negotiated())
            {
                return Err("evaluate blob negotiation was not recorded".into());
            }

            // A small result keeps its inline single-frame shape and value.
            let inline = fixture
                .command(
                    "page.evaluate",
                    json!({"identityScope":scope,"source":"()=>17","argument":null}),
                    5,
                )
                .await
                .map_err(|error| format!("inline evaluate: {error}"))?;
            if inline != json!({"value":{"ok":true,"value":"small"}}) {
                return Err(format!("inline evaluate changed shape: {inline}"));
            }

            // A small staged request takes the same blob path as the oversized one,
            // so a failure here separates the transport from the payload size.
            let small_payload = serde_json::to_vec(&json!({"source":"()=>17","argument":null}))
                .map_err(|_| "small stage serialization")?;
            let small_handle = staged_blob(&mut fixture, &scope, &small_payload).await?;
            let staged_small = fixture
                .command(
                    "page.evaluate",
                    json!({"identityScope":scope,"requestHandle":small_handle}),
                    5,
                )
                .await
                .map_err(|error| format!("small staged evaluate: {error}"))?;
            if staged_small != json!({"value":{"ok":true,"value":"small"}}) {
                return Err(format!(
                    "staged small evaluate changed shape: {staged_small}"
                ));
            }
            fixture
                .command(
                    "blob.release",
                    json!({"identityScope":scope,"handle":small_handle}),
                    5,
                )
                .await?;

            // Three megabytes of source plus its argument, staged through the same
            // blob channel an integration would use. Every request frame here is a
            // bounded descriptor or one 256 KiB chunk.
            let staged_payload = serde_json::to_vec(&json!({
                "source": format!(
                    "()=>{{/*{}STAGED-REQUEST-MARKER*/return 1}}",
                    "a".repeat(STAGED_SOURCE_BYTES)
                ),
                "argument": {"marker": "STAGED-RESULT-MARKER"},
            }))
            .map_err(|_| "stage serialization")?;
            if staged_payload.len() <= crate::native::client_protocol::MAX_FRAME_BYTES {
                return Err("staged request did not exceed one frame".into());
            }
            let request_handle = staged_blob(&mut fixture, &scope, &staged_payload).await?;

            // A four megabyte result cannot be returned inline. The writer must
            // publish one bounded descriptor instead of ending the transport.
            let data = fixture
                .command(
                    "page.evaluate",
                    json!({"identityScope":scope,"requestHandle":request_handle}),
                    5,
                )
                .await
                .map_err(|error| format!("staged evaluate: {error}"))?;
            let result_handle = data["resultHandle"]
                .as_str()
                .ok_or_else(|| format!("evaluate result was not staged: {data}"))?
                .to_owned();
            let max_chunk = data["maxChunkBytes"]
                .as_u64()
                .ok_or("result descriptor omitted chunk size")?
                as usize;
            if data["size"].as_u64().unwrap_or_default() as usize
                <= crate::native::client_protocol::MAX_FRAME_BYTES
            {
                return Err("oversized result was not routed through a blob".into());
            }
            // The descriptor alone is what the writer framed, well under the bound.
            if serde_json::to_vec(&data)
                .map_err(|_| "descriptor serialization")?
                .len()
                >= crate::native::client_protocol::MAX_FRAME_BYTES
            {
                return Err("result descriptor did not fit one frame".into());
            }

            let bytes = read_blob(&mut fixture, &scope, &result_handle, max_chunk).await?;
            let decoded: Value =
                serde_json::from_slice(&bytes).map_err(|_| "result blob was not JSON")?;
            if decoded["value"]["ok"] != true
                || decoded["value"]["value"].as_str().map(str::len) != Some(STAGED_RESULT_BYTES)
            {
                return Err("staged result did not round-trip its exact value".into());
            }
            let sha256 = {
                use sha2::{Digest, Sha256};
                format!("{:x}", Sha256::digest(&bytes))
            };
            if data["sha256"] != json!(sha256) {
                return Err("result descriptor hash did not match its bytes".into());
            }

            // Both staged resources remain releasable by the client.
            fixture
                .command(
                    "blob.release",
                    json!({"identityScope":scope,"handle":result_handle}),
                    5,
                )
                .await?;
            fixture
                .command(
                    "blob.release",
                    json!({"identityScope":scope,"handle":request_handle}),
                    5,
                )
                .await?;

            // The real CDP evaluate received the whole staged source in one
            // command; the peer asserted its length above.
            if !log.lock().unwrap().iter().any(|request| {
                request["method"] == "Runtime.evaluate"
                    && request["params"]["expression"]
                        .as_str()
                        .is_some_and(|expression| expression.contains("STAGED-REQUEST-MARKER"))
            }) {
                return Err("staged evaluate never reached the browser".into());
            }
            Ok(())
        }
        .await;
        let cleanup = fixture.finish().await;
        peer.abort();
        let _ = peer.await;
        assert!(
            proof.is_ok() && cleanup.is_ok(),
            "proof={proof:?}; cleanup={cleanup:?}"
        );
    });
}

#[test]
fn unterminated_legacy_client_refuses_an_oversized_result_without_dropping_the_transport() {
    run_on_stack(async {
        let (endpoint, log, peer) = peer().await;
        let broker = Arc::new(ClientSession::new());
        let browser = Arc::new(ClientBrowser::new(broker.clone()));
        // No EVALUATE_BLOBS: the legacy single-frame contract is unchanged.
        let mut fixture = FramedFixture::new(broker, browser);
        let proof: Result<(), String> = async {
        let scope = open_scope(&mut fixture, &endpoint).await?;
        fixture.sequence += 1;
        let sequence = fixture.sequence;
        fixture
            .write(json!({"type":"request","id":"legacy-evaluate","generation":1,
                "operationSeq":sequence,"timeoutMs":5000,"command":"page.evaluate",
                "args":{"identityScope":scope,"source":"()=>{/*STAGED-RESULT-MARKER*/return 1}","argument":null}}))
            .await?;
        let mut frame = fixture.read().await?;
        for _ in 0..64 {
            match frame["type"].as_str() {
                Some("event") => {
                    validate_fixture_notice(&frame)?;
                    fixture.event_sequence = frame["sequence"]
                        .as_u64()
                        .ok_or("event omitted sequence")?;
                    frame = fixture.read().await?;
                }
                Some("result") => break,
                _ => return Err("legacy evaluate returned an unexpected frame".into()),
            }
        }
        if frame["type"] != "result"
            || frame["id"] != "legacy-evaluate"
            || frame["operationSeq"] != sequence
        {
            return Err("legacy oversized result lost its correlated outcome".into());
        }
        // Before the transport change this result was serialized above the frame
        // bound and the writer ended the connection with no error frame. The
        // refusal below is the whole correlated outcome, not a transport loss.
        if frame["ok"] != false
            || frame["error"]["code"] != "capacity-exceeded"
            || frame["effects"] != "unknown"
        {
            return Err(format!(
                "legacy oversized result was not refused cleanly: {frame}"
            ));
        }
        if !log
            .lock()
            .unwrap()
            .iter()
            .any(|request| {
                request["method"] == "Runtime.evaluate"
                    && request["params"]["expression"]
                        .as_str()
                        .is_some_and(|expression| expression.contains("STAGED-RESULT-MARKER"))
            })
        {
            return Err("legacy evaluate never reached the browser".into());
        }
        Ok(())
    }
    .await;
        let _ = fixture.finish().await;
        peer.abort();
        let _ = peer.await;
        proof.unwrap();
    });
}
