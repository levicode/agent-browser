//! Pure websocket peer + real ClientBrowser + real framed writer. No browser process.
//! Source regression: execution is intentionally delegated to central validation.
use super::*;
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};
use tokio::io::AsyncWrite;
use tokio_tungstenite::tungstenite::Message;

#[derive(Default)]
struct RestartFlush {
    armed: AtomicBool,
    reached: AtomicBool,
    release: AtomicBool,
    waker: Mutex<Option<Waker>>,
}
impl RestartFlush {
    fn release(&self) {
        self.release.store(true, Ordering::SeqCst);
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}
struct RestartWriter<W> {
    inner: W,
    gate: Arc<RestartFlush>,
}
impl<W: AsyncWrite + Unpin> AsyncWrite for RestartWriter<W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut waker = self.gate.waker.lock().unwrap();
        if self.gate.armed.load(Ordering::SeqCst) && !self.gate.release.load(Ordering::SeqCst) {
            self.gate.reached.store(true, Ordering::SeqCst);
            *waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        drop(waker);
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
fn framed(
    browser: Arc<ClientBrowser>,
    broker: Arc<ClientSession>,
    gate: Arc<RestartFlush>,
) -> FramedFixture {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let (reader, writer) = tokio::io::split(server);
    let server = tokio::spawn(serve_with_executor(
        tokio::io::BufReader::new(reader),
        RestartWriter {
            inner: writer,
            gate,
        },
        ClientMessage::Hello {
            id: "fixture-hello".into(),
            protocol: PROTOCOL.into(),
            required_capabilities: vec![],
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
fn target(id: &str, kind: &str) -> Value {
    json!({"targetId":id,"type":kind,"browserContextId":"synthetic-context","url":"about:blank","title":""})
}
fn attach(id: &str, session: &str, kind: &str) -> Value {
    json!({"method":"Target.attachedToTarget","params":{"sessionId":session,
        "targetInfo":target(id,kind),"waitingForDebugger":true}})
}
async fn peer(
    ack_before_attach: bool,
) -> (String, Arc<Mutex<Vec<Value>>>, tokio::task::JoinHandle<()>) {
    peer_with_inputs(ack_before_attach, None, false).await
}
async fn peer_with_inputs(
    ack_before_attach: bool,
    old_input: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    hold_old_input: bool,
) -> (String, Arc<Mutex<Vec<Value>>>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let recorded = log.clone();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut pages = std::collections::BTreeMap::<String, Value>::new();
        let mut created = 0;
        let mut worker = false;
        let mut late_old = false;
        while let Some(Ok(Message::Text(text))) = socket.next().await {
            let request: Value = serde_json::from_str(&text).unwrap();
            recorded.lock().unwrap().push(request.clone());
            let method = request["method"].as_str().unwrap();
            let session = request["sessionId"].as_str().unwrap_or("");
            let mut before = Vec::new();
            let mut after = Vec::new();
            let result = match method {
                "Target.createBrowserContext" => json!({"browserContextId":"synthetic-context"}),
                "Target.createTarget" => {
                    created += 1;
                    let id = format!("page-{created}");
                    let sid = format!("session-{created}");
                    pages.insert(id.clone(), target(&id, "page"));
                    if created > 1 {
                        if ack_before_attach {
                            after.push(attach(&id, &sid, "page"));
                        } else {
                            before.push(attach(&id, &sid, "page"));
                        }
                    }
                    json!({"targetId":id})
                }
                "Target.attachToTarget" => {
                    assert_eq!(
                        created, 1,
                        "replacement must use autoattach, not rediscovery"
                    );
                    json!({"sessionId":"session-1"})
                }
                "Target.setAutoAttach" => {
                    if session.is_empty() && request["params"]["autoAttach"] == true && !worker {
                        worker = true;
                        pages.insert("worker".into(), target("worker", "service_worker"));
                        before.push(attach("worker", "worker-session", "service_worker"));
                    }
                    json!({})
                }
                "Target.getTargets" => {
                    json!({"targetInfos":pages.values().cloned().collect::<Vec<_>>()})
                }
                "Target.getTargetInfo" => {
                    let id = request["params"]["targetId"]
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| session.replace("session-", "page-"));
                    json!({"targetInfo":pages.get(&id).unwrap()})
                }
                "Runtime.runIfWaitingForDebugger" => {
                    if session == "session-2" {
                        before.push(json!({"method":"Runtime.consoleAPICalled","sessionId":session,
                            "params":{"type":"log","executionContextId":1,"args":[{"type":"string","value":"replacement-resumed"}]}}));
                    }
                    json!({})
                }
                "Target.closeTarget" => {
                    let id = request["params"]["targetId"].as_str().unwrap();
                    assert_ne!(id, "worker");
                    pages.remove(id);
                    after.push(json!({"method":"Target.detachedFromTarget","params":{
                        "targetId":id,"sessionId":id.replace("page-","session-")}}));
                    json!({"success":true})
                }
                "Target.disposeBrowserContext" => {
                    pages.clear();
                    json!({})
                }
                "Page.getFrameTree" => {
                    json!({"frameTree":{"frame":{"id":format!("frame-{session}"),
                    "loaderId":"initial-loader","url":"about:blank","securityOrigin":"null"}}})
                }
                "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":"synthetic-script"}),
                "Runtime.evaluate" => {
                    if created > 1 {
                        assert_eq!(
                            session,
                            format!("session-{created}"),
                            "first follow-up dispatched on stale session"
                        );
                        if !late_old {
                            late_old = true;
                            before.push(json!({"method":"Target.detachedFromTarget","params":{"targetId":"page-1","sessionId":"session-1"}}));
                            before.push(json!({"method":"Runtime.executionContextsCleared","sessionId":"session-1","params":{}}));
                        }
                    }
                    if request["params"]["expression"] == "location.href" {
                        json!({"result":{"type":"string","value":"https://synthetic.test/after-restart"}})
                    } else {
                        json!({"result":{"type":"object","value":{"value":17}}})
                    }
                }
                "Page.navigate" => {
                    assert_eq!(session, format!("session-{created}"));
                    let frame = format!("frame-{session}");
                    after.push(json!({"method":"Page.frameNavigated","sessionId":session,"params":{
                        "frame":{"id":frame,"loaderId":"followup-loader","url":"https://synthetic.test/after-restart","securityOrigin":"https://synthetic.test"}}}));
                    after.push(
                        json!({"method":"Page.lifecycleEvent","sessionId":session,"params":{
                        "frameId":frame,"loaderId":"followup-loader","name":"load"}}),
                    );
                    json!({"frameId":frame,"loaderId":"followup-loader"})
                }
                "Input.insertText" if old_input.is_some() => {
                    assert_eq!(request["params"]["text"], "older-native-input");
                    old_input.as_ref().unwrap().send(request.clone()).unwrap();
                    if hold_old_input {
                        continue;
                    }
                    json!({})
                }
                "Input.dispatchKeyEvent"
                | "Input.dispatchMouseEvent"
                | "Emulation.setDeviceMetricsOverride"
                    if old_input.is_some() =>
                {
                    json!({})
                }
                // Explicitly bounded ACK-only protocol, never fake a value-returning command.
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
                | "Target.setDiscoverTargets"
                | "Page.removeScriptToEvaluateOnNewDocument" => json!({}),
                other => panic!("unmodeled CDP method {other}: {request}"),
            };
            for event in before {
                if socket.send(Message::Text(event.to_string())).await.is_err() {
                    return;
                }
            }
            if socket
                .send(Message::Text(
                    json!({"id":request["id"],"result":result}).to_string(),
                ))
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
    (endpoint, log, task)
}

#[tokio::test]
async fn real_restart_writer_then_first_evaluate_and_navigation_use_replacement() {
    for ack_before_attach in [false, true] {
        let (endpoint, log, peer) = peer(ack_before_attach).await;
        let broker = Arc::new(ClientSession::new());
        let browser = Arc::new(ClientBrowser::new(broker.clone()));
        let gate = Arc::new(RestartFlush::default());
        let mut fixture = framed(browser.clone(), broker.clone(), gate.clone());
        let result: Result<(),String> = async {
            fixture.ready().await?;
            let opened = fixture.command("scope.open",fixture_scope_open("connect",Some(&endpoint)),5).await?;
            let scope = opened["identityScope"].as_str().ok_or("missing scope")?.to_owned();
            fixture.scope = Some(scope.clone());
            fixture.command("scope.configure",fixture_configuration(&scope,None),5).await?;
            fixture.command("network.routes.replace",fixture_routes(&scope),5).await?;
            fixture.registry = 1;
            fixture.command("context.media",json!({"identityScope":scope,"colorScheme":"dark","reducedMotion":"reduce"}),5).await?;
            gate.armed.store(true,Ordering::SeqCst);
            let restarted = fixture.command("scope.restart",json!({"identityScope":scope}),5).await?;
            assert_eq!(restarted["identityScope"],scope);
            assert!(gate.reached.load(Ordering::SeqCst));
            // Result bytes are observable, but the real writer has not acknowledged publication.
            assert!(tokio::time::timeout(Duration::from_millis(20),fixture.read()).await.is_err());
            gate.release();
            let published = tokio::time::timeout(Duration::from_secs(1),fixture.read()).await
                .map_err(|_|"replacement event not published after flush")??;
            assert_eq!(published["event"],"app.log");
            assert_eq!(published["payload"]["text"],"replacement-resumed");
            assert_eq!(published["payload"]["identityScope"],scope);
            fixture.event_sequence += 1;
            assert_eq!(published["sequence"],fixture.event_sequence);
            let evaluated = fixture.command("page.evaluate",json!({"identityScope":scope,"source":"()=>17","argument":null}),5).await?;
            assert_eq!(evaluated,json!({"value":17}));
            fixture.command("page.navigate",json!({"identityScope":scope,"url":"https://synthetic.test/after-restart","waitUntil":"load"}),5).await?;
            assert_eq!(broker.health().unwrap().1,ScopeState::Usable);
            let current = browser.page_lease(false).await.map_err(|e|format!("post-navigation lease: {e:?}"))?;
            assert_eq!(current.target_id,"page-2"); assert_eq!(current.page_session_id,"session-2");
            assert!(current.targets.owned_target("worker").unwrap().resumed);
            drop(current);
            // A second transition must not reuse the first replacement or its staged operation key.
            fixture.command("scope.restart",json!({"identityScope":scope}),5).await?;
            assert_eq!(fixture.command("page.evaluate",json!({"identityScope":scope,"source":"()=>17","argument":null}),5).await?,json!({"value":17}));
            fixture.command("page.navigate",json!({"identityScope":scope,"url":"https://synthetic.test/after-restart","waitUntil":"load"}),5).await?;
            let current = browser.page_lease(false).await.map_err(|e|format!("second replacement lease: {e:?}"))?;
            assert_eq!(current.target_id,"page-3"); assert_eq!(current.page_session_id,"session-3");
            let log = log.lock().unwrap();
            assert_eq!(log.iter().filter(|r|r["method"]=="Target.createTarget").count(),3);
            assert!(!log.iter().any(|r|r["method"]=="Target.detachFromTarget" || r["method"]=="Fetch.disable"));
            for session in ["session-2","session-3"] {
                assert!(log.iter().any(|r| r["method"]=="Emulation.setEmulatedMedia" && r["sessionId"]==session
                    && r["params"]["features"]==json!([{"name":"prefers-color-scheme","value":"dark"},{"name":"prefers-reduced-motion","value":"reduce"}])));
            }
            Ok(())
        }.await;
        // Preserve the first failure, but never leave the real native owner blocked in flush.
        gate.release();
        let cleanup = fixture.finish().await;
        peer.abort();
        result.unwrap();
        cleanup.unwrap();
    }
}

#[path = "client_browser_input_waiter_tests.rs"]
mod input_waiter_tests;
