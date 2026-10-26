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
    peer_with_cleanup(ack_before_attach, old_input, hold_old_input, None).await
}
async fn peer_with_cleanup(
    ack_before_attach: bool,
    old_input: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    hold_old_input: bool,
    cleanup_ack: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
) -> (String, Arc<Mutex<Vec<Value>>>, tokio::task::JoinHandle<()>) {
    peer_with_title(
        ack_before_attach,
        old_input,
        hold_old_input,
        cleanup_ack,
        None,
    )
    .await
}
async fn peer_with_title(
    ack_before_attach: bool,
    old_input: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    hold_old_input: bool,
    cleanup_ack: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    title_seen: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
) -> (String, Arc<Mutex<Vec<Value>>>, tokio::task::JoinHandle<()>) {
    peer_with_input_replies(
        ack_before_attach,
        old_input,
        hold_old_input,
        cleanup_ack,
        title_seen,
        None,
        false,
    )
    .await
}
async fn peer_with_input_replies(
    ack_before_attach: bool,
    old_input: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    hold_old_input: bool,
    cleanup_ack: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    title_seen: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    input_replies: Option<tokio::sync::mpsc::UnboundedReceiver<Value>>,
    hold_point: bool,
) -> (String, Arc<Mutex<Vec<Value>>>, tokio::task::JoinHandle<()>) {
    peer_with_media_replies(
        ack_before_attach,
        old_input,
        hold_old_input,
        cleanup_ack,
        title_seen,
        input_replies,
        hold_point,
        None,
    )
    .await
}

async fn peer_with_media_replies(
    ack_before_attach: bool,
    old_input: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    hold_old_input: bool,
    cleanup_ack: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    title_seen: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    input_replies: Option<tokio::sync::mpsc::UnboundedReceiver<Value>>,
    hold_point: bool,
    media_seen: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
) -> (String, Arc<Mutex<Vec<Value>>>, tokio::task::JoinHandle<()>) {
    peer_with_media_and_startup_replies(
        ack_before_attach,
        old_input,
        hold_old_input,
        cleanup_ack,
        title_seen,
        input_replies,
        hold_point,
        media_seen,
        None,
    )
    .await
}
async fn peer_with_startup_acquisition(
    ack_before_attach: bool,
    old_input: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    hold_old_input: bool,
    cleanup_ack: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    title_seen: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    input_replies: Option<tokio::sync::mpsc::UnboundedReceiver<Value>>,
    hold_point: bool,
    startup_ack: Option<(
        tokio::sync::oneshot::Sender<Value>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
) -> (String, Arc<Mutex<Vec<Value>>>, tokio::task::JoinHandle<()>) {
    peer_with_media_and_startup_replies(
        ack_before_attach,
        old_input,
        hold_old_input,
        cleanup_ack,
        title_seen,
        input_replies,
        hold_point,
        None,
        startup_ack,
    )
    .await
}
async fn peer_with_media_and_startup_replies(
    ack_before_attach: bool,
    old_input: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    hold_old_input: bool,
    mut cleanup_ack: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    title_seen: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    mut input_replies: Option<tokio::sync::mpsc::UnboundedReceiver<Value>>,
    hold_point: bool,
    media_seen: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    mut startup_ack: Option<(
        tokio::sync::oneshot::Sender<Value>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
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
        loop {
            let incoming = if let Some(replies) = &mut input_replies {
                tokio::select! {
                    incoming = socket.next() => incoming,
                    Some(reply) = replies.recv() => {
                        // Only the media fixture emits a genuinely attached new
                        // page through this lane; retain its native inventory.
                        if media_seen.is_some() && reply["method"] == "Target.attachedToTarget" {
                            let info = reply["params"]["targetInfo"].clone();
                            pages.insert(info["targetId"].as_str().unwrap().to_owned(), info);
                        }
                        if socket.send(Message::Text(reply.to_string())).await.is_err() { return; }
                        continue;
                    }
                }
            } else {
                socket.next().await
            };
            let Some(Ok(Message::Text(text))) = incoming else {
                break;
            };
            let request: Value = serde_json::from_str(&text).unwrap();
            recorded.lock().unwrap().push(request.clone());
            let method = request["method"].as_str().unwrap();
            let session = request["sessionId"].as_str().unwrap_or("");
            let mut before = Vec::new();
            let mut after = Vec::new();
            let result = match method {
                "Browser.getVersion" => {
                    assert!(request.get("sessionId").is_none());
                    assert_eq!(request["params"], json!({}));
                    json!({
                        "protocolVersion":"1.3",
                        "product":"Synthetic Chromium/1.0",
                        "revision":"synthetic-revision",
                        "userAgent":"Synthetic Chromium Linux",
                        "jsVersion":"synthetic-js"
                    })
                }
                "Target.createBrowserContext" => json!({"browserContextId":"synthetic-context"}),
                "Target.createTarget" => {
                    created += 1;
                    let id = format!("page-{created}");
                    let sid = format!("session-{created}");
                    pages.insert(id.clone(), target(&id, "page"));
                    if created == 1 {
                        if let Some((reached, release)) = startup_ack.take() {
                            reached.send(request.clone()).unwrap();
                            release.await.unwrap();
                        }
                    }
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
                    if session.is_empty() && request["params"]["autoAttach"] == false {
                        if let Some((reached, release)) = cleanup_ack.take() {
                            let _ = reached.send(());
                            let _ = release.await;
                        }
                    }
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
                    if request["params"]["expression"] == "document.title" {
                        if let Some(seen) = &title_seen {
                            seen.send(request.clone()).unwrap();
                            // Withhold this read's reply, not the transport or
                            // cleanup commands. Only native cancel/deadline can
                            // settle the real ClientBrowser operation.
                            continue;
                        }
                    }
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
                "Page.navigate"
                    if media_seen.is_some()
                        && request["params"]["url"] == "https://synthetic.test/held-non-media" =>
                {
                    media_seen.as_ref().unwrap().send(request.clone()).unwrap();
                    // Cross-command negative: neither this real mutation's ACK
                    // nor its lifecycle events exist until the test releases it.
                    continue;
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
                "Input.dispatchMouseEvent" if hold_point => {
                    old_input.as_ref().unwrap().send(request.clone()).unwrap();
                    continue;
                }
                "Input.dispatchKeyEvent"
                | "Input.dispatchMouseEvent"
                | "Emulation.setDeviceMetricsOverride"
                    if old_input.is_some() =>
                {
                    json!({})
                }
                "Emulation.setEmulatedMedia" if media_seen.is_some() => {
                    media_seen.as_ref().unwrap().send(request.clone()).unwrap();
                    // The test supplies this exact ACK through the independent
                    // reply lane; do not block the websocket command reader.
                    continue;
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
                | "Browser.close"
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
            // Flattened CDP replies carry the exact session of their request.
            // Browser-level replies omit it; a missing session is not an ACK
            // for a command submitted on a page or worker session.
            let mut response = json!({"id":request["id"],"result":result});
            if let Some(session) = request.get("sessionId") {
                assert!(session.as_str().is_some_and(|value| !value.is_empty()));
                response["sessionId"] = session.clone();
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
            let enrollment = browser.owner.lock().await.as_ref().unwrap()
                .runtime.as_ref().unwrap().enrollment.clone();
            let (_cancel, cancellation) = tokio::sync::watch::channel(
                crate::native::client_session::CancelSignal::None,
            );
            let input_operation = crate::native::client_session::OperationLease {
                is_callback: false,
                generation: 1,
                sequence: fixture.sequence,
                deadline: std::time::Instant::now() + Duration::from_secs(5),
                cancellation,
            };
            let current = browser.page_lease(false).await.map_err(|e|format!("first replacement input lease: {e:?}"))?;
            // The real lifecycle left old-page tombstones in this enrollment.
            // Fresh input authority must distinguish those from pending retirement.
            let first_input = enrollment.capture_settled_input_authority(&current, &input_operation)
                .map_err(|e|format!("first replacement input authority: {e:?}"))?;
            first_input.check(&enrollment, &current, &input_operation)
                .map_err(|e|format!("first replacement input check: {e:?}"))?;
            drop(current);
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
            let current = browser.page_lease(false).await.map_err(|e|format!("second replacement input lease: {e:?}"))?;
            assert!(first_input.check(&enrollment, &current, &input_operation).is_err());
            let second_operation = crate::native::client_session::OperationLease {
                is_callback: false,
                generation: 1,
                sequence: fixture.sequence,
                deadline: std::time::Instant::now() + Duration::from_secs(5),
                cancellation: input_operation.cancellation.clone(),
            };
            let second_input = enrollment.capture_settled_input_authority(&current, &second_operation)
                .map_err(|e|format!("second replacement input authority: {e:?}"))?;
            second_input.check(&enrollment, &current, &second_operation)
                .map_err(|e|format!("second replacement input check: {e:?}"))?;
            drop(current);
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

#[path = "client_browser_interruption_reason_tests.rs"]
mod interruption_reason_tests;

#[cfg(feature = "acceptance-faults")]
#[path = "client_browser_trace_retirement_tests.rs"]
mod trace_retirement_tests;

#[path = "client_browser_point_debt_tests.rs"]
mod point_debt_tests;

#[path = "client_browser_owner_transition_tests.rs"]
mod owner_transition_tests;

#[tokio::test]
async fn owned_cleanup_retires_application_before_phase_two_and_browser_close() {
    let (cleanup_reached, reached) = tokio::sync::oneshot::channel();
    let (release, cleanup_release) = tokio::sync::oneshot::channel();
    let (endpoint, log, peer) =
        peer_with_cleanup(true, None, false, Some((cleanup_reached, cleanup_release))).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture = FramedFixture::new(broker.clone(), browser.clone());
    fixture.ready().await.unwrap();
    let opened = fixture
        .command(
            "scope.open",
            fixture_scope_open("connect", Some(&endpoint)),
            5,
        )
        .await
        .unwrap();
    let scope = opened["identityScope"].as_str().unwrap().to_owned();
    fixture.scope = Some(scope.clone());
    let (ledger, waited) = {
        let mut owner = browser.owner.lock().await;
        let owner = owner.as_mut().unwrap();
        let ledger = owner.manager.client.debt_ledger().unwrap();
        let waited = owner.manager.install_cleanup_process_witness();
        (ledger, waited)
    };
    // Capture a real pre-retirement application journal. It must not become
    // usable merely because mandatory owner cleanup still has work to do.
    let journal = ledger
        .operation(
            super::super::super::client_debt::OperationKey {
                generation: 1,
                operation_seq: 99,
            },
            "page-1".into(),
            "session-1".into(),
        )
        .unwrap();
    fixture
        .write(json!({"type":"close","id":"cleanup-close","generation":1}))
        .await
        .unwrap();
    let phase_two = tokio::time::timeout(Duration::from_secs(3), reached).await;
    let application_stayed_closed = [
        ("Input.insertText", json!({"text":"must-not-revive"})),
        (
            "Runtime.evaluate",
            json!({"expression":"1","returnByValue":true}),
        ),
        ("Page.getFrameTree", json!({})),
    ]
    .iter()
    .all(|(method, params)| {
        ledger
            .reserve_command(Some(&journal), method, Some(params), Some("session-1"))
            .is_err()
            && ledger
                .reserve_command(None, method, Some(params), Some("session-1"))
                .is_err()
    });
    let _ = release.send(());
    let receipt = tokio::time::timeout(Duration::from_secs(7), fixture.read()).await;
    // Always join the real shutdown owner before reporting an assertion failure.
    let drained = fixture.finish().await;
    let peer_result = peer.await;
    let requests = log.lock().unwrap().clone();
    assert!(peer_result.is_ok());
    assert!(
        waited.load(Ordering::SeqCst),
        "real manager close did not join its owned process"
    );
    let disposal = requests
        .iter()
        .position(|r| r["method"] == "Target.disposeBrowserContext")
        .expect("owned context disposal was never submitted");
    let detach = requests
        .iter()
        .position(|r| r["method"] == "Target.setAutoAttach" && r["params"]["autoAttach"] == false)
        .expect("retired ledger denied mandatory phase-two autoattach release");
    let close = requests
        .iter()
        .position(|r| r["method"] == "Browser.close")
        .expect("retired ledger denied the actual owned manager Browser.close command");
    assert!(
        disposal < detach && detach < close,
        "cleanup command authority/order changed"
    );
    assert_eq!(
        requests[detach]["params"],
        json!({"autoAttach":false,"waitForDebuggerOnStart":false,"flatten":true})
    );
    assert!(requests[detach].get("sessionId").is_none());
    assert!(requests[close].get("sessionId").is_none());
    assert!(
        phase_two.is_ok_and(|arrived| arrived.is_ok()),
        "phase-two cleanup never reached its real CDP ACK barrier"
    );
    assert!(
        application_stayed_closed,
        "old application authority revived while mandatory cleanup was still in flight"
    );
    assert!(ledger.matches_owner(1, &scope));
    assert!(!ledger.matches_owner(2, &scope));
    let receipt = receipt
        .expect("cleanup receipt timed out")
        .expect("cleanup receipt missing");
    assert_eq!(
        receipt,
        json!({"type":"closed","id":"cleanup-close","generation":1,"scopeState":"closed"})
    );
    drained.unwrap();
}

#[tokio::test]
async fn cancelled_pre_swap_replacement_preserves_old_terminal_cleanup_proof() {
    use crate::native::client_debt::{OwnerCleanupCommand, OwnerDebtLedger};
    use crate::native::client_session::{CancelSignal, OperationLease};

    for isolated_reuse in [false, true] {
        let (endpoint, log, mut peer) = peer(true).await;
        let mut owner = tokio::time::timeout(
            Duration::from_secs(3),
            OwnedBrowser::connect(&endpoint, None),
        )
        .await
        .expect("unmanaged initial owner did not connect")
        .unwrap();
        let old_context = owner.context_id.clone();
        let old_scope = owner.identity_scope.clone();
        let ledger = OwnerDebtLedger::new(1, old_scope.clone());
        ledger.bind_context(&old_context).unwrap();
        owner.manager.bind_native_owner(ledger.clone()).unwrap();

        tokio::time::timeout(Duration::from_secs(3), owner.dispose_context())
            .await
            .expect("old context disposal ACK did not arrive")
            .unwrap();
        assert!(
            !ledger.replacement_ready(),
            "context disposal alone is not terminal cleanup proof"
        );
        owner
            .manager
            .client
            .send_owner_cleanup(
                Some(ledger.clone()),
                OwnerCleanupCommand::DisableAutoAttach,
                std::time::Instant::now() + Duration::from_secs(3),
            )
            .await
            .unwrap();
        assert!(ledger.replacement_ready());
        let waited = owner.manager.install_cleanup_process_witness();

        let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::Requested);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 2,
            deadline: std::time::Instant::now() + Duration::from_secs(30),
            cancellation,
        };
        if isolated_reuse {
            let mut failed = None;
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                OwnedBrowser::isolated_for_scope(owner.manager, &operation, &mut failed),
            )
            .await
            .expect("cancelled isolated reuse did not return its resource");
            assert!(matches!(result, Err(ProtocolError::Cancelled)));
            owner = failed.expect("cancelled isolated reuse lost the retained manager");
            assert!(owner.context_id.is_empty());
            assert!(owner.identity_scope.is_empty());
        } else {
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                owner.replace_cleaned_context(&operation),
            )
            .await
            .expect("cancelled in-place replacement did not return");
            assert!(matches!(result, Err(ProtocolError::Cancelled)));
            assert_eq!(owner.context_id, old_context);
            assert_eq!(owner.identity_scope, old_scope);
        }
        let installed = owner.manager.client.debt_ledger().unwrap();
        assert!(
            Arc::ptr_eq(&installed, &ledger),
            "cancellation swapped the old owner ledger"
        );
        assert_eq!(
            installed.bound_context().as_deref(),
            Some(old_context.as_str())
        );
        assert!(
            installed.replacement_ready(),
            "pre-swap cancellation erased terminal cleanup proof"
        );
        owner
            .manager
            .client
            .check_cleanup_owner(&Some(ledger.clone()))
            .unwrap();

        let closed = tokio::time::timeout(Duration::from_secs(3), owner.close()).await;
        let peer_result = tokio::time::timeout(Duration::from_secs(3), &mut peer).await;
        if peer_result.is_err() {
            peer.abort();
            let _ = peer.await;
        }
        closed
            .expect("retained owner close exceeded its bound")
            .unwrap();
        assert!(
            peer_result.is_ok_and(|joined| joined.is_ok()),
            "peer did not terminate after the real transport close"
        );
        assert!(
            waited.load(Ordering::SeqCst),
            "real close did not join the retained owned-process witness"
        );

        let requests = log.lock().unwrap().clone();
        for method in [
            "Target.createBrowserContext",
            "Target.createTarget",
            "Target.disposeBrowserContext",
            "Browser.close",
        ] {
            assert_eq!(requests.iter().filter(|request| request["method"] == method).count(), 1, "unexpected acquisition or repeated terminal cleanup for {method}, isolated reuse: {isolated_reuse}");
        }
        let phase_two: Vec<_> = requests
            .iter()
            .enumerate()
            .filter(|(_, request)| {
                request["method"] == "Target.setAutoAttach"
                    && request["params"]["autoAttach"] == false
            })
            .collect();
        assert_eq!(
            phase_two.len(),
            1,
            "terminal phase-two cleanup was repeated"
        );
        let (phase_two_index, phase_two_request) = phase_two[0];
        assert_eq!(
            phase_two_request["params"],
            json!({"autoAttach":false,"waitForDebuggerOnStart":false,"flatten":true})
        );
        assert!(phase_two_request.get("sessionId").is_none());
        let created = requests
            .iter()
            .position(|request| request["method"] == "Target.createBrowserContext")
            .unwrap();
        let disposed = requests
            .iter()
            .position(|request| request["method"] == "Target.disposeBrowserContext")
            .unwrap();
        let browser_closed = requests
            .iter()
            .position(|request| request["method"] == "Browser.close")
            .unwrap();
        assert!(
            created < disposed && disposed < phase_two_index && phase_two_index < browser_closed
        );
        assert_eq!(
            requests[disposed]["params"]["browserContextId"],
            old_context
        );
        assert!(requests[disposed].get("sessionId").is_none());
        assert!(requests[browser_closed].get("sessionId").is_none());
    }
}

#[path = "client_browser_response_entry_tests.rs"]
mod response_entry_tests;

#[path = "client_browser_media_merge_tests.rs"]
mod media_merge_tests;

/// Exercise the real retained startup supervisor, owner acquisition and cleanup.
/// Strict joining means the old startup must finish before the next attempt is
/// admitted; this test does not invent overlapping dirty owners to force a race.
#[tokio::test]
async fn retired_startup_joins_late_target_before_next_attempt_identity() {
    use crate::native::client_session::{CancelSignal, OperationLease};
    use crate::native::client_transport::{ClientEventSink, ClientExecutor};
    let bound = Duration::from_secs(10);
    let (reached, acquisition) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let (old_endpoint, old_log, old_peer) = peer_with_startup_acquisition(
        true,
        None,
        false,
        None,
        None,
        None,
        false,
        Some((reached, released)),
    )
    .await;
    let old_broker = Arc::new(ClientSession::new());
    let old = Arc::new(ClientBrowser::new(old_broker.clone()));
    let (sink, _old_events) = ClientEventSink::test_channel(old_broker);
    old.set_event_sink(sink).unwrap();
    let (_old_cancel, old_cancellation) = tokio::sync::watch::channel(CancelSignal::None);
    let opening = {
        let old = old.clone();
        tokio::spawn(async move {
            old.open(
                OpenRequest::Connect {
                    endpoint: old_endpoint,
                    persistent: false,
                    options: Default::default(),
                },
                OperationLease {
                    is_callback: false,
                    generation: 1,
                    sequence: 1,
                    deadline: std::time::Instant::now() + bound,
                    cancellation: old_cancellation,
                },
            )
            .await
        })
    };
    let request = tokio::time::timeout(bound, acquisition)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request["method"], "Target.createTarget");
    assert_eq!(request["params"]["browserContextId"], "synthetic-context");
    assert!(old.owner.lock().await.is_none());
    let closing = {
        let old = old.clone();
        tokio::spawn(async move { old.shutdown().await })
    };
    tokio::time::timeout(bound, async {
        while !old.gate.state.lock().unwrap().closed {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        !closing.is_finished(),
        "shutdown skipped the retained acquisition join"
    );
    assert!(
        !opening.is_finished(),
        "startup completed without its actual target ACK"
    );
    assert!(old.gate.enter(true).is_err());
    assert!(old.owner.lock().await.is_none());
    release.send(()).unwrap();
    assert!(
        tokio::time::timeout(bound, opening)
            .await
            .unwrap()
            .unwrap()
            .is_err(),
        "a retired startup published its late target"
    );
    tokio::time::timeout(bound, closing)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(bound, old_peer)
        .await
        .unwrap()
        .unwrap();
    assert!(old.owner.lock().await.is_none());
    assert!(!old.startup_uncertain.load(Ordering::SeqCst));
    assert!(old.startup_task.lock().await.is_none());
    let old_requests = old_log.lock().unwrap().clone();
    assert_eq!(
        old_requests
            .iter()
            .filter(|r| r["method"] == "Target.createBrowserContext")
            .count(),
        1
    );
    assert_eq!(
        old_requests
            .iter()
            .filter(|r| r["method"] == "Target.createTarget")
            .count(),
        1
    );
    assert!(old_requests
        .iter()
        .any(|r| r["method"] == "Target.disposeBrowserContext"
            && r["params"]["browserContextId"] == "synthetic-context"));
    assert!(old_requests
        .iter()
        .any(|r| r["method"] == "Target.setAutoAttach" && r["params"]["autoAttach"] == false));

    // Only after actual old-owner cleanup/join, start a new real ClientBrowser.
    // The peer intentionally reuses textual context/page IDs: native authority
    // must come from the new owner, not those strings or a fabricated response.
    let (next_endpoint, next_log, next_peer) = peer(true).await;
    let next_broker = Arc::new(ClientSession::new());
    let next = Arc::new(ClientBrowser::new(next_broker.clone()));
    let (sink, _next_events) = ClientEventSink::test_channel(next_broker);
    next.set_event_sink(sink).unwrap();
    let (_next_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
    let operation = |sequence| OperationLease {
        is_callback: false,
        generation: 1,
        sequence,
        deadline: std::time::Instant::now() + bound,
        cancellation: cancellation.clone(),
    };
    let opened = tokio::time::timeout(
        bound,
        next.open(
            OpenRequest::Connect {
                endpoint: next_endpoint.clone(),
                persistent: false,
                options: Default::default(),
            },
            operation(1),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let identity = opened["identityScope"].as_str().unwrap().to_owned();
    assert!(!identity.is_empty());
    let recovery = opened["recoveryIdentity"].clone();
    {
        let owner = next.owner.lock().await;
        let owner = owner.as_ref().unwrap();
        assert_eq!(owner.identity_scope, identity);
        assert_eq!(owner.recovery_identity(), recovery);
        assert_eq!(owner.context_id, "synthetic-context");
        assert_eq!(owner.manager.active_target_id().unwrap(), "page-1");
        assert_eq!(owner.manager.active_session_id().unwrap(), "session-1");
    }
    // A late use of the retired startup owner cannot begin another acquisition
    // or publish into either registry, even with the next attempt's endpoint.
    assert!(tokio::time::timeout(
        bound,
        old.open(
            OpenRequest::Connect {
                endpoint: next_endpoint,
                persistent: false,
                options: Default::default(),
            },
            operation(2)
        )
    )
    .await
    .unwrap()
    .is_err());
    assert!(old.owner.lock().await.is_none());
    {
        let owner = next.owner.lock().await;
        let owner = owner.as_ref().unwrap();
        assert_eq!(owner.identity_scope, identity);
        assert_eq!(owner.recovery_identity(), recovery);
        assert_eq!(owner.manager.active_target_id().unwrap(), "page-1");
        assert_eq!(owner.manager.active_session_id().unwrap(), "session-1");
    }
    assert_eq!(
        next_log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["method"] == "Target.createTarget")
            .count(),
        1
    );
    tokio::time::timeout(bound, next.shutdown())
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(bound, next_peer)
        .await
        .unwrap()
        .unwrap();
}
