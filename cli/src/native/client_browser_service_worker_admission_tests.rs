//! P41's held public evaluation with real native ownership/enrollment and a
//! finite CDP peer. No Chrome, logger, reordered initialization, or restart.
use super::*;
use futures_util::{FutureExt, SinkExt, StreamExt};
use std::panic::AssertUnwindSafe;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;

const CONTEXT: &str = "p41-context";
const PAGE: &str = "p41-page";
const PAGE_SESSION: &str = "p41-page-session";
const WORKER: &str = "p41-worker";
const ROOT_SESSION: &str = "p41-root-worker";
const CHILD_SESSION: &str = "p41-child-worker";
const WORKER_COMMANDS: [&str; 5] = [
    "Network.enable",
    "Fetch.enable",
    "Runtime.enable",
    "Target.setAutoAttach",
    "Runtime.runIfWaitingForDebugger",
];

type Socket = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

fn target(id: &str, kind: &str) -> Value {
    json!({"targetId":id,"type":kind,"browserContextId":CONTEXT,
        "url":"about:blank","title":""})
}
fn attachment(session: &str) -> Value {
    let mut event = json!({"method":"Target.attachedToTarget","params":{
        "sessionId":session,"waitingForDebugger":true,
        "targetInfo":target(WORKER,"service_worker")}});
    if session == CHILD_SESSION {
        event["sessionId"] = json!(PAGE_SESSION);
    }
    event
}
async fn send(socket: &mut Socket, value: Value) {
    socket.send(Message::Text(value.to_string())).await.unwrap();
}
async fn acknowledge(socket: &mut Socket, request: &Value, result: Value) {
    let mut reply = json!({"id":request["id"],"result":result});
    if let Some(session) = request.get("sessionId") {
        reply["sessionId"] = session.clone();
    }
    send(socket, reply).await;
}

struct WorkerPeer {
    endpoint: String,
    requests: Arc<Mutex<Vec<Value>>>,
    resumed: Option<oneshot::Receiver<()>>,
    release_evaluation: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for WorkerPeer {
    fn drop(&mut self) {
        // Also covers an unexpected test panic outside the retained cleanup path.
        self.task.abort();
    }
}
impl WorkerPeer {
    async fn new(duplicate_root_first: Option<bool>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let (resumed, received_resume) = oneshot::channel();
        let (release_evaluation, mut release) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let winner = if duplicate_root_first == Some(false) {
                CHILD_SESSION
            } else {
                ROOT_SESSION
            };
            let loser = if winner == ROOT_SESSION {
                CHILD_SESSION
            } else {
                ROOT_SESSION
            };
            let mut pages = std::collections::BTreeMap::new();
            let mut evaluation: Option<Value> = None;
            let mut held_runtime: Option<Value> = None;
            let mut worker_step = 0;
            let mut duplicate_detached = false;
            let mut resume_notice = Some(resumed);
            let mut release_consumed = false;
            loop {
                let message = tokio::select! {
                    released = &mut release, if !release_consumed => {
                        release_consumed = true;
                        if released.is_ok() {
                            assert_eq!(worker_step, WORKER_COMMANDS.len());
                            let request = evaluation.take().expect("release requires held public evaluation");
                            acknowledge(&mut socket, &request, json!({"result":{"type":"object","value":{"value":1}}})).await;
                        }
                        // A dropped release sender is failure cleanup, not permission
                        // to fabricate the evaluation's successful browser response.
                        continue;
                    }
                    message = socket.next() => message,
                };
                let Some(Ok(message)) = message else {
                    break;
                };
                let text = match message {
                    Message::Text(text) => text,
                    Message::Ping(bytes) => {
                        socket.send(Message::Pong(bytes)).await.unwrap();
                        continue;
                    }
                    Message::Close(_) => break,
                    _ => continue,
                };
                let request: Value = serde_json::from_str(&text).unwrap();
                {
                    let mut log = recorded.lock().unwrap();
                    assert!(log.len() < 256, "finite fixture command bound");
                    log.push(request.clone());
                }
                let method = request["method"].as_str().unwrap();
                let session = request["sessionId"].as_str();
                if session == Some(loser) {
                    panic!("duplicate worker session must not receive initialization or resume");
                }
                if session == Some(winner) {
                    // This owned isolated-context case disposes the context and
                    // disables browser-root autoattach. Its worker cleanup RPC
                    // allowlist is empty, unlike borrowed-session teardown.
                    assert!(
                        worker_step < WORKER_COMMANDS.len(),
                        "unexpected worker RPC after initialization (including cleanup)"
                    );
                    assert!(
                        evaluation.is_some(),
                        "worker must attach after public evaluate was sent"
                    );
                    assert_eq!(Some(&method), WORKER_COMMANDS.get(worker_step));
                    worker_step += 1;
                    match method {
                        "Network.enable" => {
                            assert!(request["params"]["maxTotalBufferSize"]
                                .as_u64()
                                .is_some_and(|n| n > 0));
                            assert!(request["params"]["maxResourceBufferSize"]
                                .as_u64()
                                .is_some_and(|n| n > 0));
                            assert!(request["params"].get("enableDurableMessages").is_none());
                        }
                        "Fetch.enable" => assert_eq!(
                            request["params"],
                            json!({
                            "patterns":[{"urlPattern":"*","requestStage":"Request"}],"handleAuthRequests":true})
                        ),
                        "Runtime.enable" if duplicate_root_first.is_some() => {
                            assert!(held_runtime.replace(request.clone()).is_none());
                            // The observed winner command, not event send order,
                            // proves registration won before injecting the loser.
                            send(&mut socket, attachment(loser)).await;
                            continue;
                        }
                        "Target.setAutoAttach" => {
                            assert_eq!(request["params"]["autoAttach"], true);
                            assert_eq!(request["params"]["waitForDebuggerOnStart"], true);
                            assert_eq!(request["params"]["flatten"], true);
                        }
                        _ => {}
                    }
                    acknowledge(&mut socket, &request, json!({})).await;
                    if method == "Runtime.runIfWaitingForDebugger" {
                        assert!(duplicate_root_first.is_none() || duplicate_detached);
                        let _ = resume_notice.take().unwrap().send(());
                    }
                    continue;
                }
                let result = match method {
                    "Browser.getVersion" => json!({"protocolVersion":"1.3",
                        "product":"Synthetic Chromium/1.0","revision":"synthetic",
                        "userAgent":"Synthetic Chromium Linux","jsVersion":"synthetic"}),
                    "Target.createBrowserContext" => json!({"browserContextId":CONTEXT}),
                    "Target.createTarget" => {
                        assert!(
                            pages.is_empty(),
                            "fixture never restarts or creates a second page"
                        );
                        pages.insert(PAGE, target(PAGE, "page"));
                        json!({"targetId":PAGE})
                    }
                    "Target.attachToTarget" => {
                        assert_eq!(request["params"]["targetId"], PAGE);
                        json!({"sessionId":PAGE_SESSION})
                    }
                    "Target.getTargets" => {
                        json!({"targetInfos":pages.values().cloned().collect::<Vec<_>>()})
                    }
                    "Target.getTargetInfo" => {
                        let id = request["params"]["targetId"].as_str().unwrap_or(PAGE);
                        json!({"targetInfo":pages.get(id).expect("known synthetic target")})
                    }
                    "Page.getFrameTree" => json!({"frameTree":{"frame":{
                        "id":"p41-frame","loaderId":"p41-loader","url":"about:blank","securityOrigin":"null"}}}),
                    "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":"p41-script"}),
                    "Runtime.evaluate" => {
                        assert_eq!(session, Some(PAGE_SESSION));
                        assert_eq!(request["params"]["awaitPromise"], true);
                        assert_eq!(request["params"]["returnByValue"], true);
                        assert_eq!(request["params"]["userGesture"], true);
                        assert!(request["params"]["expression"]
                            .as_str()
                            .unwrap()
                            .contains("navigator.serviceWorker.register"));
                        assert!(
                            evaluation.replace(request.clone()).is_none(),
                            "evaluation is never replayed"
                        );
                        pages.insert(WORKER, target(WORKER, "service_worker"));
                        send(&mut socket, attachment(winner)).await;
                        continue;
                    }
                    "Target.detachFromTarget" => {
                        assert!(duplicate_root_first.is_some());
                        assert_eq!(request["params"]["sessionId"], loser);
                        assert_eq!(session, (loser == CHILD_SESSION).then_some(PAGE_SESSION));
                        assert!(!duplicate_detached);
                        duplicate_detached = true;
                        acknowledge(&mut socket, &request, json!({})).await;
                        let mut detached = json!({"method":"Target.detachedFromTarget",
                            "params":{"sessionId":loser,"targetId":WORKER}});
                        if loser == CHILD_SESSION {
                            detached["sessionId"] = json!(PAGE_SESSION);
                        }
                        send(&mut socket, detached).await;
                        let runtime = held_runtime
                            .take()
                            .expect("duplicate injected only at winner Runtime.enable");
                        acknowledge(&mut socket, &runtime, json!({})).await;
                        continue;
                    }
                    "Target.disposeBrowserContext" => {
                        assert_eq!(request["params"]["browserContextId"], CONTEXT);
                        pages.clear();
                        json!({})
                    }
                    // These ACK-only commands occur during the real managed
                    // initial-page setup/configuration or retained cleanup.
                    "Page.enable"
                    | "Runtime.enable"
                    | "Network.enable"
                    | "WebMCP.enable"
                    | "DOM.enable"
                    | "DOM.disable"
                    | "Fetch.enable"
                    | "Fetch.disable"
                    | "Runtime.runIfWaitingForDebugger"
                    | "Target.setAutoAttach"
                    | "Browser.setDownloadBehavior"
                    | "Page.setLifecycleEventsEnabled"
                    | "Emulation.setEmulatedMedia"
                    | "Target.setDiscoverTargets"
                    | "Page.removeScriptToEvaluateOnNewDocument" => json!({}),
                    other => panic!("unmodeled P41 fixture command: {other}"),
                };
                acknowledge(&mut socket, &request, result).await;
            }
        });
        Self {
            endpoint,
            requests,
            resumed: Some(received_resume),
            release_evaluation: Some(release_evaluation),
            task,
        }
    }
}

async fn finish_native(fixture: FramedFixture) -> Result<(), String> {
    let FramedFixture {
        stream, mut server, ..
    } = fixture;
    // EOF is the production cancellation/shutdown entry. No success reply is
    // fabricated on failure, and the CDP peer remains available for cleanup.
    drop(stream);
    match tokio::time::timeout(Duration::from_secs(10), &mut server).await {
        Ok(Ok(true)) => Ok(()),
        Ok(_) => Err("native framed cleanup failed".into()),
        Err(_) => {
            server.abort();
            let _ = server.await;
            Err("native framed cleanup exceeded watchdog; aborted, not clean".into())
        }
    }
}

async fn managed_case(duplicate_root_first: Option<bool>) {
    let mut peer = WorkerPeer::new(duplicate_root_first).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture = FramedFixture::new(broker.clone(), browser.clone());
    let result = AssertUnwindSafe(async {
        fixture.ready().await?;
        let opened = fixture.command("scope.open", fixture_scope_open("connect",Some(&peer.endpoint)),5).await?;
        let scope = opened["identityScope"].as_str().ok_or("missing scope")?.to_owned();
        fixture.scope = Some(scope.clone());
        fixture.command("scope.configure",fixture_configuration(&scope,None),5).await?;
        fixture.command("network.routes.replace",fixture_routes(&scope),5).await?;
        fixture.registry = 1;
        fixture.command("page.activate",json!({"identityScope":scope}),5).await?;
        let page = browser.page_lease(false).await.map_err(|_|"page lease failed")?;
        let client = page.client.clone();
        let ledger = client.debt_ledger().ok_or("fixture must use real owner ledger")?;
        let targets = page.targets.clone();
        let enrollment = browser.owner.lock().await.as_ref().unwrap().runtime.as_ref().unwrap().enrollment.clone();
        let config_gate = enrollment.config_gate();
        assert!(!ledger.snapshot().integrity_lost);
        let winner = if duplicate_root_first == Some(false) { CHILD_SESSION } else { ROOT_SESSION };
        let resumed = peer.resumed.take().unwrap();
        let evaluation = fixture.command("page.evaluate",json!({"identityScope":scope,
            "source":"async () => { await navigator.serviceWorker.register('/sw.js'); return (await navigator.serviceWorker.getRegistrations()).length; }",
            "argument":null}),30);
        tokio::pin!(evaluation);
        tokio::select! {
            result = &mut evaluation => panic!("evaluation completed before worker resume ACK: {result:?}"),
            result = resumed => result.map_err(|_|"peer ended before worker resume ACK")?,
        }
        // The original gate is held until configuration_committed and the
        // enrollment resumed flag. Acquiring it observes real completion.
        let configured = config_gate.lock().await;
        let worker = targets.owned_target(WORKER).map_err(|_|"worker missing after resume ACK")?;
        assert_eq!(worker.session_id, winner);
        assert!(worker.configured && worker.resumed);
        drop(configured);
        // A check-only, non-dispatching drain budget, not a manufactured broker
        // operation or readiness flag. The real public evaluate stays pending.
        let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let drain_budget = OperationLease {
            is_callback: false, generation: 1, sequence: 0,
            deadline: Instant::now() + Duration::from_secs(5), cancellation,
        };
        enrollment.flush_app_events(&page, &drain_budget).await
            .map_err(|_|"worker events/enrollment did not drain")?;
        // Never hold configuration while draining an event task that may need it.
        let configured = config_gate.lock().await;
        assert!(worker.same_attachment(&targets.owned_target(WORKER).map_err(|_|"worker lost after event drain")?));
        let inventory = targets.inventory().map_err(|_|"worker inventory incomplete")?.1;
        assert_eq!(inventory.iter().filter(|entry| entry.target_id == WORKER).count(),1);
        targets.check_settlement_integrity().map_err(|_|"worker settlement incomplete")?;
        let debt = ledger.snapshot();
        assert!(!debt.integrity_lost);
        assert_eq!(debt.input_debt,1,"public evaluation remains real input debt");
        assert_eq!(debt.outstanding_commands,1,"worker ACKs settled independently of evaluation");
        assert_eq!(client.pending_len().await,1);
        drop(configured);
        assert!(futures_util::poll!(&mut evaluation).is_pending());
        peer.release_evaluation.take().unwrap().send(()).map_err(|_|"peer lost evaluation release")?;
        assert_eq!(evaluation.await?,json!({"value":1}));
        assert_eq!(broker.health().map_err(|_|"broker health unavailable")?.1,ScopeState::Usable);
        assert_eq!(client.pending_len().await,0);
        let debt = ledger.snapshot();
        assert!(!debt.integrity_lost);
        assert_eq!(debt.input_debt,0);
        assert_eq!(debt.outstanding_commands,0);
        let requests = peer.requests.lock().unwrap();
        let worker_methods:Vec<_> = requests.iter().filter(|r|r["sessionId"]==winner)
            .map(|r|r["method"].as_str().unwrap()).collect();
        assert_eq!(worker_methods,WORKER_COMMANDS);
        assert_eq!(requests.iter().filter(|r|r["method"]=="Runtime.evaluate").count(),1);
        assert_eq!(requests.iter().filter(|r|r["method"]=="Target.detachFromTarget").count(),usize::from(duplicate_root_first.is_some()));
        Ok::<(),String>(())
    }).catch_unwind();
    // Watchdog only: every success transition is driven by actual peer traffic,
    // ACK correlation, or the existing configuration mutex, never a sleep.
    let result = tokio::time::timeout(Duration::from_secs(15), result).await;
    drop(peer.release_evaluation.take());
    let cleanup = finish_native(fixture).await;
    let peer_result = tokio::time::timeout(Duration::from_secs(2), &mut peer.task).await;
    if peer_result.is_err() {
        peer.task.abort();
        let _ = (&mut peer.task).await;
    }
    // Preserve the initiating failure while reporting independent cleanup and
    // peer outcomes. A failed/aborted cleanup can never turn into a passing test.
    match result {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => panic!("case={error}; cleanup={cleanup:?}; peer={peer_result:?}"),
        Ok(Err(panic)) => {
            eprintln!("P41 fixture cleanup={cleanup:?}; peer={peer_result:?}");
            std::panic::resume_unwind(panic);
        }
        Err(_) => {
            panic!("managed fixture watchdog expired; cleanup={cleanup:?}; peer={peer_result:?}")
        }
    }
    assert!(
        cleanup.is_ok() && matches!(peer_result, Ok(Ok(()))),
        "cleanup={cleanup:?}; peer={peer_result:?}"
    );
}

#[tokio::test]
async fn managed_service_worker_enrollment_progresses_while_public_evaluate_pending() {
    managed_case(None).await;
}

#[tokio::test]
async fn managed_duplicate_service_worker_attachment_keeps_first_session_while_evaluate_pending() {
    for root_first in [true, false] {
        managed_case(Some(root_first)).await;
    }
}
