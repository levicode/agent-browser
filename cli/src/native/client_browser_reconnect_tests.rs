//! Source-only supervisor regressions. Include as a child of client_browser:
//! #[cfg(test)] #[path = "client_browser_reconnect_tests.rs"] mod reconnect_tests;
//! These tests use the real persistent owner, native EOF proof, reconnect
//! helper, and supervisor. No browser process or reconnect-success stub.
use super::*;
use crate::native::client_actions::{fixture_configuration, FixtureOperations};
use crate::native::client_protocol::{Effects, ServerMessage};
use crate::native::client_session::{ClientSession, OperationLease};
use crate::native::client_transport::{ClientEventSink, ClientExecutor, NativeOutcome};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PeerMode {
    Original,
    HoldInput,
    ReconnectCandidate,
    WrongContext,
    RefuseTargetInfo,
    HoldAfterAttach,
    Verified,
}

pub(super) struct Peer {
    pub(super) endpoint: String,
    pub(super) commands: Arc<Mutex<Vec<Value>>>,
    pub(super) received: mpsc::UnboundedReceiver<String>,
    pub(super) emit: mpsc::Sender<Message>,
    pub(super) task: tokio::task::JoinHandle<()>,
}

pub(super) async fn peer(mode: PeerMode) -> Peer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let commands = Arc::new(Mutex::new(Vec::new()));
    let recorded = commands.clone();
    let (send, received) = mpsc::unbounded_channel();
    let (emit, mut emitted) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut attached = false;
        let mut loader = "host-loader";
        let mut target = json!({"targetId":"host-page","type":"page",
            "browserContextId":"host-context","url":"about:blank","title":""});
        if mode == PeerMode::WrongContext {
            target["browserContextId"] = "other-context".into();
        }
        loop {
            tokio::select! {
                event = emitted.recv() => {
                    let Some(event) = event else { break; };
                    let close = matches!(event, Message::Close(_));
                    if socket.send(event).await.is_err() || close { break; }
                }
                message = socket.next() => {
                    let Some(Ok(Message::Text(text))) = message else { break; };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    recorded.lock().unwrap().push(request.clone());
                    let method = request["method"].as_str().unwrap();
                    let _ = send.send(method.to_owned());
                    let session = request["sessionId"].as_str().unwrap_or("");
                    if mode == PeerMode::ReconnectCandidate {
                        assert!(!matches!(method,
                            "Page.navigate" | "Target.createTarget" | "Target.createBrowserContext"),
                            "reconnect candidate replaced or navigated retained objects: {request}");
                    }
                    if !matches!(mode,
                        PeerMode::Original | PeerMode::HoldInput | PeerMode::ReconnectCandidate)
                    {
                        assert!(matches!(method,
                            "Target.getBrowserContexts" | "Target.getTargetInfo"
                            | "Target.attachToTarget" | "Target.detachFromTarget"),
                            "candidate unexpectedly initialized or acted: {request}");
                    }
                    if mode == PeerMode::HoldAfterAttach && attached
                        && method == "Target.getBrowserContexts"
                    {
                        // This request follows a successful attach ACK and the
                        // strict adopt helper's exact-page recheck.
                        continue;
                    }
                    if mode == PeerMode::HoldInput && method == "Input.dispatchMouseEvent" {
                        // The test closes this real socket only after observing
                        // submission in the native operation registry. No ACK.
                        continue;
                    }
                    let mut response = if mode == PeerMode::RefuseTargetInfo
                        && method == "Target.getTargetInfo"
                    {
                        json!({"id":request["id"],"error":{
                            "code":-32000,"message":"fixture refuses exact retained target"}})
                    } else {
                        let result = match method {
                            "Browser.getVersion" => json!({"protocolVersion":"1.3",
                                "product":"Synthetic Chromium/1.0","revision":"synthetic",
                                "userAgent":"Synthetic Chromium Linux","jsVersion":"synthetic"}),
                            "Target.getBrowserContexts" => json!({"browserContextIds":[],
                                "defaultBrowserContextId":"host-context"}),
                            "Target.getTargets" => json!({"targetInfos":[target.clone()]}),
                            "Target.getTargetInfo" => {
                                assert_eq!(request["params"]["targetId"], "host-page");
                                json!({"targetInfo":target.clone()})
                            }
                            "Target.attachToTarget" => {
                                assert_eq!(request["params"]["targetId"], "host-page");
                                attached = true;
                                json!({"sessionId":"host-session"})
                            }
                            "Page.getFrameTree" => json!({"frameTree":{"frame":{
                                "id":format!("frame-{session}"),"loaderId":loader,
                                "url":"about:blank"}}}),
                            "Page.navigate" => {
                                assert_eq!(request["params"]["url"], "about:blank");
                                loader = "host-activation-loader";
                                json!({"frameId":format!("frame-{session}"),
                                    "loaderId":"host-activation-loader"})
                            }
                            "Runtime.evaluate" => {
                                assert_eq!(request["params"]["expression"], "location.href");
                                json!({"result":{"type":"string","value":"about:blank"}})
                            }
                            "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":"host-script"}),
                            "Page.enable" | "Runtime.enable" | "Network.enable" | "WebMCP.enable"
                            | "DOM.enable" | "DOM.disable" | "Network.setBypassServiceWorker"
                            | "Fetch.enable" | "Fetch.disable" | "Page.setLifecycleEventsEnabled"
                            | "Target.setDiscoverTargets" | "Target.setAutoAttach"
                            | "Runtime.runIfWaitingForDebugger" | "Page.removeScriptToEvaluateOnNewDocument"
                            | "Emulation.setEmulatedMedia" | "Target.detachFromTarget"
                            | "Browser.setDownloadBehavior" => json!({}),
                            other => panic!("unmodeled reconnect fixture method {other}: {request}"),
                        };
                        json!({"id":request["id"],"result":result})
                    };
                    if !session.is_empty() { response["sessionId"] = session.into(); }
                    if socket.send(Message::Text(response.to_string())).await.is_err() { break; }
                    if method == "Page.navigate" {
                        for event in [
                            json!({"method":"Page.frameNavigated","sessionId":session,"params":{
                                "frame":{"id":format!("frame-{session}"),"loaderId":"host-activation-loader",
                                    "url":"about:blank","securityOrigin":"null"}}}),
                            json!({"method":"Page.lifecycleEvent","sessionId":session,"params":{
                                "frameId":format!("frame-{session}"),"loaderId":"host-activation-loader",
                                "name":"DOMContentLoaded"}}),
                        ] {
                            if socket.send(Message::Text(event.to_string())).await.is_err() { return; }
                        }
                    }
                }
            }
        }
    });
    Peer {
        endpoint,
        commands,
        received,
        emit,
        task,
    }
}

struct DisconnectedOwner {
    browser: Arc<ClientBrowser>,
    broker: Arc<ClientSession>,
    scope: String,
    identity: Value,
    client: Arc<CdpClient>,
    enrollment: Arc<crate::native::client_enrollment::ClientEnrollment>,
    network: Arc<crate::native::client_network::ClientNetwork>,
    actions: Arc<crate::native::client_actions::ClientActions>,
    targets: Arc<crate::native::client_targets::ClientTargets>,
    page_state: Arc<crate::native::client_page::ClientPageState>,
    ui: Arc<crate::native::client_ui::UiGate>,
    directory: PathBuf,
    gate_state: (u64, bool, bool),
    _notices: mpsc::Receiver<ServerMessage>,
}

impl DisconnectedOwner {
    async fn new() -> Self {
        let original = peer(PeerMode::Original).await;
        let broker = Arc::new(ClientSession::new());
        let browser = Arc::new(ClientBrowser::new(broker.clone()));
        let (sink, notices) = ClientEventSink::test_channel(broker.clone());
        browser.set_event_sink(sink.clone()).unwrap();
        let mut operations = FixtureOperations::new(broker.clone());
        let opened = operations
            .execute_written(
                browser.as_ref(),
                &sink,
                "scope.open",
                json!({"source":"connect","context":"persistent","endpoint":original.endpoint}),
                10,
            )
            .await
            .unwrap();
        assert_eq!(opened.effects, Effects::Completed);
        let opened = opened.result.unwrap();
        let scope = opened["identityScope"].as_str().unwrap().to_owned();
        let configured = operations
            .execute_written(
                browser.as_ref(),
                &sink,
                "scope.configure",
                fixture_configuration(&scope, None),
                10,
            )
            .await
            .unwrap();
        assert_eq!(configured.effects, Effects::Completed);
        configured.result.unwrap();
        let (identity, client, enrollment, network, actions, targets, page_state, ui, directory) = {
            let owner = browser.owner.lock().await;
            let owner = owner.as_ref().unwrap();
            assert!(!owner.owns_context);
            assert_eq!(
                owner.borrowed_targets.as_deref(),
                Some(&["host-page".to_owned()][..])
            );
            let runtime = owner.runtime.as_ref().unwrap();
            let directory = runtime
                .configuration
                .lock()
                .unwrap()
                .download_directory
                .as_ref()
                .unwrap()
                .path()
                .to_owned();
            (
                owner.recovery_identity(),
                owner.manager.client.clone(),
                runtime.enrollment.clone(),
                runtime.network.clone(),
                runtime.actions.clone(),
                owner.targets.clone(),
                owner.page_state.clone(),
                owner.ui.clone(),
                directory,
            )
        };
        // Native remote EOF, not local close or a manufactured terminal proof.
        original.emit.send(Message::Close(None)).await.unwrap();
        let mut closed = client.remote_connection_closed();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !*closed.borrow_and_update() {
                closed.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(3), enrollment.drain())
            .await
            .unwrap()
            .unwrap();
        enrollment
            .terminal_connection_proof()
            .unwrap()
            .check_client(&client)
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), original.task)
            .await
            .unwrap()
            .unwrap();
        let gate_state = {
            let state = browser.gate.state.lock().unwrap();
            (state.epoch, state.transitioning, state.closed)
        };
        assert!(!browser.startup_uncertain.load(Ordering::SeqCst));
        Self {
            browser,
            broker,
            scope,
            identity,
            client,
            enrollment,
            network,
            actions,
            targets,
            page_state,
            ui,
            directory,
            gate_state,
            _notices: notices,
        }
    }

    fn operation(&self) -> OperationLease {
        // The setup used sequences one and two. reconnect_scope is called
        // directly, so reproduce the executor's real broker start boundary.
        let operation = self.broker.admit(1, 3, 10_000).unwrap();
        assert!(self.broker.start(1, 3).unwrap());
        operation
    }

    fn request(&self, endpoint: &str) -> ReconnectRequest {
        ReconnectRequest {
            endpoint: endpoint.into(),
            expected_browser_identity: self.identity["browser"].as_str().unwrap().into(),
            expected_context_identity: self.identity["context"].as_str().unwrap().into(),
            expected_page_identity: self.identity["page"].as_str().unwrap().into(),
        }
    }

    async fn assert_old_owner_unchanged(&self) {
        let owner = self.browser.owner.lock().await;
        let owner = owner.as_ref().expect("old owner must remain journaled");
        assert_eq!(owner.identity_scope, self.scope);
        assert_eq!(owner.recovery_identity(), self.identity);
        assert!(Arc::ptr_eq(&owner.manager.client, &self.client));
        assert!(Arc::ptr_eq(&owner.targets, &self.targets));
        assert!(Arc::ptr_eq(&owner.page_state, &self.page_state));
        assert!(Arc::ptr_eq(&owner.ui, &self.ui));
        assert!(owner.replacement_actions.is_none());
        assert!(owner.replacement_routes.is_none());
        assert!(owner.disconnected_routes.is_none());
        assert!(owner.reconnect_proof.is_none());
        let runtime = owner
            .runtime
            .as_ref()
            .expect("old runtime must not retire during preflight");
        assert!(Arc::ptr_eq(&runtime.enrollment, &self.enrollment));
        assert!(Arc::ptr_eq(&runtime.network, &self.network));
        assert!(Arc::ptr_eq(&runtime.actions, &self.actions));
        assert_eq!(
            runtime
                .configuration
                .lock()
                .unwrap()
                .download_directory
                .as_ref()
                .unwrap()
                .path(),
            self.directory.as_path()
        );
        assert!(
            self.directory.is_dir(),
            "preflight removed the old download directory"
        );
        assert!(!self.browser.startup_uncertain.load(Ordering::SeqCst));
        let state = self.browser.gate.state.lock().unwrap();
        assert_eq!(
            (state.epoch, state.transitioning, state.closed),
            self.gate_state
        );
    }

    async fn finish(self, outcome: &NativeOutcome, expected_shutdown: Result<(), ProtocolError>) {
        self.broker.settle(1, 3, outcome.effects).unwrap();
        let shutdown = tokio::time::timeout(Duration::from_secs(5), self.browser.shutdown())
            .await
            .expect("existing shutdown must settle");
        assert_eq!(shutdown, expected_shutdown);
    }
}

async fn candidate_closed(candidate: Peer) -> Vec<Value> {
    // Never close or abort the candidate from the fixture. Its own retained
    // cleanup must end the socket after the reconnect result, before shutdown.
    tokio::time::timeout(Duration::from_secs(3), candidate.task)
        .await
        .expect("supervisor/helper failed to close candidate transport")
        .unwrap();
    let commands = candidate.commands.lock().unwrap().clone();
    assert!(
        !commands.is_empty(),
        "real native reconnect helper was not reached"
    );
    for request in &commands {
        assert!(matches!(
            request["method"].as_str(),
            Some(
                "Target.getBrowserContexts"
                    | "Target.getTargetInfo"
                    | "Target.attachToTarget"
                    | "Target.detachFromTarget"
            )
        ));
        if matches!(
            request["method"].as_str(),
            Some("Target.getTargetInfo" | "Target.attachToTarget")
        ) {
            assert_eq!(request["params"]["targetId"], "host-page");
        }
    }
    commands
}

async fn preflight_refusal(mode: PeerMode, error: ProtocolError) {
    let owner = DisconnectedOwner::new().await;
    let candidate = peer(mode).await;
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        owner.browser.reconnect_scope(
            owner.scope.clone(),
            owner.request(&candidate.endpoint),
            owner.operation(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(outcome.result, Err(error));
    assert_eq!(outcome.effects, Effects::NotDispatched);
    owner.assert_old_owner_unchanged().await;
    let commands = candidate_closed(candidate).await;
    assert!(!commands
        .iter()
        .any(|request| request["method"] == "Target.attachToTarget"));
    owner.finish(&outcome, Ok(())).await;
}

#[tokio::test]
async fn reconnect_supervisor_identity_mismatch_keeps_old_runtime() {
    preflight_refusal(PeerMode::WrongContext, ProtocolError::StaleScope).await;
}

#[tokio::test]
async fn reconnect_supervisor_error_ack_before_attach_keeps_old_runtime() {
    preflight_refusal(PeerMode::RefuseTargetInfo, ProtocolError::BrowserFailure).await;
}

#[tokio::test]
async fn reconnect_supervisor_cancel_after_candidate_attach_keeps_old_runtime() {
    let owner = DisconnectedOwner::new().await;
    let mut candidate = peer(PeerMode::HoldAfterAttach).await;
    let request = owner.request(&candidate.endpoint);
    let operation = owner.operation();
    let browser = owner.browser.clone();
    let scope = owner.scope.clone();
    let reconnecting =
        tokio::spawn(async move { browser.reconnect_scope(scope, request, operation).await });
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut contexts = 0;
        while let Some(method) = candidate.received.recv().await {
            if method == "Target.getBrowserContexts" {
                contexts += 1;
                if contexts == 2 {
                    return;
                }
            }
        }
        panic!("candidate never reached its post-attach identity check");
    })
    .await
    .unwrap();
    owner.broker.cancel(1, 3).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(5), reconnecting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.result, Err(ProtocolError::Cancelled));
    assert_eq!(outcome.effects, Effects::NotDispatched);
    owner.assert_old_owner_unchanged().await;
    let commands = candidate_closed(candidate).await;
    assert_eq!(
        commands
            .iter()
            .filter(|request| request["method"] == "Target.attachToTarget")
            .count(),
        1
    );
    owner.finish(&outcome, Ok(())).await;
}

#[tokio::test]
async fn reconnect_supervisor_old_cleanup_failure_closes_verified_candidate() {
    let owner = DisconnectedOwner::new().await;
    // A real filesystem obstruction makes the retained old TempDir cleanup
    // fail. No fake reconnect result or production failure injection is used.
    std::fs::remove_dir(&owner.directory).unwrap();
    std::fs::write(&owner.directory, b"retained cleanup obstruction").unwrap();
    let candidate = peer(PeerMode::Verified).await;
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        owner.browser.reconnect_scope(
            owner.scope.clone(),
            owner.request(&candidate.endpoint),
            owner.operation(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(outcome.result, Err(ProtocolError::CleanupFailed));
    assert_eq!(outcome.effects, Effects::Unknown);
    assert!(owner.browser.startup_uncertain.load(Ordering::SeqCst));
    assert!(owner.browser.gate.state.lock().unwrap().closed);
    {
        let resource = owner.browser.owner.lock().await;
        let resource = resource
            .as_ref()
            .expect("failed old cleanup must stay journaled");
        assert_eq!(resource.identity_scope, owner.scope);
        assert!(Arc::ptr_eq(&resource.manager.client, &owner.client));
        let runtime = resource
            .runtime
            .as_ref()
            .expect("failed old runtime must stay journaled");
        assert!(Arc::ptr_eq(&runtime.enrollment, &owner.enrollment));
        assert!(Arc::ptr_eq(&runtime.network, &owner.network));
        assert!(resource.replacement_actions.is_some());
        assert!(resource.reconnect_proof.is_none());
        assert_eq!(
            runtime
                .configuration
                .lock()
                .unwrap()
                .download_directory
                .as_ref()
                .unwrap()
                .path(),
            owner.directory.as_path()
        );
    }
    let commands = candidate_closed(candidate).await;
    assert_eq!(
        commands
            .iter()
            .filter(|request| request["method"] == "Target.attachToTarget")
            .count(),
        1
    );
    assert_eq!(
        commands
            .iter()
            .filter(|request| request["method"] == "Target.getTargetInfo")
            .count(),
        3
    );
    assert_eq!(
        commands
            .iter()
            .filter(|request| request["method"] == "Target.getBrowserContexts")
            .count(),
        2
    );
    std::fs::remove_file(&owner.directory).unwrap();
    // Accepted-error startup_uncertain remains unresolved. Assert that exact
    // failure rather than silently discarding the cleanup result.
    owner
        .finish(&outcome, Err(ProtocolError::CleanupFailed))
        .await;
}

// Deliberately not claimed here: candidate disappearance during old cleanup
// after verified transfer. That needs a separately synchronized fixture proving
// retained replacement ownership and the existing eventual shutdown attempt;
// it must not demand immediate disconnect after transfer or silently assert
// startup_uncertain has been resolved.
