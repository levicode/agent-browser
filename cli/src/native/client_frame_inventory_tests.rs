//! Source and native CDP-path regressions for paired frame/renderer inventory.
//! No browser is launched; the peer supplies exact native evidence only.
use super::*;
use crate::native::cdp::client::CdpClient;
use crate::native::client_actions::{
    ActionContext, ActionFailure, ActionRealmAuthority, ClientActions,
};
use crate::native::client_browser::{ExecutionGate, OwnedBrowser};
use crate::native::client_geometry::{GeometrySnapshot, BOX_PROOF};
use crate::native::client_page::ClientPageState;
use crate::native::client_protocol::Effects;
use crate::native::client_targets::ClientTargets;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    Button,
    OldPageSession,
    ReplaceSession,
    ReattachSameSession,
    LoaderChanged,
    ForeignRendererRoot,
    ForeignParent,
    ForeignFocus,
    CancelFocus,
    FocusCleanup,
    InventoryCleanup,
    InventoryStaleCleanup,
    /// The browser retires the OOPIF session while the read enumerates it, and
    /// the registry applies the detach: a fresh inventory no longer owns it.
    RetiredIframe,
    /// The same failure without the detach evidence: the read must keep its
    /// original failure rather than retrying or swallowing it.
    RetiredIframeStuck,
    /// A page (not iframe) session failure is never waited out.
    RetiredPageSession,
}
struct Peer {
    page: BrowserExecutionLease,
    operation: OperationLease,
    _cancel: tokio::sync::watch::Sender<CancelSignal>,
    log: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn attach(targets: &Arc<ClientTargets>, target: &str, session: &str, kind: &str) {
    targets
        .attached("context", target.into(), session.into(), kind.into())
        .unwrap();
    targets.configured(target).unwrap();
    targets
        .resume_permit(target)
        .await
        .unwrap()
        .complete()
        .unwrap();
}
fn node(id: &str, parent: Option<&str>, children: Vec<Value>, loader_changed: bool) -> Value {
    let loader = if loader_changed {
        "replacement-loader"
    } else {
        "loader"
    };
    let mut frame = json!({"id":id,"loaderId":loader,"url":"about:srcdoc"});
    if let Some(parent) = parent {
        frame["parentId"] = json!(parent);
    }
    json!({"frame":frame,"childFrames":children})
}
fn frame_tree(
    session: &str,
    oopif: bool,
    remote_owned: bool,
    fault: Fault,
    changed: bool,
) -> Value {
    let nested = node("nested", Some("local"), vec![], changed);
    let tree = match session {
        "page-session" => {
            // Once the OOPIF target is detached the page tree no longer owns
            // that remote root, exactly as the browser reports it.
            if oopif && remote_owned {
                let local = node("local", Some("remote-root"), vec![nested], changed);
                node(
                    "main-root",
                    None,
                    vec![node("remote-root", Some("main-root"), vec![local], changed)],
                    changed,
                )
            } else {
                let local = node("local", Some("main-root"), vec![nested], changed);
                node("main-root", None, vec![local], changed)
            }
        }
        "remote-session" => {
            let local = node("local", Some("remote-root"), vec![nested], changed);
            node(
                if fault == Fault::ForeignRendererRoot && changed {
                    "foreign-root"
                } else {
                    "remote-root"
                },
                Some(if fault == Fault::ForeignParent {
                    "foreign-parent"
                } else {
                    "main-root"
                }),
                vec![local],
                changed,
            )
        }
        other => panic!("unowned session was queried: {other}"),
    };
    json!({"frameTree":tree})
}
impl Peer {
    async fn new(oopif: bool, fault: Fault) -> Self {
        Self::with_deadline(oopif, fault, Duration::from_secs(5)).await
    }
    async fn with_deadline(oopif: bool, fault: Fault, budget: Duration) -> Self {
        let targets = ClientTargets::new("context".into(), "scope".into());
        attach(&targets, "target-for-main", "page-session", "page").await;
        if oopif {
            attach(&targets, "target-for-remote", "remote-session", "iframe").await;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let captured = log.clone();
        let registry = targets.clone();
        let (cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let server_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut world_seen = false;
            let mut remote_trees = 0;
            let mut retired_iframe_seen = false;
            while let Some(Ok(Message::Text(text))) = socket.next().await {
                let request: Value = serde_json::from_str(&text).unwrap();
                captured.lock().unwrap().push(request.clone());
                let method = request["method"].as_str().unwrap();
                let session = request["sessionId"].as_str().unwrap();
                let source = request["params"]["functionDeclaration"]
                    .as_str()
                    .unwrap_or("");
                let object = request["params"]["objectId"].as_str().unwrap_or("");
                let mut fail = false;
                let result = match method {
                    "Page.getFrameTree" => {
                        if session == "remote-session" {
                            remote_trees += 1;
                        }
                        if fault == Fault::RetiredPageSession && session == "page-session" {
                            fail = true;
                        }
                        let changed = (fault == Fault::LoaderChanged && world_seen)
                            || (fault == Fault::ForeignRendererRoot && remote_trees > 1);
                        let remote_owned = registry
                            .inventory()
                            .map(|(_, targets)| {
                                targets
                                    .iter()
                                    .any(|target| target.target_id == "target-for-remote")
                            })
                            .unwrap_or(false);
                        frame_tree(session, oopif, remote_owned, fault, changed)
                    }
                    "Page.createIsolatedWorld" => {
                        if matches!(fault, Fault::RetiredIframe | Fault::RetiredIframeStuck)
                            && session == "remote-session"
                            && !retired_iframe_seen
                        {
                            retired_iframe_seen = true;
                            if fault == Fault::RetiredIframe {
                                // The detach the browser already reported is
                                // applied before the failed read observes it.
                                registry.detach("target-for-remote").unwrap();
                            }
                            fail = true;
                        }
                        if !world_seen
                            && matches!(fault, Fault::ReplaceSession | Fault::ReattachSameSession)
                        {
                            let (target, old, kind) = if oopif {
                                ("target-for-remote", "remote-session", "iframe")
                            } else {
                                ("target-for-main", "page-session", "page")
                            };
                            registry.detach(target).unwrap();
                            attach(
                                &registry,
                                target,
                                if fault == Fault::ReplaceSession {
                                    "replacement-session"
                                } else {
                                    old
                                },
                                kind,
                            )
                            .await;
                        }
                        world_seen = true;
                        let context = match request["params"]["frameId"].as_str().unwrap() {
                            "main-root" => 1,
                            "remote-root" => 2,
                            "local" => 3,
                            "nested" => 4,
                            other => panic!("foreign frame requested: {other}"),
                        };
                        json!({"executionContextId":context})
                    }
                    "DOM.getFrameOwner" => {
                        let backend = match request["params"]["frameId"].as_str().unwrap() {
                            "remote-root" => 100,
                            "local" => 101,
                            "nested" => 102,
                            other => panic!("foreign frame owner requested: {other}"),
                        };
                        json!({"backendNodeId":backend})
                    }
                    "DOM.resolveNode" => {
                        json!({"object":{"subtype":"node","objectId":format!("object-{}-{}",
                        request["params"]["executionContextId"], request["params"]["backendNodeId"])}})
                    }
                    "Runtime.callFunctionOn" if source == observation::FRAME_OWNER_GEOMETRY => {
                        if fault == Fault::InventoryStaleCleanup {
                            json!({"exceptionDetails":{"text":"Frame owner moved"}})
                        } else {
                            json!({"result":{"value":{"x":0,"y":0,"selector":"iframe"}}})
                        }
                    }
                    "Runtime.callFunctionOn" if source == BOX_PROOF => {
                        json!({"result":{"value":{"connected":true,"frameOwner":true,"width":400,"height":300}}})
                    }
                    "Runtime.callFunctionOn" if source.contains("return this.nodeType===1") => {
                        // Preserve the production document guard and its order.
                        assert!(
                            source.find("if(this===document)return false;").unwrap()
                                < source.find("if(!this.isConnected").unwrap()
                        );
                        if fault == Fault::CancelFocus {
                            server_cancel.send_replace(CancelSignal::Requested);
                        }
                        let value = if object.ends_with("-1") {
                            json!(false)
                        } else if fault == Fault::ForeignFocus {
                            json!({"status":"stale"})
                        } else {
                            json!(fault != Fault::Button)
                        };
                        json!({"result":{"value":value}})
                    }
                    "Runtime.callFunctionOn" => {
                        assert!(
                            source.contains("Object.getOwnPropertyDescriptor(p,'isConnected')"),
                            "unmodeled proof: {source}"
                        );
                        json!({"result":{"value":true}})
                    }
                    "Runtime.releaseObject" => {
                        fail = (fault == Fault::FocusCleanup && object.ends_with("-42"))
                            || (matches!(
                                fault,
                                Fault::InventoryCleanup | Fault::InventoryStaleCleanup
                            ) && object.ends_with("-101"));
                        json!({})
                    }
                    "Accessibility.getFullAXTree" => {
                        let frame = request["params"]["frameId"].as_str().unwrap();
                        let mut nodes =
                            vec![json!({"backendDOMNodeId":1,"role":{"value":"RootWebArea"},
                            "properties":[{"name":"focused","value":{"value":true}}]})];
                        if (fault == Fault::Button && frame == "main-root")
                            || (fault != Fault::Button && frame == "nested")
                        {
                            nodes.push(json!({"backendDOMNodeId":42,"role":{"value":if fault == Fault::Button { "button" } else { "textbox" }},
                                "properties":[{"name":"focused","value":{"value":true}}]}));
                        }
                        json!({"nodes":nodes})
                    }
                    "Page.getLayoutMetrics" => {
                        json!({"cssVisualViewport":{"clientWidth":400,"clientHeight":300,"offsetX":0,"offsetY":0,"scale":1},
                        "cssLayoutViewport":{"clientWidth":400,"clientHeight":300}})
                    }
                    "DOM.getBoxModel" => {
                        json!({"model":{"content":[0,0,400,0,400,300,0,300],"border":[0,0,400,0,400,300,0,300]}})
                    }
                    "Input.insertText" => json!({}),
                    other => panic!("unmodeled frame-inventory command {other}: {request}"),
                };
                let response = if fail {
                    json!({"id":request["id"],"sessionId":session,"error":{"code":-32000,"message":"synthetic release failure"}})
                } else {
                    json!({"id":request["id"],"sessionId":session,"result":result})
                };
                if socket
                    .send(Message::Text(response.to_string()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
        let gate = Arc::new(ExecutionGate::default());
        let page = BrowserExecutionLease {
            client,
            targets,
            permit: gate.enter(false).unwrap(),
            identity_scope: "scope".into(),
            page_session_id: if fault == Fault::OldPageSession {
                "old-page-session"
            } else {
                "page-session"
            }
            .into(),
            target_id: "target-for-main".into(),
        };
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline: Instant::now() + budget,
            cancellation,
        };
        Self {
            page,
            operation,
            _cancel: cancel,
            log,
            task,
        }
    }
    fn inputs(&self) -> Vec<Value> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|entry| entry["method"].as_str().unwrap().starts_with("Input."))
            .cloned()
            .collect()
    }
    async fn type_with_inventory(
        &self,
        inventory: &VerifiedFrameInventory,
    ) -> Result<Value, ActionFailure> {
        // The same production inventory/geometry/action chain, not a hand-built
        // renderer map or a replacement focus predicate.
        let geometry = GeometrySnapshot::capture(
            &self.page.client,
            &self.page.page_session_id,
            &inventory.frames,
            &self.operation,
        )
        .await
        .unwrap();
        let state = ClientPageState::new("scope".into(), "context".into());
        let refs = RefMap::new();
        let blobs = BlobStore::new(Default::default()).unwrap();
        ClientActions::default()
            .execute(
                ActionContext {
                    page: &self.page,
                    operation: &self.operation,
                    page_state: &state,
                    refs: &refs,
                    revision: 0,
                    observation_after: None,
                    observed_revision: 0,
                    iframe_sessions: &inventory.iframe_sessions,
                    observation_frames: &inventory.frames,
                    blobs: &blobs,
                    geometry: &geometry,
                    realm_authority: ActionRealmAuthority::UntrackedFixture,
                },
                "browser.keyboard.type",
                &json!({"identityScope":"scope","text":"界","replace":false}),
            )
            .await
    }
}

#[tokio::test]
async fn verified_renderer_roots_preserve_local_descendants_and_type_exactly_once() {
    for oopif in [false, true] {
        let peer = Peer::new(oopif, Fault::None).await;
        let inventory = verified_frame_inventory(&peer.page, &peer.operation)
            .await
            .unwrap();
        assert_eq!(inventory.frames.len(), if oopif { 4 } else { 3 });
        assert_eq!(inventory.iframe_sessions.len(), usize::from(oopif));
        if oopif {
            assert_eq!(
                inventory
                    .iframe_sessions
                    .get("remote-root")
                    .map(String::as_str),
                Some("remote-session")
            );
        }
        for id in ["local", "nested"] {
            assert!(!inventory.iframe_sessions.contains_key(id));
            let frame = inventory
                .frames
                .iter()
                .find(|frame| frame.binding.frame == id)
                .unwrap();
            assert_eq!(
                frame.binding.session,
                if oopif {
                    "remote-session"
                } else {
                    "page-session"
                }
            );
        }
        peer.type_with_inventory(&inventory).await.unwrap();
        assert_eq!(peer.inputs().len(), 1);
        assert_eq!(peer.inputs()[0]["method"], "Input.insertText");
        assert_eq!(peer.inputs()[0]["params"]["text"], "界");
        assert_eq!(peer.inputs()[0]["sessionId"], "page-session");
        let log = peer.log.lock().unwrap();
        let ax = log
            .iter()
            .filter(|entry| entry["method"] == "Accessibility.getFullAXTree")
            .collect::<Vec<_>>();
        assert_eq!(ax.len(), inventory.frames.len());
        assert_eq!(ax.last().unwrap()["params"]["frameId"], "nested");
        assert_eq!(
            ax.last().unwrap()["sessionId"],
            if oopif {
                "remote-session"
            } else {
                "page-session"
            }
        );
        assert_eq!(
            log.iter()
                .filter(|entry| entry["method"] == "DOM.resolveNode"
                    && entry["params"]["backendNodeId"] == 42)
                .count(),
            1
        );
        assert_eq!(
            log.iter()
                .filter(|entry| entry["method"] == "Runtime.releaseObject"
                    && entry["params"]["objectId"] == "object-4-42")
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn verified_inventory_focused_button_and_focus_failures_never_dispatch_input() {
    for oopif in [false, true] {
        for (fault, expected, cleanup) in [
            (Fault::Button, ProtocolError::NotActionable, false),
            (Fault::ForeignFocus, ProtocolError::StaleReference, false),
            (Fault::CancelFocus, ProtocolError::Cancelled, false),
            (Fault::FocusCleanup, ProtocolError::CleanupFailed, true),
        ] {
            let peer = Peer::new(oopif, fault).await;
            let inventory = verified_frame_inventory(&peer.page, &peer.operation)
                .await
                .unwrap();
            let failure = peer.type_with_inventory(&inventory).await.unwrap_err();
            assert_eq!(failure.error, expected, "oopif={oopif}, {fault:?}");
            assert_eq!(failure.effects, Effects::NotDispatched);
            assert_eq!(failure.cleanup_failed, cleanup);
            assert!(peer.inputs().is_empty());
            assert!(peer
                .log
                .lock()
                .unwrap()
                .iter()
                .any(|entry| entry["method"] == "Accessibility.getFullAXTree"));
        }
    }
}

#[tokio::test]
async fn verified_inventory_rejects_old_replaced_and_foreign_native_identity() {
    for oopif in [false, true] {
        for (fault, expected) in [
            (Fault::OldPageSession, ProtocolError::StaleScope),
            (Fault::ReplaceSession, ProtocolError::StaleScope),
            (Fault::ReattachSameSession, ProtocolError::StaleScope),
            (Fault::LoaderChanged, ProtocolError::StaleReference),
            (Fault::InventoryCleanup, ProtocolError::CleanupFailed),
        ] {
            let peer = Peer::new(oopif, fault).await;
            assert_eq!(
                verified_frame_inventory(&peer.page, &peer.operation)
                    .await
                    .err(),
                Some(expected),
                "oopif={oopif}, {fault:?}"
            );
            assert!(peer.inputs().is_empty());
            assert!(!peer
                .log
                .lock()
                .unwrap()
                .iter()
                .any(|entry| entry["method"] == "Accessibility.getFullAXTree"));
        }
    }
    for (fault, expected) in [
        (Fault::ForeignRendererRoot, ProtocolError::StaleReference),
        (Fault::ForeignParent, ProtocolError::StaleScope),
    ] {
        let peer = Peer::new(true, fault).await;
        assert_eq!(
            verified_frame_inventory(&peer.page, &peer.operation)
                .await
                .err(),
            Some(expected)
        );
        assert!(peer.inputs().is_empty());
    }
}

#[tokio::test]
async fn frame_only_projection_preserves_primary_error_and_cleanup_flag() {
    for paired in [false, true] {
        let peer = Peer::new(false, Fault::InventoryStaleCleanup).await;
        let cleanup = AtomicBool::new(false);
        let result = if paired {
            verified_frame_inventory_with_cleanup(&peer.page, &peer.operation, Some(&cleanup))
                .await
                .map(|inventory| inventory.frames)
        } else {
            verified_frames_with_cleanup(&peer.page, &peer.operation, Some(&cleanup)).await
        };
        assert_eq!(result.err(), Some(ProtocolError::StaleReference));
        assert!(cleanup.load(Ordering::SeqCst));
        assert!(peer.inputs().is_empty());
        assert_eq!(
            peer.log
                .lock()
                .unwrap()
                .iter()
                .filter(|entry| entry["method"] == "Runtime.releaseObject")
                .count(),
            1
        );
    }
}

#[test]
fn all_production_action_contexts_consume_the_verified_renderer_map() {
    // Ordinary actions plus four recording page-open hooks: borrowed-page
    // reopen, restart, reset replacement, and reconnect replacement. Each new
    // constructor must retain the paired verified frames/session inventory.
    let source = include_str!("client_browser.rs")
        .split_whitespace()
        .collect::<String>();
    assert_eq!(
        source
            .matches("super::client_actions::ActionContext{")
            .count(),
        5
    );
    assert_eq!(
        source
            .matches("VerifiedFrameInventory{frames,iframe_sessions:sessions")
            .count(),
        5
    );
    assert_eq!(source.matches("::verified_frame_inventory(").count(), 4);
    assert_eq!(
        source.matches("::verified_action_frame_inventory(").count(),
        1
    );
    assert_eq!(
        source
            .matches("iframe_sessions:&sessions,observation_frames:&frames")
            .count(),
        5
    );
    assert!(!source.contains("filter(|frame|frame.parent_frame_id.is_some())"));
}

// A same-document route that mounts three <object> plugin documents used to
// deny every semantic read with StaleScope: the plugin documents are opaque
// author-inventory omissions, but the native lineage still listed them, so the
// paired inventory and lineage counts could never agree. The three plugin
// documents are renderer-owned targets here, exactly as the browser reports
// them, and an ordinary author iframe sits in the same tree to prove real
// iframes stay inventoried.
struct ObjectFramePeer {
    page: BrowserExecutionLease,
    operation: OperationLease,
    _cancel: tokio::sync::watch::Sender<CancelSignal>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for ObjectFramePeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
const OBJECT_FRAMES: [&str; 3] = ["obj-1", "obj-2", "obj-3"];
const OBJECT_SESSIONS: [&str; 3] = ["obj-session-1", "obj-session-2", "obj-session-3"];
const OBJECT_BACKENDS: [i64; 3] = [301, 302, 303];
fn object_frame_tree(session: &str) -> Value {
    let child = |id: &str, index: usize| {
        json!({"frame":{"id":id,"parentId":"main-root","loaderId":format!("obj-loader-{index}"),
            "url":"about:blank"},"childFrames":[]})
    };
    match session {
        "page-session" => json!({"frameTree":{"frame":{"id":"main-root","loaderId":"main-loader",
            "url":"https://fixture.example/route"},
            "childFrames":[child("obj-1",1),child("obj-2",2),child("obj-3",3),
                json!({"frame":{"id":"author-frame","parentId":"main-root",
                    "loaderId":"author-loader","url":"about:srcdoc"},"childFrames":[]})]}}),
        session if OBJECT_SESSIONS.contains(&session) => {
            let index = OBJECT_SESSIONS
                .iter()
                .position(|candidate| candidate == &session)
                .unwrap();
            let id = OBJECT_FRAMES[index];
            json!({"frameTree":{"frame":{"id":id,"parentId":"main-root",
                "loaderId":format!("obj-loader-{}",index+1),"url":"about:blank"},"childFrames":[]}})
        }
        other => panic!("unowned session was queried: {other}"),
    }
}
fn object_frame_backend(frame: &str) -> i64 {
    match frame {
        "obj-1" => OBJECT_BACKENDS[0],
        "obj-2" => OBJECT_BACKENDS[1],
        "obj-3" => OBJECT_BACKENDS[2],
        "author-frame" => 401,
        other => panic!("foreign frame owner requested: {other}"),
    }
}
fn object_frame_local_name(frame: &str) -> &'static str {
    match frame {
        "obj-1" | "obj-2" | "obj-3" => "object",
        "author-frame" => "iframe",
        other => panic!("foreign frame owner requested: {other}"),
    }
}
impl ObjectFramePeer {
    async fn new() -> Self {
        let targets = ClientTargets::new("context".into(), "scope".into());
        attach(&targets, "target-main", "page-session", "page").await;
        for (target, session) in [
            ("target-obj-1", OBJECT_SESSIONS[0]),
            ("target-obj-2", OBJECT_SESSIONS[1]),
            ("target-obj-3", OBJECT_SESSIONS[2]),
        ] {
            attach(&targets, target, session, "iframe").await;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let (cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(Message::Text(text))) = socket.next().await {
                let request: Value = serde_json::from_str(&text).unwrap();
                let method = request["method"].as_str().unwrap();
                let session = request["sessionId"].as_str().unwrap();
                let source = request["params"]["functionDeclaration"]
                    .as_str()
                    .unwrap_or("");
                let object = request["params"]["objectId"].as_str().unwrap_or("");
                let result = match method {
                    "Page.getFrameTree" => object_frame_tree(session),
                    "Page.createIsolatedWorld" => {
                        let frame = request["params"]["frameId"].as_str().unwrap();
                        let context = match frame {
                            "main-root" => 1,
                            "author-frame" => 2,
                            "obj-1" => 11,
                            "obj-2" => 12,
                            "obj-3" => 13,
                            other => panic!("foreign frame requested: {other}"),
                        };
                        json!({"executionContextId":context})
                    }
                    "DOM.getFrameOwner" => {
                        let frame = request["params"]["frameId"].as_str().unwrap();
                        assert_eq!(session, "page-session");
                        json!({"backendNodeId":object_frame_backend(frame)})
                    }
                    "DOM.resolveNode" => json!({
                        "object":{"subtype":"node","objectId":format!("object-{}-{}",
                            request["params"]["executionContextId"],
                            request["params"]["backendNodeId"])}
                    }),
                    "Runtime.callFunctionOn" if source == observation::FRAME_OWNER_GEOMETRY => {
                        let backend = object
                            .rsplit('-')
                            .next()
                            .and_then(|value| value.parse::<i64>().ok())
                            .expect("owner object id");
                        let frame = match backend {
                            301 => "obj-1",
                            302 => "obj-2",
                            303 => "obj-3",
                            401 => "author-frame",
                            other => panic!("foreign frame owner resolved: {other}"),
                        };
                        json!({"result":{"value":{"x":0,"y":0,"selector":"frame",
                            "localName":object_frame_local_name(frame)}}})
                    }
                    "Runtime.releaseObject" => json!({}),
                    other => panic!("unmodeled object-frame command {other}: {request}"),
                };
                let response = json!({"id":request["id"],"sessionId":session,"result":result});
                if socket
                    .send(Message::Text(response.to_string()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
        let gate = Arc::new(ExecutionGate::default());
        let page = BrowserExecutionLease {
            client,
            targets,
            permit: gate.enter(false).unwrap(),
            identity_scope: "scope".into(),
            page_session_id: "page-session".into(),
            target_id: "target-main".into(),
        };
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline: Instant::now() + Duration::from_secs(5),
            cancellation,
        };
        Self {
            page,
            operation,
            _cancel: cancel,
            task,
        }
    }
}
#[tokio::test]
async fn three_object_plugin_frames_do_not_stale_the_semantic_inventory() {
    let peer = ObjectFramePeer::new().await;
    let inventory = verified_frame_inventory(&peer.page, &peer.operation)
        .await
        .unwrap();
    let ids = inventory
        .frames
        .iter()
        .map(|frame| frame.binding.frame.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, vec!["main-root", "author-frame"]);
    assert!(inventory.iframe_sessions.is_empty());
    for object in OBJECT_FRAMES {
        assert!(!ids.contains(&object));
    }
}

#[test]
fn author_lineage_omits_opaque_plugin_subtrees_only() {
    let mut parents = std::collections::HashMap::new();
    parents.insert("main-root".to_string(), None);
    for object in OBJECT_FRAMES {
        parents.insert(object.to_string(), Some("main-root".to_string()));
    }
    // A frame nested inside an opaque plugin document is unreachable from the
    // author tree for the same reason; it must be omitted with its subtree.
    parents.insert("plugin-nested".to_string(), Some("obj-1".to_string()));
    parents.insert("author-frame".to_string(), Some("main-root".to_string()));
    parents.insert(
        "author-nested".to_string(),
        Some("author-frame".to_string()),
    );
    let mut iframe_sessions = std::collections::HashMap::new();
    for (object, session) in OBJECT_FRAMES.iter().zip(OBJECT_SESSIONS) {
        iframe_sessions.insert(object.to_string(), session.to_string());
    }
    let lineage = author_lineage(
        PageLineage {
            iframe_sessions,
            parents,
        },
        &OBJECT_FRAMES.map(str::to_string),
    );
    let mut ids = lineage.parents.keys().cloned().collect::<Vec<_>>();
    ids.sort();
    assert_eq!(ids, vec!["author-frame", "author-nested", "main-root"]);
    assert!(lineage.iframe_sessions.is_empty());
}

// Real-Chrome control for the same three <object> fixture. The CLI has no
// trace/observe entry point, so this drives the production paired inventory
// directly: the native tree really contains three plugin child frames plus one
// author iframe, and the semantic inventory must succeed with only the author
// frames. Run with:
//   cargo test --bin agent-browser e2e_three_object_plugin_frames -- --ignored
#[tokio::test]
#[ignore = "requires hosted Chromium: three <object> plugin frames"]
async fn e2e_three_object_plugin_frames_do_not_stale_the_semantic_inventory() {
    use crate::native::cdp::chrome::{launch_chrome, LaunchOptions};
    let _chrome = launch_chrome(&LaunchOptions {
        headless: true,
        ..Default::default()
    })
    .unwrap();
    let client = Arc::new(CdpClient::connect(&_chrome.ws_url).await.unwrap());
    let target = client
        .send_command(
            "Target.createTarget",
            Some(json!({"url":"about:blank"})),
            None,
        )
        .await
        .unwrap()["targetId"]
        .as_str()
        .unwrap()
        .to_owned();
    let session = client
        .send_command(
            "Target.attachToTarget",
            Some(json!({"targetId":target,"flatten":true})),
            None,
        )
        .await
        .unwrap()["sessionId"]
        .as_str()
        .unwrap()
        .to_owned();
    client
        .send_command("Page.enable", Some(json!({})), Some(&session))
        .await
        .unwrap();
    let html = "<html><body>\
        <object type=\"text/html\" data=\"about:blank\"></object>\
        <object type=\"text/html\" data=\"about:blank\"></object>\
        <object type=\"text/html\" data=\"about:blank\"></object>\
        <iframe src=\"about:blank\"></iframe>\
        </body></html>";
    client
        .send_command(
            "Page.navigate",
            Some(json!({"url":format!("data:text/html,{}", urlencoding::encode(html))})),
            Some(&session),
        )
        .await
        .unwrap();
    // Wait for the three plugin documents and the author iframe to exist in
    // the native frame tree before taking the paired inventory.
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let tree = client
                .send_command("Page.getFrameTree", Some(json!({})), Some(&session))
                .await
                .unwrap();
            let children = tree["frameTree"]["childFrames"]
                .as_array()
                .map(Vec::len)
                .unwrap_or(0);
            let objects = client
                .send_command(
                    "Runtime.evaluate",
                    Some(
                        json!({"expression":"document.querySelectorAll('object').length",
                        "returnByValue":true}),
                    ),
                    Some(&session),
                )
                .await
                .unwrap();
            if children >= 4 && objects["result"]["value"] == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("three <object> plugin frames did not appear");
    let targets = ClientTargets::new("context".into(), "scope".into());
    attach(&targets, &target, &session, "page").await;
    let gate = Arc::new(ExecutionGate::default());
    let page = BrowserExecutionLease {
        client: client.clone(),
        targets,
        permit: gate.enter(false).unwrap(),
        identity_scope: "scope".into(),
        page_session_id: session.clone(),
        target_id: target.clone(),
    };
    let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
    let operation = OperationLease {
        is_callback: false,
        generation: 1,
        sequence: 1,
        deadline: Instant::now() + Duration::from_secs(30),
        cancellation,
    };
    let inventory = verified_frame_inventory(&page, &operation).await.unwrap();
    let ids = inventory
        .frames
        .iter()
        .map(|frame| frame.binding.frame.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 2, "author frames only: {ids:?}");
    let root = &inventory.frames[0];
    assert!(root.parent_frame_id.is_none());
    let author = inventory
        .frames
        .iter()
        .find(|frame| frame.parent_frame_id.as_deref() == Some(root.binding.frame.as_str()))
        .expect("author iframe stays inventoried");
    assert_eq!(author.frame_path.len(), 1);
    assert!(
        author.frame_path[0].ends_with("iframe:nth-child(4)"),
        "author iframe keeps its owner path: {:?}",
        author.frame_path
    );
}

/// levicode/agent-browser#28 real fixture: a hash-routed page that mounts three
/// `<object>` plugin documents used to deny the whole screen with
/// `stale-reference`, because the geometry proof counted the deliberately
/// omitted plugin subtrees as missing inventory. This uses real Chromium, the
/// production semantic inventory and the production geometry proof, and drives
/// the same real hash navigation the UAT page uses.
#[tokio::test]
#[ignore = "hosted Chromium: three <object> plugin documents and a hash route must not deny the whole screen"]
async fn chromium_object_hash_route_geometry_accepts_proven_opaque_subtrees() {
    let mut owner = OwnedBrowser::launch(Default::default(), None)
        .await
        .unwrap();
    let gate = Arc::new(ExecutionGate::default());
    let mut page = owner.lease(gate.enter(false).unwrap()).unwrap();
    let (cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
    let operation = OperationLease {
        is_callback: false,
        generation: 1,
        sequence: 1,
        deadline: Instant::now() + Duration::from_secs(20),
        cancellation,
    };
    let setup = page
        .client
        .send_command(
            "Runtime.evaluate",
            Some(json!({
                "expression": r##"new Promise(resolve => {
                    document.body.innerHTML = '<nav><a id="to-label" href="#/account_label">labels</a></nav><div id="plugins"></div><div id="app"><h1>Home</h1></div>';
                    for (let index = 0; index < 3; index += 1) {
                        const plugin = document.createElement('object');
                        plugin.type = 'text/html';
                        plugin.data = 'about:blank';
                        plugin.width = 1;
                        plugin.height = 1;
                        plugin.dataset['plugin'] = String(index);
                        document.getElementById('plugins').append(plugin);
                    }
                    const rows = Array.from({ length: 40 }, (_, index) => '<tr><td>row ' + index + '</td><td>' + 'x'.repeat(24) + '</td></tr>').join('');
                    const render = () => {
                        document.getElementById('app').innerHTML = location.hash.indexOf('#/account_label') === 0
                            ? '<h1>Labels</h1><table><tbody>' + rows + '</tbody></table>'
                            : '<h1>Home</h1>';
                    };
                    window.addEventListener('hashchange', render);
                    location.hash = '#/home';
                    setTimeout(() => resolve(document.querySelectorAll('object').length), 300);
                })"##,
                "awaitPromise": true,
                "returnByValue": true
            })),
            Some(&page.page_session_id),
        )
        .await
        .unwrap();
    assert_eq!(
        setup["result"]["value"],
        json!(3),
        "three plugin documents mounted"
    );
    let inventory = observation::enumerate_semantic_frames(
        &page.client,
        &page.page_session_id,
        &HashMap::new(),
        &operation,
    )
    .await
    .unwrap();
    assert_eq!(
        inventory.frames.len(),
        1,
        "author inventory is the main document"
    );
    assert_eq!(
        inventory.opaque_frame_roots.len(),
        3,
        "three opaque plugin subtrees"
    );
    let opaque: HashSet<String> = inventory.opaque_frame_roots.iter().cloned().collect();
    // The pre-fix strict proof is the regression: plugin frames read as missing.
    assert_eq!(
        GeometrySnapshot::capture(
            &page.client,
            &page.page_session_id,
            &inventory.frames,
            &operation
        )
        .await
        .unwrap_err(),
        crate::native::client_geometry::GeometryError::IncompleteInventory
    );
    let geometry = GeometrySnapshot::capture_excluding_opaque(
        &page.client,
        &page.page_session_id,
        &inventory.frames,
        &opaque,
        &operation,
    )
    .await
    .unwrap();
    geometry.revalidate(&page.client, &operation).await.unwrap();
    // Same-document hash navigation must keep the same published inventory.
    let switched = page
        .client
        .send_command(
            "Runtime.evaluate",
            Some(json!({"expression":"location.hash = '#/account_label'; true","returnByValue":true})),
            Some(&page.page_session_id),
        )
        .await
        .unwrap();
    assert_eq!(switched["result"]["value"], json!(true));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let after = observation::enumerate_semantic_frames(
        &page.client,
        &page.page_session_id,
        &HashMap::new(),
        &operation,
    )
    .await
    .unwrap();
    assert_eq!(after.frames.len(), 1);
    assert_eq!(after.opaque_frame_roots.len(), 3);
    let after_opaque: HashSet<String> = after.opaque_frame_roots.iter().cloned().collect();
    let geometry = GeometrySnapshot::capture_excluding_opaque(
        &page.client,
        &page.page_session_id,
        &after.frames,
        &after_opaque,
        &operation,
    )
    .await
    .unwrap();
    geometry.revalidate(&page.client, &operation).await.unwrap();
    drop(cancel);
    owner.close().await.unwrap();
}

#[tokio::test]
async fn a_frame_target_retired_during_enumeration_settles_as_a_stale_scope() {
    let peer = Peer::new(true, Fault::RetiredIframe).await;
    let result = verified_frame_inventory(&peer.page, &peer.operation).await;
    assert!(
        matches!(result, Err(ProtocolError::StaleScope)),
        "a page-created frame target that detached during the read moves the page inventory, not the scope"
    );
    // The registry applied the detach, so the engine's one fresh re-read sees
    // the page without the transient frame.
    let (_, targets) = peer.page.targets.inventory().unwrap();
    assert!(targets
        .iter()
        .all(|target| target.target_id != "target-for-remote"));
}

#[tokio::test]
async fn a_retired_iframe_session_without_detach_keeps_its_original_failure() {
    let peer =
        Peer::with_deadline(true, Fault::RetiredIframeStuck, Duration::from_millis(300)).await;
    let started = Instant::now();
    let result = verified_frame_inventory(&peer.page, &peer.operation).await;
    assert!(
        matches!(result, Err(ProtocolError::BrowserFailure)),
        "a failure the registry never attributes to a detach keeps its class"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the wait is bounded by the operation's own deadline"
    );
}

#[tokio::test]
async fn a_page_session_failure_is_never_waited_out_as_target_churn() {
    let peer = Peer::new(false, Fault::RetiredPageSession).await;
    let started = Instant::now();
    let result = verified_frame_inventory(&peer.page, &peer.operation).await;
    assert!(matches!(result, Err(ProtocolError::BrowserFailure)));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "only page-created frame targets are target churn"
    );
}
