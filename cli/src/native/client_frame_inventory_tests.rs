//! Source and native CDP-path regressions for paired frame/renderer inventory.
//! No browser is launched; the peer supplies exact native evidence only.
use super::*;
use crate::native::cdp::client::CdpClient;
use crate::native::client_actions::{
    ActionContext, ActionFailure, ActionRealmAuthority, ClientActions,
};
use crate::native::client_browser::ExecutionGate;
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
fn frame_tree(session: &str, oopif: bool, fault: Fault, changed: bool) -> Value {
    let local_parent = if oopif { "remote-root" } else { "main-root" };
    let nested = node("nested", Some("local"), vec![], changed);
    let local = node("local", Some(local_parent), vec![nested], changed);
    let tree = match session {
        "page-session" => node(
            "main-root",
            None,
            if oopif {
                vec![node("remote-root", Some("main-root"), vec![], changed)]
            } else {
                vec![local]
            },
            changed,
        ),
        "remote-session" => node(
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
        ),
        other => panic!("unowned session was queried: {other}"),
    };
    json!({"frameTree":tree})
}
impl Peer {
    async fn new(oopif: bool, fault: Fault) -> Self {
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
                        let changed = (fault == Fault::LoaderChanged && world_seen)
                            || (fault == Fault::ForeignRendererRoot && remote_trees > 1);
                        frame_tree(session, oopif, fault, changed)
                    }
                    "Page.createIsolatedWorld" => {
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
            deadline: Instant::now() + Duration::from_secs(5),
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
    let source = include_str!("client_browser.rs")
        .split_whitespace()
        .collect::<String>();
    assert_eq!(
        source
            .matches("super::client_actions::ActionContext{")
            .count(),
        4
    );
    assert_eq!(
        source
            .matches("VerifiedFrameInventory{frames,iframe_sessions:sessions")
            .count(),
        4
    );
    assert_eq!(source.matches("::verified_frame_inventory(").count(), 4);
    assert_eq!(
        source
            .matches("iframe_sessions:&sessions,observation_frames:&frames")
            .count(),
        4
    );
    assert!(!source.contains("filter(|frame|frame.parent_frame_id.is_some())"));
}
