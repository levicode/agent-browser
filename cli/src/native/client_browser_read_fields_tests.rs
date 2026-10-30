//! Public ReadFields trust-boundary controls using the existing framed client.
//! The peer supplies CDP bytes, never callback results or synthetic settlement.
//! Internal Value delivery is provisional; only the public result may publish.
use super::*;
use crate::native::client_debt::{AdmissionClass, OwnerDebtLedger};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

// Exact single-root transaction script. Readonly release is independent.
// The last entry has no later CDP command to reject admission. The expected
// scope-unavailable must come from the final FieldReadRequest authority check,
// not the outer retained owner's separate dirty-success/cleanup-failed fallback.
const APPLICATION: [&str; 10] = [
    "Page.getFrameTree", // initial singleton inventory
    "Page.createIsolatedWorld",
    "Page.getFrameTree", // post-world confirmation
    "DOM.getDocument",
    "DOM.describeNode",
    "DOM.resolveNode",
    "Runtime.callFunctionOn",
    "DOM.getDocument",   // fresh current Document, not retained backend
    "DOM.describeNode",  // complete final policy roots
    "Page.getFrameTree", // complete final topology and publication fence
];
// A RequiresAx sample must finish fresh roots and a complete legacy frame
// inventory before entering AX, never recursively run another fresh sample.
const REQUIRES_AX_APPLICATION: [&str; 15] = [
    "Page.getFrameTree",
    "Page.createIsolatedWorld",
    "Page.getFrameTree",
    "DOM.getDocument",
    "DOM.describeNode",
    "DOM.resolveNode",
    "Runtime.callFunctionOn",
    "DOM.getDocument",
    "DOM.describeNode",
    "Page.getFrameTree", // complete final lineage
    "Page.getFrameTree", // final enumeration
    "Page.createIsolatedWorld",
    "Page.getFrameTree", // final enumeration confirmation
    "Page.getFrameTree", // AX entry frame validation
    "Accessibility.getFullAXTree",
];
const LEGACY_APPLICATION: [&str; 19] = [
    "Page.getFrameTree", // initial lineage
    "Page.getFrameTree", // initial enumeration
    "Page.createIsolatedWorld",
    "Page.getFrameTree", // initial enumeration validation
    "Page.getFrameTree", // initial policy inventory
    "DOM.getDocument",
    "DOM.describeNode",
    "Page.createIsolatedWorld",
    "DOM.resolveNode",
    "Runtime.callFunctionOn",
    "Page.getFrameTree", // final policy inventory
    "DOM.getDocument",
    "DOM.describeNode",
    "Page.getFrameTree", // query_fields ancestry
    "Page.getFrameTree", // query_fields root
    "Page.getFrameTree", // final lineage
    "Page.getFrameTree", // final enumeration
    "Page.createIsolatedWorld",
    "Page.getFrameTree", // final enumeration validation
];
const FINAL_EXTRA_WORKER_APPLICATION: [&str; 13] = [
    "Page.getFrameTree",
    "Page.createIsolatedWorld",
    "Page.getFrameTree",
    "DOM.getDocument",
    "DOM.describeNode",
    "DOM.resolveNode",
    "Runtime.callFunctionOn",
    "DOM.getDocument",
    "DOM.describeNode",
    "Page.getFrameTree",
    "Page.getFrameTree",
    "Page.createIsolatedWorld",
    "Page.getFrameTree",
];
const SAMPLE_INDEX: usize = 6;
const FINAL_DOCUMENT_INDEX: usize = 7;
const FINAL_DESCRIPTION_INDEX: usize = 8;
const FINAL_TOPOLOGY_INDEX: usize = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Valid,
    RequiresAxBackendError,
    InitialExtraWorker,
    FinalExtraWorker,
    ForeignInitialFrame,
    ForeignInitialDescription,
    ForeignFinalDescription,
    ForeignPublicationFrame,
    OpaqueInitialDescription,
    OpaqueFinalDescription,
    HeldCleanup,
    HeldInitialDescription,
    HeldFinalDescription,
    FinalChild,
    FinalFrame,
    FinalLoader,
    FinalUrl,
    FinalDocument,
    FinalClosedRoot,
    FinalLeafChurn,
}
impl Mode {
    fn script(self) -> &'static [&'static str] {
        match self {
            Self::RequiresAxBackendError => &REQUIRES_AX_APPLICATION,
            Self::InitialExtraWorker => &LEGACY_APPLICATION,
            Self::FinalExtraWorker => &FINAL_EXTRA_WORKER_APPLICATION,
            _ => &APPLICATION,
        }
    }
    fn sample_index(self) -> usize {
        if self == Self::InitialExtraWorker {
            9
        } else {
            SAMPLE_INDEX
        }
    }
    fn boundary(self) -> Option<usize> {
        match self {
            Self::ForeignInitialFrame => Some(2),
            Self::ForeignInitialDescription
            | Self::OpaqueInitialDescription
            | Self::HeldInitialDescription => Some(4),
            Self::ForeignFinalDescription
            | Self::OpaqueFinalDescription
            | Self::HeldFinalDescription => Some(FINAL_DESCRIPTION_INDEX),
            Self::FinalDocument | Self::FinalClosedRoot => Some(FINAL_DESCRIPTION_INDEX),
            Self::ForeignPublicationFrame
            | Self::FinalChild
            | Self::FinalFrame
            | Self::FinalLoader
            | Self::FinalUrl => Some(FINAL_TOPOLOGY_INDEX),
            Self::Valid
            | Self::HeldCleanup
            | Self::FinalLeafChurn
            | Self::RequiresAxBackendError
            | Self::InitialExtraWorker
            | Self::FinalExtraWorker => None,
        }
    }
    fn foreign(self) -> bool {
        matches!(
            self,
            Self::ForeignInitialFrame
                | Self::ForeignInitialDescription
                | Self::ForeignFinalDescription
                | Self::ForeignPublicationFrame
        )
    }
    fn opaque(self) -> bool {
        matches!(
            self,
            Self::OpaqueInitialDescription | Self::OpaqueFinalDescription
        )
    }
    fn hold_description(self) -> bool {
        matches!(
            self,
            Self::HeldInitialDescription | Self::HeldFinalDescription
        )
    }
}

enum Control {
    Arm(oneshot::Sender<()>),
    ReleaseHeld(oneshot::Sender<()>),
    Disarm(oneshot::Sender<()>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerExit {
    NativeCloseFrame,
    NativeEndOfStream,
    TestDisconnect,
}
#[derive(Debug)]
struct PeerReport {
    mode: Mode,
    exit: PeerExit,
    armed: bool,
    application_count: usize,
    release_seen: bool,
    held_response_pending: bool,
    final_document_response_pending: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disarm {
    Acknowledged,
    ControlClosedBeforeSend,
    ControlClosedBeforeAck,
}
struct Peer {
    mode: Mode,
    endpoint: String,
    application: Arc<Mutex<Vec<Value>>>,
    releases: Arc<Mutex<Vec<Value>>>,
    control: mpsc::UnboundedSender<Control>,
    held: mpsc::UnboundedReceiver<()>,
    disconnect: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<PeerReport>,
}
async fn control(peer: &Peer, make: impl FnOnce(oneshot::Sender<()>) -> Control) {
    let (send, receive) = oneshot::channel();
    peer.control.send(make(send)).unwrap();
    tokio::time::timeout(Duration::from_secs(2), receive)
        .await
        .expect("peer control not consumed")
        .unwrap();
}
// Only terminal teardown may observe an already exited peer. Arm and exact
// held-ACK release still use control(), whose ACK is mandatory. A closed
// Disarm channel is not success: finish() must join and validate PeerReport.
async fn disarm(peer: &Peer) -> Disarm {
    let (send, receive) = oneshot::channel();
    if peer.control.send(Control::Disarm(send)).is_err() {
        return Disarm::ControlClosedBeforeSend;
    }
    match tokio::time::timeout(Duration::from_secs(2), receive)
        .await
        .expect("peer teardown control not consumed")
    {
        Ok(()) => Disarm::Acknowledged,
        Err(_) => Disarm::ControlClosedBeforeAck,
    }
}
fn reply(request: &Value, result: Value) -> Value {
    let mut response = json!({"id":request["id"],"result":result});
    if let Some(session) = request.get("sessionId") {
        response["sessionId"] = session.clone();
    }
    response
}
async fn send_reply(
    socket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    response: Value,
) {
    socket
        .send(Message::Text(response.to_string()))
        .await
        .unwrap();
}
fn frame_tree() -> Value {
    json!({"frameTree":{"frame":{"id":"frame-host-session","loaderId":"activation-loader","url":"about:blank"}}})
}
fn application_reply(
    request: &Value,
    group: &mut Option<String>,
    mode: Mode,
    ordinal: usize,
) -> Value {
    assert_eq!(request["sessionId"], "host-session");
    match request["method"].as_str().unwrap() {
        "Page.getFrameTree" => {
            assert_eq!(request["params"], json!({}));
            frame_tree()
        }
        "Page.createIsolatedWorld" => {
            assert_eq!(
                request["params"],
                json!({"frameId":"frame-host-session","worldName":"agent-browser-native-observation"})
            );
            json!({"executionContextId":1})
        }
        "Accessibility.getFullAXTree" => {
            assert_eq!(mode, Mode::RequiresAxBackendError);
            assert_eq!(ordinal, REQUIRES_AX_APPLICATION.len() - 1);
            assert_eq!(request["params"], json!({"frameId":"frame-host-session"}));
            json!({})
        }
        "DOM.getDocument" => {
            assert_eq!(request["params"], json!({"depth":0,"pierce":true}));
            json!({"root":{"nodeType":9,"backendNodeId":1}})
        }
        "DOM.describeNode" => {
            let backend = if mode == Mode::FinalDocument && ordinal == FINAL_DESCRIPTION_INDEX {
                101
            } else {
                1
            };
            assert_eq!(
                request["params"],
                json!({"backendNodeId":backend,"depth":-1,"pierce":true})
            );
            json!({"node":{"nodeId":0,"nodeType":9,"backendNodeId":1,"children":[{"nodeId":0,"nodeType":1,"backendNodeId":2,"nodeName":"INPUT","attributes":["data-testid","city"],"children":[]}]}})
        }
        "DOM.resolveNode" => {
            assert_eq!(request["params"]["backendNodeId"], 1);
            assert_eq!(request["params"]["executionContextId"], 1);
            let observed = request["params"]["objectGroup"].as_str().unwrap();
            assert!(observed.starts_with("native-query-"));
            assert!(group.replace(observed.to_owned()).is_none());
            json!({"object":{"type":"object","subtype":"node","objectId":"field-root"}})
        }
        "Runtime.callFunctionOn" => {
            assert_eq!(request["params"]["objectId"], "field-root");
            assert_eq!(request["params"]["objectGroup"].as_str(), group.as_deref());
            assert_eq!(request["params"]["returnByValue"], true);
            assert!(request["params"]["functionDeclaration"]
                .as_str()
                .unwrap()
                .starts_with(
                "function(expression,fields,testId,secureSelector,authorRoots,domains,...roots)"
            ));
            assert_eq!(
                request["params"]["arguments"],
                json!([
                    {"value":canonical_expression()}, {"value":if mode == Mode::RequiresAxBackendError { vec!["states"] } else { vec!["value"] }},
                    {"value":"data-testid"}, {"value":FIXTURE_SECURE_SELECTOR},
                    {"value":[true]}, {"value":[0]}, {"objectId":"field-root"}
                ])
            );
            // Nonempty positive data matters: a test that always samples []
            // cannot distinguish refusal from an accidentally empty success.
            json!({"result":{"value":{"values":[{"value":"London","attributes":{},"labels":[],"states":{"secure":false}}]}}})
        }
        method => panic!("unexpected application read: {method}"),
    }
}

async fn peer(mode: Mode) -> Peer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let application = Arc::new(Mutex::new(Vec::new()));
    let recorded = application.clone();
    let releases = Arc::new(Mutex::new(Vec::new()));
    let recorded_releases = releases.clone();
    let (control, mut controls) = mpsc::unbounded_channel();
    let (held_send, held) = mpsc::unbounded_channel();
    let (disconnect, mut disconnected) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let target = json!({"targetId":"host-page","type":"page","browserContextId":"host-context","url":"about:blank","title":""});
        let mut loader = "host-loader";
        let mut armed = false;
        let mut ordinal = 0;
        let mut group = None;
        let mut release_seen = false;
        let mut held_response = None;
        let mut final_document_response = None;
        let exit = loop {
            tokio::select! {
                _ = &mut disconnected => break PeerExit::TestDisconnect,
                command = controls.recv() => {
                    match command.expect("peer controls remain owned") {
                        Control::Arm(done) => {
                            assert!(!armed);
                            assert_eq!(ordinal, 0);
                            armed = true;
                            done.send(()).unwrap();
                        }
                        Control::ReleaseHeld(done) => {
                            send_reply(&mut socket, held_response.take().expect("no held ACK")).await;
                            done.send(()).unwrap();
                        }
                        Control::Disarm(done) => {
                            assert!(held_response.is_none());
                            assert!(final_document_response.is_none());
                            armed = false;
                            done.send(()).unwrap();
                        }
                    }
                }
                message = socket.next() => {
                    let text = match message {
                        Some(Ok(Message::Text(text))) => text,
                        Some(Ok(Message::Ping(payload))) => {
                            socket.send(Message::Pong(payload)).await.unwrap();
                            continue;
                        }
                        Some(Ok(Message::Pong(_))) => continue,
                        Some(Ok(Message::Close(_))) => break PeerExit::NativeCloseFrame,
                        None => break PeerExit::NativeEndOfStream,
                        Some(Ok(Message::Binary(_) | Message::Frame(_))) => {
                            panic!("unexpected field fixture WebSocket frame")
                        }
                        Some(Err(error)) => panic!("field fixture WebSocket failed: {error}"),
                    };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    let method = request["method"].as_str().unwrap();
                    if armed {
                        if method == "Runtime.releaseObjectGroup" {
                            assert!(!release_seen, "duplicate group release");
                            assert_eq!(request["sessionId"], "host-session");
                            assert_eq!(request["params"]["objectGroup"].as_str(), group.as_deref());
                            assert!(group.is_some());
                            release_seen = true;
                            recorded_releases.lock().unwrap().push(request.clone());
                            let response = reply(&request, json!({}));
                            if mode == Mode::HeldCleanup {
                                assert!(held_response.replace(response).is_none());
                                held_send.send(()).unwrap();
                            } else {
                                send_reply(&mut socket, response).await;
                                if let Some(response) = final_document_response.take() {
                                    send_reply(&mut socket, response).await;
                                }
                            }
                            continue;
                        }
                        assert_eq!(Some(&method), mode.script().get(ordinal), "application order changed at {ordinal}");
                        let current = ordinal;
                        ordinal += 1;
                        recorded.lock().unwrap().push(request.clone());
                        let mut response = reply(&request, application_reply(&request, &mut group, mode, current));
                        if mode == Mode::RequiresAxBackendError {
                            if current == SAMPLE_INDEX {
                                response["result"]["result"]["value"] = json!({"requiresAx":true});
                            } else if current == REQUIRES_AX_APPLICATION.len() - 1 {
                                response.as_object_mut().unwrap().remove("result");
                                response["error"] = json!({"code":-32000,"message":"explicit AX control failure"});
                            }
                        }
                        if current == FINAL_DOCUMENT_INDEX && mode == Mode::FinalDocument {
                            response["result"]["root"]["backendNodeId"] = json!(101);
                        }
                        if current == FINAL_DESCRIPTION_INDEX {
                            match mode {
                                Mode::FinalDocument => response["result"]["node"]["backendNodeId"] = json!(101),
                                Mode::FinalClosedRoot => response["result"]["node"]["children"][0]["shadowRoots"] =
                                    json!([{"nodeType":11,"backendNodeId":3,"shadowRootType":"closed","children":[]}]),
                                Mode::FinalLeafChurn => response["result"]["node"]["children"][0]["backendNodeId"] = json!(99),
                                _ => {}
                            }
                        }
                        if current == FINAL_TOPOLOGY_INDEX {
                            match mode {
                                Mode::FinalChild => response["result"]["frameTree"]["childFrames"] = json!([
                                    {"frame":{"id":"same-session-child","parentId":"frame-host-session","loaderId":"child-loader","url":"about:blank"}}
                                ]),
                                Mode::FinalFrame => response["result"]["frameTree"]["frame"]["id"] = json!("replacement-frame"),
                                Mode::FinalLoader => response["result"]["frameTree"]["frame"]["loaderId"] = json!("replacement-loader"),
                                Mode::FinalUrl => response["result"]["frameTree"]["frame"]["url"] = json!("https://changed.invalid/"),
                                _ => {}
                            }
                        }
                        if mode == Mode::FinalExtraWorker && current == FINAL_DESCRIPTION_INDEX {
                            assert!(held_response.replace(response).is_none());
                            held_send.send(()).unwrap();
                            continue;
                        }
                        if mode.boundary() == Some(current) {
                            if mode.foreign() {
                                // Keep the exact command id and payload; change only session.
                                response["sessionId"] = json!("foreign-session");
                            } else if mode.opaque() {
                                response.as_object_mut().unwrap().remove("result");
                                response["error"] = json!({"code":-32000,"message":"deadline exceeded in another operation"});
                            } else if mode.hold_description() {
                                assert!(held_response.replace(response).is_none());
                                held_send.send(()).unwrap();
                                continue;
                            }
                        }
                        // Only the test peer imposes this rendezvous. It accepts
                        // either release-first or final-document-first wire order.
                        // Poison controls then measure exactly one read debt,
                        // not an unrelated racing release/group obligation.
                        if current == mode.sample_index() + 1 && mode != Mode::HeldCleanup && !release_seen {
                            assert!(final_document_response.replace(response).is_none());
                        } else {
                            send_reply(&mut socket, response).await;
                        }
                        continue;
                    }
                    // Setup may perform these reads; terminal cleanup may not
                    // silently resume the completed field application script.
                    if ordinal != 0 {
                        assert!(!mode.script().contains(&method), "late application read after Disarm: {method}");
                    }
                    let session = request["sessionId"].as_str().unwrap_or("");
                    let result = match method {
                        "Browser.getVersion" => json!({"protocolVersion":"1.3","product":"Synthetic Chromium/1.0","revision":"synthetic","userAgent":"Synthetic Chromium Linux","jsVersion":"synthetic"}),
                        "Target.getBrowserContexts" => json!({"browserContextIds":[],"defaultBrowserContextId":"host-context"}),
                        "Target.getTargets" => json!({"targetInfos":[target.clone()]}),
                        "Target.getTargetInfo" => { assert_eq!(request["params"]["targetId"], "host-page"); json!({"targetInfo":target.clone()}) },
                        "Target.attachToTarget" => { assert_eq!(request["params"]["targetId"], "host-page"); json!({"sessionId":"host-session"}) },
                        "Page.getFrameTree" => json!({"frameTree":{"frame":{"id":"frame-host-session","loaderId":loader,"url":"about:blank"}}}),
                        "Page.navigate" => { assert_eq!(request["params"]["url"], "about:blank"); loader = "activation-loader"; json!({"frameId":"frame-host-session","loaderId":loader}) },
                        "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":format!("script-{}",request["id"])}),
                        "Page.createIsolatedWorld" => { assert_eq!(request["params"]["frameId"], "frame-host-session"); json!({"executionContextId":1}) },
                        "Runtime.evaluate" if request["params"]["expression"] == "location.href" => json!({"result":{"type":"string","value":"about:blank"}}),
                        "Page.enable" | "Runtime.enable" | "Network.enable" | "WebMCP.enable"
                        | "DOM.enable" | "DOM.disable" | "Network.disable" | "Network.setBypassServiceWorker"
                        | "Fetch.enable" | "Fetch.disable" | "Page.setLifecycleEventsEnabled"
                        | "Target.setDiscoverTargets" | "Target.setAutoAttach" | "Runtime.runIfWaitingForDebugger"
                        | "Page.removeScriptToEvaluateOnNewDocument" | "Emulation.setEmulatedMedia"
                        | "Target.detachFromTarget" | "Browser.setDownloadBehavior" => json!({}),
                        other => panic!("unexpected field fixture setup/cleanup command: {other}: {request}"),
                    };
                    send_reply(&mut socket, reply(&request, result)).await;
                    if method == "Page.navigate" {
                        for event in [
                            json!({"method":"Page.frameNavigated","sessionId":session,"params":{"frame":{"id":"frame-host-session","loaderId":loader,"url":"about:blank","securityOrigin":"null"}}}),
                            json!({"method":"Page.lifecycleEvent","sessionId":session,"params":{"frameId":"frame-host-session","loaderId":loader,"name":"DOMContentLoaded"}}),
                        ] {
                            send_reply(&mut socket, event).await;
                        }
                    }
                    if method == "Target.detachFromTarget" {
                        assert_eq!(request["params"]["sessionId"], "host-session");
                        send_reply(&mut socket, json!({"method":"Target.detachedFromTarget","params":{"sessionId":"host-session","targetId":"host-page"}})).await;
                    }
                }
            }
        };
        PeerReport {
            mode,
            exit,
            armed,
            application_count: ordinal,
            release_seen,
            held_response_pending: held_response.is_some(),
            final_document_response_pending: final_document_response.is_some(),
        }
    });
    Peer {
        mode,
        endpoint,
        application,
        releases,
        control,
        held,
        disconnect,
        task,
    }
}

fn expression() -> Value {
    // Public input deliberately omits the optional/defaulted state filter.
    json!({"kind":"query","query":{"kind":"testId","value":{"kind":"string","value":"city","exact":true}}})
}
fn canonical_expression() -> Value {
    // SemanticQuery.states has serde(default), but no skip_serializing_if.
    // ClientBrowser deserializes the public input before fresh_query serializes
    // this typed expression into callFunctionOn arguments. Compare the exact
    // canonical wire value, not the unnormalized public request object.
    json!({"kind":"query","query":{"kind":"testId","value":{"kind":"string","value":"city","exact":true},"states":{}}})
}
async fn debt_settled(ledger: &OwnerDebtLedger) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = ledger.snapshot();
            assert!(!snapshot.integrity_lost);
            assert_eq!(snapshot.input_debt, 0);
            if snapshot.outstanding_commands == 0 && snapshot.object_debt == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("exact command/group ACK did not settle");
}
async fn setup(mode: Mode) -> (Peer, Arc<ClientBrowser>, FramedFixture, String) {
    eprintln!("PUBLIC_FIELD_CASE mode={mode:?} phase=setup");
    let peer = peer(mode).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture = FramedFixture::with_capabilities(
        broker,
        browser.clone(),
        [
            "browser.scope/1",
            "browser.lifecycle/1",
            "browser.network/1",
            "browser.fixture-read-fields/1",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    );
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
    let ledger = browser
        .page_lease(false)
        .await
        .unwrap()
        .client
        .debt_ledger()
        .unwrap();
    debt_settled(&ledger).await;
    assert!(browser.refs.lock().unwrap().entries_sorted().is_empty());
    control(&peer, Control::Arm).await;
    (peer, browser, fixture, scope)
}
async fn request(fixture: &mut FramedFixture, scope: &str, timeout_ms: u64) {
    request_fields(fixture, scope, timeout_ms, "value").await;
}
async fn request_fields(fixture: &mut FramedFixture, scope: &str, timeout_ms: u64, field: &str) {
    fixture.sequence += 1;
    fixture
        .write(json!({"type":"request","id":"public-fields","generation":1,
        "operationSeq":fixture.sequence,"timeoutMs":timeout_ms,"command":"fixture.read-fields",
        "args":{"identityScope":scope,"expression":expression(),"fields":[field],
        "testIdAttribute":"data-testid","secureFieldSelector":FIXTURE_SECURE_SELECTOR}}))
        .await
        .unwrap();
}
async fn result(fixture: &mut FramedFixture, cancellation: bool) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut result = None;
        let mut cancelled = false;
        for _ in 0..64 {
            let frame = fixture.read().await.unwrap();
            assert_eq!(frame["generation"], 1);
            match frame["type"].as_str() {
                Some("result") => {
                    assert_eq!(frame["id"], "public-fields");
                    assert_eq!(frame["operationSeq"], fixture.sequence);
                    assert!(result.replace(frame).is_none());
                }
                Some("control-result") => {
                    assert!(cancellation && !cancelled);
                    assert_eq!(frame["id"], "cancel-fields");
                    assert_eq!(frame["accepted"], true);
                    cancelled = true;
                }
                Some("event") => {
                    validate_fixture_notice(&frame).unwrap();
                    assert_eq!(frame["sequence"], fixture.event_sequence + 1);
                    fixture.event_sequence += 1;
                }
                other => panic!("unexpected ReadFields frame {other:?}: {frame}"),
            }
            if let Some(value) = result.take_if(|_| !cancellation || cancelled) {
                return value;
            }
        }
        panic!("ReadFields frame bound exhausted");
    })
    .await
    .expect("public ReadFields result stalled")
}
fn assert_script(peer: &Peer, mode: Mode) {
    let application = peer.application.lock().unwrap();
    let expected_count = mode.boundary().map_or(mode.script().len(), |at| at + 1);
    assert_eq!(application.len(), expected_count, "{mode:?}");
    for (request, method) in application.iter().zip(mode.script().iter().copied()) {
        assert_eq!(request["method"], method);
        assert_eq!(request["sessionId"], "host-session");
    }
    assert_eq!(
        peer.releases.lock().unwrap().len(),
        usize::from(expected_count > mode.sample_index())
    );
}
fn assert_rejected(value: &Value, browser: &ClientBrowser) {
    assert_eq!(value["ok"], false);
    assert!(
        value.get("data").is_none(),
        "untrusted sampled values escaped"
    );
    assert!(value.get("error").is_some());
    assert!(
        value.get("retention").is_none(),
        "ReadFields acquired retained Observe authority"
    );
    assert!(
        browser.refs.lock().unwrap().entries_sorted().is_empty(),
        "ReadFields minted references"
    );
}
async fn finish(peer: Peer, fixture: FramedFixture, poisoned: bool) {
    // All public result/ledger assertions run before this call. Recheck the
    // exact completed script before allowing any terminal-only alternative.
    let mode = peer.mode;
    assert_eq!(poisoned, mode.foreign());
    assert_script(&peer, mode);
    let expected_count = mode.boundary().map_or(mode.script().len(), |at| at + 1);
    let application = peer.application.clone();
    let releases = peer.releases.clone();
    let completed_application = application.lock().unwrap().clone();
    let completed_releases = releases.lock().unwrap().clone();
    eprintln!("PUBLIC_FIELD_CASE mode={mode:?} phase=business-assertions-complete");
    let disarm = disarm(&peer).await;
    // Match FramedFixture::finish's real EOF/server join, but do not collapse
    // a native framed-server panic into the expected poisoned cleanup refusal.
    drop(fixture.stream);
    let cleanup = tokio::time::timeout(Duration::from_secs(10), fixture.server)
        .await
        .expect("framed shutdown stalled")
        .expect("native framed server panicked");
    if poisoned && disarm == Disarm::Acknowledged {
        // Teardown only, after native shutdown has actually been joined. If
        // Disarm lost its ACK, do NOT force a close and mistake it for evidence
        // of the native close that must instead explain the missing control.
        let _ = peer.disconnect.send(());
    }
    let report = tokio::time::timeout(Duration::from_secs(2), peer.task)
        .await
        .expect("CDP peer not joined")
        .expect("CDP peer panicked");
    eprintln!(
        "PUBLIC_FIELD_PEER_TEARDOWN mode={mode:?} disarm={disarm:?} report={report:?} cleanup_failed={}",
        !cleanup
    );
    assert_eq!(
        !cleanup, poisoned,
        "poisoned custody cannot report clean shutdown"
    );
    assert_eq!(report.mode, mode);
    assert_eq!(*application.lock().unwrap(), completed_application);
    assert_eq!(*releases.lock().unwrap(), completed_releases);
    assert_eq!(report.application_count, expected_count);
    assert_eq!(report.release_seen, expected_count > mode.sample_index());
    assert!(
        !report.held_response_pending,
        "teardown lost a required held ACK"
    );
    assert!(
        !report.final_document_response_pending,
        "teardown lost a final-document rendezvous"
    );
    match disarm {
        Disarm::Acknowledged => {
            assert!(!report.armed);
            if !poisoned {
                assert_ne!(report.exit, PeerExit::TestDisconnect);
            }
        }
        Disarm::ControlClosedBeforeSend | Disarm::ControlClosedBeforeAck => {
            // Unknown/quarantined public results automatically start native
            // shutdown. That real close can win before test-side Disarm. Only
            // exact native Close/EOF plus joined, complete, debt-checked work is
            // acceptable; timeout, peer panic, unknown I/O failure, or test-side
            // disconnect cannot substitute for that lifecycle evidence.
            assert!(poisoned, "usable operation lost its live peer control");
            assert!(report.armed);
            assert!(matches!(
                report.exit,
                PeerExit::NativeCloseFrame | PeerExit::NativeEndOfStream
            ));
        }
    }
}

#[tokio::test]
async fn public_read_fields_foreign_inventory_acks_never_publish_values_or_refs() {
    for mode in [
        Mode::ForeignInitialFrame,
        Mode::ForeignInitialDescription,
        Mode::ForeignFinalDescription,
        Mode::ForeignPublicationFrame,
    ] {
        let (peer, browser, mut fixture, scope) = setup(mode).await;
        let ledger = browser
            .page_lease(false)
            .await
            .unwrap()
            .client
            .debt_ledger()
            .unwrap();
        request(&mut fixture, &scope, 5_000).await;
        let value = result(&mut fixture, false).await;
        assert_rejected(&value, &browser);
        assert_eq!(
            value["error"]["code"],
            if mode == Mode::ForeignPublicationFrame {
                "scope-unavailable"
            } else {
                "browser-failure"
            },
            "an eventual original deadline is not the authority refusal"
        );
        assert_eq!(value["effects"], "unknown");
        assert_eq!(value["scopeState"], "quarantined");
        let snapshot = ledger.snapshot();
        assert!(
            snapshot.integrity_lost,
            "reader must poison before waiter delivery"
        );
        assert_eq!(
            snapshot.outstanding_commands, 1,
            "foreign ACK is not settlement"
        );
        assert_eq!(
            snapshot.object_debt, 0,
            "valid release ACK precedes injected final inventory ACK"
        );
        assert_eq!(snapshot.input_debt, 0);
        for class in [AdmissionClass::Reference, AdmissionClass::FixedRead] {
            assert_eq!(
                ledger.check_admission(class),
                Err(ProtocolError::ScopeUnavailable)
            );
        }
        assert_script(&peer, mode);
        finish(peer, fixture, true).await;
    }
}

#[tokio::test]
async fn public_read_fields_valid_acks_publish_nonempty_value_without_refs() {
    let mode = Mode::Valid;
    let (peer, browser, mut fixture, scope) = setup(mode).await;
    let ledger = browser
        .page_lease(false)
        .await
        .unwrap()
        .client
        .debt_ledger()
        .unwrap();
    request(&mut fixture, &scope, 5_000).await;
    let value = result(&mut fixture, false).await;
    assert_eq!(value["ok"], true);
    assert_eq!(value["effects"], "completed");
    assert_eq!(value["scopeState"], "usable");
    assert_eq!(
        value["data"],
        json!({"identityScope":scope,"values":[{"value":"London","states":{"secure":false}}]})
    );
    assert!(browser.refs.lock().unwrap().entries_sorted().is_empty());
    debt_settled(&ledger).await;
    assert_script(&peer, mode);
    finish(peer, fixture, false).await;
}

#[tokio::test]
async fn public_read_fields_opaque_inventory_errors_do_not_forge_original_deadline() {
    for mode in [Mode::OpaqueInitialDescription, Mode::OpaqueFinalDescription] {
        let (peer, browser, mut fixture, scope) = setup(mode).await;
        let ledger = browser
            .page_lease(false)
            .await
            .unwrap()
            .client
            .debt_ledger()
            .unwrap();
        request(&mut fixture, &scope, 5_000).await;
        let value = result(&mut fixture, false).await;
        assert_rejected(&value, &browser);
        assert_eq!(value["error"]["code"], "browser-failure");
        assert_eq!(value["effects"], "not-dispatched");
        assert_eq!(value["scopeState"], "usable");
        debt_settled(&ledger).await;
        assert_script(&peer, mode);
        finish(peer, fixture, false).await;
    }
}

#[tokio::test]
async fn public_read_fields_valid_async_cleanup_custody_does_not_require_release_ack() {
    let mode = Mode::HeldCleanup;
    let (mut peer, browser, mut fixture, scope) = setup(mode).await;
    let ledger = browser
        .page_lease(false)
        .await
        .unwrap()
        .client
        .debt_ledger()
        .unwrap();
    request(&mut fixture, &scope, 5_000).await;
    tokio::time::timeout(Duration::from_secs(2), peer.held.recv())
        .await
        .unwrap()
        .unwrap();
    // Read the actual public result before permitting the release ACK.
    let value = result(&mut fixture, false).await;
    assert_eq!(value["ok"], true);
    assert_eq!(value["effects"], "completed");
    assert_eq!(value["scopeState"], "usable");
    assert_eq!(
        value["data"],
        json!({"identityScope":scope,"values":[{"value":"London","states":{"secure":false}}]})
    );
    assert!(browser.refs.lock().unwrap().entries_sorted().is_empty());
    let snapshot = ledger.snapshot();
    assert!(!snapshot.integrity_lost);
    assert_eq!(snapshot.outstanding_commands, 1);
    assert_eq!(snapshot.object_debt, 1);
    assert_eq!(snapshot.input_debt, 0);
    ledger.check_admission(AdmissionClass::Reference).unwrap();
    control(&peer, Control::ReleaseHeld).await;
    debt_settled(&ledger).await;
    assert_script(&peer, mode);
    finish(peer, fixture, false).await;
}

#[tokio::test]
async fn public_read_fields_original_stop_survives_held_inventory_ack() {
    for mode in [Mode::HeldInitialDescription, Mode::HeldFinalDescription] {
        for cancel in [false, true] {
            eprintln!("PUBLIC_FIELD_STOP mode={mode:?} cancel={cancel}");
            let (mut peer, browser, mut fixture, scope) = setup(mode).await;
            let ledger = browser
                .page_lease(false)
                .await
                .unwrap()
                .client
                .debt_ledger()
                .unwrap();
            request(&mut fixture, &scope, if cancel { 5_000 } else { 1_000 }).await;
            tokio::time::timeout(Duration::from_secs(2), peer.held.recv())
                .await
                .unwrap()
                .unwrap();
            if cancel {
                fixture.write(json!({"type":"cancel","id":"cancel-fields","generation":1,"operationSeq":fixture.sequence})).await.unwrap();
            }
            // The peer handshake fixes the command boundary. For the deadline
            // case the production original lease timer, not a test sleep, fires.
            let value = result(&mut fixture, cancel).await;
            assert_rejected(&value, &browser);
            assert_eq!(
                value["error"]["code"],
                if cancel {
                    "cancelled"
                } else {
                    "deadline-exceeded"
                }
            );
            assert_eq!(value["effects"], "not-dispatched");
            assert_eq!(value["scopeState"], "usable");
            let snapshot = ledger.snapshot();
            assert!(!snapshot.integrity_lost);
            assert_eq!(
                snapshot.outstanding_commands, 1,
                "stop cannot fabricate read ACK"
            );
            assert_eq!(snapshot.object_debt, 0);
            assert_eq!(snapshot.input_debt, 0);
            control(&peer, Control::ReleaseHeld).await;
            debt_settled(&ledger).await;
            assert!(browser.refs.lock().unwrap().entries_sorted().is_empty());
            assert_script(&peer, mode);
            finish(peer, fixture, false).await;
        }
    }
}

#[tokio::test]
async fn public_read_fields_final_topology_and_policy_changes_never_publish_sample() {
    for mode in [
        Mode::FinalChild,
        Mode::FinalFrame,
        Mode::FinalLoader,
        Mode::FinalUrl,
        Mode::FinalDocument,
        Mode::FinalClosedRoot,
    ] {
        let (peer, browser, mut fixture, scope) = setup(mode).await;
        let ledger = browser
            .page_lease(false)
            .await
            .unwrap()
            .client
            .debt_ledger()
            .unwrap();
        request(&mut fixture, &scope, 5_000).await;
        let value = result(&mut fixture, false).await;
        assert_rejected(&value, &browser);
        assert_eq!(value["effects"], "not-dispatched");
        assert_eq!(value["scopeState"], "usable");
        debt_settled(&ledger).await;
        assert_eq!(
            value["error"]["code"],
            if matches!(mode, Mode::FinalDocument | Mode::FinalClosedRoot) {
                "stale-reference"
            } else {
                "stale-scope"
            }
        );
        // The fixture supplied a nonempty sample exactly once; refusal must
        // come from the fresh final proof, never a replay on another document.
        assert_eq!(
            peer.application
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request["method"] == "Runtime.callFunctionOn")
                .count(),
            1
        );
        assert_script(&peer, mode);
        finish(peer, fixture, false).await;
    }
}

#[tokio::test]
async fn public_read_fields_leaf_churn_preserves_root_policy_and_sample() {
    let mode = Mode::FinalLeafChurn;
    let (peer, browser, mut fixture, scope) = setup(mode).await;
    let ledger = browser
        .page_lease(false)
        .await
        .unwrap()
        .client
        .debt_ledger()
        .unwrap();
    request(&mut fixture, &scope, 5_000).await;
    let value = result(&mut fixture, false).await;
    assert_eq!(value["ok"], true);
    assert_eq!(value["effects"], "completed");
    assert_eq!(value["scopeState"], "usable");
    assert_eq!(
        value["data"],
        json!({"identityScope":scope,"values":[{"value":"London","states":{"secure":false}}]})
    );
    assert!(browser.refs.lock().unwrap().entries_sorted().is_empty());
    debt_settled(&ledger).await;
    assert_script(&peer, mode);
    finish(peer, fixture, false).await;
}

#[tokio::test]
async fn public_read_fields_requires_ax_validates_final_frames_before_ax_without_resampling() {
    let mode = Mode::RequiresAxBackendError;
    let (peer, browser, mut fixture, scope) = setup(mode).await;
    let ledger = browser
        .page_lease(false)
        .await
        .unwrap()
        .client
        .debt_ledger()
        .unwrap();
    request_fields(&mut fixture, &scope, 5_000, "states").await;
    let value = result(&mut fixture, false).await;
    assert_rejected(&value, &browser);
    assert_eq!(value["error"]["code"], "browser-failure");
    assert_eq!(value["effects"], "not-dispatched");
    assert_eq!(value["scopeState"], "usable");
    debt_settled(&ledger).await;
    assert_eq!(
        peer.application
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request["method"] == "Runtime.callFunctionOn")
            .count(),
        1
    );
    assert_script(&peer, mode);
    finish(peer, fixture, false).await;
}

// This fixture constructs a ready unrelated registry member using the same
// lifecycle APIs as target-registry unit tests, never an OwnedTarget literal or
// a forged private tenure. It is detached before normal host-page shutdown.
async fn add_ready_worker(browser: &ClientBrowser) {
    let page = browser.page_lease(false).await.unwrap();
    assert!(page
        .targets
        .attached(
            "host-context",
            "extra-worker".into(),
            "worker-session".into(),
            "worker".into()
        )
        .unwrap());
    page.targets.configured("extra-worker").unwrap();
    page.targets
        .resume_permit("extra-worker")
        .await
        .unwrap()
        .complete()
        .unwrap();
    let (_, targets) = page.targets.inventory().unwrap();
    assert_eq!(targets.len(), 2);
    let worker = targets
        .iter()
        .find(|target| target.target_id == "extra-worker")
        .unwrap();
    assert_eq!(worker.session_id, "worker-session");
    assert_eq!(worker.kind, "worker");
    assert_eq!(
        worker.purpose,
        Some(crate::native::client_targets::TargetPurpose::Application)
    );
    assert!(worker.capture_ready());
}

#[tokio::test]
async fn public_read_fields_extra_ready_worker_uses_full_inventory_without_resampling() {
    for mode in [Mode::InitialExtraWorker, Mode::FinalExtraWorker] {
        let (mut peer, browser, mut fixture, scope) = setup(mode).await;
        let ledger = browser
            .page_lease(false)
            .await
            .unwrap()
            .client
            .debt_ledger()
            .unwrap();
        if mode == Mode::InitialExtraWorker {
            add_ready_worker(&browser).await;
        }
        request(&mut fixture, &scope, 5_000).await;
        if mode == Mode::FinalExtraWorker {
            tokio::time::timeout(Duration::from_secs(2), peer.held.recv())
                .await
                .unwrap()
                .unwrap();
            add_ready_worker(&browser).await;
            control(&peer, Control::ReleaseHeld).await;
        }
        let value = result(&mut fixture, false).await;
        assert_eq!(value["ok"], true);
        assert_eq!(value["effects"], "completed");
        assert_eq!(value["scopeState"], "usable");
        assert_eq!(
            value["data"],
            json!({"identityScope":scope,"values":[{"value":"London","states":{"secure":false}}]})
        );
        assert!(browser.refs.lock().unwrap().entries_sorted().is_empty());
        debt_settled(&ledger).await;
        assert_eq!(
            peer.application
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request["method"] == "Runtime.callFunctionOn")
                .count(),
            1
        );
        assert_script(&peer, mode);
        browser
            .page_lease(false)
            .await
            .unwrap()
            .targets
            .detach("extra-worker")
            .unwrap();
        finish(peer, fixture, false).await;
    }
}
