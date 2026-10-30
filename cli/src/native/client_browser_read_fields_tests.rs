//! Public ReadFields trust-boundary controls using the existing framed client.
//! The peer supplies CDP bytes, never callback results or synthetic settlement.
//! Internal Value delivery is provisional; only the public result may publish.
use super::*;
use crate::native::client_debt::{AdmissionClass, OwnerDebtLedger};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

// Exact single-frame S11 application script. Readonly release is independent.
// The last entry has no later CDP command to reject admission. The expected
// scope-unavailable must come from the final FieldReadRequest authority check,
// not the outer retained owner's separate dirty-success/cleanup-failed fallback.
const APPLICATION: [&str; 19] = [
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Valid,
    ForeignInitialFrame,
    ForeignInitialDescription,
    ForeignFinalDescription,
    ForeignPublicationFrame,
    OpaqueInitialDescription,
    OpaqueFinalDescription,
    HeldCleanup,
    HeldInitialDescription,
    HeldFinalDescription,
}
impl Mode {
    fn boundary(self) -> Option<usize> {
        match self {
            Self::ForeignInitialFrame => Some(3),
            Self::ForeignInitialDescription
            | Self::OpaqueInitialDescription
            | Self::HeldInitialDescription => Some(6),
            Self::ForeignFinalDescription
            | Self::OpaqueFinalDescription
            | Self::HeldFinalDescription => Some(12),
            Self::ForeignPublicationFrame => Some(18),
            Self::Valid | Self::HeldCleanup => None,
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
struct Peer {
    endpoint: String,
    application: Arc<Mutex<Vec<Value>>>,
    releases: Arc<Mutex<Vec<Value>>>,
    control: mpsc::UnboundedSender<Control>,
    held: mpsc::UnboundedReceiver<()>,
    disconnect: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}
async fn control(peer: &Peer, make: impl FnOnce(oneshot::Sender<()>) -> Control) {
    let (send, receive) = oneshot::channel();
    peer.control.send(make(send)).unwrap();
    tokio::time::timeout(Duration::from_secs(2), receive)
        .await
        .expect("peer control not consumed")
        .unwrap();
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
fn application_reply(request: &Value, group: &mut Option<String>) -> Value {
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
        "DOM.getDocument" => {
            assert_eq!(request["params"], json!({"depth":0,"pierce":true}));
            json!({"root":{"nodeType":9,"backendNodeId":1}})
        }
        "DOM.describeNode" => {
            assert_eq!(
                request["params"],
                json!({"backendNodeId":1,"depth":-1,"pierce":true})
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
                    {"value":expression()}, {"value":["value"]},
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
        let mut final_tree_response = None;
        loop {
            tokio::select! {
                _ = &mut disconnected => break,
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
                            assert!(final_tree_response.is_none());
                            armed = false;
                            done.send(()).unwrap();
                        }
                    }
                }
                message = socket.next() => {
                    let Some(Ok(Message::Text(text))) = message else { break; };
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
                                if let Some(response) = final_tree_response.take() {
                                    send_reply(&mut socket, response).await;
                                }
                            }
                            continue;
                        }
                        assert_eq!(Some(&method), APPLICATION.get(ordinal), "application order changed at {ordinal}");
                        let current = ordinal;
                        ordinal += 1;
                        recorded.lock().unwrap().push(request.clone());
                        let mut response = reply(&request, application_reply(&request, &mut group));
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
                        // either release-first or final-tree-first wire order.
                        // Poison controls then measure exactly one read debt,
                        // not an unrelated racing release/group obligation.
                        if current == 10 && mode != Mode::HeldCleanup && !release_seen {
                            assert!(final_tree_response.replace(response).is_none());
                        } else {
                            send_reply(&mut socket, response).await;
                        }
                        continue;
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
        }
    });
    Peer {
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
    json!({"kind":"query","query":{"kind":"testId","value":{"kind":"string","value":"city","exact":true}}})
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
    fixture.sequence += 1;
    fixture
        .write(json!({"type":"request","id":"public-fields","generation":1,
        "operationSeq":fixture.sequence,"timeoutMs":timeout_ms,"command":"fixture.read-fields",
        "args":{"identityScope":scope,"expression":expression(),"fields":["value"],
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
            if result.is_some() && (!cancellation || cancelled) {
                return result.unwrap();
            }
        }
        panic!("ReadFields frame bound exhausted");
    })
    .await
    .expect("public ReadFields result stalled")
}
fn assert_script(peer: &Peer, mode: Mode) {
    let application = peer.application.lock().unwrap();
    let expected_count = mode.boundary().map_or(APPLICATION.len(), |at| at + 1);
    assert_eq!(application.len(), expected_count, "{mode:?}");
    for (request, method) in application.iter().zip(APPLICATION) {
        assert_eq!(request["method"], method);
        assert_eq!(request["sessionId"], "host-session");
    }
    assert_eq!(
        peer.releases.lock().unwrap().len(),
        usize::from(expected_count > 9)
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
    control(&peer, Control::Disarm).await;
    let cleanup = tokio::time::timeout(Duration::from_secs(10), fixture.finish())
        .await
        .expect("framed shutdown stalled");
    assert_eq!(
        cleanup.is_err(),
        poisoned,
        "poisoned custody cannot report clean shutdown"
    );
    if poisoned {
        // Test teardown only, after all public result/debt assertions. EOF is
        // not an ACK and is never used to justify the operation's refusal.
        let _ = peer.disconnect.send(());
    }
    tokio::time::timeout(Duration::from_secs(2), peer.task)
        .await
        .expect("CDP peer not joined")
        .unwrap();
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
