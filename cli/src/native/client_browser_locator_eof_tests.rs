//! Real framed locator acquisition and enrolled Resolved lifetime across EOF.
//! Unlike the pointer fixture, the final input owns a real unresolved object.
use super::*;
use crate::native::client_browser::reconnect_tests::{candidate_cleanup_commands, peer, PeerMode};
use crate::native::client_protocol::{DISCONNECTED_RECOVERY, EXACT_OWNER_CONTINUATION};
use std::collections::HashMap;
use tokio::sync::mpsc;

fn purchase_expression() -> Value {
    json!({"kind":"query","query":{"kind":"text","value":{"kind":"string","value":"Purchase","exact":true}}})
}

// Managed readonly groups use the exact operation sequence and a transport
// allocator instance. Pure semantic bounds also use this group custody; the
// strict action object remains native-exact. A prefix-only match is not authority.
fn locator_readonly_group(session: &str, group: &str, sequence: u64) -> bool {
    if session != "host-session" || sequence == 0 {
        return false;
    }
    [
        "native-security-",
        "native-metadata-",
        "native-query-",
        "native-semantic-box-",
    ]
    .iter()
    .any(|prefix| {
        let Some(tail) = group.strip_prefix(prefix) else {
            return false;
        };
        let Some((operation, instance)) = tail.split_once('-') else {
            return false;
        };
        operation == sequence.to_string()
            && instance
                .parse::<u64>()
                .is_ok_and(|id| id > 0 && id < u64::MAX && id.to_string() == instance)
    })
}

#[test]
fn locator_readonly_group_requires_exact_owner_sequence_and_canonical_instance() {
    for prefix in [
        "native-security",
        "native-metadata",
        "native-query",
        "native-semantic-box",
    ] {
        let valid = format!("{prefix}-7-13");
        assert!(locator_readonly_group("host-session", &valid, 7));
        assert!(!locator_readonly_group("replacement-session", &valid, 7));
        assert!(!locator_readonly_group("host-session", &valid, 8));
        for suffix in [
            "0",
            "013",
            "+13",
            "13-extra",
            "",
            "x",
            "18446744073709551615",
            "18446744073709551616",
        ] {
            assert!(!locator_readonly_group(
                "host-session",
                &format!("{prefix}-7-{suffix}"),
                7
            ));
        }
    }
    for group in [
        "native-security-7",
        "native-security-8-13",
        "native-security-07-13",
        "native-security-7-0",
        "native-security-7-013",
        "native-security-7-+13",
        "native-security-7-13-extra",
        "native-security-7-",
        "native-security-7-x",
        "native-security-7-18446744073709551615",
        "native-security-7-18446744073709551616",
        "other-security-7-13",
        "native-exact",
        "native-semantic-box-8-13",
    ] {
        assert!(!locator_readonly_group("host-session", group, 7), "{group}");
    }
    assert!(!locator_readonly_group(
        "replacement-session",
        "native-security-7-13",
        7
    ));
    assert!(!locator_readonly_group(
        "host-session",
        "native-security-7-13",
        8
    ));
    assert!(!locator_readonly_group(
        "host-session",
        "native-security-0-13",
        0
    ));
}

#[derive(Debug)]
struct Handle {
    backend: Option<i64>,
    group: String,
}
#[derive(Default)]
struct LocatorModel {
    handles: HashMap<String, Handle>,
    next: usize,
    realm_created: bool,
    realm_destroyed: bool,
    input_count: usize,
    query_count: usize,
    expected_operation_seq: u64,
    exact_action: Option<String>,
    sent_release_acks: Vec<String>,
}
impl LocatorModel {
    fn object(&mut self, backend: Option<i64>, group: &str) -> String {
        self.next += 1;
        let object = format!("p06-object-{}", self.next);
        assert!(self
            .handles
            .insert(
                object.clone(),
                Handle {
                    backend,
                    group: group.into()
                }
            )
            .is_none());
        object
    }
    fn node(&self, object: &Value, backend: i64) {
        assert_eq!(
            self.handles.get(object.as_str().unwrap()).unwrap().backend,
            Some(backend)
        );
    }
    fn response(&mut self, request: &Value) -> Option<Value> {
        let method = request["method"].as_str().unwrap();
        let p = &request["params"];
        let result = match method {
            "Page.getLayoutMetrics" => {
                json!({"cssVisualViewport":{"clientWidth":100,"clientHeight":80,"offsetX":0,"offsetY":0,"scale":1},"cssLayoutViewport":{"clientWidth":100,"clientHeight":80}})
            }
            "Page.createIsolatedWorld" => {
                assert_eq!(
                    p,
                    &json!({"frameId":"frame-host-session","worldName":"agent-browser-native-observation"})
                );
                json!({"executionContextId":1})
            }
            "DOM.getDocument" => {
                json!({"root":{"nodeType":9,"backendNodeId":1,"children":[{"nodeType":1,"nodeName":"BUTTON","localName":"button","backendNodeId":7,"attributes":[]}]}})
            }
            "Accessibility.getFullAXTree" => {
                assert_eq!(p["frameId"], "frame-host-session");
                json!({"nodes":[{"nodeId":"purchase","backendDOMNodeId":7,"role":{"type":"role","value":"button"},"name":{"type":"string","value":"Purchase"}}]})
            }
            "DOM.resolveNode" => {
                let backend = p["backendNodeId"].as_i64().unwrap();
                assert!(matches!(backend, 1 | 7));
                assert_eq!(p["executionContextId"], 1);
                let group = p["objectGroup"].as_str().unwrap();
                assert!(
                    group == "native-exact"
                        || locator_readonly_group(
                            request["sessionId"].as_str().unwrap_or(""),
                            group,
                            self.expected_operation_seq,
                        )
                );
                let object = self.object(Some(backend), group);
                if group == "native-exact" && self.query_count == 2 {
                    self.exact_action = Some(object.clone());
                }
                json!({"object":{"type":"object","subtype":"node","objectId":object}})
            }
            "Runtime.getProperties" => {
                assert_eq!(
                    self.handles
                        .get(p["objectId"].as_str().unwrap())
                        .unwrap()
                        .backend,
                    None
                );
                json!({"result":[{"name":"focused","value":{"type":"object","subtype":"null","value":null}}]})
            }
            "DOM.getBoxModel" => {
                self.node(&p["objectId"], 7);
                json!({"model":{"border":[10,20,50,20,50,40,10,40]}})
            }
            "DOM.scrollIntoViewIfNeeded" => {
                self.node(&p["objectId"], 7);
                assert_eq!(p["objectId"].as_str(), self.exact_action.as_deref());
                json!({})
            }
            "Runtime.releaseObject" => {
                let object = p["objectId"].as_str().unwrap();
                assert!(
                    self.handles.remove(object).is_some(),
                    "unknown/repeated object release: {request}"
                );
                json!({})
            }
            "Runtime.releaseObjectGroup" => {
                let group = p["objectGroup"].as_str().unwrap();
                assert!(
                    self.handles.values().any(|handle| handle.group == group),
                    "unknown/empty group release: {request}"
                );
                self.handles.retain(|_, handle| handle.group != group);
                json!({})
            }
            "Runtime.callFunctionOn" => self.call(request),
            "Input.dispatchMouseEvent" => {
                assert_eq!(self.query_count, 2);
                let exact = self.exact_action.as_ref().unwrap();
                assert!(self.handles.contains_key(exact));
                let kind = ["mouseMoved", "mousePressed", "mouseReleased"]
                    .get(self.input_count)
                    .expect("input replay");
                assert_eq!(p["type"], *kind);
                assert_eq!(p["x"], 30.0);
                assert_eq!(p["y"], 30.0);
                assert_eq!(p["buttons"], if self.input_count == 1 { 1 } else { 0 });
                self.input_count += 1;
                json!({})
            }
            other if other.starts_with("Input.") => panic!("unexpected locator input: {request}"),
            _ => return None,
        };
        assert_eq!(request["sessionId"], "host-session");
        Some(result)
    }
    fn call(&mut self, request: &Value) -> Value {
        let p = &request["params"];
        let source = p["functionDeclaration"].as_str().unwrap();
        let object = p["objectId"].as_str().unwrap();
        assert!(
            self.handles.contains_key(object),
            "call without owned object: {request}"
        );
        if source.starts_with("function(selector,authorRoots,...roots)") && source.contains("const out=Array.from(result);out.focused=active;return out;") {
            self.node(&p["objectId"], 1);
            let group = p["objectGroup"].as_str().unwrap();
            assert!(group.starts_with("native-security-"));
            assert_eq!(self.handles.get(object).unwrap().group, group);
            let object = self.object(None, group);
            json!({"result":{"type":"object","objectId":object}})
        } else if source.starts_with("function(testId,secureSelector,...nodes)") && source.contains("const read=") {
            let args = p["arguments"].as_array().unwrap();
            assert_eq!(args.len(), 3);
            self.node(&args[2]["objectId"], 7);
            assert!(self.handles.get(object).unwrap().group.starts_with("native-metadata-"));
            assert_eq!(p["objectGroup"], self.handles.get(object).unwrap().group);
            json!({"result":{"value":[{"attributes":{},"labels":[],"states":{"secure":false,"hidden":false},"text":"Purchase","rect":{"x":10,"y":20,"width":40,"height":20},"author":{"tag":"button","nodeType":1,"visible":true}}]}})
        } else if source.starts_with("function(expression, data, labels, safeNames, secureSelector, protectedAncestors, ...elements)") {
            let args = p["arguments"].as_array().unwrap();
            let expression: crate::native::client_observation::LocatorExpression = serde_json::from_value(purchase_expression()).unwrap();
            assert_eq!(args[0]["value"], serde_json::to_value(expression).unwrap());
            assert_eq!(args.len(), 7);
            self.node(&args[6]["objectId"], 7);
            assert!(self.handles.get(object).unwrap().group.starts_with("native-query-"));
            assert_eq!(p["objectGroup"], self.handles.get(object).unwrap().group);
            self.query_count += 1;
            assert!(self.query_count <= 2, "unexpected locator retry");
            json!({"result":{"value":{"indices":[0],"redacted":[]}}})
        } else if source == "function() { const p=Node.prototype; return Object.getOwnPropertyDescriptor(p,'isConnected').get.call(this) === true && (this === document || Object.getOwnPropertyDescriptor(p,'ownerDocument').get.call(this) === document); }" {
            self.node(&p["objectId"], 7);
            json!({"result":{"value":true}})
        } else if source == "function(){\n if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};\n return true;\n}" {
            self.node(&p["objectId"], 7);
            assert_eq!(Some(object), self.exact_action.as_deref());
            assert_eq!(self.input_count, 1, "connectivity proof must follow hover and precede press");
            assert_eq!(p["arguments"], json!([]));
            assert_eq!(p["awaitPromise"], true);
            assert_eq!(p["returnByValue"], true);
            json!({"result":{"value":true}})
        } else if source == crate::native::client_geometry::BOX_PROOF {
            self.node(&p["objectId"], 7);
            json!({"result":{"value":{"connected":true,"frameOwner":false}}})
        } else if source == "function(){if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};const rect=this.getBoundingClientRect();const style=getComputedStyle(this);if(rect.width<=0||rect.height<=0||style.visibility==='hidden'||style.visibility==='collapse')return {status:'not-actionable'};return true;}" {
            assert_eq!(Some(object), self.exact_action.as_deref());
            json!({"result":{"value":true}})
        } else if source.starts_with("function(x,y,enabled){") && source.contains(crate::native::element::BLOCKER_AT_JS) && source.contains(crate::native::element::ACTIONABILITY_JS) && source.ends_with("return {width:rect.width,height:rect.height};\n    }") {
            assert_eq!(Some(object), self.exact_action.as_deref());
            assert_eq!(p["arguments"], json!([{"value":30.0},{"value":30.0},{"value":true}]));
            json!({"result":{"value":{"width":40,"height":20}}})
        } else {
            panic!("unmodeled locator function: {request}");
        }
    }
}

struct LocatorPeer {
    endpoint: String,
    commands: Arc<Mutex<Vec<Value>>>,
    model: Arc<Mutex<LocatorModel>>,
    release: mpsc::UnboundedReceiver<()>,
    close: mpsc::Sender<()>,
    relay: tokio::task::JoinHandle<()>,
    backend: tokio::task::JoinHandle<()>,
}
async fn locator_peer(hold_release: bool) -> LocatorPeer {
    let original = peer(PeerMode::Original).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let commands = Arc::new(Mutex::new(Vec::new()));
    let recorded = commands.clone();
    let model = Arc::new(Mutex::new(LocatorModel::default()));
    let modeled = model.clone();
    let (seen, release) = mpsc::unbounded_channel();
    let (close, mut closing) = mpsc::channel(1);
    let relay = tokio::spawn(async move {
        // Keep the lifecycle peer's explicit event control alive until relay exit.
        let _emit = original.emit;
        let (stream, _) = listener.accept().await.unwrap();
        let mut client = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut backend, _) = tokio_tungstenite::connect_async(&original.endpoint)
            .await
            .unwrap();
        let mut cleanup_index = None;
        let mut activated = false;
        loop {
            tokio::select! {
                Some(()) = closing.recv() => {
                    client.send(Message::Close(None)).await.unwrap();
                    let _ = backend.send(Message::Close(None)).await;
                    break;
                }
                message = backend.next() => {
                    let Some(Ok(message)) = message else { break; };
                    if let Message::Text(text) = &message {
                        let event: Value = serde_json::from_str(text).unwrap();
                        if matches!(event["method"].as_str(), Some("Runtime.executionContextDestroyed" | "Runtime.executionContextsCleared")) {
                            assert_eq!(event["sessionId"], "host-session");
                            modeled.lock().unwrap().realm_destroyed = true;
                        }
                    }
                    if client.send(message).await.is_err() { break; }
                }
                message = client.next() => {
                    let Some(Ok(Message::Text(text))) = message else {
                        let _ = backend.send(Message::Close(None)).await;
                        break;
                    };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    recorded.lock().unwrap().push(request.clone());
                    let method = request["method"].as_str().unwrap();
                    assert!(!matches!(method, "Target.createTarget" | "Target.createBrowserContext" | "Target.closeTarget" | "Target.disposeBrowserContext" | "Browser.close"));
                    if method == "Page.navigate" {
                        // PageActivation owns this sole setup navigation. No
                        // later action/recovery may navigate or replace the page.
                        assert!(!activated && !modeled.lock().unwrap().realm_created);
                        assert_eq!(request["sessionId"], "host-session");
                        assert_eq!(request["params"], json!({"url":"about:blank"}));
                        activated = true;
                    }
                    let cleanup = cleanup_index.is_some() || method == "Fetch.disable";
                    let result = if cleanup {
                        assert_eq!(modeled.lock().unwrap().input_count, 3);
                        let index = cleanup_index.get_or_insert(0);
                        let mut envelope = request.clone();
                        envelope.as_object_mut().unwrap().remove("id");
                        assert_eq!(Some(&envelope), candidate_cleanup_commands().get(*index));
                        *index += 1;
                        Some(json!({}))
                    } else { modeled.lock().unwrap().response(&request) };
                    let Some(result) = result else {
                        backend.send(Message::Text(text)).await.unwrap();
                        continue;
                    };
                    if method == "Page.createIsolatedWorld" {
                        let created = {
                            let mut model = modeled.lock().unwrap();
                            let first = !model.realm_created;
                            model.realm_created = true;
                            first
                        };
                        if created {
                            client.send(Message::Text(json!({"method":"Runtime.executionContextCreated","sessionId":"host-session","params":{"context":{"id":1,"uniqueId":"p06-locator-realm","name":"agent-browser-native-observation","auxData":{"frameId":"frame-host-session","isDefault":false}}}}).to_string())).await.unwrap();
                        }
                    }
                    if method == "Input.dispatchMouseEvent" && request["params"]["type"] == "mouseReleased" {
                        seen.send(()).unwrap();
                        if hold_release { continue; }
                    }
                    let mut response = json!({"id":request["id"],"result":result});
                    if let Some(session) = request.get("sessionId") { response["sessionId"] = session.clone(); }
                    client.send(Message::Text(response.to_string())).await.unwrap();
                    if method == "Runtime.releaseObject" {
                        modeled.lock().unwrap().sent_release_acks.push(request["params"]["objectId"].as_str().unwrap().into());
                    }
                }
            }
        }
        if let Some(index) = cleanup_index {
            assert_eq!(index, candidate_cleanup_commands().len());
        }
    });
    LocatorPeer {
        endpoint,
        commands,
        model,
        release,
        close,
        relay,
        backend: original.task,
    }
}

async fn locator_result(framed: &mut FramedFixture, sequence: u64) -> (Value, Vec<Value>) {
    bounded(async {
        let mut notices = Vec::new();
        let mut retired = false;
        for _ in 0..16 {
            let frame = framed.read().await.unwrap();
            assert_eq!(frame["generation"], 1);
            if frame["type"] == "result" {
                assert_eq!(frame["id"], "p06-locator");
                assert_eq!(frame["operationSeq"], sequence);
                return (frame, notices);
            }
            assert_eq!(frame["type"], "event", "unexpected locator frame: {frame}");
            let through = framed.event_sequence;
            framed.event_sequence += 1;
            assert_eq!(frame["sequence"], framed.event_sequence);
            if frame["event"] == "browser.disconnected" {
                assert_eq!(
                    frame["payload"],
                    json!({"reason":"browser-connection-closed"})
                );
                assert!(frame.get("decision").is_none());
            } else if frame["event"] == "scope.callbacks-retired" {
                assert!(valid_eof_callback_retirement(
                    &frame,
                    framed.scope.as_deref().unwrap(),
                    through,
                    retired
                ));
                retired = true;
            } else {
                assert_eq!(
                    frame["payload"]["identityScope"],
                    framed.scope.as_deref().unwrap()
                );
                validate_fixture_notice(&frame).unwrap_or_else(|error| panic!("{error}: {frame}"));
            }
            notices.push(frame);
        }
        panic!("missing locator result")
    })
    .await
}

async fn framed_locator_release(hold_release: bool) {
    let mut peer = locator_peer(hold_release).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut framed = FramedFixture::with_capabilities(
        broker.clone(),
        browser.clone(),
        vec![
            EXACT_OWNER_CONTINUATION.into(),
            DISCONNECTED_RECOVERY.into(),
            "terminal.close/1".into(),
        ],
    );
    framed.ready().await.unwrap();
    let opened = framed
        .command(
            "scope.open",
            json!({"source":"connect","context":"persistent","endpoint":peer.endpoint}),
            5,
        )
        .await
        .unwrap();
    let scope = opened["identityScope"].as_str().unwrap().to_owned();
    framed.scope = Some(scope.clone());
    framed
        .command("scope.configure", fixture_configuration(&scope, None), 5)
        .await
        .unwrap();
    framed
        .command("network.routes.replace", fixture_routes(&scope), 5)
        .await
        .unwrap();
    framed.registry = 1;
    framed
        .command("page.activate", json!({"identityScope":scope}), 5)
        .await
        .unwrap();
    let (client, ledger, page_state) = {
        let owner = browser.owner.lock().await;
        let owner = owner.as_ref().unwrap();
        assert!(!owner.owns_context);
        (
            owner.manager.client.clone(),
            owner.manager.client.debt_ledger().unwrap(),
            owner.page_state.clone(),
        )
    };
    peer.model.lock().unwrap().expected_operation_seq = framed.sequence + 1;
    let located = framed.command("browser.query", json!({"identityScope":scope,"expression":purchase_expression(),"testIdAttribute":"data-testid","secureFieldSelector":FIXTURE_SECURE_SELECTOR}), 5).await.unwrap();
    assert_eq!(located["nodes"].as_array().unwrap().len(), 1);
    let reference = located["nodes"][0]["ref"].clone();
    assert!(reference["id"].is_string() && reference["revision"].is_string());
    assert_eq!(peer.model.lock().unwrap().query_count, 1);
    // Query completion hands off readonly disposal; zero debt still requires
    // the real reader ACKs. This does not extend the request's original budget.
    bounded(async {
        while ledger.snapshot().object_debt != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(ledger.snapshot().object_debt, 0);
    framed.sequence += 1;
    peer.model.lock().unwrap().expected_operation_seq = framed.sequence;
    let key = OperationKey {
        generation: 1,
        operation_seq: framed.sequence,
    };
    framed.write(json!({"type":"request","id":"p06-locator","generation":1,"operationSeq":key.operation_seq,"timeoutMs":5000,"command":"browser.perform","args":{"identityScope":scope,"ref":reference,"action":{"kind":"tap"}}})).await.unwrap();
    bounded(peer.release.recv()).await.unwrap();
    // The action's exact object ACK stays held in the EOF case. Wait only for
    // independently acknowledged readonly groups from locator re-evaluation.
    if hold_release {
        bounded(async {
            while ledger.snapshot().object_debt != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await;
    }
    let exact = peer.model.lock().unwrap().exact_action.clone().unwrap();
    if hold_release {
        assert_eq!(
            browser
                .tasks
                .operation_retention_status(key)
                .mutation_dispatched(),
            Some(true)
        );
        assert_eq!(ledger.snapshot().input_debt, 1);
        assert_eq!(ledger.snapshot().object_debt, 1);
        assert!(!ledger.snapshot().integrity_lost);
        assert_eq!(page_state.mouse_state().unwrap().buttons, 0);
        assert!(!peer
            .model
            .lock()
            .unwrap()
            .sent_release_acks
            .contains(&exact));
        // The real socket is the only fault. Do not mutate debt, realm state,
        // producer registry, callback gates or broker recovery authority.
        peer.close.send(()).await.unwrap();
        bounded(peer.relay).await.unwrap();
        bounded(peer.backend).await.unwrap();
        let mut closed = client.remote_connection_closed();
        bounded(async {
            while !*closed.borrow_and_update() {
                closed.changed().await.unwrap();
            }
        })
        .await;
        let (original, notices) = locator_result(&mut framed, key.operation_seq).await;
        assert_eq!(original["ok"], false);
        assert_eq!(original["effects"], "unknown");
        assert_eq!(original["scopeState"], "quarantined");
        assert!(original.get("retention").is_none());
        // Read actual eligibility before any later timeout can expire it.
        let candidate = browser.tasks.recovery_candidate(key).is_some();
        let offered = broker.recovery_available();
        let status = browser.tasks.operation_retention_status(key);
        let eof_only_at_result = ledger.remote_eof_only();
        let producer_drain = bounded(browser.tasks.drain()).await;
        assert_eq!(ledger.snapshot().input_debt, 1);
        assert_eq!(ledger.snapshot().object_debt, 1);
        assert!(ledger.snapshot().integrity_lost);
        assert_eq!(page_state.mouse_state().unwrap().buttons, 0);
        {
            let model = peer.model.lock().unwrap();
            assert_eq!(model.query_count, 2);
            assert!(model.realm_created && !model.realm_destroyed);
            assert_eq!(model.input_count, 3);
            assert_eq!(model.handles.len(), 1);
            assert!(model.handles.contains_key(&exact));
            assert!(!model.sent_release_acks.contains(&exact));
        }
        {
            let commands = peer.commands.lock().unwrap();
            assert_eq!(
                commands
                    .iter()
                    .filter(|r| r["method"] == "Input.dispatchMouseEvent")
                    .count(),
                3
            );
            assert!(!commands.iter().any(
                |r| r["method"] == "Runtime.releaseObject" && r["params"]["objectId"] == exact
            ));
        }
        // EOF is not realm destruction, a release ACK or cleanup success.
        let cleanup = tokio::time::timeout(Duration::from_secs(7), framed.finish())
            .await
            .unwrap();
        eprintln!("P06 locator EOF: status={status:?}, candidate={candidate}, offered={offered}, eof_only_at_result={eof_only_at_result}, disconnected_before_result={}, producer_drain={producer_drain:?}, cleanup={cleanup:?}, original={original}", notices.iter().filter(|n| n["event"] == "browser.disconnected").count());
        assert_eq!(original["recovery"], json!({"version":1,"identityScope":scope}), "real locator EOF did not offer explicit recovery; status={status:?}, candidate={candidate}, offered={offered}");
    } else {
        let (result, _) = locator_result(&mut framed, key.operation_seq).await;
        assert_eq!(result["ok"], true, "locator control failed: {result}");
        assert_eq!(result["effects"], "completed");
        assert_eq!(result["scopeState"], "usable");
        bounded(async {
            while ledger.snapshot().object_debt != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert_eq!(ledger.snapshot().input_debt, 0);
        assert_eq!(ledger.snapshot().object_debt, 0);
        assert!(!ledger.snapshot().integrity_lost);
        assert!(peer
            .model
            .lock()
            .unwrap()
            .sent_release_acks
            .contains(&exact));
        assert!(peer.model.lock().unwrap().handles.is_empty());
        tokio::time::timeout(Duration::from_secs(7), framed.finish())
            .await
            .unwrap()
            .unwrap();
        bounded(peer.relay).await.unwrap();
        bounded(peer.backend).await.unwrap();
    }
}

#[tokio::test]
async fn p06_framed_locator_tap_control_releases_exact_object() {
    framed_locator_release(false).await;
}
#[tokio::test]
async fn p06_framed_locator_release_eof_must_offer_recovery_without_replay() {
    framed_locator_release(true).await;
}
