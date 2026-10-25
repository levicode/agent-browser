//! Exercise the public state capture path through production lifecycle admission.
//! Included as a child of client_browser; diagnostics remain test-only.
use super::super::client_actions::{
    fixture_configuration, fixture_routes, fixture_scope_open, FixtureOperations,
    FIXTURE_SECURE_SELECTOR,
};
use super::super::client_protocol::{
    ClientMessage, Decision, DecisionNotice, Effects, ScopeState, PROTOCOL,
};
use super::super::client_session::{
    CancelSignal, ClientSession, DecisionKind, DecisionOutcome, DecisionOwner, OperationLease,
};
use super::super::client_transport::{
    read_frame, serve_with_executor, ClientEventSink, ClientExecutor, NativeOutcome,
};
use super::*;
use base64::Engine;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct StagedFixture {
    broker: Arc<ClientSession>,
    sink: ClientEventSink,
    staged: Mutex<Option<ClientEventSink>>,
    fail: bool,
    uncertain: bool,
}
impl ClientExecutor for StagedFixture {
    fn capabilities(&self) -> Vec<String> {
        Vec::new()
    }
    async fn execute(
        &self,
        command: String,
        _args: serde_json::Map<String, Value>,
        lease: OperationLease,
    ) -> NativeOutcome {
        assert!(self.broker.start(lease.generation, lease.sequence).unwrap());
        if command == "synthetic.noop" {
            return NativeOutcome {
                retention: None,
                result: Ok(Value::Null),
                effects: Effects::Completed,
            };
        }
        let staged = self
            .sink
            .stage_until_result(&lease, "synthetic-scope")
            .unwrap();
        assert_eq!(staged.is_publication_pending(), Ok(true));
        *self.staged.lock().unwrap() = Some(staged);
        NativeOutcome {
            retention: None,
            result: if self.fail {
                Err(ProtocolError::InvalidArguments)
            } else {
                Ok(json!({"identityScope":"synthetic-scope"}))
            },
            effects: if self.uncertain {
                Effects::Unknown
            } else if self.fail {
                Effects::NotDispatched
            } else {
                Effects::Completed
            },
        }
    }
    async fn shutdown(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

#[tokio::test]
async fn fixture_written_ack_opens_only_its_successfully_settled_publication() {
    for (written, fail, uncertain) in [
        (false, false, false),
        (true, false, false),
        (true, true, false),
        (true, false, true),
    ] {
        let broker = Arc::new(ClientSession::new());
        let (sink, _events) = ClientEventSink::test_channel(broker.clone());
        let fixture = StagedFixture {
            broker: broker.clone(),
            sink: sink.clone(),
            staged: Mutex::new(None),
            fail,
            uncertain,
        };
        let mut ops = FixtureOperations::new(broker.clone());
        // The staged operation is sequence two, so a hard-coded first ACK
        // cannot make this preflight pass.
        ops.execute_written(&fixture, &sink, "synthetic.noop", json!({}), 1)
            .await
            .unwrap();
        let outcome = if written {
            ops.execute_written(&fixture, &sink, "synthetic.stage", json!({}), 1)
                .await
                .unwrap()
        } else {
            ops.execute(&fixture, "synthetic.stage", json!({}), 1)
                .await
                .unwrap()
        };
        assert_eq!(outcome.result.is_err(), fail);
        assert_eq!(
            broker.health().unwrap().1,
            if uncertain {
                ScopeState::Quarantined
            } else {
                ScopeState::Usable
            }
        );
        let staged = fixture.staged.lock().unwrap().take().unwrap();
        if !written {
            assert_eq!(staged.is_publication_pending(), Ok(true));
        } else if fail || uncertain {
            assert!(
                staged.is_publication_pending().is_err(),
                "failed or quarantined operation published callbacks"
            );
        } else {
            assert_eq!(staged.is_publication_pending(), Ok(false));
            let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            staged
                .wait_publication(Instant::now() + Duration::from_millis(100), cancellation)
                .await
                .unwrap();
        }
    }
}

/// Minimal fixture adapter for NativeSurface's no-listener, empty-route policy.
/// It uses the production framed reader, decision bridge and result writer, not
/// direct broker resolution or a manually acknowledged event sink. The fixture
/// configures no custom headers, auth, dialogs, downloads or route handlers.
struct FramedFixture {
    stream: tokio::io::BufReader<tokio::io::DuplexStream>,
    server: tokio::task::JoinHandle<bool>,
    sequence: u64,
    event_sequence: u64,
    scope: Option<String>,
    registry: u64,
    decisions: usize,
}
impl FramedFixture {
    fn new<E: ClientExecutor>(broker: Arc<ClientSession>, executor: Arc<E>) -> Self {
        Self::with_capabilities(broker, executor, Vec::new())
    }
    fn with_capabilities<E: ClientExecutor>(
        broker: Arc<ClientSession>,
        executor: Arc<E>,
        required_capabilities: Vec<String>,
    ) -> Self {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(server);
        let server = tokio::spawn(serve_with_executor(
            tokio::io::BufReader::new(reader),
            writer,
            ClientMessage::Hello {
                id: "fixture-hello".into(),
                protocol: PROTOCOL.into(),
                required_capabilities,
            },
            broker,
            executor,
        ));
        Self {
            stream: tokio::io::BufReader::new(client),
            server,
            sequence: 0,
            event_sequence: 0,
            scope: None,
            registry: 0,
            decisions: 0,
        }
    }
    async fn read(&mut self) -> Result<Value, String> {
        let bytes = read_frame(&mut self.stream)
            .await
            .map_err(|_| "framed fixture read failed")?
            .ok_or("framed fixture ended before its correlated result")?;
        serde_json::from_slice(&bytes).map_err(|_| "framed fixture received invalid JSON".into())
    }
    async fn write(&mut self, frame: Value) -> Result<(), String> {
        let mut bytes = serde_json::to_vec(&frame).map_err(|_| "fixture serialization failed")?;
        bytes.push(b'\n');
        self.stream
            .get_mut()
            .write_all(&bytes)
            .await
            .map_err(|_| "fixture write failed")?;
        self.stream
            .get_mut()
            .flush()
            .await
            .map_err(|_| "fixture flush failed".into())
    }
    async fn ready(&mut self) -> Result<(), String> {
        let ready = tokio::time::timeout(Duration::from_secs(2), self.read())
            .await
            .map_err(|_| "fixture hello timed out")??;
        if ready["type"] != "ready"
            || ready["id"] != "fixture-hello"
            || ready["protocol"] != PROTOCOL
            || ready["generation"] != 1
            || ready["scopeState"] != "usable"
        {
            return Err("fixture hello was not accepted".into());
        }
        Ok(())
    }
    async fn command(&mut self, name: &str, args: Value, seconds: u64) -> Result<Value, String> {
        tokio::time::timeout(
            Duration::from_secs(seconds + 2),
            self.command_inner(name, args, seconds),
        )
        .await
        .map_err(|_| format!("{name}: framed fixture timed out"))?
    }
    async fn command_inner(
        &mut self,
        name: &str,
        args: Value,
        seconds: u64,
    ) -> Result<Value, String> {
        self.sequence += 1;
        let id = format!("fixture-operation-{}", self.sequence);
        self.write(
            json!({"type":"request","id":id,"generation":1,"operationSeq":self.sequence,
            "timeoutMs":seconds * 1000,"command":name,"args":args}),
        )
        .await?;
        let mut controls = std::collections::HashSet::new();
        let mut result = None;
        // Bound the fixture's event/control work as well as every wire frame.
        for _ in 0..256 {
            let frame = self.read().await?;
            if frame["generation"] != 1 {
                return Err("fixture received a wrong-generation frame".into());
            }
            match frame["type"].as_str() {
                Some("event") => {
                    let sequence = frame["sequence"].as_u64().ok_or("event omitted sequence")?;
                    if sequence != self.event_sequence + 1 {
                        return Err("fixture event ordering changed".into());
                    }
                    self.event_sequence = sequence;
                    let scope = self
                        .scope
                        .as_deref()
                        .ok_or("event arrived before scope publication")?;
                    if frame["payload"]["identityScope"] != scope {
                        return Err("fixture event scope changed".into());
                    }
                    match frame["event"].as_str() {
                        Some("network.request") => {
                            let decision = empty_route_decision(&frame, scope, self.registry)?;
                            let control_id = format!("fixture-decision-{sequence}");
                            controls.insert(control_id.clone());
                            self.write(json!({"type":"decision","id":control_id,"generation":1,
                                "token":frame["decision"]["token"],"decision":decision}))
                                .await?;
                        }
                        Some("app.log" | "app.navigation" | "registry-released") => {
                            validate_fixture_notice(&frame)?;
                        }
                        _ => return Err("fixture received an unsupported application event".into()),
                    }
                }
                Some("control-result") => {
                    let control_id = frame["id"].as_str().ok_or("control result omitted ID")?;
                    if !controls.remove(control_id)
                        || frame["accepted"] != true
                        || frame["scopeState"] != "usable"
                    {
                        return Err(
                            "fixture decision was not accepted by the production bridge".into()
                        );
                    }
                    self.decisions += 1;
                }
                Some("result") => {
                    if result.is_some()
                        || frame["id"] != id
                        || frame["operationSeq"] != self.sequence
                        || frame["scopeState"] != "usable"
                    {
                        return Err("fixture operation correlation or health failed".into());
                    }
                    if frame["ok"] != true {
                        return Err(format!(
                            "{name}: native error {}",
                            frame["error"]["code"].as_str().unwrap_or("missing-code")
                        ));
                    }
                    if frame["effects"] != "completed" || frame.get("error").is_some() {
                        return Err("fixture result did not prove completed success".into());
                    }
                    result = Some(frame.get("data").ok_or("result omitted data")?.clone());
                }
                _ => return Err("fixture received an unexpected terminal frame".into()),
            }
            if controls.is_empty() {
                if let Some(value) = result.take() {
                    return Ok(value);
                }
            }
        }
        Err("fixture event/control bound exceeded".into())
    }
    async fn finish(self) -> Result<(), String> {
        // EOF invokes production cancellation, joins all operations and calls
        // executor.shutdown. Always await that retained owner, even on failure.
        drop(self.stream);
        match self.server.await {
            Ok(true) => Ok(()),
            _ => Err("framed fixture native cleanup was not proven".into()),
        }
    }
}

fn validate_fixture_notice(frame: &Value) -> Result<(), String> {
    let payload = &frame["payload"];
    let valid = frame.get("decision").is_none()
        && match frame["event"].as_str() {
            Some("app.log") => {
                matches!(
                    payload["source"].as_str(),
                    Some("console" | "error" | "network" | "system")
                ) && matches!(
                    payload["level"].as_str(),
                    Some("error" | "warning" | "info")
                ) && payload["text"].is_string()
            }
            Some("app.navigation") => {
                matches!(
                    payload["kind"].as_str(),
                    Some("main" | "popup" | "popup-navigation" | "frame")
                ) && payload["url"].is_string()
                    && payload.get("frameName").is_none_or(Value::is_string)
            }
            Some("registry-released") => payload["registryVersion"]
                .as_u64()
                .is_some_and(|version| version > 0),
            _ => false,
        };
    if valid {
        Ok(())
    } else {
        Err("fixture received an invalid application notice".into())
    }
}

fn empty_route_decision(frame: &Value, scope: &str, registry: u64) -> Result<Value, String> {
    let payload = &frame["payload"];
    let request = &payload["request"];
    let valid = frame["type"] == "event"
        && frame["event"] == "network.request"
        && frame["generation"] == 1
        && payload["identityScope"] == scope
        && registry != 0
        && payload["version"] == registry
        && payload["registrationIds"]
            .as_array()
            .is_some_and(Vec::is_empty)
        && frame["decision"]["token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
        && frame["decision"]["timeoutMs"]
            .as_u64()
            .is_some_and(|ms| ms > 0)
        && request["url"].is_string()
        && request["method"].is_string()
        && request["headers"]
            .as_object()
            .is_some_and(|headers| headers.values().all(Value::is_string));
    if !valid {
        return Err("fixture refused a malformed or mismatched empty-route request".into());
    }
    // NativeSurface.dispatchEvent uses exactly this default when registrationIds
    // is empty and siteHeadersFor returns undefined (no configured headers).
    Ok(json!({"kind":"continue","overrides":{}}))
}

struct RequestFixture {
    broker: Arc<ClientSession>,
    sink: Mutex<Option<ClientEventSink>>,
    prepared: std::sync::atomic::AtomicUsize,
    accepted: std::sync::atomic::AtomicUsize,
    refuse: bool,
}
impl ClientExecutor for RequestFixture {
    fn capabilities(&self) -> Vec<String> {
        Vec::new()
    }
    fn set_event_sink(&self, sink: ClientEventSink) -> Result<(), ProtocolError> {
        *self.sink.lock().unwrap() = Some(sink);
        Ok(())
    }
    fn prepare_decision(&self, _: u64, _: &str, decision: &Decision) -> Result<(), ProtocolError> {
        self.prepared
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            *decision,
            Decision::Continue {
                overrides: Default::default()
            }
        );
        if self.refuse {
            Err(ProtocolError::PolicyDenied)
        } else {
            Ok(())
        }
    }
    fn finish_decision(&self, _: &str, accepted: bool) -> Result<(), ProtocolError> {
        if accepted {
            self.accepted
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }
    async fn execute(
        &self,
        _: String,
        _: serde_json::Map<String, Value>,
        operation: OperationLease,
    ) -> NativeOutcome {
        let result = async {
            assert!(self
                .broker
                .start(operation.generation, operation.sequence)?);
            // Real navigation can interleave non-decision application notices.
            // The same framed fixture must consume these without dropping the
            // pending request or mistaking a notice for its terminal result.
            let sink = self.sink.lock().unwrap().as_ref().unwrap().clone();
            sink.emit(
                "app.navigation".into(),
                json!({"identityScope":"synthetic-scope","kind":"main",
                "url":"http://127.0.0.1/synthetic","initiatedByOperation":true}),
                None,
            )?;
            sink.emit(
                "app.log".into(),
                json!({"identityScope":"synthetic-scope","source":"console",
                "level":"info","text":"synthetic fixture notice"}),
                None,
            )?;
            let lease = self.broker.decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                1000,
                Some(1),
                Some("synthetic-scope".into()),
            )?;
            self.sink.lock().unwrap().as_ref().unwrap().emit(
                "network.request".into(),
                json!({"identityScope":"synthetic-scope","version":1,"registrationIds":[],
                    "request":{"url":"http://127.0.0.1/synthetic","method":"GET","headers":{}}}),
                Some(DecisionNotice {
                    token: lease.token,
                    timeout_ms: 1000,
                }),
            )?;
            match lease
                .outcome
                .await
                .map_err(|_| ProtocolError::BrowserFailure)?
            {
                DecisionOutcome::Selected(Decision::Continue { overrides })
                    if overrides == super::super::client_protocol::RequestOverrides::default() =>
                {
                    Ok(Value::Null)
                }
                _ => Err(ProtocolError::BrowserFailure),
            }
        }
        .await;
        NativeOutcome {
            retention: None,
            result,
            effects: Effects::Completed,
        }
    }
    async fn shutdown(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

#[tokio::test]
async fn framed_empty_route_request_uses_independent_production_decision_bridge() {
    for refuse in [false, true] {
        let broker = Arc::new(ClientSession::new());
        broker
            .register_routes_scoped(1, 1, vec![], Some("synthetic-scope".into()))
            .unwrap();
        let executor = Arc::new(RequestFixture {
            broker: broker.clone(),
            sink: Mutex::new(None),
            prepared: Default::default(),
            accepted: Default::default(),
            refuse,
        });
        let mut fixture = FramedFixture::new(broker, executor.clone());
        let result = async {
            fixture.ready().await?;
            fixture.scope = Some("synthetic-scope".into());
            fixture.registry = 1;
            fixture
                .command("synthetic.paused-request", json!({}), 2)
                .await
        }
        .await;
        let decisions = fixture.decisions;
        let events = fixture.event_sequence;
        let cleanup = fixture.finish().await;
        cleanup.unwrap();
        assert_eq!(result.is_err(), refuse);
        if refuse {
            assert_eq!(
                result.unwrap_err(),
                "fixture decision was not accepted by the production bridge"
            );
        } else {
            assert_eq!(result.unwrap(), Value::Null);
        }
        assert_eq!(events, 3);
        assert_eq!(
            executor.prepared.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            executor.accepted.load(std::sync::atomic::Ordering::SeqCst),
            usize::from(!refuse)
        );
        assert_eq!(decisions, usize::from(!refuse));
    }
}

#[test]
fn framed_empty_route_policy_rejects_mismatched_or_missing_authority() {
    let valid = json!({"type":"event","event":"network.request","generation":1,
        "payload":{"identityScope":"synthetic-scope","version":1,"registrationIds":[],
            "request":{"url":"http://127.0.0.1/synthetic","method":"GET","headers":{}}},
        "decision":{"token":"synthetic-token","timeoutMs":1000}});
    assert_eq!(
        empty_route_decision(&valid, "synthetic-scope", 1).unwrap(),
        json!({"kind":"continue","overrides":{}})
    );
    for pointer in [
        "/generation",
        "/payload/identityScope",
        "/payload/version",
        "/payload/registrationIds",
        "/decision",
        "/decision/token",
        "/decision/timeoutMs",
        "/payload/request/headers",
    ] {
        let mut invalid = valid.clone();
        *invalid.pointer_mut(pointer).unwrap() = Value::Null;
        assert!(
            empty_route_decision(&invalid, "synthetic-scope", 1).is_err(),
            "accepted invalid authority field"
        );
    }
    let mut registered = valid.clone();
    registered["payload"]["registrationIds"] = json!(["synthetic-route"]);
    assert!(empty_route_decision(&registered, "synthetic-scope", 1).is_err());
    assert!(empty_route_decision(&valid, "other-scope", 1).is_err());
    assert!(empty_route_decision(&valid, "synthetic-scope", 2).is_err());
}

#[tokio::test]
#[ignore = "requires hosted Chromium: public lifecycle state capture after HTTP navigation and query"]
async fn chromium_public_state_capture_after_navigation_and_query() {
    let mut host = super::super::browser::BrowserManager::launch(Default::default(), None)
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let http = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 8192];
            if !matches!(tokio::time::timeout(Duration::from_secs(2), socket.read(&mut request)).await, Ok(Ok(count)) if count > 0)
            {
                continue;
            }
            let body = r#"<!doctype html><html><head><title>Fixture State</title></head><body><h1 id="token">none</h1><script>
const params = new URLSearchParams(location.search);
if (params.has('set')) localStorage.setItem('token', params.get('set'));
document.getElementById('token').textContent = localStorage.getItem('token') ?? 'none';
</script></body></html>"#;
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                socket.write_all(response.as_bytes()),
            )
            .await;
        }
    });
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture = FramedFixture::new(broker, browser);
    let result: Result<(), String> = async {
        fixture.ready().await?;
        let opened = fixture.command("scope.open",
            fixture_scope_open("connect",Some(host.get_cdp_url())),30).await?;
        let scope = opened["identityScope"].as_str().ok_or("open omitted scope")?.to_owned();
        fixture.scope = Some(scope.clone());
        fixture.command("scope.configure", fixture_configuration(&scope,Some("127.0.0.1")),30).await?;
        fixture.command("network.routes.replace",
            fixture_routes(&scope),30).await?;
        fixture.registry = 1;
        fixture.command("page.activate", json!({"identityScope":scope}),30).await?;
        fixture.command("page.navigate",
            json!({"identityScope":scope,"url":format!("{origin}/state?set=abc"),"waitUntil":"load"}),30).await?;
        let query = fixture.command("browser.query", json!({
            "identityScope":scope,"expression":{"kind":"query","query":{"kind":"role","value":{"kind":"string","value":"heading","exact":true}}},
            "testIdAttribute":"data-testid","secureFieldSelector":FIXTURE_SECURE_SELECTOR
        }),30).await?;
        let nodes = query["nodes"].as_array().ok_or("query omitted nodes")?;
        if nodes.len() != 1 || nodes[0]["name"] != "abc" { return Err("synthetic storage heading was not located before capture".into()); }
        let captured = fixture.command("state.capture", json!({"identityScope":scope}),30).await?;
        if captured["identityScope"] != scope || captured["format"] != "agent-browser-storage-state" || captured["version"] != 1 {
            return Err("capture envelope did not match its admitted scope/format/version".into());
        }
        let handle = captured["handle"].as_str().ok_or("capture omitted handle")?;
        let read = fixture.command("blob.read", json!({"identityScope":scope,"handle":handle,"offset":0,"maxBytes":262144}),30).await;
        let released = fixture.command("blob.release", json!({"identityScope":scope,"handle":handle}),30).await;
        let read = read?;
        released?;
        if read["eof"] != true { return Err("synthetic state exceeded one bounded blob chunk".into()); }
        let bytes = base64::engine::general_purpose::STANDARD.decode(read["base64"].as_str().ok_or("state read omitted bytes")?).map_err(|_|"state read was not base64")?;
        if captured["size"].as_u64() != Some(bytes.len() as u64) || read["nextOffset"].as_u64() != Some(bytes.len() as u64) {
            return Err("state blob size did not match the complete read".into());
        }
        let state: Value = serde_json::from_slice(&bytes).map_err(|_|"state blob was not JSON")?;
        let origins = state["origins"].as_array().ok_or("state omitted origins")?;
        if origins.len() != 1 || origins[0]["origin"] != origin || origins[0]["localStorage"] != json!([{"name":"token","value":"abc"}]) {
            return Err("captured state did not retain exact synthetic origin/localStorage".into());
        }
        Ok(())
    }.await;
    // The actual owner settles its retained capture work before test assertions.
    let decisions = fixture.decisions;
    let cleanup = fixture.finish().await;
    let host_cleanup = host.close().await.map_err(|_| "host cleanup failed");
    http.abort();
    let _ = http.await;
    assert!(
        cleanup.is_ok() && host_cleanup.is_ok(),
        "native cleanup={cleanup:?}; host cleanup={host_cleanup:?}; state result={result:?}"
    );
    result.unwrap();
    assert!(
        decisions > 0,
        "HTTP navigation bypassed the production callback bridge"
    );
}

#[path = "client_browser_restart_transport_tests.rs"]
mod restart_transport_tests;

#[cfg(feature = "acceptance-faults")]
#[path = "client_browser_observe_trace_timeout_tests.rs"]
mod observe_trace_timeout_tests;
