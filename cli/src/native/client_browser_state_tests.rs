//! Exercise the public state capture path through production lifecycle admission.
//! Included as a child of client_browser; diagnostics remain test-only.
use super::super::client_actions::{
    fixture_configuration, fixture_routes, fixture_scope_open, FixtureOperations,
    FIXTURE_SECURE_SELECTOR,
};
use super::super::client_protocol::{Effects, ScopeState};
use super::super::client_session::{CancelSignal, ClientSession, OperationLease};
use super::super::client_transport::{ClientEventSink, ClientExecutor, NativeOutcome};
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

async fn command(
    browser: &ClientBrowser,
    ops: &mut FixtureOperations,
    sink: &ClientEventSink,
    name: &str,
    args: Value,
) -> Result<Value, String> {
    ops.execute_written(browser, sink, name, args, 30)
        .await
        .map_err(|error| format!("{name} admission/settlement/writer: {error:?}"))?
        .result
        .map_err(|error| format!("{name}: {error:?}"))
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
    let browser = ClientBrowser::new(Arc::new(ClientSession::new()));
    let (sink, _events) = ClientEventSink::test_channel(browser.broker.clone());
    browser.set_event_sink(sink.clone()).unwrap();
    let mut ops = FixtureOperations::new(browser.broker.clone());
    let result: Result<(), String> = async {
        let opened = command(&browser, &mut ops, &sink, "scope.open",
            fixture_scope_open("connect",Some(host.get_cdp_url()))).await?;
        let scope = opened["identityScope"].as_str().ok_or("open omitted scope")?.to_owned();
        command(&browser, &mut ops, &sink, "scope.configure", fixture_configuration(&scope,Some("127.0.0.1"))).await?;
        command(&browser, &mut ops, &sink, "network.routes.replace",
            fixture_routes(&scope)).await?;
        command(&browser, &mut ops, &sink, "page.activate", json!({"identityScope":scope})).await?;
        command(&browser, &mut ops, &sink, "page.navigate",
            json!({"identityScope":scope,"url":format!("{origin}/state?set=abc"),"waitUntil":"load"})).await?;
        let query = command(&browser, &mut ops, &sink, "browser.query", json!({
            "identityScope":scope,"expression":{"kind":"query","query":{"kind":"role","value":{"kind":"string","value":"heading","exact":true}}},
            "testIdAttribute":"data-testid","secureFieldSelector":FIXTURE_SECURE_SELECTOR
        })).await?;
        let nodes = query["nodes"].as_array().ok_or("query omitted nodes")?;
        if nodes.len() != 1 || nodes[0]["name"] != "abc" { return Err("synthetic storage heading was not located before capture".into()); }
        let captured = command(&browser, &mut ops, &sink, "state.capture", json!({"identityScope":scope})).await?;
        if captured["identityScope"] != scope || captured["format"] != "agent-browser-storage-state" || captured["version"] != 1 {
            return Err("capture envelope did not match its admitted scope/format/version".into());
        }
        let handle = captured["handle"].as_str().ok_or("capture omitted handle")?;
        let read = command(&browser, &mut ops, &sink, "blob.read", json!({"identityScope":scope,"handle":handle,"offset":0,"maxBytes":262144})).await;
        let released = command(&browser, &mut ops, &sink, "blob.release", json!({"identityScope":scope,"handle":handle})).await;
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
    let cleanup = browser.shutdown().await;
    let host_cleanup = host.close().await;
    http.abort();
    let _ = http.await;
    result.unwrap();
    cleanup.unwrap();
    host_cleanup.unwrap();
}
