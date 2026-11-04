//! Real Chromium + production ClientBrowser/transport + built SDK NativeSurface.
//! The only scheduling seam pauses initial inventory after its real revision
//! snapshot. A separate fixture CDP connection then causes real same-document
//! events; all refusal, settlement, grant and snapshot data remain production.
use super::super::client_debt::OperationKey;
use super::super::client_protocol::ClientMessage;
use super::super::client_transport::serve_with_executor;
use super::*;
use serde_json::{json, Value};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWrite};

struct WitnessWriter {
    inner: tokio::net::unix::OwnedWriteHalf,
    browser: Arc<ClientBrowser>,
    frames: Arc<Mutex<Vec<Value>>>,
    partial: Vec<u8>,
}
fn semantic_button(node: &Value) -> Option<&Value> {
    if node["role"] == "button" && node["name"] == "Activate once" {
        return Some(node);
    }
    node["children"]
        .as_array()?
        .iter()
        .find_map(semantic_button)
}
impl WitnessWriter {
    fn record(&mut self, bytes: &[u8]) {
        self.partial.extend_from_slice(bytes);
        while let Some(end) = self.partial.iter().position(|byte| *byte == b'\n') {
            let line: Vec<_> = self.partial.drain(..=end).collect();
            let frame: Value = serde_json::from_slice(&line).unwrap();
            let refs = self.browser.refs.lock().unwrap();
            let mut evidence = json!({"frame":frame,"nativeRefCount":refs.ref_ids().len()});
            if frame.get("observeContinuation").is_some() {
                let key = OperationKey {
                    generation: frame["generation"].as_u64().unwrap(),
                    operation_seq: frame["operationSeq"].as_u64().unwrap(),
                };
                assert!(self.browser.broker.observation_operation_settled(key));
                assert!(
                    refs.ref_ids().is_empty(),
                    "failed original capture published refs"
                );
                let owner = self.browser.owner.try_lock().unwrap();
                let ledger = owner
                    .as_ref()
                    .unwrap()
                    .manager
                    .client
                    .debt_ledger()
                    .unwrap();
                let debt = ledger.snapshot();
                assert!(!debt.integrity_lost);
                assert_eq!(
                    (debt.input_debt, debt.object_debt, debt.outstanding_commands),
                    (0, 0, 0)
                );
                assert_eq!(
                    ledger.operation_has_rejected_cleanup(key, ledger.identity_scope()),
                    Ok(false)
                );
                evidence["originalSettled"] = json!(true);
                evidence["inputDebt"] = json!(debt.input_debt);
                evidence["objectDebt"] = json!(debt.object_debt);
                evidence["outstandingCommands"] = json!(debt.outstanding_commands);
            }
            if frame["type"] == "result" && frame["ok"] == true && frame["data"]["root"].is_object()
            {
                let revision = frame["data"]["revision"].as_str().unwrap();
                let button = semantic_button(&frame["data"]["root"])
                    .expect("actual native semantic tree must contain the button");
                let id = super::super::element::parse_ref(button["ref"]["id"].as_str().unwrap())
                    .unwrap();
                let entry = refs
                    .get(&id)
                    .expect("actual semantic button ref must be published in native map");
                assert!(entry.backend_node_id.is_some());
                assert!(entry.exact_binding.is_some());
                assert_eq!(
                    entry.issued_revision(),
                    Some(revision.parse::<u64>().unwrap())
                );
                assert_eq!(
                    entry.issued_wire_revision().as_deref(),
                    button["ref"]["revision"].as_str()
                );
                evidence["publishedButtonRef"] = json!(id);
                evidence["publishedButtonWireRevision"] = button["ref"]["revision"].clone();
                evidence["publishedRevision"] = json!(revision);
            }
            self.frames.lock().unwrap().push(evidence);
        }
    }
}
impl AsyncWrite for WitnessWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // This test explicitly runs on current_thread. After accepted bytes,
        // record has no await: native cannot process the SDK's next request and
        // mutate refs before the corresponding synchronous witness is captured.
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(count)) = result {
            self.record(&bytes[..count]);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires real Chromium, built SDK and separate automatic-observation harness"]
async fn continuation_joint_browser_automatic_recovery() {
    let socket = std::env::var("OBSERVE_AUTOMATIC_SOCKET").expect("private socket path");
    let ready = std::env::var("OBSERVE_AUTOMATIC_READY").expect("private ready file");
    let evidence =
        std::env::var("OBSERVE_AUTOMATIC_NATIVE_EVIDENCE").expect("private evidence file");
    let executable =
        std::env::var("OBSERVE_AUTOMATIC_CHROME").expect("explicit real Chromium executable");
    let host = super::super::browser::BrowserManager::launch(
        super::super::cdp::chrome::LaunchOptions {
            executable_path: Some(executable),
            args: vec!["--no-sandbox".into()],
            ..Default::default()
        },
        None,
    )
    .await
    .expect("launch real fixture Chromium");
    let broker = Arc::new(super::super::client_session::ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let (probe, mut samples) = tokio::sync::mpsc::unbounded_channel();
    browser
        .observation
        .set_initial_inventory_probe_for_test(probe);
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::write(&ready, json!({"endpoint":host.get_cdp_url()}).to_string()).unwrap();
    let controller = {
        let browser = browser.clone();
        tokio::spawn(async move {
            let mut sequence = None;
            let mut control_session = None;
            let mut selected_target = None;
            let mut records = Vec::new();
            for index in 1..=3 {
                let sample = tokio::time::timeout(Duration::from_secs(35), samples.recv())
                    .await
                    .unwrap()
                    .expect("initial inventory checkpoint");
                let page = browser.page_lease(false).await.unwrap();
                let selected = page.targets.owned_target(&page.target_id).unwrap();
                assert!(browser.refs.lock().unwrap().ref_ids().is_empty());
                let debt = page.client.debt_ledger().unwrap().snapshot();
                assert!(!debt.integrity_lost);
                assert_eq!(
                    (debt.input_debt, debt.object_debt, debt.outstanding_commands),
                    (0, 0, 0)
                );
                let original = *sequence.get_or_insert(sample.operation_seq);
                assert_eq!(page.targets.inventory().unwrap().0, sample.revision);
                if control_session.is_none() {
                    // The legacy BrowserManager's initial tab need not be
                    // the Page selected by persistent native/PW startup.
                    // Attach the fixture control to this actual native lease.
                    let attached = tokio::time::timeout(
                        Duration::from_secs(5),
                        host.client.send_command(
                            "Target.attachToTarget",
                            Some(json!({"targetId":page.target_id,"flatten":true})),
                            None,
                        ),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    selected_target = Some(page.target_id.clone());
                    control_session = Some(attached["sessionId"].as_str().unwrap().to_owned());
                }
                assert_eq!(selected_target.as_ref(), Some(&page.target_id));
                let control = control_session.as_ref().unwrap();
                let observed_revision = if index <= 2 {
                    assert_eq!(sample.operation_seq, original);
                    let response = tokio::time::timeout(Duration::from_secs(5), host.client.send_command("Runtime.evaluate", Some(json!({"expression":format!("history.replaceState(null, '', '?inventory={index}'); location.href"),"returnByValue":true})), Some(control))).await.unwrap().unwrap();
                    assert!(
                        response.get("exceptionDetails").is_none(),
                        "fixture must mutate the actual selected Page"
                    );
                    assert!(response["result"]["value"]
                        .as_str()
                        .unwrap()
                        .ends_with(&format!("?inventory={index}")));
                    tokio::time::timeout(Duration::from_secs(5), async {
                        loop {
                            let changed = page.targets.changed();
                            tokio::pin!(changed);
                            changed.as_mut().enable();
                            if let Ok((revision, _)) = page.targets.inventory() {
                                if revision > sample.revision {
                                    break revision;
                                }
                            }
                            changed.await;
                        }
                    })
                    .await
                    .expect("real Chromium event must advance native inventory")
                } else {
                    assert!(sample.operation_seq > original);
                    sample.revision
                };
                assert!(
                    selected.same_attachment(&page.targets.owned_target(&page.target_id).unwrap())
                );
                records.push(json!({"sample":index,"operationSeq":sample.operation_seq,"capturedRevision":sample.revision,"observedRevision":observed_revision,"realHistoryEvent":index<=2,"controlTargetIsActualSelectedPage":true,"nativeRefs":0,"inputDebt":0,"objectDebt":0,"outstandingCommands":0,"sameAttachment":true}));
                drop(page);
                sample.resume.send(()).unwrap();
            }
            (host, control_session.unwrap(), records)
        })
    };
    let (stream, _) = tokio::time::timeout(Duration::from_secs(30), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let (read, write) = stream.into_split();
    let mut read = tokio::io::BufReader::new(read);
    let mut hello = String::new();
    read.read_line(&mut hello).await.unwrap();
    let hello: ClientMessage = serde_json::from_str(&hello).unwrap();
    let frames = Arc::new(Mutex::new(Vec::new()));
    let write = WitnessWriter {
        inner: write,
        browser: browser.clone(),
        frames: frames.clone(),
        partial: Vec::new(),
    };
    let served = tokio::time::timeout(
        Duration::from_secs(55),
        serve_with_executor(read, write, hello, broker, browser.clone()),
    )
    .await;
    let (mut returned_host, control_session, records) = controller.await.unwrap();
    let captured = frames.lock().unwrap().clone();
    std::fs::write(
        &evidence,
        serde_json::to_vec_pretty(&json!({"samples":records,"serverFrames":captured})).unwrap(),
    )
    .unwrap();
    assert!(served.unwrap());
    assert_eq!(
        captured
            .iter()
            .filter(|row| row["frame"].get("observeContinuation").is_some())
            .count(),
        1
    );
    let complete: Vec<_> = captured
        .iter()
        .filter(|row| row.get("publishedButtonRef").is_some())
        .collect();
    assert_eq!(
        complete.len(),
        1,
        "exactly one complete semantic/ref publication"
    );
    assert!(complete[0]["nativeRefCount"].as_u64().unwrap() >= 3);
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        returned_host.client.send_command(
            "Runtime.evaluate",
            Some(json!({"expression":"globalThis.clickCount","returnByValue":true})),
            Some(&control_session),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.get("exceptionDetails").is_none());
    assert_eq!(response["result"]["value"], json!(1));
    returned_host.close().await.unwrap();
    std::fs::remove_file(socket).unwrap();
    println!("JOINT_BROWSER_AUTOMATIC_RECOVERY chromium=real executor=ClientBrowser sdk=NativeSurface initial_samples=2 grants=1 continued_samples=1 semantic_ref_publications=1 explicit_actions=1 action_replays=0");
}
