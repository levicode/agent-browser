//! Managed borrowed-owner terminal cleanup. Source-only; central CI executes.
use super::*;
use crate::native::client_debt::AdmissionClass;
use crate::native::client_protocol::{Effects, ScopeState, ServerMessage};
use crate::native::client_session::{CancelSignal, ClientSession, OperationLease};
use crate::native::client_transport::{ClientEventSink, ClientExecutor};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

async fn final_local_peer() -> (
    String,
    Arc<Mutex<Vec<Value>>>,
    tokio::sync::mpsc::Sender<Message>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let recorded = log.clone();
    let (emit, mut emitted) = tokio::sync::mpsc::channel(32);
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let target = json!({"targetId":"host-page","type":"page",
            "browserContextId":"host-context","url":"about:blank","title":""});
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
                    let session = request["sessionId"].as_str().unwrap_or("");
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
                            json!({"sessionId":"host-session"})
                        }
                        "Page.getFrameTree" => json!({"frameTree":{"frame":{
                            "id":format!("frame-{session}"),"loaderId":"host-loader","url":"about:blank"}}}),
                        "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":"host-script"}),
                        "Page.enable" | "Runtime.enable" | "Network.enable" | "WebMCP.enable"
                        | "DOM.enable" | "DOM.disable" | "Network.setBypassServiceWorker"
                        | "Fetch.enable" | "Fetch.disable" | "Page.setLifecycleEventsEnabled"
                        | "Target.setDiscoverTargets" | "Target.setAutoAttach"
                        | "Runtime.runIfWaitingForDebugger" | "Page.removeScriptToEvaluateOnNewDocument"
                        | "Emulation.setEmulatedMedia" | "Target.detachFromTarget" => json!({}),
                        other => panic!("unmodeled final-local CDP method {other}: {request}"),
                    };
                    let mut response = json!({"id":request["id"],"result":result});
                    if !session.is_empty() { response["sessionId"] = session.into(); }
                    if socket.send(Message::Text(response.to_string())).await.is_err() { break; }
                }
            }
        }
    });
    (endpoint, log, emit, peer)
}

#[tokio::test]
async fn missing_borrowed_root_can_end_only_after_exact_debt_free_remote_eof() {
    for case in [
        "clean",
        "clean-child",
        "unproven-child",
        "malformed",
        "local-close",
        "registry-poison",
        "file-failure",
    ] {
        eprintln!("final-local fixture case={case}");
        let (endpoint, log, emit, peer) = final_local_peer().await;
        let broker = Arc::new(ClientSession::new());
        let browser = ClientBrowser::new(broker.clone());
        let (sink, mut notices) = ClientEventSink::test_channel(broker.clone());
        browser.set_event_sink(sink.clone()).unwrap();
        let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = |sequence| OperationLease {
            is_callback: false,
            generation: 1,
            sequence,
            deadline: Instant::now() + Duration::from_secs(10),
            cancellation: cancellation.clone(),
        };
        let opened = browser
            .open(
                OpenRequest::Connect {
                    endpoint: endpoint.clone(),
                    persistent: true,
                    options: Default::default(),
                },
                operation(1),
            )
            .await
            .unwrap();
        let scope = opened["identityScope"].as_str().unwrap().to_owned();
        // Use the real scoped result acknowledgement boundary, not an unscoped
        // fixture sink that silently skips callback retirement.
        sink.acknowledge_result_for_test(&ServerMessage::Result {
            id: "open".into(),
            generation: 1,
            operation_seq: 1,
            ok: true,
            data: Some(opened),
            error: None,
            effects: Effects::Completed,
            scope_state: ScopeState::Usable,
            retention: None,
        })
        .unwrap();
        let (client, enrollment, targets, identity, directory) = {
            let owner = browser.owner.lock().await;
            let owner = owner.as_ref().unwrap();
            assert!(!owner.owns_context);
            let runtime = owner.runtime.as_ref().unwrap();
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().to_owned();
            runtime.configuration.lock().unwrap().download_directory = Some(directory);
            (
                owner.manager.client.clone(),
                runtime.enrollment.clone(),
                owner.targets.clone(),
                owner.recovery_identity(),
                path,
            )
        };
        let ledger = client.debt_ledger().unwrap();
        assert!(enrollment.final_local_connection_proof().is_err());
        if matches!(case, "clean-child" | "unproven-child") {
            // Real received enrollment registers exact child debt. Root detach
            // recursively removes its local index, but cannot substitute for a
            // missing child's own session destruction evidence in the ledger.
            emit.send(Message::Text(
                json!({"method":"Target.attachedToTarget",
                "sessionId":"host-session","params":{"sessionId":"child-session",
                    "waitingForDebugger":true,"targetInfo":{"targetId":"child-target",
                        "type":"iframe","browserContextId":"host-context"}}})
                .to_string(),
            ))
            .await
            .unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if targets
                        .owned_target("child-target")
                        .is_ok_and(|target| target.resumed)
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            if case == "clean-child" {
                emit.send(Message::Text(
                    json!({"method":"Target.detachedFromTarget",
                    "sessionId":"host-session","params":{"sessionId":"child-session",
                        "targetId":"child-target"}})
                    .to_string(),
                ))
                .await
                .unwrap();
            }
        }
        emit.send(Message::Text(
            json!({"method":"Target.detachedFromTarget",
            "params":{"sessionId":"host-session","targetId":"host-page"}})
            .to_string(),
        ))
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if targets.owned_target("host-page").is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        if case == "malformed" {
            emit.send(Message::Text("not valid CDP JSON".into()))
                .await
                .unwrap();
        }
        if case == "registry-poison" {
            targets.seal();
        }
        if case == "local-close" {
            browser
                .owner
                .lock()
                .await
                .as_mut()
                .unwrap()
                .manager
                .close()
                .await
                .unwrap();
            // Local transport closure is not remote EOF evidence, even before
            // the fixture begins the real seal-before-drain teardown.
            assert!(!*client.remote_connection_closed().borrow(), "{case}");
            assert!(enrollment.final_local_connection_proof().is_err(), "{case}");
            enrollment.seal();
        } else {
            emit.send(Message::Close(None)).await.unwrap();
            let mut closed = client.remote_connection_closed();
            tokio::time::timeout(Duration::from_secs(2), async {
                while !*closed.borrow_and_update() {
                    closed.changed().await.unwrap();
                }
            })
            .await
            .unwrap();
        }
        if case == "file-failure" {
            std::fs::remove_dir(&directory).unwrap();
            std::fs::write(&directory, b"synthetic local cleanup obstruction").unwrap();
        }
        let drained = tokio::time::timeout(Duration::from_secs(2), enrollment.drain())
            .await
            .unwrap_or_else(|error| panic!("{case}: enrollment drain did not finish: {error}"));
        if matches!(case, "clean" | "clean-child" | "file-failure") {
            drained.unwrap();
            assert!(matches!(
                enrollment.terminal_connection_proof(),
                Err(ProtocolError::StaleScope)
            ));
            let final_only = enrollment.final_local_connection_proof().unwrap();
            final_only.check_client(&client).unwrap();
            final_only.check_targets(&targets).unwrap();
            let foreign = crate::native::client_targets::ClientTargets::new(
                "host-context".into(),
                scope.clone(),
            );
            assert_eq!(
                final_only.check_targets(&foreign),
                Err(ProtocolError::StaleScope)
            );
            // Final-local retirement cannot become a recovery proof or make old
            // application admission usable again. Refusal remains clean.
            let refused = browser
                .reconnect_scope(
                    scope.clone(),
                    ReconnectRequest {
                        endpoint: endpoint.clone(),
                        expected_browser_identity: identity["browser"].as_str().unwrap().into(),
                        expected_context_identity: identity["context"].as_str().unwrap().into(),
                        expected_page_identity: identity["page"].as_str().unwrap().into(),
                    },
                    operation(2),
                )
                .await;
            assert_eq!(refused.result, Err(ProtocolError::StaleScope));
            assert_eq!(refused.effects, Effects::NotDispatched);
            assert!(ledger.snapshot().integrity_lost);
            assert!(ledger.check_admission(AdmissionClass::Input).is_err());
        } else {
            assert!(enrollment.final_local_connection_proof().is_err());
            assert!(ledger.check_admission(AdmissionClass::Input).is_err());
        }
        let ended = browser.end_scope(scope, 0).await;
        if matches!(case, "clean" | "clean-child") {
            assert_eq!(ended, Ok(Value::Null));
            assert!(browser.owner.lock().await.is_none());
            assert!(!directory.exists());
            let mut fences = 0;
            while let Ok(notice) = notices.try_recv() {
                if matches!(notice, ServerMessage::Event { ref event, .. }
                    if event == "scope.callbacks-retired")
                {
                    fences += 1;
                }
            }
            assert_eq!(fences, 1);
        } else {
            assert!(
                ended.is_err(),
                "{case} was promoted to successful final cleanup"
            );
            assert!(browser.owner.lock().await.is_some());
        }
        assert!(
            !log.lock().unwrap().iter().any(|request| matches!(
                request["method"].as_str(),
                Some("Browser.close" | "Target.disposeBrowserContext" | "Target.closeTarget")
            )),
            "borrowed final cleanup changed host lifetime"
        );
        if case == "file-failure" {
            std::fs::remove_file(&directory).unwrap();
        }
        let _ = browser.shutdown().await;
        peer.abort();
        let _ = peer.await;
    }
}
