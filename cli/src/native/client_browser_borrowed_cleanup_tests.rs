//! Full-entry managed borrowed cleanup against a fixed synthetic CDP peer.
use super::*;
use crate::native::client_debt::AdmissionClass;
use crate::native::client_protocol::{Effects, ScopeState, ServerMessage};
use crate::native::client_session::{CancelSignal, ClientSession, OperationLease};
use crate::native::client_transport::{ClientEventSink, ClientExecutor};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

type Requests = Arc<Mutex<Vec<Value>>>;

// Adapt the small final_local_peer model. Unlike its EOF fixture, detach
// events here are caused only by real requests made by managed scope cleanup.
async fn borrowed_peer(
    event_first: bool,
    fault: &'static str,
) -> (
    String,
    Requests,
    tokio::sync::mpsc::Sender<Message>,
    tokio::sync::mpsc::UnboundedReceiver<Value>,
    Arc<AtomicBool>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let log: Requests = Arc::default();
    let recorded = log.clone();
    let (emit, mut emitted) = tokio::sync::mpsc::channel::<Message>(32);
    let (final_tx, final_rx) = tokio::sync::mpsc::unbounded_channel();
    let armed = Arc::new(AtomicBool::new(false));
    let peer_armed = armed.clone();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let host = json!({"targetId":"host-page","type":"page","browserContextId":"host-context","url":"about:blank","title":""});
        let child = json!({"targetId":"child-target","type":"iframe","browserContextId":"host-context","url":"about:blank","title":""});
        let mut child_present = false;
        loop {
            tokio::select! {
                message = emitted.recv() => {
                    let Some(message) = message else { break; };
                    if let Message::Text(text) = &message {
                        if let Ok(event) = serde_json::from_str::<Value>(text) {
                            if event["method"]=="Target.attachedToTarget" && event["params"]["sessionId"]=="child-session" { child_present=true; }
                        }
                    }
                    if socket.send(message).await.is_err() { break; }
                }
                message = socket.next() => {
                    let Some(Ok(Message::Text(text))) = message else { break; };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    recorded.lock().unwrap().push(request.clone());
                    let method=request["method"].as_str().unwrap();
                    let session=request["sessionId"].as_str().unwrap_or("");
                    let result=match method {
                        "Browser.getVersion" => json!({"protocolVersion":"1.3","product":"Synthetic Chromium/1.0","revision":"synthetic","userAgent":"Synthetic Chromium Linux","jsVersion":"synthetic"}),
                        "Target.getBrowserContexts" => json!({"browserContextIds":[],"defaultBrowserContextId":"host-context"}),
                        "Target.getTargets" => json!({"targetInfos":if child_present {vec![host.clone(),child.clone()]} else {vec![host.clone()]}}),
                        "Target.getTargetInfo" => json!({"targetInfo":if request["params"]["targetId"]=="child-target" {child.clone()} else {assert_eq!(request["params"]["targetId"],"host-page");host.clone()}}),
                        "Target.attachToTarget" => {assert_eq!(request["params"]["targetId"],"host-page");json!({"sessionId":"host-session"})},
                        "Page.getFrameTree" => json!({"frameTree":{"frame":{"id":format!("frame-{session}"),"loaderId":format!("loader-{session}"),"url":"about:blank"}}}),
                        "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":format!("script-{}",request["id"])}),
                        "Page.enable"|"Runtime.enable"|"Network.enable"|"WebMCP.enable"|"DOM.enable"|"DOM.disable"|"Network.disable"|"Network.setBypassServiceWorker"|"Fetch.enable"|"Fetch.disable"|"Page.setLifecycleEventsEnabled"|"Target.setDiscoverTargets"|"Target.setAutoAttach"|"Runtime.runIfWaitingForDebugger"|"Page.removeScriptToEvaluateOnNewDocument"|"Emulation.setEmulatedMedia"|"Target.detachFromTarget" => json!({}),
                        other => panic!("unmodeled borrowed cleanup CDP method {other}: {request}"),
                    };
                    let mut response=json!({"id":request["id"],"result":result});
                    if !session.is_empty() {response["sessionId"]=session.into();}
                    if fault=="missing-detach" && method=="Target.detachFromTarget" {continue;}
                    let rejected=(fault=="remove-script" && method=="Page.removeScriptToEvaluateOnNewDocument") || (fault=="detach" && method=="Target.detachFromTarget");
                    if rejected {response.as_object_mut().unwrap().remove("result");response["error"]=json!({"code":-32000,"message":"synthetic explicit cleanup rejection"});}
                    let detached=if method=="Target.detachFromTarget" && !rejected {
                        let detached=request["params"]["sessionId"].as_str().unwrap();
                        let target=match detached {"host-session"=>"host-page","child-session"=>"child-target",other=>panic!("unowned detach {other}")};
                        let mut event=json!({"method":"Target.detachedFromTarget","params":{"sessionId":detached,"targetId":target}});
                        if !session.is_empty() {event["sessionId"]=session.into();}
                        Some(event)
                    } else {None};
                    // Hold only the final real cleanup command. Its ledger debt
                    // is inspected before the ACK and any physical local close.
                    if fault=="none" && peer_armed.load(Ordering::Acquire) && method=="Target.setAutoAttach" && session.is_empty() && request["params"]["autoAttach"]==false {
                        final_tx.send(request).unwrap();continue;
                    }
                    if event_first {if let Some(event)=&detached {socket.send(Message::Text(event.to_string())).await.unwrap();}}
                    if socket.send(Message::Text(response.to_string())).await.is_err() {break;}
                    if !event_first {if let Some(event)=detached {socket.send(Message::Text(event.to_string())).await.unwrap();}}
                }
            }
        }
    });
    (endpoint, log, emit, final_rx, armed, peer)
}

async fn managed_borrowed_case(event_first: bool, with_child: bool, fault: &'static str) {
    let (endpoint, log, emit, mut final_command, armed, peer) =
        borrowed_peer(event_first, fault).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let (sink, mut notices) = ClientEventSink::test_channel(broker);
    browser.set_event_sink(sink.clone()).unwrap();
    let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
    let deadline = Instant::now() + Duration::from_secs(10);
    let operation = OperationLease {
        is_callback: false,
        generation: 1,
        sequence: 1,
        deadline,
        cancellation: cancellation.clone(),
    };
    let opened = browser
        .open(
            OpenRequest::Connect {
                endpoint,
                persistent: true,
                options: ScopeCreationOptions {
                    init_scripts: vec!["globalThis.__syntheticBorrowedCleanup = true;".into()],
                    ..Default::default()
                },
            },
            operation,
        )
        .await
        .unwrap();
    let scope = opened["identityScope"].as_str().unwrap().to_owned();
    sink.acknowledge_result_for_test(&ServerMessage::Result {
        id: "managed-open".into(),
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
    let (client, targets, enrollment) = {
        let owner = browser.owner.lock().await;
        let owner = owner.as_ref().unwrap();
        assert!(!owner.owns_context);
        assert_eq!(
            owner.borrowed_targets.as_deref(),
            Some(["host-page".to_owned()].as_slice())
        );
        assert_eq!(owner.context_id, "host-context");
        assert_eq!(owner.identity_scope, scope);
        let runtime = owner.runtime.as_ref().unwrap();
        (
            owner.manager.client.clone(),
            owner.targets.clone(),
            runtime.enrollment.clone(),
        )
    };
    let ledger = client.debt_ledger().unwrap();
    assert!(ledger.matches_owner(1, &scope));
    targets.require_eval_owner(&ledger).unwrap();
    ledger.check_admission(AdmissionClass::Input).unwrap();
    assert!(!ledger.snapshot().integrity_lost);
    assert_eq!(
        ledger.check_unpublished_operation(&OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline,
            cancellation: cancellation.clone()
        }),
        Err(ProtocolError::InvalidSequence)
    );
    assert!(targets.owned_target("host-page").unwrap().capture_ready());
    let lease = browser.page_lease(false).await.unwrap();
    assert_eq!(lease.page_session_id, "host-session");
    drop(lease); // Do not make end_scope wait on its own retained reader permit.
    if with_child {
        emit.send(Message::Text(json!({"method":"Target.attachedToTarget","sessionId":"host-session","params":{"sessionId":"child-session","waitingForDebugger":true,"targetInfo":{"targetId":"child-target","type":"iframe","browserContextId":"host-context"}}}).to_string())).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !targets
                .owned_target("child-target")
                .is_ok_and(|target| target.capture_ready())
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    armed.store(true, Ordering::Release);
    let ended = tokio::spawn({
        let browser = browser.clone();
        let scope = scope.clone();
        async move { browser.end_scope(scope, 2).await }
    });
    if fault == "none" {
        let last = tokio::time::timeout(Duration::from_secs(2), final_command.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!ended.is_finished());
        let before_close = ledger.snapshot();
        assert_eq!(before_close.input_debt, 0);
        assert_eq!(before_close.object_debt, 0);
        assert_eq!(
            before_close.outstanding_commands, 1,
            "only the held final disable may remain"
        );
        assert!(!before_close.integrity_lost);
        emit.send(Message::Text(
            json!({"id":last["id"],"result":{}}).to_string(),
        ))
        .await
        .unwrap();
    }
    let end_result = tokio::time::timeout(Duration::from_secs(15), ended)
        .await
        .unwrap()
        .unwrap();
    eprintln!("borrowed case event_first={event_first} child={with_child} fault={fault}: end={end_result:?}; debt={:?}",ledger.snapshot());
    assert_eq!(end_result.is_ok(), fault == "none");
    assert!(browser.page_lease(false).await.is_err());
    if fault == "none" {
        assert_eq!(end_result, Ok(Value::Null));
        assert!(browser.owner.lock().await.is_none());
        assert!(!browser
            .startup_uncertain
            .load(std::sync::atomic::Ordering::SeqCst));
        let settled = ledger.snapshot();
        assert_eq!(
            (
                settled.outstanding_commands,
                settled.input_debt,
                settled.object_debt
            ),
            (0, 0, 0)
        );
        assert!(enrollment
            .cleanup_outcome()
            .unwrap()
            .closed_targets
            .is_empty());
        assert_eq!(browser.shutdown().await, Ok(()));
        assert!(browser.owner.lock().await.is_none());
    } else {
        assert_eq!(
            end_result,
            Err(ProtocolError::CleanupFailed),
            "fault={fault}"
        );
        if fault == "missing-detach" {
            assert!(
                ledger.snapshot().outstanding_commands > 0,
                "no actual ACK may silently clear command debt"
            );
        }
        assert!(browser.owner.lock().await.is_some());
        assert!(browser
            .startup_uncertain
            .load(std::sync::atomic::Ordering::SeqCst));
        let rejected_open = browser
            .open(
                OpenRequest::Reuse {
                    options: Default::default(),
                },
                OperationLease {
                    is_callback: false,
                    generation: 1,
                    sequence: 3,
                    deadline: Instant::now() + Duration::from_secs(1),
                    cancellation: cancellation.clone(),
                },
            )
            .await;
        assert!(
            rejected_open.is_err(),
            "failed cleanup cannot become reusable"
        );
        let shutdown_result = browser.shutdown().await;
        eprintln!("borrowed negative fault={fault}: shutdown={shutdown_result:?}");
        assert_eq!(
            shutdown_result,
            Err(ProtocolError::CleanupFailed),
            "fault={fault}"
        );
    }
    let commands = log.lock().unwrap().clone();
    assert!(!commands.iter().any(|r| matches!(
        r["method"].as_str(),
        Some("Browser.close" | "Target.disposeBrowserContext" | "Target.closeTarget")
    )));
    for session in if with_child {
        vec!["child-session", "host-session"]
    } else {
        vec!["host-session"]
    } {
        let detach = commands
            .iter()
            .position(|r| {
                r["method"] == "Target.detachFromTarget" && r["params"]["sessionId"] == session
            })
            .unwrap();
        for enabled in ["Fetch.enable", "Network.enable"] {
            if commands
                .iter()
                .any(|r| r["method"] == enabled && r["sessionId"] == session)
            {
                let disable = if enabled == "Fetch.enable" {
                    "Fetch.disable"
                } else {
                    "Network.disable"
                };
                assert!(commands[..detach]
                    .iter()
                    .any(|r| r["method"] == disable && r["sessionId"] == session));
            }
        }
        assert!(commands[..detach]
            .iter()
            .any(|r| r["method"] == "Target.setAutoAttach"
                && r["sessionId"] == session
                && r["params"]["autoAttach"] == false));
        for script in commands.iter().filter(|r| {
            r["method"] == "Page.addScriptToEvaluateOnNewDocument" && r["sessionId"] == session
        }) {
            assert!(commands[..detach].iter().any(|r| r["method"]
                == "Page.removeScriptToEvaluateOnNewDocument"
                && r["sessionId"] == session
                && r["params"]["identifier"] == format!("script-{}", script["id"])));
        }
    }
    if with_child {
        let detached: Vec<_> = commands
            .iter()
            .filter(|r| r["method"] == "Target.detachFromTarget")
            .map(|r| r["params"]["sessionId"].as_str().unwrap())
            .collect();
        assert_eq!(detached, vec!["child-session", "host-session"]);
    }
    if fault == "remove-script" {
        assert!(commands
            .iter()
            .any(|r| r["method"] == "Page.removeScriptToEvaluateOnNewDocument"));
    }
    while notices.try_recv().is_ok() {}
    client.close().await; // This owner-bound view is a no-op; manager.close and peer EOF provide physical-close evidence.
    peer.await.unwrap();
}

#[tokio::test]
async fn managed_borrowed_scope_end_preserves_host_and_settles_exact_sessions() {
    for event_first in [true, false] {
        managed_borrowed_case(event_first, false, "none").await;
    }
}

#[tokio::test]
async fn managed_borrowed_child_scope_end_is_child_first_without_host_destruction() {
    for event_first in [true, false] {
        managed_borrowed_case(event_first, true, "none").await;
    }
}

#[tokio::test]
async fn managed_borrowed_cleanup_error_acks_remain_hard_failures() {
    for fault in ["remove-script", "detach"] {
        managed_borrowed_case(true, false, fault).await;
    }
}

#[tokio::test]
async fn managed_borrowed_missing_detach_ack_retains_debt_and_cannot_reuse() {
    managed_borrowed_case(true, false, "missing-detach").await;
}
