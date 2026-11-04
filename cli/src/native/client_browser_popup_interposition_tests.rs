//! Full framed preparation interpositions. The finite peer models CDP values;
//! no JavaScript/browser fidelity or runtime outcome is claimed from source.
use super::*;
use std::time::Instant;
use tokio::sync::mpsc;

fn evaluation() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/response-evaluate-entry.json"
    ))
    .unwrap()
}
fn expression() -> String {
    let a = evaluation();
    format!("(async()=>{{const value=await ({} )({}); return {{value:value===undefined?null:value}};}})()",
        a["source"].as_str().unwrap(), serde_json::to_string(&a["argument"]).unwrap())
}
async fn interposition_peer() -> (
    String,
    mpsc::Sender<Value>,
    Arc<Mutex<Vec<Value>>>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let (backend, _, backend_task) = peer(false).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let (emit, mut events) = mpsc::channel::<Value>(8);
    let commands = Arc::new(Mutex::new(Vec::new()));
    let log = commands.clone();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut backend, _) = tokio_tungstenite::connect_async(backend).await.unwrap();
        loop {
            tokio::select! {
                event = events.recv() => {
                    let Some(event) = event else { break; };
                    if socket.send(Message::Text(event.to_string())).await.is_err() { break; }
                }
                message = backend.next() => {
                    let Some(Ok(message)) = message else { break; };
                    if socket.send(message).await.is_err() { break; }
                }
                message = socket.next() => {
                    let Some(Ok(Message::Text(text))) = message else { break; };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    log.lock().unwrap().push(request.clone());
                    let result = match request["method"].as_str().unwrap() {
                        "Target.getTargetInfo" if request["params"]["targetId"] == "capture-popup"
                            || request["sessionId"] == "capture-popup-session" => {
                            let mut info = target("capture-popup", "page");
                            info["openerId"] = "page-1".into();
                            Some(json!({"targetInfo":info}))
                        }
                        "Emulation.setDeviceMetricsOverride" => {
                            assert_eq!(request["sessionId"], "session-1");
                            let width = request["params"]["width"].as_u64().unwrap();
                            let height = request["params"]["height"].as_u64().unwrap();
                            assert!(matches!((width, height), (800, 600) | (1024, 768)));
                            assert_eq!(request["params"], json!({"width":width,"height":height,
                                "deviceScaleFactor":0,"mobile":false,"screenWidth":width,"screenHeight":height}));
                            Some(json!({}))
                        }
                        "Runtime.evaluate" if request["params"]["expression"] == expression() => {
                            assert_eq!(request["sessionId"], "session-1");
                            assert_eq!(request["params"]["awaitPromise"], true);
                            assert_eq!(request["params"]["returnByValue"], true);
                            assert_eq!(request["params"]["userGesture"], true);
                            Some(json!({"result":{"type":"object","value":{"value":{"ok":true,"value":null}}}}))
                        }
                        "Runtime.evaluate"
                            if request["params"]["expression"]
                                == "String(globalThis.location && globalThis.location.href)" =>
                        {
                            // The paused initial-document probe sees a document
                            // that already started; the future registration
                            // covers it, so the one-shot does nothing.
                            Some(json!({"result":{"type":"string","value":"https://fixture.invalid/path"}}))
                        }
                        "Runtime.evaluate" => {
                            assert_eq!(request["params"]["expression"], "location.href");
                            None
                        }
                        _ => None,
                    };
                    if let Some(result) = result {
                        let reply = json!({"id":request["id"],"sessionId":request["sessionId"],"result":result});
                        if socket.send(Message::Text(reply.to_string())).await.is_err() { break; }
                    } else if backend.send(Message::Text(text)).await.is_err() { break; }
                }
            }
        }
        let _ = backend.close(None).await;
    });
    (endpoint, emit, commands, task, backend_task)
}

async fn read_entry_frame(fixture: &mut FramedFixture) -> Value {
    for _ in 0..32 {
        let frame = tokio::time::timeout(Duration::from_secs(3), fixture.read())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame["generation"], 1);
        if frame["type"] == "event" {
            fixture.event_sequence += 1;
            assert_eq!(frame["sequence"], fixture.event_sequence);
            assert_eq!(
                frame["payload"]["identityScope"].as_str(),
                fixture.scope.as_deref()
            );
            if frame["event"] == "network.response" {
                return frame;
            }
            validate_fixture_notice(&frame).unwrap();
        } else {
            return frame;
        }
    }
    panic!("response entry event bound exceeded");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Interposition {
    ViewportAba,
    UiCreated,
    UiNavigationAba,
}
async fn popup_preparation_interposition(case: Interposition) {
    let (endpoint, emit, log, peer, backend) = interposition_peer().await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture = framed(browser.clone(), broker, Arc::new(RestartFlush::default()));
    fixture.ready().await.unwrap();
    let opened = fixture
        .command(
            "scope.open",
            fixture_scope_open("connect", Some(&endpoint)),
            5,
        )
        .await
        .unwrap();
    let scope = opened["identityScope"].as_str().unwrap().to_owned();
    fixture.scope = Some(scope.clone());
    fixture
        .command("scope.configure", fixture_configuration(&scope, None), 5)
        .await
        .unwrap();
    fixture
        .command("network.routes.replace", fixture_routes(&scope), 5)
        .await
        .unwrap();
    fixture.registry = 1;
    fixture
        .command(
            "page.navigate",
            json!({"identityScope":scope,
        "url":"https://synthetic.test/","waitUntil":"load"}),
            5,
        )
        .await
        .unwrap();
    if case == Interposition::ViewportAba {
        fixture
            .command(
                "context.viewport",
                json!({"identityScope":scope,
            "width":800,"height":600}),
                5,
            )
            .await
            .unwrap();
    }
    let (enrollment, ui) = {
        let owner = browser.owner.lock().await;
        let owner = owner.as_ref().unwrap();
        (
            owner.runtime.as_ref().unwrap().enrollment.clone(),
            owner.ui.clone(),
        )
    };
    let schedule = enrollment.popup_interposition_schedule_for_test();
    let (cancel, cancellation) =
        tokio::sync::watch::channel(crate::native::client_session::CancelSignal::None);
    let exclusive = if case != Interposition::ViewportAba {
        // A genuine UiGate permit causes the original enter future to wait;
        // this does not edit UiGate counters or fabricate a blocked notification.
        Some(
            ui.enter(
                true,
                false,
                Instant::now() + Duration::from_secs(10),
                cancellation,
            )
            .await
            .unwrap(),
        )
    } else {
        None
    };
    let mut event = attach("capture-popup", "capture-popup-session", "page");
    event["params"]["targetInfo"]["openerId"] = "page-1".into();
    emit.send(event).await.unwrap();
    schedule.initializer_held().await;
    let page = browser.page_lease(false).await.unwrap();
    let ledger = page.client.debt_ledger().unwrap();
    drop(page);
    let original_configuration = enrollment.popup_interposition_configuration_for_test();
    fixture.sequence += 1;
    let original_sequence = fixture.sequence;
    let mut args = evaluation();
    args["identityScope"] = scope.clone().into();
    fixture
        .write(
            json!({"type":"request","id":"interposed-evaluate","generation":1,
        "operationSeq":original_sequence,"timeoutMs":5000,"command":"page.evaluate","args":args}),
        )
        .await
        .unwrap();
    let preparation = schedule.preparation_waiting().await;
    assert_eq!(preparation["generation"], 1);
    assert_eq!(preparation["operationSeq"], original_sequence);
    assert_eq!(preparation["target"], "capture-popup");
    assert_eq!(preparation["session"], "capture-popup-session");
    schedule.recheck_held().await;
    let mut actual_ui_wait = None;
    let before_raw;
    let after_raw;
    if case == Interposition::ViewportAba {
        before_raw = ledger.observe_eval_revision("session-1", "page-1").unwrap();
        // Both mutations are full native framed operations. Config value A is
        // restored, but the original preparation must not acquire a fresh fence.
        for (width, height) in [(1024, 768), (800, 600)] {
            fixture
                .command(
                    "context.viewport",
                    json!({"identityScope":scope,
                "width":width,"height":height}),
                    5,
                )
                .await
                .unwrap();
        }
        after_raw = ledger.observe_eval_revision("session-1", "page-1").unwrap();
        assert_eq!(enrollment.response_entry_state_for_test()["pending"], 1);
        schedule.release_initializer();
        enrollment.popup_initializer_finished_for_test().await;
    } else {
        schedule.release_initializer();
        enrollment.popup_initializer_finished_for_test().await;
        schedule.release_recheck();
        let pending = schedule.ui_pending().await;
        assert_eq!(pending["generation"], 1);
        assert_eq!(pending["operationSeq"], original_sequence);
        assert_eq!(pending["prepared"], true);
        assert_eq!(pending["actualUiPoll"], "pending");
        actual_ui_wait = Some(pending);
        assert_eq!(enrollment.response_entry_state_for_test()["pending"], 0);
        before_raw = ledger.observe_eval_revision("session-1", "page-1").unwrap();
        let before_frames = enrollment.response_entry_state_for_test()["frames"].clone();
        let root_before = before_frames
            .as_array()
            .unwrap()
            .iter()
            .find(|frame| frame[1] == "session-1")
            .unwrap()
            .clone();
        let events = if case == Interposition::UiCreated {
            vec![
                json!({"method":"Runtime.executionContextCreated","sessionId":"session-1",
                "params":{"context":{"id":901,"uniqueId":"created-during-real-ui-wait","name":"",
                    "auxData":{"frameId":"frame-session-1","isDefault":true}}}}),
            ]
        } else {
            ["interposed-loader", "followup-loader"].into_iter().map(|loader| {
                json!({"method":"Page.frameNavigated","sessionId":"session-1","params":{
                    "frame":{"id":"frame-session-1","loaderId":loader,
                        "url":"https://synthetic.test/after-restart","securityOrigin":"https://synthetic.test"}}})
            }).collect::<Vec<_>>()
        };
        for event in events {
            let event_gate = enrollment.popup_interposition_event_gate_for_test();
            emit.send(event).await.unwrap();
            event_gate.received().await;
            event_gate.release();
            enrollment
                .popup_interposition_event_applied_for_test()
                .await;
        }
        after_raw = ledger.observe_eval_revision("session-1", "page-1").unwrap();
        let after_frames = enrollment.response_entry_state_for_test()["frames"].clone();
        let root_after = after_frames
            .as_array()
            .unwrap()
            .iter()
            .find(|frame| frame[1] == "session-1")
            .unwrap()
            .clone();
        assert_eq!(
            root_after, root_before,
            "final root/frame/loader values were restored"
        );
    }
    let changed_configuration = enrollment.popup_interposition_configuration_for_test();
    let before_dispatches = log
        .lock()
        .unwrap()
        .iter()
        .filter(|request| {
            request["method"] == "Runtime.evaluate"
                && request["params"]["expression"] == expression()
        })
        .count();
    if case == Interposition::ViewportAba {
        schedule.release_recheck();
    }
    drop(exclusive);
    drop(cancel);
    let evaluated = read_entry_frame(&mut fixture).await;
    let scope_end = fixture
        .command("scope.end", json!({"identityScope":scope}), 5)
        .await;
    let cleanup = tokio::time::timeout(Duration::from_secs(15), fixture.finish()).await;
    drop(emit);
    let peer_join = tokio::time::timeout(Duration::from_secs(2), peer).await;
    let backend_join = tokio::time::timeout(Duration::from_secs(2), backend).await;
    let commands = log.lock().unwrap().clone();
    let expression_dispatches = commands
        .iter()
        .filter(|request| {
            request["method"] == "Runtime.evaluate"
                && request["params"]["expression"] == expression()
        })
        .count();
    assert!(scope_end.is_ok(), "scope_end={scope_end:?}");
    assert!(matches!(cleanup, Ok(Ok(()))), "cleanup={cleanup:?}");
    assert!(matches!(peer_join, Ok(Ok(()))), "peer={peer_join:?}");
    assert!(
        matches!(backend_join, Ok(Ok(()))),
        "backend={backend_join:?}"
    );
    eprintln!("POPUP_INTERPOSITION_OBSERVATION case={case:?} generation=1 operation={original_sequence} result={evaluated} dispatches={expression_dispatches} config_before={original_configuration} config_after={changed_configuration} actual_ui_wait={actual_ui_wait:?} cleanup=joined");
    assert_eq!(before_dispatches, 0);
    assert_eq!(evaluated["id"], "interposed-evaluate");
    assert_eq!(evaluated["ok"], false);
    assert_eq!(evaluated["effects"], "not-dispatched");
    assert_eq!(evaluated["scopeState"], "usable");
    assert_eq!(
        evaluated["error"]["code"],
        if case == Interposition::UiCreated {
            "scope-unavailable"
        } else {
            "stale-scope"
        }
    );
    assert_eq!(expression_dispatches, 0);
    assert_eq!(
        commands
            .iter()
            .filter(
                |request| request["method"] == "Runtime.runIfWaitingForDebugger"
                    && request["sessionId"] == "capture-popup-session"
            )
            .count(),
        1
    );
    if case == Interposition::ViewportAba {
        let viewports = commands
            .iter()
            .filter(|request| {
                request["method"] == "Emulation.setDeviceMetricsOverride"
                    && request["sessionId"] == "session-1"
            })
            .map(|request| json!([request["params"]["width"], request["params"]["height"]]))
            .collect::<Vec<_>>();
        assert_eq!(
            viewports,
            vec![json!([800, 600]), json!([1024, 768]), json!([800, 600])]
        );
        assert_eq!(original_configuration["viewport"], json!([800, 600]));
        assert_eq!(
            changed_configuration["viewport"],
            original_configuration["viewport"]
        );
        assert!(
            changed_configuration["revision"].as_u64().unwrap()
                > original_configuration["revision"].as_u64().unwrap()
        );
        assert_eq!(
            after_raw, before_raw,
            "negotiated viewport must not add legacy raw revocation"
        );
    } else if case == Interposition::UiCreated {
        assert_eq!(
            after_raw, before_raw,
            "created-only fence must not rely on legacy raw revocation"
        );
    } else {
        assert!(after_raw > before_raw);
    }
}

#[tokio::test]
async fn framed_popup_preparation_actual_viewport_a_b_a_refuses_original_eval() {
    tokio::time::timeout(
        Duration::from_secs(35),
        popup_preparation_interposition(Interposition::ViewportAba),
    )
    .await
    .unwrap();
}
#[tokio::test]
async fn framed_popup_preparation_actual_ui_wait_created_context_refuses_first_capture() {
    tokio::time::timeout(
        Duration::from_secs(35),
        popup_preparation_interposition(Interposition::UiCreated),
    )
    .await
    .unwrap();
}
#[tokio::test]
async fn framed_popup_preparation_actual_ui_wait_navigation_a_b_a_refuses_first_capture() {
    tokio::time::timeout(
        Duration::from_secs(35),
        popup_preparation_interposition(Interposition::UiNavigationAba),
    )
    .await
    .unwrap();
}

#[path = "client_popup_stage0_tests.rs"]
mod stage0_tests;
