//! Real framed post-script-ACK controls, no forged receipt or diagnostic authority.
use super::*;
struct RecursiveAckGate {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}
impl RecursiveAckGate {
    fn new() -> Self {
        Self {
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProofCase {
    Ready,
    Cancel,
    Deadline,
    Created,
    PopupCreated,
    NavigationAba,
    NewPopup,
    ForeignFrame,
}
async fn configuration_proof_peer(
    recursive: Arc<RecursiveAckGate>,
) -> (
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
        let mut held_recursive: Option<Value> = None;
        loop {
            tokio::select! {
                permit = recursive.release.acquire(), if held_recursive.is_some() => {
                    permit.unwrap().forget();
                    let request = held_recursive.take().unwrap();
                    let reply = json!({"id":request["id"],"sessionId":request["sessionId"],"result":{}});
                    if socket.send(Message::Text(reply.to_string())).await.is_err() { break; }
                }
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
                    if request["method"] == "Target.setAutoAttach" && request["sessionId"] == "capture-popup-session" {
                        assert!(held_recursive.replace(request).is_none());
                        recursive.entered.add_permits(1);
                        continue;
                    }
                    let result = match request["method"].as_str().unwrap() {
                        "Target.getTargetInfo" if request["params"]["targetId"] == "capture-popup"
                            || request["sessionId"] == "capture-popup-session"
                            || request["params"]["targetId"] == "second-popup"
                            || request["sessionId"] == "second-popup-session" => {
                            let id = if request["params"]["targetId"] == "second-popup" || request["sessionId"] == "second-popup-session" { "second-popup" } else { "capture-popup" };
                            let mut info = target(id, "page");
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

async fn popup_configuration_proof(case: ProofCase) {
    let recursive = Arc::new(RecursiveAckGate::new());
    let (endpoint, emit, log, peer, backend) = configuration_proof_peer(recursive.clone()).await;
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
            "context.init-script",
            json!({"identityScope":scope,"source":"globalThis.stageZeroFixture=1"}),
            5,
        )
        .await
        .unwrap();
    fixture
        .command(
            "page.navigate",
            json!({"identityScope":scope,"url":"https://synthetic.test/","waitUntil":"load"}),
            5,
        )
        .await
        .unwrap();
    let enrollment = browser
        .owner
        .lock()
        .await
        .as_ref()
        .unwrap()
        .runtime
        .as_ref()
        .unwrap()
        .enrollment
        .clone();
    let schedule = enrollment.popup_configuration_proof_schedule_for_test();
    let mut event = attach("capture-popup", "capture-popup-session", "page");
    event["params"]["targetInfo"]["openerId"] = "page-1".into();
    emit.send(event).await.unwrap();
    schedule.initializer_held().await;
    // The producer proof is now real. Release its local test gate, then hold
    // the actual recursive-CDP command reply while the event pump stays live.
    schedule.release();
    recursive.entered.acquire().await.unwrap().forget();
    let held = enrollment.response_entry_state_for_test();
    assert_eq!(held["pending"], 1);
    assert_eq!(held["unresumed"], 1);
    assert_eq!(held["failure"], false);
    assert_eq!(held["received"], held["applied"]);
    {
        let commands = log.lock().unwrap();
        assert_eq!(popup_commands(&commands, "Target.setAutoAttach"), 1);
        assert_eq!(
            popup_commands(&commands, "Page.addScriptToEvaluateOnNewDocument"),
            1
        );
        assert_eq!(
            popup_commands(&commands, "Runtime.runIfWaitingForDebugger"),
            0
        );
        assert_eq!(application_dispatches(&commands), 0);
    }
    let page = browser.page_lease(false).await.unwrap();
    let ledger = page.client.debt_ledger().unwrap();
    drop(page);
    let before_raw = ledger.observe_eval_revision("session-1", "page-1").unwrap();
    fixture.sequence += 1;
    let sequence = fixture.sequence;
    let mut args = evaluation();
    args["identityScope"] = scope.clone().into();
    let timeout_ms = if case == ProofCase::Deadline {
        1000
    } else {
        5000
    };
    fixture
        .write(
            json!({"type":"request","id":"stage-zero-evaluate","generation":1,
            "operationSeq":sequence,"timeoutMs":timeout_ms,"command":"page.evaluate","args":args}),
        )
        .await
        .unwrap();

    let mut waited = false;
    let entry_receipts;
    let evaluated;
    let mut after_raw = before_raw;
    if case == ProofCase::Ready {
        // Keep the actual framed read alive across the select. Old strict
        // capture returns its exact refusal; candidate must reach bounded wait.
        let mut read = tokio::spawn(async move {
            let result = read_entry_frame(&mut fixture).await;
            (fixture, result)
        });
        let (returned, result, receipts) = tokio::select! {
            result = &mut read => {
                let (fixture, result) = result.unwrap();
                (fixture, result, schedule.receipts())
            }
            receipt = schedule.preparation_waiting() => {
                assert_eq!(receipt["generation"], 1);
                assert_eq!(receipt["operationSeq"], sequence);
                assert_eq!(receipt["target"], "capture-popup");
                assert_eq!(receipt["session"], "capture-popup-session");
                assert_eq!(enrollment.response_entry_state_for_test(), held);
                {
                    let commands = log.lock().unwrap();
                    assert_eq!(application_dispatches(&commands), 0);
                    assert_eq!(popup_commands(&commands, "Runtime.runIfWaitingForDebugger"), 0);
                }
                let receipts = schedule.receipts();
                waited = true;
                recursive.release.add_permits(1);
                let (fixture, result) = read.await.unwrap();
                (fixture, result, receipts)
            }
        };
        fixture = returned;
        evaluated = result;
        entry_receipts = receipts;
    } else {
        let receipt = schedule.preparation_waiting().await;
        waited = true;
        assert_eq!(receipt["generation"], 1);
        assert_eq!(receipt["operationSeq"], sequence);
        assert_eq!(receipt["target"], "capture-popup");
        assert_eq!(receipt["session"], "capture-popup-session");
        assert_eq!(enrollment.response_entry_state_for_test(), held);
        if matches!(
            case,
            ProofCase::Created
                | ProofCase::PopupCreated
                | ProofCase::NavigationAba
                | ProofCase::NewPopup
                | ProofCase::ForeignFrame
        ) {
            let before_frames = enrollment.response_entry_state_for_test()["frames"].clone();
            let events = if case == ProofCase::NewPopup {
                let mut event = attach("second-popup", "second-popup-session", "page");
                event["params"]["targetInfo"]["openerId"] = "page-1".into();
                vec![event]
            } else if case == ProofCase::ForeignFrame {
                vec![
                    json!({"method":"Page.frameNavigated","sessionId":"session-1","params":{
                    "frame":{"id":"foreign-frame","parentId":"frame-session-1","loaderId":"foreign-loader",
                        "url":"https://synthetic.test/foreign","securityOrigin":"https://synthetic.test"}}}),
                ]
            } else if case == ProofCase::PopupCreated {
                vec![
                    json!({"method":"Runtime.executionContextCreated","sessionId":"capture-popup-session",
                    "params":{"context":{"id":903,"uniqueId":"late-popup-context","name":"",
                        "auxData":{"frameId":"frame-capture-popup-session","isDefault":true}}}}),
                ]
            } else if case == ProofCase::Created {
                vec![
                    json!({"method":"Runtime.executionContextCreated","sessionId":"session-1",
                    "params":{"context":{"id":902,"uniqueId":"created-during-stage-zero","name":"",
                        "auxData":{"frameId":"frame-session-1","isDefault":true}}}}),
                ]
            } else {
                ["stage-zero-loader", "followup-loader"].into_iter().map(|loader| {
                    json!({"method":"Page.frameNavigated","sessionId":"session-1","params":{
                        "frame":{"id":"frame-session-1","loaderId":loader,
                            "url":"https://synthetic.test/after-restart","securityOrigin":"https://synthetic.test"}}})
                }).collect::<Vec<_>>()
            };
            for event in events {
                let expected = enrollment.response_entry_state_for_test()["received"]
                    .as_u64()
                    .unwrap()
                    .checked_add(1)
                    .unwrap();
                let gate = enrollment.popup_interposition_event_gate_for_test();
                emit.send(event).await.unwrap();
                gate.received().await;
                gate.release();
                // Fixed frontier only: never wait for pending-empty while the
                // actual stage-zero initializer is deliberately held.
                enrollment
                    .popup_stage0_event_applied_for_test(expected)
                    .await;
            }
            if !matches!(case, ProofCase::ForeignFrame | ProofCase::NewPopup) {
                assert_eq!(
                    enrollment.response_entry_state_for_test()["frames"],
                    before_frames
                );
            }
            after_raw = ledger.observe_eval_revision("session-1", "page-1").unwrap();
        }
        if case == ProofCase::Cancel {
            fixture
                .write(json!({"type":"cancel","id":"cancel-stage-zero-evaluate",
                    "generation":1,"operationSeq":sequence}))
                .await
                .unwrap();
            let mut result = None;
            let mut acknowledged = false;
            for _ in 0..2 {
                let frame = read_entry_frame(&mut fixture).await;
                if frame["type"] == "control-result" {
                    assert_eq!(frame["id"], "cancel-stage-zero-evaluate");
                    assert_eq!(frame["accepted"], true);
                    assert!(!acknowledged);
                    acknowledged = true;
                } else {
                    assert!(result.replace(frame).is_none());
                }
            }
            assert!(acknowledged);
            evaluated = result.unwrap();
        } else {
            evaluated = read_entry_frame(&mut fixture).await;
        }
        entry_receipts = schedule.receipts();
    }
    if case != ProofCase::Ready || !waited {
        assert_eq!(
            enrollment.response_entry_state_for_test()["pending"],
            if case == ProofCase::NewPopup { 2 } else { 1 }
        );
        let commands = log.lock().unwrap();
        assert_eq!(application_dispatches(&commands), 0);
        assert_eq!(
            popup_commands(&commands, "Runtime.runIfWaitingForDebugger"),
            0
        );
    }
    recursive.release.add_permits(1);
    enrollment.popup_initializer_finished_for_test().await;
    let scope_end = fixture
        .command("scope.end", json!({"identityScope":scope}), 5)
        .await;
    let cleanup = tokio::time::timeout(Duration::from_secs(15), fixture.finish()).await;
    drop(emit);
    let peer_join = tokio::time::timeout(Duration::from_secs(2), peer).await;
    let backend_join = tokio::time::timeout(Duration::from_secs(2), backend).await;
    assert!(scope_end.is_ok(), "scope_end={scope_end:?}");
    assert!(matches!(cleanup, Ok(Ok(()))), "cleanup={cleanup:?}");
    assert!(matches!(peer_join, Ok(Ok(()))), "peer={peer_join:?}");
    assert!(
        matches!(backend_join, Ok(Ok(()))),
        "backend={backend_join:?}"
    );
    let commands = log.lock().unwrap().clone();
    let dispatches = application_dispatches(&commands);
    assert_eq!(
        popup_commands(&commands, "Runtime.runIfWaitingForDebugger"),
        1
    );
    assert_eq!(popup_commands(&commands, "Target.setAutoAttach"), 1);
    assert_eq!(
        popup_commands(&commands, "Page.addScriptToEvaluateOnNewDocument"),
        1
    );
    assert_eq!(evaluated["id"], "stage-zero-evaluate");
    assert_eq!(evaluated["operationSeq"], sequence);
    assert_eq!(evaluated["scopeState"], "usable");
    eprintln!("POPUP_CONFIGURATION_PROOF_WITNESS case={case:?} generation=1 operation={sequence} waited={waited} result={evaluated} dispatches={dispatches} cleanup=joined receipts={entry_receipts}");
    if case == ProofCase::Ready && waited {
        assert_eq!(evaluated["ok"], true);
        assert_eq!(evaluated["effects"], "completed");
        assert_eq!(evaluated["data"], json!({"value":{"ok":true,"value":null}}));
        assert_eq!(dispatches, 1);
        assert!((1..=2).contains(&entry_receipts.as_array().unwrap().len()));
        assert_eq!(entry_receipts[0]["generation"], 1);
        assert_eq!(entry_receipts[0]["operationSeq"], sequence);
        assert_eq!(entry_receipts[0]["facts"]["s"], "entry");
        assert_eq!(entry_receipts[0]["facts"]["c"], "entry");
    } else {
        assert_eq!(evaluated["ok"], false);
        assert_eq!(evaluated["effects"], "not-dispatched");
        assert_eq!(dispatches, 0);
        if matches!(case, ProofCase::NewPopup | ProofCase::ForeignFrame) {
            // Reader fencing may win before bounded event application, or the
            // applied cohort/frame guard may win. Neither permits dispatch.
            assert!(["scope-unavailable", "stale-scope"]
                .contains(&evaluated["error"]["code"].as_str().unwrap()));
        } else {
            assert_eq!(
                evaluated["error"]["code"],
                match case {
                    ProofCase::Cancel => "cancelled",
                    ProofCase::Deadline => "deadline-exceeded",
                    ProofCase::NavigationAba => "stale-scope",
                    _ => "scope-unavailable",
                }
            );
        }
    }
    if matches!(case, ProofCase::Created | ProofCase::PopupCreated) {
        assert_eq!(
            after_raw, before_raw,
            "created-only must fence without raw revocation"
        );
    } else if case == ProofCase::NavigationAba {
        assert!(
            after_raw > before_raw,
            "restored loader must not restore authority"
        );
    }
    if case == ProofCase::Ready {
        // Common C0: old strict capture is RED only after its exact refusal and
        // joined cleanup; new candidate must actually wait and dispatch once.
        assert!(
            waited,
            "old exact RED: post-script-ACK unconfigured stage-zero refused before retained wait"
        );
    }
}

async fn proof_case(case: ProofCase) {
    tokio::time::timeout(Duration::from_secs(35), popup_configuration_proof(case))
        .await
        .unwrap();
}
#[tokio::test]
async fn framed_popup_configuration_proof_waits_then_dispatches_once() {
    proof_case(ProofCase::Ready).await;
}
#[tokio::test]
async fn framed_popup_configuration_proof_preserves_original_cancel() {
    proof_case(ProofCase::Cancel).await;
}
#[tokio::test]
async fn framed_popup_configuration_proof_preserves_original_deadline() {
    proof_case(ProofCase::Deadline).await;
}
#[tokio::test]
async fn framed_popup_configuration_proof_rejects_late_root_runtime_event() {
    proof_case(ProofCase::Created).await;
}
#[tokio::test]
async fn framed_popup_configuration_proof_rejects_late_popup_runtime_event() {
    proof_case(ProofCase::PopupCreated).await;
}
#[tokio::test]
async fn framed_popup_configuration_proof_rejects_navigation_aba() {
    proof_case(ProofCase::NavigationAba).await;
}
#[tokio::test]
async fn framed_popup_configuration_proof_rejects_new_popup_cohort() {
    proof_case(ProofCase::NewPopup).await;
}
#[tokio::test]
async fn framed_popup_configuration_proof_rejects_foreign_frame() {
    proof_case(ProofCase::ForeignFrame).await;
}
