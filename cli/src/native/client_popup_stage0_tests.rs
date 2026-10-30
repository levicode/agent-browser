//! Source reconstruction after loss of the original local candidate; this is
//! not a byte-exact recovery of blob 2380607b94d6496996ffb3db0af7be85c0d28511.
//! Framed controls use real retained initialization and command admission.
//! The finite CDP peer neither executes JavaScript nor proves browser outcomes.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StageZeroCase {
    Ready,
    Unconfigured,
    Cancel,
    Deadline,
    Created,
    NavigationAba,
}

fn application_dispatches(commands: &[Value]) -> usize {
    commands
        .iter()
        .filter(|request| {
            request["method"] == "Runtime.evaluate"
                && request["params"]["expression"] == expression()
        })
        .count()
}

fn popup_commands(commands: &[Value], method: &str) -> usize {
    commands
        .iter()
        .filter(|request| {
            request["method"] == method && request["sessionId"] == "capture-popup-session"
        })
        .count()
}

async fn popup_stage_zero(case: StageZeroCase) {
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
    let schedule = enrollment.popup_stage0_schedule_for_test(case != StageZeroCase::Unconfigured);
    let mut event = attach("capture-popup", "capture-popup-session", "page");
    event["params"]["targetInfo"]["openerId"] = "page-1".into();
    emit.send(event).await.unwrap();
    schedule.initializer_held().await;
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
    let timeout_ms = if case == StageZeroCase::Deadline {
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
    if case == StageZeroCase::Ready {
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
                schedule.release();
                let (fixture, result) = read.await.unwrap();
                (fixture, result, receipts)
            }
        };
        fixture = returned;
        evaluated = result;
        entry_receipts = receipts;
    } else if case == StageZeroCase::Unconfigured {
        evaluated = read_entry_frame(&mut fixture).await;
        entry_receipts = schedule.receipts();
    } else {
        let receipt = schedule.preparation_waiting().await;
        waited = true;
        assert_eq!(receipt["generation"], 1);
        assert_eq!(receipt["operationSeq"], sequence);
        assert_eq!(receipt["target"], "capture-popup");
        assert_eq!(receipt["session"], "capture-popup-session");
        assert_eq!(enrollment.response_entry_state_for_test(), held);
        if matches!(case, StageZeroCase::Created | StageZeroCase::NavigationAba) {
            let before_frames = enrollment.response_entry_state_for_test()["frames"].clone();
            let events = if case == StageZeroCase::Created {
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
            assert_eq!(
                enrollment.response_entry_state_for_test()["frames"],
                before_frames
            );
            after_raw = ledger.observe_eval_revision("session-1", "page-1").unwrap();
        }
        if case == StageZeroCase::Cancel {
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
    if case != StageZeroCase::Ready || !waited {
        assert_eq!(enrollment.response_entry_state_for_test()["pending"], 1);
        let commands = log.lock().unwrap();
        assert_eq!(application_dispatches(&commands), 0);
        assert_eq!(
            popup_commands(&commands, "Runtime.runIfWaitingForDebugger"),
            0
        );
    }
    schedule.release();
    enrollment.popup_initializer_finished_for_test().await;
    if case == StageZeroCase::Unconfigured {
        assert_eq!(entry_receipts.as_array().unwrap().len(), 1);
        assert_eq!(entry_receipts[0]["generation"], 1);
        assert_eq!(entry_receipts[0]["operationSeq"], sequence);
        assert_eq!(entry_receipts[0]["facts"]["s"], "wait");
        assert_eq!(entry_receipts[0]["facts"]["c"], "p-config");
        assert_eq!(
            schedule.receipts(),
            entry_receipts,
            "refusal must not resample after configuration"
        );
    }
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
    eprintln!("POPUP_STAGE_ZERO_WITNESS case={case:?} generation=1 operation={sequence} waited={waited} result={evaluated} dispatches={dispatches} cleanup=joined receipts={entry_receipts}");
    if case == StageZeroCase::Ready && waited {
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
        assert_eq!(
            evaluated["error"]["code"],
            match case {
                StageZeroCase::Cancel => "cancelled",
                StageZeroCase::Deadline => "deadline-exceeded",
                StageZeroCase::NavigationAba => "stale-scope",
                _ => "scope-unavailable",
            }
        );
    }
    if case == StageZeroCase::Created {
        assert_eq!(
            after_raw, before_raw,
            "created-only must fence without raw revocation"
        );
    } else if case == StageZeroCase::NavigationAba {
        assert!(
            after_raw > before_raw,
            "restored loader must not restore authority"
        );
    }
    if case == StageZeroCase::Ready {
        // Common C0: old strict capture is RED only after its exact refusal and
        // joined cleanup; new candidate must actually wait and dispatch once.
        assert!(
            waited,
            "old exact RED: configured stage-zero scope-unavailable before retained wait"
        );
    }
}

async fn stage_zero_case(case: StageZeroCase) {
    tokio::time::timeout(Duration::from_secs(35), popup_stage_zero(case))
        .await
        .unwrap();
}

#[tokio::test]
async fn framed_popup_configured_stage_zero_waits_then_dispatches_once() {
    stage_zero_case(StageZeroCase::Ready).await;
}
#[tokio::test]
async fn framed_popup_unconfigured_stage_zero_still_refuses() {
    stage_zero_case(StageZeroCase::Unconfigured).await;
}
#[tokio::test]
async fn framed_popup_configured_stage_zero_preserves_original_cancel() {
    stage_zero_case(StageZeroCase::Cancel).await;
}
#[tokio::test]
async fn framed_popup_configured_stage_zero_preserves_original_deadline() {
    stage_zero_case(StageZeroCase::Deadline).await;
}
#[tokio::test]
async fn framed_popup_configured_stage_zero_rejects_created_only() {
    stage_zero_case(StageZeroCase::Created).await;
}
#[tokio::test]
async fn framed_popup_configured_stage_zero_rejects_navigation_aba() {
    stage_zero_case(StageZeroCase::NavigationAba).await;
}
