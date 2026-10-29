// Included only inside client_enrollment::tests. Existing scripted CDP transport,
// real retained initializer, no direct index/receipt mutation and no eval retry.

async fn popup_preparation_owner(
    mode: &'static str,
) -> (
    Arc<ClientEnrollment>,
    BrowserExecutionLease,
    Notices,
    Log,
    tokio::sync::mpsc::Sender<Value>,
    JoinHandle<()>,
    Arc<CdpClient>,
) {
    let (mut owner, notices, log, emit, server, _broker, connection) =
        fixture_with_explicit_context_ownership(mode, true, true).await;
    owner.gate.begin_transition().unwrap();
    let authority = owner.gate.initialization(owner.targets.clone()).unwrap();
    Arc::get_mut(&mut owner).unwrap().initialization = Some(authority.access());
    owner
        .enroll_existing("initial-target", "initial", "page", &owner.operation())
        .await
        .unwrap();
    owner.start(&owner.operation()).await.unwrap();
    owner.publish_initialized(&authority).unwrap();
    let entry = owner.index.lock().unwrap().sessions["initial"].clone();
    let page = owner.lease(&entry).unwrap();
    (owner, page, notices, log, emit, server, connection)
}

async fn send_preparation_popup(
    emit: &tokio::sync::mpsc::Sender<Value>,
    session: &str,
    target: &str,
) {
    emit.send(json!({"method":"Target.attachedToTarget","params":{
        "sessionId":session,"waitingForDebugger":true,"targetInfo":{
            "targetId":target,"type":"page","browserContextId":"owned-context","openerId":"initial-target"}}})).await.unwrap();
}

// These finite owner-retirement fixtures inject one event at a time and do
// not emit automatic lifecycle events. Observe that exact subscription prefix,
// not capture admission: the caller deliberately retains a pending initializer.
async fn popup_preparation_emit_applied(
    owner: &Arc<ClientEnrollment>,
    emit: &tokio::sync::mpsc::Sender<Value>,
    event: Value,
) {
    let watermark = owner.realm_watermark().unwrap();
    let frontier = watermark.received().unwrap().checked_add(1).unwrap();
    emit.send(event).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let changed = owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            owner.check().unwrap();
            assert!(watermark.same_subscription(&owner.realm_watermark().unwrap()));
            let received = watermark.received().unwrap();
            assert!(received <= frontier, "unexpected extra fixture event");
            {
                let index = owner.index.lock().unwrap();
                assert!(index.failure.is_none());
                if received == frontier && index.applied_watermark >= frontier {
                    assert!(
                        !index.pending_enrollment.is_empty(),
                        "event application must not wait away the retained initializer"
                    );
                    return;
                }
            }
            changed.await;
        }
    })
    .await
    .expect("injected popup-control event was not received and applied");
}

async fn popup_preparation_negative_case(mode: &str) {
    let (owner, page, _notices, log, emit, server, connection) =
        popup_preparation_owner("owner-retirement").await;
    let schedule = owner.popup_capture_schedule_for_test(true);
    if mode == "later-completed" {
        // initialize_inner has returned at this existing gate, releasing the
        // config lock while the original completed ResumePermit is still held.
        let mut gates = owner.capture_test_gates.lock().unwrap();
        let held = gates
            .remove(&CaptureTestPoint::AfterPopupResumeAckBeforeComplete)
            .unwrap();
        gates.insert(CaptureTestPoint::BeforeInitializationResumeRelease, held);
    }
    let recheck = matches!(mode, "navigation-aba" | "later-cohort" | "later-completed")
        .then(CaptureTestGate::new);
    if let Some(gate) = &recheck {
        owner
            .capture_test_gates
            .lock()
            .unwrap()
            .insert(CaptureTestPoint::BeforeEvalPreparationRecheck, gate.clone());
    }
    send_preparation_popup(&emit, "popup-session", "popup-target").await;
    tokio::time::timeout(Duration::from_secs(2), schedule.initializer_held())
        .await
        .unwrap();
    let (cancel, cancellation) = watch::channel(CancelSignal::None);
    let operation = OperationLease {
        is_callback: false,
        generation: owner.generation,
        sequence: 71,
        deadline: Instant::now()
            + if mode == "deadline" {
                Duration::from_secs(1)
            } else {
                Duration::from_secs(5)
            },
        cancellation,
    };
    let task_owner = owner.clone();
    let mut task =
        tokio::spawn(async move { task_owner.wait_eval_ingress(&page, &operation).await });
    let early = tokio::select! {
        result = &mut task => Some(result.unwrap()),
        _ = schedule.preparation_waiting() => None,
    };
    if early.is_none() {
        match mode {
            "cancel" => {
                cancel.send_replace(CancelSignal::Requested);
            }
            "created" => {
                popup_preparation_emit_applied(&owner, &emit, json!({"method":"Runtime.executionContextCreated","sessionId":"initial",
                    "params":{"context":{"id":901,"uniqueId":"main-replacement","name":"","auxData":{"frameId":"frame-initial","isDefault":true}}}})).await;
            }
            "navigation-aba" => {
                let recheck = recheck.as_ref().unwrap();
                recheck.wait_entered().await;
                let ledger = owner.client.debt_ledger().unwrap();
                let before = ledger
                    .observe_eval_revision("initial", "initial-target")
                    .unwrap();
                for loader in ["replacement-loader", "synthetic-loader"] {
                    popup_preparation_emit_applied(&owner, &emit, json!({"method":"Page.frameNavigated","sessionId":"initial",
                        "params":{"frame":{"id":"frame-initial","loaderId":loader,"url":"about:blank"}}})).await;
                }
                assert_eq!(
                    owner.index.lock().unwrap().frames["frame-initial"]
                        .loader
                        .as_deref(),
                    Some("synthetic-loader")
                );
                assert!(
                    ledger
                        .observe_eval_revision("initial", "initial-target")
                        .unwrap()
                        > before
                );
                recheck.release();
            }
            "later-cohort" => {
                let recheck = recheck.as_ref().unwrap();
                recheck.wait_entered().await;
                popup_preparation_emit_applied(&owner, &emit, json!({"method":"Target.attachedToTarget","params":{
                    "sessionId":"later-popup-session","waitingForDebugger":true,"targetInfo":{
                        "targetId":"later-popup-target","type":"page","browserContextId":"owned-context","openerId":"initial-target"}}})).await;
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let changed = owner.changed.notified();
                        tokio::pin!(changed);
                        changed.as_mut().enable();
                        if let Some(entry) = owner
                            .index
                            .lock()
                            .unwrap()
                            .sessions
                            .get("later-popup-session")
                        {
                            assert!(
                                !entry.application,
                                "original initializer still owns config_gate"
                            );
                            break;
                        }
                        changed.await;
                    }
                })
                .await
                .unwrap();
                recheck.release();
            }
            "later-completed" => {
                let recheck = recheck.as_ref().unwrap();
                recheck.wait_entered().await;
                let finish = CaptureTestGate::new();
                owner.capture_test_gates.lock().unwrap().insert(
                    CaptureTestPoint::AfterPopupCustodyFinishBeforeReceipt,
                    finish.clone(),
                );
                send_preparation_popup(&emit, "later-popup-session", "later-popup-target").await;
                tokio::time::timeout(Duration::from_secs(2), finish.wait_entered())
                    .await
                    .unwrap();
                let later = owner.index.lock().unwrap().pending_eval_initialization
                    ["later-popup-session"]
                    .clone();
                finish.release();
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let changed = owner.changed.notified();
                        tokio::pin!(changed);
                        changed.as_mut().enable();
                        if !owner
                            .index
                            .lock()
                            .unwrap()
                            .pending_enrollment
                            .contains_key("later-popup-session")
                        {
                            assert!(later.completed(&owner.targets).unwrap());
                            break;
                        }
                        changed.await;
                    }
                })
                .await
                .unwrap();
                assert!(owner
                    .index
                    .lock()
                    .unwrap()
                    .pending_enrollment
                    .contains_key("popup-session"));
                schedule.release();
                owner.popup_initializer_finished_for_test().await;
                assert!(owner.index.lock().unwrap().pending_enrollment.is_empty());
                recheck.release();
            }
            "deadline" => {}
            _ => unreachable!(),
        }
    }
    let waited = early.is_none();
    let result = match early {
        Some(result) => result,
        None => tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap(),
    };
    schedule.release();
    owner.popup_initializer_finished_for_test().await;
    let resume_count = log
        .lock()
        .unwrap()
        .iter()
        .filter(|request| {
            request["sessionId"] == "popup-session"
                && request["method"] == "Runtime.runIfWaitingForDebugger"
        })
        .count();
    let _ = owner.close().await;
    connection.close().await;
    server.abort();
    let _ = server.await;
    assert!(
        waited,
        "candidate did not reach the actual retained-cohort wait"
    );
    let expected = match mode {
        "cancel" => ProtocolError::Cancelled,
        "deadline" => ProtocolError::DeadlineExceeded,
        "created" | "later-cohort" => ProtocolError::ScopeUnavailable,
        _ => ProtocolError::StaleScope,
    };
    assert_eq!(result.err(), Some(expected));
    assert_eq!(
        resume_count, 1,
        "preparation must not replay the initializer"
    );
}

#[tokio::test]
async fn popup_preparation_original_cancel_and_deadline_never_mint_authority() {
    for mode in ["cancel", "deadline"] {
        popup_preparation_negative_case(mode).await;
    }
}
#[tokio::test]
async fn popup_preparation_locked_guard_keeps_hard_failure_before_cancel() {
    let (owner, page, _notices, _log, emit, server, connection) =
        popup_preparation_owner("owner-retirement").await;
    let schedule = owner.popup_capture_schedule_for_test(true);
    send_preparation_popup(&emit, "popup-session", "popup-target").await;
    schedule.initializer_held().await;
    let (cancel, cancellation) = watch::channel(CancelSignal::None);
    let operation = OperationLease {
        is_callback: false,
        generation: owner.generation,
        sequence: 73,
        deadline: Instant::now() + Duration::from_secs(5),
        cancellation,
    };
    let task_owner = owner.clone();
    let mut task = tokio::spawn(async move {
        let prepared = task_owner.wait_eval_ingress(&page, &operation).await;
        (prepared, operation)
    });
    let early = tokio::select! { result=&mut task => Some(result.unwrap()), _=schedule.preparation_waiting()=>None };
    let waited = early.is_none();
    schedule.release();
    let (prepared, operation) = match early {
        Some(result) => result,
        None => tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap(),
    };
    let result = prepared.ok().flatten().map(|prepared| {
        let entry = owner.index.lock().unwrap().sessions["initial"].clone();
        let page = owner.lease(&entry).unwrap();
        owner.poison(ProtocolError::BrowserFailure);
        cancel.send_replace(CancelSignal::Requested);
        // No outer bounded select competes here: isolate the locked guard's
        // original hard-failure precedence, not cancellation arbitration policy.
        let index = owner.index.lock().unwrap();
        owner.check_eval_preparation_locked(&index, &page, &operation, &prepared)
    });
    let _ = owner.close().await;
    connection.close().await;
    server.abort();
    let _ = server.await;
    assert!(waited);
    assert_eq!(result, Some(Err(ProtocolError::BrowserFailure)));
}
#[tokio::test]
async fn popup_preparation_main_world_created_only_is_foreign() {
    popup_preparation_negative_case("created").await;
}
#[tokio::test]
async fn popup_preparation_root_navigation_restore_is_not_forgiven() {
    popup_preparation_negative_case("navigation-aba").await;
}
#[tokio::test]
async fn popup_preparation_never_joins_a_later_registered_initializer() {
    popup_preparation_negative_case("later-cohort").await;
}
#[tokio::test]
async fn popup_preparation_rejects_later_cohort_after_both_initializers_finish() {
    popup_preparation_negative_case("later-completed").await;
}

#[tokio::test]
async fn popup_finish_then_detach_before_receipt_does_not_manufacture_initializer_failure() {
    let (owner, _page, _notices, _log, emit, server, connection) =
        popup_preparation_owner("owner-retirement").await;
    let gate = CaptureTestGate::new();
    owner.capture_test_gates.lock().unwrap().insert(
        CaptureTestPoint::AfterPopupCustodyFinishBeforeReceipt,
        gate.clone(),
    );
    send_preparation_popup(&emit, "popup-session", "popup-target").await;
    tokio::time::timeout(Duration::from_secs(2), gate.wait_entered())
        .await
        .unwrap();
    // The test point is after actual successful finish and actual permit Drop.
    assert!(owner
        .targets
        .owned_target("popup-target")
        .unwrap()
        .capture_ready());
    let receipt = owner.index.lock().unwrap().pending_eval_initialization["popup-session"].clone();
    popup_preparation_emit_applied(
        &owner,
        &emit,
        json!({"method":"Target.detachedFromTarget","params":{
        "sessionId":"popup-session","targetId":"popup-target"}}),
    )
    .await;
    gate.release();
    gate.wait_passed().await;
    owner.popup_initializer_finished_for_test().await;
    let failure = owner.index.lock().unwrap().failure.clone();
    let positive = receipt.completed(&owner.targets);
    let _ = owner.close().await;
    connection.close().await;
    server.abort();
    let _ = server.await;
    assert!(
        positive.is_err(),
        "detached tenure must not gain positive completion"
    );
    assert_eq!(
        failure, None,
        "receipt loss must not poison an already-finished initializer"
    );
}

#[tokio::test]
async fn popup_preparation_receipt_rejects_foreign_stream_owner_and_frontier() {
    let (owner, _page, _notices, _log, emit, server, connection) =
        popup_preparation_owner("owner-retirement").await;
    let schedule = owner.popup_capture_schedule_for_test(true);
    send_preparation_popup(&emit, "popup-session", "popup-target").await;
    tokio::time::timeout(Duration::from_secs(2), schedule.initializer_held())
        .await
        .unwrap();
    let receipt = owner.index.lock().unwrap().pending_eval_initialization["popup-session"].clone();
    let ledger = owner.client.debt_ledger().unwrap();
    let stream = owner.realm_watermark().unwrap();
    let received = stream.received().unwrap();
    assert!(receipt
        .capture_for_eval(
            &owner.targets,
            &ledger,
            &stream,
            received,
            "popup-target",
            "popup-session"
        )
        .is_ok());
    let foreign_stream = owner
        .client
        .subscribe_bounded_methods_with_budget(EVENTS, 256, 128 * 1024 * 1024, 256 * 1024 * 1024)
        .unwrap();
    assert!(receipt
        .capture_for_eval(
            &owner.targets,
            &ledger,
            &foreign_stream.watermark(),
            received,
            "popup-target",
            "popup-session"
        )
        .is_err());
    assert!(receipt
        .capture_for_eval(
            &owner.targets,
            &ledger,
            &stream,
            0,
            "popup-target",
            "popup-session"
        )
        .is_err());
    let foreign = super::super::client_debt::OwnerDebtLedger::new(
        owner.generation,
        owner.targets.identity_scope.clone(),
    );
    assert!(receipt
        .capture_for_eval(
            &owner.targets,
            &foreign,
            &stream,
            received,
            "popup-target",
            "popup-session"
        )
        .is_err());
    schedule.release();
    owner.popup_initializer_finished_for_test().await;
    let _ = owner.close().await;
    connection.close().await;
    server.abort();
    let _ = server.await;
}

async fn popup_preparation_unacknowledged_resume_case(negative: bool) {
    // Existing fixture mode holds Page.enable and resume ACK for session child;
    // the attached target here is a page, not an iframe.
    let (owner, page, _notices, log, emit, server, connection) =
        popup_preparation_owner("iframe-controlled-acks").await;
    send_preparation_popup(&emit, "child", "popup-target").await;
    let page_enable = wait_iframe_initialization_command(&log, "Page.enable").await;
    emit.send(json!({"id":page_enable["id"],"sessionId":"child","result":{}}))
        .await
        .unwrap();
    let resume = wait_iframe_initialization_command(&log, "Runtime.runIfWaitingForDebugger").await;
    let schedule = owner.popup_capture_schedule_for_test(true);
    // Resume has not ACKed, so the initializer gate itself has not been reached.
    let (cancel, cancellation) = watch::channel(CancelSignal::None);
    let operation = OperationLease {
        is_callback: false,
        generation: owner.generation,
        sequence: 72,
        deadline: Instant::now()
            + if negative {
                Duration::from_secs(5)
            } else {
                Duration::from_secs(1)
            },
        cancellation,
    };
    let task_owner = owner.clone();
    let mut task =
        tokio::spawn(async move { task_owner.wait_eval_ingress(&page, &operation).await });
    let early = tokio::select! { result=&mut task => Some(result.unwrap()), _=schedule.preparation_waiting()=>None };
    if negative && early.is_none() {
        emit.send(json!({"id":resume["id"],"sessionId":"child","error":{"code":-32000,"message":"controlled resume refusal"}})).await.unwrap();
    }
    let waited = early.is_none();
    let result = match early {
        Some(result) => result,
        None => tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap(),
    };
    let debt_before_ack = owner
        .client
        .debt_ledger()
        .unwrap()
        .snapshot()
        .outstanding_commands;
    if !negative || !waited {
        emit.send(json!({"id":resume["id"],"sessionId":"child","result":{}}))
            .await
            .unwrap();
        schedule.release();
        owner.popup_initializer_finished_for_test().await;
    }
    drop(cancel);
    let count = log
        .lock()
        .unwrap()
        .iter()
        .filter(|request| {
            request["sessionId"] == "child"
                && request["method"] == "Runtime.runIfWaitingForDebugger"
        })
        .count();
    let _ = owner.close().await;
    connection.close().await;
    server.abort();
    let _ = server.await;
    assert!(
        waited,
        "issued permit without ACK must be retained, not accepted"
    );
    assert_eq!(
        result.err(),
        Some(if negative {
            ProtocolError::BrowserFailure
        } else {
            ProtocolError::DeadlineExceeded
        })
    );
    if !negative {
        assert!(
            debt_before_ack > 0,
            "deadline must not erase actual outstanding resume debt"
        );
    }
    assert_eq!(count, 1);
}
#[tokio::test]
async fn popup_preparation_withheld_resume_ack_preserves_original_deadline_and_debt() {
    popup_preparation_unacknowledged_resume_case(false).await;
}
#[tokio::test]
async fn popup_preparation_negative_resume_ack_never_publishes_completion() {
    popup_preparation_unacknowledged_resume_case(true).await;
}
