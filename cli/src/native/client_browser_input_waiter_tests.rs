//! Real generic ClientBrowser dispatch against a finite websocket peer. The only
//! scheduling hook observes an exact mutex future returning Pending; it neither
//! grants authority nor pauses production work. No browser process or sleeps.
use super::*;
use crate::native::client_debt::OperationKey;
use crate::native::client_operation_state::OperationRetentionStatus;
use std::future::Future;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChangeWhileWaiting {
    Healthy,
    InputDebt,
    ProducerResultUnfixed,
    PublicationRetiring,
    SameIdAttachmentReplaced,
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    // This is a failure bound, never the source of test ordering.
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("deterministic input waiter fixture stalled")
}

async fn generic_waiter_case(command: &str, change: ChangeWhileWaiting) {
    let (old_seen, mut old_requests) = tokio::sync::mpsc::unbounded_channel();
    let (endpoint, log, peer) = peer_with_inputs(
        false,
        Some(old_seen),
        change == ChangeWhileWaiting::InputDebt,
    )
    .await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture = framed(
        browser.clone(),
        broker.clone(),
        Arc::new(RestartFlush::default()),
    );
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
        .command("page.activate", json!({"identityScope":scope}), 5)
        .await
        .unwrap();

    let gate = {
        let owner = browser.owner.lock().await;
        let runtime = owner.as_ref().unwrap().runtime.as_ref().unwrap();
        if command == "context.viewport" {
            runtime.enrollment.config_gate()
        } else {
            runtime.input_gate.clone()
        }
    };
    let held = gate.lock_owned().await;
    let page = browser.page_lease(false).await.unwrap();
    let targets = page.targets.clone();
    let original = targets.owned_target(&page.target_id).unwrap();
    let ledger = page.client.debt_ledger().unwrap();
    let client = page.client.clone();
    let session = page.page_session_id.clone();

    // The older retained producer is genuinely registered before the waiter,
    // but has not sent any input yet. Thus initial admission must succeed.
    fixture.sequence += 1;
    let old_lease = broker.admit(1, fixture.sequence, 10_000).unwrap();
    assert!(broker.start(1, old_lease.sequence).unwrap());
    let old_key = OperationKey {
        generation: 1,
        operation_seq: old_lease.sequence,
    };
    let journal = ClientBrowser::operation_journal(&page, &old_lease).unwrap();
    let (go, start_old) = tokio::sync::oneshot::channel();
    let (abort_old, stop_old) = tokio::sync::oneshot::channel();
    let uncertain = matches!(
        change,
        ChangeWhileWaiting::InputDebt
            | ChangeWhileWaiting::ProducerResultUnfixed
            | ChangeWhileWaiting::PublicationRetiring
    );
    let old_result = browser
        .tasks
        .start_operation(
            scope.clone(),
            targets.clone(),
            broker.clone(),
            journal,
            old_lease.cancellation.clone(),
            async move {
                // This page permit and exact operation journal remain captured
                // until the real CDP caller has finished or been cancelled.
                let _page = page;
                start_old.await.unwrap();
                let result = tokio::select! {
                    biased;
                    _ = stop_old => None,
                    result = client.send_command(
                        "Input.insertText", Some(json!({"text":"older-native-input"})),
                        Some(&session),
                    ) => Some(result),
                };
                if let Some(result) = result {
                    result.unwrap();
                } else {
                    assert_eq!(change, ChangeWhileWaiting::InputDebt);
                }
                (
                    NativeOutcome {
                        retention: None,
                        result: if uncertain {
                            Err(ProtocolError::Cancelled)
                        } else {
                            Ok(Value::Null)
                        },
                        effects: if uncertain {
                            Effects::Unknown
                        } else {
                            Effects::Completed
                        },
                    },
                    false,
                )
            },
        )
        .await
        .unwrap();
    assert_eq!(ledger.snapshot().input_debt, 0);

    fixture.sequence += 1;
    let waiter_lease = broker.admit(1, fixture.sequence, 10_000).unwrap();
    let waiter_key = OperationKey {
        generation: 1,
        operation_seq: waiter_lease.sequence,
    };
    let (at_wait, waiting) = tokio::sync::oneshot::channel();
    *browser.generic_admission_probe.lock().unwrap() = Some(GenericAdmissionProbe {
        key: waiter_key,
        reached: at_wait,
    });
    let args = match command {
        "input.keyboard" => json!({"identityScope":scope,"action":"press","value":"ArrowRight"}),
        "input.mouse" => json!({"identityScope":scope,"action":"move","x":41,"y":73}),
        "context.viewport" => json!({"identityScope":scope,"width":811,"height":613}),
        _ => unreachable!(),
    };
    let executor = browser.clone();
    let name = command.to_owned();
    let waiter = tokio::spawn(async move {
        executor
            .execute(name, args.as_object().unwrap().clone(), waiter_lease)
            .await
    });
    // This ACK can only be emitted after both initial native admission checks
    // and a Pending poll of this exact command's actual configuration/input lock.
    bounded(waiting).await.unwrap();
    assert!(!waiter.is_finished());
    assert_eq!(ledger.snapshot().input_debt, 0);
    assert!(matches!(
        browser.operation_retention_status(waiter_key),
        OperationRetentionStatus::KnownActive {
            mutation_dispatched: false
        }
    ));
    assert!(!log
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["method"].as_str().unwrap().starts_with("Input.")));

    go.send(()).unwrap();
    let old_request = bounded(old_requests.recv()).await.unwrap();
    assert_eq!(old_request["method"], "Input.insertText");
    assert_eq!(old_request["sessionId"], original.session_id);
    if change == ChangeWhileWaiting::InputDebt {
        // The peer has received the genuine mutation and intentionally withholds
        // its ACK. Dropping only its caller must leave reader-owned input debt.
        abort_old.send(()).unwrap();
    }
    let older = bounded(old_result).await.unwrap();
    let proof = older.retention.clone();
    assert_eq!(
        older.effects,
        if uncertain {
            Effects::Unknown
        } else {
            Effects::Completed
        }
    );
    assert_eq!(
        ledger.snapshot().input_debt,
        u32::from(change == ChangeWhileWaiting::InputDebt)
    );
    assert!(!ledger.snapshot().integrity_lost);

    match change {
        ChangeWhileWaiting::InputDebt => {
            broker
                .begin_operation_retirement(old_key, proof.as_ref().unwrap())
                .unwrap();
            browser.retire_operation_publication(old_key).await.unwrap();
            broker.finish_operation_publication(old_key).unwrap();
            assert_eq!(
                broker
                    .settle_with_retention(
                        1,
                        old_key.operation_seq,
                        Effects::Unknown,
                        proof.as_ref()
                    )
                    .unwrap(),
                ScopeState::Usable
            );
            browser.fix_operation_result(old_key);
            // Isolate the final live-debt check: no producer or broker barrier
            // remains to hide a missing post-input-mutex ledger recheck.
            browser.tasks.check_input_dispatch(waiter_key).unwrap();
            assert!(broker.check_application_publication(1).unwrap());
        }
        ChangeWhileWaiting::ProducerResultUnfixed => {
            assert!(matches!(
                browser.operation_retention_status(old_key),
                OperationRetentionStatus::Retired { .. }
            ));
            assert!(browser.tasks.check_input_dispatch(waiter_key).is_err());
            assert!(broker.check_application_publication(1).unwrap());
        }
        ChangeWhileWaiting::PublicationRetiring => {
            broker
                .begin_operation_retirement(old_key, proof.as_ref().unwrap())
                .unwrap();
            browser.retire_operation_publication(old_key).await.unwrap();
            // Deliberately release the local result slot separately to isolate
            // the broker's still-pending publication barrier as dispatch authority.
            browser.fix_operation_result(old_key);
            browser.tasks.check_input_dispatch(waiter_key).unwrap();
            assert!(!broker.check_application_publication(1).unwrap());
        }
        ChangeWhileWaiting::Healthy | ChangeWhileWaiting::SameIdAttachmentReplaced => {
            assert_eq!(
                broker
                    .settle(1, old_key.operation_seq, Effects::Completed)
                    .unwrap(),
                ScopeState::Usable
            );
            browser.fix_operation_result(old_key);
            if change == ChangeWhileWaiting::SameIdAttachmentReplaced {
                // Same textual target/session IDs, distinct genuine attachment
                // tenure. A session-string-only post-wait check is insufficient.
                targets.detach(&original.target_id).unwrap();
                assert!(targets
                    .attached(
                        &targets.context_id,
                        original.target_id.clone(),
                        original.session_id.clone(),
                        original.kind.clone()
                    )
                    .unwrap());
                targets.configured(&original.target_id).unwrap();
                targets
                    .resume_permit(&original.target_id)
                    .await
                    .unwrap()
                    .complete()
                    .unwrap();
                assert!(
                    !original.same_attachment(&targets.owned_target(&original.target_id).unwrap())
                );
            }
        }
    }

    let before_release = log.lock().unwrap().len();
    assert!(!waiter.is_finished());
    drop(held);
    let outcome = bounded(waiter).await.unwrap();
    let fresh = log.lock().unwrap()[before_release..].to_vec();
    if change == ChangeWhileWaiting::Healthy {
        assert_eq!(outcome.result, Ok(Value::Null));
        assert_eq!(outcome.effects, Effects::Completed);
        let expected_method = match command {
            "input.keyboard" => "Input.dispatchKeyEvent",
            "input.mouse" => "Input.dispatchMouseEvent",
            "context.viewport" => "Emulation.setDeviceMetricsOverride",
            _ => unreachable!(),
        };
        let dispatched = fresh
            .iter()
            .filter(|r| r["method"] == expected_method)
            .collect::<Vec<_>>();
        assert_eq!(
            dispatched.len(),
            if command == "input.keyboard" { 2 } else { 1 }
        );
        assert!(dispatched
            .iter()
            .all(|r| r["sessionId"] == original.session_id));
        match command {
            "input.keyboard" => {
                assert_eq!(dispatched[0]["params"]["type"], "rawKeyDown");
                assert_eq!(dispatched[1]["params"]["type"], "keyUp");
                assert!(dispatched
                    .iter()
                    .all(|r| r["params"]["key"] == "ArrowRight"));
            }
            "input.mouse" => {
                assert_eq!(dispatched[0]["params"]["type"], "mouseMoved");
                assert_eq!(dispatched[0]["params"]["x"], 41.0);
                assert_eq!(dispatched[0]["params"]["y"], 73.0);
            }
            "context.viewport" => {
                assert_eq!(dispatched[0]["params"]["width"], 811);
                assert_eq!(dispatched[0]["params"]["height"], 613);
            }
            _ => unreachable!(),
        }
    } else {
        assert!(outcome.result.is_err(), "{command}: {change:?}");
        assert_eq!(
            outcome.effects,
            Effects::NotDispatched,
            "{command}: {change:?}"
        );
        assert!(
            fresh
                .iter()
                .all(|r| !r["method"].as_str().unwrap().starts_with("Input.")
                    && r["method"] != "Emulation.setDeviceMetricsOverride"),
            "waiter dispatched after {change:?}: {fresh:?}"
        );
    }
    assert!(outcome.retention.is_none());
    assert_eq!(
        broker
            .settle(1, waiter_key.operation_seq, outcome.effects)
            .unwrap(),
        ScopeState::Usable
    );
    browser.fix_operation_result(waiter_key);
    if change == ChangeWhileWaiting::ProducerResultUnfixed {
        broker
            .begin_operation_retirement(old_key, proof.as_ref().unwrap())
            .unwrap();
        browser.retire_operation_publication(old_key).await.unwrap();
    }
    if matches!(
        change,
        ChangeWhileWaiting::ProducerResultUnfixed | ChangeWhileWaiting::PublicationRetiring
    ) {
        broker.finish_operation_publication(old_key).unwrap();
        assert_eq!(
            broker
                .settle_with_retention(1, old_key.operation_seq, Effects::Unknown, proof.as_ref())
                .unwrap(),
            ScopeState::Usable
        );
        browser.fix_operation_result(old_key);
    }
    let current = browser.page_lease(false).await.unwrap();
    assert_eq!(current.identity_scope, scope);
    assert_eq!(current.target_id, original.target_id);
    assert_eq!(current.page_session_id, original.session_id);
    assert!(Arc::ptr_eq(&current.client.debt_ledger().unwrap(), &ledger));
    assert_eq!(broker.health().unwrap(), (1, ScopeState::Usable));
    drop(current);
    assert!(browser.generic_admission_probe.lock().unwrap().is_none());
    let cleanup = bounded(fixture.finish()).await;
    peer.abort();
    cleanup.unwrap();
}

#[tokio::test]
async fn actual_generic_input_waiters_revalidate_every_changed_authority() {
    for command in ["input.keyboard", "input.mouse"] {
        for change in [
            ChangeWhileWaiting::Healthy,
            ChangeWhileWaiting::InputDebt,
            ChangeWhileWaiting::ProducerResultUnfixed,
            ChangeWhileWaiting::PublicationRetiring,
            ChangeWhileWaiting::SameIdAttachmentReplaced,
        ] {
            generic_waiter_case(command, change).await;
        }
    }
}

#[tokio::test]
async fn actual_configuration_waiter_revalidates_after_its_own_mutex() {
    for change in [
        ChangeWhileWaiting::Healthy,
        ChangeWhileWaiting::InputDebt,
        ChangeWhileWaiting::ProducerResultUnfixed,
        ChangeWhileWaiting::PublicationRetiring,
        ChangeWhileWaiting::SameIdAttachmentReplaced,
    ] {
        generic_waiter_case("context.viewport", change).await;
    }
}
