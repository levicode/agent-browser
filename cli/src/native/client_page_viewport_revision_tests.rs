// Component controls for existing shared configuration revision accounting.
// Framed eval/UI interposition is a separate causal control, not inferred here.

#[tokio::test]
async fn viewport_changes_restore_values_but_never_restore_configuration_revision_or_replay_scripts(
) {
    let (page, log, server) = mock("normal").await;
    let (operation, _cancel) = operation();
    let state = ClientPageState::new("scope".into(), "context".into());
    state
        .execute(
            &page,
            &[],
            &operation,
            "context.init-script",
            &json!({"source":"globalThis.viewportRevisionFixture=1"}),
        )
        .await
        .unwrap();
    assert_eq!(
        state.script_registration_ack_ordinals("page").unwrap(),
        vec![0]
    );
    assert_eq!(
        state
            .execute(
                &page,
                &[],
                &operation,
                "context.viewport",
                &json!({"width":800,"height":600})
            )
            .await
            .unwrap(),
        Value::Null
    );
    let before = state.config_revision().unwrap();
    for (width, height) in [(900, 700), (800, 600)] {
        assert_eq!(
            state
                .execute(
                    &page,
                    &[],
                    &operation,
                    "context.viewport",
                    &json!({"width":width,"height":height})
                )
                .await
                .unwrap(),
            Value::Null
        );
    }
    assert_eq!(state.requested_viewport().unwrap(), Some((800, 600)));
    assert_eq!(state.config_revision().unwrap(), before + 2);
    assert_eq!(
        state
            .apply_to_new_session(&page, "page", &operation)
            .await
            .unwrap(),
        before + 2
    );
    assert_eq!(
        state.script_registration_ack_ordinals("page").unwrap(),
        vec![0]
    );
    {
        let requests = log.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["method"] == "Page.addScriptToEvaluateOnNewDocument")
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["method"] == "Emulation.setDeviceMetricsOverride")
                .count(),
            3
        );
    }
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn viewport_revision_exhaustion_refuses_before_any_browser_command() {
    let (page, log, server) = mock("normal").await;
    let (operation, _cancel) = operation();
    let state = ClientPageState::new("scope".into(), "context".into());
    state.state().unwrap().config.revision = u64::MAX;
    let result = state
        .execute(
            &page,
            &[],
            &operation,
            "context.viewport",
            &json!({"width":800,"height":600}),
        )
        .await;
    assert_eq!(result, Err(ProtocolError::IdentifierExhausted));
    assert_eq!(state.config_revision().unwrap(), u64::MAX);
    assert_eq!(state.requested_viewport().unwrap(), None);
    assert!(log.lock().unwrap().is_empty());
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn viewport_failed_or_withheld_ack_keeps_original_error_requested_value_and_raw_revision() {
    for held in [false, true] {
        let (page, log, server) = mock(if held {
            "hold-viewport"
        } else {
            "reject-viewport"
        })
        .await;
        let state = ClientPageState::new("scope".into(), "context".into());
        // Bind before the first command, matching existing managed component
        // fixtures; no late ledger replacement repairs a failed observation.
        let ledger = client_debt::OwnerDebtLedger::new(1, "scope".into());
        page.client.install_debt_ledger(ledger.clone()).unwrap();
        let (mut operation, _cancel) = operation();
        operation.deadline = Instant::now() + Duration::from_millis(100);
        let journal = ledger
            .operation(
                client_debt::OperationKey {
                    generation: 1,
                    operation_seq: 1,
                },
                "target".into(),
                "page".into(),
            )
            .unwrap();
        journal.bind_operation(&operation).unwrap();
        let raw = ledger.observe_eval_revision("page", "target").unwrap();
        let result = journal
            .scope(state.execute(
                &page,
                &[],
                &operation,
                "context.viewport",
                &json!({"width":800,"height":600}),
            ))
            .await;
        assert_eq!(
            result,
            Err(if held {
                ProtocolError::DeadlineExceeded
            } else {
                ProtocolError::BrowserFailure
            })
        );
        assert_eq!(
            state.requested_viewport().unwrap(),
            None,
            "only a positive ACK may publish requested dimensions"
        );
        assert_eq!(
            state.config_revision().unwrap(),
            1,
            "failed attempts remain conservative preparation fences"
        );
        assert_eq!(ledger.observe_eval_revision("page", "target").unwrap(), raw);
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|request| request["method"] == "Emulation.setDeviceMetricsOverride")
                .count(),
            1
        );
        if held {
            assert_eq!(ledger.snapshot().input_debt, 1);
            assert!(ledger.snapshot().outstanding_commands > 0);
            assert!(journal.snapshot().mutation_dispatched);
        }
        server.abort();
        let _ = server.await;
    }
}
