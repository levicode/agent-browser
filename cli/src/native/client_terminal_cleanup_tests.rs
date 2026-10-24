// Terminal cleanup exercises the existing real websocket EOF fixture. Only the
// scoped publication ACK uses its established unit seam; no debt/EOF is forged.
async fn managed_terminal_cleanup_fixture() -> (
    TerminalFixture,
    Arc<super::super::client_debt::OwnerDebtLedger>,
) {
    let fixture = terminal_fixture().await;
    let ledger = super::super::client_debt::OwnerDebtLedger::new(
        1,
        fixture.source.scope.identity_scope.clone(),
    );
    fixture
        .source
        .client
        .install_debt_ledger(ledger.clone())
        .unwrap();
    fixture.targets.bind_eval_owner(&ledger, 1).unwrap();
    (fixture, ledger)
}

#[tokio::test]
async fn terminal_quarantine_parks_and_drains_without_restoring_business_authority() {
    let (mut fixture, ledger) = managed_terminal_cleanup_fixture().await;
    let source = fixture.source.clone();
    source.replace_routes(7, vec!["original".into()]).unwrap();
    let operation = source.broker.admit(1, 1, 5000).unwrap();
    let (release, blocked) = std::sync::mpsc::channel();
    let (started, entered) = tokio::sync::oneshot::channel();
    source
        .blocking_reads
        .lock()
        .unwrap()
        .spawn_blocking(move || {
            let _ = started.send(());
            let _ = blocked.recv();
        });
    tokio::time::timeout(std::time::Duration::from_secs(2), entered)
        .await
        .unwrap()
        .unwrap();
    let proof = disconnect_terminal(&fixture).await;
    source.broker.quarantine().unwrap();
    let before = ledger.snapshot();
    assert!(before.integrity_lost);
    let closing = source.clone();
    let terminal = proof.clone();
    let close = tokio::spawn(async move { closing.close_for_remote_disconnect(&terminal).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !source.sealed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!close.is_finished());
    assert!(!source.cleanup_drained.load(Ordering::Acquire));
    assert!(source
        .take_disconnected_routes(&fixture.targets, &operation)
        .is_err());
    release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), close)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(source.cleanup_drained.load(Ordering::Acquire));
    assert!(matches!(
        *source.disconnected_routes.lock().unwrap(),
        DisconnectedRouteSlot::Parked(_)
    ));
    assert_eq!(
        source.park_disconnected_routes(&proof),
        Err(ProtocolError::StaleScope)
    );
    assert!(fixture._events.try_recv().is_err());
    assert_eq!(
        source.broker.health().unwrap().1,
        super::super::client_protocol::ScopeState::Quarantined
    );
    assert!(source.broker.admit(1, 2, 5000).is_err());
    assert!(source
        .take_disconnected_routes(&fixture.targets, &operation)
        .is_err());
    let after = ledger.snapshot();
    assert!(after.integrity_lost);
    assert_eq!(after.input_debt, before.input_debt);
    assert_eq!(after.outstanding_commands, before.outstanding_commands);
    assert!(Arc::ptr_eq(&source.client.debt_ledger().unwrap(), &ledger));
    source.close().await.unwrap();
    assert!(matches!(
        *source.disconnected_routes.lock().unwrap(),
        DisconnectedRouteSlot::Retired
    ));
    assert_eq!(
        source.broker.take_released_registry_events(8).unwrap(),
        vec![(7, Some(source.scope.identity_scope.clone()))]
    );
    fixture.server.abort();
}

#[tokio::test]
async fn terminal_callback_disposition_distinguishes_queue_from_local_only() {
    use super::super::client_transport::NativeCallbackRetirement;
    for publication_closed in [false, true] {
        let (mut fixture, ledger) = managed_terminal_cleanup_fixture().await;
        let source = &fixture.source;
        let proof = disconnect_terminal(&fixture).await;
        // No asynchronous producer or reader exists in this fixture. Revoke the
        // exact source before exercising the callback-only boundary directly.
        source.revoke_resources().unwrap();
        if publication_closed {
            source.retirement_sink.close_publications_for_test();
        }
        assert_eq!(
            source
                .retirement_sink
                .retire_callbacks_after_terminal_drain(&proof),
            Ok(if publication_closed {
                NativeCallbackRetirement::LocalOnlyTerminal
            } else {
                NativeCallbackRetirement::NoticeQueued
            })
        );
        if publication_closed {
            assert!(fixture._events.try_recv().is_err());
        } else {
            assert!(
                matches!(fixture._events.try_recv().unwrap(), ServerMessage::Event { event, .. } if event == "scope.callbacks-retired")
            );
        }
        assert_eq!(
            source
                .retirement_sink
                .retire_callbacks_after_terminal_drain(&proof),
            Err(ProtocolError::StaleScope)
        );
        assert!(source
            .retirement_sink
            .emit(
                "late".into(),
                json!({"identityScope":source.scope.identity_scope}),
                None
            )
            .is_err());
        assert!(ledger.snapshot().integrity_lost);
        source.close().await.unwrap();
        fixture.server.abort();
    }
}

#[tokio::test]
async fn terminal_cleanup_rejects_foreign_broker_ledger_generation_and_missing_owner() {
    let (fixture, _ledger) = managed_terminal_cleanup_fixture().await;
    let source = &fixture.source;
    source.replace_routes(7, vec!["original".into()]).unwrap();
    assert!(
        super::super::client_enrollment::NativeTerminalProof::for_test(
            source.client.clone(),
            fixture.targets.clone(),
            source,
            1,
            "retained-page".into()
        )
        .is_err(),
        "local identity cannot substitute for reader EOF"
    );
    let proof = disconnect_terminal(&fixture).await;
    source.broker.quarantine().unwrap();
    let foreign = Arc::new(ClientSession::new());
    assert!(matches!(
        foreign.park_registry_after_terminal(&proof, 7),
        Err(ProtocolError::StaleScope)
    ));
    let same_labels = super::super::client_targets::ClientTargets::new(
        fixture.targets.context_id.clone(),
        source.scope.identity_scope.clone(),
    );
    let foreign_ledger =
        super::super::client_debt::OwnerDebtLedger::new(1, source.scope.identity_scope.clone());
    same_labels.bind_eval_owner(&foreign_ledger, 1).unwrap();
    let wrong_owner = super::super::client_enrollment::NativeTerminalProof::for_test(
        source.client.clone(),
        same_labels,
        source,
        1,
        "retained-page".into(),
    )
    .unwrap();
    assert_eq!(
        source.park_disconnected_routes(&wrong_owner),
        Err(ProtocolError::StaleScope)
    );
    let wrong_generation = super::super::client_enrollment::NativeTerminalProof::for_test(
        source.client.clone(),
        fixture.targets.clone(),
        source,
        2,
        "retained-page".into(),
    )
    .unwrap();
    assert_eq!(
        source.park_disconnected_routes(&wrong_generation),
        Err(ProtocolError::StaleGeneration)
    );
    assert_eq!(*source.registry.lock().unwrap(), Some(7));
    assert!(matches!(
        *source.disconnected_routes.lock().unwrap(),
        DisconnectedRouteSlot::Uncaptured
    ));
    source.close().await.unwrap();
    fixture.server.abort();

    let fixture = terminal_fixture().await;
    fixture
        .source
        .replace_routes(7, vec!["original".into()])
        .unwrap();
    let proof = disconnect_terminal(&fixture).await;
    fixture.source.broker.quarantine().unwrap();
    assert_eq!(
        fixture.source.park_disconnected_routes(&proof),
        Err(ProtocolError::StaleScope)
    );
    assert_eq!(*fixture.source.registry.lock().unwrap(), Some(7));
    fixture.source.close().await.unwrap();
    fixture.server.abort();
}

#[tokio::test]
async fn terminal_local_fence_rejects_pending_and_discarded_publications() {
    let (mut fixture, _ledger) = managed_terminal_cleanup_fixture().await;
    let source = &fixture.source;
    let operation = source.broker.admit(1, 1, 5000).unwrap();
    let pending = source
        .retirement_sink
        .stage_until_result(&operation, &source.scope.identity_scope)
        .unwrap();
    let proof = disconnect_terminal(&fixture).await;
    source.broker.quarantine().unwrap();
    source.revoke_resources().unwrap();
    assert_eq!(
        source
            .retirement_sink
            .retire_callbacks_after_terminal_drain(&proof),
        Err(ProtocolError::StaleScope)
    );
    assert_eq!(
        pending.retire_callbacks_after_terminal_drain(&proof),
        Err(ProtocolError::StaleScope)
    );
    source.retirement_sink.close_publications_for_test();
    assert_eq!(
        pending.retire_callbacks_after_terminal_drain(&proof),
        Err(ProtocolError::StaleScope)
    );
    assert!(fixture._events.try_recv().is_err());
    source.close().await.unwrap();
    fixture.server.abort();
}

#[tokio::test]
async fn terminal_notice_queue_failure_never_becomes_local_only_success() {
    let (mut fixture, _ledger) = managed_terminal_cleanup_fixture().await;
    let source = &fixture.source;
    for _ in 0..64 {
        source
            .retirement_sink
            .emit(
                "queued".into(),
                json!({"identityScope":source.scope.identity_scope}),
                None,
            )
            .unwrap();
    }
    let proof = disconnect_terminal(&fixture).await;
    source.revoke_resources().unwrap();
    assert_eq!(
        source
            .retirement_sink
            .retire_callbacks_after_terminal_drain(&proof),
        Err(ProtocolError::CapacityExceeded)
    );
    source.retirement_sink.close_publications_for_test();
    assert_eq!(
        source
            .retirement_sink
            .retire_callbacks_after_terminal_drain(&proof),
        Err(ProtocolError::StaleScope)
    );
    while let Ok(event) = fixture._events.try_recv() {
        assert!(
            !matches!(event, ServerMessage::Event { event, .. } if event == "scope.callbacks-retired")
        );
    }
    source.close().await.unwrap();
    fixture.server.abort();
}

#[tokio::test]
async fn terminal_local_fence_never_hides_a_failed_retained_reader() {
    let (mut fixture, ledger) = managed_terminal_cleanup_fixture().await;
    let source = &fixture.source;
    source.replace_routes(7, vec!["original".into()]).unwrap();
    source.blocking_reads.lock().unwrap().spawn_blocking(|| {
        panic!("synthetic retained reader failure");
    });
    let proof = disconnect_terminal(&fixture).await;
    source.broker.quarantine().unwrap();
    assert_eq!(
        source.close_for_remote_disconnect(&proof).await,
        Err(ProtocolError::CleanupFailed)
    );
    assert!(!source.cleanup_drained.load(Ordering::Acquire));
    assert!(ledger.snapshot().integrity_lost);
    assert!(fixture._events.try_recv().is_err());
    // Cached worker failure survives the second call; no empty JoinSet can
    // masquerade as successful drainage after the original task was moved.
    assert_eq!(
        source.close_for_remote_disconnect(&proof).await,
        Err(ProtocolError::CleanupFailed)
    );
    assert_eq!(source.close().await, Err(ProtocolError::CleanupFailed));
    fixture.server.abort();
}
