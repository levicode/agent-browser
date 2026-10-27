// Exact-owner scripted CDP evidence, not Chrome behavior.
#[tokio::test]
async fn peer_context_absence_runs_original_phase_two_without_native_dispose() {
    let (owner, _notices, log, _emit, server, _broker, connection) =
        fixture_with_explicit_context_ownership("peer-absent", true, true).await;
    assert!(owner.prepare_peer_context_retirement().await.is_err());
    assert!(owner.confirm_peer_context_retirement().await.is_err());
    assert!(log.lock().unwrap().is_empty());
    owner.seal();
    owner.drain().await.unwrap();
    owner.prepare_peer_context_retirement().await.unwrap();
    owner.confirm_peer_context_retirement().await.unwrap();
    let ledger = owner.client.debt_ledger().unwrap();
    assert!(
        !ledger.replacement_ready(),
        "absence alone cannot skip phase two"
    );
    let proof = owner.contain_owned_resources().await.unwrap();
    owner.release_after_containment(proof).await.unwrap();
    assert!(ledger.replacement_ready());
    let methods: Vec<_> = log
        .lock()
        .unwrap()
        .iter()
        .map(|item| item["method"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        methods,
        ["Target.getBrowserContexts", "Target.setAutoAttach"]
    );
    connection.close().await;
    server.abort();
}

#[tokio::test]
async fn present_peer_context_cannot_mint_finish_but_terminal_owner_can_destroy_it() {
    let (owner, _notices, log, _emit, server, _broker, connection) =
        fixture_with_explicit_context_ownership("peer-present", true, true).await;
    owner.seal();
    owner.drain().await.unwrap();
    owner.prepare_peer_context_retirement().await.unwrap();
    assert!(owner.confirm_peer_context_retirement().await.is_err());
    assert!(!owner.cleanup_outcome().unwrap().owned_resources_contained);
    assert!(!owner.client.debt_ledger().unwrap().replacement_ready());
    let proof = owner.contain_owned_resources().await.unwrap();
    owner.release_after_containment(proof).await.unwrap();
    assert!(owner.client.debt_ledger().unwrap().replacement_ready());
    let commands = log.lock().unwrap().clone();
    let disposals: Vec<_> = commands
        .iter()
        .filter(|item| item["method"] == "Target.disposeBrowserContext")
        .collect();
    assert_eq!(disposals.len(), 1);
    assert_eq!(
        disposals[0]["params"],
        json!({"browserContextId":"owned-context"})
    );
    connection.close().await;
    server.abort();
}

#[tokio::test]
async fn malformed_peer_inventory_preserves_owner_and_never_releases_phase_two() {
    for mode in ["peer-malformed", "peer-duplicate"] {
        let (owner, _notices, log, _emit, server, _broker, connection) =
            fixture_with_explicit_context_ownership(mode, true, true).await;
        owner.seal();
        owner.drain().await.unwrap();
        owner.prepare_peer_context_retirement().await.unwrap();
        assert!(owner.confirm_peer_context_retirement().await.is_err());
        assert!(!owner.cleanup_outcome().unwrap().owned_resources_contained);
        assert!(!owner.client.debt_ledger().unwrap().replacement_ready());
        assert!(log
            .lock()
            .unwrap()
            .iter()
            .all(|item| item["method"] == "Target.getBrowserContexts"));
        connection.close().await;
        server.abort();
    }
}

#[tokio::test]
async fn borrowed_target_ownership_never_enters_peer_context_retirement() {
    let (mut owner, _notices, log, _emit, server) = fixture("normal").await;
    Arc::get_mut(&mut owner).unwrap().ownership =
        ScopeOwnership::BorrowedTargets(vec!["target".into()]);
    owner.seal();
    owner.drain().await.unwrap();
    assert!(owner.prepare_peer_context_retirement().await.is_err());
    assert!(owner.confirm_peer_context_retirement().await.is_err());
    assert!(log.lock().unwrap().is_empty());
    owner.client.close().await;
    server.abort();
}

#[tokio::test]
async fn peer_absence_never_substitutes_for_a_rejected_phase_two_ack() {
    let (owner, _notices, log, _emit, server, _broker, connection) =
        fixture_with_explicit_context_ownership("peer-release-failed", true, true).await;
    owner.seal();
    owner.drain().await.unwrap();
    owner.prepare_peer_context_retirement().await.unwrap();
    owner.confirm_peer_context_retirement().await.unwrap();
    let proof = owner.contain_owned_resources().await.unwrap();
    assert!(owner.release_after_containment(proof).await.is_err());
    assert!(!owner.cleanup_outcome().unwrap().autoattach_disabled);
    assert!(!owner.client.debt_ledger().unwrap().replacement_ready());
    assert!(!log
        .lock()
        .unwrap()
        .iter()
        .any(|item| item["method"] == "Target.disposeBrowserContext"));
    connection.close().await;
    server.abort();
}
