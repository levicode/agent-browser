// New reset/restore helper boundaries. Reuse the constructor's strict CDP peer
// and real old-context dispose/phase-two ACKs; no cleanup flags are invented.
use super::*;

fn cleaned_owner(manager: crate::native::browser::BrowserManager) -> OwnedBrowser {
    let identity_scope = "old-scope".to_owned();
    let context_id = "old-context".to_owned();
    OwnedBrowser {
        targets: crate::native::client_targets::ClientTargets::new_managed(
            context_id.clone(),
            identity_scope.clone(),
        ),
        page_state: Arc::new(crate::native::client_page::ClientPageState::new(
            identity_scope.clone(),
            context_id.clone(),
        )),
        ui: Arc::new(crate::native::client_ui::UiGate::default()),
        manager,
        context_id,
        owns_context: true,
        identity_scope,
        runtime: None,
        replacement_actions: None,
        replacement_routes: None,
        disconnected_routes: None,
        reconnect_proof: None,
        persistent_probe: Default::default(),
        borrowed_targets: None,
        browser_tenure: "retained-test-browser".into(),
    }
}

#[tokio::test]
async fn replacement_inventory_rejects_foreign_context_without_attach_or_disposal() {
    let (manager, old, peer) = retained_manager(true).await;
    let mut owner = cleaned_owner(manager);
    let old_client = owner.manager.client.clone();
    let baseline = peer.commands.lock().unwrap().len();
    let (_cancel, mut op) = operation();
    op.sequence = 2;
    let before = owner.interop_replacement_inventory(&op).await.unwrap();
    assert!(before.contains("host-context"));
    assert_eq!(
        owner
            .replace_cleaned_interop_context(&op, &before, "host-context", "pw-page")
            .await
            .err(),
        Some(ProtocolError::PolicyDenied)
    );
    assert!(Arc::ptr_eq(&old_client, &owner.manager.client));
    assert!(old.replacement_ready());
    assert_eq!(owner.context_id, "old-context");
    owner.close().await.unwrap();
    let commands = peer.commands.lock().unwrap()[baseline..].to_vec();
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0]["method"], "Target.getBrowserContexts");
    joined(peer).await;
}

#[tokio::test]
async fn replacement_inventory_requires_original_phase_two_without_clearing_owner() {
    let (manager, old, peer) = retained_manager(false).await;
    let mut owner = cleaned_owner(manager);
    let old_client = owner.manager.client.clone();
    let baseline = peer.commands.lock().unwrap().len();
    let (_cancel, mut op) = operation();
    op.sequence = 2;
    assert_eq!(
        owner.interop_replacement_inventory(&op).await.err(),
        Some(ProtocolError::CleanupFailed)
    );
    assert!(Arc::ptr_eq(&old_client, &owner.manager.client));
    assert!(!old.replacement_ready());
    assert_eq!(peer.commands.lock().unwrap().len(), baseline);
    owner
        .manager
        .client
        .send_owner_cleanup(
            Some(old.clone()),
            crate::native::client_debt::OwnerCleanupCommand::DisableAutoAttach,
            op.deadline,
        )
        .await
        .unwrap();
    assert!(old.replacement_ready());
    owner.close().await.unwrap();
    joined(peer).await;
}

#[tokio::test]
async fn replacement_cancellation_before_and_after_validation_retains_exact_custody() {
    for mode in [Mode::HoldBeforeIdentity, Mode::HoldAfterAttach] {
        let (manager, old, mut peer) = retained_manager_with_mode(true, mode).await;
        let mut owner = cleaned_owner(manager);
        let old_client = owner.manager.client.clone();
        let baseline = peer.commands.lock().unwrap().len();
        let (cancel, mut op) = operation();
        op.sequence = 2;
        let before = owner.interop_replacement_inventory(&op).await.unwrap();
        let task = tokio::spawn(async move {
            let error = owner
                .replace_cleaned_interop_context(&op, &before, "pw-context", "pw-page")
                .await
                .err();
            (error, owner)
        });
        tokio::time::timeout(Duration::from_secs(2), peer.held.recv())
            .await
            .unwrap()
            .unwrap();
        cancel.send_replace(CancelSignal::Requested);
        let (error, mut owner) = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(error, Some(ProtocolError::Cancelled));
        let validated = mode == Mode::HoldAfterAttach;
        assert_eq!(owner.owns_context, validated);
        assert_eq!(owner.context_id.is_empty(), !validated);
        assert!(owner.runtime.is_none());
        assert!(old.replacement_ready());
        assert!(!Arc::ptr_eq(&old_client, &owner.manager.client));
        let debt = owner.manager.client.debt_ledger().unwrap();
        assert_eq!(
            debt.bound_context().as_deref(),
            validated.then_some("pw-context")
        );
        assert_ne!(owner.identity_scope, "old-scope");
        assert!(old_client
            .send_command("Target.getBrowserContexts", Some(json!({})), None)
            .await
            .is_err());
        // The late CDP response cannot resume the cancelled helper. Its exact
        // native owner, not a detached waiter, must now finish physical cleanup.
        assert_eq!(debt.snapshot().outstanding_commands, 1);
        peer.release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while debt.snapshot().outstanding_commands != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the actual held metadata response must settle before physical close");
        owner.close().await.unwrap();
        assert!(owner.runtime.is_none());
        let commands = peer.commands.lock().unwrap()[baseline..].to_vec();
        let disposals: Vec<_> = commands
            .iter()
            .filter(|request| request["method"] == "Target.disposeBrowserContext")
            .collect();
        assert_eq!(disposals.len(), usize::from(validated));
        for request in disposals {
            assert_eq!(request["params"]["browserContextId"], "pw-context");
        }
        assert_eq!(
            commands
                .iter()
                .any(|request| request["method"] == "Target.attachToTarget"),
            validated
        );
        assert!(commands.iter().all(|request| !matches!(
            request["method"].as_str(),
            Some(
                "Browser.close"
                    | "Target.closeTarget"
                    | "Target.createBrowserContext"
                    | "Target.createTarget"
                    | "Page.navigate"
            )
        )));
        joined(peer).await;
    }
}
