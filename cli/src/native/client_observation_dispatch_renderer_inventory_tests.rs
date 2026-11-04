//! Shape controls for the single application renderer optimization. These use
//! real registry attachment tenures. Mutated snapshot fields are fed only to
//! the pure predicate, never to an operation or a browser authority constructor.
use super::*;
use crate::native::client_targets::ClientTargets;

async fn ready(registry: &Arc<ClientTargets>, target: &str, session: &str, kind: &str) {
    assert!(registry
        .attached("context", target.into(), session.into(), kind.into())
        .unwrap());
    registry.configured(target).unwrap();
    registry
        .resume_permit(target)
        .await
        .unwrap()
        .complete()
        .unwrap();
}

#[tokio::test]
async fn ready_non_renderers_keep_one_renderer_but_duplicate_sessions_refuse() {
    let registry = ClientTargets::new("context".into(), "scope".into());
    ready(&registry, "main", "main-session", "page").await;
    for (target, kind) in [
        ("worker", "worker"),
        ("service", "service_worker"),
        ("ui", "browser_ui"),
    ] {
        ready(&registry, target, &format!("{target}-session"), kind).await;
    }
    let (_, targets) = registry.inventory().unwrap();
    assert_eq!(targets.len(), 4);
    assert_eq!(single_application_renderer(&targets), Ok(true));
    // The public registry itself rejects duplicate sessions. Independently
    // check the defensive shape rule on a cloned, non-authoritative snapshot.
    assert_eq!(
        registry.attached(
            "context",
            "duplicate".into(),
            "main-session".into(),
            "worker".into()
        ),
        Err(ProtocolError::InvalidArguments)
    );
    let mut duplicate = targets.clone();
    duplicate
        .iter_mut()
        .find(|t| t.target_id == "worker")
        .unwrap()
        .session_id = "main-session".into();
    assert_eq!(
        single_application_renderer(&duplicate),
        Err(ProtocolError::StaleScope)
    );
}

#[tokio::test]
async fn unready_non_renderer_is_an_error_not_an_optimization_decline() {
    let registry = ClientTargets::new("context".into(), "scope".into());
    ready(&registry, "main", "main-session", "page").await;
    ready(&registry, "worker", "worker-session", "worker").await;
    let (_, targets) = registry.inventory().unwrap();
    for configured in [false, true] {
        let mut unready = targets.clone();
        let worker = unready
            .iter_mut()
            .find(|t| t.target_id == "worker")
            .unwrap();
        worker.configured = configured;
        worker.resumed = !configured;
        assert_eq!(
            single_application_renderer(&unready),
            Err(ProtocolError::ScopeUnavailable)
        );
    }
}

#[tokio::test]
async fn extra_page_or_iframe_requires_the_original_full_inventory() {
    for kind in ["page", "iframe"] {
        let registry = ClientTargets::new("context".into(), "scope".into());
        ready(&registry, "main", "main-session", "page").await;
        ready(&registry, "extra", "extra-session", kind).await;
        let (_, targets) = registry.inventory().unwrap();
        assert_eq!(single_application_renderer(&targets), Ok(false));
    }
    assert_eq!(single_application_renderer(&[]), Ok(false));
}

#[tokio::test]
async fn non_renderer_churn_still_invalidates_the_complete_phase_revision() {
    let registry = ClientTargets::new("context".into(), "scope".into());
    ready(&registry, "main", "main-session", "page").await;
    let (revision, targets, before) = registry.inventory_with_diagnostic(false).unwrap();
    let main = targets.iter().find(|t| t.target_id == "main").unwrap();
    assert_eq!(single_application_renderer(&targets), Ok(true));
    ready(&registry, "worker", "worker-session", "worker").await;
    let (_, current) = registry.inventory().unwrap();
    assert_eq!(single_application_renderer(&current), Ok(true));
    assert_eq!(
        registry
            .check_acquisition_revision(
                revision,
                before.as_ref(),
                main,
                diagnostic::FrameInventoryPass::Initial,
                false
            )
            .result,
        Err(ProtocolError::StaleScope)
    );
}

#[tokio::test]
async fn same_id_owner_replacement_does_not_reuse_a_phase_proof() {
    let registry = ClientTargets::new("context".into(), "scope".into());
    ready(&registry, "main", "main-session", "page").await;
    let (revision, targets, before) = registry.inventory_with_diagnostic(false).unwrap();
    let main = targets.iter().find(|t| t.target_id == "main").unwrap();
    registry.detach("main").unwrap();
    ready(&registry, "main", "main-session", "page").await;
    let replacement = registry.owned_target("main").unwrap();
    assert!(!main.same_attachment(&replacement));
    let (_, current) = registry.inventory().unwrap();
    assert_eq!(single_application_renderer(&current), Ok(true));
    assert_eq!(
        registry
            .check_acquisition_revision(
                revision,
                before.as_ref(),
                main,
                diagnostic::FrameInventoryPass::Initial,
                false
            )
            .result,
        Err(ProtocolError::StaleScope)
    );
}
