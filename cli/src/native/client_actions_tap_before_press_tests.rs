use super::super::super::{client_protocol::ScopeState, client_session::ClientSession};
use super::*;

async fn exercise(mode: &'static str) -> (Result<Value, ActionFailure>, Vec<Value>, ScopeState) {
    let broker = Arc::new(ClientSession::new());
    let mut f = fixture_scoped_with_action_broker(mode, mode, Some(broker.clone())).await;
    let ledger = client_debt::OwnerDebtLedger::new(1, mode.into());
    ledger.bind_context("context").unwrap();
    f.page.client.install_debt_ledger(ledger.clone()).unwrap();
    f.page.client = f.page.client.owner_view(ledger.clone()).unwrap();
    let (owner, state, _notices) = preparation_settlement_owner(&f, broker.clone()).await;
    f.op = broker.admit(1, 1, 5_000).unwrap();
    assert!(broker.start(1, 1).unwrap());
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
    journal.bind_operation(&f.op).unwrap();
    f.log.lock().unwrap().clear();
    f.replies.lock().unwrap().clear();
    let result = journal.scope(ClientActions::default().execute(
        ActionContext { realm_authority: ActionRealmAuthority::Enrolled(&owner), page_state: &state, ..f.context() },
        "browser.perform", &json!({"identityScope":mode,"ref":{"id":"@e1","revision":"1"},"action":{"kind":"tap"}}),
    )).await;
    let effects = result
        .as_ref()
        .map(|_| Effects::Completed)
        .unwrap_or_else(|failure| failure.effects);
    let scope = broker.settle(1, 1, effects).unwrap();
    if mode == "preparation-tap-before-press-detached" {
        assert_eq!(journal.snapshot().input_debt, 0);
        assert_eq!(journal.snapshot().object_debt, 0);
        assert!(!journal.snapshot().integrity_lost);
        assert_eq!(state.mouse_state().unwrap().buttons, 0);
        let next = broker.admit(1, 2, 1_000).unwrap();
        assert!(broker.start(1, 2).unwrap());
        assert_eq!(
            broker.settle(1, 2, Effects::NotDispatched).unwrap(),
            ScopeState::Usable
        );
        drop(next);
    }
    let requests = f.log.lock().unwrap().clone();
    // Deliberately injected cleanup/transport failures can retire enrollment.
    // This is resource disposal, not a replacement result for the action above.
    let _ = owner.close().await;
    (result, requests, scope)
}

#[tokio::test]
async fn exact_tap_detached_after_hover_returns_only_a_settled_no_press_receipt() {
    let (result, requests, scope) = exercise("preparation-tap-before-press-detached").await;
    let failure = result.unwrap_err();
    assert_eq!(failure.error, ProtocolError::StaleReference);
    assert_eq!(
        failure.reason,
        Some(ActionReason::TapTargetReplacedBeforePress)
    );
    assert_eq!(failure.effects, Effects::Completed);
    assert!(!failure.cleanup_failed);
    assert_eq!(scope, ScopeState::Usable);
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["method"] == "DOM.resolveNode")
            .count(),
        1,
        "never resolve another target"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["method"] == "Input.dispatchMouseEvent"
                && r["params"]["type"] == "mouseMoved")
            .count(),
        1
    );
    assert!(!requests.iter().any(
        |r| r["method"] == "Input.dispatchMouseEvent" && r["params"]["type"] == "mousePressed"
    ));
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["method"] == "Runtime.releaseObject"
                && r["params"]["objectId"] == "exact-node")
            .count(),
        1
    );
}

#[tokio::test]
async fn connected_tap_revalidates_the_exact_receiver_before_its_single_press() {
    let (result, requests, scope) = exercise("preparation-tap-before-press-connected").await;
    result.unwrap();
    assert_eq!(scope, ScopeState::Usable);
    let index = |kind: &str| {
        requests
            .iter()
            .position(|r| r["method"] == "Input.dispatchMouseEvent" && r["params"]["type"] == kind)
            .unwrap()
    };
    let probe = requests
        .iter()
        .position(|r| r["params"]["functionDeclaration"] == TAP_RECEIVER_AFTER_HOVER)
        .unwrap();
    assert!(
        index("mouseMoved") < probe
            && probe < index("mousePressed")
            && index("mousePressed") < index("mouseReleased")
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["method"] == "Input.dispatchMouseEvent")
            .count(),
        3
    );
    assert!(requests[probe..index("mousePressed")]
        .iter()
        .any(|r| r["params"]["functionDeclaration"]
            .as_str()
            .is_some_and(|source| source.contains("if(blocker(doc,this,x,y)!==null)"))));
}

#[tokio::test]
async fn uncertain_hover_probe_cleanup_or_authority_never_authorizes_relocation() {
    for mode in [
        "preparation-tap-before-press-move-error",
        "preparation-tap-before-press-probe-error",
        "preparation-tap-before-press-release-error",
        "preparation-tap-before-press-cancel",
        "preparation-tap-before-press-retired",
    ] {
        let (result, requests, scope) = exercise(mode).await;
        let failure = result.unwrap_err();
        assert_eq!(failure.reason, None, "{mode}");
        assert_eq!(failure.effects, Effects::Unknown, "{mode}");
        assert_eq!(scope, ScopeState::Quarantined, "{mode}");
        assert!(
            !requests
                .iter()
                .any(|r| r["method"] == "Input.dispatchMouseEvent"
                    && r["params"]["type"] == "mousePressed"),
            "{mode}"
        );
        if mode.ends_with("release-error") {
            assert!(failure.cleanup_failed);
        }
    }
}

#[tokio::test]
async fn uncertain_press_is_never_replayed_or_relabelled_as_prepress_refusal() {
    let (result, requests, scope) = exercise("preparation-tap-before-press-press-error").await;
    let failure = result.unwrap_err();
    assert_eq!(failure.reason, None);
    assert_eq!(failure.effects, Effects::Unknown);
    assert_eq!(scope, ScopeState::Quarantined);
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["method"] == "Input.dispatchMouseEvent"
                && r["params"]["type"] == "mousePressed")
            .count(),
        1
    );
}

#[test]
fn tap_receipt_is_terminal_and_cannot_hide_later_authority_cleanup_or_input() {
    let d = Dispatch::default();
    d.mark();
    d.tap_before_press_certified.store(true, Ordering::SeqCst);
    assert_eq!(
        d.failure(ProtocolError::StaleReference).reason,
        Some(ActionReason::TapTargetReplacedBeforePress)
    );
    for error in [
        ProtocolError::Cancelled,
        ProtocolError::StaleScope,
        ProtocolError::BrowserFailure,
        ProtocolError::CleanupFailed,
    ] {
        let failure = d.failure(error);
        assert_eq!(failure.reason, None);
        assert_eq!(failure.effects, Effects::Unknown);
    }
    d.cleanup.store(true, Ordering::SeqCst);
    assert_eq!(d.failure(ProtocolError::StaleReference).reason, None);
    assert_eq!(
        d.failure(ProtocolError::StaleReference).effects,
        Effects::Unknown
    );
    d.cleanup.store(false, Ordering::SeqCst);
    d.mark();
    assert_eq!(d.failure(ProtocolError::StaleReference).reason, None);
    assert_eq!(
        d.failure(ProtocolError::StaleReference).effects,
        Effects::Unknown
    );
}
