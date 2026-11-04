//! Ledger-level restrictive-fence controls. These do not claim a framed popup
//! receipt or custody proof; the common C0 tests cover that production path.
use super::*;
use serde_json::json;

fn prepared_stamp() -> (
    Arc<OwnerDebtLedger>,
    OperationJournalHandle,
    OperationLease,
    EvalAuthorityStamp,
) {
    let (ledger, journal, operation, window) = tests::eval_fixture();
    let (mut stamp, fence) = {
        let state = ledger.state.lock().unwrap();
        (
            state.eval_window.as_ref().unwrap().stamp.clone(),
            EvalPreparationFence {
                owner: Arc::downgrade(&ledger),
                foreign_revision: state.eval_foreign_revision,
                received: 64,
            },
        )
    };
    ledger.abandon_eval_preparation(&window);
    ledger.bind_eval_preparation(&mut stamp, &fence).unwrap();
    (ledger, journal, operation, stamp)
}

fn created(ledger: &Arc<OwnerDebtLedger>, id: i64) {
    let revision = ledger.state.lock().unwrap().eval_revision;
    let publication = ledger.observe_event_for_publication(&CdpEvent {
        method: "Runtime.executionContextCreated".into(),
        session_id: Some("page".into()),
        params: json!({"context":{"id":id,"uniqueId":"replacement", "auxData":{"isDefault":true,"frameId":"frame"}}}),
    });
    assert!(
        publication.is_none(),
        "legacy raw publication semantics changed"
    );
    assert_eq!(ledger.state.lock().unwrap().eval_revision, revision);
}

fn installed() -> (
    Arc<OwnerDebtLedger>,
    OperationJournalHandle,
    OperationLease,
    EvalWindowHandle,
) {
    let (ledger, journal, operation, stamp) = prepared_stamp();
    let window = ledger
        .begin_eval_window(&journal, &operation, stamp)
        .unwrap();
    ledger.arm_eval_window(&window).unwrap();
    ledger.bind_eval_root(&window, &operation).unwrap();
    (ledger, journal, operation, window)
}

#[test]
fn prepared_stamp_created_after_wrapper_cannot_install_with_unchanged_raw_revision() {
    let (ledger, journal, operation, stamp) = prepared_stamp();
    created(&ledger, 1);
    assert!(matches!(
        ledger.begin_eval_window(&journal, &operation, stamp),
        Err(ProtocolError::ScopeUnavailable)
    ));
}

#[test]
fn prepared_window_created_before_arm_or_broker_bind_is_closed() {
    for before_arm in [true, false] {
        let (ledger, journal, operation, stamp) = prepared_stamp();
        let window = ledger
            .begin_eval_window(&journal, &operation, stamp)
            .unwrap();
        if !before_arm {
            ledger.arm_eval_window(&window).unwrap();
        }
        created(&ledger, 1);
        let result = if before_arm {
            ledger.arm_eval_window(&window)
        } else {
            ledger.bind_eval_root(&window, &operation)
        };
        assert_eq!(result, Err(ProtocolError::ScopeUnavailable));
    }
}

#[tokio::test]
async fn prepared_window_created_after_reservation_cannot_submit_original_js() {
    let (ledger, journal, _, window) = installed();
    let reservation =
        tests::eval_reservation(&ledger, &journal, EvalCommandGrant::Root(window)).await;
    created(&ledger, 1);
    assert!(matches!(
        reservation.submit(),
        Err(ProtocolError::ScopeUnavailable)
    ));
}

#[tokio::test]
async fn prepared_window_created_after_root_submit_cannot_capture_or_issue_child() {
    let (ledger, journal, root, window) = installed();
    let submitted =
        tests::eval_reservation(&ledger, &journal, EvalCommandGrant::Root(window.clone()))
            .await
            .submit()
            .unwrap();
    assert!(window.live_deadline("scope").is_some());
    assert!(ledger.capturable_eval_window("scope", "page").is_some());
    created(&ledger, 1);
    assert!(window.live_deadline("scope").is_none());
    assert!(ledger.capturable_eval_window("scope", "page").is_none());
    let child = OperationLease {
        is_callback: true,
        generation: root.generation,
        sequence: root.sequence + 1,
        deadline: root.deadline,
        cancellation: root.cancellation.clone(),
    };
    assert!(matches!(
        ledger.issue_eval_child(&window, &child),
        Err(ProtocolError::ScopeUnavailable)
    ));
    drop(submitted);
}

#[tokio::test]
async fn prepared_window_created_after_child_reservation_cannot_consume_child() {
    let (ledger, journal, root, window) = installed();
    let submitted =
        tests::eval_reservation(&ledger, &journal, EvalCommandGrant::Root(window.clone()))
            .await
            .submit()
            .unwrap();
    let (_child, child_journal, permit) = tests::eval_child(&ledger, &root, &window);
    assert!(ledger.check_eval_input(&permit).is_ok());
    let reservation =
        tests::eval_reservation(&ledger, &child_journal, EvalCommandGrant::Child(permit)).await;
    created(&ledger, 2);
    assert!(matches!(
        reservation.submit(),
        Err(ProtocolError::ScopeUnavailable)
    ));
    drop(submitted);
}

#[tokio::test]
async fn unprepared_window_keeps_legacy_created_only_raw_behavior() {
    let (ledger, journal, _, window) = tests::eval_fixture();
    created(&ledger, 1);
    let reservation =
        tests::eval_reservation(&ledger, &journal, EvalCommandGrant::Root(window)).await;
    assert!(reservation.submit().is_ok());
}

#[test]
fn prepared_marker_rejects_foreign_owner_and_later_origin_even_after_owner_disappears() {
    let (ledger, journal, operation, stamp) = prepared_stamp();
    ledger.state.lock().unwrap().eval_maximum_initializer_origin = 65;
    assert!(matches!(
        ledger.begin_eval_window(&journal, &operation, stamp),
        Err(ProtocolError::ScopeUnavailable)
    ));
    let (ledger, _journal, _operation, mut stamp) = prepared_stamp();
    stamp.preparation = None;
    let foreign = OwnerDebtLedger::new(7, "scope".into());
    let fence = EvalPreparationFence {
        owner: Arc::downgrade(&foreign),
        foreign_revision: 0,
        received: 64,
    };
    assert_eq!(
        ledger.bind_eval_preparation(&mut stamp, &fence),
        Err(ProtocolError::StaleScope)
    );
}

#[test]
fn unproven_progress_is_foreign_and_keeps_raw_revision_and_revocation() {
    let (ledger, _journal, _operation, _window) = tests::eval_fixture();
    let before = ledger.state.lock().unwrap().eval_revision;
    ledger.with_eval_popup_progress(None, || ((), true));
    let state = ledger.state.lock().unwrap();
    assert_eq!(state.eval_revision, before + 1);
    assert_eq!(state.eval_foreign_revision, 1);
    assert_eq!(state.eval_maximum_initializer_origin, 0);
    assert!(state.eval_window.as_ref().unwrap().revoked);
}

#[test]
fn preparation_foreign_counter_exhaustion_never_wraps_to_valid_evidence() {
    let (ledger, _, _, _) = prepared_stamp();
    ledger.state.lock().unwrap().eval_foreign_revision = u64::MAX;
    ledger.invalidate_eval_authority();
    let state = ledger.state.lock().unwrap();
    assert_eq!(state.eval_foreign_revision, u64::MAX);
    assert!(state.integrity_lost);
}
