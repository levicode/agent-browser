//! Fresh continuation starts only after the real original retained read settles.
use super::*;
use crate::native::client_browser::{
    protected_read_receipt_eligible, settle_observation_dispatch, settle_protected_read,
    settle_trace_screenshot,
};
use crate::native::client_protocol::{Effects, ObserveContinuationDescriptor, ScopeState};
use crate::native::client_session::ClientSession;
use crate::native::client_tasks::RetainedTasks;

#[path = "client_observe_continuation_bridge_tests.rs"]
mod bridge_tests;

fn request(continuation: Option<ObserveContinuationDescriptor>) -> DispatchRequest {
    DispatchRequest::Observe(ObserveRequest {
        continuation,
        options: ObserveFlags::default(),
        test_id_attribute: "data-testid".into(),
        secure_field_selector: "input[type=password]".into(),
    })
}
fn args(ticket: &ObserveContinuationDescriptor) -> serde_json::Map<String, Value> {
    json!({"identityScope":"scope","options":{},"testIdAttribute":"data-testid","secureFieldSelector":"input[type=password]","continuation":ticket}).as_object().unwrap().clone()
}
struct Settled {
    broker: Arc<ClientSession>,
    settlement: Mutex<Option<crate::native::client_session::ObservationSettlement>>,
    dispatch: Arc<ObservationDispatch>,
    retained: RetainedTasks,
    client: Arc<CdpClient>,
    targets: Arc<ClientTargets>,
    ledger: Arc<OwnerDebtLedger>,
    blobs: Arc<BlobStore>,
    ui: Arc<UiGate>,
    scope: BlobScope,
    policy: ReadPolicy,
    samples: Arc<AtomicUsize>,
    log: Arc<Mutex<Vec<Value>>>,
    peer: tokio::task::JoinHandle<()>,
    _readonly_replies: tokio::sync::mpsc::UnboundedSender<Value>,
    deadline: Instant,
}
impl Settled {
    fn offer(&self) -> Option<ObserveContinuationDescriptor> {
        self.settlement
            .lock()
            .unwrap()
            .take()
            .and_then(|proof| self.dispatch.offer_observe_continuation(proof))
    }

    fn context(&self) -> DispatchContext {
        let gate = Arc::new(ExecutionGate::default());
        DispatchContext {
            query_authority: None,
            #[cfg(feature = "acceptance-faults")]
            faults: Arc::new(crate::native::client_test_faults::FaultController::default()),
            attachment: self.targets.owned_target("target").unwrap(),
            page: BrowserExecutionLease {
                client: self.client.clone(),
                page_session_id: "session".into(),
                target_id: "target".into(),
                identity_scope: "scope".into(),
                permit: gate.enter(false).unwrap(),
                targets: self.targets.clone(),
            },
            ui: self.ui.clone(),
            blobs: self.blobs.clone(),
            scope: self.scope.clone(),
            policy: self.policy.clone(),
        }
    }
    async fn finish(self) {
        assert!(self.retained.drain().await.is_ok());
        self.client.close().await;
        self.peer.await.unwrap();
    }
}
async fn settled(race: Race) -> Settled {
    settled_with_cancel(race, false).await
}
async fn settled_with_cancel(race: Race, cancel_before_settle: bool) -> Settled {
    let broker = Arc::new(ClientSession::new());
    let f = Fixture::new_mode_with_broker(race, true, Some(broker.clone())).await;
    let Fixture {
        context,
        operation,
        journal,
        ledger,
        dispatch,
        samples,
        log,
        peer,
        readonly_replies,
        ..
    } = f;
    let deadline = operation.deadline;
    let client = context.page.client.clone();
    let targets = context.page.targets.clone();
    let blobs = context.blobs.clone();
    let ui = context.ui.clone();
    let scope = context.scope.clone();
    let policy = context.policy.clone();
    let retained = RetainedTasks::default();
    let run = dispatch.clone();
    let receipt = journal.clone();
    let cancel = operation.cancellation.clone();
    let receive = retained
        .start_operation_prepared(
            "scope".into(),
            targets.clone(),
            broker.clone(),
            journal,
            cancel,
            move || {
                let req = request(None);
                let eligible = protected_read_receipt_eligible(&req);
                let prepared = run.prepare(context, req, operation)?;
                Ok(async move {
                    let task = run.start_prepared(prepared);
                    let output = task.result.await;
                    let cleanup = task.join.await;
                    assert!(matches!(cleanup, Ok(Ok(()))));
                    let (outcome, dirty) = settle_observation_dispatch(output, cleanup, true);
                    let (outcome, dirty) = settle_trace_screenshot(outcome, dirty, false, &receipt);
                    settle_protected_read(outcome, dirty, eligible, &receipt)
                })
            },
        )
        .await
        .unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(3), receive)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.result, Err(ProtocolError::StaleScope));
    assert_eq!(outcome.effects, Effects::NotDispatched);
    assert!(!broker.observation_operation_settled(OperationKey {
        generation: 1,
        operation_seq: 1
    }));
    if cancel_before_settle {
        broker.cancel(1, 1).unwrap();
    }
    let (health, settlement) = broker
        .settle_with_observation_proof(1, 1, outcome.effects, outcome.retention.as_ref())
        .unwrap();
    assert_eq!(health, ScopeState::Usable);
    if cancel_before_settle {
        assert!(settlement.is_none());
    }
    retained.fix_operation_result(OperationKey {
        generation: 1,
        operation_seq: 1,
    });
    assert!(broker.observation_operation_settled(OperationKey {
        generation: 1,
        operation_seq: 1
    }));
    no_protected_read(&log.lock().unwrap());
    assert!(dispatch.refs.lock().unwrap().ref_ids().is_empty());
    Settled {
        settlement: Mutex::new(settlement),
        broker,
        dispatch,
        retained,
        client,
        targets,
        ledger,
        blobs,
        ui,
        scope,
        policy,
        samples,
        log,
        peer,
        _readonly_replies: readonly_replies,
        deadline,
    }
}
#[tokio::test]
async fn continuation_recovers_exact_settled_other_attach_race_with_fresh_operation() {
    let s = settled(Race::AttachOtherTwice).await;
    assert_eq!(s.samples.load(Ordering::SeqCst), 2);
    let ticket = s
        .offer()
        .expect("clean initial race must authorize one fresh read");
    assert!(s
        .broker
        .settle_with_observation_proof(1, 1, Effects::NotDispatched, None)
        .is_err());
    let cap = s
        .dispatch
        .observe_deadline_cap(1, 2, &args(&ticket))
        .unwrap();
    assert_eq!(cap, Some(s.deadline));
    let op = s
        .broker
        .admit_callback_capped(1, 2, 60000, None, Ok(cap))
        .unwrap();
    assert!(s.broker.start(1, 2).unwrap());
    assert_eq!(op.deadline, s.deadline);
    let journal = s
        .ledger
        .operation(
            OperationKey {
                generation: 1,
                operation_seq: 2,
            },
            "target".into(),
            "session".into(),
        )
        .unwrap();
    journal.bind_operation(&op).unwrap();
    let prepared = s
        .dispatch
        .prepare(s.context(), request(Some(ticket.clone())), op)
        .unwrap();
    assert_eq!(prepared.operation.deadline, s.deadline);
    assert_eq!(prepared.semantic_operation.deadline, s.deadline);
    assert_eq!(
        prepared.semantic_operation.generation,
        prepared.operation.generation
    );
    assert_eq!(
        prepared.semantic_operation.sequence,
        prepared.operation.sequence
    );
    assert!(prepared
        .semantic_operation
        .cancellation
        .same_channel(&prepared.operation.cancellation));
    let cleanup = AtomicBool::new(false);
    let frames = journal
        .scope(s.dispatch.initial_observe_frames(
            &prepared.context,
            &prepared.operation,
            prepared.capture.as_ref(),
            prepared.retirement_fence,
            &cleanup,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(s.samples.load(Ordering::SeqCst), 3);
    assert!(!cleanup.load(Ordering::SeqCst));
    assert!(prepared
        .capture
        .as_ref()
        .unwrap()
        .continuation
        .lock()
        .unwrap()
        .is_none());
    assert!(s
        .dispatch
        .observe_deadline_cap(1, 2, &args(&ticket))
        .is_err());
    no_protected_read(&s.log.lock().unwrap());
    assert!(s.dispatch.refs.lock().unwrap().ref_ids().is_empty());
    drop(prepared);
    drop(journal);
    s.broker.settle(1, 2, Effects::Completed).unwrap();
    s.finish().await;
}
#[tokio::test]
async fn continuation_rejects_changed_options_once_without_any_read() {
    let s = settled(Race::AttachOtherTwice).await;
    let ticket = s.offer().unwrap();
    let before = s.log.lock().unwrap().len();
    let mut changed = args(&ticket);
    changed.insert("options".into(), json!({"pixels":true}));
    assert!(s.dispatch.observe_deadline_cap(1, 2, &changed).is_err());
    assert!(s
        .dispatch
        .observe_deadline_cap(1, 2, &args(&ticket))
        .is_err());
    assert_eq!(before, s.log.lock().unwrap().len());
    s.finish().await;
}
#[tokio::test]
async fn continuation_rejects_replaced_attachment_before_any_read() {
    let s = settled(Race::AttachOtherTwice).await;
    let ticket = s.offer().unwrap();
    let before = s.log.lock().unwrap().len();
    s.targets.detach("target").unwrap();
    ready(&s.targets).await;
    assert!(s
        .dispatch
        .observe_deadline_cap(1, 2, &args(&ticket))
        .is_err());
    assert_eq!(before, s.log.lock().unwrap().len());
    s.finish().await;
}
#[tokio::test]
async fn continuation_rejects_owner_replacement_after_reservation_before_prepare() {
    let s = settled(Race::AttachOtherTwice).await;
    let ticket = s.offer().unwrap();
    let cap = s.dispatch.observe_deadline_cap(1, 2, &args(&ticket));
    let op = s
        .broker
        .admit_callback_capped(1, 2, 60_000, None, cap)
        .unwrap();
    assert!(s.broker.start(1, 2).unwrap());
    let before = s.log.lock().unwrap().len();
    s.targets.detach("target").unwrap();
    ready(&s.targets).await;
    assert_eq!(
        s.dispatch
            .prepare(s.context(), request(Some(ticket.clone())), op)
            .err(),
        Some(ProtocolError::StaleScope)
    );
    assert_eq!(s.log.lock().unwrap().len(), before);
    assert_eq!(s.samples.load(Ordering::SeqCst), 2);
    assert!(s.dispatch.refs.lock().unwrap().ref_ids().is_empty());
    s.broker.settle(1, 2, Effects::NotDispatched).unwrap();
    assert!(s
        .dispatch
        .observe_deadline_cap(1, 3, &args(&ticket))
        .is_err());
    s.finish().await;
}
#[tokio::test]
async fn continuation_rejects_publication_retirement() {
    let s = settled(Race::AttachOtherTwice).await;
    let ticket = s.offer().unwrap();
    s.dispatch.retire_interaction().await.unwrap();
    assert!(s
        .dispatch
        .observe_deadline_cap(1, 2, &args(&ticket))
        .is_err());
    s.finish().await;
}
#[tokio::test]
async fn continuation_cannot_chain_a_second_two_sample_race() {
    let s = settled(Race::AttachOtherContinuous).await;
    let ticket = s.offer().unwrap();
    let cap = s.dispatch.observe_deadline_cap(1, 2, &args(&ticket));
    let op = s
        .broker
        .admit_callback_capped(1, 2, 60000, None, cap)
        .unwrap();
    assert!(s.broker.start(1, 2).unwrap());
    let journal = s
        .ledger
        .operation(
            OperationKey {
                generation: 1,
                operation_seq: 2,
            },
            "target".into(),
            "session".into(),
        )
        .unwrap();
    journal.bind_operation(&op).unwrap();
    let prepared = s
        .dispatch
        .prepare(s.context(), request(Some(ticket)), op)
        .unwrap();
    let cleanup = AtomicBool::new(false);
    assert_eq!(
        journal
            .scope(s.dispatch.initial_observe_frames(
                &prepared.context,
                &prepared.operation,
                prepared.capture.as_ref(),
                prepared.retirement_fence,
                &cleanup,
                None
            ))
            .await
            .err(),
        Some(ProtocolError::StaleScope)
    );
    assert_eq!(s.samples.load(Ordering::SeqCst), 4);
    assert!(prepared
        .capture
        .as_ref()
        .unwrap()
        .continuation
        .lock()
        .unwrap()
        .is_none());
    drop(prepared);
    drop(journal);
    let (health, proof) = s
        .broker
        .settle_with_observation_proof(1, 2, Effects::NotDispatched, None)
        .unwrap();
    assert_eq!(health, ScopeState::Usable);
    assert!(s
        .dispatch
        .offer_observe_continuation(proof.expect("second clean settlement still has a real proof"))
        .is_none());
    s.finish().await;
}

#[tokio::test]
async fn continuation_cancel_between_failure_and_settlement_has_no_offer() {
    let s = settled_with_cancel(Race::AttachOtherTwice, true).await;
    assert!(s.offer().is_none());
    s.finish().await;
}
#[tokio::test]
async fn continuation_reservation_is_spent_on_cancel_before_prepare() {
    let s = settled(Race::AttachOtherTwice).await;
    let ticket = s.offer().unwrap();
    let cap = s.dispatch.observe_deadline_cap(1, 2, &args(&ticket));
    let op = s
        .broker
        .admit_callback_capped(1, 2, 60000, None, cap)
        .unwrap();
    s.broker.cancel(1, 2).unwrap();
    drop(op);
    s.broker.settle(1, 2, Effects::NotDispatched).unwrap();
    assert!(s
        .dispatch
        .observe_deadline_cap(1, 3, &args(&ticket))
        .is_err());
    assert_eq!(s.samples.load(Ordering::SeqCst), 2);
    s.finish().await;
}
#[tokio::test]
async fn continuation_expiry_cannot_renew_original_budget() {
    let s = settled(Race::AttachOtherTwice).await;
    let ticket = s.offer().unwrap();
    {
        let authority = s.dispatch.captures.lock().unwrap();
        authority.latest[0]
            .continuation
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .deadline = Instant::now();
    }
    assert_eq!(
        s.dispatch.observe_deadline_cap(1, 2, &args(&ticket)).err(),
        Some(ProtocolError::DeadlineExceeded)
    );
    assert!(s
        .dispatch
        .observe_deadline_cap(1, 3, &args(&ticket))
        .is_err());
    assert_eq!(s.samples.load(Ordering::SeqCst), 2);
    s.finish().await;
}
#[tokio::test]
async fn continuation_does_not_offer_for_held_debt_or_replaced_owner() {
    for race in [
        Race::HeldRelease,
        Race::Replacement,
        Race::AttachOtherHeldRelease,
    ] {
        let s = settled(race).await;
        assert!(s.settlement.lock().unwrap().is_some());
        assert!(s.offer().is_none());
        s.finish().await;
    }
}

#[tokio::test]
async fn continuation_new_object_obligation_after_offer_denies_before_read() {
    let s = settled(Race::AttachOtherTwice).await;
    let ticket = s.offer().unwrap();
    let op = s.broker.admit(1, 2, 1000).unwrap();
    assert!(s.broker.start(1, 2).unwrap());
    let journal = s
        .ledger
        .operation(
            OperationKey {
                generation: 1,
                operation_seq: 2,
            },
            "target".into(),
            "session".into(),
        )
        .unwrap();
    journal.bind_operation(&op).unwrap();
    let params = json!({"backendNodeId":101,"objectGroup":"post-offer-owner"});
    let pending = journal
        .register_remote_obligation("DOM.resolveNode", Some(&params), Some("session"))
        .unwrap()
        .submit()
        .unwrap();
    let debt = s.ledger.snapshot();
    assert!(debt.object_debt > 0 && debt.outstanding_commands > 0);
    let before = s.log.lock().unwrap().len();
    assert!(s
        .dispatch
        .observe_deadline_cap(1, 3, &args(&ticket))
        .is_err());
    assert_eq!(s.log.lock().unwrap().len(), before);
    drop(pending);
    drop(journal);
    drop(op);
    s.broker.settle(1, 2, Effects::NotDispatched).unwrap();
    s.finish().await;
}

#[tokio::test]
async fn continuation_rejected_original_cleanup_has_no_offer() {
    let broker = Arc::new(ClientSession::new());
    let Fixture {
        context,
        operation,
        journal,
        ledger,
        dispatch,
        samples,
        log,
        peer,
        readonly_replies,
        release_fence_receipt,
        ..
    } = Fixture::new_mode_with_broker(Race::ReleaseError, true, Some(broker.clone())).await;
    let client = context.page.client.clone();
    let targets = context.page.targets.clone();
    let retained = RetainedTasks::default();
    let run = dispatch.clone();
    let receipt = journal.clone();
    let cancel = operation.cancellation.clone();
    let receive = retained
        .start_operation_prepared(
            "scope".into(),
            targets,
            broker.clone(),
            journal,
            cancel,
            move || {
                let req = request(None);
                let eligible = protected_read_receipt_eligible(&req);
                let prepared = run.prepare(context, req, operation)?;
                Ok(async move {
                    let task = run.start_prepared(prepared);
                    let output = task.result.await;
                    let cleanup = task.join.await;
                    let (outcome, dirty) = settle_observation_dispatch(output, cleanup, true);
                    settle_protected_read(outcome, dirty, eligible, &receipt)
                })
            },
        )
        .await
        .unwrap();
    let replies = tokio::time::timeout(Duration::from_secs(3), release_fence_receipt.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(
        replies[0].get("error").is_some(),
        "real cleanup reply must be rejected"
    );
    {
        let requests = log.lock().unwrap();
        let releases: Vec<_> = requests
            .iter()
            .filter(|row| row["method"] == "Runtime.releaseObjectGroup")
            .collect();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0]["sessionId"], "session");
        assert_eq!(replies[0]["sessionId"], releases[0]["sessionId"]);
        assert_eq!(replies[0]["id"], releases[0]["id"]);
        assert_eq!(replies[0]["error"]["code"], -32000);
        assert!(replies[0].get("result").is_none());
    }
    let outcome = tokio::time::timeout(Duration::from_secs(3), receive)
        .await
        .unwrap()
        .unwrap();
    let key = OperationKey {
        generation: 1,
        operation_seq: 1,
    };
    assert_eq!(
        ledger.operation_has_rejected_cleanup(key, "scope"),
        Ok(true)
    );
    assert_eq!(outcome.result, Err(ProtocolError::StaleScope));
    assert_eq!(outcome.effects, Effects::NotDispatched);
    let (health, proof) = broker
        .settle_with_observation_proof(1, 1, outcome.effects, outcome.retention.as_ref())
        .unwrap();
    assert_eq!(health, ScopeState::Usable);
    retained.fix_operation_result(key);
    assert!(broker.observation_operation_settled(key));
    let before_offer = log.lock().unwrap().clone();
    assert!(dispatch
        .offer_observe_continuation(proof.expect("actual usable broker settlement"))
        .is_none());
    assert_eq!(samples.load(Ordering::SeqCst), 1);
    no_protected_read(&log.lock().unwrap());
    assert!(dispatch.refs.lock().unwrap().ref_ids().is_empty());
    assert!(retained.drain().await.is_ok());
    assert_eq!(*log.lock().unwrap(), before_offer);
    assert!(!before_offer.iter().any(|row| row["method"]
        .as_str()
        .is_some_and(|method| method.starts_with("Input."))));
    let debt = ledger.snapshot();
    assert!(!debt.integrity_lost);
    assert_eq!(
        (debt.input_debt, debt.object_debt, debt.outstanding_commands),
        (0, 1, 1)
    );
    assert_eq!(
        ledger.operation_has_rejected_cleanup(key, "scope"),
        Ok(true)
    );
    assert_eq!(broker.health().unwrap(), (1, ScopeState::Usable));
    client.close().await;
    peer.await.unwrap();
    drop(readonly_replies);
}
