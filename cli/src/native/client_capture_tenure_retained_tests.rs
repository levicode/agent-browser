// Included only in client_enrollment::tests. This is deliberately a boundary
// control, NOT a complete state.capture/export or transport acceptance test.
// The mutation is a real, ACKed Page.enable on the same CDP fixture, not an
// exported storage-state transaction or a test-written journal mutation bit.
#[tokio::test]
async fn capture_mutation_then_tenure_not_export_retains_primary_and_cleanup() {
    use super::super::client_debt::{OperationKey, OwnerDebtLedger};
    use super::super::client_protocol::{Effects, ScopeState};
    use super::super::client_tasks::RetainedTasks;
    use super::super::client_transport::NativeOutcome;

    for mutated in [false, true] {
        for replaced in [false, true] {
            let f = CaptureWireFixture::new(false).await;
            let proof = f.owner.attest_capture(&f.owner.operation()).await.unwrap();
            let ledger = OwnerDebtLedger::new(1, "owned-scope".into());
            ledger.bind_context("owned-context").unwrap();
            ledger.bind_session("owned-context", "target", "initial").unwrap();
            f.owner.client.install_debt_ledger(ledger.clone()).unwrap();
            f.owner.targets.bind_eval_owner(&ledger, 1).unwrap();

            // The existing fixture performs both attestations through its real
            // reader/supervisor. Keep the original exact attachment witness.
            let original = f.owner.targets.owned_target("target").unwrap();
            let epoch = f.owner.index.lock().unwrap().application_epoch;
            let gate = f.gate(CaptureTestPoint::BeforeVerifyReturn);
            let broker = Arc::new(ClientSession::new());
            let op = broker.admit(1, 1, 40_000).unwrap();
            assert!(broker.start(1, 1).unwrap());
            let key = OperationKey { generation: 1, operation_seq: 1 };
            let journal = ledger.operation(key, "target".into(), "initial".into()).unwrap();
            journal.bind_operation(&op).unwrap();
            let tasks = RetainedTasks::default();
            let owner = f.owner.clone();
            let targets = f.owner.targets.clone();
            let prefix_count = f.requests("Page.enable").len();
            let receive = tasks.start_operation(
                "owned-scope".into(), targets.clone(), broker.clone(), journal.clone(),
                op.cancellation.clone(), async move {
                    if mutated {
                        owner.command(&op, Some("initial"), "Page.enable", json!({})).await.unwrap();
                    }
                    let result = owner.verify_capture_attestation(&proof, &op).await;
                    // Only adapt the real verification result to the retained
                    // input boundary. No mutation/cleanup/Unknown classifier is
                    // implemented here; RetainedTasks owns the promotion.
                    let effects = if result.is_ok() { Effects::Completed } else { Effects::NotDispatched };
                    (NativeOutcome { retention: None, result: result.map(|()| Value::Null), effects }, false)
                },
            ).await.unwrap();
            gate.wait_entered().await;
            assert_eq!(f.requests("Page.enable").len(), prefix_count + usize::from(mutated));
            assert_eq!(journal.snapshot().mutation_dispatched, mutated);
            assert_eq!(journal.snapshot().input_debt, 0, "prefix ACK must be reader-accounted before invalidation");

            if replaced {
                // Same public strings, NEW authoritative insertion. This is the
                // existing fixture's exact-tenure adversary, not direct epoch
                // editing, an unrelated scope change, or delayed network sleep.
                targets.detach("target").unwrap();
                targets.attached("owned-context", "target".into(), "initial".into(), "page".into()).unwrap();
                targets.configured("target").unwrap();
                targets.resume_permit("target").await.unwrap().complete().unwrap();
                assert!(!targets.owned_target("target").unwrap().same_attachment(&original));
            } else {
                assert!(targets.owned_target("target").unwrap().same_attachment(&original));
            }
            assert_eq!(f.owner.index.lock().unwrap().application_epoch, epoch);
            gate.release();
            let outcome = tokio::time::timeout(Duration::from_secs(2), receive).await.unwrap().unwrap();
            assert_eq!(outcome.result, if replaced { Err(ProtocolError::StaleScope) } else { Ok(Value::Null) });
            assert_eq!(outcome.effects, match (replaced, mutated) {
                (false, _) => Effects::Completed,
                (true, false) => Effects::NotDispatched,
                (true, true) => Effects::Unknown,
            });
            let snapshot = journal.snapshot();
            assert_eq!(snapshot.mutation_dispatched, mutated);
            assert!(!snapshot.integrity_lost);
            assert!(snapshot.local_producers_finished);
            assert_eq!((snapshot.input_debt, snapshot.object_debt), (0, 0));
            assert_eq!(tasks.drain().await, Ok(()), "Unknown here is not dirty cleanup");
            assert!(targets.operation_settlement_integrity_diagnostic(false).0.is_ok());
            assert_eq!(broker.health(), Ok((1, ScopeState::Usable)), "retained completion alone is not transport publication");
            assert_eq!(outcome.retention.is_some(), replaced && mutated);
            if let Some(retention) = &outcome.retention { assert!(retention.matches(key)); }
            assert_eq!(f.requests("Page.enable").len(), prefix_count + usize::from(mutated), "no retry or re-dispatch");
            // No claim about final wire scopeState: publication retirement and
            // transport settlement are intentionally outside this narrow test.
            f.finish().await;
        }
    }
}
