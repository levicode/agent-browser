// Included only inside client_enrollment::tests. This characterizes one possible
// source of page.evaluate's ScopeUnavailable, not the observed E2E's root cause.
// No browser, fabricated watermark, manual event application, or retry policy.

#[tokio::test]
async fn eval_capture_network_reader_ahead_of_apply_is_scope_unavailable() {
    // Reuse the existing real websocket reader and managed owner fixture. Its
    // ledger is bound before enrollment; do not install a healthy ledger later.
    let (mut owner, _notices, log, emit, server, _broker, connection) =
        fixture_with_client("eval-network-watermark", true).await;
    owner.gate.begin_transition().unwrap();
    let authority = owner.gate.initialization(owner.targets.clone()).unwrap();
    let mutable = Arc::get_mut(&mut owner).unwrap();
    mutable.initialization = Some(authority.access());
    mutable.ownership = ScopeOwnership::BorrowedTargets(vec!["initial-target".into()]);
    owner
        .enroll_existing("initial-target", "initial", "page", &owner.operation())
        .await
        .unwrap();
    owner.start(&owner.operation()).await.unwrap();
    owner.publish_initialized(&authority).unwrap();

    let entry = owner.index.lock().unwrap().sessions["initial"].clone();
    let page = owner.lease(&entry).unwrap();
    let ledger = owner.client.debt_ledger().unwrap();
    let mut operation = owner.operation();
    operation.sequence = 2;
    let baseline = owner.capture_eval_authority(&page, &operation).unwrap();
    let watermark = owner.realm_watermark().unwrap();

    // Neither event changes the active page's frame, loader, or JavaScript realm.
    // No response subscriber/body reader is needed to exercise this admission
    // gate, which runs before the attempted evaluation can dispatch its fetch.
    for event in [
        json!({"method":"Network.responseReceived","sessionId":"initial","params":{
            "requestId":"background-response","loaderId":"synthetic-loader",
            "timestamp":1.0,"type":"Fetch","hasExtraInfo":false,
            "response":{"url":"https://synthetic.test/background","status":200,
                "statusText":"OK","headers":{},"mimeType":"application/json",
                "connectionReused":true,"connectionId":1,"encodedDataLength":11,
                "securityState":"secure"}
        }}),
        json!({"method":"Network.loadingFinished","sessionId":"initial","params":{
            "requestId":"background-response","timestamp":2.0,"encodedDataLength":11
        }}),
    ] {
        let gate = CaptureTestGate::new();
        assert!(owner
            .capture_test_gates
            .lock()
            .unwrap()
            .insert(CaptureTestPoint::BeforeEventApply, gate.clone())
            .is_none());
        let before = watermark.received().unwrap();
        assert_eq!(owner.index.lock().unwrap().applied_watermark, before);
        let commands_before = log.lock().unwrap().len();
        emit.send(event.clone()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), gate.wait_entered())
            .await
            .expect("network event did not reach the existing before-apply gate");

        // The production reader advanced received; the existing semaphore gate
        // stopped only the supervisor, before it could advance applied.
        assert_eq!(watermark.received().unwrap(), before + 1);
        {
            let index = owner.index.lock().unwrap();
            assert_eq!(index.applied_watermark, before);
            assert!(index.failure.is_none());
            assert!(index.reconciled);
            assert!(index.pending_enrollment.is_empty());
        }
        assert!(!ledger.snapshot().integrity_lost);
        assert_eq!(ledger.snapshot().input_debt, 0);
        assert_eq!(ledger.snapshot().outstanding_commands, 0);
        assert_eq!(
            ledger
                .capture_eval_revision(&page.page_session_id, &page.target_id)
                .unwrap(),
            baseline.revision,
            "network bookkeeping must not masquerade as realm revocation"
        );
        let refused = owner.capture_eval_authority(&page, &operation);
        assert_eq!(
            refused.err(),
            Some(ProtocolError::ScopeUnavailable),
            "unapplied {} must preserve the original refusal category",
            event["method"]
        );
        assert_eq!(log.lock().unwrap().len(), commands_before);

        // This is a test-controlled scheduling boundary, not production retry:
        // the first refusal remains fixed. Let the real supervisor apply once.
        gate.release();
        owner
            .drain_capture_watermark(&watermark, &operation)
            .await
            .unwrap();
        assert_eq!(owner.index.lock().unwrap().applied_watermark, before + 1);
        let after = owner.capture_eval_authority(&page, &operation).unwrap();
        assert_eq!(after.revision, baseline.revision);
        assert_eq!(after.target, baseline.target);
        assert_eq!(after.session, baseline.session);
        assert_eq!(after.frame, baseline.frame);
        assert_eq!(after.loader, baseline.loader);
        assert!(!ledger.snapshot().integrity_lost);
        assert_eq!(log.lock().unwrap().len(), commands_before);
    }

    drop(page);
    tokio::time::timeout(CLEANUP_TIMEOUT * 3, owner.close())
        .await
        .expect("network watermark fixture supervisor did not join")
        .unwrap();
    connection.close().await;
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("network watermark fixture peer did not stop")
        .unwrap();
}

// These helpers only schedule real reader/supervisor work. They do not alter
// watermarks, ownership, debt, command outcomes, or publication state.
pub(crate) struct ResponseEntrySchedule {
    apply: Arc<CaptureTestGate>,
    entry: Arc<CaptureTestGate>,
}
impl ResponseEntrySchedule {
    pub(crate) async fn event_received(&self) {
        self.apply.wait_entered().await;
    }
    pub(crate) async fn release_at_eval_entry(&self) {
        self.entry.wait_entered().await;
        self.apply.release();
    }
    pub(crate) fn release(&self) {
        self.apply.release();
    }
}
impl ClientEnrollment {
    pub(crate) fn response_entry_schedule_for_test(&self) -> Arc<ResponseEntrySchedule> {
        let apply = CaptureTestGate::new();
        let entry = CaptureTestGate::new();
        let mut gates = self.capture_test_gates.lock().unwrap();
        assert!(gates
            .insert(CaptureTestPoint::BeforeEventApply, apply.clone())
            .is_none());
        assert!(gates
            .insert(CaptureTestPoint::EvalEntry, entry.clone())
            .is_none());
        Arc::new(ResponseEntrySchedule { apply, entry })
    }
    pub(crate) fn response_entry_state_for_test(&self) -> Value {
        let index = self.index.lock().unwrap();
        json!({"received":self.realm_watermark().unwrap().received().unwrap(),
            "applied":index.applied_watermark,"failure":index.failure.is_some(),
            "reconciled":index.reconciled,"pending":index.pending_enrollment.len(),
            "unresumed":index.sessions.values().filter(|entry| (entry.application || entry.observation_only) && !entry.resumed).count(),
            "epoch":index.application_epoch,
            "frames":index.frames.iter().map(|(id,frame)| (id.clone(),frame.session.clone(),frame.loader.clone(),frame.parent.clone())).collect::<Vec<_>>()})
    }
    pub(crate) async fn response_entry_drain_for_test(&self, op: &OperationLease) {
        self.drain_capture_watermark(&self.realm_watermark().unwrap(), op)
            .await
            .unwrap();
    }
}
