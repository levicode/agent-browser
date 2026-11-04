// Included only inside client_enrollment::tests. Schedulers use real existing
// initializer boundaries and actual UI polling; no production fact is forged.
pub(crate) struct PopupInterpositionSchedule {
    popup: PopupCaptureSchedule,
    recheck: Arc<CaptureTestGate>,
    ui: Arc<CaptureTestGate>,
}
impl PopupInterpositionSchedule {
    pub(crate) async fn initializer_held(&self) {
        self.popup.initializer_held().await;
    }
    pub(crate) async fn preparation_waiting(&self) -> Value {
        self.popup.preparation_waiting().await
    }
    pub(crate) async fn recheck_held(&self) {
        self.recheck.wait_entered().await;
    }
    pub(crate) fn release_initializer(&self) {
        self.popup.release();
    }
    pub(crate) fn release_recheck(&self) {
        self.recheck.release();
    }
    pub(crate) async fn ui_pending(&self) -> Value {
        self.ui.wait_entered().await;
        self.ui.preparation_receipt.lock().unwrap().clone().unwrap()
    }
}
pub(crate) struct PopupInterpositionEventGate(Arc<CaptureTestGate>);
impl PopupInterpositionEventGate {
    pub(crate) async fn received(&self) {
        self.0.wait_entered().await;
    }
    pub(crate) fn release(&self) {
        self.0.release();
    }
}
impl ClientEnrollment {
    pub(crate) fn popup_interposition_schedule_for_test(&self) -> PopupInterpositionSchedule {
        let popup = self.popup_capture_schedule_for_test(true);
        let recheck = CaptureTestGate::new();
        let ui = CaptureTestGate::new();
        let mut gates = self.capture_test_gates.lock().unwrap();
        let initializer = gates
            .remove(&CaptureTestPoint::AfterPopupResumeAckBeforeComplete)
            .unwrap();
        // initialize_inner returned, so its real config lock is no longer held.
        // The original completed ResumePermit and retained custody remain held.
        assert!(gates
            .insert(
                CaptureTestPoint::BeforeInitializationResumeRelease,
                initializer
            )
            .is_none());
        assert!(gates
            .insert(
                CaptureTestPoint::BeforeEvalPreparationRecheck,
                recheck.clone()
            )
            .is_none());
        assert!(gates
            .insert(CaptureTestPoint::EvalPreparedUiPending, ui.clone())
            .is_none());
        PopupInterpositionSchedule { popup, recheck, ui }
    }
    pub(crate) fn popup_interposition_event_gate_for_test(&self) -> PopupInterpositionEventGate {
        let gate = CaptureTestGate::new();
        assert!(self
            .capture_test_gates
            .lock()
            .unwrap()
            .insert(CaptureTestPoint::BeforeEventApply, gate.clone())
            .is_none());
        PopupInterpositionEventGate(gate)
    }
    pub(crate) async fn popup_interposition_event_applied_for_test(&self) {
        self.drain_capture_watermark(&self.realm_watermark().unwrap(), &self.operation())
            .await
            .unwrap();
    }
    pub(crate) fn popup_interposition_configuration_for_test(&self) -> Value {
        json!({"revision":self.page.config_revision().unwrap(),
            "viewport":self.page.requested_viewport().unwrap()})
    }
    pub(crate) async fn observe_eval_ui_wait_for_test<F>(
        &self,
        op: &OperationLease,
        prepared: bool,
        future: F,
    ) -> F::Output
    where
        F: std::future::Future,
    {
        let mut future = Box::pin(future);
        let mut observed = false;
        std::future::poll_fn(|cx| {
            let result = future.as_mut().poll(cx);
            if result.is_pending() && prepared && !observed {
                observed = true;
                let recorder = self
                    .capture_test_gates
                    .lock()
                    .unwrap()
                    .remove(&CaptureTestPoint::EvalPreparedUiPending);
                if let Some(recorder) = recorder {
                    *recorder.preparation_receipt.lock().unwrap() = Some(json!({
                        "generation":op.generation,"operationSeq":op.sequence,
                        "prepared":true,"actualUiPoll":"pending"
                    }));
                    recorder.entered.add_permits(1);
                }
            }
            result
        })
        .await
    }
}
