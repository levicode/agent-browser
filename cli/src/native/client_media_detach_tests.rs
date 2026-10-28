// Included inside client_enrollment::tests. These use the real enrollment,
// event reader and media producer against a controlled CDP peer. The shared
// fixture starts without a debt ledger. The tracked cases explicitly install
// the real ledger after settled enrollment and prove command debt retirement;
// the other cases isolate attachment/owner routing without claiming that proof.
mod media_detach_tests {
    use super::super::super::client_debt::{OperationJournalHandle, OperationKey, OwnerDebtLedger};
    use super::super::super::client_targets::OwnedTarget;
    use super::*;

    const MEDIA: &str = "Emulation.setEmulatedMedia";

    async fn fixture() -> CaptureWireFixture {
        let f = CaptureWireFixture::new(false).await;
        f.attach("popup-target", "popup", "page").await;
        f.attach("later-target", "later", "page").await;
        f
    }

    fn tickets(f: &CaptureWireFixture) -> Vec<OwnedTarget> {
        let (_, inventory) = f.owner.targets.inventory().unwrap();
        // Deliberately put the active page last: production must still apply it
        // first, while the popup failure must occur before the later live page.
        ["popup", "later", "initial"]
            .iter()
            .map(|session| {
                inventory
                    .iter()
                    .find(|target| target.session_id == *session)
                    .unwrap()
                    .clone()
            })
            .collect()
    }

    fn start(
        f: &CaptureWireFixture,
        attachments: Vec<OwnedTarget>,
        op: OperationLease,
    ) -> JoinHandle<Result<Value, ProtocolError>> {
        start_in_journal(f, attachments, op, None)
    }

    fn start_in_journal(
        f: &CaptureWireFixture,
        attachments: Vec<OwnedTarget>,
        op: OperationLease,
        journal: Option<OperationJournalHandle>,
    ) -> JoinHandle<Result<Value, ProtocolError>> {
        let owner = f.owner.clone();
        let entry = owner.index.lock().unwrap().sessions["initial"].clone();
        let page = owner.lease(&entry).unwrap();
        tokio::spawn(async move {
            // The dispatcher holds this same lock around context configuration.
            // A detach proof must not wait for another enrollment's config turn.
            let gate = owner.config_gate();
            let _configuration = gate.lock().await;
            let args = json!({"colorScheme":"dark", "reducedMotion":"reduce"});
            let run = owner
                .page
                .execute_media_with_owner(&page, &op, &args, &owner, &attachments);
            match journal {
                Some(journal) => journal.scope(run).await,
                None => run.await,
            }
        })
    }

    fn install_ledger(f: &CaptureWireFixture) -> Arc<OwnerDebtLedger> {
        let ledger = OwnerDebtLedger::new(1, f.owner.targets.identity_scope.clone());
        ledger.bind_context("owned-context").unwrap();
        for target in tickets(f) {
            ledger
                .bind_session("owned-context", &target.target_id, &target.session_id)
                .unwrap();
        }
        f.owner.client.install_debt_ledger(ledger.clone()).unwrap();
        f.owner.targets.bind_eval_owner(&ledger, 1).unwrap();
        ledger
    }

    fn operation_journal(
        ledger: &Arc<OwnerDebtLedger>,
        op: &OperationLease,
    ) -> OperationJournalHandle {
        let journal = ledger
            .operation(
                OperationKey {
                    generation: op.generation,
                    operation_seq: op.sequence,
                },
                "target".into(),
                "initial".into(),
            )
            .unwrap();
        journal.bind_operation(op).unwrap();
        journal
    }

    fn hold(f: &CaptureWireFixture, session: &str) {
        f.held
            .lock()
            .unwrap()
            .insert((MEDIA.into(), session.into()));
    }

    async fn failure(f: &CaptureWireFixture, request: &Value) {
        f.emit
            .send(json!({
                "id": request["id"], "sessionId": request["sessionId"],
                "error": {"code": -32000, "message": "synthetic media failure"}
            }))
            .await
            .unwrap();
    }

    fn detach(target: &str, session: &str) -> Value {
        json!({"method":"Target.detachedFromTarget", "params":{
            "sessionId":session, "targetId":target
        }})
    }

    async fn result(
        task: JoinHandle<Result<Value, ProtocolError>>,
    ) -> Result<Value, ProtocolError> {
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("media must finish without draining a queued configuration")
            .expect("media producer panicked")
    }

    fn assert_writes(f: &CaptureWireFixture, sessions: &[&str]) {
        let requests = f.requests(MEDIA);
        let actual: Vec<_> = requests
            .iter()
            .map(|request| request["sessionId"].as_str().unwrap())
            .collect();
        assert_eq!(
            actual, sessions,
            "media must neither replay nor skip live pages"
        );
        for request in requests {
            assert_eq!(
                request["params"]["features"],
                json!([
                    {"name":"prefers-color-scheme","value":"dark"},
                    {"name":"prefers-reduced-motion","value":"reduce"}
                ])
            );
        }
    }

    async fn finish(f: CaptureWireFixture) {
        let _ = f.owner.close().await;
        f.server.abort();
        match f.server.await {
            Ok(()) => {}
            Err(error) if error.is_cancelled() => {}
            Err(error) => panic!("CDP peer panicked: {error}"),
        }
    }

    #[tokio::test]
    async fn media_exact_popup_detach_during_write_continues_live_pages_without_replay() {
        let f = fixture().await;
        let attachments = tickets(&f);
        hold(&f, "popup");
        let task = start(&f, attachments, f.owner.operation());
        let request = f.request(MEDIA, 2).await;
        assert_eq!(request["sessionId"], "popup");
        // The real CDP reader terminates this pending waiter on direct detach.
        // No synthetic successful ACK is supplied for the vanished page.
        f.emit.send(detach("popup-target", "popup")).await.unwrap();
        assert_eq!(result(task).await.unwrap(), Value::Null);
        assert_writes(&f, &["initial", "popup", "later"]);
        assert_eq!(f.owner.page.config_revision().unwrap(), 1);
        assert!(!f.owner.index.lock().unwrap().sessions.contains_key("popup"));
        assert!(f.owner.index.lock().unwrap().sessions.contains_key("later"));
        finish(f).await;
    }

    #[tokio::test]
    async fn media_tracked_exact_popup_detach_retires_real_command_debt_and_continues() {
        let f = fixture().await;
        f.server_barrier().await;
        let ledger = install_ledger(&f);
        let mut op = f.owner.operation();
        op.sequence = 71;
        let journal = operation_journal(&ledger, &op);
        hold(&f, "popup");
        let task = start_in_journal(&f, tickets(&f), op, Some(journal.clone()));
        f.request(MEDIA, 2).await;
        let held = ledger.snapshot();
        assert_eq!(held.outstanding_commands, 1);
        assert_eq!(
            held.input_debt, 1,
            "held media must be real tracked mutation debt"
        );
        assert_eq!(held.object_debt, 0);
        assert!(!held.integrity_lost);
        assert_eq!(journal.snapshot().input_debt, 1);
        f.emit.send(detach("popup-target", "popup")).await.unwrap();
        assert_eq!(result(task).await.unwrap(), Value::Null);
        assert_writes(&f, &["initial", "popup", "later"]);
        let settled = ledger.snapshot();
        assert_eq!(settled.outstanding_commands, 0);
        assert_eq!(settled.input_debt, 0);
        assert_eq!(settled.object_debt, 0);
        assert!(!settled.integrity_lost);
        let operation = journal.snapshot();
        assert!(operation.mutation_dispatched);
        assert_eq!(operation.input_debt, 0);
        assert_eq!(operation.object_debt, 0);
        assert!(!operation.integrity_lost);
        assert!(!operation.submission_revoked);
        // Installing a ledger does not convert this fixture's legacy service
        // handles into owner-bound cleanup authority. Teardown below is not an
        // assertion of scope-close success; the assertions above are the actual
        // operation/reader debt proof, before any external fixture teardown.
        finish(f).await;
    }

    #[tokio::test]
    async fn media_tracked_detach_with_mismatched_operation_key_remains_failure() {
        let f = fixture().await;
        let ledger = install_ledger(&f);
        let mut op = f.owner.operation();
        op.sequence = 71;
        let journal = operation_journal(&ledger, &op);
        op.sequence = 72;
        hold(&f, "popup");
        let task = start_in_journal(&f, tickets(&f), op, Some(journal.clone()));
        f.request(MEDIA, 2).await;
        assert_eq!(ledger.snapshot().input_debt, 1);
        f.emit.send(detach("popup-target", "popup")).await.unwrap();
        assert!(result(task).await.is_err());
        assert_writes(&f, &["initial", "popup"]);
        assert_eq!(ledger.snapshot().input_debt, 0);
        assert!(journal.snapshot().integrity_lost);
        finish(f).await;
    }

    #[tokio::test]
    async fn media_tracked_detach_cannot_clear_another_sessions_unknown_input_debt() {
        let f = fixture().await;
        let ledger = install_ledger(&f);
        let mut op = f.owner.operation();
        op.sequence = 71;
        let journal = operation_journal(&ledger, &op);
        f.held
            .lock()
            .unwrap()
            .insert(("Input.dispatchKeyEvent".into(), "later".into()));
        let client = f.owner.client.clone();
        let input_journal = journal.clone();
        let input = tokio::spawn(async move {
            input_journal
                .scope(client.send_command(
                    "Input.dispatchKeyEvent",
                    Some(json!({"type":"keyDown", "key":"a"})),
                    Some("later"),
                ))
                .await
        });
        let input_request = f.request("Input.dispatchKeyEvent", 1).await;
        assert_eq!(journal.snapshot().input_debt, 1);
        hold(&f, "popup");
        let task = start_in_journal(&f, tickets(&f), op, Some(journal.clone()));
        f.request(MEDIA, 2).await;
        assert_eq!(journal.snapshot().input_debt, 2);
        f.emit.send(detach("popup-target", "popup")).await.unwrap();
        assert!(result(task).await.is_err());
        assert_writes(&f, &["initial", "popup"]);
        assert_eq!(journal.snapshot().input_debt, 1);
        assert_eq!(ledger.snapshot().outstanding_commands, 1);
        assert!(journal.snapshot().integrity_lost);
        // A later exact ACK settles only its own command; it cannot turn the
        // already-failed media operation into success or replay remaining media.
        f.emit
            .send(json!({"id":input_request["id"], "sessionId":"later", "result":{}}))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), input)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(journal.snapshot().input_debt, 0);
        assert!(journal.snapshot().integrity_lost);
        assert_writes(&f, &["initial", "popup"]);
        finish(f).await;
    }

    #[tokio::test]
    async fn media_tracked_missing_or_foreign_journal_cannot_dispatch_or_succeed() {
        for foreign in [false, true] {
            let f = fixture().await;
            let ledger = install_ledger(&f);
            let mut op = f.owner.operation();
            op.sequence = 71;
            let journal = if foreign {
                let other = OwnerDebtLedger::new(1, "another-scope".into());
                Some(operation_journal(&other, &op))
            } else {
                None
            };
            assert!(result(start_in_journal(&f, tickets(&f), op, journal))
                .await
                .is_err());
            assert!(f.requests(MEDIA).is_empty());
            assert_eq!(ledger.snapshot().outstanding_commands, 0);
            finish(f).await;
        }
    }

    #[tokio::test]
    async fn media_exact_detach_does_not_wait_for_queued_enrollment_configuration() {
        let f = fixture().await;
        hold(&f, "popup");
        let task = start(&f, tickets(&f), f.owner.operation());
        f.request(MEDIA, 2).await;
        f.emit
            .send(capture_attach_event("queued-target", "queued", "page"))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                {
                    let index = f.owner.index.lock().unwrap();
                    if index.pending_enrollment.contains_key("queued")
                        && index.sessions.contains_key("queued")
                    {
                        assert!(!index.sessions["queued"].application);
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("queued attach must reach its real configuration gate");
        f.emit.send(detach("popup-target", "popup")).await.unwrap();
        assert_eq!(result(task).await.unwrap(), Value::Null);
        // Only now may the queued enrollment acquire configuration and resume.
        // It must inherit the same successful media state, not replay the popup.
        let watermark = f.owner.realm_watermark().unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            f.owner
                .drain_capture_watermark(&watermark, &f.owner.operation()),
        )
        .await
        .expect("queued enrollment must finish after media releases its gate")
        .unwrap();
        assert_writes(&f, &["initial", "popup", "later", "queued"]);
        assert!(f.owner.index.lock().unwrap().sessions["queued"].resumed);
        finish(f).await;
    }

    #[tokio::test]
    async fn media_live_popup_failure_remains_failure_and_is_not_replayed() {
        let f = fixture().await;
        hold(&f, "popup");
        let task = start(&f, tickets(&f), f.owner.operation());
        let request = f.request(MEDIA, 2).await;
        failure(&f, &request).await;
        assert!(matches!(
            result(task).await,
            Err(ProtocolError::BrowserFailure)
        ));
        assert_writes(&f, &["initial", "popup"]);
        assert!(f.owner.index.lock().unwrap().sessions.contains_key("popup"));
        finish(f).await;
    }

    #[tokio::test]
    async fn media_target_destroyed_without_direct_detach_does_not_excuse_failure() {
        let f = fixture().await;
        hold(&f, "popup");
        let task = start(&f, tickets(&f), f.owner.operation());
        let request = f.request(MEDIA, 2).await;
        realm_emit(
            &f.owner,
            &f.emit,
            json!({"method":"Target.targetDestroyed", "params":{"targetId":"popup-target"}}),
        )
        .await;
        failure(&f, &request).await;
        assert!(result(task).await.is_err());
        assert_writes(&f, &["initial", "popup"]);
        finish(f).await;
    }

    #[tokio::test]
    async fn media_conflicting_detach_target_id_does_not_excuse_failure() {
        let f = fixture().await;
        hold(&f, "popup");
        let task = start(&f, tickets(&f), f.owner.operation());
        f.request(MEDIA, 2).await;
        f.emit
            .send(detach("another-target", "popup"))
            .await
            .unwrap();
        assert!(result(task).await.is_err());
        assert_writes(&f, &["initial", "popup"]);
        finish(f).await;
    }

    #[tokio::test]
    async fn media_active_root_detach_never_becomes_popup_success() {
        let f = fixture().await;
        hold(&f, "initial");
        let task = start(&f, tickets(&f), f.owner.operation());
        f.request(MEDIA, 1).await;
        f.emit.send(detach("target", "initial")).await.unwrap();
        assert!(result(task).await.is_err());
        assert_writes(&f, &["initial"]);
        finish(f).await;
    }

    #[tokio::test]
    async fn media_original_detach_receipt_does_not_excuse_same_text_replacement() {
        let f = fixture().await;
        let attachments = tickets(&f);
        realm_emit(&f.owner, &f.emit, detach("popup-target", "popup")).await;
        // Complete real re-enrollment before returning the error. This makes
        // replacement tenure deterministic rather than racing two wire events.
        f.attach("popup-target", "popup", "page").await;
        let replacement = tickets(&f);
        assert!(!attachments[0].same_attachment(&replacement[0]));
        hold(&f, "popup");
        let task = start(&f, attachments, f.owner.operation());
        let request = f.request(MEDIA, 2).await;
        failure(&f, &request).await;
        assert!(result(task).await.is_err());
        assert_writes(&f, &["initial", "popup"]);
        assert!(f.owner.index.lock().unwrap().sessions.contains_key("popup"));
        finish(f).await;
    }

    #[tokio::test]
    async fn closed_active_root_text_stays_rejected_after_active_selection_changes() {
        for (target, session) in [
            ("popup-target", "popup"),
            ("another-target", "popup"),
            ("popup-target", "another-session"),
        ] {
            let f = fixture().await;
            f.owner.set_active_root("popup").unwrap();
            realm_emit(&f.owner, &f.emit, detach("popup-target", "popup")).await;
            f.owner.set_active_root("initial").unwrap();
            let recorded_active = f
                .owner
                .index
                .lock()
                .unwrap()
                .detached_active_roots
                .contains("popup-target");
            let refusal = f
                .owner
                .register("owned-context", target, session, "page", None)
                .err();
            finish(f).await;
            assert!(
                recorded_active,
                "Active-root history must survive later selection changes"
            );
            assert_eq!(refusal, Some(ProtocolError::StaleScope));
        }
    }

    #[tokio::test]
    async fn media_cancelled_operation_is_not_rescued_by_exact_popup_detach() {
        let f = fixture().await;
        hold(&f, "popup");
        let (cancel, cancellation) = watch::channel(CancelSignal::None);
        let mut op = f.owner.operation();
        op.cancellation = cancellation;
        let task = start(&f, tickets(&f), op);
        f.request(MEDIA, 2).await;
        cancel.send_replace(CancelSignal::Requested);
        f.emit.send(detach("popup-target", "popup")).await.unwrap();
        assert!(matches!(result(task).await, Err(ProtocolError::Cancelled)));
        assert_writes(&f, &["initial", "popup"]);
        finish(f).await;
    }

    #[tokio::test]
    async fn media_expired_original_deadline_cannot_be_renewed_by_owner_path() {
        let f = fixture().await;
        let mut op = f.owner.operation();
        op.deadline = Instant::now();
        assert!(matches!(
            result(start(&f, tickets(&f), op)).await,
            Err(ProtocolError::DeadlineExceeded)
        ));
        assert!(f.requests(MEDIA).is_empty());
        finish(f).await;
    }
}
