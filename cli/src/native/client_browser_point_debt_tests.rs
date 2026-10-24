//! Real ClientBrowser dispatch and retained journals against the existing framed
//! owner fixture and finite websocket peer. The peer, not a dropped waiter,
//! supplies each exact input ACK. No browser or replacement executor is used.
use super::*;
use crate::native::client_debt::{
    AdmissionClass, OperationJournalHandle, OperationKey, OwnerDebtLedger,
};
use crate::native::client_targets::{ClientTargets, OwnedTarget};
use std::future::Future;

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("point debt fixture stalled")
}

struct OldInput {
    journal: OperationJournalHandle,
    outcome: NativeOutcome,
    request: Value,
}
struct Fixture {
    framed: FramedFixture,
    browser: Arc<ClientBrowser>,
    broker: Arc<ClientSession>,
    scope: String,
    ledger: Arc<OwnerDebtLedger>,
    targets: Arc<ClientTargets>,
    attachment: OwnedTarget,
    requests: tokio::sync::mpsc::UnboundedReceiver<Value>,
    replies: tokio::sync::mpsc::UnboundedSender<Value>,
    log: Arc<Mutex<Vec<Value>>>,
    peer: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn new(hold_point: bool) -> Self {
        let (seen, requests) = tokio::sync::mpsc::unbounded_channel();
        let (replies, reply_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (endpoint, log, peer) = peer_with_input_replies(
            false,
            Some(seen),
            true,
            None,
            None,
            Some(reply_receiver),
            hold_point,
        )
        .await;
        let broker = Arc::new(ClientSession::new());
        let browser = Arc::new(ClientBrowser::new(broker.clone()));
        let mut framed = framed(
            browser.clone(),
            broker.clone(),
            Arc::new(RestartFlush::default()),
        );
        framed.ready().await.unwrap();
        let opened = framed
            .command(
                "scope.open",
                fixture_scope_open("connect", Some(&endpoint)),
                5,
            )
            .await
            .unwrap();
        let scope = opened["identityScope"].as_str().unwrap().to_owned();
        framed.scope = Some(scope.clone());
        framed
            .command("scope.configure", fixture_configuration(&scope, None), 5)
            .await
            .unwrap();
        framed
            .command("network.routes.replace", fixture_routes(&scope), 5)
            .await
            .unwrap();
        framed.registry = 1;
        framed
            .command("page.activate", json!({"identityScope":scope}), 5)
            .await
            .unwrap();
        let page = browser.page_lease(false).await.unwrap();
        let ledger = page.client.debt_ledger().unwrap();
        let targets = page.targets.clone();
        let attachment = targets.owned_target(&page.target_id).unwrap();
        drop(page);
        Self {
            framed,
            browser,
            broker,
            scope,
            ledger,
            targets,
            attachment,
            requests,
            replies,
            log,
            peer,
        }
    }

    fn lease(&mut self, timeout: u64) -> OperationLease {
        self.framed.sequence += 1;
        self.broker.admit(1, self.framed.sequence, timeout).unwrap()
    }

    async fn fix(&self, key: OperationKey, outcome: &NativeOutcome) {
        if let Some(proof) = &outcome.retention {
            self.broker.begin_operation_retirement(key, proof).unwrap();
            self.browser
                .retire_operation_publication(key)
                .await
                .unwrap();
            self.broker.finish_operation_publication(key).unwrap();
        }
        assert_eq!(
            self.broker
                .settle_with_retention(
                    key.generation,
                    key.operation_seq,
                    outcome.effects,
                    outcome.retention.as_ref(),
                )
                .unwrap(),
            ScopeState::Usable
        );
        self.browser.fix_operation_result(key);
    }

    async fn old_input(&mut self) -> OldInput {
        let lease = self.lease(10_000);
        assert!(self.broker.start(1, lease.sequence).unwrap());
        let key = OperationKey {
            generation: 1,
            operation_seq: lease.sequence,
        };
        let page = self.browser.page_lease(false).await.unwrap();
        let journal = ClientBrowser::operation_journal(&page, &lease).unwrap();
        let kept = journal.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let result = self.browser.tasks.start_operation(
            self.scope.clone(), self.targets.clone(), self.broker.clone(), journal,
            lease.cancellation.clone(), async move {
                let page = page;
                tokio::select! { biased;
                    _ = stopped => {},
                    _ = page.client.send_command("Input.insertText", Some(json!({"text":"older-native-input"})), Some(&page.page_session_id)) => panic!("old input must remain unacknowledged"),
                }
                (NativeOutcome { retention: None, result: Err(ProtocolError::Cancelled), effects: Effects::Unknown }, false)
            },
        ).await.unwrap();
        let request = bounded(self.requests.recv()).await.unwrap();
        assert_eq!(request["method"], "Input.insertText");
        assert_eq!(self.ledger.snapshot().input_debt, 1);
        assert!(kept.snapshot().mutation_dispatched);
        stop.send(()).unwrap();
        let outcome = bounded(result).await.unwrap();
        assert_eq!(outcome.effects, Effects::Unknown);
        assert!(outcome.retention.is_some());
        self.fix(key, &outcome).await;
        OldInput {
            journal: kept,
            outcome,
            request,
        }
    }

    fn point(
        &mut self,
        timeout: u64,
        probe: bool,
    ) -> (
        OperationKey,
        tokio::task::JoinHandle<NativeOutcome>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        let lease = self.lease(timeout);
        let key = OperationKey {
            generation: 1,
            operation_seq: lease.sequence,
        };
        let (reached, waiting) = tokio::sync::oneshot::channel();
        if probe {
            *self.browser.generic_admission_probe.lock().unwrap() =
                Some(GenericAdmissionProbe { key, reached });
        }
        let browser = self.browser.clone();
        let args =
            json!({"identityScope":self.scope,"point":{"x":10,"y":10},"action":{"kind":"tap"}});
        let task = tokio::spawn(async move {
            browser
                .execute(
                    "browser.pointer".into(),
                    args.as_object().unwrap().clone(),
                    lease,
                )
                .await
        });
        (key, task, waiting)
    }

    async fn framed_point(&mut self) -> (OperationKey, tokio::sync::oneshot::Receiver<()>) {
        self.framed.sequence += 1;
        let key = OperationKey {
            generation: 1,
            operation_seq: self.framed.sequence,
        };
        let (reached, waiting) = tokio::sync::oneshot::channel();
        *self.browser.generic_admission_probe.lock().unwrap() =
            Some(GenericAdmissionProbe { key, reached });
        self.framed
            .write(
                json!({"type":"request","id":format!("point-{}",key.operation_seq),
            "generation":1,"operationSeq":key.operation_seq,"timeoutMs":1000,
            "command":"browser.pointer","args":{"identityScope":self.scope,
                "point":{"x":10,"y":10},"action":{"kind":"tap"}}}),
            )
            .await
            .unwrap();
        (key, waiting)
    }

    async fn framed_result(&mut self, key: OperationKey) -> Value {
        // This fixture has no route decisions. Preserve strict application
        // event ordering while reading the actual production result writer.
        bounded(async {
            for _ in 0..8 {
                let frame = self.framed.read().await.unwrap();
                assert_eq!(frame["generation"], key.generation);
                match frame["type"].as_str() {
                    Some("event") => {
                        self.framed.event_sequence += 1;
                        assert_eq!(frame["sequence"], self.framed.event_sequence);
                        assert_eq!(frame["payload"]["identityScope"], self.scope);
                        validate_fixture_notice(&frame).unwrap();
                    }
                    Some("result") => {
                        assert_eq!(frame["id"], format!("point-{}", key.operation_seq));
                        assert_eq!(frame["operationSeq"], key.operation_seq);
                        return frame;
                    }
                    _ => panic!("unexpected point fixture frame: {frame:?}"),
                }
            }
            panic!("point result missing from bounded frame sequence")
        })
        .await
    }

    fn point_inputs(&self) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["method"] == "Input.dispatchMouseEvent")
            .count()
    }

    fn ack(&self, request: &Value) {
        self.replies
            .send(json!({"id":request["id"],"sessionId":request["sessionId"],"result":{}}))
            .unwrap();
    }

    async fn acknowledged(&mut self) {
        // A genuine broker lease bounds a read-only admission witness. It
        // grants no input authority and waits for the real transport reader.
        let lease = self.lease(2000);
        self.ledger
            .wait_admission(AdmissionClass::Input, &lease, || Ok(()))
            .await
            .unwrap();
        assert_eq!(self.ledger.snapshot().input_debt, 0);
        self.broker
            .settle(1, lease.sequence, Effects::NotDispatched)
            .unwrap();
    }

    async fn finish(self) {
        let cleanup = bounded(self.framed.finish()).await;
        self.peer.abort();
        cleanup.unwrap();
    }
}

#[tokio::test]
async fn direct_point_deadline_keeps_old_input_owned_and_never_sends_second_input() {
    let mut f = Fixture::new(false).await;
    let old = f.old_input().await;
    for _ in 0..2 {
        let (key, waiting) = f.framed_point().await;
        bounded(waiting).await.unwrap();
        assert_eq!(f.point_inputs(), 0);
        assert_eq!(f.ledger.snapshot().input_debt, 1);
        f.browser.tasks.check_input_dispatch(key).unwrap();
        let result = f.framed_result(key).await;
        assert_eq!(result["ok"], false);
        assert_eq!(result["error"]["code"], "deadline-exceeded");
        assert_eq!(result["effects"], "not-dispatched");
        assert_eq!(result["scopeState"], "usable");
        assert!(result.get("retention").is_none());
        assert_eq!(f.point_inputs(), 0);
        assert_eq!(f.ledger.snapshot().input_debt, 1);
        assert!(old.journal.snapshot().mutation_dispatched);
        assert_eq!(old.outcome.effects, Effects::Unknown);
        assert_eq!(
            old.outcome
                .retention
                .as_ref()
                .unwrap()
                .descriptor()
                .input_debt,
            1
        );
    }
    f.ack(&old.request);
    f.acknowledged().await;
    let fresh = f
        .framed
        .command(
            "browser.pointer",
            json!({"identityScope":f.scope,
        "point":{"x":10,"y":10},"action":{"kind":"tap"}}),
            5,
        )
        .await
        .unwrap();
    assert_eq!(fresh, Value::Null);
    assert_eq!(f.point_inputs(), 3);
    assert_eq!(old.outcome.effects, Effects::Unknown);
    f.finish().await;
}

#[tokio::test]
async fn direct_point_resumes_only_after_real_old_ack_without_holding_input_lock() {
    let mut f = Fixture::new(false).await;
    let old = f.old_input().await;
    let (key, task, waiting) = f.point(5000, true);
    bounded(waiting).await.unwrap();
    let input = {
        let owner = f.browser.owner.lock().await;
        owner
            .as_ref()
            .unwrap()
            .runtime
            .as_ref()
            .unwrap()
            .input_gate
            .clone()
    };
    assert!(input.try_lock().is_ok());
    assert_eq!(f.point_inputs(), 0);
    f.ack(&old.request);
    let outcome = bounded(task).await.unwrap();
    assert_eq!(outcome.result, Ok(Value::Null));
    assert_eq!(outcome.effects, Effects::Completed);
    assert_eq!(f.point_inputs(), 3);
    assert_eq!(f.ledger.snapshot().input_debt, 0);
    f.fix(key, &outcome).await;
    assert_eq!(old.outcome.effects, Effects::Unknown);
    assert!(old.journal.snapshot().mutation_dispatched);
    f.finish().await;
}

#[tokio::test]
async fn direct_point_user_cancel_keeps_old_input_debt_and_is_not_timeout() {
    let mut f = Fixture::new(false).await;
    let old = f.old_input().await;
    let (key, task, waiting) = f.point(5000, true);
    bounded(waiting).await.unwrap();
    f.broker.cancel(1, key.operation_seq).unwrap();
    let outcome = bounded(task).await.unwrap();
    assert_eq!(outcome.result, Err(ProtocolError::Cancelled));
    assert_eq!(outcome.effects, Effects::NotDispatched);
    assert_eq!(f.point_inputs(), 0);
    assert_eq!(f.ledger.snapshot().input_debt, 1);
    f.fix(key, &outcome).await;
    f.ack(&old.request);
    f.acknowledged().await;
    f.finish().await;
}

#[tokio::test]
async fn direct_point_owner_retirement_wakes_before_ack_and_cannot_be_revived() {
    let mut f = Fixture::new(false).await;
    let old = f.old_input().await;
    let (key, task, waiting) = f.point(5000, true);
    bounded(waiting).await.unwrap();
    f.browser.stop_enrollment(false).unwrap();
    let outcome = bounded(task).await.unwrap();
    assert_eq!(outcome.result, Err(ProtocolError::StaleScope));
    assert_eq!(outcome.effects, Effects::NotDispatched);
    assert_eq!(f.ledger.snapshot().input_debt, 1);
    assert_eq!(f.point_inputs(), 0);
    f.fix(key, &outcome).await;
    f.ack(&old.request);
    f.acknowledged().await;
    let (key, fresh, _) = f.point(5000, false);
    let fresh = bounded(fresh).await.unwrap();
    assert!(fresh.result.is_err());
    assert_eq!(fresh.effects, Effects::NotDispatched);
    assert_eq!(f.point_inputs(), 0);
    f.fix(key, &fresh).await;
    f.finish().await;
}

#[tokio::test]
async fn direct_point_rejects_same_textual_ids_with_new_attachment_after_ack() {
    let mut f = Fixture::new(false).await;
    let old = f.old_input().await;
    let (key, task, waiting) = f.point(5000, true);
    bounded(waiting).await.unwrap();
    let original = &f.attachment;
    f.targets.detach(&original.target_id).unwrap();
    assert!(f
        .targets
        .attached(
            &f.targets.context_id,
            original.target_id.clone(),
            original.session_id.clone(),
            original.kind.clone()
        )
        .unwrap());
    f.targets.configured(&original.target_id).unwrap();
    f.targets
        .resume_permit(&original.target_id)
        .await
        .unwrap()
        .complete()
        .unwrap();
    f.ack(&old.request);
    let outcome = bounded(task).await.unwrap();
    assert_eq!(outcome.result, Err(ProtocolError::StaleScope));
    assert_eq!(outcome.effects, Effects::NotDispatched);
    assert_eq!(f.point_inputs(), 0);
    f.fix(key, &outcome).await;
    f.finish().await;
}

#[tokio::test]
async fn direct_point_already_submitted_without_ack_stays_unknown() {
    let mut f = Fixture::new(true).await;
    let (key, task, _) = f.point(5000, false);
    let request = bounded(f.requests.recv()).await.unwrap();
    assert_eq!(request["method"], "Input.dispatchMouseEvent");
    assert_eq!(f.point_inputs(), 1);
    f.broker.cancel(1, key.operation_seq).unwrap();
    let outcome = bounded(task).await.unwrap();
    assert_eq!(outcome.effects, Effects::Unknown);
    assert!(outcome.retention.is_some());
    assert_eq!(f.ledger.snapshot().input_debt, 1);
    f.fix(key, &outcome).await;
    f.ack(&request);
    f.acknowledged().await;
    assert_eq!(outcome.effects, Effects::Unknown);
    f.finish().await;
}

// Minimal P06 entry-boundary RED, not the full post-click mutation scenario.
// Tap's first mouseMoved loses its ACK before any press/release is sent. This
// does not prove recovery with held buttons or unresolved input-release work.
// Use a real framed request, not a fabricated EOF, proof, or direct reconnect.
struct EofRecoveryObservation {
    original: Value,
    reconnect: Value,
    producer_drain: Result<(), ProtocolError>,
    cleanup: Result<(), String>,
    candidate_commands: Vec<Value>,
}

async fn eof_recovery_result(framed: &mut FramedFixture, id: &str, sequence: u64) -> Value {
    bounded(async {
        for _ in 0..8 {
            let frame = framed.read().await.unwrap();
            assert_eq!(frame["generation"], 1);
            match frame["type"].as_str() {
                Some("event") => {
                    framed.event_sequence += 1;
                    assert_eq!(frame["sequence"], framed.event_sequence);
                    if frame["event"] == "browser.disconnected" {
                        assert_eq!(
                            frame["payload"],
                            json!({"reason":"browser-connection-closed"})
                        );
                        assert!(frame.get("decision").is_none());
                    } else {
                        assert_eq!(
                            frame["payload"]["identityScope"],
                            framed.scope.as_deref().unwrap()
                        );
                        validate_fixture_notice(&frame).unwrap();
                    }
                }
                Some("result") => {
                    assert_eq!(frame["id"], id);
                    assert_eq!(frame["operationSeq"], sequence);
                    return frame;
                }
                _ => panic!("unexpected P06 frame: {frame}"),
            }
        }
        panic!("P06 correlated result missing")
    })
    .await
}

async fn framed_input_eof_reconnect() -> EofRecoveryObservation {
    use crate::native::client_browser::reconnect_tests::{peer as reconnect_peer, PeerMode};
    use crate::native::client_protocol::EXACT_OWNER_CONTINUATION;

    let mut original = reconnect_peer(PeerMode::HoldInput).await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    // These are the existing NativeClient REQUIRED_CAPABILITIES, not a new
    // recovery capability. terminal.close/1 makes its refusal observable after
    // quarantine; continuation must not turn EOF into an input acknowledgement.
    let mut framed = FramedFixture::with_capabilities(
        broker.clone(),
        browser.clone(),
        vec![EXACT_OWNER_CONTINUATION.into(), "terminal.close/1".into()],
    );
    framed.ready().await.unwrap();
    let opened = framed
        .command(
            "scope.open",
            json!({"source":"connect","context":"persistent","endpoint":original.endpoint}),
            5,
        )
        .await
        .unwrap();
    let scope = opened["identityScope"].as_str().unwrap().to_owned();
    let identity = opened["recoveryIdentity"].clone();
    framed.scope = Some(scope.clone());
    framed
        .command("scope.configure", fixture_configuration(&scope, None), 5)
        .await
        .unwrap();
    framed
        .command("network.routes.replace", fixture_routes(&scope), 5)
        .await
        .unwrap();
    framed.registry = 1;
    framed
        .command("page.activate", json!({"identityScope":scope}), 5)
        .await
        .unwrap();
    let (client, ledger, enrollment, page_state) = {
        let owner = browser.owner.lock().await;
        let owner = owner.as_ref().unwrap();
        assert!(!owner.owns_context);
        assert_eq!(owner.recovery_identity(), identity);
        assert_eq!(
            owner.borrowed_targets.as_deref(),
            Some(&["host-page".to_owned()][..])
        );
        (
            owner.manager.client.clone(),
            owner.manager.client.debt_ledger().unwrap(),
            owner.runtime.as_ref().unwrap().enrollment.clone(),
            owner.page_state.clone(),
        )
    };
    assert_eq!(ledger.snapshot().input_debt, 0);
    assert!(!ledger.snapshot().integrity_lost);
    assert_eq!(page_state.mouse_state().unwrap().buttons, 0);
    framed.sequence += 1;
    let key = OperationKey {
        generation: 1,
        operation_seq: framed.sequence,
    };
    framed
        .write(json!({"type":"request","id":"p06-original","generation":1,
            "operationSeq":key.operation_seq,"timeoutMs":5000,"command":"browser.pointer",
            "args":{"identityScope":scope,"point":{"x":10,"y":10},"action":{"kind":"tap"}}}))
        .await
        .unwrap();
    bounded(async {
        while let Some(method) = original.received.recv().await {
            if method == "Input.dispatchMouseEvent" {
                return;
            }
        }
        panic!("P06 peer ended before receiving the original input")
    })
    .await;
    assert_eq!(
        browser
            .tasks
            .operation_retention_status(key)
            .mutation_dispatched(),
        Some(true)
    );
    assert_eq!(ledger.snapshot().input_debt, 1);
    assert!(!ledger.snapshot().integrity_lost);
    assert_eq!(page_state.mouse_state().unwrap().buttons, 0);
    {
        let commands = original.commands.lock().unwrap();
        let input = commands
            .iter()
            .find(|request| request["method"] == "Input.dispatchMouseEvent")
            .unwrap();
        assert_eq!(input["method"], "Input.dispatchMouseEvent");
        assert_eq!(input["sessionId"], "host-session");
        assert_eq!(input["params"]["type"], "mouseMoved");
        assert_eq!(input["params"]["buttons"], 0);
    }
    // Only the websocket peer closes. The real CdpClient reader observes EOF;
    // do not call ledger.observe_remote_eof, drop a waiter, or forge retention.
    original.emit.send(Message::Close(None)).await.unwrap();
    bounded(original.task).await.unwrap();
    let mut closed = client.remote_connection_closed();
    bounded(async {
        while !*closed.borrow_and_update() {
            closed.changed().await.unwrap();
        }
    })
    .await;
    let original_result = eof_recovery_result(&mut framed, "p06-original", key.operation_seq).await;
    assert_eq!(original_result["ok"], false);
    assert_eq!(original_result["effects"], "unknown");
    assert!(original_result.get("retention").is_none());
    // Joining the actual producer is not an acknowledgement of its remote
    // command. Retain the outcome of this join for the characterization test.
    let producer_drain = bounded(browser.tasks.drain()).await;
    assert!(!matches!(
        browser.tasks.operation_retention_status(key),
        crate::native::client_operation_state::OperationRetentionStatus::NotRegistered
    ));
    bounded(enrollment.drain()).await.unwrap();
    enrollment
        .terminal_connection_proof()
        .unwrap()
        .check_client(&client)
        .unwrap();
    assert!(ledger.matches_owner(1, &scope));
    assert_eq!(ledger.snapshot().input_debt, 1);
    assert!(ledger.snapshot().integrity_lost);
    // This is not the stronger debt-free final-local cleanup proof.
    assert!(ledger.check_final_local_eof(1, &scope).is_err());

    // A different transport advertising the exact retained browser/context/page
    // is eligible for verification, never a replacement page or input retry.
    let candidate = reconnect_peer(PeerMode::ReconnectCandidate).await;
    framed.sequence += 1;
    framed
        .write(json!({"type":"request","id":"p06-reconnect","generation":1,
            "operationSeq":framed.sequence,"timeoutMs":5000,"command":"scope.reconnect",
            "args":{"identityScope":scope,"endpoint":candidate.endpoint,
                "expectedBrowserIdentity":identity["browser"],
                "expectedContextIdentity":identity["context"],
                "expectedPageIdentity":identity["page"]}}))
        .await
        .unwrap();
    let reconnect_sequence = framed.sequence;
    let reconnect = eof_recovery_result(&mut framed, "p06-reconnect", reconnect_sequence).await;
    if reconnect["ok"] == true {
        assert_ne!(reconnect["data"]["identityScope"], scope);
    }
    let cleanup = tokio::time::timeout(Duration::from_secs(7), framed.finish())
        .await
        .expect("P06 native shutdown stalled");
    let candidate_commands = candidate.commands.lock().unwrap().clone();
    if reconnect["ok"] == true {
        // A claimed recovered scope must also finish its own native cleanup.
        // This does not clear or acknowledge the separately retained old debt.
        let peer = bounded(candidate.task).await;
        assert!(
            cleanup.is_ok() && peer.is_ok(),
            "recovered scope cleanup failed: {cleanup:?}; candidate peer: {peer:?}"
        );
    } else if candidate_commands.is_empty() {
        // Current refusal never opens the candidate. Stop its fixture listener,
        // but never mask a panic that completed before this explicit abort.
        candidate.task.abort();
        match candidate.task.await {
            Ok(()) => {}
            Err(error) if error.is_cancelled() => {}
            Err(error) => panic!("refused candidate peer failed: {error}"),
        }
    } else {
        bounded(candidate.task)
            .await
            .expect("rejected candidate transport did not finish cleanly");
    }
    assert!(!candidate_commands.iter().any(|request| matches!(
        request["method"].as_str(),
        Some("Page.navigate" | "Target.createTarget" | "Target.createBrowserContext")
    )));
    let commands = original.commands.lock().unwrap();
    assert_eq!(
        commands
            .iter()
            .filter(|r| r["method"] == "Input.dispatchMouseEvent")
            .count(),
        1,
        "the original action must never be replayed or continued after EOF"
    );
    assert!(!candidate_commands.iter().any(|r| r["method"]
        .as_str()
        .is_some_and(|m| m.starts_with("Input."))));
    assert_eq!(original_result["effects"], "unknown");
    assert_eq!(page_state.mouse_state().unwrap().buttons, 0);
    assert!(!matches!(
        browser.tasks.operation_retention_status(key),
        crate::native::client_operation_state::OperationRetentionStatus::NotRegistered
    ));
    assert!(ledger.matches_owner(1, &scope));
    assert_eq!(ledger.snapshot().input_debt, 1);
    assert!(ledger.snapshot().integrity_lost);
    EofRecoveryObservation {
        original: original_result,
        reconnect,
        producer_drain,
        cleanup,
        candidate_commands,
    }
}

#[tokio::test]
async fn p06_framed_input_eof_currently_quarantines_before_reconnect_verification() {
    let observed = framed_input_eof_reconnect().await;
    assert_eq!(observed.original["scopeState"], "quarantined");
    assert_eq!(observed.producer_drain, Err(ProtocolError::CleanupFailed));
    assert_eq!(observed.reconnect["ok"], false);
    assert_eq!(observed.reconnect["effects"], "not-dispatched");
    assert_eq!(observed.reconnect["scopeState"], "quarantined");
    assert_eq!(observed.reconnect["error"]["code"], "scope-unavailable");
    assert!(observed.candidate_commands.is_empty());
    assert!(observed.cleanup.is_err());
}

#[tokio::test]
async fn p06_framed_input_eof_explicit_reconnect_must_recover_session_without_replay() {
    let observed = framed_input_eof_reconnect().await;
    // Intentional RED on the current baseline. Recovery belongs only to the
    // session: the helper has already proved the original receipt stays Unknown,
    // its one dispatched input remains owned, and neither transport replays it.
    assert_eq!(
        observed.reconnect["ok"], true,
        "P06 exact-identity reconnect never reached verification: {}",
        observed.reconnect
    );
    assert_eq!(observed.reconnect["effects"], "completed");
    assert_eq!(observed.reconnect["scopeState"], "usable");
    assert!(observed.reconnect["data"]["identityScope"].is_string());
    assert!(observed
        .candidate_commands
        .iter()
        .any(|r| r["method"] == "Target.getTargetInfo"));
}
