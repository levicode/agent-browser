//! Deterministic initial trace-inventory races over the real native CDP reader.
//! These fixtures stop at protected-read admission; they do not claim browser QA.
use super::diagnostic::InventoryRevisionEvent;
use super::*;
use crate::native::cdp::client::CdpClient;
use crate::native::client_blobs::BlobLimits;
use crate::native::client_browser::ExecutionGate;
use crate::native::client_debt::{
    OperationJournalHandle, OperationKey, OwnerCleanupCommand, OwnerDebtLedger, OwnerDebtSnapshot,
};
use crate::native::client_targets::ClientTargets;
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::AtomicUsize;
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Race {
    Once,
    Continuous,
    Cancel,
    Sealed,
    Reservation,
    Replacement,
    HeldRelease,
    HeldReleaseAfterReacquisition,
    Protected,
    InvalidLoader,
}
struct Fixture {
    context: DispatchContext,
    operation: OperationLease,
    journal: OperationJournalHandle,
    ledger: Arc<OwnerDebtLedger>,
    dispatch: Arc<ObservationDispatch>,
    cancel: tokio::sync::watch::Sender<CancelSignal>,
    samples: Arc<AtomicUsize>,
    log: Arc<Mutex<Vec<Value>>>,
    peer: tokio::task::JoinHandle<()>,
}
async fn ready(targets: &Arc<ClientTargets>) {
    targets
        .attached("context", "target".into(), "session".into(), "page".into())
        .unwrap();
    targets.configured("target").unwrap();
    targets
        .resume_permit("target")
        .await
        .unwrap()
        .complete()
        .unwrap();
    targets.acknowledge_enrollment().unwrap();
}
impl Fixture {
    async fn new(race: Race) -> Self {
        let targets = ClientTargets::new("context".into(), "scope".into());
        ready(&targets).await;
        let (cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let peer_cancel = cancel.clone();
        let peer_targets = targets.clone();
        let samples = Arc::new(AtomicUsize::new(0));
        let peer_samples = samples.clone();
        let log = Arc::new(Mutex::new(Vec::new()));
        let peer_log = log.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut trees = 0;
            let mut releases = 0;
            let mut reservation = None;
            let child = matches!(
                race,
                Race::HeldRelease | Race::HeldReleaseAfterReacquisition
            );
            while let Some(Ok(Message::Text(text))) = socket.next().await {
                let request: Value = serde_json::from_str(&text).unwrap();
                peer_log.lock().unwrap().push(request.clone());
                let method = request["method"].as_str().unwrap();
                let mut failed = false;
                let result = match method {
                    "Page.getFrameTree" => {
                        trees += 1;
                        let completed = peer_samples.load(Ordering::SeqCst);
                        let last = trees == if child { 4 } else { 3 };
                        let loader = if race == Race::InvalidLoader && last {
                            "unmatched-loader"
                        } else if completed == 0 || race == Race::Protected {
                            "old-loader"
                        } else {
                            "fresh-loader"
                        };
                        let mut result = json!({"frameTree":{"frame":{"id":"frame","loaderId":loader,"url":"about:blank"}}});
                        if child {
                            result["frameTree"]["childFrames"] = json!([{"frame":{"id":"child","parentId":"frame","loaderId":loader,"url":"about:blank"}}]);
                        }
                        // Inventory, enumeration, then one exact loader validation
                        // per frame. Inject only at the final ACK of a full sample.
                        if last {
                            trees = 0;
                            peer_samples.fetch_add(1, Ordering::SeqCst);
                            let invalidate = match race {
                                Race::Continuous => true,
                                Race::Protected => completed == 1,
                                Race::InvalidLoader => false,
                                _ => completed == 0,
                            };
                            if invalidate {
                                peer_targets
                                    .invalidate_inventory_for(
                                        InventoryRevisionEvent::Navigate,
                                        "target",
                                    )
                                    .unwrap();
                                peer_targets
                                    .invalidate_inventory_for(
                                        InventoryRevisionEvent::Info,
                                        "target",
                                    )
                                    .unwrap();
                            }
                            if completed == 0 {
                                match race {
                                    Race::Cancel => {
                                        peer_cancel.send_replace(CancelSignal::Requested);
                                    }
                                    Race::Sealed => peer_targets.seal_admission(),
                                    Race::Reservation => {
                                        reservation = Some(
                                            peer_targets
                                                .reserve_creation(TargetPurpose::Application)
                                                .unwrap(),
                                        );
                                    }
                                    Race::Replacement => {
                                        peer_targets.detach("target").unwrap();
                                        ready(&peer_targets).await;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        result
                    }
                    "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                    "DOM.getFrameOwner" if child => {
                        assert_eq!(request["params"]["frameId"], "child");
                        json!({"backendNodeId":101})
                    }
                    "DOM.resolveNode" if child => {
                        json!({"object":{"subtype":"node","objectId":format!("owner-{releases}")}})
                    }
                    "Runtime.callFunctionOn" if child => {
                        assert_eq!(
                            request["params"]["functionDeclaration"],
                            observation::FRAME_OWNER_GEOMETRY
                        );
                        json!({"result":{"value":{"x":0,"y":0,"selector":"iframe"}}})
                    }
                    "Runtime.releaseObject" if child => {
                        releases += 1;
                        if race == Race::HeldRelease || releases == 2 {
                            // Keep the socket alive and process later reads. The
                            // release is accounted, but deliberately has no ACK.
                            continue;
                        }
                        json!({})
                    }
                    "Target.setAutoAttach" => {
                        assert_eq!(request["params"]["autoAttach"], false);
                        json!({})
                    }
                    "Animation.enable" => json!({}),
                    "Animation.getPlaybackRate" if race == Race::Protected => {
                        json!({"playbackRate":1})
                    }
                    "Animation.setPlaybackRate" if race == Race::Protected => {
                        assert!(
                            request["params"]["playbackRate"] == 0
                                || request["params"]["playbackRate"] == 1
                        );
                        json!({})
                    }
                    "Animation.getPlaybackRate" => {
                        failed = true;
                        json!({})
                    }
                    other => panic!("unexpected initial trace command: {other}"),
                };
                let mut response =
                    json!({"id":request["id"],"sessionId":request["sessionId"],"result":result});
                if failed {
                    response.as_object_mut().unwrap().remove("result");
                    response["error"] =
                        json!({"code":-32000,"message":"stop after initial acquisition"});
                }
                if socket
                    .send(Message::Text(response.to_string()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            drop(reservation);
        });
        let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
        let ledger = OwnerDebtLedger::new(1, "scope".into());
        client.install_debt_ledger(ledger.clone()).unwrap();
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline: Instant::now()
                + Duration::from_secs(if race == Race::Continuous { 1 } else { 5 }),
            cancellation,
        };
        let journal = ledger
            .operation(
                OperationKey {
                    generation: 1,
                    operation_seq: 1,
                },
                "target".into(),
                "session".into(),
            )
            .unwrap();
        journal.bind_operation(&operation).unwrap();
        let gate = Arc::new(ExecutionGate::default());
        // One handle permits the original quota reservation, never one per sample.
        let blobs = Arc::new(
            BlobStore::new(BlobLimits {
                max_blob_bytes: 1024,
                max_total_bytes: 1024,
                max_handles: 1,
            })
            .unwrap(),
        );
        let scope = BlobScope {
            generation: 1,
            identity_scope: "scope".into(),
        };
        blobs.activate_scope(scope.clone()).unwrap();
        let context = DispatchContext {
            #[cfg(feature = "acceptance-faults")]
            faults: Arc::new(crate::native::client_test_faults::FaultController::default()),
            attachment: targets.owned_target("target").unwrap(),
            page: BrowserExecutionLease {
                client,
                page_session_id: "session".into(),
                target_id: "target".into(),
                identity_scope: "scope".into(),
                permit: gate.enter(false).unwrap(),
                targets,
            },
            ui: Arc::new(UiGate::default()),
            blobs,
            scope,
            policy: ReadPolicy {
                test_id_attribute: "data-testid".into(),
                secure_field_selector: "input[type=password]".into(),
            },
        };
        Self {
            context,
            operation,
            journal,
            ledger,
            dispatch: ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new()))),
            cancel,
            samples,
            log,
            peer,
        }
    }
}
#[tokio::test]
async fn trace_initial_inventory_single_navigation_race_reaches_protected_read() {
    let fixture = Fixture::new(Race::Once).await;
    let blobs = fixture.context.blobs.clone();
    let scope = fixture.context.scope.clone();
    let client = fixture.context.page.client.clone();
    let request = DispatchRequest::Screenshot(ScreenshotRequest {
        purpose: ScreenshotPurpose::Trace,
        secure_field_selector: "input[type=password]".into(),
    });
    let witness = ScreenshotFailureWitness::new(&request, &fixture.operation, true).unwrap();
    let prepared = fixture
        .dispatch
        .prepare_inner(fixture.context, request, fixture.operation, Some(&witness))
        .unwrap();
    let result = fixture
        .journal
        .scope(fixture.dispatch.run(
            prepared.context,
            prepared.request,
            prepared.operation,
            prepared.capture,
            prepared.trace,
            prepared.retirement_fence,
            Some(&witness),
        ))
        .await;
    let failure = result.err().unwrap();
    // On the old one-shot implementation this is StaleScope after one sample.
    // The expected behavior completes a wholly fresh second sample before the
    // deliberately failing protected-read command, without retrying that command.
    assert_eq!(failure.error, ProtocolError::BrowserFailure);
    assert!(!failure.cleanup_integrity_lost);
    assert_eq!(fixture.samples.load(Ordering::SeqCst), 2);
    witness.failure(&failure.error);
    let first = witness.take_failure(|| None).unwrap();
    assert_eq!(first.stage, ScreenshotStage::AnimationStabilization);
    assert_eq!(first.error, ProtocolError::BrowserFailure);
    assert!(witness.state.lock().unwrap().inventory_rejection.is_none());
    assert_eq!(fixture.ledger.snapshot().outstanding_commands, 0);
    assert_eq!(fixture.ledger.snapshot().object_debt, 0);
    assert!(!fixture.ledger.snapshot().integrity_lost);
    assert!(!fixture
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|row| row["method"] == "Page.captureScreenshot"
            || row["method"].as_str().unwrap().starts_with("Input.")));
    drop(blobs.reserve_bounded_producer(scope, 1024).unwrap());
    client.close().await;
    fixture.peer.await.unwrap();
}

struct FailureOutcome {
    error: ProtocolError,
    cleanup_integrity_lost: bool,
    first: Option<ScreenshotFailure>,
    inventory: Option<diagnostic::FrameInventoryRejection>,
    samples: usize,
    debt: OwnerDebtSnapshot,
    log: Vec<Value>,
}
impl Fixture {
    async fn run_failure(self, purpose: ScreenshotPurpose, diagnostics: bool) -> FailureOutcome {
        let request = DispatchRequest::Screenshot(ScreenshotRequest {
            purpose,
            secure_field_selector: "input[type=password]".into(),
        });
        let witness = ScreenshotFailureWitness::new(&request, &self.operation, diagnostics);
        let client = self.context.page.client.clone();
        let blobs = self.context.blobs.clone();
        let scope = self.context.scope.clone();
        let prepared = self
            .dispatch
            .prepare_inner(self.context, request, self.operation, witness.as_ref())
            .unwrap();
        let failure = self
            .journal
            .scope(self.dispatch.run(
                prepared.context,
                prepared.request,
                prepared.operation,
                prepared.capture,
                prepared.trace,
                prepared.retirement_fence,
                witness.as_ref(),
            ))
            .await
            .err()
            .unwrap();
        // If the original deadline won a final read/ACK race, let the existing
        // reader settle that exact response, never resend a command.
        if failure.error == ProtocolError::DeadlineExceeded {
            tokio::time::timeout(Duration::from_secs(1), async {
                while self.ledger.snapshot().outstanding_commands != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        let first = witness.as_ref().and_then(|witness| {
            witness.failure(&failure.error);
            witness.take_failure(|| None)
        });
        let inventory = witness
            .as_ref()
            .and_then(|witness| witness.state.lock().unwrap().inventory_rejection.take());
        let outcome = FailureOutcome {
            error: failure.error,
            cleanup_integrity_lost: failure.cleanup_integrity_lost,
            first,
            inventory,
            samples: self.samples.load(Ordering::SeqCst),
            debt: self.ledger.snapshot(),
            log: self.log.lock().unwrap().clone(),
        };
        // The original reservation was released and never multiplied by a retry.
        let quota = blobs.reserve_bounded_producer(scope.clone(), 1024).unwrap();
        assert!(blobs.reserve_bounded_producer(scope, 1).is_err());
        drop(quota);
        client.close().await;
        self.peer.await.unwrap();
        outcome
    }
}
fn no_capture_or_input(log: &[Value]) {
    assert!(!log
        .iter()
        .any(|row| row["method"] == "Page.captureScreenshot"
            || row["method"].as_str().unwrap().starts_with("Input.")));
}
fn no_protected_read(log: &[Value]) {
    no_capture_or_input(log);
    assert!(!log
        .iter()
        .any(|row| row["method"].as_str().unwrap().starts_with("Animation.")));
}
fn settled(outcome: &FailureOutcome) {
    assert!(!outcome.cleanup_integrity_lost);
    assert!(!outcome.debt.integrity_lost);
    assert_eq!(outcome.debt.input_debt, 0);
    assert_eq!(outcome.debt.object_debt, 0);
    assert_eq!(outcome.debt.outstanding_commands, 0);
}
#[tokio::test]
async fn trace_initial_inventory_reacquisition_is_independent_of_diagnostics() {
    let outcome = Fixture::new(Race::Once)
        .await
        .run_failure(ScreenshotPurpose::Trace, false)
        .await;
    assert_eq!(outcome.error, ProtocolError::BrowserFailure);
    assert_eq!(outcome.samples, 2);
    assert!(outcome.first.is_none());
    assert!(outcome.inventory.is_none());
    settled(&outcome);
    no_capture_or_input(&outcome.log);
}
#[tokio::test]
async fn trace_initial_inventory_discards_old_bindings_and_recovers_without_failure_witness() {
    let fixture = Fixture::new(Race::Once).await;
    let request = DispatchRequest::Screenshot(ScreenshotRequest {
        purpose: ScreenshotPurpose::Trace,
        secure_field_selector: "input[type=password]".into(),
    });
    let witness = ScreenshotFailureWitness::new(&request, &fixture.operation, true).unwrap();
    witness.enter(ScreenshotStage::InitialFrames);
    let cleanup = AtomicBool::new(false);
    let frames = fixture
        .journal
        .scope(fixture.dispatch.initial_trace_frames(
            &fixture.context,
            &fixture.operation,
            fixture.dispatch.publication_fence().unwrap(),
            &cleanup,
            Some(&witness),
        ))
        .await
        .unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].binding.loader, "fresh-loader");
    assert_eq!(fixture.samples.load(Ordering::SeqCst), 2);
    assert!(witness.take_failure(|| None).is_none());
    assert!(witness.state.lock().unwrap().inventory_rejection.is_none());
    assert!(!cleanup.load(Ordering::SeqCst));
    assert_eq!(fixture.ledger.snapshot().outstanding_commands, 0);
    assert_eq!(fixture.ledger.snapshot().object_debt, 0);
    no_protected_read(&fixture.log.lock().unwrap());
    fixture.context.page.client.close().await;
    fixture.peer.await.unwrap();
}
#[tokio::test]
async fn trace_initial_inventory_continuous_navigation_uses_original_deadline() {
    let outcome = Fixture::new(Race::Continuous)
        .await
        .run_failure(ScreenshotPurpose::Trace, true)
        .await;
    assert_eq!(outcome.error, ProtocolError::DeadlineExceeded);
    assert!(outcome.samples >= 2);
    assert_eq!(
        outcome.first.as_ref().unwrap().stage,
        ScreenshotStage::InitialFrames
    );
    assert!(
        outcome.inventory.is_none(),
        "recovered fences cannot replace the terminal deadline"
    );
    settled(&outcome);
    no_protected_read(&outcome.log);
}
#[tokio::test]
async fn trace_initial_inventory_cancel_wins_without_reacquisition() {
    let outcome = Fixture::new(Race::Cancel)
        .await
        .run_failure(ScreenshotPurpose::Trace, true)
        .await;
    assert_eq!(outcome.error, ProtocolError::Cancelled);
    assert_eq!(outcome.samples, 1);
    assert_eq!(
        outcome.first.as_ref().unwrap().stage,
        ScreenshotStage::InitialFrames
    );
    assert!(outcome.inventory.is_none());
    settled(&outcome);
    no_protected_read(&outcome.log);
}
#[tokio::test]
async fn trace_initial_inventory_pre_cancel_sends_no_commands() {
    let fixture = Fixture::new(Race::Once).await;
    fixture.cancel.send_replace(CancelSignal::Requested);
    let cleanup = AtomicBool::new(false);
    let error = fixture
        .journal
        .scope(fixture.dispatch.initial_trace_frames(
            &fixture.context,
            &fixture.operation,
            fixture.dispatch.publication_fence().unwrap(),
            &cleanup,
            None,
        ))
        .await
        .err()
        .unwrap();
    assert_eq!(error, ProtocolError::Cancelled);
    assert!(fixture.log.lock().unwrap().is_empty());
    fixture.context.page.client.close().await;
    fixture.peer.await.unwrap();
}
#[tokio::test]
async fn trace_initial_inventory_sealed_and_reserved_fences_are_not_retryable() {
    for race in [Race::Sealed, Race::Reservation] {
        let outcome = Fixture::new(race)
            .await
            .run_failure(ScreenshotPurpose::Trace, true)
            .await;
        assert_eq!(outcome.error, ProtocolError::StaleScope, "{race:?}");
        assert_eq!(outcome.samples, 1, "{race:?}");
        assert_eq!(
            outcome.first.as_ref().unwrap().stage,
            ScreenshotStage::FrameInventoryFence
        );
        let inventory = outcome.inventory.as_ref().unwrap();
        assert_eq!(inventory.sealed, race == Race::Sealed);
        assert_eq!(inventory.reservations, race == Race::Reservation);
        assert!(inventory.revision_mismatch);
        settled(&outcome);
        no_protected_read(&outcome.log);
    }
}
#[tokio::test]
async fn trace_initial_inventory_same_ids_new_attachment_cannot_reacquire() {
    let outcome = Fixture::new(Race::Replacement)
        .await
        .run_failure(ScreenshotPurpose::Trace, true)
        .await;
    assert_eq!(outcome.error, ProtocolError::StaleScope);
    assert_eq!(outcome.samples, 1);
    assert_eq!(
        outcome.first.as_ref().unwrap().stage,
        ScreenshotStage::InitialFrames
    );
    assert!(outcome.inventory.is_none());
    settled(&outcome);
    no_protected_read(&outcome.log);
}
#[tokio::test]
async fn trace_initial_inventory_accounted_release_without_ack_cannot_reacquire() {
    let outcome = Fixture::new(Race::HeldRelease)
        .await
        .run_failure(ScreenshotPurpose::Trace, true)
        .await;
    assert_eq!(outcome.error, ProtocolError::StaleScope);
    assert_eq!(outcome.samples, 1);
    assert!(!outcome.cleanup_integrity_lost);
    assert!(!outcome.debt.integrity_lost);
    assert_eq!(outcome.debt.object_debt, 1);
    assert_eq!(outcome.debt.outstanding_commands, 1);
    assert_eq!(
        outcome.first.as_ref().unwrap().stage,
        ScreenshotStage::FrameInventoryFence
    );
    assert!(outcome.inventory.as_ref().unwrap().revision_mismatch);
    no_protected_read(&outcome.log);
}
#[tokio::test]
async fn trace_initial_inventory_new_debt_after_reacquisition_is_current_stage_failure() {
    let outcome = Fixture::new(Race::HeldReleaseAfterReacquisition)
        .await
        .run_failure(ScreenshotPurpose::Trace, true)
        .await;
    assert_eq!(outcome.error, ProtocolError::ScopeUnavailable);
    assert_eq!(outcome.samples, 2);
    assert!(!outcome.cleanup_integrity_lost);
    assert!(!outcome.debt.integrity_lost);
    assert_eq!(outcome.debt.object_debt, 1);
    assert_eq!(outcome.debt.outstanding_commands, 1);
    assert_eq!(
        outcome.first.as_ref().unwrap().stage,
        ScreenshotStage::InitialFrames
    );
    assert!(
        outcome.inventory.is_none(),
        "the recovered first fence is not terminal evidence"
    );
    no_protected_read(&outcome.log);
}
#[tokio::test]
async fn trace_initial_inventory_protected_phase_remains_one_shot() {
    let outcome = Fixture::new(Race::Protected)
        .await
        .run_failure(ScreenshotPurpose::Trace, true)
        .await;
    assert_eq!(outcome.error, ProtocolError::StaleScope);
    assert_eq!(
        outcome.samples, 2,
        "one initial sample and exactly one protected sample"
    );
    assert_eq!(
        outcome.first.as_ref().unwrap().stage,
        ScreenshotStage::FrameInventoryFence
    );
    assert_eq!(
        outcome.inventory.as_ref().unwrap().pass,
        diagnostic::FrameInventoryPass::Protected
    );
    assert_eq!(
        outcome
            .log
            .iter()
            .filter(|row| row["method"] == "Animation.setPlaybackRate"
                && row["params"]["playbackRate"] == 0)
            .count(),
        1
    );
    assert_eq!(
        outcome
            .log
            .iter()
            .filter(|row| row["method"] == "Animation.setPlaybackRate"
                && row["params"]["playbackRate"] == 1)
            .count(),
        1
    );
    settled(&outcome);
    no_capture_or_input(&outcome.log);
}
#[tokio::test]
async fn trace_initial_inventory_final_phase_helper_remains_one_shot() {
    let fixture = Fixture::new(Race::Once).await;
    let request = DispatchRequest::Screenshot(ScreenshotRequest {
        purpose: ScreenshotPurpose::Trace,
        secure_field_selector: "input[type=password]".into(),
    });
    let witness = ScreenshotFailureWitness::new(&request, &fixture.operation, true).unwrap();
    witness.enter(ScreenshotStage::FinalFrames);
    let cleanup = AtomicBool::new(false);
    let error = fixture
        .journal
        .scope(verified_frames_with_diagnostic(
            &fixture.context.page,
            &fixture.operation,
            Some(&cleanup),
            Some(&witness),
        ))
        .await
        .err()
        .unwrap();
    assert_eq!(error, ProtocolError::StaleScope);
    assert_eq!(fixture.samples.load(Ordering::SeqCst), 1);
    assert_eq!(
        witness
            .state
            .lock()
            .unwrap()
            .inventory_rejection
            .as_ref()
            .unwrap()
            .pass,
        diagnostic::FrameInventoryPass::Final
    );
    no_protected_read(&fixture.log.lock().unwrap());
    fixture.context.page.client.close().await;
    fixture.peer.await.unwrap();
}
#[tokio::test]
async fn trace_initial_inventory_pixels_only_remains_one_shot() {
    let outcome = Fixture::new(Race::Once)
        .await
        .run_failure(ScreenshotPurpose::PixelsOnly, true)
        .await;
    assert_eq!(outcome.error, ProtocolError::StaleScope);
    assert_eq!(outcome.samples, 1);
    assert!(outcome.first.is_none());
    settled(&outcome);
    no_protected_read(&outcome.log);
}
#[tokio::test]
async fn trace_initial_inventory_loader_failure_is_not_revision_retry() {
    let outcome = Fixture::new(Race::InvalidLoader)
        .await
        .run_failure(ScreenshotPurpose::Trace, true)
        .await;
    assert_eq!(outcome.error, ProtocolError::StaleReference);
    assert_eq!(outcome.samples, 1);
    assert_eq!(
        outcome.first.as_ref().unwrap().stage,
        ScreenshotStage::InitialFrames
    );
    assert!(outcome.inventory.is_none());
    settled(&outcome);
    no_protected_read(&outcome.log);
}
#[tokio::test]
async fn trace_initial_inventory_settlement_requires_exact_current_owner() {
    let mut fixture = Fixture::new(Race::Once).await;
    let client = fixture.context.page.client.clone();
    let same_names = OwnerDebtLedger::new(1, "scope".into());
    assert_eq!(same_names.snapshot().outstanding_commands, 0);
    assert_eq!(
        client.check_cleanup_owner(&Some(same_names.clone())),
        Err(ProtocolError::StaleScope)
    );
    assert_eq!(
        client.install_debt_ledger(same_names),
        Err(ProtocolError::StaleScope)
    );
    // A frozen old owner cannot use a replacement transport's clean ledger.
    fixture.context.page.client = client.owner_view(fixture.ledger.clone()).unwrap();
    fixture.ledger.bind_context("context").unwrap();
    fixture
        .ledger
        .retire_after_context_destroy("context")
        .unwrap();
    client
        .send_owner_cleanup(
            Some(fixture.ledger.clone()),
            OwnerCleanupCommand::DisableAutoAttach,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
    let replacement = OwnerDebtLedger::new(2, "replacement".into());
    client.install_debt_ledger(replacement).unwrap();
    assert_eq!(
        fixture
            .context
            .page
            .client
            .check_cleanup_owner(&Some(fixture.ledger.clone())),
        Err(ProtocolError::StaleScope)
    );
    assert!(!ObservationDispatch::initial_trace_prefix_settled(
        &fixture.context,
        &fixture.operation,
        &AtomicBool::new(false)
    ));
    assert_eq!(fixture.log.lock().unwrap().len(), 1);
    assert_eq!(
        fixture.log.lock().unwrap()[0]["method"],
        "Target.setAutoAttach"
    );
    client.close().await;
    fixture.peer.await.unwrap();
}
