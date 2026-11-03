//! Actual readonly CDP-prefix races. No stale sample is promoted to publication.
//! Native helper/dispatcher proof only; original frozen consumers remain required.
use super::super::diagnostic;
use super::*;

fn request() -> DispatchRequest {
    DispatchRequest::Observe(ObserveRequest {
        continuation: None,
        options: ObserveFlags::default(),
        test_id_attribute: "data-testid".into(),
        secure_field_selector: "input[type=password]".into(),
    })
}
fn prepare(mut fixture: Fixture) -> (Fixture, Arc<CaptureAdmission>, u64) {
    // Move the exact original permit/lease through real synchronous admission;
    // do not manufacture or clone a second scope permit for the tests.
    let prepared = fixture
        .dispatch
        .prepare(fixture.context, request(), fixture.operation)
        .unwrap();
    fixture.context = prepared.context;
    fixture.operation = prepared.operation;
    (
        fixture,
        prepared.capture.unwrap(),
        prepared.retirement_fence,
    )
}
async fn acquire(
    fixture: &Fixture,
    capture: &Arc<CaptureAdmission>,
    fence: u64,
    cleanup: &AtomicBool,
    witness: Option<&ScreenshotFailureWitness>,
) -> Result<Vec<ObservationFrame>, ProtocolError> {
    fixture
        .journal
        .scope(fixture.dispatch.initial_observe_frames(
            &fixture.context,
            &fixture.operation,
            Some(capture),
            fence,
            cleanup,
            witness,
        ))
        .await
}
fn no_publication_or_semantics(fixture: &Fixture) {
    no_protected_read(&fixture.log.lock().unwrap());
    assert!(!fixture
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|row| row["method"] == "Accessibility.getFullAXTree"));
    assert!(fixture.dispatch.refs.lock().unwrap().ref_ids().is_empty());
}
async fn ack_held_group(fixture: &Fixture, ordinal: usize) {
    let request = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let request = fixture
                .log
                .lock()
                .unwrap()
                .iter()
                .filter(|row| row["method"] == "Runtime.releaseObjectGroup")
                .nth(ordinal)
                .cloned();
            if let Some(request) = request {
                break request;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(request["sessionId"], "session");
    fixture
        .readonly_replies
        .send(json!({"id":request["id"],"sessionId":"session","result":{}}))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while fixture.ledger.snapshot().object_debt != 0
            || fixture.ledger.snapshot().outstanding_commands != 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!fixture.ledger.snapshot().integrity_lost);
}

#[tokio::test]
async fn observe_initial_same_document_reacquires_once_with_fresh_bindings() {
    for diagnostics in [false, true] {
        let fixture = Fixture::new_mode(Race::Once, true).await;
        let (fixture, capture, fence) = prepare(fixture);
        let witness = ScreenshotFailureWitness::new(&request(), &fixture.operation, diagnostics);
        screenshot_stage(witness.as_ref(), ScreenshotStage::InitialFrames);
        let cleanup = AtomicBool::new(false);
        let frames = acquire(&fixture, &capture, fence, &cleanup, witness.as_ref())
            .await
            .unwrap();
        assert!(Instant::now() < fixture.operation.deadline);
        assert_eq!(fixture.samples.load(Ordering::SeqCst), 2);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].binding.loader, "fresh-loader");
        assert_eq!(frames[0].url, "https://fixture.invalid/fresh");
        assert!(!cleanup.load(Ordering::SeqCst));
        assert_eq!(fixture.ledger.snapshot().object_debt, 0);
        assert_eq!(fixture.ledger.snapshot().outstanding_commands, 0);
        if let Some(witness) = witness {
            assert!(witness.take_failure(|| None).is_none());
        }
        no_publication_or_semantics(&fixture);
        fixture.context.page.client.close().await;
        fixture.peer.await.unwrap();
    }
}

#[tokio::test]
async fn observe_initial_reacquisition_is_bounded_and_keeps_original_refusals() {
    for (race, expected, samples) in [
        (Race::Continuous, ProtocolError::StaleScope, 2),
        (Race::Cancel, ProtocolError::Cancelled, 1),
        (Race::Sealed, ProtocolError::StaleScope, 1),
        (Race::Reservation, ProtocolError::StaleScope, 1),
        (Race::Replacement, ProtocolError::StaleScope, 1),
        (Race::Superseded, ProtocolError::StaleReference, 1),
        (Race::InvalidLoader, ProtocolError::StaleReference, 1),
        (Race::Deadline, ProtocolError::DeadlineExceeded, 1),
    ] {
        let fixture = Fixture::new_mode(race, true).await;
        let (fixture, capture, fence) = prepare(fixture);
        let cleanup = AtomicBool::new(false);
        let result = acquire(&fixture, &capture, fence, &cleanup, None).await;
        assert_eq!(result.err(), Some(expected), "{race:?}");
        assert_eq!(fixture.samples.load(Ordering::SeqCst), samples, "{race:?}");
        no_publication_or_semantics(&fixture);
        fixture.context.page.client.close().await;
        fixture.peer.await.unwrap();
    }
}

#[tokio::test]
async fn observe_initial_failed_prefix_held_group_ack_cannot_reacquire() {
    let fixture = Fixture::new_mode(Race::HeldRelease, true).await;
    let (fixture, capture, fence) = prepare(fixture);
    let cleanup = AtomicBool::new(false);
    let result = acquire(&fixture, &capture, fence, &cleanup, None).await;
    assert_eq!(result.err(), Some(ProtocolError::StaleScope));
    assert!(Instant::now() < fixture.operation.deadline);
    assert_eq!(fixture.samples.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.ledger.snapshot().object_debt, 1);
    assert_eq!(fixture.ledger.snapshot().outstanding_commands, 1);
    assert!(!fixture.ledger.snapshot().integrity_lost);
    no_publication_or_semantics(&fixture);
    ack_held_group(&fixture, 0).await;
    assert_eq!(
        fixture.samples.load(Ordering::SeqCst),
        1,
        "a later cleanup ACK cannot restart the failed read"
    );
    fixture.context.page.client.close().await;
    fixture.peer.await.unwrap();
}

#[tokio::test]
async fn observe_initial_second_success_retains_its_own_group_without_waiting() {
    let fixture = Fixture::new_mode(Race::HeldReleaseAfterReacquisition, true).await;
    let (fixture, capture, fence) = prepare(fixture);
    let cleanup = AtomicBool::new(false);
    let frames = acquire(&fixture, &capture, fence, &cleanup, None)
        .await
        .unwrap();
    assert!(Instant::now() < fixture.operation.deadline);
    assert_eq!(fixture.samples.load(Ordering::SeqCst), 2);
    assert!(frames
        .iter()
        .all(|frame| frame.binding.loader == "fresh-loader"));
    assert_eq!(fixture.ledger.snapshot().object_debt, 1);
    assert_eq!(fixture.ledger.snapshot().outstanding_commands, 1);
    assert!(!fixture.ledger.snapshot().integrity_lost);
    assert!(!cleanup.load(Ordering::SeqCst));
    no_publication_or_semantics(&fixture);
    ack_held_group(&fixture, 1).await;
    assert_eq!(fixture.samples.load(Ordering::SeqCst), 2);
    fixture.context.page.client.close().await;
    fixture.peer.await.unwrap();
}

#[tokio::test]
async fn observe_initial_first_success_keeps_original_accounted_group_contract() {
    let fixture = Fixture::new_mode(Race::HeldReleaseWithoutMutation, true).await;
    let (fixture, capture, fence) = prepare(fixture);
    let cleanup = AtomicBool::new(false);
    let frames = acquire(&fixture, &capture, fence, &cleanup, None)
        .await
        .unwrap();
    assert!(Instant::now() < fixture.operation.deadline);
    assert_eq!(fixture.samples.load(Ordering::SeqCst), 1);
    assert!(frames
        .iter()
        .all(|frame| frame.binding.loader == "old-loader"));
    assert_eq!(fixture.ledger.snapshot().object_debt, 1);
    assert_eq!(fixture.ledger.snapshot().outstanding_commands, 1);
    no_publication_or_semantics(&fixture);
    ack_held_group(&fixture, 0).await;
    fixture.context.page.client.close().await;
    fixture.peer.await.unwrap();
}

#[tokio::test]
async fn observe_initial_release_error_and_wrong_session_never_authorize_reacquisition() {
    // Exercise both arrival orders through the same pure rendezvous used by the
    // socket peer; a lone request must never produce either response.
    for release_first in [false, true] {
        let release =
            json!({"id":1,"sessionId":"session","error":{"code":-32000,"message":"release"}});
        let frame = json!({"id":2,"sessionId":"session","result":{}});
        let mut replies = ReleaseFenceReplies::default();
        let (first, second) = if release_first {
            (release.clone(), frame.clone())
        } else {
            (frame.clone(), release.clone())
        };
        assert!(replies.capture(release_first, first).is_none());
        assert_eq!(
            replies.capture(!release_first, second),
            Some([release, frame]),
            "release_first={release_first}"
        );
    }
    for race in [Race::ReleaseError, Race::ReleaseWrongSession] {
        let fixture = Fixture::new_mode(race, true).await;
        let (mut fixture, capture, fence) = prepare(fixture);
        let cleanup = AtomicBool::new(false);
        let result = acquire(&fixture, &capture, fence, &cleanup, None).await;
        let replies = tokio::time::timeout(
            Duration::from_secs(1),
            fixture.release_fence_receipt.take().unwrap(),
        )
        .await
        .unwrap_or_else(|_| panic!("{race:?} missing release/final-frame wire-order receipt"))
        .unwrap_or_else(|_| panic!("{race:?} peer ended before the ordered response pair"));
        let requests = fixture.log.lock().unwrap().clone();
        let release_requests: Vec<_> = requests
            .iter()
            .filter(|row| row["method"] == "Runtime.releaseObjectGroup")
            .collect();
        let trees: Vec<_> = requests
            .iter()
            .filter(|row| row["method"] == "Page.getFrameTree")
            .collect();
        assert_eq!(release_requests.len(), 1, "{race:?}: {requests:?}");
        assert_eq!(trees.len(), 4, "{race:?}: {requests:?}");
        assert_eq!(replies[0]["id"], release_requests[0]["id"], "{race:?}");
        assert_eq!(replies[1]["id"], trees[3]["id"], "{race:?}");
        assert_eq!(replies[1]["sessionId"], "session", "{race:?}");
        assert!(replies[1]["result"]["frameTree"].is_object(), "{race:?}");
        if race == Race::ReleaseError {
            assert_eq!(replies[0]["sessionId"], "session", "{race:?}");
            assert_eq!(replies[0]["error"]["code"], -32000, "{race:?}");
            assert!(replies[0].get("result").is_none(), "{race:?}");
        } else {
            assert_eq!(replies[0]["sessionId"], "other-session", "{race:?}");
            assert_eq!(replies[0]["result"], json!({}), "{race:?}");
            assert!(replies[0].get("error").is_none(), "{race:?}");
        }
        assert!(result.is_err(), "{race:?}: {replies:?}");
        assert!(
            !matches!(
                &result,
                Err(ProtocolError::DeadlineExceeded | ProtocolError::Cancelled)
            ),
            "{race:?} must refuse the poisoned prefix, not expire: {result:?}; {replies:?}"
        );
        assert_eq!(fixture.samples.load(Ordering::SeqCst), 1, "{race:?}");
        assert!(fixture.ledger.snapshot().object_debt > 0, "{race:?}");
        assert!(
            fixture.ledger.snapshot().outstanding_commands > 0,
            "{race:?}"
        );
        assert_eq!(
            fixture.ledger.snapshot().integrity_lost,
            race == Race::ReleaseWrongSession,
            "{race:?}: {replies:?}"
        );
        no_publication_or_semantics(&fixture);
        tokio::time::timeout(Duration::from_secs(1), fixture.context.page.client.close())
            .await
            .unwrap_or_else(|_| panic!("{race:?} client close timed out"));
        tokio::time::timeout(Duration::from_secs(1), fixture.peer)
            .await
            .unwrap_or_else(|_| panic!("{race:?} peer join timed out"))
            .unwrap_or_else(|error| panic!("{race:?} peer failed: {error}"));
    }
}

#[tokio::test]
async fn observe_initial_known_cleanup_loss_cannot_reacquire() {
    let fixture = Fixture::new_mode(Race::Once, true).await;
    let (fixture, capture, fence) = prepare(fixture);
    let cleanup = AtomicBool::new(true);
    assert_eq!(
        acquire(&fixture, &capture, fence, &cleanup, None)
            .await
            .err(),
        Some(ProtocolError::StaleScope)
    );
    assert!(cleanup.load(Ordering::SeqCst));
    assert_eq!(fixture.samples.load(Ordering::SeqCst), 1);
    no_publication_or_semantics(&fixture);
    fixture.context.page.client.close().await;
    fixture.peer.await.unwrap();
}

async fn dispatch_stops_before_semantics(race: Race) {
    let fixture = Fixture::new_mode(race, true).await;
    let client = fixture.context.page.client.clone();
    let old_id = {
        let mut refs = fixture.dispatch.refs.lock().unwrap();
        refs.begin_observation("scope", 1, 7);
        refs.try_bind_exact(
            77,
            "button",
            "Previously published",
            crate::native::element::ExactBinding {
                page_session: "session".into(),
                session: "session".into(),
                frame: "frame".into(),
                loader: "old-loader".into(),
                actionable: true,
            },
        )
        .unwrap()
    };
    {
        let mut publication = fixture.dispatch.publication.lock().await;
        publication.revision = 7;
        publication.published_revision = 7;
        publication.observed_revision = 7;
    }
    let witness = ScreenshotFailureWitness::new(&request(), &fixture.operation, true).unwrap();
    let prepared = fixture
        .dispatch
        .prepare_inner(
            fixture.context,
            request(),
            fixture.operation,
            Some(&witness),
        )
        .unwrap();
    let mut send = None;
    let receipt = ObservationResultReceipt::default();
    let failure = fixture
        .journal
        .scope(fixture.dispatch.run(
            prepared.context,
            prepared.request,
            prepared.operation,
            prepared.semantic_operation,
            prepared.capture,
            prepared.trace,
            prepared.retirement_fence,
            Some(&witness),
            &mut send,
            &receipt,
        ))
        .await
        .err()
        .unwrap();
    witness.failure(&failure.error);
    let first = witness.take_failure(|| None).unwrap();
    if race == Race::Protected {
        assert_eq!(failure.error, ProtocolError::StaleScope);
        // Initial + failed protected proof + the pre-existing post-cleanup
        // document-retirement classifier. The third read cannot resume capture.
        assert_eq!(fixture.samples.load(Ordering::SeqCst), 3);
        assert!(!fixture
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|row| row["method"] == "Page.getLayoutMetrics"));
        assert_eq!(first.stage, ScreenshotStage::FrameInventoryFence);
        let state = witness.state.lock().unwrap();
        assert_eq!(
            state.inventory_rejection.as_ref().unwrap().pass,
            diagnostic::FrameInventoryPass::Protected
        );
    } else {
        assert_eq!(failure.error, ProtocolError::BrowserFailure);
        assert_eq!(fixture.samples.load(Ordering::SeqCst), 3);
        assert_eq!(first.stage, ScreenshotStage::SemanticViewport);
    }
    assert!(!failure.cleanup_integrity_lost);
    assert!(!receipt.is_sealed_observation());
    {
        let refs = fixture.dispatch.refs.lock().unwrap();
        assert_eq!(
            refs.ref_ids(),
            std::collections::HashSet::from([old_id.clone()])
        );
        assert_eq!(refs.get(&old_id).unwrap().backend_node_id, Some(77));
        assert!(refs.get(&old_id).unwrap().is_current_observed(7));
    }
    let published = fixture.dispatch.publication.lock().await;
    assert_eq!(
        (published.published_revision, published.observed_revision),
        (7, 7)
    );
    drop(published);
    no_capture_or_input(&fixture.log.lock().unwrap());
    assert!(!fixture
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|row| row["method"] == "Accessibility.getFullAXTree"));
    client.close().await;
    fixture.peer.await.unwrap();
}
#[tokio::test]
async fn observe_dispatch_reaches_semantics_only_after_fresh_initial_sample() {
    dispatch_stops_before_semantics(Race::Once).await;
}
#[tokio::test]
async fn observe_dispatch_never_reacquires_a_protected_frame_fence() {
    dispatch_stops_before_semantics(Race::Protected).await;
}

// Receipt-boundary controls use the real admitted lease, retained task registry,
// dispatch result/join, read-settlement helpers, and same broker settlement.
// They do not execute the public CLI or infer owner validity from broker health.
async fn retained_observe_receipt_control(race: Race, acknowledge_after_receipt: bool) {
    use crate::native::client_browser::{
        protected_read_receipt_eligible, settle_observation_dispatch, settle_protected_read,
        settle_trace_screenshot,
    };
    use crate::native::client_protocol::{Effects, ScopeState};
    use crate::native::client_session::ClientSession;
    use crate::native::client_tasks::RetainedTasks;

    let broker = Arc::new(ClientSession::new());
    let fixture = Fixture::new_mode_with_broker(race, true, Some(broker.clone())).await;
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
        attached_others,
        ..
    } = fixture;
    let client = context.page.client.clone();
    let targets = context.page.targets.clone();
    let original_attachment = context.attachment.clone();
    assert!(original_attachment.capture_ready());
    assert!(original_attachment.same_attachment(&targets.owned_target("target").unwrap()));
    assert_eq!(
        journal.key(),
        OperationKey {
            generation: 1,
            operation_seq: 1
        }
    );
    assert!(ledger.matches_owner(operation.generation, &context.scope.identity_scope));
    let attach_other = matches!(
        race,
        Race::AttachOtherContinuous | Race::AttachOtherHeldRelease
    );
    let witness_receipt = Arc::new(Mutex::new(None));
    let witness_observer = witness_receipt.clone();
    let cancellation = operation.cancellation.clone();
    let identity_scope = context.scope.identity_scope.clone();
    let receipt_journal = journal.clone();
    let journal_probe = journal.clone();
    let retained = RetainedTasks::default();
    let observed_join = Arc::new(Mutex::new(None));
    let join_receipt = observed_join.clone();
    let run_dispatch = dispatch.clone();
    let receive = retained
        .start_operation_prepared(
            identity_scope,
            targets.clone(),
            broker.clone(),
            journal,
            cancellation,
            move || {
                let request = request();
                let eligible = protected_read_receipt_eligible(&request);
                let prepared = if attach_other {
                    let mut witness =
                        ScreenshotFailureWitness::new(&request, &operation, true).unwrap();
                    witness.receipt_for_test = Some(witness_observer);
                    let mut prepared =
                        run_dispatch.prepare_inner(context, request, operation, Some(&witness))?;
                    prepared.screenshot = Some(witness);
                    prepared
                } else {
                    run_dispatch.prepare(context, request, operation)?
                };
                Ok(async move {
                    let task = run_dispatch.start_prepared(prepared);
                    let output = task.result.await;
                    assert!(!task.receipt.is_sealed_observation());
                    let original_error = output
                        .as_ref()
                        .unwrap()
                        .as_ref()
                        .err()
                        .unwrap()
                        .error
                        .clone();
                    let cleanup = task.join.await;
                    // Observe the actual join. Never substitute Ok(cleanup).
                    let joined_clean = matches!(&cleanup, Ok(Ok(())));
                    let (outcome, dirty) = settle_observation_dispatch(output, cleanup);
                    *join_receipt.lock().unwrap() = Some((original_error, joined_clean, dirty));
                    let (outcome, dirty) =
                        settle_trace_screenshot(outcome, dirty, false, &receipt_journal);
                    settle_protected_read(outcome, dirty, eligible, &receipt_journal)
                })
            },
        )
        .await
        .unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(3), receive)
        .await
        .unwrap()
        .unwrap();
    let settled = broker
        .settle_with_retention(1, 1, outcome.effects, outcome.retention.as_ref())
        .unwrap();
    retained.fix_operation_result(OperationKey {
        generation: 1,
        operation_seq: 1,
    });
    let (original_error, joined_clean, dispatch_dirty) =
        observed_join.lock().unwrap().clone().unwrap();
    assert_eq!(outcome.result.as_ref().err(), Some(&original_error));
    assert!(outcome.retention.is_none());
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.input_debt, 0);
    assert!(!journal_probe.snapshot().mutation_dispatched);
    let same_owner = targets
        .owned_target("target")
        .ok()
        .map(|current| original_attachment.same_attachment(&current) && current.capture_ready());
    let terminal = matches!(race, Race::Sealed | Race::ReleaseWrongSession);
    assert_eq!(
        outcome.effects,
        if terminal {
            Effects::Unknown
        } else {
            Effects::NotDispatched
        }
    );
    assert_eq!(
        settled,
        if terminal {
            ScopeState::Quarantined
        } else {
            ScopeState::Usable
        }
    );
    assert_eq!(broker.health().unwrap(), (1, settled));
    if terminal {
        assert!(broker.admit(1, 2, 1_000).is_err());
        assert!(targets.owned_target("target").is_err());
    } else {
        assert!(joined_clean && !dispatch_dirty);
        assert_eq!(original_error, ProtocolError::StaleScope);
        assert_eq!(same_owner, Some(race != Race::Replacement));
        assert!(!snapshot.integrity_lost);
    }
    if matches!(
        race,
        Race::HeldRelease | Race::AttachOtherHeldRelease | Race::ReleaseError
    ) {
        assert_eq!(snapshot.object_debt, 1);
        assert_eq!(snapshot.outstanding_commands, 1);
    } else if matches!(
        race,
        Race::Continuous | Race::AttachOtherContinuous | Race::Replacement
    ) {
        assert_eq!(snapshot.object_debt, 0);
        assert_eq!(snapshot.outstanding_commands, 0);
    }
    let expected_samples = if matches!(race, Race::Continuous | Race::AttachOtherContinuous) {
        2
    } else {
        1
    };
    assert_eq!(samples.load(Ordering::SeqCst), expected_samples);
    if attach_other {
        // These are actual facts consumed by production witness.finish, not a
        // reconstruction from peer timing or manually assigned revision history.
        let (stage, sample, prefix, rejection) = witness_receipt.lock().unwrap().unwrap();
        assert_eq!(stage, ScreenshotStage::FrameInventoryFence);
        assert_eq!(sample, Some(expected_samples as u8));
        let rejection = rejection.unwrap();
        assert_eq!(rejection.pass, diagnostic::FrameInventoryPass::Initial);
        assert!(!rejection.sealed && !rejection.reservations);
        assert!(rejection.revision_mismatch && rejection.exact);
        assert_eq!(rejection.delta, Some(1));
        assert_eq!(rejection.events, Some([1, 0, 0, 0, 0, 0, 0]));
        assert_eq!(
            rejection.last_event,
            diagnostic::InventoryRevisionEvent::Attach
        );
        assert_eq!(
            rejection.last_target,
            diagnostic::InventoryRevisionTarget::Other
        );
        let others = attached_others.lock().unwrap();
        assert_eq!(others.len(), expected_samples);
        let last = others.last().unwrap();
        assert!(!original_attachment.same_attachment(last));
        assert!(last.capture_ready());
        assert_eq!(last.kind, "browser_ui");
        assert_eq!(
            rejection.selected_attachment,
            Some(
                original_attachment
                    .diagnostic_snapshot()
                    .unwrap()
                    .attachment
            )
        );
        assert_eq!(
            rejection.last_attachment,
            Some(last.diagnostic_snapshot().unwrap().attachment)
        );
        assert!(rejection.selected_attachment.unwrap() > 0);
        assert!(rejection.last_attachment.unwrap() > 0);
        assert_ne!(rejection.last_attachment, rejection.selected_attachment);
        if race == Race::AttachOtherHeldRelease {
            assert_eq!(
                prefix,
                Some(diagnostic::ObserveInitialPrefix {
                    check: diagnostic::ObserveInitialPrefixCheck::BeforeYield,
                    refusal: diagnostic::ObserveInitialPrefixRefusal::ObjectDebt,
                    debt: Some([0, 1, 1]),
                    debt_capped: Some(false),
                })
            );
        } else {
            assert!(prefix.is_none());
        }
        println!(
            "ATTACH_FENCE_CONTROL {}",
            json!({
                "case":format!("{race:?}"), "initialSample":sample,
                "pass":rejection.pass, "sealed":rejection.sealed,
                "reservations":rejection.reservations, "exact":rejection.exact,
                "delta":rejection.delta, "events":rejection.events,
                "lastEvent":rejection.last_event, "lastTarget":rejection.last_target,
                "selectedAttachmentOrdinal":rejection.selected_attachment,
                "lastAttachmentOrdinal":rejection.last_attachment,
                "prefixCheck":prefix.map(|value| value.check),
                "prefixRefusal":prefix.map(|value| value.refusal),
                "prefixDebt":prefix.and_then(|value| value.debt),
            })
        );
    }
    no_protected_read(&log.lock().unwrap());
    assert!(!log
        .lock()
        .unwrap()
        .iter()
        .any(|row| row["method"] == "Accessibility.getFullAXTree"));
    assert!(dispatch.refs.lock().unwrap().ref_ids().is_empty());
    {
        let published = dispatch.publication.lock().await;
        assert_eq!(
            (published.published_revision, published.observed_revision),
            (0, 0)
        );
    }
    println!(
        "READ_RECEIPT_CONTROL {}",
        json!({
            "case":format!("{race:?}"), "ackAfterReceipt":acknowledge_after_receipt,
            "error":original_error, "effects":outcome.effects, "scopeState":settled,
            "joinedClean":joined_clean, "dispatchDirty":dispatch_dirty,
            "sameOriginalAttachment":same_owner, "inputDebt":snapshot.input_debt,
            "objectDebt":snapshot.object_debt, "outstandingCommands":snapshot.outstanding_commands,
            "integrityLost":snapshot.integrity_lost,
        })
    );
    if acknowledge_after_receipt {
        assert_eq!(race, Race::HeldRelease);
        let requests: Vec<_> = log
            .lock()
            .unwrap()
            .iter()
            .filter(|row| row["method"] == "Runtime.releaseObjectGroup")
            .cloned()
            .collect();
        assert_eq!(requests.len(), 1);
        readonly_replies
            .send(json!({"id":requests[0]["id"],"sessionId":"session","result":{}}))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while ledger.snapshot().object_debt != 0 || ledger.snapshot().outstanding_commands != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Late ACK changes debt, never the already-fixed result or read count.
        assert_eq!(samples.load(Ordering::SeqCst), 1);
        assert_eq!(
            outcome.result.as_ref().err(),
            Some(&ProtocolError::StaleScope)
        );
        assert_eq!(outcome.effects, Effects::NotDispatched);
        assert_eq!(broker.health().unwrap(), (1, ScopeState::Usable));
        assert!(original_attachment.same_attachment(&targets.owned_target("target").unwrap()));
    }
    if matches!(race, Race::ReleaseError | Race::ReleaseWrongSession) {
        let replies = tokio::time::timeout(Duration::from_secs(1), release_fence_receipt.unwrap())
            .await
            .unwrap()
            .unwrap();
        let requests = log.lock().unwrap();
        let releases: Vec<_> = requests
            .iter()
            .filter(|row| row["method"] == "Runtime.releaseObjectGroup")
            .collect();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0]["sessionId"], "session");
        assert_eq!(replies[0]["id"], releases[0]["id"]);
        assert_ne!(replies[0]["id"], replies[1]["id"]);
        let final_frames: Vec<_> = requests
            .iter()
            .filter(|row| row["method"] == "Page.getFrameTree")
            .collect();
        assert_eq!(final_frames.len(), 4);
        assert_eq!(replies[1]["id"], final_frames.last().unwrap()["id"]);
        assert_eq!(replies[1]["sessionId"], "session");
        assert!(replies[1].get("error").is_none());
        assert!(replies[1]["result"]["frameTree"].is_object());
        let rejected = ledger.operation_has_rejected_cleanup(journal_probe.key(), "scope");
        if race == Race::ReleaseError {
            // A valid error ACK retains this exact cleanup obligation. It is
            // neither successful release nor transport/accounting corruption.
            assert_eq!(replies[0]["sessionId"], releases[0]["sessionId"]);
            assert_eq!(replies[0]["error"]["code"], -32000);
            assert!(replies[0].get("result").is_none());
            assert_eq!(rejected, Ok(true));
            assert_eq!(
                ledger.operation_has_rejected_cleanup(
                    OperationKey {
                        generation: 1,
                        operation_seq: 2
                    },
                    "scope"
                ),
                Ok(false)
            );
            assert_eq!(journal_probe.snapshot().object_debt, 1);
            assert!(!journal_probe.snapshot().integrity_lost);
        } else {
            // A reply for another session cannot acknowledge or merely reject
            // the original release, even with its correct request id.
            assert_eq!(replies[0]["sessionId"], "other-session");
            assert!(replies[0]["result"].is_object());
            assert!(replies[0].get("error").is_none());
            assert_eq!(rejected, Err(ProtocolError::CleanupFailed));
            assert!(snapshot.integrity_lost);
            assert!(journal_probe.snapshot().integrity_lost);
        }
    }
    let commands_before_drain = log.lock().unwrap().clone();
    let drained = retained.drain().await;
    assert_eq!(*log.lock().unwrap(), commands_before_drain);
    assert_eq!(samples.load(Ordering::SeqCst), expected_samples);
    if race == Race::ReleaseError {
        assert_eq!(ledger.snapshot().object_debt, 1);
        assert_eq!(ledger.snapshot().outstanding_commands, 1);
        assert_eq!(
            ledger.operation_has_rejected_cleanup(journal_probe.key(), "scope"),
            Ok(true)
        );
    }
    assert_eq!(drained.is_err(), terminal);
    tokio::time::timeout(Duration::from_secs(1), client.close())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn observe_receipt_continuous_read_race_keeps_clean_owned_scope() {
    retained_observe_receipt_control(Race::Continuous, false).await;
}
#[tokio::test]
async fn observe_receipt_held_release_is_not_a_settled_prefix() {
    retained_observe_receipt_control(Race::HeldRelease, false).await;
}
#[tokio::test]
async fn observe_receipt_late_release_ack_cannot_restart_failed_read() {
    retained_observe_receipt_control(Race::HeldRelease, true).await;
}
#[tokio::test]
async fn observe_receipt_usable_broker_does_not_restore_replaced_attachment() {
    retained_observe_receipt_control(Race::Replacement, false).await;
}
#[tokio::test]
async fn observe_receipt_sealed_owner_stays_terminal() {
    retained_observe_receipt_control(Race::Sealed, false).await;
}
#[tokio::test]
async fn observe_receipt_failed_release_preserves_terminal_cleanup() {
    retained_observe_receipt_control(Race::ReleaseError, false).await;
}
#[tokio::test]
async fn observe_receipt_wrong_session_release_preserves_terminal_cleanup() {
    retained_observe_receipt_control(Race::ReleaseWrongSession, false).await;
}

#[tokio::test]
async fn observe_receipt_other_attach_each_sample_has_exact_initial_delta_one() {
    retained_observe_receipt_control(Race::AttachOtherContinuous, false).await;
}
#[tokio::test]
async fn observe_receipt_other_attach_with_held_release_has_exact_prefix_refusal() {
    retained_observe_receipt_control(Race::AttachOtherHeldRelease, false).await;
}
