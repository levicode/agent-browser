//! Actual readonly CDP-prefix races. No stale sample is promoted to publication.
//! Native helper/dispatcher proof only; original frozen consumers remain required.
use super::super::diagnostic;
use super::*;

fn request() -> DispatchRequest {
    DispatchRequest::Observe(ObserveRequest {
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
    let fixture = Fixture::new_mode(Race::HeldReleaseWithoutRace, true).await;
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
    for race in [Race::ReleaseError, Race::ReleaseWrongSession] {
        let fixture = Fixture::new_mode(race, true).await;
        let (fixture, capture, fence) = prepare(fixture);
        let cleanup = AtomicBool::new(false);
        let result = acquire(&fixture, &capture, fence, &cleanup, None).await;
        assert!(result.is_err(), "{race:?}");
        assert_eq!(fixture.samples.load(Ordering::SeqCst), 1);
        assert!(fixture.ledger.snapshot().object_debt > 0);
        assert!(fixture.ledger.snapshot().outstanding_commands > 0);
        assert_eq!(
            fixture.ledger.snapshot().integrity_lost,
            race == Race::ReleaseWrongSession
        );
        no_publication_or_semantics(&fixture);
        fixture.context.page.client.close().await;
        fixture.peer.await.unwrap();
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
        assert_eq!(refs.ref_ids(), vec![old_id.clone()]);
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
