//! Scoped orchestration of the existing native matcher and protected capture.
//! The executor retains every task through restoration; capabilities are gated
//! separately by browser conformance, not by this module's existence.
use super::client_blobs::{BlobError, BlobScope, BlobStore};
use super::client_browser::BrowserExecutionLease;
use super::client_capture::{
    self, CaptureAttemptFailure, CaptureContext, CapturePhase, CaptureReason, CaptureRequest,
};
use super::client_geometry::GeometrySnapshot;
use super::client_observation::{
    self as observation, ObservationError, ObservationFrame, ObservationOptions, QueryOptions,
    SemanticNode,
};
use super::client_protected_read::{ProtectedReadJournal, ProtectedReadReason};
use super::client_protocol::ProtocolError;
use super::client_session::{CancelSignal, OperationLease};
use super::client_settlement_trace::{
    self as diagnostic, InventoryAfterFailure, ScreenshotCapturePhase, ScreenshotFailure,
    ScreenshotStage,
};
use super::client_targets::TargetPurpose;
use super::client_ui::UiGate;
use super::element::{parse_ref, RefMap};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
#[cfg(test)]
#[path = "client_observation_composition_dispatch_tests.rs"]
mod composition_tests;
#[path = "client_reference_correlation.rs"]
mod reference_correlation;
#[cfg(test)]
#[path = "client_capture_supersession_tests.rs"]
mod supersession_tests;
pub use reference_correlation::CorrelateRequest;

// Failure-only hosted-test evidence. This value lives in one dispatcher run,
// not a global registry or inherited task-local, and cannot mix operations.
// The semantic phase deliberately remains aggregate: no renderer values,
// command arguments, identities, or exception text enter this witness.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObserveFailureStage {
    Admission,
    InitialFrames,
    ProtectedBarrier,
    ProtectedFrames,
    Viewport,
    SemanticRead,
    Geometry,
    DocumentRoot,
    Restoration,
    FinalProof,
    Publication,
}

#[cfg(test)]
struct ObserveFailureWitness {
    enabled: bool,
    state: Mutex<(ObserveFailureStage, bool)>,
}

#[cfg(test)]
impl ObserveFailureWitness {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            state: Mutex::new((ObserveFailureStage::Admission, false)),
        }
    }
    fn enter(&self, stage: ObserveFailureStage) {
        if let Ok(mut state) = self.state.lock() {
            if !state.1 {
                state.0 = stage;
            }
        }
    }
    fn failure(&self) {
        if self.enabled {
            if let Ok(mut state) = self.state.lock() {
                if !state.1 {
                    state.1 = true;
                    eprintln!("native-observe-first-failure stage={:?}", state.0);
                }
            }
        }
    }
}

// Production, default-off evidence for one trace or observation read. The cell
// contains no browser authority and holds no lock across an await. It records
// the first failed call site before restoration, but emits only after run returns.
struct ScreenshotFailureWitness {
    generation: u64,
    sequence: u64,
    state: Mutex<ScreenshotFailureState>,
}
struct ScreenshotFailureState {
    stage: ScreenshotStage,
    first: Option<(ScreenshotStage, ScreenshotCapturePhase, ProtocolError)>,
    revision: Option<u64>,
    inventory_rejection: Option<diagnostic::FrameInventoryRejection>,
    read_failure: Option<(diagnostic::ReadError, bool)>,
}
impl ScreenshotFailureWitness {
    fn new(request: &DispatchRequest, operation: &OperationLease, enabled: bool) -> Option<Self> {
        let trace = matches!(request, DispatchRequest::TraceSemantic(_))
            || matches!(request, DispatchRequest::Screenshot(request) if request.purpose == ScreenshotPurpose::Trace)
            || matches!(request, DispatchRequest::Observe(_));
        (enabled && trace).then(|| Self {
            generation: operation.generation,
            sequence: operation.sequence,
            state: Mutex::new(ScreenshotFailureState {
                stage: ScreenshotStage::PrepareScope,
                first: None,
                revision: None,
                inventory_rejection: None,
                read_failure: None,
            }),
        })
    }
    fn enter(&self, stage: ScreenshotStage) {
        if let Ok(mut state) = self.state.lock() {
            if state.first.is_none() {
                state.stage = stage;
            }
        }
    }
    fn failure(&self, error: &ProtocolError) {
        if let Ok(mut state) = self.state.lock() {
            if state.first.is_none() {
                state.first = Some((
                    state.stage,
                    ScreenshotCapturePhase::NotEntered,
                    error.clone(),
                ));
            }
        }
    }
    fn read_failure(&self, detail: (diagnostic::ReadError, bool), error: &ProtocolError) {
        if let Ok(mut state) = self.state.lock() {
            if state.first.is_none() {
                state.first = Some((
                    state.stage,
                    ScreenshotCapturePhase::NotEntered,
                    error.clone(),
                ));
                state.read_failure = Some(detail);
            }
        }
    }
    fn inventory_failure(
        &self,
        failure: Option<diagnostic::FrameInventoryRejection>,
        error: &ProtocolError,
    ) {
        if let Ok(mut state) = self.state.lock() {
            if state.first.is_none() {
                state.first = Some((
                    ScreenshotStage::FrameInventoryFence,
                    ScreenshotCapturePhase::NotEntered,
                    error.clone(),
                ));
                state.inventory_rejection = failure;
            }
        }
    }
    fn frame_pass(&self) -> diagnostic::FrameInventoryPass {
        use diagnostic::FrameInventoryPass;
        match self.state.lock().ok().map(|state| state.stage) {
            Some(ScreenshotStage::ProtectedFrames) => FrameInventoryPass::Protected,
            Some(ScreenshotStage::FinalFrames) => FrameInventoryPass::Final,
            _ => FrameInventoryPass::Initial,
        }
    }
    fn capture_failure(&self, failure: CaptureAttemptFailure) {
        if let Ok(mut state) = self.state.lock() {
            if state.first.is_none() {
                let phase = match failure.phase {
                    CapturePhase::Admission => ScreenshotCapturePhase::Admission,
                    CapturePhase::IndependentCoverage => {
                        ScreenshotCapturePhase::IndependentCoverage
                    }
                    CapturePhase::SourceProtection => ScreenshotCapturePhase::SourceProtection,
                    CapturePhase::RawCapture => ScreenshotCapturePhase::RawCapture,
                    CapturePhase::PostCaptureValidation => {
                        ScreenshotCapturePhase::PostCaptureValidation
                    }
                };
                state.first = Some((
                    ScreenshotStage::Capture,
                    phase,
                    capture_error(failure.reason),
                ));
            }
        }
    }
    // Called only with the revision already returned by an ordinary inventory
    // read. This does not acquire a diagnostic baseline or change admission.
    fn revision(&self, revision: u64) {
        if let Ok(mut state) = self.state.lock() {
            if state.first.is_none() && state.revision.is_none() {
                state.revision = Some(revision);
            }
        }
    }
    fn finish(self, targets: Option<&super::client_targets::ClientTargets>) {
        if let Some(failure) = self.take_failure(|| {
            targets.and_then(|targets| targets.inventory().ok().map(|(revision, _)| revision))
        }) {
            diagnostic::screenshot_failure(self.generation, self.sequence, failure);
            let inventory = self
                .state
                .lock()
                .ok()
                .and_then(|mut state| state.inventory_rejection.take());
            if let Some(inventory) = inventory {
                diagnostic::frame_inventory_rejection(self.generation, self.sequence, inventory);
            }
        }
    }
    fn take_failure(&self, after: impl FnOnce() -> Option<u64>) -> Option<ScreenshotFailure> {
        let (stage, capture_phase, error, before, read_failure) = {
            let mut state = self.state.lock().ok()?;
            let (stage, phase, error) = state.first.take()?;
            (
                stage,
                phase,
                error,
                state.revision,
                state.read_failure.take(),
            )
        };
        let inventory_after_failure = match before {
            None => InventoryAfterFailure::NotSampled,
            Some(before) => match after() {
                None => InventoryAfterFailure::Unavailable,
                Some(after) if after == before => InventoryAfterFailure::Unchanged,
                Some(_) => InventoryAfterFailure::Changed,
            },
        };
        Some(ScreenshotFailure {
            stage,
            read_error: read_failure.map(|detail| detail.0),
            read_cleanup_lost: read_failure.map(|detail| detail.1),
            capture_phase,
            error,
            inventory_after_failure,
        })
    }
}
fn screenshot_stage(witness: Option<&ScreenshotFailureWitness>, stage: ScreenshotStage) {
    if let Some(witness) = witness {
        witness.enter(stage);
    }
}

#[cfg(test)]
#[test]
fn observe_failure_witness_keeps_first_stage_local_to_one_operation() {
    let first = ObserveFailureWitness::new(true);
    let second = ObserveFailureWitness::new(true);
    first.enter(ObserveFailureStage::SemanticRead);
    first.failure();
    first.enter(ObserveFailureStage::Restoration);
    first.failure();
    second.enter(ObserveFailureStage::InitialFrames);
    second.failure();
    assert_eq!(
        *first.state.lock().unwrap(),
        (ObserveFailureStage::SemanticRead, true)
    );
    assert_eq!(
        *second.state.lock().unwrap(),
        (ObserveFailureStage::InitialFrames, true)
    );
}

#[cfg(test)]
tokio::task_local! {
    // Scoped to one retained dispatcher task, never shared between fixtures.
    // This injects an observed-cleanup flag, not a real resource cleanup failure.
    static FALLBACK_OBSERVED_CLEANUP_FOR_TEST: bool;
}

#[derive(Debug)]
pub struct DispatchFailure {
    pub error: ProtocolError,
    pub identity_scope: String,
    pub cleanup_integrity_lost: bool,
}
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObserveFlags {
    #[serde(default)]
    pub pixels: bool,
    #[serde(default)]
    pub pixel_fallback: bool,
    #[serde(default)]
    pub comparable: bool,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObserveRequest {
    pub options: ObserveFlags,
    pub test_id_attribute: String,
    pub secure_field_selector: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryPurpose {
    Fixture,
    Protected,
}
pub struct QueryRequest {
    pub options: QueryOptions,
    pub purpose: QueryPurpose,
}
pub struct FieldReadRequest {
    pub options: QueryOptions,
    pub fields: Vec<observation::ReadField>,
    pub broker: Arc<super::client_session::ClientSession>,
}
impl FieldReadRequest {
    fn admission_class(&self, operation: &OperationLease) -> super::client_debt::AdmissionClass {
        if operation.is_callback {
            super::client_debt::AdmissionClass::FixedRead
        } else {
            super::client_debt::AdmissionClass::Reference
        }
    }
    fn check_authority(
        &self,
        operation: &OperationLease,
        identity: &str,
        ledger: &super::client_debt::OwnerDebtLedger,
    ) -> Result<(), ProtocolError> {
        self.broker.validate_field_read(operation, identity)?;
        if !ledger.matches_owner(operation.generation, identity) {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    fn check_admission(
        &self,
        operation: &OperationLease,
        identity: &str,
        ledger: &super::client_debt::OwnerDebtLedger,
    ) -> Result<(), ProtocolError> {
        self.check_authority(operation, identity, ledger)?;
        ledger.check_admission(self.admission_class(operation))
    }
}
/// Screenshot publication policy; omitted purpose preserves pixels-only behavior.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ScreenshotPurpose {
    #[default]
    PixelsOnly,
    Trace,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScreenshotRequest {
    pub secure_field_selector: String,
    #[serde(default)]
    pub purpose: ScreenshotPurpose,
}
pub enum DispatchRequest {
    ReadFields(FieldReadRequest),
    Correlate(CorrelateRequest),
    Observe(ObserveRequest),
    TraceSemantic(ObserveRequest),
    Query(QueryRequest),
    Screenshot(ScreenshotRequest),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadPolicy {
    /// Captured once at scope.configure, never taken from observation requests.
    pub(crate) frame_policy: observation::ObservationFramePolicy,
    pub test_id_attribute: String,
    pub secure_field_selector: String,
}
impl ReadPolicy {
    // Only automatic semantic consumers call this. Explicit query, frame,
    // navigation, pixel and action authorization do not consult frame_policy.
    fn observation_options(&self) -> ObservationOptions {
        ObservationOptions {
            frame_policy: self.frame_policy.clone(),
            test_id_attribute: self.test_id_attribute.clone(),
            secure_field_selector: self.secure_field_selector.clone(),
            ..Default::default()
        }
    }
}
pub struct DispatchContext {
    #[cfg(feature = "acceptance-faults")]
    pub faults: Arc<super::client_test_faults::FaultController>,
    pub page: BrowserExecutionLease,
    /// Runtime-issued selected-page authority; never reconstructed from wire IDs.
    pub(crate) query_authority: Option<super::client_enrollment::PageQueryAuthority>,
    /// Native attachment tenure captured with the page and policy, before any
    /// retained-registration await. Never rebound from current registry state.
    pub attachment: super::client_targets::OwnedTarget,
    pub ui: Arc<UiGate>,
    pub blobs: Arc<BlobStore>,
    pub scope: BlobScope,
    pub policy: ReadPolicy,
}
/// Private evidence that only this dispatcher may issue after committing an
/// independently complete Observe tree. It grants no cleanup or UI authority.
#[derive(Clone, Default)]
pub(crate) struct ObservationResultReceipt {
    sealed: Arc<AtomicBool>,
    cleanup_failed_before_publication: Arc<AtomicBool>,
    #[cfg(test)]
    optional_timing: Arc<Mutex<OptionalPublicationTiming>>,
}
// Test-only causal timestamps, not scheduling hooks or publication authority.
// Only the producer writes these fields; the fixture reads after the joined run.
#[cfg(test)]
#[derive(Clone, Copy, Default)]
struct OptionalPublicationTiming {
    cutoff_deadline: Option<Instant>,
    cutoff_selected: Option<Instant>,
    publication_attempt: Option<Instant>,
    result_sent: Option<Instant>,
}
impl ObservationResultReceipt {
    #[cfg(test)]
    fn optional_timing(&self) -> OptionalPublicationTiming {
        *self.optional_timing.lock().unwrap()
    }
    #[cfg(test)]
    fn mark_optional_cutoff(&self) {
        self.optional_timing.lock().unwrap().cutoff_selected = Some(Instant::now());
    }
    #[cfg(test)]
    fn mark_publication_attempt(&self) {
        self.optional_timing.lock().unwrap().publication_attempt = Some(Instant::now());
    }
    #[cfg(test)]
    fn mark_result_sent(&self) {
        self.optional_timing.lock().unwrap().result_sent = Some(Instant::now());
    }
    pub(crate) fn is_sealed_observation(&self) -> bool {
        self.sealed.load(Ordering::Acquire)
    }
    pub(crate) fn cleanup_failed_before_publication(&self) -> bool {
        self.cleanup_failed_before_publication
            .load(Ordering::Acquire)
    }
}
pub struct DispatchTask {
    pub(crate) receipt: ObservationResultReceipt,
    /// Must be retained and joined by lifecycle shutdown, never aborted merely
    /// because the RPC receiver or its deadline has gone away.
    pub join: tokio::task::JoinHandle<Result<(), DispatchFailure>>,
    pub result: oneshot::Receiver<Result<Value, DispatchFailure>>,
}
struct Publication {
    revision: u64,
    published_revision: u64,
    observed_revision: u64,
}
#[derive(Clone, Copy)]
enum PublicationKind {
    Snapshot,
    AdditiveQuery,
    PixelsOnly,
    TraceViewport,
    TraceSemantic,
}
impl Publication {
    fn stage_revision(&mut self, kind: PublicationKind) -> Result<u64, ProtocolError> {
        if matches!(kind, PublicationKind::TraceSemantic) {
            // Private staging only: even the revision counters remain unchanged.
            return self
                .revision
                .checked_add(1)
                .ok_or(ProtocolError::IdentifierExhausted);
        }
        if matches!(kind, PublicationKind::PixelsOnly)
            || matches!(kind, PublicationKind::AdditiveQuery) && self.published_revision != 0
        {
            return Ok(self.published_revision);
        }
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        Ok(self.revision)
    }
    fn commit_refs(
        &mut self,
        kind: PublicationKind,
        revision: u64,
        destination: &mut RefMap,
        staged: RefMap,
    ) {
        if matches!(kind, PublicationKind::TraceSemantic) {
            return;
        }
        if matches!(kind, PublicationKind::TraceViewport) {
            destination.commit_viewport_from(&staged);
        } else if !matches!(kind, PublicationKind::PixelsOnly) {
            *destination = staged;
            self.published_revision = revision;
            if matches!(kind, PublicationKind::Snapshot) {
                self.observed_revision = revision;
            }
        }
    }
}
// Admission authority is separate from the one committed RefMap. Entries are
// bounded, exact-owner tenures, never reference registries or published revisions.
// Match the target registry's existing bound, rather than imposing a smaller
// page-history limit. Dead or detached exact tenures are pruned at admission.
const MAX_CAPTURE_OWNERS: usize = 1024;
struct CaptureOwner {
    scope: BlobScope,
    page_session_id: String,
    target_id: String,
    attachment: super::client_targets::OwnedTarget,
    client: Weak<super::cdp::client::CdpClient>,
    targets: Weak<super::client_targets::ClientTargets>,
}
impl CaptureOwner {
    fn new(context: &DispatchContext) -> Result<Self, ProtocolError> {
        let attachment = context.attachment.clone();
        let current = context.page.targets.owned_target(&context.page.target_id)?;
        if !attachment.same_attachment(&current)
            || context.page.targets.identity_scope != context.page.identity_scope
            || attachment.session_id != context.page.page_session_id
            || attachment.kind != "page"
            || attachment.purpose != Some(TargetPurpose::Application)
            || !attachment.configured
            || !attachment.resumed
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(Self {
            scope: context.scope.clone(),
            page_session_id: context.page.page_session_id.clone(),
            target_id: context.page.target_id.clone(),
            attachment,
            client: Arc::downgrade(&context.page.client),
            targets: Arc::downgrade(&context.page.targets),
        })
    }
    fn matches(&self, page: &BrowserExecutionLease, generation: u64) -> bool {
        self.scope.generation == generation
            && self.scope.identity_scope == page.identity_scope
            && self.page_session_id == page.page_session_id
            && self.target_id == page.target_id
            && self.client.ptr_eq(&Arc::downgrade(&page.client))
            && self.targets.ptr_eq(&Arc::downgrade(&page.targets))
            && page
                .targets
                .owned_target(&self.target_id)
                .is_ok_and(|current| self.attachment.same_attachment(&current))
    }
    fn live(&self) -> bool {
        self.client.strong_count() != 0
            && self.targets.upgrade().is_some_and(|targets| {
                targets
                    .owned_target(&self.target_id)
                    .is_ok_and(|current| self.attachment.same_attachment(&current))
            })
    }
}
struct CaptureAdmission {
    owner: CaptureOwner,
    sequence: u64,
    retired: tokio::sync::watch::Sender<bool>,
}
#[derive(Default)]
struct CaptureAuthority {
    retirement_fence: u64,
    page_blob_tenure: Arc<()>,
    latest: Vec<Arc<CaptureAdmission>>,
}
// Optional traces observe the existing admission, but never own or replace it.
struct TraceFence {
    owner: CaptureOwner,
    admission: Option<Arc<CaptureAdmission>>,
}
/// Created only by validated synchronous admission. Dropping an admitted
/// request never restores its predecessor, even if this task never runs.
pub(crate) struct PreparedDispatch {
    retirement_fence: u64,
    context: DispatchContext,
    request: DispatchRequest,
    operation: OperationLease,
    capture: Option<Arc<CaptureAdmission>>,
    trace: Option<TraceFence>,
    screenshot: Option<ScreenshotFailureWitness>,
}
pub struct ObservationDispatch {
    captures: Mutex<CaptureAuthority>,
    refs: Arc<Mutex<RefMap>>,
    publication: tokio::sync::Mutex<Publication>,
    // Branch seam only: the semantic reader has no natural PolicyDenied producer.
    #[cfg(test)]
    semantic_failure_for_test: Mutex<Option<ObservationError>>,
    #[cfg(test)]
    observed_cleanup_for_test: AtomicBool,
}
struct Output {
    value: Value,
    handles: Vec<String>,
}
impl ObservationDispatch {
    pub fn new(refs: Arc<Mutex<RefMap>>) -> Arc<Self> {
        Arc::new(Self {
            #[cfg(test)]
            semantic_failure_for_test: Mutex::new(None),
            #[cfg(test)]
            observed_cleanup_for_test: AtomicBool::new(false),
            refs,
            captures: Mutex::new(CaptureAuthority::default()),
            publication: tokio::sync::Mutex::new(Publication {
                revision: 0,
                published_revision: 0,
                observed_revision: 0,
            }),
        })
    }
    /// The existing publication authority owns one retirement counter; this
    /// never replaces scope generation, target tenure or the shared ref map.
    pub(crate) fn publication_fence(&self) -> Result<u64, ProtocolError> {
        self.captures
            .lock()
            .map(|authority| authority.retirement_fence)
            .map_err(|_| ProtocolError::ScopeUnavailable)
    }
    pub(crate) fn check_publication_fence(&self, captured: u64) -> Result<(), ProtocolError> {
        if self.publication_fence()? != captured {
            return Err(ProtocolError::StaleReference);
        }
        Ok(())
    }
    /// Broker application admission is blocked before this call. Advance and
    /// revoke under the short capture lock, release it before awaiting the
    /// publication mutex, then use publication -> captures -> refs lock order.
    /// In-flight publishers can restore sources but cannot commit old tickets.
    pub(crate) async fn retire_interaction(&self) -> Result<(), ProtocolError> {
        {
            let mut authority = self
                .captures
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            authority.retirement_fence = authority
                .retirement_fence
                .checked_add(1)
                .ok_or(ProtocolError::IdentifierExhausted)?;
            for capture in authority.latest.drain(..) {
                capture.retired.send_replace(true);
            }
        }
        let mut publication = self.publication.lock().await;
        let _authority = self
            .captures
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        self.refs
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .retire_interaction_references();
        publication.observed_revision = 0;
        Ok(())
    }

    /// The caller retains exclusive UI/input/lifecycle authority. Old capture
    /// producers have drained; revoke both reference publication and exact old
    /// pixel handles without touching saved videos or context/network bodies.
    pub(crate) async fn retire_page_publication(
        &self,
        blobs: &BlobStore,
        scope: &BlobScope,
    ) -> Result<(), ProtocolError> {
        self.retire_interaction().await?;
        let mut authority = self
            .captures
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        blobs
            .revoke_page_captures(scope, &authority.page_blob_tenure)
            .map_err(blob_error)?;
        authority.page_blob_tenure = Arc::new(());
        Ok(())
    }

    /// Caller holds the ordinary UI permit and exact scope lease. This is the
    /// sole current revision authority; a request's revision is never authority.
    pub async fn snapshot_for_action(
        &self,
        operation: &OperationLease,
    ) -> Result<(u64, RefMap), ProtocolError> {
        let (revision, refs, _) = self.snapshot_with_observation(operation).await?;
        Ok((revision, refs))
    }
    pub async fn snapshot_with_observation(
        &self,
        operation: &OperationLease,
    ) -> Result<(u64, RefMap, u64), ProtocolError> {
        let mut cancellation = operation.cancellation.clone();
        if *cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        let publication = tokio::select! {
            biased;
            _=cancellation.changed()=>return Err(ProtocolError::Cancelled),
            _=tokio::time::sleep_until(operation.deadline.into())=>return Err(ProtocolError::DeadlineExceeded),
            publication=self.publication.lock()=>publication,
        };
        let refs = self
            .refs
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .clone();
        if *cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok((
            publication.published_revision,
            refs,
            publication.observed_revision,
        ))
    }
    /// Read-only fixture witness; exact owner matching, never admission mutation.
    #[cfg(test)]
    pub(crate) fn capture_sequence_for_test(
        &self,
        page: &BrowserExecutionLease,
        generation: u64,
    ) -> Result<Option<u64>, ProtocolError> {
        let authority = self
            .captures
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        Ok(authority
            .latest
            .iter()
            .find(|entry| entry.owner.matches(page, generation) && !*entry.retired.borrow())
            .map(|entry| entry.sequence))
    }
    /// This is called by the retained registry's synchronous prepare closure,
    /// never on raw RPC acceptance and never before capacity admission.
    pub(crate) fn prepare(
        &self,
        context: DispatchContext,
        request: DispatchRequest,
        operation: OperationLease,
    ) -> Result<PreparedDispatch, ProtocolError> {
        let screenshot =
            ScreenshotFailureWitness::new(&request, &operation, diagnostic::inventory_enabled());
        let result = self.prepare_inner(context, request, operation, screenshot.as_ref());
        match result {
            Ok(mut prepared) => {
                prepared.screenshot = screenshot;
                Ok(prepared)
            }
            Err(error) => {
                if let Some(witness) = screenshot {
                    witness.failure(&error);
                    witness.finish(None);
                }
                Err(error)
            }
        }
    }
    fn prepare_inner(
        &self,
        context: DispatchContext,
        request: DispatchRequest,
        operation: OperationLease,
        screenshot: Option<&ScreenshotFailureWitness>,
    ) -> Result<PreparedDispatch, ProtocolError> {
        screenshot_stage(screenshot, ScreenshotStage::PrepareFence);
        let retirement_fence = self.publication_fence()?;
        screenshot_stage(screenshot, ScreenshotStage::PrepareScope);
        if context.scope.identity_scope != context.page.identity_scope
            || context.scope.generation != operation.generation
        {
            return Err(ProtocolError::StaleScope);
        }
        screenshot_stage(screenshot, ScreenshotStage::PreparePermit);
        check(&context.page, &operation)?;
        screenshot_stage(screenshot, ScreenshotStage::PreparePolicy);
        validate_policy(&context.policy, &request)?;
        if let DispatchRequest::Query(query) = &request {
            observation::validate_expression(&query.options.expression, 0)
                .map_err(observation_error)?;
        }
        if let DispatchRequest::ReadFields(read) = &request {
            observation::validate_expression(&read.options.expression, 0)
                .map_err(observation_error)?;
            observation::validate_read_fields(&read.fields).map_err(observation_error)?;
            read.broker
                .validate_field_read(&operation, &context.page.identity_scope)?;
        }
        let protected = !matches!(&request, DispatchRequest::ReadFields(_))
            && !matches!(&request, DispatchRequest::Query(q) if q.purpose == QueryPurpose::Fixture);
        if protected && operation.is_callback {
            return Err(ProtocolError::InvalidArguments);
        }
        let capture = if matches!(&request, DispatchRequest::Observe(_)) {
            let mut authority = self
                .captures
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            // Recheck the captured permit and budget while holding the same
            // short lock used by final publication. No await or UI lock here.
            check(&context.page, &operation)?;
            let owner = CaptureOwner::new(&context)?;
            authority.latest.retain(|entry| entry.owner.live());
            let prior = authority
                .latest
                .iter()
                .position(|entry| entry.owner.matches(&context.page, operation.generation));
            if let Some(index) = prior {
                // Spawning does not establish trusted request order. An older
                // request reaching validation late cannot displace a newer one.
                if operation.sequence <= authority.latest[index].sequence {
                    return Err(ProtocolError::StaleReference);
                }
            } else if authority.latest.len() >= MAX_CAPTURE_OWNERS {
                return Err(ProtocolError::CapacityExceeded);
            }
            let (retired, _) = tokio::sync::watch::channel(false);
            let capture = Arc::new(CaptureAdmission {
                owner,
                sequence: operation.sequence,
                retired,
            });
            if let Some(index) = prior {
                let prior = std::mem::replace(&mut authority.latest[index], capture.clone());
                prior.retired.send_replace(true);
            } else {
                authority.latest.push(capture.clone());
            }
            Some(capture)
        } else {
            None
        };
        let trace = if matches!(&request, DispatchRequest::TraceSemantic(_))
            || matches!(&request, DispatchRequest::Screenshot(r) if r.purpose == ScreenshotPurpose::Trace)
        {
            let authority = self
                .captures
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            screenshot_stage(screenshot, ScreenshotStage::PreparePermit);
            check(&context.page, &operation)?;
            screenshot_stage(screenshot, ScreenshotStage::PrepareOwner);
            let owner = CaptureOwner::new(&context)?;
            let admission = authority
                .latest
                .iter()
                .find(|entry| entry.owner.matches(&context.page, operation.generation))
                .cloned();
            if admission
                .as_ref()
                .is_some_and(|entry| entry.sequence >= operation.sequence)
            {
                return Err(ProtocolError::StaleReference);
            }
            Some(TraceFence { owner, admission })
        } else {
            None
        };
        screenshot_stage(screenshot, ScreenshotStage::PrepareFence);
        self.check_publication_fence(retirement_fence)?;
        Ok(PreparedDispatch {
            retirement_fence,
            context,
            request,
            operation,
            capture,
            trace,
            screenshot: None,
        })
    }
    #[cfg(test)]
    fn start(
        self: Arc<Self>,
        context: DispatchContext,
        request: DispatchRequest,
        operation: OperationLease,
    ) -> DispatchTask {
        let identity_scope = context.scope.identity_scope.clone();
        match self.prepare(context, request, operation) {
            Ok(prepared) => self.start_prepared(prepared),
            Err(error) => {
                let (send, result) = oneshot::channel();
                let join = tokio::spawn(async move {
                    let _ = send.send(Err(DispatchFailure {
                        error,
                        identity_scope,
                        cleanup_integrity_lost: false,
                    }));
                    Ok(())
                });
                DispatchTask {
                    join,
                    result,
                    receipt: ObservationResultReceipt::default(),
                }
            }
        }
    }
    pub(crate) fn start_prepared(self: Arc<Self>, prepared: PreparedDispatch) -> DispatchTask {
        let PreparedDispatch {
            retirement_fence,
            context,
            request,
            operation,
            capture,
            trace,
            screenshot,
        } = prepared;
        let (send, result) = oneshot::channel();
        let receipt = ObservationResultReceipt::default();
        let task_receipt = receipt.clone();
        // Explicit inheritance only for this operation-local capture task.
        // Durable owner services intentionally do not inherit task-local state.
        let operation_journal = super::client_debt::OperationJournalHandle::current();
        let join = tokio::spawn(async move {
            let mut send = Some(send);
            let scope = context.scope.clone();
            let blobs = context.blobs.clone();
            let targets = context.page.targets.clone();
            let cancellation = operation.cancellation.clone();
            let retirement = capture
                .as_ref()
                .or_else(|| trace.as_ref().and_then(|fence| fence.admission.as_ref()))
                .map(|ticket| observation::CaptureRetirement::new(ticket.retired.subscribe()));
            // Task-local context is installed inside the spawned task. Neither
            // the outer owner nor unrelated spawned work inherits it.
            #[cfg(test)]
            let observed_cleanup = self.observed_cleanup_for_test.load(Ordering::SeqCst);
            let optional_pixels =
                matches!(&request, DispatchRequest::Observe(request) if request.options.pixels);
            let diagnostic_generation = operation.generation;
            let diagnostic_sequence = operation.sequence;
            let run = self.run(
                context,
                request,
                operation,
                capture,
                trace,
                retirement_fence,
                screenshot.as_ref(),
                &mut send,
                &task_receipt,
            );
            #[cfg(test)]
            let run = FALLBACK_OBSERVED_CLEANUP_FOR_TEST.scope(observed_cleanup, run);
            let run = observation::with_capture_retirement(retirement, run);
            let mut output = match operation_journal {
                Some(journal) => journal.scope(run).await,
                None => run.await,
            };
            if optional_pixels {
                diagnostic::observation_pixel_result(
                    diagnostic_generation,
                    diagnostic_sequence,
                    output.is_ok(),
                    output
                        .as_ref()
                        .is_ok_and(|output| output.value.get("pixels").is_some()),
                    task_receipt.sealed.load(Ordering::Acquire),
                );
            }
            if let Some(witness) = screenshot {
                if let Err(failure) = &output {
                    witness.failure(&failure.error);
                }
                witness.finish(Some(&targets));
            }
            if let Err(failure) = &mut output {
                // A cancellation already visible at this unsettled boundary
                // wins over clean supersession, never over cleanup uncertainty.
                if !failure.cleanup_integrity_lost
                    && failure.error == ProtocolError::StaleReference
                    && *cancellation.borrow() != CancelSignal::None
                {
                    failure.error = ProtocolError::Cancelled;
                }
            }
            match output {
                Ok(output) => {
                    if send.take().is_some_and(|send| {
                        let delivered = send.send(Ok(output.value));
                        #[cfg(test)]
                        task_receipt.mark_result_sent();
                        delivered.is_err()
                    }) && !release_handles(&blobs, &scope, &output.handles)
                    {
                        targets.seal();
                        return Err(DispatchFailure {
                            error: ProtocolError::CleanupFailed,
                            identity_scope: scope.identity_scope,
                            cleanup_integrity_lost: true,
                        });
                    }
                }
                Err(error) => {
                    if error.cleanup_integrity_lost {
                        targets.seal();
                    }
                    match send.take() {
                        Some(send) => {
                            let delivered = send.send(Err(error));
                            #[cfg(test)]
                            task_receipt.mark_result_sent();
                            if let Err(Err(error)) = delivered {
                                if error.cleanup_integrity_lost {
                                    return Err(error);
                                }
                            }
                        }
                        // The immutable result is already fixed. Report later
                        // custody failure through the retained join, exactly once.
                        None if error.cleanup_integrity_lost => return Err(error),
                        None => {}
                    }
                }
            }
            Ok(())
        });
        DispatchTask {
            join,
            result,
            receipt,
        }
    }
    /// Admission and final comparison/commit are one linearization domain.
    /// The publication/UI guards are already held by the caller; this short
    /// lock never spans asynchronous browser work or mandatory restoration.
    // Keep the exact authority and staged publication inputs explicit at this boundary.
    #[allow(clippy::too_many_arguments)]
    fn commit_staged(
        &self,
        page: &BrowserExecutionLease,
        operation: &OperationLease,
        capture: Option<&Arc<CaptureAdmission>>,
        trace: Option<&TraceFence>,
        retirement_fence: u64,
        publication: &mut Publication,
        kind: PublicationKind,
        revision: u64,
        staged: RefMap,
        blobs: &BlobStore,
        blob_scope: &BlobScope,
        handles: &[String],
        query_partition: Option<&super::client_enrollment::PageAcquisitionProof>,
    ) -> Result<(), ProtocolError> {
        let authority = self
            .captures
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        check(page, operation)?;
        if authority.retirement_fence != retirement_fence {
            return Err(ProtocolError::StaleReference);
        }
        if let Some(capture) = capture {
            if !capture.owner.matches(page, operation.generation)
                || capture.sequence != operation.sequence
                || !authority
                    .latest
                    .iter()
                    .any(|current| Arc::ptr_eq(current, capture))
            {
                return Err(ProtocolError::StaleReference);
            }
        } else if matches!(kind, PublicationKind::Snapshot) {
            return Err(ProtocolError::StaleReference);
        }
        if matches!(
            kind,
            PublicationKind::TraceViewport | PublicationKind::TraceSemantic
        ) {
            let trace = trace.ok_or(ProtocolError::StaleReference)?;
            let current = authority
                .latest
                .iter()
                .find(|entry| entry.owner.matches(page, operation.generation));
            let unchanged = match (&trace.admission, current) {
                (Some(sampled), Some(current)) => Arc::ptr_eq(sampled, current),
                (None, None) => true,
                _ => false,
            };
            if !trace.owner.matches(page, operation.generation) || !unchanged {
                return Err(ProtocolError::StaleReference);
            }
        }
        let mut refs = self
            .refs
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        check(page, operation)?;
        let commit = || {
            blobs
                .bind_page_captures(blob_scope, handles, &authority.page_blob_tenure)
                .map_err(blob_error)?;
            publication.commit_refs(kind, revision, &mut refs, staged);
            Ok(())
        };
        // Preserve captures -> refs before adding index -> watermark -> targets.
        // Never enter captures while holding the registry: capture admission
        // itself checks target tenure under its captures lock.
        if let Some(partition) = query_partition {
            partition.with_publication(page, operation, commit)
        } else {
            commit()
        }
    }

    fn commit_staged_query_attempt(
        &self,
        page: &BrowserExecutionLease,
        operation: &OperationLease,
        capture: Option<&Arc<CaptureAdmission>>,
        trace: Option<&TraceFence>,
        retirement_fence: u64,
        publication: &mut Publication,
        kind: PublicationKind,
        revision: u64,
        staged: &mut Option<RefMap>,
        blobs: &BlobStore,
        blob_scope: &BlobScope,
        handles: &[String],
        query_partition: &super::client_enrollment::PageAcquisitionProof,
    ) -> Result<super::client_enrollment::QueryBoundary<()>, ProtocolError> {
        let authority = self
            .captures
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        check(page, operation)?;
        if authority.retirement_fence != retirement_fence {
            return Err(ProtocolError::StaleReference);
        }
        if let Some(capture) = capture {
            if !capture.owner.matches(page, operation.generation)
                || capture.sequence != operation.sequence
                || !authority
                    .latest
                    .iter()
                    .any(|current| Arc::ptr_eq(current, capture))
            {
                return Err(ProtocolError::StaleReference);
            }
        } else if matches!(kind, PublicationKind::Snapshot) {
            return Err(ProtocolError::StaleReference);
        }
        if matches!(
            kind,
            PublicationKind::TraceViewport | PublicationKind::TraceSemantic
        ) {
            let trace = trace.ok_or(ProtocolError::StaleReference)?;
            let current = authority
                .latest
                .iter()
                .find(|entry| entry.owner.matches(page, operation.generation));
            let unchanged = match (&trace.admission, current) {
                (Some(sampled), Some(current)) => Arc::ptr_eq(sampled, current),
                (None, None) => true,
                _ => false,
            };
            if !trace.owner.matches(page, operation.generation) || !unchanged {
                return Err(ProtocolError::StaleReference);
            }
        }
        let mut refs = self
            .refs
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        check(page, operation)?;
        let commit = || {
            blobs
                .bind_page_captures(blob_scope, handles, &authority.page_blob_tenure)
                .map_err(blob_error)?;
            publication.commit_refs(
                kind,
                revision,
                &mut refs,
                staged.take().ok_or(ProtocolError::StaleScope)?,
            );
            Ok(())
        };
        // Preserve captures -> refs before adding index -> watermark -> targets.
        // Never enter captures while holding the registry: capture admission
        // itself checks target tenure under its captures lock.
        query_partition.publication_attempt(page, operation, commit)
    }

    async fn commit_staged_query(
        &self,
        page: &BrowserExecutionLease,
        operation: &OperationLease,
        capture: Option<&Arc<CaptureAdmission>>,
        trace: Option<&TraceFence>,
        retirement_fence: u64,
        publication: &mut Publication,
        kind: PublicationKind,
        revision: u64,
        staged: RefMap,
        blobs: &BlobStore,
        blob_scope: &BlobScope,
        handles: &[String],
        query_partition: &super::client_enrollment::PageAcquisitionProof,
    ) -> Result<(), ProtocolError> {
        let mut staged = Some(staged);
        loop {
            match self.commit_staged_query_attempt(
                page,
                operation,
                capture,
                trace,
                retirement_fence,
                publication,
                kind,
                revision,
                &mut staged,
                blobs,
                blob_scope,
                handles,
                query_partition,
            )? {
                super::client_enrollment::QueryBoundary::Ready(()) => return Ok(()),
                super::client_enrollment::QueryBoundary::Pending(prefix) => {
                    // Attempt returned: captures/refs/index/watermark/targets
                    // locks are all gone. Staged refs have not been consumed.
                    query_partition
                        .wait_pending(page, operation, &prefix)
                        .await?;
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn commit_query_staged_for_test(
        &self,
        page: &BrowserExecutionLease,
        operation: &OperationLease,
        partition: &super::client_enrollment::PageAcquisitionProof,
        staged: RefMap,
        blobs: &BlobStore,
        scope: &BlobScope,
    ) -> Result<u64, ProtocolError> {
        let fence = self.publication_fence()?;
        let mut publication = self.publication.lock().await;
        let revision = publication.stage_revision(PublicationKind::AdditiveQuery)?;
        self.commit_staged_query(
            page,
            operation,
            None,
            None,
            fence,
            &mut publication,
            PublicationKind::AdditiveQuery,
            revision,
            staged,
            blobs,
            scope,
            &[],
            partition,
        )
        .await?;
        Ok(publication.published_revision)
    }
    #[cfg(test)]
    pub(crate) fn query_commit_short_locks_available_for_test(&self) -> bool {
        let Ok(_captures) = self.captures.try_lock() else {
            return false;
        };
        let Ok(_refs) = self.refs.try_lock() else {
            return false;
        };
        self.publication.try_lock().is_err()
    }

    fn check_initial_trace_owner(
        &self,
        context: &DispatchContext,
        operation: &OperationLease,
        retirement_fence: u64,
    ) -> Result<(), ProtocolError> {
        check(&context.page, operation)?;
        self.check_publication_fence(retirement_fence)?;
        if !context
            .attachment
            .same_attachment(&context.page.targets.owned_target(&context.page.target_id)?)
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    // This is a settled-prefix check, not permission for later commands. The
    // existing journal/admission checks still run on every subsequent RPC.
    fn initial_trace_prefix_settled(
        context: &DispatchContext,
        operation: &OperationLease,
        cleanup: &AtomicBool,
    ) -> bool {
        let Some(ledger) = context.page.client.debt_ledger() else {
            return false;
        };
        if cleanup.load(Ordering::SeqCst)
            || !ledger.matches_owner(operation.generation, &context.scope.identity_scope)
            || context
                .page
                .client
                .check_cleanup_owner(&Some(ledger.clone()))
                .is_err()
            || ledger
                .check_admission(super::client_debt::AdmissionClass::Reference)
                .is_err()
        {
            return false;
        }
        let debt = ledger.snapshot();
        !debt.integrity_lost
            && debt.input_debt == 0
            && debt.object_debt == 0
            && debt.outstanding_commands == 0
    }
    async fn initial_trace_frames(
        &self,
        context: &DispatchContext,
        operation: &OperationLease,
        retirement_fence: u64,
        cleanup: &AtomicBool,
        screenshot: Option<&ScreenshotFailureWitness>,
    ) -> Result<Vec<ObservationFrame>, ProtocolError> {
        let mut reacquired = false;
        loop {
            self.check_initial_trace_owner(context, operation, retirement_fence)?;
            let result =
                frame_inventory_attempt(&context.page, operation, Some(cleanup), screenshot).await;
            match result {
                Ok(inventory) => {
                    self.check_initial_trace_owner(context, operation, retirement_fence)?;
                    // A later prefix cannot borrow the previous round's zero-debt
                    // observation. In particular, an accepted retained release is
                    // not a settled ACK, even when enumeration returned success.
                    if reacquired
                        && !Self::initial_trace_prefix_settled(context, operation, cleanup)
                    {
                        return Err(ProtocolError::ScopeUnavailable);
                    }
                    return Ok(inventory.frames);
                }
                Err(failure) => {
                    if !failure.revision_only() {
                        return Err(failure.record(screenshot));
                    }
                    self.check_initial_trace_owner(context, operation, retirement_fence)?;
                    if !Self::initial_trace_prefix_settled(context, operation, cleanup) {
                        return Err(failure.record(screenshot));
                    }
                    // The failed attempt owns only local binding vectors here;
                    // all remote obligations must have settled before repeating.
                    // No protected journal, animation, source mask or capture has begun.
                    tokio::task::yield_now().await;
                    self.check_initial_trace_owner(context, operation, retirement_fence)?;
                    if !Self::initial_trace_prefix_settled(context, operation, cleanup) {
                        return Err(failure.record(screenshot));
                    }
                    reacquired = true;
                }
            }
        }
    }
    // Only INITIAL Observe inventory can discard one revision-raced prefix.
    // Neither a changed sample nor a queued release is usable proof for the next
    // attempt. Semantic capture and every later protected/final proof stay strict.
    async fn initial_observe_frames(
        &self,
        context: &DispatchContext,
        operation: &OperationLease,
        capture: Option<&Arc<CaptureAdmission>>,
        retirement_fence: u64,
        cleanup: &AtomicBool,
        screenshot: Option<&ScreenshotFailureWitness>,
    ) -> Result<Vec<ObservationFrame>, ProtocolError> {
        let check_owner = || {
            self.check_initial_trace_owner(context, operation, retirement_fence)?;
            let capture = capture.ok_or(ProtocolError::StaleReference)?;
            let authority = self
                .captures
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if authority.retirement_fence != retirement_fence
                || capture.sequence != operation.sequence
                || capture.owner.scope != context.scope
                || !capture.owner.matches(&context.page, operation.generation)
                || !authority
                    .latest
                    .iter()
                    .any(|current| Arc::ptr_eq(current, capture))
            {
                return Err(ProtocolError::StaleReference);
            }
            Ok(())
        };
        check_owner()?;
        let first = frame_inventory_attempt_impl(
            &context.page,
            operation,
            Some(cleanup),
            screenshot,
            true,
            None,
        )
        .await;
        let rejected = match first {
            Ok(inventory) => {
                check_owner()?;
                // The original successful-read contract permits accounted
                // readonly disposal debt; it never requires a release ACK here.
                return Ok(inventory.frames);
            }
            Err(failure) => failure,
        };
        if !rejected.revision_only() {
            return Err(rejected.record(screenshot));
        }
        check_owner()?;
        if !Self::initial_trace_prefix_settled(context, operation, cleanup) {
            return Err(rejected.record(screenshot));
        }
        tokio::task::yield_now().await;
        check_owner()?;
        if !Self::initial_trace_prefix_settled(context, operation, cleanup) {
            return Err(rejected.record(screenshot));
        }
        // No loop: the old sample is discarded and a second raced sample fails.
        let inventory = frame_inventory_attempt_impl(
            &context.page,
            operation,
            Some(cleanup),
            screenshot,
            true,
            None,
        )
        .await
        .map_err(|failure| failure.record(screenshot))?;
        check_owner()?;
        let ledger = context
            .page
            .client
            .debt_ledger()
            .ok_or(ProtocolError::ScopeUnavailable)?;
        if cleanup.load(Ordering::SeqCst)
            || !ledger.matches_owner(operation.generation, &context.scope.identity_scope)
            || context
                .page
                .client
                .check_cleanup_owner(&Some(ledger.clone()))
                .is_err()
            || ledger
                .check_admission(super::client_debt::AdmissionClass::Reference)
                .is_err()
            || ledger.snapshot().integrity_lost
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        // NEW readonly debt belongs to the accepted second sample, not to the
        // discarded first prefix. Its exact custody remains normally retained.
        Ok(inventory.frames)
    }
    /// Enrich an independently sealed tree without giving its result deadline to
    /// raw-pixel settlement. This future stays inside the original retained run,
    /// with its UI/publication guards, journal and exact capture ticket alive.
    #[allow(clippy::too_many_arguments)]
    async fn optional_observe_pixels(
        &self,
        context: &CaptureContext,
        operation: &OperationLease,
        capture: Option<&Arc<CaptureAdmission>>,
        retirement_fence: u64,
        blobs: &BlobStore,
        scope: &BlobScope,
        publication: &mut Publication,
        revision: u64,
        staged: &RefMap,
        secure_field_selector: String,
        semantic: Value,
        result_send: &mut Option<oneshot::Sender<Result<Value, DispatchFailure>>>,
        receipt: &ObservationResultReceipt,
        screenshot: Option<&ScreenshotFailureWitness>,
    ) -> Result<Output, DispatchFailure> {
        let identity = &context.page.identity_scope;
        let cleanup_lost = AtomicBool::new(false);
        let failure = |error: ProtocolError| {
            if let Some(witness) = screenshot {
                witness.failure(&error);
            }
            DispatchFailure {
                cleanup_integrity_lost: error == ProtocolError::CleanupFailed
                    || cleanup_lost.load(Ordering::SeqCst),
                error,
                identity_scope: identity.clone(),
            }
        };
        let pixel_operation = optional_observe_lease(operation);
        #[cfg(test)]
        {
            receipt.optional_timing.lock().unwrap().cutoff_deadline =
                Some(pixel_operation.deadline);
        }
        let published = AtomicBool::new(false);
        let optional = async {
            screenshot_stage(screenshot, ScreenshotStage::ProducerReservation);
            check(&context.page, &pixel_operation).map_err(failure)?;
            let producer = blobs
                .reserve_bounded_producer(
                    scope.clone(),
                    client_capture::MAX_PNG_BYTES.min(blobs.producer_limit()),
                )
                .map_err(|error| failure(blob_error(error)))?;
            screenshot_stage(screenshot, ScreenshotStage::ProtectedBarrier);
            let mut journal =
                ProtectedReadJournal::begin(&context.page, operation).map_err(|error| {
                    if let Some(witness) = screenshot {
                        witness.failure(&protected_error(error.reason));
                    }
                    DispatchFailure {
                        error: protected_error(error.reason),
                        identity_scope: error.identity_scope,
                        cleanup_integrity_lost: error.cleanup_integrity_lost,
                    }
                })?;
            let captured = async {
                screenshot_stage(screenshot, ScreenshotStage::AnimationStabilization);
                journal
                    .stabilize_animations()
                    .await
                    .map_err(protected_error)?;
                screenshot_stage(screenshot, ScreenshotStage::ProtectedFrames);
                let frames = verified_frames_with_cleanup(
                    &context.page,
                    &pixel_operation,
                    Some(&cleanup_lost),
                )
                .await?;
                same_frames(&context.frames, &frames)?;
                screenshot_stage(screenshot, ScreenshotStage::Geometry);
                let geometry = GeometrySnapshot::capture(
                    &context.page.client,
                    &context.page.page_session_id,
                    &frames,
                    &pixel_operation,
                )
                .await
                .map_err(|error| geometry_error_with_cleanup(error, &cleanup_lost))?;
                screenshot_stage(screenshot, ScreenshotStage::Capture);
                let pixels = client_capture::capture_under_journal(
                    context,
                    &CaptureRequest {
                        secure_field_selector,
                    },
                    &pixel_operation,
                    &mut journal,
                    &geometry,
                )
                .await
                .map_err(|error| {
                    if let Some(witness) = screenshot {
                        witness.capture_failure(error);
                    }
                    capture_error(error.reason)
                })?;
                Ok::<_, ProtocolError>((pixels, geometry))
            }
            .await;
            if let (Some(witness), Err(error)) = (screenshot, &captured) {
                witness.failure(error);
            }
            screenshot_stage(screenshot, ScreenshotStage::Restoration);
            // Even after publishing semantics, this exact owner must finish
            // source-mask/animation/raw custody. No detached cleanup task.
            if let Err(error) = journal.restore().await {
                if let Some(witness) = screenshot {
                    witness.failure(&protected_error(error.reason));
                }
                return Err(DispatchFailure {
                    error: captured
                        .as_ref()
                        .err()
                        .cloned()
                        .unwrap_or_else(|| protected_error(error.reason)),
                    identity_scope: identity.clone(),
                    cleanup_integrity_lost: error.cleanup_integrity_lost
                        || cleanup_lost.load(Ordering::SeqCst),
                });
            }
            // A captured cleanup failure survives even if the journal itself
            // restored cleanly. Publication does not discharge remote resources.
            let (pixels, geometry) = captured.map_err(failure)?;
            if published.load(Ordering::Acquire) {
                // A late ACK can discharge custody, never publish pixels or
                // restart final-proof reads after the optional acceptance cut.
                return Ok(Output {
                    value: semantic.clone(),
                    handles: vec![],
                });
            }
            screenshot_stage(screenshot, ScreenshotStage::FinalGeometry);
            geometry
                .revalidate(&context.page.client, &pixel_operation)
                .await
                .map_err(|error| failure(geometry_error_with_cleanup(error, &cleanup_lost)))?;
            screenshot_stage(screenshot, ScreenshotStage::FinalBarrier);
            journal
                .check()
                .map_err(|error| failure(protected_error(error)))?;
            screenshot_stage(screenshot, ScreenshotStage::FinalFrames);
            let current =
                verified_frames_with_cleanup(&context.page, &pixel_operation, Some(&cleanup_lost))
                    .await
                    .map_err(failure)?;
            same_frames(&context.frames, &current).map_err(failure)?;
            screenshot_stage(screenshot, ScreenshotStage::FinalViewport);
            if viewport(&context.page, &pixel_operation)
                .await
                .map_err(failure)?
                != semantic["viewport"]
            {
                return Err(failure(ProtocolError::StaleScope));
            }
            check(&context.page, &pixel_operation).map_err(failure)?;
            screenshot_stage(screenshot, ScreenshotStage::BlobPublication);
            let image = blobs
                .finish_producer(producer, pixels.png)
                .map_err(|error| failure(blob_error(error)))?;
            let handles = vec![image.handle.clone()];
            let mut value = semantic.clone();
            value["maskedRegionCount"] = json!(pixels.masked_region_count);
            value["pixels"] = json!({"identityScope":identity,"handle":image.handle,"size":image.size,
                "sha256":image.sha256,"mediaType":"image/png","width":pixels.width,"height":pixels.height,
                "scale":pixels.scale,"maskedRegionCount":pixels.masked_region_count});
            let publish = bounded_result(&value);
            if let Err(error) = publish {
                if !release_handles(blobs, scope, &handles) {
                    cleanup_lost.store(true, Ordering::SeqCst);
                }
                return Err(failure(error));
            }
            Ok(Output { value, handles })
        };
        tokio::pin!(optional);
        // This is immutable-result authority only. Check the original permit,
        // cancellation, generation ticket and supersession, not new UI admission.
        let mut publish_semantic =
            |result_send: &mut Option<oneshot::Sender<Result<Value, DispatchFailure>>>| {
                #[cfg(test)]
                receipt.mark_publication_attempt();
                check(&context.page, operation)?;
                let authority = self
                    .captures
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                let capture = capture.ok_or(ProtocolError::StaleReference)?;
                if authority.retirement_fence != retirement_fence
                    || capture.sequence != operation.sequence
                    || capture.owner.scope != *scope
                    || capture.owner.page_session_id != context.page.page_session_id
                    || capture.owner.target_id != context.page.target_id
                    || !capture
                        .owner
                        .client
                        .ptr_eq(&Arc::downgrade(&context.page.client))
                    || !capture
                        .owner
                        .targets
                        .ptr_eq(&Arc::downgrade(&context.page.targets))
                    || !context
                        .page
                        .targets
                        .retains_exact_attachment(&capture.owner.attachment)
                    || !authority
                        .latest
                        .iter()
                        .any(|current| Arc::ptr_eq(current, capture))
                {
                    return Err(ProtocolError::StaleReference);
                }
                let mut refs = self
                    .refs
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                check(&context.page, operation)?;
                if let Some(send) = result_send.take() {
                    publication.commit_refs(
                        PublicationKind::Snapshot,
                        revision,
                        &mut refs,
                        staged.clone(),
                    );
                    receipt.sealed.store(true, Ordering::Release);
                    published.store(true, Ordering::Release);
                    // The exact operation keeps cleanup custody even if the RPC
                    // receiver has gone away. There are no blob handles in this value.
                    let _ = send.send(Ok(semantic.clone()));
                    #[cfg(test)]
                    receipt.mark_result_sent();
                }
                Ok::<(), ProtocolError>(())
            };
        let completed = tokio::select! {
            biased;
            result = &mut optional => result,
            _ = tokio::time::sleep_until(pixel_operation.deadline.into()) => {
                #[cfg(test)]
                receipt.mark_optional_cutoff();
                // Do not cancel/drop the optional future: a raw ACK or a mask
                // restore may still be outstanding. Only its output is cut off.
                // The timeout wins here before later cleanup can overwrite the
                // phase of the refused optional pixel result.
                if let Some(witness) = screenshot { witness.failure(&ProtocolError::DeadlineExceeded); }
                let publication = publish_semantic(result_send);
                let result = optional.await;
                if let Err(error) = publication {
                    let mut rejected = failure(error);
                    match result {
                        Err(cleanup) if cleanup.cleanup_integrity_lost => return Err(cleanup),
                        Err(_) => {},
                        Ok(output) => rejected.cleanup_integrity_lost |= !release_handles(blobs, scope, &output.handles),
                    }
                    return Err(rejected);
                }
                result
            }
        };
        match completed {
            Ok(output) if !published.load(Ordering::Acquire) => {
                screenshot_stage(screenshot, ScreenshotStage::Publication);
                let publish = self.commit_staged(
                    &context.page,
                    &pixel_operation,
                    capture,
                    None,
                    retirement_fence,
                    publication,
                    PublicationKind::Snapshot,
                    revision,
                    staged.clone(),
                    blobs,
                    scope,
                    &output.handles,
                    None,
                );
                if let Err(error) = publish {
                    if !release_handles(blobs, scope, &output.handles) {
                        cleanup_lost.store(true, Ordering::SeqCst);
                    }
                    return Err(failure(error));
                }
                Ok(output)
            }
            Ok(output) => Ok(output),
            Err(error) if published.load(Ordering::Acquire) => {
                if error.cleanup_integrity_lost {
                    Err(error)
                } else {
                    Ok(Output {
                        value: semantic.clone(),
                        handles: vec![],
                    })
                }
            }
            Err(error)
                if matches!(
                    error.error,
                    ProtocolError::BrowserFailure
                        | ProtocolError::DeadlineExceeded
                        | ProtocolError::PolicyDenied
                        | ProtocolError::CapacityExceeded
                        | ProtocolError::CleanupFailed
                ) =>
            {
                // Pixel-only refusal cannot revoke a separately completed tree.
                // Cancellation, identity loss and supersession are not optional.
                // Known failure is published truthfully by the browser bridge;
                // pending custody alone is not evidence of failed cleanup.
                receipt
                    .cleanup_failed_before_publication
                    .store(error.cleanup_integrity_lost, Ordering::Release);
                if let Err(rejected) = publish_semantic(result_send) {
                    // A cancelled/stale publication must not erase an already
                    // established resource or restoration cleanup failure.
                    return Err(if error.cleanup_integrity_lost {
                        error
                    } else {
                        failure(rejected)
                    });
                }
                if error.cleanup_integrity_lost {
                    Err(error)
                } else {
                    Ok(Output {
                        value: semantic.clone(),
                        handles: vec![],
                    })
                }
            }
            Err(error) => Err(error),
        }
    }
    #[allow(clippy::too_many_arguments)] // The optional diagnostic borrows only for this run.
    async fn run(
        &self,
        context: DispatchContext,
        request: DispatchRequest,
        operation: OperationLease,
        capture: Option<Arc<CaptureAdmission>>,
        trace: Option<TraceFence>,
        retirement_fence: u64,
        screenshot: Option<&ScreenshotFailureWitness>,
        result_send: &mut Option<oneshot::Sender<Result<Value, DispatchFailure>>>,
        receipt: &ObservationResultReceipt,
    ) -> Result<Output, DispatchFailure> {
        let identity = context.page.identity_scope.clone();
        #[cfg(test)]
        let witness = ObserveFailureWitness::new(
            matches!(&request, DispatchRequest::Observe(request) if !request.options.pixels && !request.options.pixel_fallback),
        );
        let observation_cleanup = AtomicBool::new(false);
        let map_observation = |error| {
            let detail = screenshot.map(|_| observation_read_failure(&error));
            let error = observation_error_with_cleanup(error, &observation_cleanup);
            if let (Some(witness), Some(detail)) = (screenshot, detail) {
                witness.read_failure(detail, &error);
            }
            error
        };
        let map_geometry = |error| {
            let detail = screenshot.map(|_| geometry_read_failure(&error));
            let error = geometry_error_with_cleanup(error, &observation_cleanup);
            if let (Some(witness), Some(detail)) = (screenshot, detail) {
                witness.read_failure(detail, &error);
            }
            error
        };
        let failure = |error: ProtocolError| {
            if let Some(witness) = screenshot {
                witness.failure(&error);
            }
            #[cfg(test)]
            witness.failure();
            DispatchFailure {
                error: error.clone(),
                identity_scope: identity.clone(),
                cleanup_integrity_lost: error == ProtocolError::CleanupFailed
                    || observation_cleanup.load(Ordering::SeqCst),
            }
        };
        screenshot_stage(screenshot, ScreenshotStage::RunScope);
        if context.scope.identity_scope != identity
            || context.scope.generation != operation.generation
        {
            return Err(failure(ProtocolError::StaleScope));
        }
        check(&context.page, &operation).map_err(failure)?;
        validate_policy(&context.policy, &request).map_err(failure)?;
        // The same validator used by query() refuses unsupported composition
        // before UI admission, revision staging, frame acquisition, or CDP.
        if let DispatchRequest::Query(query) = &request {
            observation::validate_expression(&query.options.expression, 0)
                .map_err(map_observation)
                .map_err(failure)?;
        }
        // Classify already received attachments before acquiring UI/publication.
        // This is not a wait for unrelated initializer readiness or task exit.
        if matches!(&request, DispatchRequest::Query(_)) {
            if let Some(authority) = &context.query_authority {
                authority
                    .wait_classified(&context.page, &operation)
                    .await
                    .map_err(failure)?;
            }
        }
        let protected = !matches!(&request, DispatchRequest::ReadFields(_))
            && !matches!(&request, DispatchRequest::Query(q) if q.purpose == QueryPurpose::Fixture);
        // Semantic-only reads need exclusive admission and exact target/frame
        // fences, not a browser lifecycle mutation. Chromium's frozen state
        // also hides the page; setting active does not undo that visibility.
        let stabilize_pixels = matches!(&request, DispatchRequest::Screenshot(_));
        // Pending browser input can need a late route/dialog callback to settle.
        // Wait before UI/publication locks so that owner service stays runnable.
        screenshot_stage(screenshot, ScreenshotStage::DebtAdmission);
        if let Some(ledger) = context.page.client.debt_ledger() {
            let category = match &request {
                DispatchRequest::ReadFields(read) => read.admission_class(&operation),
                _ => super::client_debt::AdmissionClass::Reference,
            };
            let admission = ledger.wait_admission(category, &operation, || {
                check(&context.page, &operation)?;
                if let DispatchRequest::ReadFields(read) = &request {
                    // Class choice is not authority. Never turn an invalid
                    // callback into an ordinary read or bypass its broker.
                    read.check_authority(&operation, &identity, &ledger)?;
                }
                if !ledger.matches_owner(operation.generation, &context.scope.identity_scope) {
                    return Err(ProtocolError::StaleScope);
                }
                self.check_publication_fence(retirement_fence)?;
                if !context
                    .attachment
                    .same_attachment(&context.page.targets.owned_target(&context.page.target_id)?)
                {
                    return Err(ProtocolError::StaleScope);
                }
                Ok(())
            });
            tokio::select! {
                result = admission => result.map_err(failure)?,
                _ = observation::capture_retired() => {
                    check(&context.page, &operation).map_err(failure)?;
                    return Err(failure(ProtocolError::StaleReference));
                }
            }
        } else if matches!(&request, DispatchRequest::ReadFields(_)) {
            return Err(failure(ProtocolError::ScopeUnavailable));
        }
        // Warm only isolated-world identities in a first ordinary UI permit.
        // No DOM, selector, geometry or semantic result is read here. The same
        // original proof is retained through all later protected checks.
        let query_partition = if matches!(&request, DispatchRequest::Query(_)) {
            match context.query_authority.as_ref() {
                Some(authority) => Some(
                    authority
                        .acquire_async(&context.page, &operation)
                        .await
                        .map_err(failure)?,
                ),
                None => None,
            }
        } else {
            None
        };
        if let Some(partition) = query_partition.as_ref() {
            tokio::select! {
                result = prepare_query_worlds(&context.page, &operation, partition, &context.ui, protected) => result.map_err(failure)?,
                _ = observation::capture_retired() => {
                    check(&context.page, &operation).map_err(failure)?;
                    return Err(failure(ProtocolError::StaleReference));
                }
            }
        }
        screenshot_stage(screenshot, ScreenshotStage::UiAdmission);
        let _ui = tokio::select! {
            result = context.ui.enter(protected, operation.is_callback,
                operation.deadline, operation.cancellation.clone()) => result.map_err(failure)?,
            _ = observation::capture_retired() => {
                check(&context.page, &operation).map_err(failure)?;
                return Err(failure(ProtocolError::StaleReference));
            }
        };
        if let DispatchRequest::ReadFields(read) = &request {
            let check_authority = || {
                check(&context.page, &operation)?;
                self.check_publication_fence(retirement_fence)?;
                if !context
                    .attachment
                    .same_attachment(&context.page.targets.owned_target(&context.page.target_id)?)
                {
                    return Err(ProtocolError::StaleScope);
                }
                let ledger = context
                    .page
                    .client
                    .debt_ledger()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                read.check_admission(&operation, &identity, &ledger)
            };
            check_authority().map_err(failure)?;
            let frames =
                verified_frames_with_cleanup(&context.page, &operation, Some(&observation_cleanup))
                    .await
                    .map_err(failure)?;
            let values = observation::query_fields(
                &context.page.client,
                &frames,
                &read.options,
                &read.fields,
                &operation,
            )
            .await
            .map_err(map_observation)
            .map_err(failure)?;
            let current =
                verified_frames_with_cleanup(&context.page, &operation, Some(&observation_cleanup))
                    .await
                    .map_err(failure)?;
            same_frames(&frames, &current).map_err(failure)?;
            check_authority().map_err(failure)?;
            let value = json!({"identityScope":identity,"values":values});
            bounded_result(&value).map_err(failure)?;
            return Ok(Output {
                value,
                handles: vec![],
            });
        }
        // Acquire UI first: a queued protected writer must not hold this mutex
        // while a valid callback query needs it to finish the active parent.
        screenshot_stage(screenshot, ScreenshotStage::PublicationAdmission);
        let mut cancellation = operation.cancellation.clone();
        let mut publication = tokio::select! {
            lock = self.publication.lock() => lock,
            _ = observation::capture_retired() => {
                check(&context.page, &operation).map_err(failure)?;
                return Err(failure(ProtocolError::StaleReference));
            },
            _ = cancellation.changed() => return Err(failure(ProtocolError::Cancelled)),
            _ = tokio::time::sleep_until(operation.deadline.into()) => return Err(failure(ProtocolError::DeadlineExceeded)),
        };
        check(&context.page, &operation).map_err(failure)?;
        self.check_publication_fence(retirement_fence)
            .map_err(failure)?;
        if !context.attachment.same_attachment(
            &context
                .page
                .targets
                .owned_target(&context.page.target_id)
                .map_err(failure)?,
        ) {
            return Err(failure(ProtocolError::StaleScope));
        }
        if let Some(ledger) = context.page.client.debt_ledger() {
            ledger
                .check_admission(super::client_debt::AdmissionClass::Reference)
                .map_err(failure)?;
        }
        // Correlation reads committed authority only. It must return before any
        // revision staging, clone publication, pixel reservation or journal.
        if let DispatchRequest::Correlate(request) = &request {
            let value = reference_correlation::run(
                self,
                &context,
                request,
                &operation,
                publication.observed_revision,
                &observation_cleanup,
            )
            .await
            .map_err(failure)?;
            self.check_publication_fence(retirement_fence)
                .map_err(failure)?;
            return Ok(Output {
                value,
                handles: vec![],
            });
        }
        let publication_kind = match &request {
            DispatchRequest::ReadFields(_) => return Err(failure(ProtocolError::InvalidArguments)),
            DispatchRequest::Correlate(_) => return Err(failure(ProtocolError::InvalidArguments)),
            DispatchRequest::Observe(_) => PublicationKind::Snapshot,
            DispatchRequest::TraceSemantic(_) => PublicationKind::TraceSemantic,
            DispatchRequest::Query(_) => PublicationKind::AdditiveQuery,
            DispatchRequest::Screenshot(request) => {
                if request.purpose == ScreenshotPurpose::Trace {
                    PublicationKind::TraceViewport
                } else {
                    PublicationKind::PixelsOnly
                }
            }
        };
        let revision = publication
            .stage_revision(publication_kind)
            .map_err(failure)?;
        let mut staged = self
            .refs
            .lock()
            .map_err(|_| failure(ProtocolError::ScopeUnavailable))?
            .clone();
        if matches!(publication_kind, PublicationKind::TraceSemantic) {
            // Clear only the clone. No trace ref, including its viewport, may
            // alias committed action authority; the monotonic allocator is shared.
            staged.retire_interaction_references();
        }
        let wants_pixels = matches!(&request, DispatchRequest::Screenshot(_));
        // Charge the native producer before screenshot collection starts.
        screenshot_stage(screenshot, ScreenshotStage::ProducerReservation);
        let mut producer = if wants_pixels {
            Some(
                context
                    .blobs
                    .reserve_bounded_producer(
                        context.scope.clone(),
                        client_capture::MAX_PNG_BYTES.min(context.blobs.producer_limit()),
                    )
                    .map_err(|error| failure(blob_error(error)))?,
            )
        } else {
            None
        };
        #[cfg(test)]
        witness.enter(ObserveFailureStage::InitialFrames);
        screenshot_stage(screenshot, ScreenshotStage::InitialFrames);
        let frames = if matches!(&request, DispatchRequest::TraceSemantic(_))
            || matches!(&request, DispatchRequest::Screenshot(request) if request.purpose == ScreenshotPurpose::Trace) {
            self.initial_trace_frames(&context, &operation, retirement_fence, &observation_cleanup, screenshot).await
        } else if matches!(&request, DispatchRequest::Observe(_)) {
            self.initial_observe_frames(&context, &operation, capture.as_ref(), retirement_fence, &observation_cleanup, screenshot).await
        } else {
            query_frames(&context.page, &operation, Some(&observation_cleanup), screenshot, query_partition.as_ref().map(|proof| proof.diagnostic_phase(diagnostic::QueryScopeStage::InitialFrames)).as_ref()).await
        }.map_err(failure)?;
        let fallback_selector = match &request {
            DispatchRequest::Observe(request) if request.options.pixel_fallback => {
                Some(request.secure_field_selector.clone())
            }
            _ => None,
        };
        let mut capture_context = CaptureContext {
            page: context.page,
            frames,
            inventory_complete: true,
        };
        let is_observe = matches!(&request, DispatchRequest::Observe(_));
        let outcome = async {
        #[cfg(test)]
        witness.enter(ObserveFailureStage::ProtectedBarrier);
        screenshot_stage(screenshot, ScreenshotStage::ProtectedBarrier);
        let mut journal = if protected {
            Some(
                ProtectedReadJournal::begin_query_async(
                    &capture_context.page,
                    &operation,
                    query_partition.as_ref(),
                )
                .await
                .map_err(|e| DispatchFailure {
                    error: protected_error(e.reason),
                    identity_scope: e.identity_scope,
                    cleanup_integrity_lost: e.cleanup_integrity_lost,
                })?,
            )
        } else {
            None
        };
        let mut geometry = None;
        let mut completed_optional = None;
        let result = async {
            screenshot_stage(screenshot, ScreenshotStage::AnimationStabilization);
            if stabilize_pixels { journal.as_mut().ok_or(ProtocolError::PolicyDenied)?.stabilize_animations().await.map_err(protected_error)?; }
            #[cfg(test)]
            witness.enter(ObserveFailureStage::ProtectedFrames);
            screenshot_stage(screenshot, ScreenshotStage::ProtectedFrames);
            let frozen = if is_observe {
                verified_semantic_frames_with_cleanup(&capture_context.page, &operation, Some(&observation_cleanup), screenshot).await?
            } else {
                query_frames(&capture_context.page, &operation, Some(&observation_cleanup), screenshot, query_partition.as_ref().map(|proof| proof.diagnostic_phase(diagnostic::QueryScopeStage::ProtectedFrames)).as_ref()).await?
            };
            same_frames(&capture_context.frames, &frozen)?;
            // Semantic capture proves which exact documents were projected,
            // including separate hidden/policy/depth/budget omissions. Acquire
            // its private proof before geometry; pixels and queries stay strict.
            screenshot_stage(screenshot, ScreenshotStage::Geometry);
            if !matches!(&request, DispatchRequest::TraceSemantic(_))
                && !matches!(&request, DispatchRequest::Observe(_)) {
                geometry = Some(GeometrySnapshot::capture(&capture_context.page.client, &capture_context.page.page_session_id, &frozen, &operation).await.map_err(map_geometry)?);
            }
            match request {
                DispatchRequest::ReadFields(_) => Err(ProtocolError::InvalidArguments),
                DispatchRequest::Correlate(_) => Err(ProtocolError::InvalidArguments),
                DispatchRequest::TraceSemantic(_) => {
                    let options = context.policy.observation_options();
                    screenshot_stage(screenshot, ScreenshotStage::SemanticViewport);
                    let observed_viewport = viewport(&capture_context.page, &operation).await?;
                    let semantic = semantic_lease(&operation, false);
                    // Capture is semantic here; the pixel capture subphase stays NotEntered.
                    screenshot_stage(screenshot, ScreenshotStage::SemanticMetadata);
                    let mut tree = observation::observe(&capture_context.page.client, &frozen, &mut staged, &identity, revision, &options, &semantic).await.map_err(map_observation)?;
                    screenshot_stage(screenshot, ScreenshotStage::SemanticFrameGeometry);
                    geometry = Some(GeometrySnapshot::capture_semantic(&capture_context.page.client, &capture_context.page.page_session_id, &frozen, &tree.semantic_frame_proof, &context.policy.frame_policy, &identity, revision, &operation).await.map_err(map_geometry)?);
                    let proof = geometry.as_ref().ok_or(ProtocolError::PolicyDenied)?;
                    screenshot_stage(screenshot, ScreenshotStage::SemanticNodeGeometry);
                    observation::project_geometry(&capture_context.page.client, &frozen, &staged, proof, &mut tree.roots, &operation).await.map_err(map_geometry)?;
                    screenshot_stage(screenshot, ScreenshotStage::SemanticDocumentRoot);
                    let root = exact_root(tree.roots, &staged, &frozen)?;
                    verify_document_root(&capture_context.page, &root, &staged, &operation).await?;
                    screenshot_stage(screenshot, ScreenshotStage::SemanticFinalViewport);
                    if viewport(&capture_context.page, &operation).await? != observed_viewport { return Err(ProtocolError::StaleScope); }
                    Ok((json!({"identityScope":identity,"revision":revision.to_string(),"root":root,
                        "viewportRef":tree.viewport_ref,"truncated":tree.truncated,
                        "viewport":observed_viewport,"location":main_frame(&frozen)?.url}), None, None))
                }
                DispatchRequest::Query(query) => {
                    let geometry = geometry.as_ref().ok_or(ProtocolError::PolicyDenied)?;
                    let mut output = observation::query(&capture_context.page.client, &frozen, &mut staged, &identity, revision, &query.options, &operation).await.map_err(map_observation)?;
                    observation::project_geometry(&capture_context.page.client, &frozen, &staged, geometry, &mut output.nodes, &operation).await.map_err(map_geometry)?;
                    Ok((serde_json::to_value(output).map_err(|_| ProtocolError::BrowserFailure)?, None, None))
                }
                DispatchRequest::Screenshot(request) => {
                    screenshot_stage(screenshot, ScreenshotStage::TraceMetadata);
                    let geometry = geometry.as_ref().ok_or(ProtocolError::PolicyDenied)?;
                    let value = if request.purpose == ScreenshotPurpose::Trace {
                        let viewport_ref = staged.try_viewport_ref(&identity, operation.generation,
                            &capture_context.page.page_session_id, revision).map_err(|_| ProtocolError::IdentifierExhausted)?;
                        let viewport_ref = observation::NodeReference { id: format!("@{}", viewport_ref.id), revision: viewport_ref.issuance.revision.to_string() };
                        json!({"identityScope":identity,"viewportRef":viewport_ref,
                            "viewport":viewport(&capture_context.page, &operation).await?,
                            "location":main_frame(&frozen)?.url})
                    } else { Value::Null };
                    screenshot_stage(screenshot, ScreenshotStage::Capture);
                    let pixels = client_capture::capture_under_journal(&capture_context, &CaptureRequest { secure_field_selector: request.secure_field_selector }, &operation, journal.as_mut().ok_or(ProtocolError::PolicyDenied)?, geometry).await.map_err(|error| {
                        if let Some(witness) = screenshot { witness.capture_failure(error); }
                        capture_error(error.reason)
                    })?;
                    Ok((value, Some(pixels), None))
                }
                DispatchRequest::Observe(request) => {
                    let options = context.policy.observation_options();
                    #[cfg(test)]
                    witness.enter(ObserveFailureStage::Viewport);
                    screenshot_stage(screenshot, ScreenshotStage::SemanticViewport);
                    let observed_viewport = viewport(&capture_context.page, &operation).await?;
                    let semantic = semantic_lease(&operation, request.options.pixel_fallback);
                    #[cfg(test)]
                    witness.enter(ObserveFailureStage::SemanticRead);
                    screenshot_stage(screenshot, ScreenshotStage::SemanticMetadata);
                    let tree = async {
                        #[cfg(test)]
                        {
                            let injected = self.semantic_failure_for_test.lock()
                                .map_err(|_| ObservationError::BackendFailure)?.take();
                            if let Some(error) = injected { return Err(error); }
                        }
                        #[cfg(feature = "acceptance-faults")]
                        context.faults.checkpoint(&identity, super::client_test_faults::Phase::SemanticAcquire, vec![], &semantic).await.map_err(fault_observation_error)?;
                        #[cfg(feature = "acceptance-faults")]
                        let prior_next_ref = staged.next_ref_num();
                        let tree = observation::observe(&capture_context.page.client, &frozen, &mut staged, &identity, revision, &options, &semantic).await?;
                        #[cfg(feature = "acceptance-faults")]
                        {
                            let mut allocated = staged.ref_ids().into_iter().filter(|id| id.strip_prefix('e').and_then(|number| number.parse::<usize>().ok()).is_some_and(|number| number >= prior_next_ref)).map(|id| format!("@{id}")).collect::<Vec<_>>();
                            allocated.sort();
                            context.faults.checkpoint(&identity, super::client_test_faults::Phase::SemanticPublish, allocated, &semantic).await.map_err(fault_observation_error)?;
                        }
                        Ok::<_, ObservationError>(tree)
                    }.await;
                    let (mut value, fallback) = match tree {
                        Ok(mut tree) => {
                            #[cfg(test)]
                            witness.enter(ObserveFailureStage::Geometry);
                            if geometry.is_none() {
                                screenshot_stage(screenshot, ScreenshotStage::SemanticFrameGeometry);
                                geometry = Some(GeometrySnapshot::capture_semantic(&capture_context.page.client, &capture_context.page.page_session_id, &frozen, &tree.semantic_frame_proof, &context.policy.frame_policy, &identity, revision, &operation).await.map_err(map_geometry)?);
                            }
                            let geometry = geometry.as_ref().ok_or(ProtocolError::PolicyDenied)?;
                            screenshot_stage(screenshot, ScreenshotStage::SemanticNodeGeometry);
                            observation::project_geometry(&capture_context.page.client, &frozen, &staged, geometry, &mut tree.roots, &operation).await.map_err(map_geometry)?;
                            #[cfg(test)]
                            witness.enter(ObserveFailureStage::DocumentRoot);
                            screenshot_stage(screenshot, ScreenshotStage::SemanticDocumentRoot);
                            let root = exact_root(tree.roots, &staged, &frozen)?;
                            verify_document_root(&capture_context.page, &root, &staged, &operation).await?;
                            (json!({"identityScope":identity,"revision":revision.to_string(),"root":root,"viewportRef":tree.viewport_ref,"truncated":tree.truncated}), false)
                        }
                        Err(ObservationError::DeadlineExceeded) if request.options.pixel_fallback => {
                            check(&capture_context.page, &operation)?;
                            // Any previous pixel stabilization must restore before fresh
                            // fallback pixels can observe current application state.
                            return Ok((Value::Null, None, Some(SemanticDeadline)));
                        }
                        Err(error) => return Err(map_observation(error)),
                    };
                    #[cfg(test)]
                    witness.enter(ObserveFailureStage::Viewport);
                    screenshot_stage(screenshot, ScreenshotStage::SemanticFinalViewport);
                    if viewport(&capture_context.page, &operation).await? != observed_viewport { return Err(ProtocolError::StaleScope); }
                    value["viewport"] = observed_viewport;
                    let main = main_frame(&frozen)?;
                    value["location"] = Value::String(main.url.clone());
                    if request.options.pixels && !fallback {
                        // Finish the same proof as tree-only Observe before any
                        // optional-only animation, strict geometry or raw capture.
                        if let Some(semantic_journal) = journal.take() {
                            semantic_journal.check_async().await.map_err(protected_error)?;
                            // Observe has not stabilized or installed masks yet.
                            // The existing no-effects Drop closes this read-only
                            // barrier without starting the raw cleanup clock.
                            drop(semantic_journal);
                        }
                        let geometry = geometry.as_ref().ok_or(ProtocolError::PolicyDenied)?;
                        screenshot_stage(screenshot, ScreenshotStage::FinalGeometry);
                        geometry.revalidate(&capture_context.page.client, &operation).await.map_err(map_geometry)?;
                        screenshot_stage(screenshot, ScreenshotStage::FinalFrames);
                        let current = verified_semantic_frames_with_cleanup(&capture_context.page, &operation, Some(&observation_cleanup), screenshot).await?;
                        same_frames(&capture_context.frames, &current)?;
                        screenshot_stage(screenshot, ScreenshotStage::FinalViewport);
                        if viewport(&capture_context.page, &operation).await? != value["viewport"] {
                            return Err(ProtocolError::StaleScope);
                        }
                        screenshot_stage(screenshot, ScreenshotStage::FinalScope);
                        bounded_result(&value)?;
                        check(&capture_context.page, &operation)?;
                        // The tree is immutable, but its staged refs remain
                        // private until the on-time result actually publishes.
                        completed_optional = Some(self.optional_observe_pixels(
                            &capture_context, &operation, capture.as_ref(), retirement_fence,
                            &context.blobs, &context.scope, &mut publication, revision, &staged,
                            request.secure_field_selector, value, result_send, receipt, screenshot,
                        ).await);
                        return Ok((Value::Null, None, None));
                    }
                    Ok((value, None, None))
                }
            }
        }.await;
        if let Some(output) = completed_optional { return output; }
        if let (Some(witness), Err(error)) = (screenshot, &result) { witness.failure(error); }
        screenshot_stage(screenshot, ScreenshotStage::Restoration);
        #[cfg(test)]
        {
            // Capture the primary before restoration or final proof can fail.
            if result.is_err() { witness.failure(); }
            witness.enter(ObserveFailureStage::Restoration);
        }
        let restoration = match &mut journal {
            Some(journal) => journal.restore().await,
            None => Ok(()),
        };
        if let Err(error) = restoration {
            if let Some(witness) = screenshot { witness.failure(&protected_error(error.reason)); }
            return Err(DispatchFailure {
                error: result
                    .as_ref()
                    .err()
                    .cloned()
                    .unwrap_or_else(|| protected_error(error.reason)),
                identity_scope: identity.clone(),
                cleanup_integrity_lost: error.cleanup_integrity_lost
                    || observation_cleanup.load(Ordering::SeqCst),
            });
        }
        // A clean restore must not turn a policy failure into a timeout and
        // thereby accidentally authorize fallback at a higher layer.
        let (mut value, mut pixels, fallback_cause) = result.map_err(failure)?;
        #[cfg(test)]
        witness.enter(ObserveFailureStage::FinalProof);
        screenshot_stage(screenshot, ScreenshotStage::FinalGeometry);
        if fallback_cause.is_none() {
            if let Some(geometry) = &geometry {
                geometry
                    .revalidate(&capture_context.page.client, &operation)
                    .await
                    .map_err(map_geometry)
                    .map_err(failure)?;
            }
        }
        if let Some(cause) = fallback_cause {
            if let Some(journal) = &journal {
                journal.check_async().await.map_err(|e| failure(protected_error(e)))?;
            }
            // Release the old target barrier only after acknowledged restoration.
            // The UI owner and original operation budget remain unchanged.
            drop(journal);
            check(&capture_context.page, &operation).map_err(failure)?;
            capture_context.frames = verified_frames_with_cleanup(&capture_context.page, &operation, Some(&observation_cleanup))
                .await
                .map_err(failure)?;
            staged = self
                .refs
                .lock()
                .map_err(|_| failure(ProtocolError::ScopeUnavailable))?
                .clone();
            // Fallback retires both current populations, not inert document identity.
            // Standalone pixels-only publication does not take this branch.
            staged.retire_semantic_authority();
            staged.begin_observation(&capture_context.page.identity_scope, operation.generation, revision);
            let selector = fallback_selector
                .as_deref()
                .ok_or_else(|| failure(ProtocolError::PolicyDenied))?;
            // Permission to fall back does not itself request pixels. Admit
            // fresh fallback only after the semantic deadline and restoration,
            // under the same exact scope and unchanged operation budget.
            check(&capture_context.page, &operation).map_err(failure)?;
            if producer.is_none() {
                producer = Some(context.blobs.reserve_bounded_producer(context.scope.clone(), client_capture::MAX_PNG_BYTES.min(context.blobs.producer_limit()))
                    .map_err(|error| failure(blob_error(error)))?);
            }
            let (fresh_value, fresh_pixels, fresh_journal) = fresh_fallback(
                &capture_context,
                selector,
                &mut staged,
                revision,
                &operation,
                cause,
            )
            .await?;
            value = fresh_value;
            pixels = Some(fresh_pixels);
            journal = Some(fresh_journal);
        }
        screenshot_stage(screenshot, ScreenshotStage::FinalBarrier);
        if let Some(journal) = &journal {
            journal.check_async().await.map_err(|e| failure(protected_error(e)))?;
        }
        screenshot_stage(screenshot, ScreenshotStage::FinalScope);
        check(&capture_context.page, &operation).map_err(failure)?;
        screenshot_stage(screenshot, ScreenshotStage::FinalFrames);
        let final_frames = if is_observe {
            verified_semantic_frames_with_cleanup(&capture_context.page, &operation, Some(&observation_cleanup), screenshot).await
        } else {
            query_frames(&capture_context.page, &operation, Some(&observation_cleanup), screenshot, query_partition.as_ref().map(|proof| proof.diagnostic_phase(diagnostic::QueryScopeStage::FinalFrames)).as_ref()).await
        }
            .map_err(failure)?;
        same_frames(&capture_context.frames, &final_frames).map_err(failure)?;
        screenshot_stage(screenshot, ScreenshotStage::FinalViewport);
        if value.get("viewport").is_some()
            && viewport(&capture_context.page, &operation)
                .await
                .map_err(failure)?
                != value["viewport"]
        {
            return Err(failure(ProtocolError::StaleScope));
        }
        screenshot_stage(screenshot, ScreenshotStage::BlobPublication);
        let mut handles = Vec::new();
        if let Some(pixels) = pixels {
            let producer = producer
                .take()
                .ok_or_else(|| failure(ProtocolError::ScopeUnavailable))?;
            let image = context
                .blobs
                .finish_producer(producer, pixels.png)
                .map_err(|error| failure(blob_error(error)))?;
            handles.push(image.handle.clone());
            let image = json!({"identityScope":identity,"handle":image.handle,"size":image.size,"sha256":image.sha256,"mediaType":"image/png","width":pixels.width,"height":pixels.height,"scale":pixels.scale,"maskedRegionCount":pixels.masked_region_count});
            if value.is_null() {
                value = image;
            } else if matches!(publication_kind, PublicationKind::TraceViewport) {
                value.as_object_mut().ok_or_else(|| failure(ProtocolError::BrowserFailure))?.extend(image.as_object().ok_or_else(|| failure(ProtocolError::BrowserFailure))?.clone());
            } else {
                value["maskedRegionCount"] = image["maskedRegionCount"].clone();
                value["pixels"] = image;
            }
        }
        #[cfg(test)]
        witness.enter(ObserveFailureStage::Publication);
        screenshot_stage(screenshot, ScreenshotStage::Publication);
        let publish = (async {
            bounded_result(&value)?;
            check(&capture_context.page, &operation)?;
            if let Some(journal) = &journal {
                journal.check_async().await.map_err(protected_error)?;
            }
            if let Some(partition) = query_partition.as_ref() {
                self.commit_staged_query(&capture_context.page, &operation, capture.as_ref(), trace.as_ref(), retirement_fence,
                    &mut publication, publication_kind, revision, staged, &context.blobs, &context.scope, &handles, partition).await?;
            } else {
                self.commit_staged(&capture_context.page, &operation, capture.as_ref(), trace.as_ref(), retirement_fence,
                    &mut publication, publication_kind, revision, staged, &context.blobs, &context.scope, &handles, None)?;
            }
            Ok::<(), ProtocolError>(())
        }).await;
        if let Err(error) = publish {
            if let Some(witness) = screenshot { witness.failure(&error); }
            let clean = release_handles(&context.blobs, &context.scope, &handles);
            if !clean {
                capture_context.page.targets.seal();
            }
            return Err(DispatchFailure {
                error,
                identity_scope: identity.clone(),
                cleanup_integrity_lost: !clean,
            });
        }
        Ok(Output { value, handles })
        }.await;
        #[cfg(test)]
        if outcome.is_err() {
            witness.failure();
        }
        match outcome {
            Err(mut failure)
                if is_observe
                    && !failure.cleanup_integrity_lost
                    && failure.error == ProtocolError::StaleScope =>
            {
                match document_retirement_proven(&capture_context, &operation).await {
                    Ok(true) => failure.error = ProtocolError::StaleReference,
                    Err(ProtocolError::CleanupFailed) => failure.cleanup_integrity_lost = true,
                    _ => {}
                }
                Err(failure)
            }
            outcome => outcome,
        }
    }
}

/// Classify only an observe failure after its cleanup has finished. A stale
/// capture can also mean layout movement, a retired attempt, or lost inventory
/// authority; none of those is evidence of document replacement.
async fn document_retirement_proven(
    context: &CaptureContext,
    operation: &OperationLease,
) -> Result<bool, ProtocolError> {
    if check(&context.page, operation).is_err() {
        return Ok(false);
    }
    let Ok((revision, targets)) = context.page.targets.inventory() else {
        return Ok(false);
    };
    let page_present = targets.iter().any(|target| {
        target.target_id == context.page.target_id
            && target.session_id == context.page.page_session_id
            && target.kind == "page"
            && target.purpose == Some(TargetPurpose::Application)
    });
    let replaced = if !page_present {
        true
    } else {
        // This recheck consumes only the original operation's remaining budget.
        // Failure to obtain a complete owned inventory is inconclusive, not a
        // reason to convert cancellation or a backend error into NODE_STALE.
        match verified_frames(&context.page, operation).await {
            Ok(current) => retired_document(&context.frames, &current),
            Err(ProtocolError::CleanupFailed) => return Err(ProtocolError::CleanupFailed),
            Err(_) => false,
        }
    };
    Ok(replaced
        && context.page.targets.check_revision(revision).is_ok()
        && check(&context.page, operation).is_ok())
}
fn retired_document(before: &[ObservationFrame], after: &[ObservationFrame]) -> bool {
    before.iter().any(|old| {
        !after.iter().any(|new| {
            old.binding.page_session == new.binding.page_session
                && old.binding.session == new.binding.session
                && old.binding.frame == new.binding.frame
                && old.binding.loader == new.binding.loader
        })
    })
}

#[cfg(feature = "acceptance-faults")]
fn fault_observation_error(error: ProtocolError) -> ObservationError {
    match error {
        ProtocolError::DeadlineExceeded => ObservationError::DeadlineExceeded,
        ProtocolError::Cancelled => ObservationError::Cancelled,
        ProtocolError::StaleScope => ObservationError::StaleReference,
        ProtocolError::StaleReference => ObservationError::Superseded,
        _ => ObservationError::BackendFailure,
    }
}
/// Only the exact semantic DeadlineExceeded arm may authorize fresh fallback.
struct SemanticDeadline;
impl SemanticDeadline {
    fn error(self) -> ProtocolError {
        ProtocolError::DeadlineExceeded
    }
}

enum FallbackFailure {
    Protocol(ProtocolError),
    Capture(CaptureAttemptFailure),
}
impl From<ProtocolError> for FallbackFailure {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}
impl FallbackFailure {
    fn protocol_error(&self) -> ProtocolError {
        match self {
            Self::Protocol(error) => error.clone(),
            Self::Capture(error) => capture_error(error.reason),
        }
    }
    fn independent_coverage_unproven(&self) -> bool {
        matches!(
            self,
            Self::Capture(CaptureAttemptFailure {
                phase: CapturePhase::IndependentCoverage,
                reason: CaptureReason::MaskingUnproven,
            })
        )
    }
}
/// A timed-out semantic transaction is already restored before entering here.
/// Returned journal retains the new target barrier until the final publication.
async fn fresh_fallback<'a>(
    context: &'a CaptureContext,
    selector: &str,
    refs: &mut RefMap,
    revision: u64,
    operation: &'a OperationLease,
    cause: SemanticDeadline,
) -> Result<
    (
        Value,
        super::client_capture::MaskedCapture,
        ProtectedReadJournal<'a>,
    ),
    DispatchFailure,
> {
    let observation_cleanup = AtomicBool::new(false);
    #[cfg(test)]
    if FALLBACK_OBSERVED_CLEANUP_FOR_TEST
        .try_with(|flag| *flag)
        .unwrap_or(false)
    {
        // Branch evidence only: the actual capture and journal still run, but
        // this flag does not claim that a renderer cleanup failed naturally.
        observation_cleanup.store(true, Ordering::SeqCst);
    }
    let failure = |error: ProtocolError| DispatchFailure {
        cleanup_integrity_lost: error == ProtocolError::CleanupFailed
            || observation_cleanup.load(Ordering::SeqCst),
        error,
        identity_scope: context.page.identity_scope.clone(),
    };
    let mut journal =
        ProtectedReadJournal::begin(&context.page, operation).map_err(|error| DispatchFailure {
            error: protected_error(error.reason),
            identity_scope: error.identity_scope,
            cleanup_integrity_lost: error.cleanup_integrity_lost,
        })?;
    let mut geometry = None;
    let result = async {
        journal.stabilize_animations().await.map_err(protected_error)?;
        let frozen = verified_frames_with_cleanup(&context.page, operation, Some(&observation_cleanup)).await?;
        same_frames(&context.frames, &frozen)?;
        geometry = Some(GeometrySnapshot::capture(&context.page.client, &context.page.page_session_id, &frozen, operation).await.map_err(geometry_error)?);
        let geometry = geometry.as_ref().ok_or(ProtocolError::PolicyDenied)?;
        let root = minimal_document(&context.page, &frozen, refs, operation).await?;
        let viewport_ref = {
            let viewport = refs.try_viewport_ref(&context.page.identity_scope, operation.generation,
                &context.page.page_session_id, revision).map_err(|_| ProtocolError::IdentifierExhausted)?;
            observation::NodeReference { id: format!("@{}", viewport.id), revision: viewport.issuance.revision.to_string() }
        };
        let viewport = viewport(&context.page, operation).await?;
        let pixels = client_capture::capture_under_journal(context, &CaptureRequest { secure_field_selector: selector.to_owned() }, &pixel_lease(operation), &mut journal, geometry).await.map_err(FallbackFailure::Capture)?;
        let value = json!({"identityScope":context.page.identity_scope,"revision":revision.to_string(),"root":{"ref":root},
            "viewportRef":viewport_ref,"truncated":true,"treeUnavailable":true,
            "viewport":viewport,"location":main_frame(&frozen)?.url});
        Ok::<_, FallbackFailure>((value, pixels))
    }.await;
    if let Err(error) = journal.restore().await {
        return Err(DispatchFailure {
            error: result
                .as_ref()
                .err()
                .map(FallbackFailure::protocol_error)
                .unwrap_or_else(|| protected_error(error.reason)),
            identity_scope: error.identity_scope,
            cleanup_integrity_lost: error.cleanup_integrity_lost
                || observation_cleanup.load(Ordering::SeqCst)
                || result
                    .as_ref()
                    .err()
                    .is_some_and(|error| error.protocol_error() == ProtocolError::CleanupFailed),
        });
    }
    let (value, pixels) = match result {
        Ok(value) => value,
        Err(error)
            if error.independent_coverage_unproven()
                && !observation_cleanup.load(Ordering::SeqCst) =>
        {
            // Restore must settle first. Cancellation or authority loss during
            // restoration still outranks this narrowly recoverable proof failure.
            journal
                .check()
                .map_err(|error| failure(protected_error(error)))?;
            check(&context.page, operation).map_err(failure)?;
            return Err(failure(cause.error()));
        }
        Err(error) => return Err(failure(error.protocol_error())),
    };
    if let Some(geometry) = &geometry {
        geometry
            .revalidate(&context.page.client, operation)
            .await
            .map_err(geometry_error)
            .map_err(failure)?;
    }
    journal
        .check()
        .map_err(|error| failure(protected_error(error)))?;
    check(&context.page, operation).map_err(failure)?;
    same_frames(
        &context.frames,
        &verified_frames_with_cleanup(&context.page, operation, Some(&observation_cleanup))
            .await
            .map_err(failure)?,
    )
    .map_err(failure)?;
    if viewport(&context.page, operation).await.map_err(failure)? != value["viewport"] {
        return Err(failure(ProtocolError::StaleScope));
    }
    Ok((value, pixels, journal))
}

fn validate_policy(policy: &ReadPolicy, request: &DispatchRequest) -> Result<(), ProtocolError> {
    if let DispatchRequest::TraceSemantic(request) = request {
        if request.options.pixels || request.options.pixel_fallback || request.options.comparable {
            return Err(ProtocolError::InvalidArguments);
        }
    }
    if policy.test_id_attribute.is_empty()
        || policy.test_id_attribute.len() > 256
        || policy.secure_field_selector.is_empty()
        || policy.secure_field_selector.len() > 8192
    {
        return Err(ProtocolError::PolicyDenied);
    }
    let matches = match request {
        DispatchRequest::ReadFields(request) => {
            policy.test_id_attribute == request.options.test_id_attribute
                && policy.secure_field_selector == request.options.secure_field_selector
        }
        DispatchRequest::Correlate(_) => true,
        DispatchRequest::Observe(request) | DispatchRequest::TraceSemantic(request) => {
            policy.test_id_attribute == request.test_id_attribute
                && policy.secure_field_selector == request.secure_field_selector
        }
        DispatchRequest::Query(request) => {
            policy.test_id_attribute == request.options.test_id_attribute
                && policy.secure_field_selector == request.options.secure_field_selector
        }
        DispatchRequest::Screenshot(request) => {
            policy.secure_field_selector == request.secure_field_selector
        }
    };
    if !matches {
        return Err(ProtocolError::PolicyDenied);
    }
    Ok(())
}
/// Leave room for correlation/outcome metadata without allocating a second
/// unbounded serialized copy. Query matches are never silently discarded.
fn bounded_result(value: &Value) -> Result<(), ProtocolError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.0 {
                return Err(std::io::Error::other("native result bound exceeded"));
            }
            self.0 -= bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(
        Counter(super::client_protocol::MAX_FRAME_BYTES - 16 * 1024),
        value,
    )
    .map_err(|_| ProtocolError::CapacityExceeded)
}
fn release_handles(blobs: &BlobStore, scope: &BlobScope, handles: &[String]) -> bool {
    let mut clean = true;
    for handle in handles {
        clean &= blobs.release(scope, handle).is_ok();
    }
    clean
}
fn blob_error(error: BlobError) -> ProtocolError {
    match error {
        BlobError::QuotaExceeded => ProtocolError::CapacityExceeded,
        BlobError::StaleScope | BlobError::Closed => ProtocolError::StaleScope,
        _ => ProtocolError::BrowserFailure,
    }
}
fn check(page: &BrowserExecutionLease, operation: &OperationLease) -> Result<(), ProtocolError> {
    page.permit.check()?;
    if *operation.cancellation.borrow() != CancelSignal::None {
        return Err(ProtocolError::Cancelled);
    }
    if Instant::now() >= operation.deadline {
        return Err(ProtocolError::DeadlineExceeded);
    }
    if observation::capture_superseded() {
        return Err(ProtocolError::StaleReference);
    }
    Ok(())
}
async fn command(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    session: &str,
    method: &str,
    args: Value,
) -> Result<Value, ProtocolError> {
    check(page, operation)?;
    let mut cancellation = operation.cancellation.clone();
    tokio::select! {
        result = page.client.send_command(method, Some(args), Some(session)) => { check(page, operation)?; result.map_err(|_| ProtocolError::BrowserFailure) },
        _ = cancellation.changed() => Err(ProtocolError::Cancelled),
        _ = tokio::time::sleep_until(operation.deadline.into()) => Err(ProtocolError::DeadlineExceeded),
    }
}
/// Derive frame/session ownership from native session evidence, never from the
/// commonly equal but non-contractual target ID and frame ID strings.
async fn verified_semantic_frames_with_cleanup(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    cleanup: Option<&AtomicBool>,
    screenshot: Option<&ScreenshotFailureWitness>,
) -> Result<Vec<ObservationFrame>, ProtocolError> {
    frame_inventory_attempt_impl(page, operation, cleanup, screenshot, true, None)
        .await
        .map(|inventory| inventory.frames)
        .map_err(|failure| failure.record(screenshot))
}
pub async fn verified_frames(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
) -> Result<Vec<ObservationFrame>, ProtocolError> {
    verified_frames_with_cleanup(page, operation, None).await
}
async fn verified_frames_with_cleanup(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    cleanup: Option<&AtomicBool>,
) -> Result<Vec<ObservationFrame>, ProtocolError> {
    verified_frames_with_diagnostic(page, operation, cleanup, None).await
}
async fn verified_frames_with_diagnostic(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    cleanup: Option<&AtomicBool>,
    screenshot: Option<&ScreenshotFailureWitness>,
) -> Result<Vec<ObservationFrame>, ProtocolError> {
    Ok(
        verified_frame_inventory_with_diagnostic(page, operation, cleanup, screenshot)
            .await?
            .frames,
    )
}
/// Frames and renderer roots from the same verified native inventory. A frame
/// with a parent is not necessarily a renderer root: same-process descendants
/// inherit their parent's session, including descendants within an OOPIF.
pub(crate) struct VerifiedFrameInventory {
    pub frames: Vec<ObservationFrame>,
    pub iframe_sessions: HashMap<String, String>,
}
pub(crate) async fn verified_frame_inventory(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
) -> Result<VerifiedFrameInventory, ProtocolError> {
    verified_frame_inventory_with_cleanup(page, operation, None).await
}
/// A revision-only race may discard one read-only prefix before input begins.
/// Both samples retain the caller's exact owner and original operation deadline.
pub(crate) async fn verified_action_frame_inventory(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    check_owner: impl Fn() -> Result<(), ProtocolError>,
) -> Result<VerifiedFrameInventory, ProtocolError> {
    check(page, operation)?;
    check_owner()?;
    let ledger = page.client.debt_ledger();
    let prefix_settled = || {
        let Some(ledger) = ledger.as_ref() else {
            return false;
        };
        if !ledger.matches_owner(operation.generation, &page.identity_scope)
            || page
                .client
                .check_cleanup_owner(&Some(ledger.clone()))
                .is_err()
            || ledger
                .check_admission(super::client_debt::AdmissionClass::Reference)
                .is_err()
        {
            return false;
        }
        let debt = ledger.snapshot();
        !debt.integrity_lost
            && debt.input_debt == 0
            && debt.object_debt == 0
            && debt.outstanding_commands == 0
    };
    let first = frame_inventory_attempt(page, operation, None, None).await;
    match first {
        Ok(inventory) => {
            check(page, operation)?;
            check_owner()?;
            Ok(inventory)
        }
        Err(failure) => {
            if !failure.revision_only() {
                return Err(failure.record(None));
            }
            check(page, operation)?;
            check_owner()?;
            if !prefix_settled() {
                return Err(failure.record(None));
            }
            tokio::task::yield_now().await;
            check(page, operation)?;
            check_owner()?;
            if !prefix_settled() {
                return Err(failure.record(None));
            }
            let inventory = frame_inventory_attempt(page, operation, None, None)
                .await
                .map_err(|failure| failure.record(None))?;
            check(page, operation)?;
            check_owner()?;
            if !prefix_settled() {
                return Err(ProtocolError::ScopeUnavailable);
            }
            Ok(inventory)
        }
    }
}
async fn verified_frame_inventory_with_cleanup(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    cleanup: Option<&AtomicBool>,
) -> Result<VerifiedFrameInventory, ProtocolError> {
    verified_frame_inventory_with_diagnostic(page, operation, cleanup, None).await
}
async fn verified_frame_inventory_with_diagnostic(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    cleanup: Option<&AtomicBool>,
    screenshot: Option<&ScreenshotFailureWitness>,
) -> Result<VerifiedFrameInventory, ProtocolError> {
    frame_inventory_attempt(page, operation, cleanup, screenshot)
        .await
        .map_err(|failure| failure.record(screenshot))
}
enum FrameInventoryFailure {
    Read(ProtocolError),
    Fence {
        error: ProtocolError,
        revision_only: bool,
        diagnostic: Option<diagnostic::FrameInventoryRejection>,
    },
}
impl From<ProtocolError> for FrameInventoryFailure {
    fn from(error: ProtocolError) -> Self {
        Self::Read(error)
    }
}
impl FrameInventoryFailure {
    fn revision_only(&self) -> bool {
        matches!(
            self,
            Self::Fence {
                revision_only: true,
                ..
            }
        )
    }
    fn record(self, witness: Option<&ScreenshotFailureWitness>) -> ProtocolError {
        match self {
            Self::Read(error) => error,
            Self::Fence {
                error, diagnostic, ..
            } => {
                if let Some(witness) = witness {
                    witness.inventory_failure(diagnostic, &error);
                }
                error
            }
        }
    }
}
async fn frame_inventory_attempt(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    cleanup: Option<&AtomicBool>,
    screenshot: Option<&ScreenshotFailureWitness>,
) -> Result<VerifiedFrameInventory, FrameInventoryFailure> {
    frame_inventory_attempt_impl(page, operation, cleanup, screenshot, false, None).await
}
#[cfg(test)]
pub(crate) async fn selected_query_frames_for_test(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    partition: &super::client_enrollment::PageAcquisitionProof,
) -> Result<Vec<ObservationFrame>, ProtocolError> {
    query_frames(page, operation, None, None, Some(partition)).await
}
/// Metadata RPCs use the SAME UI admission as the final query. Drop that
/// permit before awaiting event application; never retain publication/barriers.
async fn prepare_query_worlds(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    partition: &super::client_enrollment::PageAcquisitionProof,
    ui: &Arc<UiGate>,
    protected: bool,
) -> Result<(), ProtocolError> {
    let partition = partition.diagnostic_phase(diagnostic::QueryScopeStage::WarmWorlds);
    let permit = ui
        .enter(
            protected,
            operation.is_callback,
            operation.deadline,
            operation.cancellation.clone(),
        )
        .await?;
    warm_query_worlds(page, operation, &partition).await?;
    drop(permit);
    partition.wait_received_prefix(page, operation).await?;
    partition.check_async(page, operation).await
}
/// Only exact frame/world metadata, never DOM/geometry/selector projection.
async fn warm_query_worlds(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    partition: &super::client_enrollment::PageAcquisitionProof,
) -> Result<(), ProtocolError> {
    let partition = partition.diagnostic_phase(diagnostic::QueryScopeStage::WarmWorlds);
    partition.check_async(page, operation).await?;
    let mut trees = Vec::new();
    for target in partition.targets() {
        if !matches!(target.kind.as_str(), "page" | "iframe") {
            return Err(ProtocolError::StaleScope);
        }
        let tree = command(
            page,
            operation,
            &target.session_id,
            "Page.getFrameTree",
            json!({}),
        )
        .await?;
        trees.push((target.session_id.clone(), target.kind == "page", tree));
    }
    let lineage = page_lineage(&trees, &page.page_session_id)?;
    if lineage.parents.len() > 256 || lineage.iframe_sessions.len() > 256 {
        return Err(ProtocolError::InvalidArguments);
    }
    // Frame ancestry, never opener metadata, selects the exact CDP session.
    for frame in lineage.parents.keys() {
        let mut ancestor = frame;
        let mut session = page.page_session_id.as_str();
        let mut resolved = false;
        for _ in 0..=lineage.parents.len() {
            if let Some(owner) = lineage.iframe_sessions.get(ancestor) {
                session = owner;
                resolved = true;
                break;
            }
            match lineage.parents.get(ancestor) {
                Some(Some(parent)) => ancestor = parent,
                Some(None) => {
                    resolved = true;
                    break;
                }
                None => return Err(ProtocolError::StaleScope),
            }
        }
        if !resolved
            || !partition
                .targets()
                .iter()
                .any(|target| target.session_id == session)
        {
            return Err(ProtocolError::StaleScope);
        }
        command(
            page,
            operation,
            session,
            "Page.createIsolatedWorld",
            json!({"frameId":frame,"worldName":"agent-browser-native-observation"}),
        )
        .await?;
    }
    Ok(())
}
#[cfg(test)]
pub(crate) async fn warm_query_worlds_for_test(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    partition: &super::client_enrollment::PageAcquisitionProof,
    ui: &Arc<UiGate>,
) -> Result<(), ProtocolError> {
    prepare_query_worlds(page, operation, partition, ui, true).await
}
async fn query_frames(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    cleanup: Option<&AtomicBool>,
    screenshot: Option<&ScreenshotFailureWitness>,
    partition: Option<&super::client_enrollment::PageAcquisitionProof>,
) -> Result<Vec<ObservationFrame>, ProtocolError> {
    frame_inventory_attempt_impl(page, operation, cleanup, screenshot, false, partition)
        .await
        .map(|inventory| inventory.frames)
        .map_err(|error| error.record(screenshot))
}
async fn frame_inventory_attempt_impl(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    cleanup: Option<&AtomicBool>,
    screenshot: Option<&ScreenshotFailureWitness>,
    readonly_disposal: bool,
    partition: Option<&super::client_enrollment::PageAcquisitionProof>,
) -> Result<VerifiedFrameInventory, FrameInventoryFailure> {
    check(page, operation)?;
    let (revision, targets, inventory_before) = if let Some(partition) = partition {
        partition
            .check_frame_boundary_async(page, operation, true)
            .await?;
        (0, partition.targets().to_vec(), None)
    } else {
        page.targets
            .inventory_with_diagnostic(screenshot.is_some())?
    };
    if let Some(witness) = screenshot {
        witness.revision(revision);
    }
    let main = targets
        .iter()
        .find(|target| {
            target.target_id == page.target_id
                && target.session_id == page.page_session_id
                && target.kind == "page"
                && target.purpose == Some(TargetPurpose::Application)
        })
        .ok_or(ProtocolError::StaleScope)?;
    if !main.resumed {
        return Err(ProtocolError::ScopeUnavailable.into());
    }
    let mut sessions = HashSet::new();
    let mut trees = Vec::new();
    for target in &targets {
        if target.purpose != Some(TargetPurpose::Application) {
            // State-bootstrap targets have independent ownership and cannot
            // establish application frame ancestry.
            continue;
        }
        if !target.configured || !target.resumed {
            return Err(ProtocolError::ScopeUnavailable.into());
        }
        if !sessions.insert(target.session_id.clone()) {
            return Err(ProtocolError::StaleScope.into());
        }
        if !matches!(target.kind.as_str(), "page" | "iframe") {
            continue;
        }
        let tree = command(
            page,
            operation,
            &target.session_id,
            "Page.getFrameTree",
            json!({}),
        )
        .await?;
        trees.push((target.session_id.clone(), target.kind == "page", tree));
    }
    let lineage = page_lineage(&trees, &page.page_session_id)?;
    let mapping = lineage.iframe_sessions;
    let frames = if readonly_disposal {
        observation::enumerate_semantic_frames(
            &page.client,
            &page.page_session_id,
            &mapping,
            operation,
        )
        .await
    } else {
        observation::enumerate_frames(&page.client, &page.page_session_id, &mapping, operation)
            .await
    }
    .map_err(|error| match cleanup {
        Some(cleanup) => observation_error_with_cleanup(error, cleanup),
        None => observation_error(error),
    })?;
    let root = main_frame(&frames)?;
    if root.binding.session != page.page_session_id {
        return Err(ProtocolError::StaleScope.into());
    }
    let mut ids = HashSet::new();
    for frame in &frames {
        if frame.binding.page_session != page.page_session_id
            || frame.binding.loader.is_empty()
            || !sessions.contains(&frame.binding.session)
            || !ids.insert(frame.binding.frame.clone())
        {
            return Err(ProtocolError::StaleScope.into());
        }
        if let Some(parent) = &frame.parent_frame_id {
            if !frames
                .iter()
                .any(|candidate| &candidate.binding.frame == parent)
            {
                return Err(ProtocolError::StaleScope.into());
            }
        }
    }
    if frames.len() != lineage.parents.len()
        || frames
            .iter()
            .any(|frame| lineage.parents.get(&frame.binding.frame) != Some(&frame.parent_frame_id))
    {
        return Err(ProtocolError::StaleScope.into());
    }
    for (frame, session) in &mapping {
        if !frames.iter().any(|candidate| {
            &candidate.binding.frame == frame
                && &candidate.binding.session == session
                && candidate.parent_frame_id.is_some()
        }) {
            return Err(ProtocolError::UnsupportedCapability.into());
        }
    }
    if let Some(partition) = partition {
        partition
            .check_frame_boundary_async(page, operation, false)
            .await?;
    } else {
        let fence = page.targets.check_acquisition_revision(
            revision,
            inventory_before.as_ref(),
            main,
            screenshot.map_or(
                diagnostic::FrameInventoryPass::Initial,
                ScreenshotFailureWitness::frame_pass,
            ),
            screenshot.is_some(),
        );
        if let Err(error) = fence.result {
            return Err(FrameInventoryFailure::Fence {
                error,
                revision_only: fence.revision_only,
                diagnostic: fence.diagnostic,
            });
        }
    }
    check(page, operation)?;
    Ok(VerifiedFrameInventory {
        frames,
        iframe_sessions: mapping,
    })
}
/// Page roots and renderer roots are different identities. Merge exact native
/// parent edges first, then attribute every renderer root to one owned page.
struct PageLineage {
    iframe_sessions: HashMap<String, String>,
    parents: HashMap<String, Option<String>>,
}
fn page_lineage(
    trees: &[(String, bool, Value)],
    active_session: &str,
) -> Result<PageLineage, ProtocolError> {
    let mut parents: HashMap<String, String> = HashMap::new();
    let mut nodes = HashSet::new();
    let mut pages = HashMap::new();
    let mut renderers = HashMap::new();
    let mut active_root = None;
    let mut visits = 0usize;
    for (session, is_page, tree) in trees {
        let root = tree.get("frameTree").ok_or(ProtocolError::BrowserFailure)?;
        let root_id = root["frame"]["id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or(ProtocolError::BrowserFailure)?;
        if *is_page {
            if pages.insert(root_id.to_owned(), session.clone()).is_some() {
                return Err(ProtocolError::StaleScope);
            }
            if session == active_session {
                active_root = Some(root_id.to_owned());
            }
        } else if renderers
            .insert(root_id.to_owned(), session.clone())
            .is_some()
        {
            return Err(ProtocolError::StaleScope);
        }
        let mut pending = vec![(root, None::<&str>, 0usize)];
        let mut seen = HashSet::new();
        while let Some((node, nested_parent, depth)) = pending.pop() {
            visits += 1;
            if visits > 100_000 || depth > 256 {
                return Err(ProtocolError::UnsupportedCapability);
            }
            let id = node["frame"]["id"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or(ProtocolError::BrowserFailure)?;
            if !seen.insert(id) {
                return Err(ProtocolError::StaleScope);
            }
            nodes.insert(id.to_owned());
            let explicit = match node["frame"].get("parentId") {
                None => None,
                Some(v) => Some(
                    v.as_str()
                        .filter(|s| !s.is_empty())
                        .ok_or(ProtocolError::BrowserFailure)?,
                ),
            };
            if nested_parent.is_some() && explicit.is_some() && nested_parent != explicit {
                return Err(ProtocolError::StaleScope);
            }
            if let Some(parent) = nested_parent.or(explicit) {
                if parent == id
                    || parents
                        .insert(id.to_owned(), parent.to_owned())
                        .is_some_and(|old| old != parent)
                {
                    return Err(ProtocolError::StaleScope);
                }
            }
            if let Some(children) = node.get("childFrames") {
                for child in children.as_array().ok_or(ProtocolError::BrowserFailure)? {
                    pending.push((child, Some(id), depth + 1));
                }
            }
        }
    }
    let active_root = active_root.ok_or(ProtocolError::StaleScope)?;
    if pages
        .keys()
        .any(|id| parents.contains_key(id) || renderers.contains_key(id))
    {
        return Err(ProtocolError::StaleScope);
    }
    let mut owners = HashMap::new();
    for id in &nodes {
        let mut current = id;
        let mut seen = HashSet::new();
        loop {
            if !seen.insert(current) || seen.len() > 256 {
                return Err(ProtocolError::StaleScope);
            }
            if pages.contains_key(current) {
                owners.insert(id.clone(), current.clone());
                break;
            }
            current = parents
                .get(current)
                .filter(|parent| nodes.contains(*parent))
                .ok_or(ProtocolError::StaleScope)?;
        }
    }
    Ok(PageLineage {
        iframe_sessions: renderers
            .into_iter()
            .filter(|(id, _)| owners.get(id) == Some(&active_root))
            .collect(),
        parents: nodes
            .into_iter()
            .filter(|id| owners.get(id) == Some(&active_root))
            .map(|id| {
                let parent = parents.get(&id).cloned();
                (id, parent)
            })
            .collect(),
    })
}
fn main_frame(frames: &[ObservationFrame]) -> Result<&ObservationFrame, ProtocolError> {
    let mut roots = frames
        .iter()
        .filter(|frame| frame.parent_frame_id.is_none());
    let root = roots.next().ok_or(ProtocolError::BrowserFailure)?;
    if roots.next().is_some() {
        return Err(ProtocolError::BrowserFailure);
    }
    Ok(root)
}
fn same_frames(
    before: &[ObservationFrame],
    after: &[ObservationFrame],
) -> Result<(), ProtocolError> {
    if before.len() != after.len()
        || before.iter().any(|a| {
            !after.iter().any(|b| {
                a.binding.page_session == b.binding.page_session
                    && a.binding.session == b.binding.session
                    && a.binding.frame == b.binding.frame
                    && a.binding.loader == b.binding.loader
                    && a.parent_frame_id == b.parent_frame_id
                    && a.owner_backend_id == b.owner_backend_id
                    // Location is projected from this transaction too. A
                    // same-document navigation need not change its loader.
                    && a.url == b.url
            })
        })
    {
        return Err(ProtocolError::StaleScope);
    }
    Ok(())
}
fn exact_root(
    mut roots: Vec<SemanticNode>,
    refs: &RefMap,
    frames: &[ObservationFrame],
) -> Result<SemanticNode, ProtocolError> {
    if roots.len() != 1 {
        return Err(ProtocolError::BrowserFailure);
    }
    let root = roots.remove(0);
    let main = main_frame(frames)?;
    let entry = parse_ref(&root.reference.id)
        .and_then(|id| refs.get(&id))
        .ok_or(ProtocolError::StaleReference)?;
    let binding = entry
        .exact_binding
        .as_ref()
        .ok_or(ProtocolError::StaleReference)?;
    if root.role.as_deref() != Some("document")
        || entry.backend_node_id.is_none()
        || binding.page_session != main.binding.page_session
        || binding.session != main.binding.session
        || binding.frame != main.binding.frame
        || binding.loader != main.binding.loader
    {
        return Err(ProtocolError::StaleReference);
    }
    Ok(root)
}
async fn verify_document_root(
    page: &BrowserExecutionLease,
    root: &SemanticNode,
    refs: &RefMap,
    operation: &OperationLease,
) -> Result<(), ProtocolError> {
    let backend = parse_ref(&root.reference.id)
        .and_then(|id| refs.get(&id))
        .and_then(|entry| entry.backend_node_id)
        .ok_or(ProtocolError::StaleReference)?;
    let value = command(
        page,
        operation,
        &page.page_session_id,
        "DOM.getDocument",
        json!({"depth":0,"pierce":false}),
    )
    .await?;
    if value["root"]["nodeType"].as_i64() != Some(9)
        || value["root"]["backendNodeId"].as_i64() != Some(backend)
    {
        return Err(ProtocolError::StaleReference);
    }
    Ok(())
}
async fn minimal_document(
    page: &BrowserExecutionLease,
    frames: &[ObservationFrame],
    refs: &mut RefMap,
    operation: &OperationLease,
) -> Result<observation::NodeReference, ProtocolError> {
    let main = main_frame(frames)?;
    let value = command(
        page,
        operation,
        &main.binding.session,
        "DOM.getDocument",
        json!({"depth":0,"pierce":false}),
    )
    .await?;
    let document = &value["root"];
    if document["nodeType"].as_i64() != Some(9) {
        return Err(ProtocolError::BrowserFailure);
    }
    let backend = document["backendNodeId"]
        .as_i64()
        .filter(|id| *id > 0)
        .ok_or(ProtocolError::BrowserFailure)?;
    let reference = refs
        .try_bind_exact(backend, "document", "", main.binding.clone())
        .map_err(|_| ProtocolError::IdentifierExhausted)?;
    Ok(observation::NodeReference {
        id: format!("@{reference}"),
        revision: refs
            .get(&reference)
            .and_then(|entry| entry.issued_revision())
            .ok_or(ProtocolError::StaleReference)?
            .to_string(),
    })
}
async fn viewport(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
) -> Result<Value, ProtocolError> {
    let metrics = command(
        page,
        operation,
        &page.page_session_id,
        "Page.getLayoutMetrics",
        json!({}),
    )
    .await?;
    let viewport = &metrics["cssVisualViewport"];
    let width = viewport["clientWidth"]
        .as_f64()
        .filter(|n| n.is_finite() && *n > 0.0)
        .ok_or(ProtocolError::BrowserFailure)?;
    let height = viewport["clientHeight"]
        .as_f64()
        .filter(|n| n.is_finite() && *n > 0.0)
        .ok_or(ProtocolError::BrowserFailure)?;
    Ok(json!({"width":width,"height":height}))
}
fn optional_observe_lease(operation: &OperationLease) -> OperationLease {
    optional_observe_lease_at(operation, Instant::now())
}
fn optional_observe_lease_at(operation: &OperationLease, now: Instant) -> OperationLease {
    let remaining = operation.deadline.saturating_duration_since(now);
    // Cleanup is independently retained. The locked Tokio timer rounds the
    // deadline up to a millisecond, then parks for an integer tick difference
    // from floor(now): together these can consume nearly two milliseconds.
    // Keep a separate millisecond for publication and receiver scheduling.
    // This is bounded local headroom, not the strict-fallback cleanup reserve
    // and not a guarantee against arbitrary scheduler stalls. At <=3ms the
    // optional lease is already expired, so its first check cannot admit work.
    let timer_rounding = Duration::from_millis(2);
    let publication = Duration::from_millis(1);
    OperationLease {
        is_callback: operation.is_callback,
        generation: operation.generation,
        sequence: operation.sequence,
        deadline: operation.deadline - remaining.min(timer_rounding + publication),
        cancellation: operation.cancellation.clone(),
    }
}
fn pixel_lease(operation: &OperationLease) -> OperationLease {
    let remaining = operation.deadline.saturating_duration_since(Instant::now());
    let reserve = (remaining / 5).min(Duration::from_millis(500));
    OperationLease {
        is_callback: operation.is_callback,
        generation: operation.generation,
        sequence: operation.sequence,
        deadline: operation.deadline - reserve,
        cancellation: operation.cancellation.clone(),
    }
}
fn semantic_lease(operation: &OperationLease, fallback: bool) -> OperationLease {
    semantic_lease_at(operation, fallback, Instant::now())
}
fn semantic_lease_at(operation: &OperationLease, fallback: bool, now: Instant) -> OperationLease {
    let remaining = operation.deadline.saturating_duration_since(now);
    let reserve = if fallback {
        // Preserve the original reader budget: reserve one quarter, capped at
        // two seconds, for a fresh masked capture after semantic timeout.
        (remaining / 4).min(Duration::from_secs(2))
    } else {
        Duration::ZERO
    };
    OperationLease {
        is_callback: operation.is_callback,
        generation: operation.generation,
        sequence: operation.sequence,
        deadline: operation.deadline - reserve,
        cancellation: operation.cancellation.clone(),
    }
}
fn observation_error_with_cleanup(error: ObservationError, cleanup: &AtomicBool) -> ProtocolError {
    match error {
        ObservationError::CleanupFailed { primary } => {
            cleanup.store(true, Ordering::SeqCst);
            primary
                .map(|error| observation_error_with_cleanup(*error, cleanup))
                .unwrap_or(ProtocolError::CleanupFailed)
        }
        error => observation_error(error),
    }
}
fn observation_error(error: ObservationError) -> ProtocolError {
    match error {
        ObservationError::ResourceLimit => ProtocolError::CapacityExceeded,
        ObservationError::CleanupFailed { .. } => ProtocolError::CleanupFailed,
        ObservationError::InvalidArguments => ProtocolError::InvalidArguments,
        ObservationError::InvalidLocator => ProtocolError::InvalidLocator,
        ObservationError::FrameNotFound(index) => ProtocolError::FrameNotFound(index),
        ObservationError::FrameAmbiguous(facts) => ProtocolError::FrameAmbiguous(facts),
        ObservationError::UnsupportedCapability => ProtocolError::UnsupportedCapability,
        ObservationError::StaleReference | ObservationError::Superseded => {
            ProtocolError::StaleReference
        }
        ObservationError::Cancelled => ProtocolError::Cancelled,
        ObservationError::DeadlineExceeded => ProtocolError::DeadlineExceeded,
        ObservationError::BackendFailure => ProtocolError::BrowserFailure,
        ObservationError::PolicyDenied => ProtocolError::PolicyDenied,
    }
}
fn protected_error(error: ProtectedReadReason) -> ProtocolError {
    match error {
        ProtectedReadReason::Cancelled => ProtocolError::Cancelled,
        ProtectedReadReason::Deadline => ProtocolError::DeadlineExceeded,
        ProtectedReadReason::StaleScope => ProtocolError::StaleScope,
        ProtectedReadReason::Superseded => ProtocolError::StaleReference,
        ProtectedReadReason::CleanupFailed => ProtocolError::CleanupFailed,
        ProtectedReadReason::IncompleteInventory => ProtocolError::ScopeUnavailable,
        ProtectedReadReason::BrowserFailure => ProtocolError::BrowserFailure,
    }
}
fn observation_read_failure(error: &ObservationError) -> (diagnostic::ReadError, bool) {
    use diagnostic::ObservationReadError as Kind;
    let kind = match error {
        ObservationError::InvalidArguments => Kind::InvalidArguments,
        ObservationError::InvalidLocator => Kind::InvalidLocator,
        ObservationError::FrameNotFound(_) => Kind::FrameNotFound,
        ObservationError::FrameAmbiguous(_) => Kind::FrameAmbiguous,
        ObservationError::UnsupportedCapability => Kind::UnsupportedCapability,
        ObservationError::StaleReference => Kind::StaleReference,
        ObservationError::Superseded => Kind::Superseded,
        ObservationError::Cancelled => Kind::Cancelled,
        ObservationError::DeadlineExceeded => Kind::DeadlineExceeded,
        ObservationError::BackendFailure => Kind::BackendFailure,
        ObservationError::PolicyDenied => Kind::PolicyDenied,
        ObservationError::ResourceLimit => Kind::ResourceLimit,
        ObservationError::CleanupFailed { primary } => {
            return (
                primary
                    .as_ref()
                    .map(|error| observation_read_failure(error).0)
                    .unwrap_or(diagnostic::ReadError::Observation(Kind::CleanupFailed)),
                true,
            );
        }
    };
    (diagnostic::ReadError::Observation(kind), false)
}
fn geometry_read_failure(
    error: &super::client_geometry::GeometryError,
) -> (diagnostic::ReadError, bool) {
    use super::client_geometry::GeometryError as Error;
    use diagnostic::GeometryReadError as Kind;
    let kind = match error {
        Error::InvalidGeometry => Kind::InvalidGeometry,
        Error::IncompleteInventory => Kind::IncompleteInventory,
        Error::StaleIdentity => Kind::StaleIdentity,
        Error::Cancelled => Kind::Cancelled,
        Error::Superseded => Kind::Superseded,
        Error::DeadlineExceeded => Kind::DeadlineExceeded,
        Error::BackendFailure => Kind::BackendFailure,
        Error::CleanupFailed { primary } => {
            return (
                primary
                    .as_ref()
                    .map(|error| geometry_read_failure(error).0)
                    .unwrap_or(diagnostic::ReadError::Geometry(Kind::CleanupFailed)),
                true,
            );
        }
    };
    (diagnostic::ReadError::Geometry(kind), false)
}
fn geometry_error_with_cleanup(
    error: super::client_geometry::GeometryError,
    cleanup: &AtomicBool,
) -> ProtocolError {
    match error {
        super::client_geometry::GeometryError::CleanupFailed { primary } => {
            cleanup.store(true, Ordering::SeqCst);
            primary
                .map(|error| geometry_error_with_cleanup(*error, cleanup))
                .unwrap_or(ProtocolError::CleanupFailed)
        }
        error => geometry_error(error),
    }
}
fn geometry_error(error: super::client_geometry::GeometryError) -> ProtocolError {
    capture_error(client_capture::geometry_reason(error))
}
fn capture_error(error: CaptureReason) -> ProtocolError {
    match error {
        CaptureReason::CleanupFailed => ProtocolError::CleanupFailed,
        CaptureReason::Cancelled => ProtocolError::Cancelled,
        CaptureReason::Deadline => ProtocolError::DeadlineExceeded,
        CaptureReason::StaleScope => ProtocolError::StaleScope,
        CaptureReason::Superseded => ProtocolError::StaleReference,
        CaptureReason::BrowserFailure => ProtocolError::BrowserFailure,
        CaptureReason::BoundsExceeded => ProtocolError::CapacityExceeded,
        CaptureReason::IncompleteFrames
        | CaptureReason::UnsafeGeometry
        | CaptureReason::UninspectableContent
        | CaptureReason::MaskingUnproven => ProtocolError::PolicyDenied,
    }
}

#[cfg(test)]
mod tests {
    use super::super::element::ExactBinding;
    use super::*;
    #[test]
    fn only_live_callback_fields_can_read_over_unchanged_unrelated_input_debt() {
        use super::super::client_debt::{AdmissionClass, OperationKey, OwnerDebtLedger};
        use super::super::client_session::{ClientSession, DecisionKind, DecisionOwner};
        let broker = Arc::new(ClientSession::new());
        let parent = broker.admit(1, 1, 5000).unwrap();
        assert!(broker.start(1, 1).unwrap());
        let decision = broker
            .decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Authentication,
                5000,
                None,
                Some("scope".into()),
            )
            .unwrap();
        let mut callback = broker
            .admit_callback(1, 2, 5000, Some(&decision.token))
            .unwrap();
        assert!(broker.start(1, 2).unwrap());
        let ledger = OwnerDebtLedger::new(1, "scope".into());
        let journal = ledger
            .operation(
                OperationKey {
                    generation: 1,
                    operation_seq: 1,
                },
                "target".into(),
                "page".into(),
            )
            .unwrap();
        let _retained = ledger
            .reserve_command(
                Some(&journal),
                "Input.dispatchMouseEvent",
                Some(&json!({"type":"mousePressed"})),
                Some("page"),
            )
            .unwrap()
            .submit()
            .unwrap();
        let request = FieldReadRequest {
            broker,
            fields: vec![observation::ReadField::Text],
            options: serde_json::from_value(
                json!({"expression":{"kind":"selector","selector":"button"}}),
            )
            .unwrap(),
        };
        assert_eq!(ledger.snapshot().input_debt, 1);
        assert_eq!(
            ledger.check_admission(AdmissionClass::Reference),
            Err(ProtocolError::ScopeUnavailable)
        );
        assert_eq!(
            request.check_admission(&parent, "scope", &ledger),
            Err(ProtocolError::ScopeUnavailable)
        );
        assert_eq!(request.check_admission(&callback, "scope", &ledger), Ok(()));
        assert_eq!(ledger.snapshot().input_debt, 1);
        assert_eq!(
            ledger.check_admission(AdmissionClass::Input),
            Err(ProtocolError::ScopeUnavailable)
        );
        let foreign = OwnerDebtLedger::new(1, "foreign".into());
        assert_eq!(
            request.check_admission(&callback, "scope", &foreign),
            Err(ProtocolError::StaleScope)
        );
        callback.is_callback = false;
        assert_eq!(
            request.check_admission(&callback, "scope", &ledger),
            Err(ProtocolError::InvalidSequence)
        );
        assert_eq!(ledger.snapshot().input_debt, 1);
        callback.is_callback = true;
        ledger.connection_lost();
        assert_eq!(
            request.check_admission(&callback, "scope", &ledger),
            Err(ProtocolError::ScopeUnavailable)
        );
        assert_eq!(ledger.snapshot().input_debt, 1);
    }
    #[test]
    fn frame_failures_preserve_typed_facts_but_never_downgrade_cleanup_uncertainty() {
        use super::super::client_protocol::{Effects, FrameAmbiguity, FrameSelectionIndex};
        for observation in [
            ObservationError::FrameNotFound(FrameSelectionIndex::new(1).unwrap()),
            ObservationError::FrameAmbiguous(FrameAmbiguity::new(2, 2).unwrap()),
        ] {
            for dirty_dispatch in [false, true] {
                for dirty_join in [false, true] {
                    let cleanup = AtomicBool::new(false);
                    let code = observation_error_with_cleanup(
                        if dirty_dispatch {
                            ObservationError::CleanupFailed {
                                primary: Some(Box::new(observation.clone())),
                            }
                        } else {
                            observation.clone()
                        },
                        &cleanup,
                    );
                    assert_eq!(code, observation_error(observation.clone()));
                    assert_eq!(cleanup.load(Ordering::SeqCst), dirty_dispatch);
                    let failure = |error, cleanup_integrity_lost| DispatchFailure {
                        error,
                        identity_scope: "scope".into(),
                        cleanup_integrity_lost,
                    };
                    let (outcome, dirty) =
                        super::super::client_browser::settle_observation_dispatch(
                            Ok(Err(failure(code.clone(), dirty_dispatch))),
                            Ok(if dirty_join {
                                Err(failure(ProtocolError::CleanupFailed, true))
                            } else {
                                Ok(())
                            }),
                        );
                    assert_eq!(outcome.result, Err(code));
                    assert_eq!(dirty, dirty_dispatch || dirty_join);
                    assert_eq!(
                        outcome.effects,
                        if dirty {
                            Effects::Unknown
                        } else {
                            Effects::NotDispatched
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn observation_cleanup_preserves_primary_without_authorizing_fallback() {
        let cleanup = AtomicBool::new(false);
        let error = observation_error_with_cleanup(
            ObservationError::CleanupFailed {
                primary: Some(Box::new(ObservationError::DeadlineExceeded)),
            },
            &cleanup,
        );
        assert_eq!(error, ProtocolError::DeadlineExceeded);
        assert!(cleanup.load(Ordering::SeqCst));
        // Fallback matches the original observation variant, never this mapped error.
        assert_eq!(
            observation_error(ObservationError::ResourceLimit),
            ProtocolError::CapacityExceeded
        );
        assert_eq!(
            observation_error(ObservationError::CleanupFailed { primary: None }),
            ProtocolError::CleanupFailed
        );
    }
    fn lineage_tree(id: &str, parent: Option<&str>, children: Vec<Value>) -> Value {
        let mut frame = json!({"id":id});
        if let Some(parent) = parent {
            frame["parentId"] = json!(parent);
        }
        json!({"frameTree":{"frame":frame,"childFrames":children}})
    }
    #[test]
    fn page_lineage_excludes_only_proven_other_tab_renderers() {
        let child = |id| json!({"frame":{"id":id}});
        let trees = vec![
            (
                "page-a".into(),
                true,
                lineage_tree("a", None, vec![child("remote-a")]),
            ),
            (
                "page-b".into(),
                true,
                lineage_tree("b", None, vec![child("remote-b")]),
            ),
            (
                "session-a".into(),
                false,
                lineage_tree(
                    "remote-a",
                    Some("a"),
                    vec![child("local-a"), child("nested-a")],
                ),
            ),
            (
                "session-nested".into(),
                false,
                lineage_tree("nested-a", Some("remote-a"), vec![]),
            ),
            (
                "session-b".into(),
                false,
                lineage_tree("remote-b", Some("b"), vec![]),
            ),
        ];
        let result = page_lineage(&trees, "page-a").unwrap();
        assert_eq!(result.iframe_sessions.len(), 2);
        assert_eq!(result.iframe_sessions.get("remote-a").unwrap(), "session-a");
        assert_eq!(
            result.iframe_sessions.get("nested-a").unwrap(),
            "session-nested"
        );
        assert_eq!(result.parents.len(), 4);
        assert_eq!(
            result.parents.get("local-a"),
            Some(&Some("remote-a".into()))
        );
        assert!(!result.parents.contains_key("b"));
    }
    #[test]
    fn page_lineage_rejects_ambiguous_foreign_and_incomplete_edges() {
        let page = ("page".into(), true, lineage_tree("root", None, vec![]));
        for bad in [
            lineage_tree("child", None, vec![]),
            lineage_tree("child", Some("foreign"), vec![]),
            lineage_tree("child", Some("child"), vec![]),
            lineage_tree("root", None, vec![]),
        ] {
            assert!(page_lineage(&[page.clone(), ("remote".into(), false, bad)], "page").is_err());
        }
        let conflicting = vec![
            (
                "page".into(),
                true,
                lineage_tree("root", None, vec![json!({"frame":{"id":"child"}})]),
            ),
            (
                "other".into(),
                true,
                lineage_tree("other-root", None, vec![]),
            ),
            (
                "remote".into(),
                false,
                lineage_tree("child", Some("other-root"), vec![]),
            ),
        ];
        assert!(page_lineage(&conflicting, "page").is_err());
    }
    #[test]
    fn page_lineage_requires_unique_root_sessions_and_valid_tree_shape() {
        let duplicate = vec![
            ("page".into(), true, lineage_tree("root", None, vec![])),
            ("other".into(), true, lineage_tree("root", None, vec![])),
        ];
        assert!(page_lineage(&duplicate, "page").is_err());
        let malformed = vec![(
            "page".into(),
            true,
            json!({"frameTree":{"frame":{"id":"root"},"childFrames":null}}),
        )];
        assert!(page_lineage(&malformed, "page").is_err());
    }
    fn frame(id: &str, parent: Option<&str>) -> ObservationFrame {
        ObservationFrame {
            parent_frame_id: parent.map(str::to_owned),
            owner_backend_id: parent.map(|_| 2),
            url: "https://fixture.invalid/".into(),
            binding: ExactBinding {
                page_session: "page-session".into(),
                session: "page-session".into(),
                frame: id.into(),
                loader: "loader".into(),
                actionable: false,
            },
            offset_x: 0.0,
            offset_y: 0.0,
            frame_path: Vec::new(),
        }
    }
    #[test]
    fn retirement_proof_requires_loss_of_an_existing_exact_document() {
        let old = vec![frame("main", None), frame("child", Some("main"))];
        let mut current = old.clone();
        current[0].offset_x = 100.0;
        current[0].url.push_str("#same-document");
        assert!(!retired_document(&old, &current));
        current.push(frame("new-child", Some("main")));
        assert!(!retired_document(&old, &current));
        current[1].binding.loader = "replacement-loader".into();
        assert!(retired_document(&old, &current));
        assert!(retired_document(&old, &old[..1]));
        let mut replacement = old.clone();
        replacement[0].binding.session = "replacement-session".into();
        assert!(retired_document(&old, &replacement));
        assert!(!retired_document(&[], &old));
    }
    fn operation() -> OperationLease {
        let (_send, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 7,
            deadline: Instant::now() + Duration::from_secs(8),
            cancellation,
        }
    }
    fn diagnostic_trace() -> DispatchRequest {
        DispatchRequest::Screenshot(ScreenshotRequest {
            secure_field_selector: "input[type=password]".into(),
            purpose: ScreenshotPurpose::Trace,
        })
    }
    #[test]
    fn screenshot_witness_is_disabled_for_opt_out_nontrace_and_success() {
        let op = operation();
        assert!(ScreenshotFailureWitness::new(&diagnostic_trace(), &op, false).is_none());
        let pixels = DispatchRequest::Screenshot(ScreenshotRequest {
            secure_field_selector: "input[type=password]".into(),
            purpose: ScreenshotPurpose::PixelsOnly,
        });
        assert!(ScreenshotFailureWitness::new(&pixels, &op, true).is_none());
        let observe = DispatchRequest::Observe(ObserveRequest {
            options: ObserveFlags::default(),
            test_id_attribute: "data-testid".into(),
            secure_field_selector: "input[type=password]".into(),
        });
        assert!(ScreenshotFailureWitness::new(&observe, &op, false).is_none());
        assert!(ScreenshotFailureWitness::new(&observe, &op, true).is_some());
        let witness = ScreenshotFailureWitness::new(&diagnostic_trace(), &op, true).unwrap();
        assert!(witness
            .take_failure(|| panic!("success must not sample inventory"))
            .is_none());
    }
    #[test]
    fn optional_pixel_witness_is_opt_in_and_keeps_pre_capture_refusal_before_cleanup() {
        let request = DispatchRequest::Observe(ObserveRequest {
            options: ObserveFlags {
                pixels: true,
                ..ObserveFlags::default()
            },
            test_id_attribute: "data-testid".into(),
            secure_field_selector: "input[type=password]".into(),
        });
        let operation = operation();
        assert!(ScreenshotFailureWitness::new(&request, &operation, false).is_none());
        let witness = ScreenshotFailureWitness::new(&request, &operation, true).unwrap();
        witness.enter(ScreenshotStage::Geometry);
        witness.failure(&ProtocolError::DeadlineExceeded);
        witness.enter(ScreenshotStage::Restoration);
        witness.failure(&ProtocolError::CleanupFailed);
        let failure = witness
            .take_failure(|| panic!("no inventory read for absent baseline"))
            .unwrap();
        assert_eq!(failure.stage, ScreenshotStage::Geometry);
        assert_eq!(failure.capture_phase, ScreenshotCapturePhase::NotEntered);
        assert_eq!(failure.error, ProtocolError::DeadlineExceeded);
        assert!(witness
            .take_failure(|| panic!("only one refusal"))
            .is_none());
    }

    #[test]
    fn semantic_read_failure_keeps_typed_primary_and_cleanup_wrapper() {
        use super::super::client_geometry::GeometryError as Geometry;
        use super::diagnostic::{
            GeometryReadError as G, ObservationReadError as O, ReadError as R,
        };
        for (error, kind) in [
            (ObservationError::StaleReference, O::StaleReference),
            (ObservationError::Superseded, O::Superseded),
            (ObservationError::Cancelled, O::Cancelled),
            (ObservationError::DeadlineExceeded, O::DeadlineExceeded),
            (ObservationError::BackendFailure, O::BackendFailure),
            (
                ObservationError::FrameNotFound(
                    super::super::client_protocol::FrameSelectionIndex::new(0).unwrap(),
                ),
                O::FrameNotFound,
            ),
            (
                ObservationError::FrameAmbiguous(
                    super::super::client_protocol::FrameAmbiguity::new(0, 2).unwrap(),
                ),
                O::FrameAmbiguous,
            ),
        ] {
            assert_eq!(
                observation_read_failure(&error),
                (R::Observation(kind), false)
            );
            assert_eq!(
                observation_read_failure(&ObservationError::CleanupFailed {
                    primary: Some(Box::new(error))
                }),
                (R::Observation(kind), true)
            );
        }
        for (error, kind) in [
            (Geometry::StaleIdentity, G::StaleIdentity),
            (Geometry::InvalidGeometry, G::InvalidGeometry),
            (Geometry::IncompleteInventory, G::IncompleteInventory),
            (Geometry::Superseded, G::Superseded),
            (Geometry::Cancelled, G::Cancelled),
            (Geometry::DeadlineExceeded, G::DeadlineExceeded),
            (Geometry::BackendFailure, G::BackendFailure),
        ] {
            assert_eq!(geometry_read_failure(&error), (R::Geometry(kind), false));
            assert_eq!(
                geometry_read_failure(&Geometry::CleanupFailed {
                    primary: Some(Box::new(Geometry::CleanupFailed {
                        primary: Some(Box::new(error))
                    }))
                }),
                (R::Geometry(kind), true)
            );
        }
        assert_eq!(
            geometry_read_failure(&Geometry::CleanupFailed { primary: None }),
            (R::Geometry(G::CleanupFailed), true)
        );
        assert_eq!(
            observation_read_failure(&ObservationError::CleanupFailed { primary: None }),
            (R::Observation(O::CleanupFailed), true)
        );
    }

    #[test]
    fn semantic_read_witness_keeps_first_stage_and_does_not_invent_typed_scope_failure() {
        let request = DispatchRequest::Observe(ObserveRequest {
            options: ObserveFlags::default(),
            test_id_attribute: "private-test-id".into(),
            secure_field_selector: "private-selector".into(),
        });
        for stage in [
            ScreenshotStage::SemanticMetadata,
            ScreenshotStage::SemanticFrameGeometry,
            ScreenshotStage::SemanticNodeGeometry,
            ScreenshotStage::SemanticDocumentRoot,
            ScreenshotStage::SemanticFinalViewport,
            ScreenshotStage::FinalScope,
        ] {
            let witness = ScreenshotFailureWitness::new(&request, &operation(), true).unwrap();
            witness.enter(stage);
            let detail =
                geometry_read_failure(&super::super::client_geometry::GeometryError::StaleIdentity);
            witness.read_failure(detail, &ProtocolError::StaleScope);
            witness.enter(ScreenshotStage::Restoration);
            witness.read_failure(
                (
                    diagnostic::ReadError::Geometry(diagnostic::GeometryReadError::CleanupFailed),
                    true,
                ),
                &ProtocolError::CleanupFailed,
            );
            let failure = witness
                .take_failure(|| panic!("no new inventory read"))
                .unwrap();
            assert_eq!(failure.stage, stage);
            assert_eq!(failure.error, ProtocolError::StaleScope);
            assert_eq!(failure.read_error, Some(detail.0));
            assert_eq!(failure.read_cleanup_lost, Some(false));
            assert!(witness.take_failure(|| panic!("emit once")).is_none());
        }
        let witness = ScreenshotFailureWitness::new(&request, &operation(), true).unwrap();
        witness.enter(ScreenshotStage::FinalScope);
        witness.failure(&ProtocolError::StaleScope);
        witness.read_failure(
            geometry_read_failure(&super::super::client_geometry::GeometryError::StaleIdentity),
            &ProtocolError::StaleScope,
        );
        let failure = witness.take_failure(|| None).unwrap();
        assert_eq!(failure.stage, ScreenshotStage::FinalScope);
        assert_eq!(failure.read_error, None);
        assert_eq!(failure.read_cleanup_lost, None);
    }

    #[test]
    fn semantic_trace_retains_first_inventory_failure_without_enabling_capture() {
        let trace = DispatchRequest::TraceSemantic(ObserveRequest {
            options: ObserveFlags::default(),
            test_id_attribute: "data-testid".into(),
            secure_field_selector: "input[type=password]".into(),
        });
        assert!(ScreenshotFailureWitness::new(&trace, &operation(), false).is_none());
        let success = ScreenshotFailureWitness::new(&trace, &operation(), true).unwrap();
        assert!(success
            .take_failure(|| panic!("success must not sample inventory"))
            .is_none());
        let witness = ScreenshotFailureWitness::new(&trace, &operation(), true).unwrap();
        witness.enter(ScreenshotStage::InitialFrames);
        witness.failure(&ProtocolError::ScopeUnavailable);
        witness.enter(ScreenshotStage::Restoration);
        witness.failure(&ProtocolError::CleanupFailed);
        let failure = witness
            .take_failure(|| panic!("no initial revision must not sample inventory"))
            .unwrap();
        assert_eq!(failure.stage, ScreenshotStage::InitialFrames);
        assert_eq!(failure.capture_phase, ScreenshotCapturePhase::NotEntered);
        assert_eq!(failure.error, ProtocolError::ScopeUnavailable);
        assert_eq!(
            failure.inventory_after_failure,
            InventoryAfterFailure::NotSampled
        );
        assert!(witness.take_failure(|| panic!("emit once")).is_none());
    }
    #[test]
    fn screenshot_capture_first_failure_survives_cleanup_and_is_consumed_once() {
        let witness =
            ScreenshotFailureWitness::new(&diagnostic_trace(), &operation(), true).unwrap();
        witness.capture_failure(CaptureAttemptFailure {
            phase: CapturePhase::PostCaptureValidation,
            reason: CaptureReason::StaleScope,
        });
        witness.enter(ScreenshotStage::Restoration);
        witness.failure(&ProtocolError::CleanupFailed);
        let result = witness
            .take_failure(|| panic!("no baseline must not sample inventory"))
            .unwrap();
        assert_eq!(result.stage, ScreenshotStage::Capture);
        assert_eq!(
            result.capture_phase,
            ScreenshotCapturePhase::PostCaptureValidation
        );
        assert_eq!(result.error, ProtocolError::StaleScope);
        assert_eq!(
            result.inventory_after_failure,
            InventoryAfterFailure::NotSampled
        );
        assert!(witness
            .take_failure(|| panic!("must emit only once"))
            .is_none());
    }
    #[tokio::test]
    async fn screenshot_production_witness_observes_real_prepare_and_restore_failure_paths() {
        use super::super::cdp::client::CdpClient;
        use super::super::client_browser::ExecutionGate;
        use super::super::client_targets::ClientTargets;
        use futures_util::{SinkExt, StreamExt};
        for fail_restore in [false, true] {
            let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let targets = ClientTargets::new("context".into(), "scope".into());
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
            let peer_targets = targets.clone();
            let restored = Arc::new(AtomicBool::new(false));
            let peer_restored = restored.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("ws://{}", listener.local_addr().unwrap());
            let peer = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                while let Some(Ok(message)) = socket.next().await {
                    let Ok(text) = message.to_text() else {
                        continue;
                    };
                    let request: Value = serde_json::from_str(text).unwrap();
                    let result = match request["method"].as_str().unwrap() {
                        "Page.getFrameTree" => {
                            json!({"frameTree":{"frame":{"id":"frame","loaderId":"loader","url":"https://fixture.invalid/"}}})
                        }
                        "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                        "Animation.getPlaybackRate" => json!({"playbackRate":1}),
                        "Animation.enable" | "Animation.setPlaybackRate" => json!({}),
                        method => panic!("unexpected screenshot diagnostic command: {method}"),
                    };
                    assert_ne!(request["method"], "Page.captureScreenshot");
                    let mut response = json!({"id":request["id"],"sessionId":request["sessionId"],"result":result});
                    if request["method"] == "Animation.setPlaybackRate" {
                        if request["params"]["playbackRate"].as_f64() == Some(0.0) {
                            peer_targets.invalidate_inventory().unwrap();
                        } else {
                            peer_restored.store(true, Ordering::SeqCst);
                            if fail_restore {
                                response.as_object_mut().unwrap().remove("result");
                                response["error"] =
                                    json!({"code":-32000,"message":"private restore error"});
                            }
                        }
                    }
                    if socket
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            response.to_string(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
            let gate = Arc::new(ExecutionGate::default());
            let blobs = Arc::new(BlobStore::new(Default::default()).unwrap());
            let scope = BlobScope {
                generation: 1,
                identity_scope: "scope".into(),
            };
            blobs.activate_scope(scope.clone()).unwrap();
            let context = || DispatchContext {
                query_authority: None,
                #[cfg(feature = "acceptance-faults")]
                faults: Arc::new(super::super::client_test_faults::FaultController::default()),
                attachment: targets.owned_target("target").unwrap(),
                page: BrowserExecutionLease {
                    client: client.clone(),
                    page_session_id: "session".into(),
                    target_id: "target".into(),
                    identity_scope: "scope".into(),
                    permit: gate.enter(false).unwrap(),
                    targets: targets.clone(),
                },
                ui: Arc::new(UiGate::default()),
                blobs: blobs.clone(),
                scope: scope.clone(),
                policy: ReadPolicy {
                    frame_policy: Default::default(),
                    test_id_attribute: "data-testid".into(),
                    secure_field_selector: "input[type=password]".into(),
                },
            };
            let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
            let mut op = operation();
            op.cancellation = cancellation.clone();
            let witness = ScreenshotFailureWitness::new(&diagnostic_trace(), &op, true).unwrap();
            let mut wrong = context();
            wrong.scope.generation = 2;
            let error = dispatch
                .prepare_inner(wrong, diagnostic_trace(), op, Some(&witness))
                .err()
                .unwrap();
            witness.failure(&error);
            let fact = witness
                .take_failure(|| panic!("prepare does not read inventory"))
                .unwrap();
            assert_eq!(fact.error, ProtocolError::StaleScope);
            assert_eq!(fact.stage, ScreenshotStage::PrepareScope);
            let mut op = operation();
            op.cancellation = cancellation.clone();
            let witness = ScreenshotFailureWitness::new(&diagnostic_trace(), &op, true).unwrap();
            let prepared = dispatch
                .prepare_inner(context(), diagnostic_trace(), op, Some(&witness))
                .unwrap();
            let mut result_send = None;
            let receipt = ObservationResultReceipt::default();
            let result = dispatch
                .run(
                    prepared.context,
                    prepared.request,
                    prepared.operation,
                    prepared.capture,
                    prepared.trace,
                    prepared.retirement_fence,
                    Some(&witness),
                    &mut result_send,
                    &receipt,
                )
                .await;
            let error = result.err().unwrap();
            assert_eq!(error.error, ProtocolError::StaleScope);
            assert_eq!(error.cleanup_integrity_lost, fail_restore);
            assert!(restored.load(Ordering::SeqCst));
            let fact = witness
                .take_failure(|| targets.inventory().ok().map(|(revision, _)| revision))
                .unwrap();
            assert_eq!(fact.stage, ScreenshotStage::AnimationStabilization);
            assert_eq!(fact.error, ProtocolError::StaleScope);
            assert_eq!(
                fact.inventory_after_failure,
                if fail_restore {
                    InventoryAfterFailure::Unavailable
                } else {
                    InventoryAfterFailure::Changed
                }
            );
            client.close().await;
            peer.abort();
        }
    }
    #[tokio::test]
    async fn abandoned_rpc_keeps_ui_exclusive_until_restore_and_reports_dirty_cleanup() {
        use super::super::cdp::client::CdpClient;
        use super::super::client_browser::ExecutionGate;
        use super::super::client_targets::ClientTargets;
        use futures_util::{SinkExt, StreamExt};
        for fail_restore in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let (restoring_send, restoring_receive) = oneshot::channel();
            let (release_send, release_receive) = oneshot::channel();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut restoring_send = Some(restoring_send);
                let mut release_receive = Some(release_receive);
                while let Some(Ok(message)) = socket.next().await {
                    let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                    let result = match request["method"].as_str().unwrap() {
                        "Page.getFrameTree" => {
                            json!({"frameTree":{"frame":{"id":"frame","loaderId":"loader","url":"https://fixture.invalid/"}}})
                        }
                        "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                        "Animation.getPlaybackRate" => json!({"playbackRate":1}),
                        _ => json!({}),
                    };
                    let mut response = json!({"id":request["id"],"sessionId":request["sessionId"],"result":result});
                    assert_ne!(request["method"], "Page.setWebLifecycleState");
                    // Hold the exact saved-rate restoration ACK, not the removed
                    // lifecycle activation command. JSON encodes this f64 as 1.0.
                    if request["method"] == "Animation.setPlaybackRate"
                        && request["params"]["playbackRate"].as_f64() == Some(1.0)
                    {
                        if let Some(send) = restoring_send.take() {
                            let _ = send.send(());
                        }
                        if let Some(release) = release_receive.take() {
                            let _ = release.await;
                        }
                        if fail_restore {
                            response.as_object_mut().unwrap().remove("result");
                            response["error"] =
                                json!({"code":-32000,"message":"synthetic restore failure"});
                        }
                    }
                    if socket
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            response.to_string(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let client = Arc::new(CdpClient::connect(&url).await.unwrap());
            let targets = ClientTargets::new("context".into(), "scope".into());
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
            targets.acknowledge_enrollment().unwrap(); // Exact synthetic single-page fixture only.
            let gate = Arc::new(ExecutionGate::default());
            let page = BrowserExecutionLease {
                client,
                page_session_id: "session".into(),
                target_id: "target".into(),
                identity_scope: "scope".into(),
                permit: gate.enter(false).unwrap(),
                targets: targets.clone(),
            };
            let ui = Arc::new(UiGate::default());
            let blobs = Arc::new(BlobStore::new(Default::default()).unwrap());
            let scope = BlobScope {
                generation: 1,
                identity_scope: "scope".into(),
            };
            blobs.activate_scope(scope.clone()).unwrap();
            let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let operation = OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline: Instant::now() + Duration::from_secs(5),
                cancellation: cancellation.clone(),
            };
            let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
            let task = dispatch.start(
                DispatchContext {
                    query_authority: None,
                    #[cfg(feature = "acceptance-faults")]
                    faults: Arc::new(super::super::client_test_faults::FaultController::default()),
                    attachment: page.targets.owned_target(&page.target_id).unwrap(),
                    page,
                    ui: ui.clone(),
                    blobs,
                    scope,
                    policy: ReadPolicy {
                        frame_policy: Default::default(),
                        test_id_attribute: "data-testid".into(),
                        secure_field_selector: "input[type=password]".into(),
                    },
                },
                DispatchRequest::Screenshot(ScreenshotRequest {
                    purpose: ScreenshotPurpose::PixelsOnly,
                    secure_field_selector: "input[type=password]".into(),
                }),
                operation,
            );
            drop(task.result);
            tokio::time::timeout(Duration::from_secs(2), restoring_receive)
                .await
                .unwrap()
                .unwrap();
            assert!(!task.join.is_finished());
            assert!(tokio::time::timeout(
                Duration::from_millis(10),
                ui.enter(
                    false,
                    false,
                    Instant::now() + Duration::from_secs(1),
                    cancellation.clone()
                )
            )
            .await
            .is_err());
            release_send.send(()).unwrap();
            let settled = task.join.await.unwrap();
            if fail_restore {
                assert!(settled.unwrap_err().cleanup_integrity_lost);
                assert!(targets.inventory().is_err());
            } else {
                settled.unwrap();
                assert!(targets.inventory().is_ok());
            }
            ui.enter(
                false,
                false,
                Instant::now() + Duration::from_secs(1),
                cancellation,
            )
            .await
            .unwrap();
            server.abort();
        }
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn semantic_only_timeout_never_mutates_lifecycle_and_fallback_stabilizes_separately() {
        for (pixels, fallback) in [(false, false), (false, true), (true, true)] {
            semantic_timeout_fallback_admission(
                pixels,
                fallback,
                FallbackTestMode::Available,
                false,
            )
            .await;
        }
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn actual_semantic_timeout_requires_admission_before_fallback_capture() {
        semantic_timeout_fallback_admission(false, true, FallbackTestMode::Occupied, false).await;
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn fallback_capture_refusal_releases_admitted_producer_after_restore() {
        semantic_timeout_fallback_admission(false, true, FallbackTestMode::CaptureRefused, false)
            .await;
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn fallback_dirty_restore_releases_admitted_producer_without_publishing() {
        semantic_timeout_fallback_admission(false, true, FallbackTestMode::Available, true).await;
    }
    #[cfg(feature = "acceptance-faults")]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FallbackTestMode {
        Available,
        Occupied,
        CaptureRefused,
        CoverageUnproven,
        CoverageCancelDuringRestore,
        CoverageAuthorityRevokedDuringRestore,
        CoverageObservedCleanupFlag,
        CoverageBrowserFailure,
        PostCapturePolicy,
        SemanticPolicyBranch,
        PolicyGate,
        SemanticCancel,
        CaptureCancel,
        CaptureCancelWithheldAck,
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn fallback_initial_coverage_unproven_preserves_semantic_deadline_after_restore() {
        semantic_timeout_fallback_admission(false, true, FallbackTestMode::CoverageUnproven, false)
            .await;
        // A generic rejected probe remains BrowserFailure, not coverage fallback.
        semantic_timeout_fallback_admission(
            false,
            true,
            FallbackTestMode::CoverageBrowserFailure,
            false,
        )
        .await;
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn fallback_post_capture_policy_failure_survives_clean_restore() {
        semantic_timeout_fallback_admission(
            false,
            true,
            FallbackTestMode::PostCapturePolicy,
            false,
        )
        .await;
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn semantic_policy_and_cancellation_never_admit_fallback() {
        // The typed branch seam is not a natural reader PolicyDenied producer.
        for mode in [
            FallbackTestMode::SemanticPolicyBranch,
            FallbackTestMode::PolicyGate,
            FallbackTestMode::SemanticCancel,
        ] {
            semantic_timeout_fallback_admission(false, true, mode, false).await;
        }
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn fallback_inflight_capture_cancel_waits_for_restoration_without_publishing() {
        for mode in [
            FallbackTestMode::CaptureCancel,
            FallbackTestMode::CaptureCancelWithheldAck,
        ] {
            semantic_timeout_fallback_admission(false, true, mode, false).await;
        }
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn fallback_capture_error_ack_restores_exact_owner_and_preserves_prior_refs() {
        semantic_timeout_fallback_admission_with_refs(
            false,
            true,
            FallbackTestMode::CaptureRefused,
            false,
            true,
        )
        .await;
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn fallback_withheld_raw_ack_retains_masks_and_rejects_late_revival() {
        semantic_timeout_fallback_admission(
            false,
            true,
            FallbackTestMode::CaptureCancelWithheldAck,
            false,
        )
        .await;
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn fallback_dirty_restore_dominates_coverage_policy_and_cancellation() {
        for mode in [
            FallbackTestMode::CoverageUnproven,
            FallbackTestMode::PostCapturePolicy,
            FallbackTestMode::CaptureCancel,
        ] {
            semantic_timeout_fallback_admission(false, true, mode, true).await;
        }
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn semantic_failure_before_optional_pixels_never_creates_restore_debt() {
        // Optional pixels start only after complete safe semantics. Policy and
        // cancellation failures cannot own an animation restoration to fail,
        // even when the caller requested pixels and allowed deadline fallback.
        for pixels in [false, true] {
            for mode in [
                FallbackTestMode::SemanticPolicyBranch,
                FallbackTestMode::PolicyGate,
                FallbackTestMode::SemanticCancel,
            ] {
                semantic_timeout_fallback_admission_with_refs(pixels, true, mode, false, true)
                    .await;
            }
        }
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn fallback_coverage_restore_rechecks_cancellation_and_scope_authority() {
        for mode in [
            FallbackTestMode::CoverageCancelDuringRestore,
            FallbackTestMode::CoverageAuthorityRevokedDuringRestore,
        ] {
            semantic_timeout_fallback_admission(false, true, mode, false).await;
        }
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn fallback_coverage_observed_cleanup_flag_prevents_usable_deadline() {
        // Injected flag propagation, not evidence of a natural cleanup failure.
        semantic_timeout_fallback_admission(
            false,
            true,
            FallbackTestMode::CoverageObservedCleanupFlag,
            false,
        )
        .await;
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn fallback_failure_preserves_committed_refs_without_reviving_lost_authority() {
        for (mode, dirty) in [
            (FallbackTestMode::CoverageUnproven, false),
            (FallbackTestMode::PostCapturePolicy, false),
            (FallbackTestMode::SemanticPolicyBranch, false),
            (FallbackTestMode::PolicyGate, false),
            (FallbackTestMode::SemanticCancel, false),
            (FallbackTestMode::CaptureCancel, false),
            (FallbackTestMode::CaptureCancelWithheldAck, false),
            (FallbackTestMode::CaptureCancel, true),
            (FallbackTestMode::CoverageCancelDuringRestore, false),
            (
                FallbackTestMode::CoverageAuthorityRevokedDuringRestore,
                false,
            ),
            (FallbackTestMode::CoverageObservedCleanupFlag, false),
            (FallbackTestMode::CoverageUnproven, true),
        ] {
            semantic_timeout_fallback_admission_with_refs(false, true, mode, dirty, true).await;
        }
    }
    #[cfg(feature = "acceptance-faults")]
    async fn semantic_timeout_fallback_admission(
        pixels: bool,
        fallback: bool,
        mode: FallbackTestMode,
        dirty_restore: bool,
    ) {
        semantic_timeout_fallback_admission_with_refs(pixels, fallback, mode, dirty_restore, false)
            .await;
    }
    #[cfg(feature = "acceptance-faults")]
    async fn semantic_timeout_fallback_admission_with_refs(
        pixels: bool,
        fallback: bool,
        mode: FallbackTestMode,
        dirty_restore: bool,
        seed_refs: bool,
    ) {
        use super::super::cdp::client::CdpClient;
        use super::super::client_blobs::BlobLimits;
        use super::super::client_browser::ExecutionGate;
        use super::super::client_targets::ClientTargets;
        use super::super::client_test_faults::{FaultController, Phase, State};
        use base64::Engine;
        use futures_util::{SinkExt, StreamExt};
        let coverage_unproven = matches!(
            mode,
            FallbackTestMode::CoverageUnproven
                | FallbackTestMode::CoverageCancelDuringRestore
                | FallbackTestMode::CoverageAuthorityRevokedDuringRestore
                | FallbackTestMode::CoverageObservedCleanupFlag
        );
        let observed_cleanup = mode == FallbackTestMode::CoverageObservedCleanupFlag;
        let capture_cancel = matches!(
            mode,
            FallbackTestMode::CaptureCancel | FallbackTestMode::CaptureCancelWithheldAck
        );
        let capture_unsettled = mode == FallbackTestMode::CaptureCancelWithheldAck;
        let integrity_lost_expected = dirty_restore || observed_cleanup || capture_unsettled;
        let authority_revoked = mode == FallbackTestMode::CoverageAuthorityRevokedDuringRestore;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let lifecycle = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = lifecycle.clone();
        let animation_commands = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let animation_log = animation_commands.clone();
        let source_commands = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let source_log = source_commands.clone();
        let captures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let capture_log = captures.clone();
        let snapshots = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let snapshot_log = snapshots.clone();
        let commands = Arc::new(Mutex::new(Vec::<String>::new()));
        let command_log = commands.clone();
        let hold_restore = dirty_restore
            || coverage_unproven
            || matches!(
                mode,
                FallbackTestMode::CoverageBrowserFailure
                    | FallbackTestMode::PostCapturePolicy
                    | FallbackTestMode::CaptureCancel
                    | FallbackTestMode::CaptureCancelWithheldAck
                    | FallbackTestMode::CaptureRefused
            );
        let (capture_reached, capture_receipt) = oneshot::channel();
        let (restore_reached, mut restore_receipt) = oneshot::channel();
        let (restore_release, restore_release_receipt) = oneshot::channel();
        let (capture_release, capture_release_receipt) = oneshot::channel();
        let (capture_sent, capture_sent_receipt) = oneshot::channel();
        let mut capture_release = Some(capture_release);
        let mut capture_sent_receipt = Some(capture_sent_receipt);
        let blobs = Arc::new(
            BlobStore::new(BlobLimits {
                max_blob_bytes: 4096,
                max_total_bytes: 8192,
                max_handles: 8,
            })
            .unwrap(),
        );
        let scope = BlobScope {
            generation: 1,
            identity_scope: "scope".into(),
        };
        blobs.activate_scope(scope.clone()).unwrap();
        let retained = blobs.insert_sealed(scope.clone(), b"r").unwrap();
        let live_producer = if mode == FallbackTestMode::Occupied {
            Some(blobs.reserve_producer(scope.clone()).unwrap())
        } else {
            None
        };
        if live_producer.is_some() {
            assert!(matches!(
                blobs.reserve_producer(scope.clone()),
                Err(BlobError::QuotaExceeded)
            ));
        }
        let budget_changes = blobs.budget_changes().unwrap();
        let capture_blobs = blobs.clone();
        let capture_scope = scope.clone();
        let mut bytes = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgba8(10, 10)
            .write_to(&mut bytes, image::ImageFormat::Png)
            .unwrap();
        let png = base64::engine::general_purpose::STANDARD.encode(bytes.into_inner());
        let faults = Arc::new(FaultController::default());
        let token = faults.arm("scope", Phase::SemanticAcquire).unwrap();
        let peer_faults = faults.clone();
        let peer_token = token.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut capture_reached = Some(capture_reached);
            let mut restore_reached = Some(restore_reached);
            let mut restore_release_receipt = Some(restore_release_receipt);
            let mut capture_release_receipt = capture_release_receipt;
            let mut capture_sent = Some(capture_sent);
            let mut held_capture = None::<Value>;
            let mut source_verifications = 0;
            loop {
                let message = tokio::select! {
                    message = socket.next() => match message {
                        Some(Ok(message)) => message,
                        _ => break,
                    },
                    release = &mut capture_release_receipt, if held_capture.is_some() => {
                        release.unwrap();
                        let response = held_capture.take().unwrap();
                        socket.send(tokio_tungstenite::tungstenite::Message::Text(response.to_string())).await.unwrap();
                        capture_sent.take().unwrap().send(()).unwrap();
                        continue;
                    },
                };
                let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                command_log
                    .lock()
                    .unwrap()
                    .push(request["method"].as_str().unwrap().to_owned());
                let method = request["method"].as_str().unwrap();
                if method.starts_with("Animation.")
                    || matches!(
                        method,
                        "Page.setWebLifecycleState"
                            | "DOMSnapshot.captureSnapshot"
                            | "Page.captureScreenshot"
                            | "Runtime.evaluate"
                            | "Runtime.callFunctionOn"
                            | "Runtime.releaseObjectGroup"
                    )
                {
                    assert!(
                        fallback
                            && !matches!(
                                mode,
                                FallbackTestMode::SemanticPolicyBranch
                                    | FallbackTestMode::PolicyGate
                                    | FallbackTestMode::SemanticCancel
                            ),
                        "semantic refusal must not dispatch pixel work: {mode:?}, {method}"
                    );
                    assert_eq!(
                        peer_faults.status("scope", &peer_token).unwrap().state,
                        State::Expired,
                        "pixel work must follow the actual semantic deadline: {method}"
                    );
                }
                if request["method"]
                    .as_str()
                    .is_some_and(|method| method.starts_with("Animation."))
                {
                    animation_log.fetch_add(1, Ordering::SeqCst);
                }
                if request["method"] == "Page.setWebLifecycleState" {
                    log.lock()
                        .unwrap()
                        .push(request["params"]["state"].as_str().unwrap().into());
                }
                if matches!(
                    request["method"].as_str(),
                    Some(
                        "Animation.enable"
                            | "DOMSnapshot.captureSnapshot"
                            | "Page.captureScreenshot"
                    )
                ) {
                    assert!(
                        matches!(
                            capture_blobs.reserve_producer(capture_scope.clone()),
                            Err(BlobError::QuotaExceeded)
                        ),
                        "pixel stabilization and capture must follow producer admission"
                    );
                }
                let result = match request["method"].as_str().unwrap() {
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"frame","loaderId":"loader","url":"https://fixture.invalid/"}}})
                    }
                    "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                    "Animation.getPlaybackRate" => json!({"playbackRate":1}),
                    "Page.getLayoutMetrics" => {
                        json!({"cssVisualViewport":{"clientWidth":10,"clientHeight":10,"scale":1,"offsetX":0,"offsetY":0},"cssLayoutViewport":{"clientWidth":10,"clientHeight":10}})
                    }
                    "DOM.getDocument" => json!({"root":{"nodeType":9,"backendNodeId":1}}),
                    "DOMSnapshot.captureSnapshot" => {
                        let ordinal = snapshot_log.fetch_add(1, Ordering::SeqCst);
                        if coverage_unproven && ordinal == 0 {
                            // Actual initial coverage parser failure, before any source mask.
                            json!({"documents":[]})
                        } else {
                            json!({"strings":["frame"],"documents":[{"frameId":0,"nodes":{"nodeType":[],"backendNodeId":[]}}]})
                        }
                    }
                    "Runtime.evaluate" => {
                        // This peer has an empty DOM inventory. Its only evaluate is
                        // the source-mask holder factory, never an arbitrary script.
                        assert_eq!(request["params"]["contextId"], 1);
                        assert!(request["params"]["objectGroup"]
                            .as_str()
                            .unwrap()
                            .starts_with("capture-source-"));
                        source_log.lock().unwrap().push("holder");
                        json!({"result":{"type":"object","objectId":"source-holder"}})
                    }
                    "Runtime.callFunctionOn" => {
                        assert_eq!(request["params"]["objectId"], "source-holder");
                        let phase = match request["params"]["functionDeclaration"].as_str().unwrap()
                        {
                            "function(){return this.verify()}" => "verify",
                            "function(){return this.remove()}" => "remove",
                            other => panic!("unexpected source holder method: {other}"),
                        };
                        assert_eq!(request["params"]["returnByValue"], true);
                        assert!(request["params"]["objectGroup"]
                            .as_str()
                            .unwrap()
                            .starts_with("capture-source-"));
                        source_log.lock().unwrap().push(phase);
                        if phase == "verify" {
                            source_verifications += 1;
                        }
                        // Same MaskingUnproven reason as initial coverage, but a
                        // real post-screenshot source-protection policy failure.
                        let verified = !(mode == FallbackTestMode::PostCapturePolicy
                            && phase == "verify"
                            && source_verifications == 2);
                        json!({"result":{"type":"boolean","value":verified}})
                    }
                    "Runtime.releaseObjectGroup"
                        if request["params"]["objectGroup"]
                            .as_str()
                            .is_some_and(|group| group.starts_with("capture-source-")) =>
                    {
                        source_log.lock().unwrap().push("release");
                        json!({})
                    }
                    "Page.captureScreenshot" => {
                        capture_log.fetch_add(1, Ordering::SeqCst);
                        json!({"data":png})
                    }
                    _ => json!({}),
                };
                let is_restore = request["method"] == "Animation.setPlaybackRate"
                    && request["params"]["playbackRate"].as_f64() == Some(1.0);
                if hold_restore && is_restore && restore_reached.is_some() {
                    restore_reached.take().unwrap().send(()).unwrap();
                    restore_release_receipt.take().unwrap().await.unwrap();
                }
                let refused = mode == FallbackTestMode::CaptureRefused
                    && request["method"] == "Page.captureScreenshot"
                    || mode == FallbackTestMode::CoverageBrowserFailure
                        && request["method"] == "DOMSnapshot.captureSnapshot"
                    || dirty_restore && is_restore;
                let response = if refused {
                    json!({"id":request["id"],"sessionId":request["sessionId"],"error":{"code":-32000,"message":"synthetic capture or restore refusal"}})
                } else {
                    json!({"id":request["id"],"sessionId":request["sessionId"],"result":result})
                };
                if capture_cancel && request["method"] == "Page.captureScreenshot" {
                    assert!(held_capture.replace(response).is_none());
                    capture_reached.take().unwrap().send(()).unwrap();
                    continue;
                }
                if socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        response.to_string(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        let targets = ClientTargets::new("context".into(), "scope".into());
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
        // The boundary under test is Dispatch.start, not enrollment startup.
        targets.acknowledge_enrollment().unwrap();
        let gate = Arc::new(ExecutionGate::default());
        let mut page = BrowserExecutionLease {
            client: client.clone(),
            page_session_id: "session".into(),
            target_id: "target".into(),
            identity_scope: "scope".into(),
            permit: gate.enter(false).unwrap(),
            targets: targets.clone(),
        };
        let (cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline: Instant::now() + Duration::from_millis(2000),
            cancellation,
        };
        // Error-ACK custody is reader-owned command evidence, not a String
        // returned by the screenshot wrapper. This branch supplies the same
        // exact owner/operation accounting as production dispatch.
        let capture_journal = if mode == FallbackTestMode::CaptureRefused {
            use super::super::client_debt::{OperationKey, OwnerDebtLedger};
            let ledger = OwnerDebtLedger::new(operation.generation, page.identity_scope.clone());
            ledger.bind_context(&page.targets.context_id).unwrap();
            ledger
                .bind_session(
                    &page.targets.context_id,
                    &page.target_id,
                    &page.page_session_id,
                )
                .unwrap();
            client.install_debt_ledger(ledger.clone()).unwrap();
            page.client = client.owner_view(ledger.clone()).unwrap();
            let journal = ledger
                .operation(
                    OperationKey {
                        generation: operation.generation,
                        operation_seq: operation.sequence,
                    },
                    page.target_id.clone(),
                    page.page_session_id.clone(),
                )
                .unwrap();
            journal.bind_operation(&operation).unwrap();
            Some(journal)
        } else {
            None
        };
        // All subsequent fixture control/validation uses the same owner-bound
        // view; installing a ledger never upgrades a legacy raw client handle.
        let client = page.client.clone();
        let refs = Arc::new(Mutex::new(RefMap::new()));
        let dispatch = ObservationDispatch::new(refs.clone());
        dispatch
            .observed_cleanup_for_test
            .store(observed_cleanup, Ordering::SeqCst);
        let committed_revision = if seed_refs { 7 } else { 0 };
        let prior_viewport = if seed_refs {
            // Seed trusted observed and located issuance into the real stores.
            // This is publication bookkeeping evidence, not renderer actions.
            let binding = ExactBinding {
                page_session: "session".into(),
                session: "session".into(),
                frame: "frame".into(),
                loader: "loader".into(),
                actionable: true,
            };
            let mut initial = refs.lock().unwrap();
            initial.begin_observation("scope", 1, committed_revision);
            initial
                .try_bind_exact(10, "button", "Prior observed", binding.clone())
                .unwrap();
            initial
                .try_bind_located(
                    11,
                    "button",
                    binding,
                    super::super::element::LocatedIssuance {
                        identity_scope: "scope".into(),
                        generation: 1,
                        revision: 5,
                    },
                    None,
                )
                .unwrap();
            Some(
                initial
                    .try_viewport_ref("scope", 1, "session", committed_revision)
                    .unwrap()
                    .clone(),
            )
        } else {
            None
        };
        if seed_refs {
            let mut publication = dispatch.publication.lock().await;
            publication.revision = committed_revision;
            publication.published_revision = committed_revision;
            publication.observed_revision = committed_revision;
        }
        let prior_refs = refs.lock().unwrap().clone();
        let prior_ref_ids = prior_refs.ref_ids();
        if mode == FallbackTestMode::SemanticPolicyBranch {
            *dispatch.semantic_failure_for_test.lock().unwrap() =
                Some(ObservationError::PolicyDenied);
        }
        let original_deadline = operation.deadline;
        let retained_capture = capture_cancel
            .then(|| client_capture::retained_capture_test::register(&client, operation.sequence));
        let (_retained_capture_guard, retained_capture_receipt) = match retained_capture {
            Some((guard, receipt)) => (Some(guard), Some(receipt)),
            None => (None, None),
        };
        let start_dispatch = || {
            dispatch.clone().start(
                DispatchContext {
                    query_authority: None,
                    faults: faults.clone(),
                    attachment: page.targets.owned_target(&page.target_id).unwrap(),
                    page,
                    ui: Arc::new(UiGate::default()),
                    blobs: blobs.clone(),
                    scope: scope.clone(),
                    policy: ReadPolicy {
                        frame_policy: Default::default(),
                        test_id_attribute: "data-testid".into(),
                        secure_field_selector: "input[type=password]".into(),
                    },
                },
                DispatchRequest::Observe(ObserveRequest {
                    options: ObserveFlags {
                        pixels,
                        pixel_fallback: fallback,
                        comparable: false,
                    },
                    test_id_attribute: "data-testid".into(),
                    secure_field_selector: if mode == FallbackTestMode::PolicyGate {
                        "input".into()
                    } else {
                        "input[type=password]".into()
                    },
                }),
                operation,
            )
        };
        let mut task = match capture_journal.as_ref() {
            Some(journal) => journal.scope(async { start_dispatch() }).await,
            None => start_dispatch(),
        };
        if mode == FallbackTestMode::SemanticCancel {
            tokio::time::timeout(Duration::from_secs(5), async {
                while faults.status("scope", &token).unwrap().state != State::Reached {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(animation_commands.load(Ordering::SeqCst), 0);
            assert_eq!(snapshots.load(Ordering::SeqCst), 0);
            assert_eq!(captures.load(Ordering::SeqCst), 0);
            assert!(source_commands.lock().unwrap().is_empty());
            assert!(!budget_changes.has_changed().unwrap());
            cancel.send(CancelSignal::Requested).unwrap();
        }
        if capture_cancel {
            tokio::time::timeout(Duration::from_secs(5), capture_receipt)
                .await
                .unwrap()
                .unwrap();
            assert!(Instant::now() < original_deadline);
            cancel.send(CancelSignal::Requested).unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), retained_capture_receipt.unwrap())
                    .await
                    .unwrap()
                    .unwrap(),
                CaptureReason::Cancelled,
                "the screenshot ACK must follow entry into retained cancellation"
            );
            assert!(matches!(
                task.result.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(!task.join.is_finished());
            assert_eq!(*source_commands.lock().unwrap(), ["holder", "verify"]);
            assert!(matches!(
                blobs.reserve_producer(scope.clone()),
                Err(BlobError::QuotaExceeded)
            ));
            if !capture_unsettled {
                // Settle the actual screenshot within its existing retention
                // window, then independently block the mandatory restore ACK.
                capture_release.take().unwrap().send(()).unwrap();
                tokio::time::timeout(Duration::from_secs(5), capture_sent_receipt.take().unwrap())
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
        // A still-unacknowledged raw screenshot keeps source-mask custody.
        // No animation restore can safely begin after its drain budget expires.
        // The settled/error-ACK branches must still hit the original restore gate.
        if hold_restore && !capture_unsettled {
            tokio::time::timeout(Duration::from_secs(5), &mut restore_receipt)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(
                task.result.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(
                !task.join.is_finished(),
                "the retained task must wait for restore ACK"
            );
            assert!(
                matches!(
                    blobs.reserve_producer(scope.clone()),
                    Err(BlobError::QuotaExceeded)
                ),
                "producer ownership must survive until restoration settles"
            );
            if mode == FallbackTestMode::CoverageCancelDuringRestore {
                cancel.send(CancelSignal::Requested).unwrap();
            }
            if authority_revoked {
                // Revoke the actual captured ExecutionGate permit while its
                // mandatory restore still owns the journal. No fake error.
                gate.seal();
            }
            restore_release.send(()).unwrap();
        }
        let output = task.result.await;
        let cleanup = task.join.await;
        assert!(matches!(&cleanup, Ok(Ok(()))));
        if let Some(journal) = &capture_journal {
            assert_eq!(journal.ledger().snapshot().outstanding_commands, 0);
            assert_eq!(journal.snapshot().object_debt, 0);
            assert!(
                journal.clean_protected_read(),
                "error ACK still requires real protection restoration"
            );
        }
        if let Ok(Err(error)) = &output {
            assert_eq!(error.identity_scope, "scope");
            assert_eq!(error.cleanup_integrity_lost, integrity_lost_expected);
        }
        let (settled, integrity_lost) =
            super::super::client_browser::settle_observation_dispatch(output, cleanup);
        assert_eq!(integrity_lost, integrity_lost_expected);
        assert_eq!(
            settled.effects,
            if integrity_lost_expected {
                super::super::client_protocol::Effects::Unknown
            } else if settled.result.is_ok() {
                super::super::client_protocol::Effects::Completed
            } else {
                super::super::client_protocol::Effects::NotDispatched
            }
        );
        let output = settled.result;
        let semantic_policy = matches!(
            mode,
            FallbackTestMode::SemanticPolicyBranch | FallbackTestMode::PolicyGate
        );
        let semantic_failure = semantic_policy || mode == FallbackTestMode::SemanticCancel;
        let expected_animation: &[&str] =
            if !fallback || semantic_failure || mode == FallbackTestMode::Occupied {
                &[]
            } else if capture_unsettled {
                &[
                    "Animation.enable",
                    "Animation.getPlaybackRate",
                    "Animation.setPlaybackRate",
                ]
            } else {
                &[
                    "Animation.enable",
                    "Animation.getPlaybackRate",
                    "Animation.setPlaybackRate",
                    "Animation.setPlaybackRate",
                ]
            };
        assert_eq!(
            commands
                .lock()
                .unwrap()
                .iter()
                .filter(|method| method.starts_with("Animation."))
                .map(String::as_str)
                .collect::<Vec<_>>(),
            expected_animation,
            "only the separately admitted fallback owns an animation cycle: {mode:?}"
        );
        assert_eq!(
            faults.status("scope", &token).unwrap().state,
            if semantic_policy {
                State::Armed
            } else {
                State::Expired
            },
            "only an expired semantic deadline may admit fresh fallback"
        );
        if capture_unsettled {
            assert_eq!(output, Err(ProtocolError::CleanupFailed));
            assert!(targets.inventory().is_err());
            assert!(targets.protected_read_residual.replacement_safe().is_err());
            assert!(
                matches!(
                    restore_receipt.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
                "withheld raw ACK must not authorize animation restoration"
            );
            assert_eq!(
                *source_commands.lock().unwrap(),
                ["holder", "verify"],
                "withheld raw ACK must retain installed source-mask custody"
            );
            let count_before_late = commands.lock().unwrap().len();
            // Keep the old withheld-ACK schedule as a distinct negative case:
            // only a terminal CleanupFailed/Unknown result permits this ACK.
            capture_release.take().unwrap().send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), capture_sent_receipt.take().unwrap())
                .await
                .unwrap()
                .unwrap();
            // One correlated command orders the late raw response through the
            // same CDP reader; it must not revive a retired capture continuation.
            client
                .send_command("Browser.getVersion", None, None)
                .await
                .unwrap();
            assert_eq!(commands.lock().unwrap().len(), count_before_late + 1);
            assert!(
                targets.protected_read_residual.replacement_safe().is_err(),
                "late ACK must not retroactively retire abandoned raw custody"
            );
            assert!(matches!(
                restore_receipt.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
        }
        assert_eq!(blobs.read(&scope, &retained.handle, 0, 1).unwrap(), b"r");
        if mode == FallbackTestMode::Occupied {
            assert_eq!(output.unwrap_err(), ProtocolError::CapacityExceeded);
            assert!(refs.lock().unwrap().ref_ids().is_empty());
            assert_eq!(dispatch.publication.lock().await.published_revision, 0);
            assert_eq!(animation_commands.load(Ordering::SeqCst), 0);
            assert!(source_commands.lock().unwrap().is_empty());
            assert_eq!(captures.load(Ordering::SeqCst), 0);
            assert!(lifecycle.lock().unwrap().is_empty());
            assert!(!budget_changes.has_changed().unwrap());
            assert!(matches!(
                blobs.reserve_producer(scope.clone()),
                Err(BlobError::QuotaExceeded)
            ));
            drop(live_producer);
            let released = blobs.reserve_producer(scope.clone()).unwrap();
            drop(released);
            blobs.release(&scope, &retained.handle).unwrap();
            blobs.check_budget_integrity().unwrap();
            assert!(targets.inventory().is_ok());
            server.abort();
            let _ = server.await;
            return;
        }
        if mode != FallbackTestMode::Available || dirty_restore {
            let expected_error = match mode {
                FallbackTestMode::CoverageUnproven if !dirty_restore => {
                    ProtocolError::DeadlineExceeded
                }
                FallbackTestMode::CoverageCancelDuringRestore => ProtocolError::Cancelled,
                FallbackTestMode::CoverageAuthorityRevokedDuringRestore => {
                    ProtocolError::StaleScope
                }
                FallbackTestMode::CoverageUnproven
                | FallbackTestMode::CoverageObservedCleanupFlag
                | FallbackTestMode::PostCapturePolicy
                | FallbackTestMode::SemanticPolicyBranch
                | FallbackTestMode::PolicyGate => ProtocolError::PolicyDenied,
                FallbackTestMode::SemanticCancel | FallbackTestMode::CaptureCancel => {
                    ProtocolError::Cancelled
                }
                FallbackTestMode::CaptureCancelWithheldAck => ProtocolError::CleanupFailed,
                _ => ProtocolError::BrowserFailure,
            };
            assert_eq!(
                output.unwrap_err(),
                expected_error,
                "mode={mode:?}, dirty={dirty_restore}"
            );
            assert_eq!(refs.lock().unwrap().ref_ids(), prior_ref_ids);
            {
                let publication = dispatch.publication.lock().await;
                assert_eq!(publication.published_revision, committed_revision);
                assert_eq!(publication.observed_revision, committed_revision);
            }
            let pre_capture = coverage_unproven
                || matches!(
                    mode,
                    FallbackTestMode::CoverageBrowserFailure
                        | FallbackTestMode::SemanticPolicyBranch
                        | FallbackTestMode::PolicyGate
                        | FallbackTestMode::SemanticCancel
                );
            assert_eq!(captures.load(Ordering::SeqCst), usize::from(!pre_capture));
            assert_eq!(
                animation_commands.load(Ordering::SeqCst),
                if semantic_failure {
                    0
                } else if capture_unsettled {
                    3
                } else {
                    4
                }
            );
            assert!(lifecycle.lock().unwrap().is_empty());
            let expected_source = if pre_capture {
                vec![]
            } else if capture_unsettled {
                vec!["holder", "verify"]
            } else if matches!(
                mode,
                FallbackTestMode::CaptureRefused
                    | FallbackTestMode::CaptureCancel
                    | FallbackTestMode::CaptureCancelWithheldAck
            ) {
                vec!["holder", "verify", "remove", "release"]
            } else {
                vec!["holder", "verify", "verify", "remove", "release"]
            };
            assert_eq!(*source_commands.lock().unwrap(), expected_source);
            assert_eq!(
                snapshots.load(Ordering::SeqCst),
                if semantic_failure {
                    0
                } else if pre_capture {
                    1
                } else if mode == FallbackTestMode::Available {
                    3
                } else {
                    2
                }
            );
            assert_eq!(targets.inventory().is_err(), integrity_lost_expected);
            assert_eq!(gate.enter(false).is_err(), authority_revoked);
            if semantic_failure {
                assert!(!budget_changes.has_changed().unwrap());
            }
            if mode == FallbackTestMode::PolicyGate {
                assert!(
                    commands.lock().unwrap().is_empty(),
                    "policy gate precedes all CDP work"
                );
            }
            if seed_refs {
                let preserved = refs.lock().unwrap().clone();
                for id in &prior_ref_ids {
                    let before = prior_refs.get(id).unwrap();
                    let after = preserved.get(id).unwrap();
                    assert_eq!(after.backend_node_id, before.backend_node_id);
                    assert_eq!(after.exact_binding, before.exact_binding);
                    assert_eq!(after.lifetime, before.lifetime);
                    assert_eq!(after.kind, before.kind);
                    assert_eq!(after.issued_revision(), before.issued_revision());
                    assert_eq!(
                        after.is_current_observed(committed_revision),
                        before.is_current_observed(committed_revision)
                    );
                }
                let viewport = prior_viewport.as_ref().unwrap();
                assert!(preserved.matches_viewport_reference(
                    "scope",
                    1,
                    "session",
                    &format!("@{}", viewport.id),
                    &viewport.issuance.revision.to_string()
                ));
                if !integrity_lost_expected && !authority_revoked {
                    // Retained data is usable only while the original scope and
                    // exact document remain authoritative. A fresh operation
                    // avoids confusing operation cancellation with scope loss.
                    gate.enter(false).unwrap().check().unwrap();
                    targets.inventory().unwrap();
                    let (_fresh_cancel, cancellation) =
                        tokio::sync::watch::channel(CancelSignal::None);
                    let fresh_operation = OperationLease {
                        is_callback: false,
                        generation: 1,
                        sequence: 2,
                        deadline: Instant::now() + Duration::from_secs(2),
                        cancellation,
                    };
                    let (revision, actionable) = dispatch
                        .snapshot_for_action(&fresh_operation)
                        .await
                        .unwrap();
                    assert_eq!(revision, committed_revision);
                    assert_eq!(actionable.ref_ids(), prior_ref_ids);
                    for id in &prior_ref_ids {
                        let entry = actionable.get(id).unwrap();
                        assert!(entry.matches_reference(
                            "scope",
                            1,
                            "session",
                            &entry.issued_revision().unwrap().to_string()
                        ));
                        super::super::element::validate_exact_binding_typed(
                            &client,
                            "session",
                            entry.exact_binding.as_ref().unwrap(),
                        )
                        .await
                        .unwrap();
                    }
                } else {
                    // Preserved metadata alone never revives a revoked or
                    // quarantined scope; do not claim actionability in this arm.
                    assert!(targets.inventory().is_err() || gate.enter(false).is_err());
                }
                // The shared allocator may burn staged IDs, but only the old
                // committed set and issuance may remain publicly addressable.
                assert_eq!(refs.lock().unwrap().ref_ids(), prior_ref_ids);
            }
            // Exact maximum reservations and checked accounting prove no
            // unpublished charge survives or was returned twice after cleanup.
            blobs.check_budget_integrity().unwrap();
            let released = blobs.reserve_producer(scope.clone()).unwrap();
            drop(released);
            blobs.release(&scope, &retained.handle).unwrap();
            let first = blobs.reserve_producer(scope.clone()).unwrap();
            let second = blobs.reserve_producer(scope.clone()).unwrap();
            assert!(matches!(
                blobs.reserve_producer(scope.clone()),
                Err(BlobError::QuotaExceeded)
            ));
            drop((first, second));
            blobs.check_budget_integrity().unwrap();
            server.abort();
            let _ = server.await;
            return;
        }
        if !fallback {
            assert_eq!(output.unwrap_err(), ProtocolError::DeadlineExceeded);
            assert!(lifecycle.lock().unwrap().is_empty());
            assert_eq!(animation_commands.load(Ordering::SeqCst), 0);
            assert!(source_commands.lock().unwrap().is_empty());
            assert!(!budget_changes.has_changed().unwrap());
            server.abort();
            let _ = server.await;
            return;
        }
        let output = output.unwrap();
        assert_eq!(output["treeUnavailable"], true);
        let root = output["root"].as_object().expect("fallback root object");
        assert_eq!(
            root.len(),
            1,
            "unavailable tree must serialize only the exact root reference"
        );
        assert!(root.contains_key("ref"));
        assert!(root["ref"]["id"].as_str().unwrap().starts_with("@e"));
        assert_eq!(output["truncated"], true);
        assert_eq!(
            faults.status("scope", &token).unwrap().state,
            State::Expired
        );
        assert!(lifecycle.lock().unwrap().is_empty());
        assert_eq!(animation_commands.load(Ordering::SeqCst), 4);
        let expected_source_cycle = ["holder", "verify", "verify", "remove", "release"];
        assert_eq!(
                *source_commands.lock().unwrap(),
                expected_source_cycle,
                "the timed-out semantic phase never captures; fresh fallback owns one settled source holder"
            );
        assert_eq!(captures.load(Ordering::SeqCst), 1);
        assert_eq!(output["viewport"], json!({"width":10.0,"height":10.0}));
        assert_eq!(output["pixels"]["width"], 10);
        assert_eq!(output["pixels"]["height"], 10);
        assert_eq!(output["pixels"]["maskedRegionCount"], 0);
        assert_eq!(dispatch.publication.lock().await.published_revision, 1);
        let root_id = root["ref"]["id"].as_str().unwrap();
        assert_eq!(
            refs.lock()
                .unwrap()
                .get(root_id.trim_start_matches('@'))
                .unwrap()
                .backend_node_id,
            Some(1)
        );
        blobs
            .release(&scope, output["pixels"]["handle"].as_str().unwrap())
            .unwrap();
        blobs.release(&scope, &retained.handle).unwrap();
        let first = blobs.reserve_producer(scope.clone()).unwrap();
        let second = blobs.reserve_producer(scope.clone()).unwrap();
        drop((first, second));
        blobs.check_budget_integrity().unwrap();
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn page_retirement_fences_publication_and_revokes_old_pixel_handles() {
        let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
        let blobs = BlobStore::new(Default::default()).unwrap();
        let scope = BlobScope {
            generation: 1,
            identity_scope: "page-scope".into(),
        };
        blobs.activate_scope(scope.clone()).unwrap();
        let old = blobs.insert_sealed(scope.clone(), b"old pixels").unwrap();
        let video = blobs
            .insert_sealed(scope.clone(), b"saved segment")
            .unwrap();
        let before = dispatch.publication_fence().unwrap();
        let tenure = dispatch.captures.lock().unwrap().page_blob_tenure.clone();
        blobs
            .bind_page_captures(&scope, &[old.handle.clone()], &tenure)
            .unwrap();
        dispatch
            .retire_page_publication(&blobs, &scope)
            .await
            .unwrap();
        assert_eq!(
            dispatch.check_publication_fence(before),
            Err(ProtocolError::StaleReference)
        );
        assert_eq!(
            blobs.read(&scope, &old.handle, 0, 32),
            Err(BlobError::Missing)
        );
        assert_eq!(
            blobs.read(&scope, &video.handle, 0, 32).unwrap(),
            b"saved segment"
        );
        let fresh = blobs.insert_sealed(scope.clone(), b"fresh pixels").unwrap();
        let current = dispatch.captures.lock().unwrap().page_blob_tenure.clone();
        assert!(!Arc::ptr_eq(&tenure, &current));
        blobs
            .bind_page_captures(&scope, &[fresh.handle.clone()], &current)
            .unwrap();
        blobs.revoke_page_captures(&scope, &tenure).unwrap();
        assert_eq!(
            blobs.read(&scope, &fresh.handle, 0, 32).unwrap(),
            b"fresh pixels"
        );
    }

    #[tokio::test]
    async fn action_snapshot_uses_committed_revision_not_failed_staging_counter() {
        let refs = Arc::new(Mutex::new(RefMap::new()));
        let dispatch = ObservationDispatch::new(refs);
        {
            let mut publication = dispatch.publication.lock().await;
            publication.revision = 9;
            publication.published_revision = 4;
        }
        let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let mut operation = operation();
        operation.cancellation = cancellation;
        assert_eq!(dispatch.snapshot_for_action(&operation).await.unwrap().0, 4);
        let locked = dispatch.publication.lock().await;
        operation.deadline = Instant::now() + Duration::from_millis(5);
        assert!(matches!(
            dispatch.snapshot_for_action(&operation).await,
            Err(ProtocolError::DeadlineExceeded)
        ));
        drop(locked);
    }
    #[tokio::test]
    async fn screenshot_and_additive_query_preserve_action_snapshot_but_observe_replaces_it() {
        let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            cancellation,
            ..operation()
        };
        let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
        let binding = frame("root", None).binding;
        let mut initial = RefMap::new();
        let id = initial
            .try_bind_exact(10, "button", "Public", binding.clone())
            .unwrap();
        let mut publication = dispatch.publication.lock().await;
        let original = publication
            .stage_revision(PublicationKind::Snapshot)
            .unwrap();
        publication.commit_refs(
            PublicationKind::Snapshot,
            original,
            &mut dispatch.refs.lock().unwrap(),
            initial.clone(),
        );
        let pixel_revision = publication
            .stage_revision(PublicationKind::PixelsOnly)
            .unwrap();
        // Even an accidental mutation of the screenshot's private clone must
        // not alter actionable identity or its committed revision.
        let mut pixels = initial.clone();
        pixels.begin_snapshot();
        publication.commit_refs(
            PublicationKind::PixelsOnly,
            pixel_revision,
            &mut dispatch.refs.lock().unwrap(),
            pixels,
        );
        drop(publication);
        let (current, refs) = dispatch.snapshot_for_action(&operation).await.unwrap();
        assert_eq!(current, original);
        assert!(refs.get(&id).is_some());
        let mut publication = dispatch.publication.lock().await;
        let queried = publication
            .stage_revision(PublicationKind::AdditiveQuery)
            .unwrap();
        let mut additive = refs;
        let added = additive
            .try_bind_exact(11, "button", "Second", binding)
            .unwrap();
        publication.commit_refs(
            PublicationKind::AdditiveQuery,
            queried,
            &mut dispatch.refs.lock().unwrap(),
            additive,
        );
        drop(publication);
        let (current, refs) = dispatch.snapshot_for_action(&operation).await.unwrap();
        assert_eq!(current, original);
        assert!(refs.get(&id).is_some() && refs.get(&added).is_some());
        let mut publication = dispatch.publication.lock().await;
        let replacement = publication
            .stage_revision(PublicationKind::Snapshot)
            .unwrap();
        publication.commit_refs(
            PublicationKind::Snapshot,
            replacement,
            &mut dispatch.refs.lock().unwrap(),
            RefMap::new(),
        );
        drop(publication);
        let (current, _) = dispatch.snapshot_for_action(&operation).await.unwrap();
        assert_ne!(current, original); // Strict action revision equality rejects the old ref.
    }
    #[test]
    fn only_committed_observation_advances_reconnect_evidence() {
        let mut publication = Publication {
            revision: 0,
            published_revision: 0,
            observed_revision: 0,
        };
        let mut refs = RefMap::new();
        for kind in [PublicationKind::AdditiveQuery, PublicationKind::PixelsOnly] {
            let revision = publication.stage_revision(kind).unwrap();
            publication.commit_refs(kind, revision, &mut refs, RefMap::new());
            assert_eq!(publication.observed_revision, 0);
        }
        let abandoned = publication
            .stage_revision(PublicationKind::Snapshot)
            .unwrap();
        assert_eq!(publication.observed_revision, 0);
        let committed = publication
            .stage_revision(PublicationKind::Snapshot)
            .unwrap();
        assert!(committed > abandoned);
        publication.commit_refs(
            PublicationKind::Snapshot,
            committed,
            &mut refs,
            RefMap::new(),
        );
        assert_eq!(publication.observed_revision, committed);
        for kind in [PublicationKind::AdditiveQuery, PublicationKind::PixelsOnly] {
            let revision = publication.stage_revision(kind).unwrap();
            publication.commit_refs(kind, revision, &mut refs, RefMap::new());
            assert_eq!(publication.observed_revision, committed);
        }
    }
    #[test]
    fn semantic_trace_discards_temporary_authority_without_advancing_publication() {
        let mut publication = Publication {
            revision: 7,
            published_revision: 6,
            observed_revision: 5,
        };
        let mut refs = RefMap::new();
        let binding = frame("root", None).binding;
        let original = refs
            .try_bind_exact(10, "button", "kept", binding.clone())
            .unwrap();
        let mut staged = refs.clone();
        staged.retire_interaction_references();
        let temporary = staged
            .try_bind_exact(11, "button", "trace", binding.clone())
            .unwrap();
        let revision = publication
            .stage_revision(PublicationKind::TraceSemantic)
            .unwrap();
        publication.commit_refs(PublicationKind::TraceSemantic, revision, &mut refs, staged);
        assert_eq!(
            (
                publication.revision,
                publication.published_revision,
                publication.observed_revision
            ),
            (7, 6, 5)
        );
        assert!(refs.get(&original).is_some());
        assert!(refs.get(&temporary).is_none());
        let next = refs.try_bind_exact(12, "button", "next", binding).unwrap();
        assert_ne!(next, temporary); // A discarded trace ID is never recycled.
    }
    #[test]
    fn semantic_trace_rejects_pixel_or_fallback_options() {
        let policy = ReadPolicy {
            frame_policy: Default::default(),
            test_id_attribute: "data-testid".into(),
            secure_field_selector: "input[type=password]".into(),
        };
        for flags in [
            ObserveFlags {
                pixels: true,
                ..Default::default()
            },
            ObserveFlags {
                pixel_fallback: true,
                ..Default::default()
            },
            ObserveFlags {
                comparable: true,
                ..Default::default()
            },
        ] {
            let request = DispatchRequest::TraceSemantic(ObserveRequest {
                options: flags,
                test_id_attribute: policy.test_id_attribute.clone(),
                secure_field_selector: policy.secure_field_selector.clone(),
            });
            assert_eq!(
                validate_policy(&policy, &request),
                Err(ProtocolError::InvalidArguments)
            );
        }
    }
    #[test]
    fn initial_query_allocates_epoch_and_pixels_do_not_allocate_one() {
        let mut publication = Publication {
            revision: 0,
            published_revision: 0,
            observed_revision: 0,
        };
        assert_eq!(
            publication
                .stage_revision(PublicationKind::PixelsOnly)
                .unwrap(),
            0
        );
        assert_eq!(publication.revision, 0);
        assert_eq!(
            publication
                .stage_revision(PublicationKind::AdditiveQuery)
                .unwrap(),
            1
        );
        // Abandoned first-query epoch is not published or reused.
        assert_eq!(
            publication
                .stage_revision(PublicationKind::AdditiveQuery)
                .unwrap(),
            2
        );
        assert_eq!(publication.published_revision, 0);
    }
    #[test]
    fn semantic_geometry_cleanup_preserves_nested_primary_and_integrity() {
        use super::super::client_geometry::GeometryError;
        let cleanup = AtomicBool::new(false);
        assert_eq!(
            geometry_error_with_cleanup(
                GeometryError::CleanupFailed {
                    primary: Some(Box::new(GeometryError::CleanupFailed {
                        primary: Some(Box::new(GeometryError::Cancelled))
                    }))
                },
                &cleanup
            ),
            ProtocolError::Cancelled
        );
        assert!(cleanup.load(Ordering::SeqCst));
    }
    #[tokio::test]
    async fn fixture_query_publishes_zero_area_semantics_through_dispatch() {
        use super::super::cdp::client::CdpClient;
        use super::super::client_browser::ExecutionGate;
        use super::super::client_targets::ClientTargets;
        use futures_util::{SinkExt, StreamExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = ws.next().await {
                let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                let result = match request["method"].as_str().unwrap() {
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"frame","loaderId":"loader","url":"https://fixture.invalid/"}}})
                    }
                    "Page.getLayoutMetrics" => {
                        json!({"cssVisualViewport":{"clientWidth":100,"clientHeight":80,"offsetX":0,"offsetY":0,"scale":1},"cssLayoutViewport":{"clientWidth":100,"clientHeight":80}})
                    }
                    "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                    "DOM.getDocument" => {
                        json!({"root":{"nodeType":9,"backendNodeId":1,"children":[{"nodeType":1,"backendNodeId":7}]}})
                    }
                    "Accessibility.getFullAXTree" => {
                        json!({"nodes":[{"nodeId":"zero","backendDOMNodeId":7,"role":{"type":"role","value":"generic"}}]})
                    }
                    "DOM.resolveNode" => json!({"object":{"objectId":"owner","subtype":"node"}}),
                    "DOM.getBoxModel" => json!({"model":{"border":[10,20,10,20,10,20,10,20]}}),
                    "Runtime.getProperties" => {
                        json!({"result":[{"name":"focused","value":{"type":"object","subtype":"null","value":null}}]})
                    }
                    "Runtime.callFunctionOn" => {
                        let declaration =
                            request["params"]["functionDeclaration"].as_str().unwrap();
                        if declaration.contains("Array.from(result)") {
                            json!({"result":{"objectId":"security"}})
                        } else if declaration.starts_with("function(expression") {
                            json!({"result":{"value":{"indices":[0],"redacted":[]}}})
                        } else if declaration.contains("const read=") {
                            json!({"result":{"value":[{"attributes":{},"labels":[],"states":{"secure":false,"hidden":true},"text":"","rect":{"x":999,"y":999,"width":0,"height":0}}]}})
                        } else if declaration.contains("frameOwner") {
                            json!({"result":{"value":{"connected":true,"frameOwner":false}}})
                        } else {
                            json!({"result":{"value":true}})
                        }
                    }
                    "Runtime.releaseObject" | "Runtime.releaseObjectGroup" => json!({}),
                    method => panic!("unexpected zero-area dispatch command: {method}"),
                };
                if ws
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        json!({"id":request["id"],"result":result}).to_string(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
        let targets = ClientTargets::new("context".into(), "scope".into());
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
        targets.acknowledge_enrollment().unwrap(); // Synthetic complete inventory only.
        let gate = Arc::new(ExecutionGate::default());
        let page = BrowserExecutionLease {
            client,
            page_session_id: "session".into(),
            target_id: "target".into(),
            identity_scope: "scope".into(),
            permit: gate.enter(false).unwrap(),
            targets,
        };
        let blobs = Arc::new(BlobStore::new(Default::default()).unwrap());
        let scope = BlobScope {
            generation: 1,
            identity_scope: "scope".into(),
        };
        blobs.activate_scope(scope.clone()).unwrap();
        let refs = Arc::new(Mutex::new(RefMap::new()));
        let dispatch = ObservationDispatch::new(refs.clone());
        let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            generation: 1,
            sequence: 1,
            is_callback: false,
            deadline: Instant::now() + Duration::from_secs(5),
            cancellation,
        };
        let task = dispatch.start(DispatchContext {
            query_authority: None,
            #[cfg(feature="acceptance-faults")]
            faults:Arc::new(super::super::client_test_faults::FaultController::default()),
            attachment: page.targets.owned_target(&page.target_id).unwrap(),
            page, ui:Arc::new(UiGate::default()), blobs, scope,
            policy:ReadPolicy { frame_policy: Default::default(), test_id_attribute:"data-testid".into(), secure_field_selector:"input[type=password]".into() },
        }, DispatchRequest::Query(QueryRequest {
            purpose:QueryPurpose::Fixture,
            options:serde_json::from_value(json!({"expression":{"kind":"selector","selector":"#zero"},"secureFieldSelector":"input[type=password]"})).unwrap(),
        }), operation);
        let result = task.result.await.unwrap().unwrap();
        task.join.await.unwrap().unwrap();
        assert_eq!(
            result["nodes"][0]["rect"],
            json!({"x":10.0,"y":20.0,"width":0.0,"height":0.0})
        );
        assert_eq!(result["nodes"][0]["states"]["hidden"], true);
        let id = result["nodes"][0]["ref"]["id"].as_str().unwrap();
        assert_eq!(
            refs.lock()
                .unwrap()
                .get(id.trim_start_matches('@'))
                .unwrap()
                .backend_node_id,
            Some(7)
        );
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn tree_observe_skips_positive_hidden_iframe_before_spatial_proof() {
        tree_observe_with_hidden_iframe(false).await;
    }
    #[tokio::test]
    async fn tree_only_fallback_does_not_reserve_unused_pixels_under_live_blob_pressure() {
        tree_observe_with_hidden_iframe(true).await;
    }
    async fn tree_observe_with_hidden_iframe(pixel_fallback: bool) {
        use super::super::cdp::client::CdpClient;
        use super::super::client_blobs::BlobLimits;
        use super::super::client_browser::ExecutionGate;
        use super::super::client_targets::ClientTargets;
        use futures_util::{SinkExt, StreamExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = ws.next().await {
                let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                let result = match request["method"].as_str().unwrap() {
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"frame","loaderId":"loader","url":"https://fixture.invalid/"},"childFrames":[{"frame":{"id":"child","parentId":"frame","loaderId":"child-loader","url":"about:blank"}}]}})
                    }
                    "Page.getLayoutMetrics" => {
                        json!({"cssVisualViewport":{"clientWidth":100,"clientHeight":80,"offsetX":0,"offsetY":0,"scale":1},"cssLayoutViewport":{"clientWidth":100,"clientHeight":80}})
                    }
                    "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                    "DOM.getDocument" => {
                        json!({"root":{"nodeType":9,"backendNodeId":1,"children":[{"nodeType":1,"nodeName":"IFRAME","localName":"iframe","backendNodeId":7}]}})
                    }
                    "Accessibility.getFullAXTree" => {
                        assert_eq!(
                            request["params"]["frameId"], "frame",
                            "hidden child AX must not be acquired"
                        );
                        json!({"nodes":[{"nodeId":"document","backendDOMNodeId":1,"role":{"type":"role","value":"RootWebArea"}},{"nodeId":"owner","backendDOMNodeId":7,"role":{"type":"role","value":"Iframe"}}]})
                    }
                    "DOM.resolveNode" => {
                        json!({"object":{"objectId":format!("node-{}", request["params"]["backendNodeId"]),"subtype":"node"}})
                    }
                    "DOM.getFrameOwner" => json!({"backendNodeId":7}),
                    "DOM.getBoxModel" => panic!("hidden frame spatial proof must not run"),
                    "Runtime.getProperties" => {
                        json!({"result":[{"name":"focused","value":{"type":"object","subtype":"null","value":null}}]})
                    }
                    "Runtime.callFunctionOn" => {
                        let declaration =
                            request["params"]["functionDeclaration"].as_str().unwrap();
                        if declaration.contains("Array.from(result)") {
                            json!({"result":{"objectId":"security"}})
                        } else if declaration.contains("selector:parts.join") {
                            json!({"result":{"value":{"x":0,"y":0,"selector":"iframe"}}})
                        } else if declaration.starts_with("function(expression") {
                            json!({"result":{"value":{"indices":[0],"redacted":[]}}})
                        } else if declaration.contains("return {status:data.__nativeStatus") {
                            json!({"result":{"value":{"nodeType":1,"tag":"iframe","hidden":true}}})
                        } else if declaration.contains("const read=") {
                            let values = request["params"]["arguments"].as_array().unwrap().iter().skip(2).map(|argument| {
                                match argument["objectId"].as_str().unwrap() {
                                    "node-1" => json!({"attributes":{},"labels":[],"states":{},"rect":null,"author":{"nodeType":9,"visible":true}}),
                                    "node-7" => json!({"attributes":{},"labels":[],"states":{"hidden":true},"rect":null,"author":{"nodeType":1,"tag":"iframe","visible":false}}),
                                    _ => panic!("unknown exact metadata receiver"),
                                }
                            }).collect::<Vec<_>>();
                            json!({"result":{"value":values}})
                        } else if declaration
                            .starts_with("function(testId,secureSelector,boundedObservation")
                        {
                            json!({"result":{"value":{"attributes":{},"labels":[],"states":{"hidden":true},"rect":null,"author":{"nodeType":1,"tag":"iframe","visible":false}}}})
                        } else if declaration.contains("frameOwner") {
                            json!({"result":{"value":{"connected":true,"frameOwner":false}}})
                        } else {
                            json!({"result":{"value":true}})
                        }
                    }
                    "Runtime.releaseObject" | "Runtime.releaseObjectGroup" => json!({}),
                    method => panic!("unexpected zero-area dispatch command: {method}"),
                };
                if ws
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        json!({"id":request["id"],"result":result}).to_string(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
        let targets = ClientTargets::new("context".into(), "scope".into());
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
        // This synthetic peer tests production Dispatch.start admission, not
        // browser startup or enrollment readiness.
        targets.acknowledge_enrollment().unwrap();
        let gate = Arc::new(ExecutionGate::default());
        let page = BrowserExecutionLease {
            client,
            page_session_id: "session".into(),
            target_id: "target".into(),
            identity_scope: "scope".into(),
            permit: gate.enter(false).unwrap(),
            targets,
        };
        let blobs = Arc::new(
            BlobStore::new(BlobLimits {
                max_blob_bytes: 4096,
                max_total_bytes: 8192,
                max_handles: 8,
            })
            .unwrap(),
        );
        let scope = BlobScope {
            generation: 1,
            identity_scope: "scope".into(),
        };
        blobs.activate_scope(scope.clone()).unwrap();
        let retained = blobs.insert_sealed(scope.clone(), b"r").unwrap();
        let live_producer = blobs.reserve_producer(scope.clone()).unwrap();
        assert!(matches!(
            blobs.reserve_producer(scope.clone()),
            Err(BlobError::QuotaExceeded)
        ));
        let budget_changes = blobs.budget_changes().unwrap();
        let refs = Arc::new(Mutex::new(RefMap::new()));
        let dispatch = ObservationDispatch::new(refs.clone());
        let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            generation: 1,
            sequence: 1,
            is_callback: false,
            deadline: Instant::now() + Duration::from_secs(5),
            cancellation,
        };
        let task = dispatch.clone().start(
            DispatchContext {
                query_authority: None,
                #[cfg(feature = "acceptance-faults")]
                faults: Arc::new(super::super::client_test_faults::FaultController::default()),
                attachment: page.targets.owned_target(&page.target_id).unwrap(),
                page,
                ui: Arc::new(UiGate::default()),
                blobs: blobs.clone(),
                scope: scope.clone(),
                policy: ReadPolicy {
                    frame_policy: Default::default(),
                    test_id_attribute: "data-testid".into(),
                    secure_field_selector: "input[type=password]".into(),
                },
            },
            DispatchRequest::Observe(ObserveRequest {
                options: ObserveFlags {
                    pixels: false,
                    pixel_fallback,
                    comparable: false,
                },
                test_id_attribute: "data-testid".into(),
                secure_field_selector: "input[type=password]".into(),
            }),
            operation,
        );
        let result = task.result.await.unwrap().unwrap();
        task.join.await.unwrap().unwrap();
        assert_eq!(result["root"]["role"], "document");
        assert!(result["root"]["children"]
            .as_array()
            .is_none_or(Vec::is_empty));
        assert!(result.get("hidden_frame_proof").is_none());
        assert!(result.get("semanticFrameProof").is_none());
        assert!(result.get("hiddenFrameProof").is_none());
        assert!(result.get("pixels").is_none());
        assert!(result.get("treeUnavailable").is_none());
        assert_eq!(result["viewport"], json!({"width":100.0,"height":80.0}));
        assert_eq!(result["location"], "https://fixture.invalid/");
        // The strict peer rejects screenshots, source-mask commands, animation
        // changes, and spatial reads of the positively hidden iframe.
        assert!(!budget_changes.has_changed().unwrap());
        assert_eq!(blobs.read(&scope, &retained.handle, 0, 1).unwrap(), b"r");
        assert!(matches!(
            blobs.reserve_producer(scope.clone()),
            Err(BlobError::QuotaExceeded)
        ));
        assert_eq!(
            dispatch
                .snapshot_for_action(&OperationLease {
                    generation: 1,
                    sequence: 2,
                    is_callback: false,
                    deadline: Instant::now() + Duration::from_secs(1),
                    cancellation: _sender.subscribe(),
                })
                .await
                .unwrap()
                .0,
            1
        );
        let root = result["root"]["ref"]["id"].as_str().unwrap();
        assert_eq!(
            refs.lock()
                .unwrap()
                .get(root.trim_start_matches('@'))
                .unwrap()
                .backend_node_id,
            Some(1)
        );
        drop(live_producer);
        blobs.release(&scope, &retained.handle).unwrap();
        blobs.check_budget_integrity().unwrap();
        server.abort();
        let _ = server.await;
    }
    #[test]
    fn optional_observe_headroom_covers_two_timer_roundings_and_publication() {
        let now = Instant::now();
        for remaining in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_millis(1),
            Duration::from_millis(2),
            Duration::from_millis(3),
            Duration::from_nanos(3_000_001),
            Duration::from_millis(80),
            Duration::from_secs(4),
        ] {
            let mut parent = operation();
            parent.deadline = now + remaining;
            let optional = optional_observe_lease_at(&parent, now);
            let reserve = remaining.min(Duration::from_millis(3));
            assert_eq!(optional.deadline, parent.deadline - reserve);
            assert_eq!(parent.deadline, now + remaining);
            assert_eq!(
                optional.deadline <= now,
                remaining <= Duration::from_millis(3)
            );
        }
    }
    #[test]
    fn optional_observe_headroom_preserves_owner_cancellation_and_expired_deadline() {
        let now = Instant::now();
        let (cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let parent = OperationLease {
            is_callback: true,
            generation: 9,
            sequence: 17,
            deadline: now + Duration::from_millis(80),
            cancellation,
        };
        let optional = optional_observe_lease_at(&parent, now);
        assert_eq!(optional.generation, parent.generation);
        assert_eq!(optional.sequence, parent.sequence);
        assert_eq!(optional.is_callback, parent.is_callback);
        assert!(optional.cancellation.same_channel(&parent.cancellation));
        cancel.send_replace(CancelSignal::Requested);
        assert_eq!(*optional.cancellation.borrow(), CancelSignal::Requested);
        let expired = optional_observe_lease_at(&parent, now + Duration::from_millis(81));
        assert_eq!(expired.deadline, parent.deadline);
        assert_eq!(parent.deadline, now + Duration::from_millis(80));
    }
    #[test]
    fn fallback_reserves_bounded_time_without_resetting_parent_deadline() {
        let parent = operation();
        let now = parent.deadline - Duration::from_secs(8);
        let semantic = semantic_lease_at(&parent, true, now);
        assert_eq!(parent.deadline - semantic.deadline, Duration::from_secs(2));
        assert_eq!(semantic.sequence, parent.sequence);
        assert_eq!(semantic_lease(&parent, false).deadline, parent.deadline);
        let pixels = pixel_lease(&parent);
        assert_eq!(
            parent.deadline - pixels.deadline,
            Duration::from_millis(500)
        );
    }
    #[test]
    fn fallback_semantic_budget_matches_quarter_reserve_and_cap_boundaries() {
        let now = Instant::now();
        for (remaining, reserve) in [
            (Duration::ZERO, Duration::ZERO),
            (Duration::from_millis(4), Duration::from_millis(1)),
            (Duration::from_secs(2), Duration::from_millis(500)),
            (Duration::from_secs(8), Duration::from_secs(2)),
            (Duration::from_secs(12), Duration::from_secs(2)),
        ] {
            let mut parent = operation();
            parent.deadline = now + remaining;
            let semantic = semantic_lease_at(&parent, true, now);
            assert_eq!(semantic.deadline, parent.deadline - reserve);
            assert_eq!(
                semantic_lease_at(&parent, false, now).deadline,
                parent.deadline
            );
            assert_eq!(semantic.sequence, parent.sequence);
            assert_eq!(semantic.generation, parent.generation);
            assert_eq!(semantic.is_callback, parent.is_callback);
        }
        // A two-second stalled reader expires at 1500ms, not the former
        // 1000ms half-budget cut that violated the original >1250ms fixture.
        let mut parent = operation();
        parent.deadline = now + Duration::from_secs(2);
        assert_eq!(
            semantic_lease_at(&parent, true, now).deadline - now,
            Duration::from_millis(1500)
        );
        // Setup already spent from the same parent deadline, not a fresh budget.
        assert_eq!(
            semantic_lease_at(&parent, true, now + Duration::from_secs(1)).deadline,
            parent.deadline - Duration::from_millis(250)
        );
        assert_eq!(
            semantic_lease_at(&parent, true, now + Duration::from_secs(3)).deadline,
            parent.deadline
        );
    }
    #[test]
    fn frames_are_order_independent_but_never_rebind_documents_or_sessions() {
        let a = vec![frame("root", None), frame("child", Some("root"))];
        let mut b = vec![a[1].clone(), a[0].clone()];
        same_frames(&a, &b).unwrap();
        b[0].binding.loader = "replacement".into();
        assert_eq!(same_frames(&a, &b), Err(ProtocolError::StaleScope));
        b[0] = a[1].clone();
        b[0].binding.session = "foreign".into();
        assert_eq!(same_frames(&a, &b), Err(ProtocolError::StaleScope));
        b[0] = a[1].clone();
        b[1].url.push_str("#same-document-navigation");
        assert_eq!(same_frames(&a, &b), Err(ProtocolError::StaleScope));
        assert!(main_frame(&[frame("one", None), frame("two", None)]).is_err());
    }
    #[test]
    fn document_root_is_exact_and_viewport_is_not_a_document_wrapper() {
        let frames = vec![frame("root", None)];
        let mut refs = RefMap::new();
        let id = refs
            .try_bind_exact(10, "document", "", frames[0].binding.clone())
            .unwrap();
        let mut root = SemanticNode::default();
        root.reference.id = format!("@{id}");
        root.reference.revision = "1".into();
        root.role = Some("document".into());
        assert!(exact_root(vec![root.clone()], &refs, &frames).is_ok());
        assert!(exact_root(vec![root.clone(), root.clone()], &refs, &frames).is_err());
        let mut foreign = frames.clone();
        foreign[0].binding.loader = "new".into();
        assert!(exact_root(vec![root.clone()], &refs, &foreign).is_err());
        let viewport = refs
            .try_viewport_ref("scope", 1, &frames[0].binding.page_session, 1)
            .unwrap();
        let mut fake = root;
        fake.reference.id = format!("@{}", viewport.id);
        assert!(exact_root(vec![fake], &refs, &frames).is_err());
    }
    #[test]
    fn abandoned_staging_consumes_native_ids_without_publishing_entries() {
        let mut refs = RefMap::new();
        let mut abandoned = refs.clone();
        let binding = frame("root", None).binding;
        let lost = abandoned
            .try_bind_exact(1, "button", "", binding.clone())
            .unwrap();
        assert!(refs.get(&lost).is_none());
        let next = refs.try_bind_exact(2, "button", "", binding).unwrap();
        assert_ne!(lost, next);
    }
    #[test]
    fn masking_failures_are_never_reclassified_as_optional_backend_errors() {
        assert_eq!(
            capture_error(CaptureReason::MaskingUnproven),
            ProtocolError::PolicyDenied
        );
        assert_eq!(
            capture_error(CaptureReason::UnsafeGeometry),
            ProtocolError::PolicyDenied
        );
        assert_eq!(
            capture_error(CaptureReason::Cancelled),
            ProtocolError::Cancelled
        );
        assert_eq!(
            observation_error(ObservationError::PolicyDenied),
            ProtocolError::PolicyDenied
        );
    }
    #[test]
    fn oversized_semantics_fail_before_publication_not_transport_poison() {
        bounded_result(&json!({"nodes":[]})).unwrap();
        assert_eq!(
            bounded_result(
                &json!({"text":"x".repeat(super::super::client_protocol::MAX_FRAME_BYTES)})
            ),
            Err(ProtocolError::CapacityExceeded)
        );
    }
    #[test]
    fn repeated_request_policy_cannot_weaken_captured_scope_policy() {
        let policy = ReadPolicy {
            frame_policy: Default::default(),
            test_id_attribute: "data-testid".into(),
            secure_field_selector: "input[type=password],.private".into(),
        };
        let weaker = DispatchRequest::Screenshot(ScreenshotRequest {
            purpose: ScreenshotPurpose::PixelsOnly,
            secure_field_selector: "input[type=password]".into(),
        });
        assert_eq!(
            validate_policy(&policy, &weaker),
            Err(ProtocolError::PolicyDenied)
        );
        let exact = DispatchRequest::Screenshot(ScreenshotRequest {
            purpose: ScreenshotPurpose::PixelsOnly,
            secure_field_selector: policy.secure_field_selector.clone(),
        });
        validate_policy(&policy, &exact).unwrap();
    }
    #[test]
    fn semantic_options_are_frozen_scope_policy_not_per_observe_input() {
        let mut policy = ReadPolicy {
            frame_policy: observation::ObservationFramePolicy::configured(Some(
                "app.example".into(),
            )),
            test_id_attribute: "data-testid".into(),
            secure_field_selector: "input[type=password],.private".into(),
        };
        let captured = policy.clone();
        let options = captured.observation_options();
        policy.frame_policy =
            observation::ObservationFramePolicy::configured(Some("other.example".into()));
        assert_eq!(options.frame_policy, captured.frame_policy);
        assert_ne!(options.frame_policy, policy.frame_policy);
        for key in ["site", "framePolicy", "maxFrameDepth", "omittedFrames"] {
            let mut args = json!({"options":{},"testIdAttribute":"data-testid","secureFieldSelector":"input[type=password],.private"});
            args[key] = json!("other.example");
            assert!(serde_json::from_value::<ObserveRequest>(args).is_err());
            let mut args = json!({"options":{},"testIdAttribute":"data-testid","secureFieldSelector":"input[type=password],.private"});
            args["options"][key] = json!("other.example");
            assert!(serde_json::from_value::<ObserveRequest>(args).is_err());
        }
        let request: ObserveRequest = serde_json::from_value(json!({"options":{},"testIdAttribute":"data-testid","secureFieldSelector":"input[type=password],.private"})).unwrap();
        validate_policy(&captured, &DispatchRequest::Observe(request)).unwrap();
        assert_eq!(
            captured.observation_options().frame_policy,
            options.frame_policy
        );
    }
    #[test]
    fn wire_observe_flags_do_not_grant_fixture_read_authority() {
        assert!(serde_json::from_value::<ObserveFlags>(json!({"purpose":"fixture"})).is_err());
        let flags: ObserveFlags = serde_json::from_value(json!({"pixelFallback":true})).unwrap();
        assert!(flags.pixel_fallback);
        assert!(!flags.pixels);
    }
    #[test]
    fn atomic_inventory_first_failure_survives_cleanup_and_is_consumed_once() {
        let witness =
            ScreenshotFailureWitness::new(&diagnostic_trace(), &operation(), true).unwrap();
        let fact = diagnostic::FrameInventoryRejection {
            pass: diagnostic::FrameInventoryPass::Protected,
            sealed: false,
            revision_mismatch: true,
            reservations: false,
            delta: Some(1),
            events: Some([0, 0, 1, 0, 0, 0, 0]),
            exact: true,
            last_event: diagnostic::InventoryRevisionEvent::Info,
            last_target: diagnostic::InventoryRevisionTarget::Same,
        };
        witness.inventory_failure(Some(fact), &ProtocolError::StaleScope);
        witness.enter(ScreenshotStage::Restoration);
        witness.failure(&ProtocolError::CleanupFailed);
        witness.inventory_failure(
            Some(diagnostic::FrameInventoryRejection {
                sealed: true,
                ..fact
            }),
            &ProtocolError::CleanupFailed,
        );
        let first = witness.take_failure(|| None).unwrap();
        assert_eq!(first.stage, ScreenshotStage::FrameInventoryFence);
        assert_eq!(first.error, ProtocolError::StaleScope);
        assert_eq!(
            witness.state.lock().unwrap().inventory_rejection.take(),
            Some(fact)
        );
        assert!(witness.take_failure(|| None).is_none());
        assert!(witness
            .state
            .lock()
            .unwrap()
            .inventory_rejection
            .take()
            .is_none());
    }
}

#[cfg(test)]
#[path = "client_frame_inventory_tests.rs"]
mod frame_inventory_tests;

#[cfg(test)]
#[path = "client_trace_initial_inventory_tests.rs"]
mod trace_initial_inventory_tests;
