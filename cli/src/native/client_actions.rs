//! Exact-reference action execution for one negotiated scope. No selector
//! fallback, second identity registry, or renderer handles cross the wire.
//! The owner retains execution and cleanup through cancellation, and quarantines
//! Unknown effects before disposing the original context.
use super::client_blobs::{ArtifactReservation, AttemptArtifacts, BlobLease, BlobScope, BlobStore};
use super::client_browser::BrowserExecutionLease;
use super::client_debt::{self, CommandCategory, OperationJournalHandle};
use super::client_geometry::{GeometryError, GeometrySnapshot, Point as GeometryPoint};
use super::client_observation::NodeReference;
use super::client_page::ClientPageState;
use super::client_protocol::{Effects, ProtocolError};
use super::client_session::{CancelSignal, OperationLease};
use super::client_settlement_trace::{
    self as diagnostic, ReadonlyAck, ReadonlyCleanup, ReadonlyPrepareFailure, ReadonlyWindow,
};
use super::element::{self, ExactBinding, RefMap};
use super::recording::{self, CaptureOptions, RecordingOptions, RecordingState};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, OnceLock,
};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionReason {
    InterceptedPointer,
    CheckedStateUnchanged,
    ControlReplacedAfterClick,
}
#[derive(Debug)]
pub struct ActionFailure {
    pub error: ProtocolError,
    pub effects: Effects,
    pub cleanup_failed: bool,
    pub reason: Option<ActionReason>,
}
#[derive(Default)]
struct Dispatch {
    sent: AtomicBool,
    cleanup: AtomicBool,
    intercepted: AtomicBool,
    checked_unchanged: AtomicBool,
    checked_replaced: AtomicBool,
    acknowledged_postcondition: AtomicBool,
    settled_replacement_prefix: Mutex<Option<Arc<SettledReplacementPrefix>>>,
    preparation_enabled: AtomicBool,
    preparation_refusal: AtomicBool,
    preparation_stopped: AtomicBool,
    preparation_disqualified: AtomicBool,
    // A read-only Swipe refusal is never the Tap's settled mutation prefix.
    readonly_preparation_enabled: AtomicBool,
    readonly_preparation_refusal: AtomicBool,
    readonly_preparation_stopped: AtomicBool,
    readonly_preparation_disqualified: AtomicBool,
    readonly_timing: OnceLock<Mutex<Option<ReadonlyPrepareTiming>>>,
    #[cfg(test)]
    preparation_trace: Mutex<tests::PreparationTrace>,
}
// Optional scalar observations only. No receipt, authority, or clock estimate
// from this cell participates in preparation or settlement decisions.
struct ReadonlyPrepareTiming {
    entry_us: u64,
    ack_us: Option<u64>,
    ack: ReadonlyAck,
    wake_us: Option<u64>,
    fail_us: Option<u64>,
    window: ReadonlyWindow,
}
fn diagnostic_us(duration: Duration) -> u64 {
    duration.as_micros().min(60_000_000) as u64
}
impl Dispatch {
    fn start_readonly_timing(&self, deadline: Instant, enabled: bool) {
        if enabled && self.readonly_preparation_enabled.load(Ordering::SeqCst) {
            self.readonly_timing.get_or_init(|| {
                Mutex::new(Some(ReadonlyPrepareTiming {
                    entry_us: diagnostic_us(deadline.saturating_duration_since(Instant::now())),
                    ack_us: None,
                    ack: ReadonlyAck::None,
                    wake_us: None,
                    fail_us: None,
                    window: ReadonlyWindow::NotEntered,
                }))
            });
        }
    }
    fn update_readonly_timing(&self, update: impl FnOnce(&mut ReadonlyPrepareTiming)) {
        if let Some(cell) = self.readonly_timing.get() {
            if let Ok(mut timing) = cell.lock() {
                if let Some(timing) = timing.as_mut() {
                    update(timing);
                }
            }
        }
    }
    fn readonly_timing_failure(
        &self,
        deadline: Instant,
        result: &Result<Value, ActionFailure>,
    ) -> Option<ReadonlyPrepareFailure> {
        let timing = self.readonly_timing.get()?.lock().ok()?.take()?;
        let failure = result.as_ref().err()?;
        // sent is set before every application mutation submission. A later
        // successful probe or input path must not become no-box failure evidence.
        if self.sent.load(Ordering::SeqCst) {
            return None;
        }
        Some(ReadonlyPrepareFailure {
            entry_us: timing.entry_us,
            ack_us: timing.ack_us,
            ack: if timing.ack == ReadonlyAck::Current
                && (!self.readonly_preparation_refusal.load(Ordering::SeqCst)
                    || self
                        .readonly_preparation_disqualified
                        .load(Ordering::SeqCst))
            {
                ReadonlyAck::Retired
            } else {
                timing.ack
            },
            wake_us: timing.wake_us,
            fail_us: timing.fail_us,
            window: timing.window,
            deadline: Instant::now() >= deadline,
            zero_input: true,
            cleanup: if failure.cleanup_failed {
                ReadonlyCleanup::FailureObserved
            } else {
                ReadonlyCleanup::NotObserved
            },
            error: failure.error.clone(),
        })
    }
    fn begin_preparation_attempt(&self) {
        // Even a read invalidates the previous attempt's refusal receipt.
        self.preparation_refusal.store(false, Ordering::SeqCst);
        self.readonly_preparation_refusal
            .store(false, Ordering::SeqCst);
        self.update_readonly_timing(|timing| {
            if timing.ack == ReadonlyAck::Current {
                timing.ack = ReadonlyAck::Retired;
            }
        });
    }
    fn mark(&self) {
        self.mark_mutation(false);
    }
    fn mark_mutation(&self, preparation: bool) {
        self.readonly_preparation_refusal
            .store(false, Ordering::SeqCst);
        self.readonly_preparation_disqualified
            .store(true, Ordering::SeqCst);
        self.preparation_refusal.store(false, Ordering::SeqCst);
        if !preparation {
            self.preparation_disqualified.store(true, Ordering::SeqCst);
        }
        // A prefix cannot describe any later mutation, including its pending ACK.
        match self.settled_replacement_prefix.lock() {
            Ok(mut prefix) => *prefix = None,
            Err(_) => self.cleanup.store(true, Ordering::SeqCst),
        }
        self.sent.store(true, Ordering::SeqCst);
    }
    fn failure(&self, error: ProtocolError) -> ActionFailure {
        // A reason refines a semantic refusal, never an authority, transport,
        // or cleanup error from a later attempt in the same action.
        let semantic_refusal = error == ProtocolError::NotActionable;
        ActionFailure {
            error,
            cleanup_failed: self.cleanup.load(Ordering::SeqCst),
            reason: if !semantic_refusal {
                None
            } else if self.intercepted.load(Ordering::SeqCst) {
                Some(ActionReason::InterceptedPointer)
            } else if self.checked_replaced.load(Ordering::SeqCst) {
                Some(ActionReason::ControlReplacedAfterClick)
            } else if self.checked_unchanged.load(Ordering::SeqCst) {
                Some(ActionReason::CheckedStateUnchanged)
            } else {
                None
            },
            effects: if self.acknowledged_postcondition.load(Ordering::SeqCst)
                && !self.cleanup.load(Ordering::SeqCst)
            {
                Effects::Completed
            } else if self.sent.load(Ordering::SeqCst) {
                Effects::Unknown
            } else {
                Effects::NotDispatched
            },
        }
    }
}
/// A completed prefix is not successful replacement or rollback. It certifies
/// only whole, acknowledged select-all/Delete substeps on this exact action's
/// immutable page lease. Capture authority once before select-all and never
/// rebase it at Delete. Install it in Dispatch only after the entire keyboard
/// future has returned successfully.
struct SettledReplacementPrefix {
    identity_scope: String,
    session: String,
    target: String,
    generation: u64,
    sequence: u64,
    target_revision: u64,
    enrollment: Option<super::client_enrollment::SettledInputAuthority>,
}
impl SettledReplacementPrefix {
    fn capture(ctx: &ActionContext<'_>) -> Result<Self, ProtocolError> {
        ctx.check()?;
        if ctx.page.targets.identity_scope != ctx.page.identity_scope {
            return Err(ProtocolError::StaleScope);
        }
        let (target_revision, targets) = ctx.page.targets.inventory()?;
        let enrollment = match ctx.realm_authority {
            ActionRealmAuthority::Enrolled(owner) => {
                if !targets.iter().any(|target| {
                    target.target_id == ctx.page.target_id
                        && target.session_id == ctx.page.page_session_id
                        && target.configured
                        && target.resumed
                        && target.purpose == Some(super::client_targets::TargetPurpose::Application)
                }) {
                    return Err(ProtocolError::StaleScope);
                }
                Some(owner.capture_settled_input_authority(ctx.page, ctx.operation)?)
            }
            #[cfg(test)]
            ActionRealmAuthority::UntrackedFixture => None,
        };
        Ok(Self {
            identity_scope: ctx.page.identity_scope.clone(),
            session: ctx.page.page_session_id.clone(),
            target: ctx.page.target_id.clone(),
            generation: ctx.operation.generation,
            sequence: ctx.operation.sequence,
            target_revision,
            enrollment,
        })
    }
    /// Ignore requested cancellation only: it is the result being certified.
    /// The original permit still fences the exact scope epoch.
    fn check(&self, ctx: &ActionContext<'_>) -> Result<(), ProtocolError> {
        ctx.page.permit.check()?;
        if *ctx.page.client.remote_connection_closed().borrow() {
            return Err(ProtocolError::BrowserFailure);
        }
        if self.identity_scope != ctx.page.identity_scope
            || self.identity_scope != ctx.page.targets.identity_scope
            || self.session != ctx.page.page_session_id
            || self.target != ctx.page.target_id
            || self.generation != ctx.operation.generation
            || self.sequence != ctx.operation.sequence
        {
            return Err(ProtocolError::StaleScope);
        }
        ctx.page.targets.check_revision(self.target_revision)?;
        match (&self.enrollment, &ctx.realm_authority) {
            (Some(proof), ActionRealmAuthority::Enrolled(owner)) => {
                proof.check(owner, ctx.page, ctx.operation)
            }
            #[cfg(test)]
            (None, ActionRealmAuthority::UntrackedFixture) => Ok(()),
            _ => Err(ProtocolError::StaleScope),
        }
    }
}
async fn settle_replacement_cancellation(ctx: &ActionContext<'_>, d: &Dispatch) -> bool {
    let prefix = match d.settled_replacement_prefix.lock() {
        Ok(mut prefix) => prefix.take(),
        Err(_) => {
            d.cleanup.store(true, Ordering::SeqCst);
            return false;
        }
    };
    let Some(prefix) = prefix else { return false };
    // Retain mandatory key/button cleanup even though the cancelled operation
    // cannot dispatch another substep. Cleanup has its own existing budget.
    let authority = prefix.check(ctx);
    if ctx.page_state.release_input(ctx.page).await.is_err() {
        d.cleanup.store(true, Ordering::SeqCst);
        return false;
    }
    authority.is_ok()
        && prefix.check(ctx).is_ok()
        && *ctx.operation.cancellation.borrow() == CancelSignal::Requested
        && !d.cleanup.load(Ordering::SeqCst)
}
fn finish_dispatch(
    d: &Dispatch,
    result: Result<Value, ProtocolError>,
) -> Result<Value, ActionFailure> {
    match result {
        Ok(_) if d.cleanup.load(Ordering::SeqCst) => Err(d.failure(ProtocolError::CleanupFailed)),
        result => result.map_err(|error| d.failure(error)),
    }
}
pub enum ActionRealmAuthority<'a> {
    Enrolled(&'a Arc<super::client_enrollment::ClientEnrollment>),
    #[cfg(test)]
    UntrackedFixture,
}
pub struct ActionContext<'a> {
    pub realm_authority: ActionRealmAuthority<'a>,
    pub page: &'a BrowserExecutionLease,
    pub operation: &'a OperationLease,
    pub page_state: &'a ClientPageState,
    pub refs: &'a RefMap,
    pub revision: u64,
    pub observation_after: Option<u64>,
    pub observed_revision: u64,
    pub iframe_sessions: &'a HashMap<String, String>,
    pub observation_frames: &'a [super::client_observation::ObservationFrame],
    pub blobs: &'a BlobStore,
    pub geometry: &'a GeometrySnapshot,
}
impl ActionContext<'_> {
    fn check(&self) -> Result<(), ProtocolError> {
        self.page.permit.check()?;
        if let Some(journal) = OperationJournalHandle::current() {
            journal.check_application_submission()?;
        }
        if *self.operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= self.operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(())
    }
    fn blob_scope(&self) -> BlobScope {
        BlobScope {
            generation: self.operation.generation,
            identity_scope: self.page.identity_scope.clone(),
        }
    }
    async fn bounded<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, String>>,
    ) -> Result<T, ProtocolError> {
        self.check()?;
        let mut cancel = self.operation.cancellation.clone();
        tokio::select! {
            value=future=>{self.check()?;value.map_err(|_|ProtocolError::BrowserFailure)},
            _=cancel.changed()=>Err(ProtocolError::Cancelled),
            _=tokio::time::sleep_until(self.operation.deadline.into())=>Err(ProtocolError::DeadlineExceeded),
        }
    }
    async fn command(
        &self,
        dispatch: &Dispatch,
        mutation: bool,
        session: &str,
        method: &str,
        args: Value,
    ) -> Result<Value, ProtocolError> {
        self.check()?;
        if mutation {
            dispatch.mark_mutation(method == "DOM.scrollIntoViewIfNeeded");
        }
        let category = if method.starts_with("Input.") {
            CommandCategory::ApplicationInput
        } else if method.starts_with("DOM.") || method.starts_with("Runtime.") {
            CommandCategory::ApplicationObject
        } else {
            CommandCategory::ApplicationRead
        };
        let command = client_debt::command_scope(
            category,
            mutation,
            self.page
                .client
                .send_command(method, Some(args), Some(session)),
        );
        let mut cancel = self.operation.cancellation.clone();
        tokio::select! {
            value = command => {
                // Transfer actual resource replies to their exact owning helper
                // before a cancellation check can discard cleanup authority.
                if !super::client_observation::produces_remote_objects(method) { self.check()?; }
                value.map_err(|_| ProtocolError::BrowserFailure)
            },
            _ = cancel.changed() => Err(ProtocolError::Cancelled),
            _ = tokio::time::sleep_until(self.operation.deadline.into()) => Err(ProtocolError::DeadlineExceeded),
        }
    }
    async fn pause(&self, duration: Duration) -> Result<(), ProtocolError> {
        self.check()?;
        let mut cancel = self.operation.cancellation.clone();
        tokio::select! {
            _=tokio::time::sleep(duration)=>self.check(),
            _=cancel.changed()=>Err(ProtocolError::Cancelled),
            _=tokio::time::sleep_until(self.operation.deadline.into())=>Err(ProtocolError::DeadlineExceeded),
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Point {
    x: f64,
    y: f64,
}
impl Point {
    fn validate(self) -> Result<Self, ProtocolError> {
        if self.x.is_finite() && self.y.is_finite() {
            Ok(Self {
                x: self.x.round(),
                y: self.y.round(),
            })
        } else {
            Err(ProtocolError::InvalidArguments)
        }
    }
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Direction {
    Up,
    Down,
    Left,
    Right,
}
#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Momentum {
    #[default]
    None,
    Slow,
    Fast,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Selection {
    LabelString(String),
    Exact(SelectionObject),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionObject {
    label: Option<String>,
    value: Option<String>,
    index: Option<usize>,
}
impl Selection {
    fn wire(&self) -> Result<Value, ProtocolError> {
        match self {
            Self::LabelString(label) => Ok(json!({"label":label})),
            Self::Exact(s) => {
                if usize::from(s.label.is_some())
                    + usize::from(s.value.is_some())
                    + usize::from(s.index.is_some())
                    != 1
                {
                    return Err(ProtocolError::InvalidArguments);
                }
                Ok(if let Some(label) = &s.label {
                    json!({"label":label})
                } else if let Some(value) = &s.value {
                    json!({"value":value})
                } else {
                    json!({"index":s.index})
                })
            }
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UploadFile {
    name: String,
    mime_type: String,
    body_handle: String,
    relative_path: Option<String>,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum LocatorAction {
    Tap {
        modifiers: Option<Vec<String>>,
    },
    DoubleTap {
        modifiers: Option<Vec<String>>,
    },
    SecondaryTap {
        modifiers: Option<Vec<String>>,
    },
    Check,
    Uncheck,
    Clear,
    Focus,
    Hover,
    ScrollIntoView,
    LongPress {
        #[serde(rename = "durationMs")]
        duration_ms: Option<u64>,
    },
    Fill {
        value: String,
        sensitive: bool,
    },
    Press {
        key: String,
    },
    SelectOption {
        value: Selection,
    },
    SetInputFiles {
        #[serde(rename = "directoryName")]
        directory_name: Option<String>,
        files: Vec<UploadFile>,
    },
    DragTo {
        target: NodeReference,
    },
    Swipe {
        direction: Direction,
        #[serde(default)]
        momentum: Momentum,
    },
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum PointerAction {
    Tap,
    DoubleTap,
    SecondaryTap,
    Hover,
    LongPress {
        #[serde(rename = "durationMs")]
        duration_ms: Option<u64>,
    },
    DragTo {
        target: Point,
    },
    Swipe {
        direction: Direction,
        #[serde(default)]
        momentum: Momentum,
    },
    SwipeTo {
        target: Point,
        #[serde(rename = "durationMs")]
        duration_ms: Option<u64>,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Perform {
    identity_scope: String,
    #[serde(rename = "ref")]
    reference: NodeReference,
    action: LocatorAction,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pointer {
    identity_scope: String,
    point: Point,
    action: PointerAction,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyboardType {
    identity_scope: String,
    text: String,
    replace: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyboardPress {
    identity_scope: String,
    key: String,
}
fn decode<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, ProtocolError> {
    serde_json::from_value(v.clone()).map_err(|_| ProtocolError::InvalidArguments)
}
fn scope(ctx: &ActionContext<'_>, identity: &str) -> Result<(), ProtocolError> {
    ctx.check()?;
    if ctx.page.identity_scope != identity {
        Err(ProtocolError::StaleScope)
    } else {
        Ok(())
    }
}
fn reference<'a>(
    ctx: &'a ActionContext<'_>,
    r: &NodeReference,
) -> Result<(&'a element::RefEntry, ExactBinding), ProtocolError> {
    let id = element::parse_ref(&r.id).ok_or(ProtocolError::InvalidArguments)?;
    let entry = ctx.refs.get(&id).ok_or(ProtocolError::StaleReference)?;
    if !entry.matches_reference(
        &ctx.page.identity_scope,
        ctx.operation.generation,
        &ctx.page.page_session_id,
        &r.revision,
    ) {
        return Err(ProtocolError::StaleReference);
    }
    if entry.kind == element::NativeReferenceKind::ReadOnlyCssPseudo {
        return Err(ProtocolError::NotActionable);
    }
    let binding = entry
        .exact_binding
        .clone()
        .ok_or(ProtocolError::StaleReference)?;
    if binding.page_session != ctx.page.page_session_id {
        return Err(ProtocolError::StaleReference);
    }
    Ok((entry, binding))
}
/// Only an exact, pre-reserved object-release command may become retained
/// release debt. This helper is never used for source-mask/security restoration.
pub(crate) async fn release_object_accounted(
    client: &super::cdp::client::CdpClient,
    session: &str,
    object: &str,
) -> bool {
    release_accounted(
        client,
        session,
        "Runtime.releaseObject",
        json!({"objectId":object}),
    )
    .await
}
/// Ownership release only. Source-mask/security restoration must use strict ACKs.
pub(crate) async fn release_group_accounted(
    client: &super::cdp::client::CdpClient,
    session: &str,
    group: &str,
) -> bool {
    release_accounted(
        client,
        session,
        "Runtime.releaseObjectGroup",
        json!({"objectGroup":group}),
    )
    .await
}
#[derive(Clone, Copy, Default)]
struct ObjectReleaseOutcome {
    // Preserve the existing ownership-transfer contract for every old caller.
    accepted: bool,
    // New refusal evidence requires an exact settled command, not retained debt.
    settled: bool,
}
async fn release_object_outcome(
    client: &super::cdp::client::CdpClient,
    session: &str,
    object: &str,
) -> ObjectReleaseOutcome {
    release_outcome(
        client,
        session,
        "Runtime.releaseObject",
        json!({"objectId":object}),
    )
    .await
}
async fn release_accounted(
    client: &super::cdp::client::CdpClient,
    session: &str,
    method: &str,
    params: Value,
) -> bool {
    release_outcome(client, session, method, params)
        .await
        .accepted
}
async fn release_outcome(
    client: &super::cdp::client::CdpClient,
    session: &str,
    method: &str,
    params: Value,
) -> ObjectReleaseOutcome {
    client_debt::command_scope(
        CommandCategory::CleanupObject,
        false,
        release_accounted_inner(client, session, method, params),
    )
    .await
}
async fn release_accounted_inner(
    client: &super::cdp::client::CdpClient,
    session: &str,
    method: &str,
    params: Value,
) -> ObjectReleaseOutcome {
    let reservation = match client.reserve_tracked_command(method, Some(&params), Some(session)) {
        Ok(reservation) => reservation,
        Err(_) => return ObjectReleaseOutcome::default(),
    };
    let status = reservation.as_ref().map(|reservation| reservation.status());
    let result = tokio::time::timeout(
        Duration::from_millis(250),
        client.send_reserved_command(method, Some(params), Some(session), reservation),
    )
    .await;
    ObjectReleaseOutcome {
        accepted: matches!(result, Ok(Ok(_)))
            || (status
                .as_ref()
                .is_some_and(|status| status.settled() || status.accountably_retained())
                && client
                    .debt_ledger()
                    .is_some_and(|ledger| !ledger.snapshot().integrity_lost)),
        // The transport may deliver a successful envelope even after rejecting
        // its session identity. Neither that value nor absent tracking is proof.
        settled: status.as_ref().is_some_and(|status| status.settled())
            && client
                .debt_ledger()
                .is_some_and(|ledger| !ledger.snapshot().integrity_lost),
    }
}
struct Resolved {
    realm: Option<super::client_enrollment::ExactRealmTicket>,
    object: String,
    session: String,
    binding: ExactBinding,
}
impl Resolved {
    async fn release_settled(&self, ctx: &ActionContext<'_>) -> Result<(), ProtocolError> {
        if self
            .realm
            .as_ref()
            .is_some_and(|realm| realm.destroyed() == Ok(true))
        {
            return Ok(());
        }
        if release_object_outcome(&ctx.page.client, &self.session, &self.object)
            .await
            .settled
            || self
                .realm
                .as_ref()
                .is_some_and(|realm| realm.destroyed() == Ok(true))
        {
            Ok(())
        } else {
            Err(ProtocolError::CleanupFailed)
        }
    }
    async fn release(&self, ctx: &ActionContext<'_>) -> Result<(), ProtocolError> {
        if self
            .realm
            .as_ref()
            .is_some_and(|realm| realm.destroyed() == Ok(true))
        {
            return Ok(());
        }
        if release_object_accounted(&ctx.page.client, &self.session, &self.object).await {
            return Ok(());
        }
        // Failed release is not evidence. Only the captured native realm's
        // authoritative destruction can settle its now-invalid handles.
        if self
            .realm
            .as_ref()
            .is_some_and(|realm| realm.destroyed() == Ok(true))
        {
            return Ok(());
        }
        Err(ProtocolError::CleanupFailed)
    }
    async fn call(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        mutation: bool,
        source: &str,
        args: Vec<Value>,
    ) -> Result<Value, ProtocolError> {
        let result=ctx.command(d,mutation,&self.session,"Runtime.callFunctionOn",json!({"objectId":self.object,"functionDeclaration":source,"arguments":args.into_iter().map(|value|json!({"value":value})).collect::<Vec<_>>(),"returnByValue":true,"awaitPromise":true})).await?;
        let released =
            release_call_handles(ctx, d, &self.session, &result, Some(&self.object)).await;
        if result.get("exceptionDetails").is_some() {
            return Err(ProtocolError::BrowserFailure);
        }
        released?;
        // Object-producing replies transfer cleanup ownership before checking
        // authority. After that cleanup, the original lease must still permit
        // interpretation: a late semantic refusal cannot hide stale/cancelled
        // authority or become a public action reason for a retired operation.
        ctx.check()?;
        let value = result["result"]["value"].clone();
        match value["status"].as_str() {
            Some("stale") => Err(ProtocolError::StaleReference),
            Some("intercepted-pointer") => {
                d.intercepted.store(true, Ordering::SeqCst);
                Err(ProtocolError::NotActionable)
            }
            Some("not-actionable") => Err(ProtocolError::NotActionable),
            Some("invalid") => Err(ProtocolError::InvalidArguments),
            _ => Ok(value),
        }
    }
}
async fn release_call_handles(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    session: &str,
    result: &Value,
    retained: Option<&str>,
) -> Result<(), ProtocolError> {
    let mut seen = HashSet::new();
    let mut failed = false;
    for object in [
        result["result"]["objectId"].as_str(),
        result["exceptionDetails"]["exception"]["objectId"].as_str(),
    ]
    .into_iter()
    .flatten()
    {
        if Some(object) == retained || !seen.insert(object) {
            continue;
        }
        let release = release_object_outcome(&ctx.page.client, session, object).await;
        failed |= !release.accepted;
        if !release.settled && d.readonly_preparation_enabled.load(Ordering::SeqCst) {
            // An earlier retained auxiliary object cannot be washed out by a
            // later probe which happens to return no object handles.
            d.readonly_preparation_disqualified
                .store(true, Ordering::SeqCst);
            d.readonly_preparation_refusal
                .store(false, Ordering::SeqCst);
        }
    }
    if failed {
        d.cleanup.store(true, Ordering::SeqCst);
        Err(ProtocolError::CleanupFailed)
    } else {
        Ok(())
    }
}
fn exact_resolution_error(d: &Dispatch, error: element::ExactResolutionError) -> ProtocolError {
    match error {
        element::ExactResolutionError::StaleReference
        | element::ExactResolutionError::Superseded => ProtocolError::StaleReference,
        element::ExactResolutionError::BackendFailure => ProtocolError::BrowserFailure,
        element::ExactResolutionError::CleanupFailed { primary } => {
            d.cleanup.store(true, Ordering::SeqCst);
            primary.map_or(ProtocolError::CleanupFailed, |error| {
                exact_resolution_error(d, *error)
            })
        }
    }
}
async fn resolve_action_object(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    binding: &ExactBinding,
    backend: i64,
) -> Result<String, ProtocolError> {
    resolve_action_object_in_realm(ctx, d, binding, backend, None).await
}
async fn resolve_action_object_in_realm(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    binding: &ExactBinding,
    backend: i64,
    context: Option<i64>,
) -> Result<String, ProtocolError> {
    ctx.check()?;
    let future = async {
        match context {
            Some(context) => {
                element::resolve_exact_object_in_realm_typed(
                    &ctx.page.client,
                    binding,
                    backend,
                    context,
                )
                .await
            }
            None => element::resolve_exact_object_typed(&ctx.page.client, binding, backend).await,
        }
    };
    tokio::pin!(future);
    let mut cancellation = ctx.operation.cancellation.clone();
    let outcome = tokio::select! {
        result=&mut future => Ok(result),
        _=cancellation.changed()=>Err(ProtocolError::Cancelled),
        _=tokio::time::sleep_until(ctx.operation.deadline.into())=>Err(ProtocolError::DeadlineExceeded),
    };
    let (result, interrupted) = match outcome {
        Ok(result) => (result, None),
        Err(primary) => match tokio::time::timeout(Duration::from_millis(250), &mut future).await {
            Ok(result) => (result, Some(primary)),
            Err(_) => {
                if !OperationJournalHandle::current()
                    .is_some_and(|journal| journal.has_accounted_object_creation(&binding.session))
                {
                    d.cleanup.store(true, Ordering::SeqCst);
                }
                return Err(primary);
            }
        },
    };
    let object = match result {
        Ok(object) => object,
        Err(error) => {
            if interrupted.is_some() {
                d.cleanup.store(true, Ordering::SeqCst);
            }
            let primary = exact_resolution_error(d, error);
            return Err(interrupted.unwrap_or(primary));
        }
    };
    if let Some(primary) = interrupted.or_else(|| ctx.check().err()) {
        if !release_object_accounted(&ctx.page.client, &binding.session, &object).await {
            d.cleanup.store(true, Ordering::SeqCst);
        }
        return Err(primary);
    }
    Ok(object)
}
fn live_query_error(
    d: &Dispatch,
    error: super::client_observation::ObservationError,
) -> ProtocolError {
    use super::client_observation::ObservationError;
    match error {
        ObservationError::CleanupFailed { primary } => {
            d.cleanup.store(true, Ordering::SeqCst);
            primary.map_or(ProtocolError::CleanupFailed, |error| {
                live_query_error(d, *error)
            })
        }
        ObservationError::ResourceLimit => ProtocolError::CapacityExceeded,
        ObservationError::InvalidArguments => ProtocolError::InvalidArguments,
        ObservationError::UnsupportedCapability => ProtocolError::UnsupportedCapability,
        ObservationError::StaleReference
        | ObservationError::Superseded
        | ObservationError::FrameNotFound(_)
        | ObservationError::FrameAmbiguous(_) => ProtocolError::StaleReference,
        ObservationError::Cancelled => ProtocolError::Cancelled,
        ObservationError::DeadlineExceeded => ProtocolError::DeadlineExceeded,
        ObservationError::BackendFailure => ProtocolError::BrowserFailure,
        ObservationError::PolicyDenied => ProtocolError::PolicyDenied,
    }
}
async fn resolve(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    r: &NodeReference,
) -> Result<Resolved, ProtocolError> {
    let (entry, acquisition) = reference(ctx, r)?;
    let (binding, backend) = if let Some(origin) = &entry.live_query {
        // Keep the evaluator alive through cancellation so its object groups
        // settle. Never validate or resolve the captured backend first.
        let resolved = super::client_observation::resolve_live_query(
            &ctx.page.client,
            ctx.observation_frames,
            origin,
            &acquisition,
            ctx.operation,
        )
        .await
        .map_err(|error| live_query_error(d, error))?;
        ctx.check()?;
        (resolved.binding, resolved.backend_node_id)
    } else {
        (
            acquisition,
            entry.backend_node_id.ok_or(ProtocolError::StaleReference)?,
        )
    };
    ctx.bounded(async {
        Ok(element::validate_exact_binding_typed(
            &ctx.page.client,
            &ctx.page.page_session_id,
            &binding,
        )
        .await)
    })
    .await?
    .map_err(|error| exact_resolution_error(d, error))?;
    let (context, realm) = match &ctx.realm_authority {
        ActionRealmAuthority::Enrolled(enrollment) => {
            let capture = enrollment.reserve_exact_realm(ctx.page, &binding, ctx.operation)?;
            let context = ctx
                .bounded(async {
                    Ok(element::create_exact_realm(&ctx.page.client, &binding).await)
                })
                .await?
                .map_err(|error| exact_resolution_error(d, error))?;
            let realm = capture.bind(context, ctx.operation).await?;
            ctx.check()?;
            if realm.destroyed()? {
                return Err(ProtocolError::StaleReference);
            }
            (Some(context), Some(realm))
        }
        #[cfg(test)]
        ActionRealmAuthority::UntrackedFixture => (None, None),
    };
    let object = resolve_action_object_in_realm(ctx, d, &binding, backend, context).await?;
    if let Some(ticket) = &realm {
        if let Err(primary) = ticket.verify_resolution_owner(ctx.operation).await {
            // Numeric context-ID reuse makes this handle's realm uncertain.
            // Do not attach the old ticket or waive release using its destruction.
            if !release_object_accounted(&ctx.page.client, &binding.session, &object).await {
                d.cleanup.store(true, Ordering::SeqCst);
            }
            return Err(primary);
        }
    }
    Ok(Resolved {
        realm,
        object,
        session: binding.session.clone(),
        binding,
    })
}

/// Upload directories and recording tasks remain owned beyond an interrupted
/// RPC. The scope owner must await cleanup before disposing its context.
pub struct ClientActions {
    uploads: tokio::sync::Mutex<Vec<UploadResource>>,
    recording: tokio::sync::Mutex<RecordingLedger>,
}
impl Default for ClientActions {
    fn default() -> Self {
        Self {
            uploads: tokio::sync::Mutex::new(Vec::new()),
            recording: tokio::sync::Mutex::new(RecordingLedger::default()),
        }
    }
}
impl ClientActions {
    /// Validate without activating a borrowed page or mutating attempt state.
    pub(crate) fn validate_recording_start(
        identity_scope: &str,
        args: &Value,
    ) -> Result<(), ProtocolError> {
        let request: RecordingStart = decode(args)?;
        if request.identity_scope != identity_scope {
            return Err(ProtocolError::StaleScope);
        }
        request.capture_options(None).map(|_| ())
    }
    pub async fn execute(
        &self,
        ctx: ActionContext<'_>,
        name: &str,
        args: &Value,
    ) -> Result<Value, ActionFailure> {
        let d = Dispatch::default();
        let result = self.execute_inner(&ctx, &d, name, args).await;
        let settled_prefix = matches!(&result, Err(ProtocolError::Cancelled))
            && settle_replacement_cancellation(&ctx, &d).await;
        if result.is_err()
            && OperationJournalHandle::current().is_some()
            && ctx.page_state.release_input(ctx.page).await.is_err()
        {
            d.cleanup.store(true, Ordering::SeqCst);
        }
        #[cfg(test)]
        tests::emit_preparation_mismatch(&ctx, &d, &result);
        let result = finish_dispatch(&d, result).map_err(|mut failure| {
            if settled_prefix {
                failure.effects = Effects::Completed;
            }
            failure
        });
        if let Some(failure) = d.readonly_timing_failure(ctx.operation.deadline, &result) {
            diagnostic::readonly_prepare_failure(
                ctx.operation.generation,
                ctx.operation.sequence,
                failure,
            );
        }
        result
    }
    async fn execute_inner(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        name: &str,
        args: &Value,
    ) -> Result<Value, ProtocolError> {
        ctx.check()?;
        match name {
            "browser.perform" => {
                let request: Perform = decode(args)?;
                scope(ctx, &request.identity_scope)?;
                self.perform(ctx, d, request).await?;
            }
            "browser.pointer" => {
                let request: Pointer = decode(args)?;
                scope(ctx, &request.identity_scope)?;
                require_recovery_observation(ctx)?;
                self.pointer(ctx, d, request.point.validate()?, request.action)
                    .await?;
            }
            "browser.keyboard.type" => {
                let request: KeyboardType = decode(args)?;
                scope(ctx, &request.identity_scope)?;
                require_editable_focus(ctx, d).await?;
                ctx.check()?;
                if request.replace {
                    replacement_substep(ctx, d, ReplacementStep::SelectAll).await?;
                    ctx.check()?;
                    replacement_substep(ctx, d, ReplacementStep::Delete).await?;
                    ctx.check()?;
                }
                keyboard(ctx, d, "type", &request.text).await?;
            }
            "browser.keyboard.press" => {
                let request: KeyboardPress = decode(args)?;
                scope(ctx, &request.identity_scope)?;
                require_recovery_observation(ctx)?;
                keyboard(ctx, d, "press", &request.key).await?;
            }
            "recording.start" => {
                self.record_start(ctx, d, decode(args)?).await?;
            }
            "recording.stop" => return self.record_stop(ctx, d, decode(args)?).await,
            _ => return Err(ProtocolError::UnsupportedCommand),
        }
        ctx.check()?;
        Ok(Value::Null)
    }
}

/// The caller has admitted the exact page and owns both guards. There is no
/// DOM-reference or renderer geometry authority in this direct-input context.
pub(crate) struct DirectPointContext<'a> {
    pub page: &'a BrowserExecutionLease,
    pub operation: &'a OperationLease,
    pub page_state: &'a ClientPageState,
    pub journal: &'a OperationJournalHandle,
    pub ui: super::client_ui::UiPermit,
    pub input: tokio::sync::MutexGuard<'a, ()>,
}
struct DirectPointRunner<'a, 'b> {
    context: &'a DirectPointContext<'b>,
    attachment: super::client_targets::OwnedTarget,
    dispatch: Dispatch,
}
impl DirectPointRunner<'_, '_> {
    fn check(&self) -> Result<(), ProtocolError> {
        let ctx = self.context;
        ctx.page.permit.check()?;
        ctx.journal.check_application_submission()?;
        if ctx.journal.key().generation != ctx.operation.generation
            || ctx.journal.key().operation_seq != ctx.operation.sequence
            || ctx.page.identity_scope != ctx.page.targets.identity_scope
            || !ctx
                .page
                .targets
                .owned_target(&ctx.page.target_id)?
                .same_attachment(&self.attachment)
            || self.attachment.session_id != ctx.page.page_session_id
            || !self.attachment.configured
            || !self.attachment.resumed
            || self.attachment.purpose != Some(super::client_targets::TargetPurpose::Application)
        {
            return Err(ProtocolError::StaleScope);
        }
        if *ctx.operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= ctx.operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(())
    }
    async fn pause(&self, duration: Duration) -> Result<(), ProtocolError> {
        self.check()?;
        let mut cancel = self.context.operation.cancellation.clone();
        tokio::select! {
            _ = tokio::time::sleep(duration) => self.check(),
            _ = cancel.changed() => Err(ProtocolError::Cancelled),
            _ = tokio::time::sleep_until(self.context.operation.deadline.into()) => Err(ProtocolError::DeadlineExceeded),
        }
    }
    async fn event(
        &self,
        kind: &str,
        point: Point,
        button: Option<&str>,
        count: Option<i32>,
    ) -> Result<(), ProtocolError> {
        self.check()?;
        self.dispatch.mark();
        action_stage(match kind {
            "mousePressed" => "input.press.dispatch",
            "mouseReleased" => "input.release.dispatch",
            _ => "input.move.dispatch",
        });
        self.context
            .page_state
            .pointer_event(
                self.context.page,
                self.context.operation,
                kind,
                Some((point.x, point.y)),
                button,
                count,
                None,
            )
            .await?;
        self.check()
    }
    async fn click(
        &self,
        point: Point,
        button: &str,
        count: i32,
        hold: Duration,
    ) -> Result<(), ProtocolError> {
        self.event("mouseMoved", point, None, None).await?;
        for click in 1..=count {
            self.event("mousePressed", point, Some(button), Some(click))
                .await?;
            if !hold.is_zero() {
                self.pause(hold).await?;
            }
            self.event("mouseReleased", point, Some(button), Some(click))
                .await?;
        }
        Ok(())
    }
    async fn drag(
        &self,
        from: Point,
        to: Point,
        pace: Option<Duration>,
    ) -> Result<(), ProtocolError> {
        self.event("mouseMoved", from, None, None).await?;
        self.event("mousePressed", from, Some("left"), Some(1))
            .await?;
        let steps = pace
            .map(|pace| (pace.as_millis() / 16).max(2) as usize)
            .unwrap_or(2);
        let start = Instant::now();
        for step in 1..=steps {
            if let Some(pace) = pace {
                let due = start + pace.mul_f64(step as f64 / steps as f64);
                if let Some(wait) = due.checked_duration_since(Instant::now()) {
                    self.pause(wait).await?;
                }
            }
            let fraction = step as f64 / steps as f64;
            let point = Point {
                x: from.x + (to.x - from.x) * fraction,
                y: from.y + (to.y - from.y) * fraction,
            }
            .validate()?;
            self.event("mouseMoved", point, None, None).await?;
        }
        self.event("mouseReleased", to, Some("left"), Some(1)).await
    }
}
impl ClientActions {
    pub(crate) fn is_direct_point(args: &Value) -> Result<bool, ProtocolError> {
        let request: Pointer = decode(args)?;
        request.point.validate()?;
        match request.action {
            PointerAction::Swipe { .. } => Ok(false),
            PointerAction::LongPress { duration_ms } => {
                duration(duration_ms, 500)?;
                Ok(true)
            }
            PointerAction::DragTo { target } => {
                target.validate()?;
                Ok(true)
            }
            PointerAction::SwipeTo {
                target,
                duration_ms,
            } => {
                target.validate()?;
                duration(duration_ms, 0)?;
                Ok(true)
            }
            _ => Ok(true),
        }
    }
    pub(crate) async fn execute_direct_point(
        &self,
        context: DirectPointContext<'_>,
        args: &Value,
    ) -> Result<Value, ActionFailure> {
        // Taking guards by value keeps them alive through mandatory cleanup,
        // even when the RPC receiver or original command future is gone.
        let _guards = (&context.ui, &context.input);
        let journal = context.journal.clone();
        journal
            .scope(async {
                let d = Dispatch::default();
                let request: Pointer = decode(args).map_err(|error| d.failure(error))?;
                if request.identity_scope != context.page.identity_scope
                    || !Self::is_direct_point(args).map_err(|error| d.failure(error))?
                {
                    return Err(d.failure(ProtocolError::InvalidArguments));
                }
                let attachment = context
                    .page
                    .targets
                    .owned_target(&context.page.target_id)
                    .map_err(|error| d.failure(error))?;
                let runner = DirectPointRunner {
                    context: &context,
                    attachment,
                    dispatch: d,
                };
                let result = async {
                    runner.check()?;
                    let point = request.point.validate()?;
                    match request.action {
                        PointerAction::Tap => {
                            runner.click(point, "left", 1, Duration::ZERO).await?
                        }
                        PointerAction::DoubleTap => {
                            runner.click(point, "left", 2, Duration::ZERO).await?
                        }
                        PointerAction::SecondaryTap => {
                            runner.click(point, "right", 1, Duration::ZERO).await?
                        }
                        PointerAction::Hover => {
                            runner.event("mouseMoved", point, None, None).await?
                        }
                        PointerAction::LongPress { duration_ms } => {
                            runner
                                .click(point, "left", 1, duration(duration_ms, 500)?)
                                .await?
                        }
                        PointerAction::DragTo { target } => {
                            runner.drag(point, target.validate()?, None).await?
                        }
                        PointerAction::SwipeTo {
                            target,
                            duration_ms,
                        } => {
                            runner
                                .drag(
                                    point,
                                    target.validate()?,
                                    duration_ms
                                        .map(|value| duration(Some(value), 0))
                                        .transpose()?,
                                )
                                .await?
                        }
                        PointerAction::Swipe { .. } => return Err(ProtocolError::InvalidArguments),
                    }
                    runner.check()?;
                    Ok(Value::Null)
                }
                .await;
                if result.is_err()
                    && context
                        .page_state
                        .release_input(context.page)
                        .await
                        .is_err()
                {
                    runner.dispatch.cleanup.store(true, Ordering::SeqCst);
                }
                finish_dispatch(&runner.dispatch, result).map_err(|mut failure| {
                    // The transport journal, not entering the helper, proves a
                    // possible mutation. Reservations refused before send are clean.
                    failure.effects = if context.journal.snapshot().mutation_dispatched {
                        Effects::Unknown
                    } else {
                        Effects::NotDispatched
                    };
                    failure
                })
            })
            .await
    }
}

struct StagedUpload {
    directory: OwnedDirectory,
    paths: Vec<String>,
    _leases: Vec<BlobLease>,
    error: Option<ProtocolError>,
}
struct UploadResource {
    job: Option<tokio::task::JoinHandle<Result<StagedUpload, ProtocolError>>>,
    staged: Option<StagedUpload>,
}
impl UploadResource {
    async fn settle(&mut self) -> Result<(), ProtocolError> {
        if let Some(job) = self.job.as_mut() {
            let result = job.await.map_err(|_| ProtocolError::CleanupFailed);
            self.job.take();
            self.staged = Some(result??);
        }
        match self.staged.as_ref().and_then(|value| value.error.clone()) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

struct OwnedDirectory {
    path: PathBuf,
}
impl OwnedDirectory {
    fn create() -> Result<Self, ProtocolError> {
        let path =
            std::env::temp_dir().join(format!("agent-browser-action-{}", uuid::Uuid::new_v4()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&path)
            .map_err(|_| ProtocolError::BrowserFailure)?;
        Ok(Self { path })
    }
    fn close(self) -> Result<(), ProtocolError> {
        std::fs::remove_dir_all(&self.path).map_err(|_| ProtocolError::CleanupFailed)
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
fn component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0', ':'])
        && name.len() <= 255
}
fn upload_path(name: &str) -> Result<PathBuf, ProtocolError> {
    if name.is_empty() || name.len() > 4096 || name.contains(['\\', '\0', ':']) {
        return Err(ProtocolError::InvalidArguments);
    }
    let path = Path::new(name);
    if path.is_absolute()
        || path
            .components()
            .any(|p| !matches!(p, Component::Normal(_)))
        || name.split('/').any(|p| !component(p))
    {
        return Err(ProtocolError::InvalidArguments);
    }
    Ok(path.into())
}
fn duration(value: Option<u64>, default: u64) -> Result<Duration, ProtocolError> {
    let ms = value.unwrap_or(default);
    if ms > 60_000 {
        Err(ProtocolError::InvalidArguments)
    } else {
        Ok(Duration::from_millis(ms))
    }
}
fn wheel(
    direction: Direction,
    momentum: Momentum,
    width: f64,
    height: f64,
) -> Result<(f64, f64), ProtocolError> {
    if !width.is_finite() || !height.is_finite() || width <= 0.0 || height <= 0.0 {
        return Err(ProtocolError::NotActionable);
    }
    let extent = if matches!(direction, Direction::Up | Direction::Down) {
        height
    } else {
        width
    };
    let distance = (extent
        * match momentum {
            Momentum::None => 0.5,
            Momentum::Slow => 0.75,
            Momentum::Fast => 1.5,
        })
    .round();
    Ok(match direction {
        Direction::Up => (0.0, -distance),
        Direction::Down => (0.0, distance),
        Direction::Left => (-distance, 0.0),
        Direction::Right => (distance, 0.0),
    })
}
enum ReplacementStep {
    SelectAll,
    Delete,
}
async fn replacement_substep(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    step: ReplacementStep,
) -> Result<(), ProtocolError> {
    let key = match step {
        ReplacementStep::SelectAll => "ControlOrMeta+A",
        ReplacementStep::Delete => "Delete",
    };
    // Proof collection is opportunistic. A queued unrelated enrollment event
    // must not introduce a new failure into otherwise ordinary typing; it only
    // prevents a later cancellation from receiving the settled-prefix result.
    let prefix = match step {
        ReplacementStep::SelectAll => SettledReplacementPrefix::capture(ctx).ok().map(Arc::new),
        // Carry only the original authority forward. An unavailable or lost
        // select-all proof cannot be re-certified against a later healthy epoch.
        ReplacementStep::Delete => d
            .settled_replacement_prefix
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?
            .clone(),
    };
    // Ok means every key/modifier release was ACKed and the keyboard executor's
    // post-ACK budget check passed. An error, including keyUp cancellation, must
    // never mint this proof even when release_input later succeeds.
    keyboard(ctx, d, "press", key).await?;
    let prefix = prefix.filter(|prefix| prefix.check(ctx).is_ok());
    *d.settled_replacement_prefix
        .lock()
        .map_err(|_| ProtocolError::CleanupFailed)? = prefix;
    #[cfg(test)]
    tests::replacement_boundary_hook(ctx, key);
    Ok(())
}
async fn keyboard(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    action: &str,
    value: &str,
) -> Result<(), ProtocolError> {
    ctx.check()?;
    ClientPageState::validate_keyboard_command(action, value)?;
    d.mark();
    ctx.page_state
        .execute(
            ctx.page,
            &[],
            ctx.operation,
            "input.keyboard",
            &json!({"action":action,"value":value}),
        )
        .await?;
    Ok(())
}
async fn pointer_event(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    kind: &str,
    point: Option<Point>,
    button: Option<&str>,
    count: Option<i32>,
    delta: Option<(f64, f64)>,
) -> Result<(), ProtocolError> {
    ctx.check()?;
    d.mark();
    // Static stage labels only: no node IDs, text, URL, keys or coordinates.
    action_stage(match kind {
        "mousePressed" => "input.press.dispatch",
        "mouseReleased" => "input.release.dispatch",
        _ => "input.move.dispatch",
    });
    // Shared page input state is the single owner of held keys/buttons.
    let result = ctx
        .page_state
        .pointer_event(
            ctx.page,
            ctx.operation,
            kind,
            point.map(|p| (p.x, p.y)),
            button,
            count,
            delta,
        )
        .await;
    if result.is_ok() {
        action_stage(match kind {
            "mousePressed" => "input.press.ack",
            "mouseReleased" => "input.release.ack",
            _ => "input.move.ack",
        });
    }
    result
}
async fn viewport(ctx: &ActionContext<'_>, d: &Dispatch) -> Result<(f64, f64), ProtocolError> {
    let result = ctx
        .command(
            d,
            false,
            &ctx.page.page_session_id,
            "Page.getLayoutMetrics",
            json!({}),
        )
        .await?;
    let size = result
        .get("cssLayoutViewport")
        .or_else(|| result.get("layoutViewport"))
        .ok_or(ProtocolError::BrowserFailure)?;
    Ok((
        size["clientWidth"]
            .as_f64()
            .ok_or(ProtocolError::BrowserFailure)?,
        size["clientHeight"]
            .as_f64()
            .ok_or(ProtocolError::BrowserFailure)?,
    ))
}
async fn rendered(ctx: &ActionContext<'_>, d: &Dispatch) -> Result<(), ProtocolError> {
    let result=ctx.command(d,false,&ctx.page.page_session_id,"Runtime.evaluate",json!({"expression":"document.hidden?true:new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>resolve(true))))","awaitPromise":true,"returnByValue":true})).await?;
    if result.get("exceptionDetails").is_some() {
        return Err(ProtocolError::BrowserFailure);
    }
    Ok(())
}
async fn scroll(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    point: Option<Point>,
    direction: Direction,
    momentum: Momentum,
    extent: (f64, f64),
) -> Result<(), ProtocolError> {
    let delta = wheel(direction, momentum, extent.0, extent.1)?;
    if let Some(point) = point {
        pointer_event(ctx, d, "mouseMoved", Some(point), None, None, None).await?;
    }
    pointer_event(ctx, d, "mouseWheel", None, None, None, Some(delta)).await?;
    rendered(ctx, d).await
}
async fn click(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    point: Point,
    button: &str,
    count: i32,
    hold: Duration,
) -> Result<(), ProtocolError> {
    pointer_event(ctx, d, "mouseMoved", Some(point), None, None, None).await?;
    for click_count in 1..=count {
        pointer_event(
            ctx,
            d,
            "mousePressed",
            Some(point),
            Some(button),
            Some(click_count),
            None,
        )
        .await?;
        if !hold.is_zero() {
            ctx.pause(hold).await?;
        }
        pointer_event(
            ctx,
            d,
            "mouseReleased",
            Some(point),
            Some(button),
            Some(click_count),
            None,
        )
        .await?;
    }
    Ok(())
}
async fn drag(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    from: Point,
    to: Point,
    pace: Option<Duration>,
) -> Result<(), ProtocolError> {
    pointer_event(ctx, d, "mouseMoved", Some(from), None, None, None).await?;
    pointer_event(
        ctx,
        d,
        "mousePressed",
        Some(from),
        Some("left"),
        Some(1),
        None,
    )
    .await?;
    drag_move_and_release(ctx, d, from, to, pace).await
}
async fn drag_move_and_release(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    from: Point,
    to: Point,
    pace: Option<Duration>,
) -> Result<(), ProtocolError> {
    let steps = pace
        .map(|p| (p.as_millis() / 16).max(2) as usize)
        .unwrap_or(2);
    let start = Instant::now();
    for step in 1..=steps {
        if let Some(pace) = pace {
            let due = start + pace.mul_f64(step as f64 / steps as f64);
            if let Some(wait) = due.checked_duration_since(Instant::now()) {
                ctx.pause(wait).await?;
            }
        }
        let t = step as f64 / steps as f64;
        let point = Point {
            x: from.x + (to.x - from.x) * t,
            y: from.y + (to.y - from.y) * t,
        }
        .validate()?;
        pointer_event(ctx, d, "mouseMoved", Some(point), None, None, None).await?;
    }
    pointer_event(
        ctx,
        d,
        "mouseReleased",
        Some(to),
        Some("left"),
        Some(1),
        None,
    )
    .await
}
async fn action_target(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    r: &NodeReference,
) -> Result<Resolved, ProtocolError> {
    let resolved = resolve(ctx, d, r).await?;
    if resolved.binding.actionable {
        return Ok(resolved);
    }
    let result=ctx.command(d,false,&resolved.session,"Runtime.callFunctionOn",json!({"objectId":resolved.object,"functionDeclaration":"function(){if(this!==document||!this.isConnected)return null;return this.documentElement;}","returnByValue":false})).await;
    let released = resolved.release(ctx).await;
    if released.is_err() {
        d.cleanup.store(true, Ordering::SeqCst);
    }
    let value = result?;
    let candidate = value["result"]["objectId"].as_str();
    if released.is_err() || value.get("exceptionDetails").is_some() || candidate.is_none() {
        let _ =
            release_call_handles(ctx, d, &resolved.session, &value, Some(&resolved.object)).await;
        if released.is_ok() && value.get("exceptionDetails").is_none() {
            ctx.check()?;
        }
        return Err(if value.get("exceptionDetails").is_some() {
            ProtocolError::BrowserFailure
        } else if released.is_err() {
            ProtocolError::CleanupFailed
        } else {
            ProtocolError::NotActionable
        });
    }
    let object = candidate.unwrap().to_owned();
    release_call_handles(ctx, d, &resolved.session, &value, Some(&object)).await?;
    if let Err(primary) = ctx.check() {
        if !release_object_accounted(&ctx.page.client, &resolved.session, &object).await {
            d.cleanup.store(true, Ordering::SeqCst);
        }
        return Err(primary);
    }
    Ok(Resolved {
        realm: resolved.realm,
        object,
        session: resolved.session,
        binding: resolved.binding,
    })
}
async fn center(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    node: &Resolved,
    enabled: bool,
) -> Result<(Point, (f64, f64)), ProtocolError> {
    d.start_readonly_timing(ctx.operation.deadline, diagnostic::inventory_enabled());
    let mut previous: Option<(Point, (f64, f64))> = None;
    let mut longest_attempt = Duration::ZERO;
    let mut longest_retry_interval = Duration::ZERO;
    loop {
        #[cfg(test)]
        tests::preparation_trace(
            ctx,
            d,
            tests::PreparationTracePhase::BeforeRetry,
            longest_attempt,
        );
        // A pause sends no command. Recheck its actual wake time while the
        // preceding ACK still covers the entire preparation attempt, before
        // clearing that receipt or starting any later read or mutation.
        preparation_refusal_checkpoint(
            d,
            ctx.operation
                .deadline
                .saturating_duration_since(Instant::now()),
            preparation_retry_estimate(d, longest_attempt, longest_retry_interval),
            || ctx.check(),
        )?;
        // An earlier ACK cannot certify even a later read which is still pending.
        d.begin_preparation_attempt();
        #[cfg(test)]
        tests::preparation_trace(
            ctx,
            d,
            tests::PreparationTracePhase::AttemptStart,
            longest_attempt,
        );
        let started = Instant::now();
        let attempt = center_once(ctx, d, node, enabled).await;
        longest_attempt = longest_attempt.max(started.elapsed());
        #[cfg(test)]
        tests::preparation_classification_gate(ctx, d, &attempt, longest_attempt).await;
        #[cfg(test)]
        tests::preparation_trace(
            ctx,
            d,
            tests::PreparationTracePhase::AfterAttempt,
            longest_attempt,
        );
        match attempt {
            Ok(current) => {
                if previous.as_ref().is_some_and(|old| {
                    (old.0.x - current.0.x).abs() < 0.5
                        && (old.0.y - current.0.y).abs() < 0.5
                        && (old.1 .0 - current.1 .0).abs() < 0.5
                        && (old.1 .1 - current.1 .1).abs() < 0.5
                }) {
                    return Ok(current);
                }
                previous = Some(current);
            }
            Err(ProtocolError::NotActionable) => {
                previous = None;
                preparation_refusal_checkpoint(
                    d,
                    ctx.operation
                        .deadline
                        .saturating_duration_since(Instant::now()),
                    preparation_retry_estimate(d, longest_attempt, longest_retry_interval),
                    || ctx.check(),
                )?;
            }
            Err(ProtocolError::DeadlineExceeded) => {
                return Err(
                    if d.readonly_preparation_enabled.load(Ordering::SeqCst)
                        && !d.sent.load(Ordering::SeqCst)
                    {
                        ProtocolError::DeadlineExceeded
                    } else {
                        ProtocolError::NotActionable
                    },
                );
            }
            Err(error) => return Err(error),
        }
        let pause = ctx.pause(Duration::from_millis(16)).await;
        d.update_readonly_timing(|timing| {
            // Same origin as the existing retry estimate; this also observes
            // a cancelled/expired pause, without treating it as a timer ACK.
            timing.wake_us = Some(diagnostic_us(started.elapsed()));
        });
        match pause {
            Ok(()) => (),
            Err(ProtocolError::DeadlineExceeded) => {
                return Err(
                    if d.readonly_preparation_enabled.load(Ordering::SeqCst)
                        && !d.sent.load(Ordering::SeqCst)
                    {
                        ProtocolError::DeadlineExceeded
                    } else {
                        ProtocolError::NotActionable
                    },
                );
            }
            Err(error) => return Err(error),
        }
        if d.readonly_preparation_enabled.load(Ordering::SeqCst) {
            // Include the actual timer wake, not just the pure probe. A rounded
            // retry pause can otherwise skip the entire classification window.
            longest_retry_interval = longest_retry_interval.max(started.elapsed());
        }
    }
}
fn preparation_retry_estimate(
    d: &Dispatch,
    longest_attempt: Duration,
    longest_retry_interval: Duration,
) -> Duration {
    if d.readonly_preparation_enabled.load(Ordering::SeqCst) {
        longest_attempt.max(longest_retry_interval)
    } else {
        longest_attempt
    }
}
/// Return an ordinary refusal only while its exact attempt remains current.
/// This does not certify Completed: the original authority, reference, realm,
/// and owned cleanup must still pass perform's final settlement checks.
fn preparation_refusal_checkpoint(
    d: &Dispatch,
    remaining: Duration,
    longest_attempt: Duration,
    check: impl FnOnce() -> Result<(), ProtocolError>,
) -> Result<(), ProtocolError> {
    if d.readonly_preparation_enabled.load(Ordering::SeqCst)
        && d.readonly_preparation_refusal.load(Ordering::SeqCst)
        && !d.readonly_preparation_disqualified.load(Ordering::SeqCst)
        && !d.sent.load(Ordering::SeqCst)
    {
        // Below the existing cleanup floor, keep waiting for the original
        // deadline/cancellation. Tap's early retirement mapping is not proof
        // of this unmutated Swipe's safe semantic refusal.
        if preparation_classification_window(remaining, longest_attempt) {
            d.update_readonly_timing(|timing| timing.window = ReadonlyWindow::Entered);
            check()?;
            d.readonly_preparation_stopped.store(true, Ordering::SeqCst);
            return Err(ProtocolError::NotActionable);
        }
        return Ok(());
    }
    if !d.preparation_enabled.load(Ordering::SeqCst)
        || !d.preparation_refusal.load(Ordering::SeqCst)
        || d.preparation_disqualified.load(Ordering::SeqCst)
    {
        return Ok(());
    }
    if !preparation_has_classification_slack(remaining) {
        // A late wake retires conservatively, never using the preceding ACK
        // to grant a receipt below the original cleanup/classification floor.
        return Err(preparation_retirement_error(check()));
    }
    if preparation_classification_window(remaining, longest_attempt) {
        check()?;
        d.preparation_stopped.store(true, Ordering::SeqCst);
        return Err(ProtocolError::NotActionable);
    }
    Ok(())
}
/// Leave the existing 250ms exact-handle cleanup budget plus a small positive
/// classification window. Observed duration is only an admission estimate: any
/// overrun still fails the original deadline/authority checks after cleanup.
fn preparation_has_classification_slack(remaining: Duration) -> bool {
    remaining >= Duration::from_millis(250 + 16)
}
fn preparation_classification_window(remaining: Duration, longest_attempt: Duration) -> bool {
    preparation_has_classification_slack(remaining)
        && remaining <= Duration::from_millis(16 + 250 + 16).saturating_add(longest_attempt)
}
fn preparation_retirement_error(check: Result<(), ProtocolError>) -> ProtocolError {
    // Preserve center's existing deadline-to-refusal mapping without hiding
    // cancellation or loss of the original permit during the final check.
    match check {
        Ok(()) | Err(ProtocolError::DeadlineExceeded) => ProtocolError::NotActionable,
        Err(error) => error,
    }
}
fn geometry_failure(d: &Dispatch, error: GeometryError) -> ProtocolError {
    match error {
        GeometryError::Cancelled => ProtocolError::Cancelled,
        GeometryError::DeadlineExceeded => ProtocolError::DeadlineExceeded,
        GeometryError::StaleIdentity | GeometryError::Superseded => ProtocolError::StaleReference,
        GeometryError::CleanupFailed { primary } => {
            d.cleanup.store(true, Ordering::SeqCst);
            primary
                .map(|e| geometry_failure(d, *e))
                .unwrap_or(ProtocolError::CleanupFailed)
        }
        GeometryError::InvalidGeometry | GeometryError::IncompleteInventory => {
            ProtocolError::UnsupportedCapability
        }
        GeometryError::BackendFailure => ProtocolError::BrowserFailure,
    }
}
fn action_stage(stage: &'static str) {
    #[cfg(test)]
    eprintln!("native-action-stage {stage}");
    #[cfg(not(test))]
    let _ = stage;
}
async fn center_once(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    node: &Resolved,
    enabled: bool,
) -> Result<(Point, (f64, f64)), ProtocolError> {
    let probe = node.call(ctx,d,false,r#"function(){if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};const rect=this.getBoundingClientRect();const style=getComputedStyle(this);if(rect.width<=0||rect.height<=0||style.visibility==='hidden'||style.visibility==='collapse')return {status:'not-actionable'};return true;}"#,vec![]).await;
    if matches!(&probe, Err(ProtocolError::NotActionable))
        && d.readonly_preparation_enabled.load(Ordering::SeqCst)
        && !d.readonly_preparation_disqualified.load(Ordering::SeqCst)
        && !d.sent.load(Ordering::SeqCst)
    {
        // Resolved.call has already interpreted the exact semantic ACK only
        // after auxiliary release accounting and the original authority check.
        ctx.check()?;
        d.readonly_preparation_refusal.store(true, Ordering::SeqCst);
        d.update_readonly_timing(|timing| {
            timing.ack_us = Some(diagnostic_us(
                ctx.operation
                    .deadline
                    .saturating_duration_since(Instant::now()),
            ));
            timing.ack = ReadonlyAck::Current;
        });
    }
    probe?;
    action_stage("scroll.dispatch");
    ctx.command(
        d,
        true,
        &node.session,
        "DOM.scrollIntoViewIfNeeded",
        json!({"objectId":node.object}),
    )
    .await?;
    action_stage("scroll.ack");
    action_stage("geometry.refresh.dispatch");
    let geometry = ctx
        .geometry
        .refresh_after_scroll(&ctx.page.client, ctx.operation)
        .await
        .map_err(|e| geometry_failure(d, e))?;
    action_stage("geometry.refresh.ack");
    let bounds = ctx
        .command(
            d,
            false,
            &node.session,
            "DOM.getBoxModel",
            json!({"objectId":node.object}),
        )
        .await?;
    let quad = bounds["model"]["border"]
        .as_array()
        .ok_or(ProtocolError::NotActionable)?;
    if quad.len() != 8 {
        return Err(ProtocolError::BrowserFailure);
    }
    let values = quad
        .iter()
        .map(|v| {
            v.as_f64()
                .filter(|v| v.is_finite())
                .ok_or(ProtocolError::BrowserFailure)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let local = GeometryPoint {
        x: (values[0] + values[2] + values[4] + values[6]) / 4.0,
        y: (values[1] + values[3] + values[5] + values[7]) / 4.0,
    };
    let root = geometry
        .project_native_point(
            &node.binding.frame,
            GeometryPoint {
                x: local.x,
                y: local.y,
            },
        )
        .map_err(|e| geometry_failure(d, e))?;
    // Public Input rounds once in root space. Hit-test precisely that eventual
    // dispatch point, not a separately rounded renderer-local coordinate.
    let rounded = Point {
        x: root.x,
        y: root.y,
    }
    .validate()?;
    let root = GeometryPoint {
        x: rounded.x,
        y: rounded.y,
    };
    let local = geometry
        .root_to_frame_point(&node.binding.frame, root)
        .map_err(|e| geometry_failure(d, e))?;
    let function = format!(
        r#"function(x,y,enabled){{
      if(!this.isConnected||this.ownerDocument!==document)return {{status:'stale'}};
      const rect=this.getBoundingClientRect();const style=this.ownerDocument.defaultView.getComputedStyle(this);
      if(rect.width<=0||rect.height<=0||style.visibility==='hidden'||style.visibility==='collapse')return {{status:'not-actionable'}};
      const doc=this.ownerDocument;
      if(typeof doc.elementFromPoint!=='function'||typeof this.matches!=='function'||!doc.elementFromPoint(x,y))return {{status:'not-actionable'}};
      const blocker={};const actionable={};
      if(blocker(doc,this,x,y)!==null)return {{status:'intercepted-pointer'}};
      if(enabled&&actionable(doc,this,x,y)!==null)return {{status:'not-actionable'}};
      return {{width:rect.width,height:rect.height}};
    }}"#,
        element::BLOCKER_AT_JS,
        element::ACTIONABILITY_JS
    );
    let size = node
        .call(
            ctx,
            d,
            false,
            &function,
            vec![json!(local.x), json!(local.y), json!(enabled)],
        )
        .await;
    let size = match size {
        Err(ProtocolError::NotActionable) if d.preparation_enabled.load(Ordering::SeqCst) => {
            // The semantic refusal is ACKed, all auxiliary handles released.
            // Revalidate the same geometry before recording this attempt only.
            geometry
                .revalidate(&ctx.page.client, ctx.operation)
                .await
                .map_err(|error| geometry_failure(d, error))?;
            ctx.check()?;
            d.preparation_refusal.store(true, Ordering::SeqCst);
            return Err(ProtocolError::NotActionable);
        }
        other => other?,
    };
    // A child-frame local hit can be unobscured while its iframe is covered in
    // an ancestor. Prove each exact native owner in its own parent realm.
    for (binding, backend) in geometry
        .owner_chain(&node.binding.frame)
        .map_err(|e| geometry_failure(d, e))?
    {
        let local = geometry
            .root_to_frame_point(&binding.frame, root)
            .map_err(|e| geometry_failure(d, e))?;
        let object = resolve_action_object(ctx, d, &binding, backend).await?;
        let owner = Resolved {
            realm: None,
            object,
            session: binding.session.clone(),
            binding,
        };
        let result = owner
            .call(
                ctx,
                d,
                false,
                &function,
                vec![json!(local.x), json!(local.y), json!(false)],
            )
            .await;
        let cleanup = owner.release(ctx).await;
        if cleanup.is_err() {
            d.cleanup.store(true, Ordering::SeqCst);
        }
        result?;
        cleanup?;
    }
    geometry
        .revalidate(&ctx.page.client, ctx.operation)
        .await
        .map_err(|e| geometry_failure(d, e))?;
    ctx.check()?;
    Ok((
        Point {
            x: root.x,
            y: root.y,
        }
        .validate()?,
        (
            size["width"]
                .as_f64()
                .ok_or(ProtocolError::BrowserFailure)?,
            size["height"]
                .as_f64()
                .ok_or(ProtocolError::BrowserFailure)?,
        ),
    ))
}
impl ClientActions {
    async fn pointer(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        point: Point,
        action: PointerAction,
    ) -> Result<(), ProtocolError> {
        match action {
            PointerAction::Tap => click(ctx, d, point, "left", 1, Duration::ZERO).await,
            PointerAction::DoubleTap => click(ctx, d, point, "left", 2, Duration::ZERO).await,
            PointerAction::SecondaryTap => click(ctx, d, point, "right", 1, Duration::ZERO).await,
            PointerAction::Hover => {
                pointer_event(ctx, d, "mouseMoved", Some(point), None, None, None).await
            }
            PointerAction::LongPress { duration_ms } => {
                click(ctx, d, point, "left", 1, duration(duration_ms, 500)?).await
            }
            PointerAction::DragTo { target } => drag(ctx, d, point, target.validate()?, None).await,
            PointerAction::SwipeTo {
                target,
                duration_ms,
            } => {
                drag(
                    ctx,
                    d,
                    point,
                    target.validate()?,
                    duration_ms.map(|v| duration(Some(v), 0)).transpose()?,
                )
                .await
            }
            PointerAction::Swipe {
                direction,
                momentum,
            } => {
                scroll(
                    ctx,
                    d,
                    Some(point),
                    direction,
                    momentum,
                    viewport(ctx, d).await?,
                )
                .await
            }
        }
    }
    async fn perform(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        request: Perform,
    ) -> Result<(), ProtocolError> {
        // Scope admission precedes the client-lifetime viewport exception.
        if ctx.refs.is_viewport_ref(&request.reference.id) {
            if !ctx.refs.matches_viewport_reference(
                &ctx.page.identity_scope,
                ctx.operation.generation,
                &ctx.page.page_session_id,
                &request.reference.id,
                &request.reference.revision,
            ) {
                return Err(ProtocolError::StaleReference);
            }
            if let LocatorAction::Swipe {
                direction,
                momentum,
            } = request.action
            {
                require_recovery_observation(ctx)?;
                return scroll(ctx, d, None, direction, momentum, viewport(ctx, d).await?).await;
            }
            return Err(ProtocolError::NotActionable);
        }
        if let LocatorAction::DragTo { target } = &request.action {
            reference(ctx, target)?;
        }
        if let LocatorAction::SelectOption { value } = &request.action {
            value.wire()?;
        }
        if let LocatorAction::LongPress { duration_ms } = &request.action {
            duration(*duration_ms, 500)?;
        }
        // Capture before the first scroll; never mint replacement authority at
        // the end of a deadline or after a retry. Only ordinary Tap participates.
        let preparation =
            if matches!(&request.action, LocatorAction::Tap { .. }) && !ctx.operation.is_callback {
                // Optional settlement evidence is not another action admission gate.
                // Callback leases cannot obtain this receipt. Any other inability to
                // capture it keeps the original execution/Unknown classification;
                // exact resolution still enforces all normal action authority.
                SettledReplacementPrefix::capture(ctx).ok()
            } else {
                None
            };
        let readonly_preparation = if matches!(&request.action, LocatorAction::Swipe { .. })
            && !ctx.operation.is_callback
            && matches!(&ctx.realm_authority, ActionRealmAuthority::Enrolled(_))
            && OperationJournalHandle::current().is_some_and(|journal| {
                journal.key().generation == ctx.operation.generation
                    && journal.key().operation_seq == ctx.operation.sequence
                    && ctx.page.client.debt_ledger().is_some_and(|ledger| {
                        ledger.matches_owner(ctx.operation.generation, &ctx.page.identity_scope)
                            && Arc::ptr_eq(&journal.ledger(), &ledger)
                    })
            }) {
            SettledReplacementPrefix::capture(ctx).ok()
        } else {
            // Legacy untracked seams retain their old behavior and cannot
            // manufacture the new exact settlement receipt.
            None
        };
        d.readonly_preparation_enabled
            .store(readonly_preparation.is_some(), Ordering::SeqCst);
        action_stage("exact.resolve.dispatch");
        let node = action_target(ctx, d, &request.reference).await?;
        action_stage("exact.resolve.ack");
        d.preparation_enabled
            .store(preparation.is_some(), Ordering::SeqCst);
        let result = self.perform_node(ctx, d, &node, request.action).await;
        if result.is_err() {
            d.update_readonly_timing(|timing| {
                timing.fail_us = Some(diagnostic_us(
                    ctx.operation
                        .deadline
                        .saturating_duration_since(Instant::now()),
                ));
            });
        }
        #[cfg(test)]
        tests::preparation_trace(
            ctx,
            d,
            tests::PreparationTracePhase::BeforeRelease,
            Duration::ZERO,
        );
        let readonly_refusal = matches!(&result, Err(ProtocolError::NotActionable))
            && d.readonly_preparation_stopped.load(Ordering::SeqCst)
            && d.readonly_preparation_refusal.load(Ordering::SeqCst)
            && !d.readonly_preparation_disqualified.load(Ordering::SeqCst)
            && !d.sent.load(Ordering::SeqCst);
        let released = if readonly_refusal {
            node.release_settled(ctx).await
        } else {
            node.release(ctx).await
        };
        #[cfg(test)]
        tests::preparation_trace(
            ctx,
            d,
            tests::PreparationTracePhase::AfterRelease,
            Duration::ZERO,
        );
        if released.is_err() {
            d.cleanup.store(true, Ordering::SeqCst);
            if readonly_refusal {
                return Err(ProtocolError::CleanupFailed);
            }
            return result.and(Err(ProtocolError::CleanupFailed));
        }
        if readonly_refusal {
            // Every failing final fence is the actual result; a boolean guard
            // would otherwise fall through to NotActionable/NotDispatched.
            ctx.check()?;
            readonly_preparation
                .as_ref()
                .ok_or(ProtocolError::ScopeUnavailable)?
                .check(ctx)?;
            reference(ctx, &request.reference)?;
            if node
                .realm
                .as_ref()
                .ok_or(ProtocolError::ScopeUnavailable)?
                .destroyed()?
            {
                return Err(ProtocolError::StaleReference);
            }
            let journal =
                OperationJournalHandle::current().ok_or(ProtocolError::ScopeUnavailable)?;
            let settled = journal.snapshot();
            if settled.integrity_lost
                || settled.mutation_dispatched
                || settled.input_debt != 0
                || settled.object_debt != 0
            {
                d.cleanup.store(true, Ordering::SeqCst);
                return Err(ProtocolError::CleanupFailed);
            }
            ctx.check()?;
        }
        if matches!(&result, Err(ProtocolError::NotActionable))
            && d.preparation_stopped.load(Ordering::SeqCst)
            && d.preparation_refusal.load(Ordering::SeqCst)
            && !d.preparation_disqualified.load(Ordering::SeqCst)
            && !d.cleanup.load(Ordering::SeqCst)
            && ctx.check().is_ok()
            && preparation
                .as_ref()
                .is_some_and(|proof| proof.check(ctx).is_ok())
            && reference(ctx, &request.reference).is_ok()
            && node
                .realm
                .as_ref()
                .is_none_or(|realm| realm.destroyed() == Ok(false))
            && ctx.check().is_ok()
        {
            // Scroll may have invoked page code. Completed certifies a settled
            // preparation prefix, not success, rollback, or replay permission.
            d.acknowledged_postcondition.store(true, Ordering::SeqCst);
        }
        result
    }
    async fn perform_node(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        node: &Resolved,
        action: LocatorAction,
    ) -> Result<(), ProtocolError> {
        match action {
            LocatorAction::Tap { modifiers } => self.tap(ctx, d, node, "left", 1, modifiers).await,
            LocatorAction::DoubleTap { modifiers } => {
                self.tap(ctx, d, node, "left", 2, modifiers).await
            }
            LocatorAction::SecondaryTap { modifiers } => {
                self.tap(ctx, d, node, "right", 1, modifiers).await
            }
            LocatorAction::LongPress { duration_ms } => {
                let (point, _) = center(ctx, d, node, true).await?;
                click(ctx, d, point, "left", 1, duration(duration_ms, 500)?).await
            }
            LocatorAction::Hover => {
                let (point, _) = center(ctx, d, node, false).await?;
                pointer_event(ctx, d, "mouseMoved", Some(point), None, None, None).await
            }
            LocatorAction::Swipe {
                direction,
                momentum,
            } => {
                let (point, size) = center(ctx, d, node, false).await?;
                scroll(ctx, d, Some(point), direction, momentum, size).await
            }
            LocatorAction::ScrollIntoView => {
                ctx.command(
                    d,
                    true,
                    &node.session,
                    "DOM.scrollIntoViewIfNeeded",
                    json!({"objectId":node.object}),
                )
                .await?;
                Ok(())
            }
            LocatorAction::Focus => focus(ctx, d, node).await,
            LocatorAction::Press { key } => {
                ClientPageState::validate_keyboard_command("press", &key)?;
                focus(ctx, d, node).await?;
                keyboard(ctx, d, "press", &key).await
            }
            LocatorAction::Fill { value, sensitive } => {
                // Sensitive and ordinary fills both return only fixed error
                // categories. No submitted value or raw renderer cause escapes.
                fill(ctx, d, node, &value, sensitive).await
            }
            LocatorAction::Clear => fill(ctx, d, node, "", false).await,
            LocatorAction::SelectOption { value } => {
                node.call(ctx, d, true, SELECT_OPTION, vec![value.wire()?])
                    .await?;
                Ok(())
            }
            LocatorAction::Check => set_checked(ctx, d, node, true).await,
            LocatorAction::Uncheck => set_checked(ctx, d, node, false).await,
            LocatorAction::DragTo { target } => {
                // Only the stored live-query origin permits selecting a different
                // destination after mousePressed invokes application code. An
                // observed reference keeps its original exact object throughout.
                let live = reference(ctx, &target)?.0.live_query.is_some();
                let mut other = Some(action_target(ctx, d, &target).await?);
                let mut press_attempted = false;
                let result = async {
                    let (from, _) = center(ctx, d, node, true).await?;
                    center(ctx, d, other.as_ref().unwrap(), true).await?;
                    pointer_event(ctx, d, "mouseMoved", Some(from), None, None, None).await?;
                    press_attempted = true;
                    pointer_event(
                        ctx,
                        d,
                        "mousePressed",
                        Some(from),
                        Some("left"),
                        Some(1),
                        None,
                    )
                    .await?;
                    if live {
                        let previous = other.take().unwrap();
                        if previous.release(ctx).await.is_err() {
                            d.cleanup.store(true, Ordering::SeqCst);
                            return Err(ProtocolError::CleanupFailed);
                        }
                        // Reuse the same authority and resolver. Strict ambiguity,
                        // disappearance and cancellation are post-dispatch errors,
                        // never permission to replay the press or choose a match.
                        other = Some(action_target(ctx, d, &target).await?);
                    }
                    let (to, _) = center(ctx, d, other.as_ref().unwrap(), true).await?;
                    drag_move_and_release(ctx, d, from, to, None).await
                }
                .await;
                let released = match other {
                    Some(other) => other.release(ctx).await,
                    None => Ok(()),
                };
                if released.is_err() {
                    d.cleanup.store(true, Ordering::SeqCst);
                }
                let result = result.and(released);
                // Managed execution owns input cleanup once, in execute. A
                // retained release ACK must keep its original status handles:
                // calling release_input twice can resubmit and overwrite them.
                if result.is_err()
                    && press_attempted
                    && OperationJournalHandle::current().is_none()
                    && ctx.page_state.release_input(ctx.page).await.is_err()
                {
                    // Direct fixtures have no outer journal cleanup owner. Their
                    // cleanup still retains the original page outside cancellation.
                    d.cleanup.store(true, Ordering::SeqCst);
                }
                result
            }
            LocatorAction::SetInputFiles {
                directory_name,
                files,
            } => self.upload(ctx, d, node, directory_name, files).await,
        }
    }
    async fn tap(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        node: &Resolved,
        button: &str,
        count: i32,
        modifiers: Option<Vec<String>>,
    ) -> Result<(), ProtocolError> {
        let (point, _) = center(ctx, d, node, true).await?;
        let receipt = if let Some(modifiers) = modifiers {
            ctx.check()?;
            d.mark();
            Some(
                ctx.page_state
                    .acquire_modifiers(ctx.page, ctx.operation, &modifiers)
                    .await?,
            )
        } else {
            None
        };
        let result = click(ctx, d, point, button, count, Duration::ZERO).await;
        if let Some(receipt) = receipt {
            let restored = ctx
                .page_state
                .restore_modifiers(ctx.page, ctx.operation, receipt)
                .await;
            if restored.is_err() {
                d.cleanup.store(true, Ordering::SeqCst);
            }
            if let Err(error) = restored {
                return Err(result.err().unwrap_or(error));
            }
        }
        result
    }
    async fn upload(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        node: &Resolved,
        directory_name: Option<String>,
        files: Vec<UploadFile>,
    ) -> Result<(), ProtocolError> {
        if files.len() > 10000 || directory_name.as_ref().is_some_and(|n| !component(n)) {
            return Err(ProtocolError::InvalidArguments);
        }
        let mut seen = HashSet::new();
        let mut staged = Vec::<(PathBuf, BlobLease)>::new();
        for file in files {
            if !component(&file.name)
                || file.mime_type.len() > 255
                || file.mime_type.contains(['\r', '\n', '\0'])
            {
                return Err(ProtocolError::InvalidArguments);
            }
            let relative = match (&directory_name, file.relative_path) {
                (Some(_), Some(path)) => {
                    let path = upload_path(&path)?;
                    if path.file_name().and_then(|n| n.to_str()) != Some(&file.name) {
                        return Err(ProtocolError::InvalidArguments);
                    }
                    path
                }
                (None, None) => PathBuf::from(&file.name),
                _ => return Err(ProtocolError::InvalidArguments),
            };
            if !seen.insert(relative.clone()) {
                return Err(ProtocolError::InvalidArguments);
            }
            let lease = ctx
                .blobs
                .borrow_sealed(&ctx.blob_scope(), &file.body_handle)
                .map_err(|_| ProtocolError::InvalidArguments)?;
            staged.push((relative, lease));
        }
        // Validate file-input and cardinality before creating files or dispatch.
        node.call(ctx,d,false,r#"function(directory,count){if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};if(!(this instanceof HTMLInputElement)||this.type!=='file'||this.disabled||this.webkitdirectory!==directory||(!directory&&!this.multiple&&count>1))return {status:'not-actionable'};return true;}"#,vec![json!(directory_name.is_some()),json!(staged.len())]).await?;
        let deadline = ctx.operation.deadline;
        let cancellation = ctx.operation.cancellation.clone();
        let mut resources = self.uploads.lock().await;
        ctx.check()?;
        let job = tokio::task::spawn_blocking(move || {
            stage_upload(directory_name, staged, deadline, cancellation)
        });
        resources.push(UploadResource {
            job: Some(job),
            staged: None,
        });
        let resource = resources.last_mut().ok_or(ProtocolError::BrowserFailure)?;
        // Await without detaching. On a dropped outer future, the stored handle
        // is still joined by cleanup and owns the directory plus quota leases.
        resource.settle().await?;
        let paths = resource
            .staged
            .as_ref()
            .ok_or(ProtocolError::BrowserFailure)?
            .paths
            .clone();
        drop(resources);
        ctx.check()?;
        ctx.command(
            d,
            true,
            &node.session,
            "DOM.setFileInputFiles",
            json!({"objectId":node.object,"files":paths}),
        )
        .await?;
        Ok(())
    }
    /// Scope teardown drains only scope-local uploads. Recording is owned by
    /// the attempt and survives a properly sequenced page replacement.
    pub async fn cleanup_scope_uploads(&self) -> Result<(), ProtocolError> {
        let mut uploads = self.uploads.lock().await;
        let mut failed = false;
        for upload in uploads.iter_mut() {
            failed |= upload.settle().await.is_err();
        }
        let resources = std::mem::take(&mut *uploads);
        drop(uploads);
        for mut upload in resources {
            if let Some(staged) = upload.staged.take() {
                failed |= staged.directory.close().is_err();
            }
        }
        if failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
    pub async fn cleanup(&self) -> Result<(), ProtocolError> {
        self.cleanup_with_diagnostics(&None).await
    }
    pub(crate) async fn cleanup_with_diagnostics(
        &self,
        diagnostics: &Option<super::client_settlement_trace::CleanupObserver>,
    ) -> Result<(), ProtocolError> {
        use super::client_settlement_trace::{observe_cleanup, CleanupComponent};
        let recording = self.abandon_recording().await;
        observe_cleanup(diagnostics, CleanupComponent::Recording, &recording);
        let uploads = self.cleanup_scope_uploads().await;
        observe_cleanup(diagnostics, CleanupComponent::Upload, &uploads);
        if recording.is_err() || uploads.is_err() {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
}
async fn focus(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    node: &Resolved,
) -> Result<(), ProtocolError> {
    node.call(ctx,d,true,"function(){if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};if(typeof this.focus!=='function')return {status:'not-actionable'};this.focus();return true;}",vec![]).await?;
    Ok(())
}
const PREPARE_FILL: &str = r#"function(value){
 if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};
 if(this.matches(':disabled')||this.readOnly)return {status:'not-actionable'};
 if(this instanceof HTMLInputElement){
  const type=this.type;
  if(['button','checkbox','file','hidden','image','radio','range','reset','submit','color'].includes(type))return {status:'not-actionable'};
  if(type==='number'&&value!==''&&!Number.isFinite(Number(value)))return {status:'invalid'};
  this.focus();
  if(['date','datetime-local','month','time','week'].includes(type)){this.value=value;if(this.value!==value)return {status:'invalid'};this.dispatchEvent(new Event('input',{bubbles:true,composed:true}));this.dispatchEvent(new Event('change',{bubbles:true}));return {complete:true};}
  this.select();return {complete:false};
 }
 if(this instanceof HTMLTextAreaElement){this.focus();this.select();return {complete:false};}
 if(this.isContentEditable){this.focus();const range=document.createRange();range.selectNodeContents(this);const selection=document.getSelection();selection.removeAllRanges();selection.addRange(range);return {complete:false};}
 return {status:'not-actionable'};
}"#;
async fn fill(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    node: &Resolved,
    value: &str,
    _sensitive: bool,
) -> Result<(), ProtocolError> {
    let result = node
        .call(ctx, d, true, PREPARE_FILL, vec![json!(value)])
        .await?;
    if result["complete"] == true {
        return Ok(());
    }
    if value.is_empty() {
        keyboard(ctx, d, "press", "Delete").await?;
    } else {
        ctx.command(
            d,
            true,
            &ctx.page.page_session_id,
            "Input.insertText",
            json!({"text":value}),
        )
        .await?;
    }
    Ok(())
}
const SELECT_OPTION: &str = r#"function(wanted){
 if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};
 if(!(this instanceof HTMLSelectElement)||this.matches(':disabled'))return {status:'not-actionable'};
 const options=Array.from(this.options);const selected=options.find((option,index)=>wanted.index!==undefined?index===wanted.index:wanted.value!==undefined?option.value===wanted.value:option.label===wanted.label);
 if(!selected||selected.disabled)return {status:'not-actionable'};
 for(const option of options)option.selected=option===selected;
 this.dispatchEvent(new Event('input',{bubbles:true,composed:true}));this.dispatchEvent(new Event('change',{bubbles:true}));return true;
}"#;
const CHECKED_STATE: &str = r#"function(){
 if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};
 if(this instanceof HTMLInputElement&&['checkbox','radio'].includes(this.type))return {checked:this.checked,radio:this.type==='radio'};
 const role=this.getAttribute('role');if(['checkbox','radio','switch'].includes(role)){const value=this.getAttribute('aria-checked');if(value==='true'||value==='false')return {checked:value==='true',radio:role==='radio'};}
 return {status:'not-actionable'};
}"#;
async fn set_checked(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    node: &Resolved,
    wanted: bool,
) -> Result<(), ProtocolError> {
    action_stage("checked.before.dispatch");
    let before = node.call(ctx, d, false, CHECKED_STATE, vec![]).await?;
    action_stage("checked.before.ack");
    if before["checked"] == wanted {
        return Ok(());
    }
    if !wanted && before["radio"] == true {
        return Err(ProtocolError::NotActionable);
    }
    let (point, _) = center(ctx, d, node, true).await?;
    click(ctx, d, point, "left", 1, Duration::ZERO).await?;
    let mut first = true;
    let mut largest_read = Duration::ZERO;
    loop {
        // A completed unchanged read is evidence; a timed-out in-flight read is
        // not. Do not dispatch another poll after its measured round-trip budget
        // has gone, and never reinterpret a transport timeout as unchanged.
        if !first {
            ctx.page.permit.check()?;
            if *ctx.operation.cancellation.borrow() != CancelSignal::None {
                return Err(ProtocolError::Cancelled);
            }
            if !checked_poll_fits(
                Instant::now(),
                ctx.operation.deadline,
                Duration::ZERO,
                largest_read,
            ) {
                return checked_unchanged(d);
            }
        }
        let read_started = Instant::now();
        match node.call(ctx, d, false, CHECKED_STATE, vec![]).await {
            Ok(value) if value["checked"] == wanted => return Ok(()),
            Err(ProtocolError::StaleReference) if first => return Ok(()),
            Err(ProtocolError::StaleReference) => {
                d.checked_replaced.store(true, Ordering::SeqCst);
                d.acknowledged_postcondition.store(true, Ordering::SeqCst);
                return Err(ProtocolError::NotActionable);
            }
            Err(error) => {
                let retired = if matches!(
                    error,
                    ProtocolError::BrowserFailure | ProtocolError::StaleReference
                ) {
                    match &node.realm {
                        Some(realm) => realm.document_retired(ctx.operation).await == Ok(true),
                        None => false,
                    }
                } else {
                    false
                };
                if checked_navigation_recovery_allowed(d, retired) {
                    ctx.check()?;
                    if first {
                        return Ok(());
                    }
                    d.checked_replaced.store(true, Ordering::SeqCst);
                    d.acknowledged_postcondition.store(true, Ordering::SeqCst);
                    return Err(ProtocolError::NotActionable);
                }
                return Err(error);
            }
            _ => {}
        }
        largest_read = largest_read.max(read_started.elapsed());
        first = false;
        let interval = Duration::from_millis(20);
        if !checked_poll_fits(
            Instant::now(),
            ctx.operation.deadline,
            interval,
            largest_read,
        ) {
            return checked_unchanged(d);
        }
        match ctx.pause(interval).await {
            Ok(()) => (),
            Err(ProtocolError::DeadlineExceeded) => {
                ctx.page.permit.check()?;
                if *ctx.operation.cancellation.borrow() != CancelSignal::None {
                    return Err(ProtocolError::Cancelled);
                }
                return checked_unchanged(d);
            }
            Err(error) => return Err(error),
        }
    }
}
// A realm ticket covers the owned node, not arbitrary auxiliary handles whose
// release already failed. Never erase an independently recorded integrity loss.
fn checked_navigation_recovery_allowed(d: &Dispatch, retired: bool) -> bool {
    retired && !d.cleanup.load(Ordering::SeqCst)
}
fn checked_poll_fits(
    now: Instant,
    deadline: Instant,
    pause: Duration,
    last_read: Duration,
) -> bool {
    pause
        .checked_add(last_read)
        .and_then(|budget| now.checked_add(budget))
        .is_some_and(|due| due < deadline)
}
fn checked_unchanged(d: &Dispatch) -> Result<(), ProtocolError> {
    d.checked_unchanged.store(true, Ordering::SeqCst);
    d.acknowledged_postcondition.store(true, Ordering::SeqCst);
    Err(ProtocolError::NotActionable)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordingSize {
    width: u32,
    height: u32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordingStart {
    identity_scope: String,
    size: Option<RecordingSize>,
    quality: Option<u8>,
}
impl RecordingStart {
    fn capture_options(
        &self,
        output_limit: Option<usize>,
    ) -> Result<CaptureOptions, ProtocolError> {
        CaptureOptions {
            size: self.size.as_ref().map(|s| (s.width, s.height)),
            jpeg: true,
            quality: self.quality,
            output_limit,
        }
        .validate()
        .map_err(|_| ProtocolError::InvalidArguments)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordingStop {
    identity_scope: String,
}
struct RecordingAttachment {
    client: Arc<super::cdp::client::CdpClient>,
    reservation: super::client_targets::AuxiliaryAttachmentReservation,
    startup: Option<tokio::task::JoinHandle<Result<String, String>>>,
    session: Option<String>,
    detached: Arc<AtomicBool>,
    acknowledged_cleanup: HashSet<String>,
    terminal_complete: bool,
    cleanup_failed: bool,
}
impl RecordingAttachment {
    async fn settle_terminal(
        &mut self,
        client: &Arc<super::cdp::client::CdpClient>,
        proof: &super::client_enrollment::NativeTerminalProof,
    ) -> Result<(), ProtocolError> {
        proof.check_client(client)?;
        if !Arc::ptr_eq(client, &self.client) || !*self.client.remote_connection_closed().borrow() {
            return Err(ProtocolError::CleanupFailed);
        }
        if let Some(job) = self.startup.as_mut() {
            // Retain the handle until its await completes, including when this
            // cleanup call is cancelled. A lost attach ACK is not replayed.
            let result = job.await;
            self.startup.take();
            if let Ok(Ok(session)) = result {
                self.session = Some(session.clone());
                let _ = self.reservation.claim(&session);
            }
        }
        self.reservation.settle_terminal_connection(proof)?;
        self.terminal_complete = true;
        self.cleanup_failed = false;
        Ok(())
    }
    async fn settle(&mut self) -> bool {
        if self.terminal_complete {
            return true;
        }
        if let Some(job) = self.startup.as_mut() {
            let result = job.await;
            self.startup.take();
            match result {
                Ok(Ok(session)) => {
                    self.session = Some(session.clone());
                    let _ = self.reservation.claim(&session);
                }
                _ => self.reservation.quarantine(),
            }
        }
        if self.detached.load(Ordering::SeqCst) {
            if let Some(session) = &self.session {
                self.acknowledged_cleanup.insert(session.clone());
            }
        }
        let Ok(sessions) = self.reservation.cleanup_sessions() else {
            self.cleanup_failed = true;
            return false;
        };
        if self.session.is_none()
            || sessions
                .iter()
                .any(|s| !self.acknowledged_cleanup.contains(s))
        {
            self.reservation.quarantine();
        }
        for session in sessions {
            if !self.acknowledged_cleanup.contains(&session) {
                if recording::detach_capture_session_checked(&self.client, &session).await {
                    self.acknowledged_cleanup.insert(session.clone());
                } else {
                    self.cleanup_failed = true;
                    continue;
                }
            }
            if self.session.as_deref() != Some(session.as_str()) {
                self.cleanup_failed |= self.reservation.candidate_detached(&session).is_err();
            }
        }
        let complete = self.session.as_ref().is_some_and(|session| {
            self.acknowledged_cleanup.contains(session)
                && self.reservation.detached(session).is_ok()
        });
        complete && !self.cleanup_failed
    }
}
struct OwnedRecording {
    state: RecordingState,
    directory: OwnedDirectory,
    reservation: Option<ArtifactReservation>,
    scope: BlobScope,
    started_at: String,
    ordinal: u64,
    read_job: Option<tokio::task::JoinHandle<Result<Vec<u8>, ProtocolError>>>,
    bytes: Option<Vec<u8>>,
    cleanup_complete: Arc<AtomicBool>,
    attachment: Option<RecordingAttachment>,
}
#[derive(Default)]
struct RecordingLedger {
    authority: Option<AttemptArtifacts>,
    options: Option<CaptureOptions>,
    current: Option<OwnedRecording>,
    finished: Vec<OwnedRecording>,
    armed: bool,
    abandoned: bool,
    ordinal: u64,
    lost: Option<u64>,
    cleanup_failed: bool,
    filesystem_cleanup_failed: bool,
}
impl RecordingLedger {
    async fn finish_current(&mut self, blobs: &BlobStore) -> Result<(), ProtocolError> {
        let Some(owned) = self.current.as_mut() else {
            return Ok(());
        };
        // A failed native stop can still leave a valid finalized WebM. Retain
        // that artifact rather than discarding it because of the stop status.
        let had_capture = owned.state.capture_task.is_some();
        let stop = recording::stop_recording_task(&mut owned.state).await;
        let acknowledgement_failed = stop
            .as_ref()
            .is_err_and(|error| error == recording::FRAME_ACK_UNAVAILABLE);
        if let Some(attachment) = owned.attachment.as_mut() {
            let clean = attachment.settle().await;
            self.cleanup_failed |= !clean;
            if !had_capture
                && clean
                && owned.state.encoder_complete.load(Ordering::SeqCst)
                && !owned.state.cleanup_task_failed
            {
                owned.cleanup_complete.store(true, Ordering::SeqCst);
            }
        }
        self.cleanup_failed |= !owned.cleanup_complete.load(Ordering::SeqCst);
        let _ = recording::recording_stop(&mut owned.state);
        if owned.read_job.is_none() && owned.bytes.is_none() {
            let path = owned.state.output_path.clone();
            let limit = blobs.producer_limit();
            let (sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            owned.read_job = Some(tokio::task::spawn_blocking(move || {
                let _sender = sender;
                read_recording(
                    path,
                    limit,
                    Instant::now() + Duration::from_secs(30),
                    cancellation,
                )
            }));
        }
        let result = if let Some(job) = owned.read_job.as_mut() {
            let result = job.await;
            owned.read_job.take();
            result
                .map_err(|_| ProtocolError::BrowserFailure)
                .and_then(|v| v)
        } else {
            Ok(owned.bytes.take().ok_or(ProtocolError::BrowserFailure)?)
        };
        match result {
            Ok(bytes) => {
                blobs
                    .shrink_artifact(
                        owned
                            .reservation
                            .as_mut()
                            .ok_or(ProtocolError::BrowserFailure)?,
                        bytes.len(),
                    )
                    .map_err(|_| ProtocolError::CapacityExceeded)?;
                owned.bytes = Some(bytes);
                self.finished
                    .push(self.current.take().ok_or(ProtocolError::BrowserFailure)?);
            }
            Err(_) => {
                self.lost.get_or_insert(owned.ordinal);
                if !owned.cleanup_complete.load(Ordering::SeqCst) {
                    return Err(ProtocolError::CleanupFailed);
                }
                let owned = self.current.take().ok_or(ProtocolError::BrowserFailure)?;
                if owned.directory.close().is_err() {
                    self.cleanup_failed = true;
                    self.filesystem_cleanup_failed = true;
                    return Err(ProtocolError::CleanupFailed);
                }
            }
        }
        if acknowledgement_failed {
            return Err(ProtocolError::BrowserFailure);
        }
        Ok(())
    }
    async fn settle_start(
        &mut self,
        d: &Dispatch,
        result: Result<(), ProtocolError>,
    ) -> Result<(), ProtocolError> {
        self.armed = result.is_ok();
        if result.is_err() && self.discard_current().await.is_err() {
            d.cleanup.store(true, Ordering::SeqCst);
        }
        result
    }
    async fn discard_current(&mut self) -> Result<(), ProtocolError> {
        let mut failed = false;
        if let Some(owned) = self.current.as_mut() {
            let had_capture = owned.state.capture_task.is_some();
            let _ = recording::stop_recording_task(&mut owned.state).await;
            if let Some(attachment) = owned.attachment.as_mut() {
                let clean = attachment.settle().await;
                failed |= !clean;
                if !had_capture
                    && clean
                    && owned.state.encoder_complete.load(Ordering::SeqCst)
                    && !owned.state.cleanup_task_failed
                {
                    owned.cleanup_complete.store(true, Ordering::SeqCst);
                }
            }
            failed |= !owned.cleanup_complete.load(Ordering::SeqCst);
            if let Some(job) = owned.read_job.as_mut() {
                failed |= job.await.is_err();
            }
            owned.read_job.take();
        }
        // A failed startup/stop still owns its exact attachment and private
        // reservation. Keep it available for proven terminal settlement.
        if failed {
            return Err(ProtocolError::CleanupFailed);
        }
        if let Some(owned) = self.current.take() {
            failed |= owned.directory.close().is_err();
        }
        if failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
}
impl ClientActions {
    /// Settle only resources belonging to the exact terminal native connection.
    /// This does not prove host target, process, or evaluate termination, and
    /// leaves private files, quota reservations, and attempt authority intact.
    pub(crate) async fn settle_terminal_recording(
        &self,
        client: &Arc<super::cdp::client::CdpClient>,
        proof: &super::client_enrollment::NativeTerminalProof,
    ) -> Result<(), ProtocolError> {
        proof.check_client(client)?;
        if !*client.remote_connection_closed().borrow() {
            return Err(ProtocolError::CleanupFailed);
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut ledger = self.recording.lock().await;
            let mut failed = false;
            let RecordingLedger {
                current, finished, ..
            } = &mut *ledger;
            for owned in current.iter_mut().chain(finished.iter_mut()) {
                let Some(attachment) = owned.attachment.as_mut() else {
                    // No connection-specific ownership means no authority to
                    // clear an existing unrelated cleanup failure.
                    failed |= !owned.cleanup_complete.load(Ordering::SeqCst);
                    continue;
                };
                if !Arc::ptr_eq(&attachment.client, client) {
                    // Earlier, already settled segments may belong to a previous
                    // connection; their artifacts remain in the same attempt.
                    failed |= !owned.cleanup_complete.load(Ordering::SeqCst);
                    continue;
                }
                let _ = recording::stop_recording_task(&mut owned.state).await;
                let remote = attachment.settle_terminal(client, proof).await.is_ok();
                if let Some(job) = owned.read_job.as_mut() {
                    let result = job.await;
                    owned.read_job.take();
                    match result {
                        Ok(Ok(bytes)) => owned.bytes = Some(bytes),
                        Ok(Err(_)) => {} // Artifact validity is independent.
                        Err(_) => owned.state.cleanup_task_failed = true,
                    }
                }
                let complete = remote
                    && owned.state.encoder_complete.load(Ordering::SeqCst)
                    && !owned.state.cleanup_task_failed;
                owned.cleanup_complete.store(complete, Ordering::SeqCst);
                failed |= !complete;
            }
            // Do not clear historical filesystem failures with connection proof.
            if !failed && (ledger.current.is_some() || !ledger.finished.is_empty()) {
                ledger.cleanup_failed = ledger.filesystem_cleanup_failed;
            }
            if failed || ledger.cleanup_failed {
                Err(ProtocolError::CleanupFailed)
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|_| ProtocolError::CleanupFailed)?
    }
    /// Read the one attempt ledger, bounded independently of a caller RPC.
    pub async fn is_recording_armed(&self) -> Result<bool, ProtocolError> {
        let ledger = tokio::time::timeout(Duration::from_secs(5), self.recording.lock())
            .await
            .map_err(|_| ProtocolError::DeadlineExceeded)?;
        Ok(ledger.armed && !ledger.abandoned)
    }
    /// Lifecycle-only: call before disposing/revoking the recorded page scope.
    /// The owner retains this future until capture and file reads have joined.
    pub async fn recording_page_closing(
        &self,
        expected_scope: &str,
        blobs: &BlobStore,
    ) -> Result<(), ProtocolError> {
        let mut ledger = self.recording.lock().await;
        if ledger
            .current
            .as_ref()
            .is_some_and(|v| v.scope.identity_scope != expected_scope)
        {
            return Err(ProtocolError::StaleScope);
        }
        ledger.finish_current(blobs).await?;
        if ledger.cleanup_failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
    /// Lifecycle-only: new scope is already initialized and admitted. This
    /// never observes target events or creates a second page registry.
    pub async fn recording_page_opened(&self, ctx: ActionContext<'_>) -> Result<(), ActionFailure> {
        let d = Dispatch::default();
        let mut ledger = self.recording.lock().await;
        if !ledger.armed || ledger.abandoned {
            return Ok(());
        }
        if ledger.current.is_some() {
            return Err(d.failure(ProtocolError::NotActionable));
        }
        let result = Self::begin_segment(&ctx, &d, &mut ledger).await;
        ledger
            .settle_start(&d, result)
            .await
            .map_err(|error| d.failure(error))
    }
    /// Final attempt teardown. Disarm before awaiting so queued page-open
    /// hooks cannot create another segment; retire publication authority first.
    pub async fn abandon_recording(&self) -> Result<(), ProtocolError> {
        let mut ledger = self.recording.lock().await;
        ledger.abandoned = true;
        ledger.armed = false;
        let mut failed = ledger.cleanup_failed;
        failed |= ledger
            .authority
            .as_ref()
            .is_some_and(|a| a.retire().is_err());
        failed |= ledger.discard_current().await.is_err();
        for owned in ledger.finished.drain(..) {
            failed |= owned.directory.close().is_err();
        }
        ledger.lost = None;
        ledger.authority.take();
        if failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
    async fn record_start(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        request: RecordingStart,
    ) -> Result<(), ProtocolError> {
        scope(ctx, &request.identity_scope)?;
        let options = request.capture_options(Some(ctx.blobs.producer_limit()))?;
        let mut ledger = self.recording.lock().await;
        if ledger.abandoned {
            return Err(ProtocolError::StaleScope);
        }
        if ledger.current.is_some() {
            ledger.armed = true;
            return Ok(());
        }
        if ledger.authority.is_none() {
            ledger.authority = Some(
                ctx.blobs
                    .begin_artifact_attempt(&ctx.blob_scope())
                    .map_err(|_| ProtocolError::StaleScope)?,
            );
        }
        ledger.options = Some(options);
        let result = Self::begin_segment(ctx, d, &mut ledger).await;
        ledger.settle_start(d, result).await
    }
    async fn begin_segment(
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        ledger: &mut RecordingLedger,
    ) -> Result<(), ProtocolError> {
        ctx.check()?;
        let mut options = ledger.options.ok_or(ProtocolError::BrowserFailure)?;
        if options.size.is_none() {
            let metrics = ctx
                .command(
                    d,
                    false,
                    &ctx.page.page_session_id,
                    "Page.getLayoutMetrics",
                    json!({}),
                )
                .await?;
            let viewport = &metrics["cssLayoutViewport"];
            let width = viewport["clientWidth"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(ProtocolError::BrowserFailure)?;
            let height = viewport["clientHeight"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(ProtocolError::BrowserFailure)?;
            options.size = Some((width, height));
            options = options
                .validate()
                .map_err(|_| ProtocolError::InvalidArguments)?;
        }
        ctx.bounded(recording::check_ffmpeg_available()).await?;
        let reservation = ctx
            .blobs
            .reserve_artifact(
                ledger
                    .authority
                    .as_ref()
                    .ok_or(ProtocolError::BrowserFailure)?,
                &ctx.blob_scope(),
            )
            .map_err(|_| ProtocolError::CapacityExceeded)?;
        let directory = OwnedDirectory::create()?;
        ledger.ordinal = ledger
            .ordinal
            .checked_add(1)
            .filter(|v| *v <= 1_000_000)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        let name = if ledger.ordinal == 1 {
            "video.webm".into()
        } else {
            format!("video-part{}.webm", ledger.ordinal)
        };
        let path = directory
            .path
            .join(name)
            .to_str()
            .ok_or(ProtocolError::BrowserFailure)?
            .to_owned();
        let mut state = RecordingState::new();
        if let Some(journal) = OperationJournalHandle::current() {
            journal.mark_mutation_maybe_submitted()?;
        }
        recording::recording_start(&mut state, &path, RecordingOptions::default())
            .map_err(|_| ProtocolError::BrowserFailure)?;
        ledger.current = Some(OwnedRecording {
            state,
            directory,
            reservation: Some(reservation),
            scope: ctx.blob_scope(),
            started_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            ordinal: ledger.ordinal,
            read_job: None,
            bytes: None,
            cleanup_complete: Arc::new(AtomicBool::new(true)),
            attachment: None,
        });
        let owned = ledger
            .current
            .as_mut()
            .ok_or(ProtocolError::BrowserFailure)?;
        let initial = ctx
            .bounded(recording::capture_initial_image_with_options(
                &ctx.page.client,
                &ctx.page.page_session_id,
                options,
            ))
            .await?;
        ctx.check()?;
        let reservation = ctx.page.targets.reserve_auxiliary_attachment(
            &ctx.page.identity_scope,
            &ctx.page.target_id,
            &ctx.page.page_session_id,
        )?;
        if let Some(debt) = ctx.page.client.debt_ledger() {
            debt.register_recording_target(&ctx.page.target_id)?;
        }
        let client = ctx.page.client.clone();
        let target = ctx.page.target_id.clone();
        let shared = owned.state.capture_session.clone();
        // Register retained ownership synchronously with spawn, before any
        // cancellation-sensitive await. The bounded job still owns an unknown
        // attachment outcome when the caller stops waiting.
        d.mark();
        owned.cleanup_complete.store(false, Ordering::SeqCst);
        owned.attachment = Some(RecordingAttachment {
            client: client.clone(),
            reservation,
            session: None,
            detached: Arc::new(AtomicBool::new(false)),
            acknowledged_cleanup: HashSet::new(),
            terminal_complete: false,
            cleanup_failed: false,
            startup: Some(tokio::spawn(async move {
                tokio::time::timeout(
                    Duration::from_secs(5),
                    recording::attach_capture_session_to_target(&client, &target, &shared),
                )
                .await
                .map_err(|_| "Native recorder attach outcome unknown".to_owned())?
            })),
        });
        let attachment = owned
            .attachment
            .as_mut()
            .ok_or(ProtocolError::BrowserFailure)?;
        let job = attachment
            .startup
            .as_mut()
            .ok_or(ProtocolError::BrowserFailure)?;
        let mut cancellation = ctx.operation.cancellation.clone();
        let result = tokio::select! {
            result = job => result,
            _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
            _ = tokio::time::sleep_until(ctx.operation.deadline.into()) => return Err(ProtocolError::DeadlineExceeded),
        };
        // Clear a terminal JoinHandle before propagating any failure. A pending
        // handle remains owned above when cancellation wins the select.
        attachment.startup.take();
        let capture = match result {
            Ok(Ok(session)) => session,
            _ => {
                attachment.reservation.quarantine();
                return Err(ProtocolError::BrowserFailure);
            }
        };
        attachment.session = Some(capture.clone());
        attachment.reservation.claim(&capture)?;
        ctx.check()?;
        let frames = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let captured = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let sheets = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        owned.state.encoder_complete.store(false, Ordering::SeqCst);
        owned.state.capture_task = Some(recording::spawn_recording_task_with_session_proof(
            ctx.page.client.clone(),
            capture,
            initial,
            path,
            owned.state.fps,
            frames.clone(),
            captured.clone(),
            false,
            owned.state.shared_cursor.clone(),
            owned.state.cursor_overlays.clone(),
            Vec::new(),
            None,
            owned.state.contact_sheet_threshold,
            sheets.clone(),
            cancel_rx,
            options,
            Some(ready_tx),
            Some(owned.cleanup_complete.clone()),
            Some(attachment.detached.clone()),
            Some(owned.state.encoder_complete.clone()),
        ));
        owned.state.cancel_tx = Some(cancel_tx);
        owned.state.shared_frame_count = Some(frames);
        owned.state.shared_captured_count = Some(captured);
        owned.state.shared_contact_sheet_count = Some(sheets);
        ctx.bounded(async {
            ready_rx
                .await
                .map_err(|_| "Native recording startup unavailable".to_string())?
        })
        .await?;
        ctx.check()
    }
    async fn record_stop(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        request: RecordingStop,
    ) -> Result<Value, ProtocolError> {
        scope(ctx, &request.identity_scope)?;
        let mut ledger = self.recording.lock().await;
        if ledger.armed || ledger.current.is_some() {
            if let Some(journal) = OperationJournalHandle::current() {
                journal.mark_mutation_maybe_submitted()?;
            }
        }
        ledger.armed = false;
        if ledger.current.is_some() {
            d.mark();
        }
        let finalized = ledger.finish_current(ctx.blobs).await;
        d.cleanup.store(ledger.cleanup_failed, Ordering::SeqCst);
        finalized?;
        ctx.check()?;
        if ledger.cleanup_failed {
            return Err(ProtocolError::CleanupFailed);
        }
        if let Some(ordinal) = ledger.lost.take() {
            // Finalization and cleanup are acknowledged, but the recording is
            // incomplete. Report this once without publishing retained blobs;
            // the public adapter raises the artifact error and may retry stop.
            return Ok(json!({"identityScope":ctx.page.identity_scope,"missingSegment":ordinal}));
        }
        if ledger
            .finished
            .iter()
            .any(|v| v.reservation.is_none() || v.bytes.is_none())
        {
            return Err(ProtocolError::BrowserFailure);
        }
        let mut items = Vec::with_capacity(ledger.finished.len());
        for owned in &mut ledger.finished {
            items.push((
                owned
                    .reservation
                    .take()
                    .ok_or(ProtocolError::BrowserFailure)?,
                owned.bytes.take().ok_or(ProtocolError::BrowserFailure)?,
            ));
        }
        let infos = match ctx.blobs.finish_artifact_batch(items, ctx.blob_scope()) {
            Ok(infos) => infos,
            Err((_, items)) => {
                for (owned, (reservation, bytes)) in ledger.finished.iter_mut().zip(items) {
                    owned.reservation = Some(reservation);
                    owned.bytes = Some(bytes);
                }
                return Err(ProtocolError::StaleScope);
            }
        };
        let mut segments: Vec<Value> = Vec::with_capacity(infos.len());
        let mut cleanup_failed = false;
        for (owned, info) in ledger.finished.drain(..).zip(&infos) {
            let started_at = owned.started_at;
            cleanup_failed |= owned.directory.close().is_err();
            segments.push(json!({"identityScope":ctx.page.identity_scope,"handle":info.handle,"size":info.size,"sha256":info.sha256,"mediaType":"video/webm","startedAt":started_at}));
        }
        let check = ctx.check();
        if cleanup_failed || check.is_err() {
            for info in infos {
                cleanup_failed |= ctx.blobs.release(&ctx.blob_scope(), &info.handle).is_err();
            }
            d.cleanup.store(cleanup_failed, Ordering::SeqCst);
            return Err(check.err().unwrap_or(ProtocolError::CleanupFailed));
        }

        Ok(json!({"identityScope":ctx.page.identity_scope,"segments":segments}))
    }
}

/// Focus is discovered by the native AX tree, including closed shadow roots.
/// No synthetic locator/ref or injected shadow-root registry is introduced.
fn observation_action_error(
    error: super::client_observation::ObservationError,
    dispatch: &Dispatch,
) -> ProtocolError {
    use super::client_observation::ObservationError;
    match error {
        ObservationError::CleanupFailed { primary } => {
            dispatch.cleanup.store(true, Ordering::SeqCst);
            primary
                .map(|error| observation_action_error(*error, dispatch))
                .unwrap_or(ProtocolError::CleanupFailed)
        }
        ObservationError::Cancelled => ProtocolError::Cancelled,
        ObservationError::DeadlineExceeded => ProtocolError::DeadlineExceeded,
        ObservationError::StaleReference
        | ObservationError::Superseded
        | ObservationError::FrameNotFound(_)
        | ObservationError::FrameAmbiguous(_) => ProtocolError::StaleReference,
        ObservationError::ResourceLimit => ProtocolError::CapacityExceeded,
        ObservationError::InvalidArguments => ProtocolError::InvalidArguments,
        ObservationError::UnsupportedCapability => ProtocolError::UnsupportedCapability,
        ObservationError::PolicyDenied => ProtocolError::PolicyDenied,
        ObservationError::BackendFailure => ProtocolError::BrowserFailure,
    }
}
fn require_recovery_observation(ctx: &ActionContext<'_>) -> Result<(), ProtocolError> {
    if ctx
        .observation_after
        .is_some_and(|baseline| ctx.observed_revision <= baseline)
    {
        return Err(ProtocolError::StaleReference);
    }
    Ok(())
}
async fn require_editable_focus(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
) -> Result<(), ProtocolError> {
    require_recovery_observation(ctx)?;
    let frames = super::client_observation::enumerate_frames(
        &ctx.page.client,
        &ctx.page.page_session_id,
        ctx.iframe_sessions,
        ctx.operation,
    )
    .await
    .map_err(|error| observation_action_error(error, d))?;
    ctx.check()?;
    for frame in frames {
        let tree = ctx
            .command(
                d,
                false,
                &frame.binding.session,
                "Accessibility.getFullAXTree",
                json!({"frameId":frame.binding.frame}),
            )
            .await?;
        let nodes = tree["nodes"]
            .as_array()
            .ok_or(ProtocolError::BrowserFailure)?;
        for node in nodes {
            if !node["properties"].as_array().is_some_and(|properties| {
                properties.iter().any(|property| {
                    property["name"] == "focused" && property["value"]["value"] == true
                })
            }) {
                continue;
            }
            let backend = node["backendDOMNodeId"]
                .as_i64()
                .ok_or(ProtocolError::BrowserFailure)?;
            let object = ctx
                .bounded(element::resolve_exact_object(
                    &ctx.page.client,
                    &frame.binding,
                    backend,
                ))
                .await?;
            let resolved = Resolved {
                realm: None,
                object,
                session: frame.binding.session.clone(),
                binding: frame.binding.clone(),
            };
            let result=resolved.call(ctx,d,false,r#"function(){
              if(this===document)return false;
              if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};
              if(this===document.body||this===document.documentElement)return false;
              if(this instanceof HTMLInputElement)return !this.disabled&&!this.readOnly&&!['button','submit','reset','checkbox','radio','file','image','range','color'].includes(this.type);
              if(this instanceof HTMLTextAreaElement)return !this.disabled&&!this.readOnly;
              if(this instanceof HTMLSelectElement||this instanceof HTMLButtonElement||this instanceof HTMLAnchorElement||this instanceof HTMLIFrameElement||this instanceof HTMLFrameElement)return false;
              return this.nodeType===1;
            }"#,vec![]).await;
            let released = resolved.release(ctx).await;
            if released.is_err() {
                d.cleanup.store(true, Ordering::SeqCst);
                return result.map(|_| ()).and(Err(ProtocolError::CleanupFailed));
            }
            ctx.check()?;
            if result? == true {
                return Ok(());
            }
        }
    }
    Err(ProtocolError::NotActionable)
}

fn stage_upload(
    directory_name: Option<String>,
    staged: Vec<(PathBuf, BlobLease)>,
    deadline: Instant,
    cancellation: tokio::sync::watch::Receiver<CancelSignal>,
) -> Result<StagedUpload, ProtocolError> {
    let check = || {
        if *cancellation.borrow() != CancelSignal::None {
            Err(ProtocolError::Cancelled)
        } else if Instant::now() >= deadline {
            Err(ProtocolError::DeadlineExceeded)
        } else {
            Ok(())
        }
    };
    check()?;
    let directory = OwnedDirectory::create()?;
    let result = (|| -> Result<Vec<String>, ProtocolError> {
        let root = if let Some(name) = &directory_name {
            let root = directory.path.join(name);
            std::fs::create_dir(&root).map_err(|_| ProtocolError::BrowserFailure)?;
            root
        } else {
            directory.path.clone()
        };
        let mut paths = Vec::new();
        for (relative, lease) in &staged {
            check()?;
            let path = root.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|_| ProtocolError::BrowserFailure)?;
            }
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&path)
                .map_err(|_| ProtocolError::BrowserFailure)?;
            for chunk in lease.bytes().chunks(256 * 1024) {
                check()?;
                std::io::Write::write_all(&mut file, chunk)
                    .map_err(|_| ProtocolError::BrowserFailure)?;
            }
            paths.push(
                path.to_str()
                    .ok_or(ProtocolError::BrowserFailure)?
                    .to_owned(),
            );
        }
        if directory_name.is_some() {
            paths = vec![root
                .to_str()
                .ok_or(ProtocolError::BrowserFailure)?
                .to_owned()];
        }
        check()?;
        Ok(paths)
    })();
    let (paths, error) = match result {
        Ok(paths) => (paths, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    Ok(StagedUpload {
        directory,
        paths,
        _leases: staged.into_iter().map(|(_, lease)| lease).collect(),
        error,
    })
}

fn read_recording(
    path: String,
    limit: usize,
    deadline: Instant,
    cancellation: tokio::sync::watch::Receiver<CancelSignal>,
) -> Result<Vec<u8>, ProtocolError> {
    let metadata = std::fs::metadata(&path).map_err(|_| ProtocolError::BrowserFailure)?;
    if metadata.len() == 0 || metadata.len() >= limit as u64 {
        return Err(ProtocolError::CapacityExceeded);
    }
    let mut file = std::fs::File::open(path).map_err(|_| ProtocolError::BrowserFailure)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut buffer = [0u8; 256 * 1024];
    loop {
        if *cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        let count = std::io::Read::read(&mut file, &mut buffer)
            .map_err(|_| ProtocolError::BrowserFailure)?;
        if count == 0 {
            break;
        }
        if bytes.len() + count > limit {
            return Err(ProtocolError::CapacityExceeded);
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    if !bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]) {
        return Err(ProtocolError::BrowserFailure);
    }
    Ok(bytes)
}

#[cfg(test)]
pub(crate) const FIXTURE_SECURE_SELECTOR: &str = "input[type=\"password\" i]";
#[cfg(test)]
pub(crate) fn fixture_configuration(scope: &str, site: Option<&str>) -> Value {
    json!({"identityScope":scope,"testIdAttribute":"data-testid",
        "secureFieldSelector":FIXTURE_SECURE_SELECTOR,
        "requestPolicy":{"site":site},"downloads":{"source":"local"}})
}

#[cfg(test)]
pub(crate) fn fixture_scope_open(source: &str, endpoint: Option<&str>) -> Value {
    let mut value = json!({"source":source,"context":"isolated"});
    if let Some(endpoint) = endpoint {
        value["endpoint"] = json!(endpoint);
    }
    if source == "launch" {
        value["headless"] = json!(true);
        value["blockServiceWorkers"] = json!(false);
        value["viewport"] = json!({"width":800,"height":600});
        value["media"] = json!({});
        value["initScripts"] = json!([]);
    }
    value
}
#[cfg(test)]
pub(crate) fn fixture_routes(scope: &str) -> Value {
    json!({"identityScope":scope,"version":1,"registrationIds":[]})
}

/// Direct-executor fixtures must reproduce the real reader's broker admission
/// and settlement. ClientBrowser itself owns start(); never pre-start its lease.
#[cfg(test)]
pub(crate) struct FixtureOperations {
    broker: Arc<super::client_session::ClientSession>,
    sequence: u64,
}
#[cfg(test)]
impl FixtureOperations {
    pub(crate) fn new(broker: Arc<super::client_session::ClientSession>) -> Self {
        Self {
            broker,
            sequence: 0,
        }
    }
    pub(crate) async fn execute(
        &mut self,
        executor: &impl super::client_transport::ClientExecutor,
        command: &str,
        args: Value,
        seconds: u64,
    ) -> Result<super::client_transport::NativeOutcome, ProtocolError> {
        let args = args
            .as_object()
            .ok_or(ProtocolError::InvalidArguments)?
            .clone();
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        let lease = self.broker.admit(
            1,
            self.sequence,
            seconds
                .checked_mul(1000)
                .ok_or(ProtocolError::InvalidTimeout)?,
        )?;
        self.broker.validate_reconnect_operation(&lease)?;
        let outcome = executor.execute(command.into(), args, lease).await;
        self.broker.settle(1, self.sequence, outcome.effects)?;
        Ok(outcome)
    }
    /// Also reproduce the real writer's post-settlement result ACK. This opens
    /// only the exact operation's staged sink, never target/enrollment readiness.
    pub(crate) async fn execute_written(
        &mut self,
        executor: &impl super::client_transport::ClientExecutor,
        sink: &super::client_transport::ClientEventSink,
        command: &str,
        args: Value,
        seconds: u64,
    ) -> Result<super::client_transport::NativeOutcome, ProtocolError> {
        use super::client_protocol::{ServerMessage, WireError};
        let outcome = self.execute(executor, command, args, seconds).await?;
        let (_, scope_state) = self.broker.health()?;
        let (ok, data, error) = match &outcome.result {
            Ok(data) => (true, Some(data.clone()), None),
            Err(code) => (false, None, Some(WireError { code: code.clone() })),
        };
        sink.acknowledge_result_for_test(&ServerMessage::Result {
            id: "synthetic-fixture-result".into(),
            generation: 1,
            operation_seq: self.sequence,
            ok,
            data,
            error,
            effects: outcome.effects,
            scope_state,
            retention: None,
        })?;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        cdp::client::CdpClient, client_blobs::BlobLimits, client_browser::ExecutionGate,
        client_targets::ClientTargets,
    };
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    mod legacy_locator_dispatch {
        include!("client_actions_locator_dispatch_tests.rs");
    }
    mod direct_point_clicks {
        include!("client_actions_direct_point_click_tests.rs");
    }
    #[test]
    fn readonly_timing_is_silent_when_disabled_tap_success_or_mutated() {
        let deadline = Instant::now() + Duration::from_secs(1);
        for mode in ["disabled", "tap", "success", "mutated"] {
            let d = Dispatch::default();
            d.readonly_preparation_enabled
                .store(mode != "tap", Ordering::SeqCst);
            d.start_readonly_timing(deadline, mode != "disabled");
            if matches!(mode, "disabled" | "tap") {
                assert!(d.readonly_timing.get().is_none());
            }
            if mode == "mutated" {
                d.mark();
            }
            let result = finish_dispatch(
                &d,
                if mode == "success" {
                    Ok(Value::Null)
                } else {
                    Err(ProtocolError::DeadlineExceeded)
                },
            );
            assert!(
                d.readonly_timing_failure(deadline, &result).is_none(),
                "{mode}"
            );
        }
    }
    #[test]
    fn readonly_timing_retires_old_ack_without_classifying_late_wake() {
        let d = Dispatch::default();
        d.readonly_preparation_enabled.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(1);
        d.start_readonly_timing(deadline, true);
        d.readonly_preparation_refusal.store(true, Ordering::SeqCst);
        d.update_readonly_timing(|timing| {
            timing.ack_us = Some(300_000);
            timing.ack = ReadonlyAck::Current;
            timing.wake_us = Some(40_000);
        });
        assert_eq!(
            preparation_refusal_checkpoint(
                &d,
                Duration::from_millis(260),
                Duration::from_millis(40),
                || panic!("below floor cannot classify")
            ),
            Ok(())
        );
        d.begin_preparation_attempt();
        let result = finish_dispatch(&d, Err(ProtocolError::DeadlineExceeded));
        let fact = d.readonly_timing_failure(Instant::now(), &result).unwrap();
        assert_eq!(fact.ack, ReadonlyAck::Retired);
        assert_eq!(fact.ack_us, Some(300_000));
        assert_eq!(fact.wake_us, Some(40_000));
        assert_eq!(fact.window, ReadonlyWindow::NotEntered);
        assert!(fact.deadline && fact.zero_input);
        assert_eq!(fact.cleanup, ReadonlyCleanup::NotObserved);
        assert!(d.readonly_timing_failure(deadline, &result).is_none());
    }
    #[test]
    fn readonly_timing_keeps_observed_window_and_original_failure_through_cleanup() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let d = Dispatch::default();
        d.readonly_preparation_enabled.store(true, Ordering::SeqCst);
        d.start_readonly_timing(deadline, true);
        d.readonly_preparation_refusal.store(true, Ordering::SeqCst);
        d.update_readonly_timing(|timing| {
            timing.ack_us = Some(280_000);
            timing.ack = ReadonlyAck::Current;
        });
        let primary = preparation_refusal_checkpoint(
            &d,
            Duration::from_millis(280),
            Duration::from_millis(20),
            || Err(ProtocolError::StaleScope),
        )
        .unwrap_err();
        d.cleanup.store(true, Ordering::SeqCst);
        d.readonly_preparation_disqualified
            .store(true, Ordering::SeqCst);
        let result = finish_dispatch(&d, Err(primary));
        let fact = d.readonly_timing_failure(deadline, &result).unwrap();
        assert_eq!(fact.error, ProtocolError::StaleScope);
        assert_eq!(result.unwrap_err().error, ProtocolError::StaleScope);
        assert_eq!(fact.window, ReadonlyWindow::Entered);
        assert_eq!(fact.ack, ReadonlyAck::Retired);
        assert_eq!(fact.cleanup, ReadonlyCleanup::FailureObserved);
        assert!(!fact.deadline);
    }
    #[test]
    fn readonly_timing_does_not_invent_an_unobserved_ack_or_wake() {
        let d = Dispatch::default();
        d.readonly_preparation_enabled.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(1);
        d.start_readonly_timing(deadline, true);
        let result = finish_dispatch(&d, Err(ProtocolError::Cancelled));
        let fact = d.readonly_timing_failure(deadline, &result).unwrap();
        assert_eq!(fact.ack, ReadonlyAck::None);
        assert_eq!(fact.ack_us, None);
        assert_eq!(fact.wake_us, None);
        assert_eq!(fact.fail_us, None);
        assert_eq!(fact.window, ReadonlyWindow::NotEntered);
        assert!(fact.entry_us <= 1_000_000);
        assert_eq!(diagnostic_us(Duration::from_secs(61)), 60_000_000);
    }
    #[test]
    fn readonly_preparation_refusal_uses_current_ack_without_completed_mutation() {
        let d = Dispatch::default();
        d.readonly_preparation_enabled.store(true, Ordering::SeqCst);
        d.begin_preparation_attempt();
        d.readonly_preparation_refusal.store(true, Ordering::SeqCst);
        assert_eq!(
            preparation_refusal_checkpoint(
                &d,
                Duration::from_millis(280),
                Duration::from_millis(20),
                || Ok(())
            ),
            Err(ProtocolError::NotActionable)
        );
        assert!(d.readonly_preparation_stopped.load(Ordering::SeqCst));
        assert!(!d.acknowledged_postcondition.load(Ordering::SeqCst));
        assert!(!d.preparation_enabled.load(Ordering::SeqCst));
        assert_eq!(
            d.failure(ProtocolError::NotActionable).effects,
            Effects::NotDispatched
        );
    }

    #[test]
    fn readonly_preparation_never_uses_missing_stale_mutated_or_below_floor_receipt() {
        for mode in [
            "missing",
            "new-attempt",
            "mutation",
            "retained",
            "below-floor",
        ] {
            let d = Dispatch::default();
            d.readonly_preparation_enabled.store(true, Ordering::SeqCst);
            d.readonly_preparation_refusal
                .store(mode != "missing", Ordering::SeqCst);
            match mode {
                "new-attempt" => d.begin_preparation_attempt(),
                "mutation" => d.mark_mutation(true),
                "retained" => {
                    d.readonly_preparation_disqualified
                        .store(true, Ordering::SeqCst);
                }
                _ => {}
            }
            let remaining = if mode == "below-floor" { 265 } else { 280 };
            assert_eq!(
                preparation_refusal_checkpoint(
                    &d,
                    Duration::from_millis(remaining),
                    Duration::from_millis(20),
                    || panic!("uncertified receipt must not check/classify")
                ),
                Ok(()),
                "{mode}"
            );
            assert!(
                !d.readonly_preparation_stopped.load(Ordering::SeqCst),
                "{mode}"
            );
            assert!(!d.acknowledged_postcondition.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn readonly_preparation_preserves_original_authority_errors() {
        for error in [
            ProtocolError::Cancelled,
            ProtocolError::DeadlineExceeded,
            ProtocolError::StaleScope,
            ProtocolError::StaleReference,
        ] {
            let d = Dispatch::default();
            d.readonly_preparation_enabled.store(true, Ordering::SeqCst);
            d.readonly_preparation_refusal.store(true, Ordering::SeqCst);
            assert_eq!(
                preparation_refusal_checkpoint(
                    &d,
                    Duration::from_millis(280),
                    Duration::from_millis(20),
                    || Err(error.clone())
                ),
                Err(error)
            );
            assert!(!d.readonly_preparation_stopped.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn readonly_preparation_accounts_for_actual_retry_wake_without_widening_tap() {
        let attempt = Duration::from_micros(50);
        let retry = Duration::from_micros(18_500);
        let remaining = Duration::from_millis(284);
        assert!(preparation_has_classification_slack(remaining));
        assert!(!preparation_classification_window(remaining, attempt));
        let late = remaining.saturating_sub(retry);
        assert!(!preparation_has_classification_slack(late));

        let readonly = Dispatch::default();
        readonly
            .readonly_preparation_enabled
            .store(true, Ordering::SeqCst);
        readonly
            .readonly_preparation_refusal
            .store(true, Ordering::SeqCst);
        assert_eq!(
            preparation_refusal_checkpoint(
                &readonly,
                remaining,
                preparation_retry_estimate(&readonly, attempt, retry),
                || Ok(())
            ),
            Err(ProtocolError::NotActionable)
        );
        assert!(readonly.readonly_preparation_stopped.load(Ordering::SeqCst));

        readonly
            .readonly_preparation_stopped
            .store(false, Ordering::SeqCst);
        assert_eq!(
            preparation_refusal_checkpoint(
                &readonly,
                late,
                preparation_retry_estimate(&readonly, attempt, retry),
                || panic!("late wake must not mint a safe refusal")
            ),
            Ok(())
        );
        assert!(!readonly.readonly_preparation_stopped.load(Ordering::SeqCst));
        readonly.begin_preparation_attempt();
        assert_eq!(
            preparation_refusal_checkpoint(
                &readonly,
                remaining,
                preparation_retry_estimate(&readonly, attempt, retry),
                || panic!("new probe must invalidate the old receipt")
            ),
            Ok(())
        );

        let tap = Dispatch::default();
        tap.preparation_enabled.store(true, Ordering::SeqCst);
        tap.preparation_refusal.store(true, Ordering::SeqCst);
        assert_eq!(
            preparation_refusal_checkpoint(
                &tap,
                remaining,
                preparation_retry_estimate(&tap, attempt, retry),
                || panic!("read-only retry timing must not widen Tap's window")
            ),
            Ok(())
        );
        assert!(!tap.preparation_stopped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn readonly_release_requires_exact_settled_ack_not_legacy_acceptance() {
        use tokio_tungstenite::tungstenite::Message;
        for mode in ["settled", "held", "rejected", "wrong-session", "untracked"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                while let Some(message) = socket.next().await {
                    let text = match message.unwrap() {
                        Message::Text(text) => text,
                        Message::Close(_) => break,
                        other => panic!("unexpected synthetic frame: {other:?}"),
                    };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    let method = request["method"].as_str().unwrap();
                    let mut reply = match method {
                        "DOM.resolveNode" => {
                            json!({"id":request["id"],"sessionId":"page","result":{"object":{"objectId":"owned-object"}}})
                        }
                        "Runtime.releaseObject" if mode == "held" => continue,
                        "Runtime.releaseObject" if mode == "rejected" => {
                            json!({"id":request["id"],"sessionId":"page","error":{"code":-32000,"message":"synthetic release rejection"}})
                        }
                        "Runtime.releaseObject" => {
                            json!({"id":request["id"],"sessionId":"page","result":{}})
                        }
                        _ => panic!("unexpected synthetic command"),
                    };
                    if mode == "wrong-session" && method == "Runtime.releaseObject" {
                        reply["sessionId"] = json!("foreign-page");
                    }
                    socket.send(Message::Text(reply.to_string())).await.unwrap();
                }
            });
            let client = CdpClient::connect(&url).await.unwrap();
            let ledger = client_debt::OwnerDebtLedger::new(1, "release-fixture".into());
            let journal = ledger
                .operation(
                    client_debt::OperationKey {
                        generation: 1,
                        operation_seq: 1,
                    },
                    "target".into(),
                    "page".into(),
                )
                .unwrap();
            let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let operation = OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline: Instant::now() + Duration::from_secs(3),
                cancellation,
            };
            journal.bind_operation(&operation).unwrap();
            if mode != "untracked" {
                client.install_debt_ledger(ledger.clone()).unwrap();
            }
            journal
                .scope(client.send_command(
                    "DOM.resolveNode",
                    Some(json!({"backendNodeId":42})),
                    Some("page"),
                ))
                .await
                .unwrap();
            let outcome = journal
                .scope(release_object_outcome(&client, "page", "owned-object"))
                .await;
            assert!(
                outcome.accepted,
                "legacy accountable release acceptance changed for {mode}"
            );
            assert_eq!(outcome.settled, mode == "settled", "{mode}");
            if mode == "settled" {
                assert_eq!(ledger.snapshot().object_debt, 0);
            }
            if matches!(mode, "held" | "rejected") {
                assert!(ledger.snapshot().object_debt > 0);
            }
            if mode == "wrong-session" {
                assert!(ledger.snapshot().integrity_lost);
            }
            client.close().await;
            server.abort();
            let _ = server.await;
        }
    }

    #[test]
    fn fresh_frame_facts_cannot_authorize_retained_actions() {
        use super::super::client_observation::ObservationError;
        use super::super::client_protocol::{FrameAmbiguity, FrameSelectionIndex};
        for error in [
            ObservationError::FrameNotFound(FrameSelectionIndex::new(0).unwrap()),
            ObservationError::FrameAmbiguous(FrameAmbiguity::new(1, 2).unwrap()),
        ] {
            let dispatch = Dispatch::default();
            assert_eq!(
                live_query_error(&dispatch, error.clone()),
                ProtocolError::StaleReference
            );
            assert_eq!(
                observation_action_error(error, &dispatch),
                ProtocolError::StaleReference
            );
            assert!(!dispatch.sent.load(Ordering::SeqCst));
            assert!(!dispatch.cleanup.load(Ordering::SeqCst));
        }
    }

    // Test-only, operation-local numeric evidence. A fixed ring retains the
    // last attempt/pause and cleanup boundaries, not request or page content.
    #[derive(Clone, Copy)]
    pub(super) enum PreparationTracePhase {
        BeforeRetry = 1,
        AttemptStart = 2,
        AfterAttempt = 3,
        BeforeRelease = 4,
        AfterRelease = 5,
        Finished = 6,
    }
    #[derive(Clone, Copy, serde::Serialize)]
    struct PreparationTraceEvent {
        phase: u8,
        remaining_us: u64,
        longest_attempt_us: u64,
        flags: u8,
    }
    #[derive(Default)]
    pub(super) struct PreparationTrace {
        events: [Option<PreparationTraceEvent>; 8],
        next: usize,
        recorded: u64,
    }
    impl PreparationTrace {
        fn record(&mut self, event: PreparationTraceEvent) {
            self.events[self.next] = Some(event);
            self.next = (self.next + 1) % self.events.len();
            self.recorded = self.recorded.saturating_add(1);
        }
        fn ordered(&self) -> Vec<PreparationTraceEvent> {
            (0..self.events.len())
                .filter_map(|offset| self.events[(self.next + offset) % self.events.len()])
                .collect()
        }
    }
    pub(super) fn preparation_trace(
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        phase: PreparationTracePhase,
        longest_attempt: Duration,
    ) {
        let micros = |duration: Duration| duration.as_micros().min(u64::MAX as u128) as u64;
        // Bits: enabled, refusal, stopped, disqualified, cleanup failed,
        // acknowledged postcondition. No diagnostic can alter these facts.
        let flags = u8::from(d.preparation_enabled.load(Ordering::SeqCst))
            | (u8::from(d.preparation_refusal.load(Ordering::SeqCst)) << 1)
            | (u8::from(d.preparation_stopped.load(Ordering::SeqCst)) << 2)
            | (u8::from(d.preparation_disqualified.load(Ordering::SeqCst)) << 3)
            | (u8::from(d.cleanup.load(Ordering::SeqCst)) << 4)
            | (u8::from(d.acknowledged_postcondition.load(Ordering::SeqCst)) << 5);
        if let Ok(mut trace) = d.preparation_trace.lock() {
            trace.record(PreparationTraceEvent {
                phase: phase as u8,
                remaining_us: micros(
                    ctx.operation
                        .deadline
                        .saturating_duration_since(Instant::now()),
                ),
                longest_attempt_us: micros(longest_attempt),
                flags,
            });
        }
    }
    pub(super) fn emit_preparation_mismatch(
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        result: &Result<Value, ProtocolError>,
    ) {
        // The two existing positive fixtures expect Completed. Scope names
        // select diagnostics only, never classification or settlement behavior.
        let Err(error) = result else { return };
        if !matches!(
            ctx.page.identity_scope.as_str(),
            "preparation-intercepted" | "preparation-not-actionable"
        ) || d.failure(error.clone()).effects == Effects::Completed
        {
            return;
        }
        preparation_trace(ctx, d, PreparationTracePhase::Finished, Duration::ZERO);
        if let Ok(trace) = d.preparation_trace.lock() {
            eprintln!(
                "native-preparation-mismatch {}",
                json!({"schema": 1, "recorded": trace.recorded, "events": trace.ordered()})
            );
        }
    }

    type Log = Arc<std::sync::Mutex<Vec<Value>>>;
    // Hooks are keyed to one exact scope/generation/sequence, never a process-
    // wide next-action callback. Replacement hooks follow real keyboard ACKs;
    // preparation gates follow real refusal/revalidation ACKs. Neither can
    // manufacture a prefix receipt.
    type BoundaryKey = (String, u64, u64, String);
    enum ReplacementHook {
        Run(Box<dyn FnOnce() + Send>),
        Preparation(Option<PreparationClassificationHook>),
    }
    fn replacement_hooks() -> &'static Mutex<HashMap<BoundaryKey, ReplacementHook>> {
        static HOOKS: std::sync::OnceLock<Mutex<HashMap<BoundaryKey, ReplacementHook>>> =
            std::sync::OnceLock::new();
        HOOKS.get_or_init(Mutex::default)
    }
    struct ReplacementBoundary(BoundaryKey);
    impl ReplacementBoundary {
        fn install(
            scope: &str,
            generation: u64,
            sequence: u64,
            key: &'static str,
            run: impl FnOnce() + Send + 'static,
        ) -> Self {
            let binding = (scope.to_owned(), generation, sequence, key.to_owned());
            assert!(replacement_hooks()
                .lock()
                .unwrap()
                .insert(binding.clone(), ReplacementHook::Run(Box::new(run)))
                .is_none());
            Self(binding)
        }
    }
    impl Drop for ReplacementBoundary {
        fn drop(&mut self) {
            replacement_hooks().lock().unwrap().remove(&self.0);
        }
    }
    pub(super) fn replacement_boundary_hook(ctx: &ActionContext<'_>, key: &str) {
        let binding = (
            ctx.page.identity_scope.clone(),
            ctx.operation.generation,
            ctx.operation.sequence,
            key.to_owned(),
        );
        let hook = replacement_hooks().lock().unwrap().remove(&binding);
        if let Some(ReplacementHook::Run(run)) = hook {
            run();
        }
    }

    const PREPARATION_CLASSIFICATION_BOUNDARY: &str = "preparation-classification";
    #[derive(Clone, Copy)]
    struct PreparationGateEntered {
        deadline: Instant,
        remaining: Duration,
        longest_attempt: Duration,
        authority_valid: bool,
    }
    #[derive(Clone, Copy)]
    struct PreparationGateReleased {
        remaining: Duration,
        authority_valid: bool,
        release_received: bool,
    }
    struct PreparationClassificationHook {
        authority: Arc<super::super::client_enrollment::SettledInputAuthority>,
        entered: tokio::sync::oneshot::Sender<PreparationGateEntered>,
        release: tokio::sync::oneshot::Receiver<()>,
        released: tokio::sync::oneshot::Sender<PreparationGateReleased>,
    }
    struct PreparationClassificationBoundary {
        _registration: ReplacementBoundary,
        entered: tokio::sync::oneshot::Receiver<PreparationGateEntered>,
        release: tokio::sync::oneshot::Sender<()>,
        released: tokio::sync::oneshot::Receiver<PreparationGateReleased>,
    }
    impl PreparationClassificationBoundary {
        fn install(
            fixture: &Fixture,
            authority: Arc<super::super::client_enrollment::SettledInputAuthority>,
        ) -> Self {
            // Only these synthetic, ordinary taps may install the async gate.
            assert!(matches!(
                fixture.page.identity_scope.as_str(),
                "preparation-controlled-inside-window" | "preparation-controlled-below-floor"
            ));
            assert!(!fixture.op.is_callback);
            let binding = (
                fixture.page.identity_scope.clone(),
                fixture.op.generation,
                fixture.op.sequence,
                PREPARATION_CLASSIFICATION_BOUNDARY.to_owned(),
            );
            let (entered, entered_receive) = tokio::sync::oneshot::channel();
            let (release, release_receive) = tokio::sync::oneshot::channel();
            let (released, released_receive) = tokio::sync::oneshot::channel();
            // Reuse the existing exact-owner test-hook map, not a second
            // operation/reference registry or a process-wide next-action hook.
            {
                let mut hooks = replacement_hooks().lock().unwrap();
                let std::collections::hash_map::Entry::Vacant(entry) = hooks.entry(binding.clone())
                else {
                    panic!("controlled preparation gate is already registered");
                };
                entry.insert(ReplacementHook::Preparation(Some(
                    PreparationClassificationHook {
                        authority,
                        entered,
                        release: release_receive,
                        released,
                    },
                )));
            }
            Self {
                _registration: ReplacementBoundary(binding),
                entered: entered_receive,
                release,
                released: released_receive,
            }
        }
    }
    pub(super) async fn preparation_classification_gate(
        ctx: &ActionContext<'_>,
        dispatch: &Dispatch,
        attempt: &Result<(Point, (f64, f64)), ProtocolError>,
        longest_attempt: Duration,
    ) {
        if !matches!(
            ctx.page.identity_scope.as_str(),
            "preparation-controlled-inside-window" | "preparation-controlled-below-floor"
        ) || !matches!(attempt, Err(ProtocolError::NotActionable))
            || !dispatch.preparation_enabled.load(Ordering::SeqCst)
            || !dispatch.preparation_refusal.load(Ordering::SeqCst)
            || dispatch.preparation_disqualified.load(Ordering::SeqCst)
            || ctx.operation.is_callback
        {
            return;
        }
        let binding = (
            ctx.page.identity_scope.clone(),
            ctx.operation.generation,
            ctx.operation.sequence,
            PREPARATION_CLASSIFICATION_BOUNDARY.to_owned(),
        );
        let hook = {
            let mut hooks = replacement_hooks().lock().unwrap();
            match hooks.get_mut(&binding) {
                Some(ReplacementHook::Preparation(hook)) => hook.take(),
                _ => None,
            }
        };
        let Some(hook) = hook else { return };
        // Keep the consumed registration until its exact owner drops it, so a
        // duplicate installation cannot replace another live gate's channels.
        // The ACKed refusal and measured attempt are real production facts.
        // Do not change Dispatch, the result, the lease, or longest_attempt.
        let original_authority = hook.authority;
        let authority_valid = || {
            ctx.check().is_ok()
                && match ctx.realm_authority {
                    ActionRealmAuthority::Enrolled(owner) => original_authority
                        .check(owner, ctx.page, ctx.operation)
                        .is_ok(),
                    ActionRealmAuthority::UntrackedFixture => false,
                }
        };
        let _ = hook.entered.send(PreparationGateEntered {
            deadline: ctx.operation.deadline,
            remaining: ctx
                .operation
                .deadline
                .saturating_duration_since(Instant::now()),
            longest_attempt,
            authority_valid: authority_valid(),
        });
        // A missing controller must not create an unbounded test-only wait.
        // Timeout/channel loss is an inconclusive schedule, never a receipt.
        let release_received = tokio::time::timeout_at(ctx.operation.deadline.into(), hook.release)
            .await
            .is_ok_and(|result| result.is_ok());
        let _ = hook.released.send(PreparationGateReleased {
            remaining: ctx
                .operation
                .deadline
                .saturating_duration_since(Instant::now()),
            authority_valid: authority_valid(),
            release_received,
        });
    }
    struct Fixture {
        gate: Arc<ExecutionGate>,
        page: BrowserExecutionLease,
        op: OperationLease,
        _cancel: tokio::sync::watch::Sender<CancelSignal>,
        state: ClientPageState,
        refs: RefMap,
        blobs: BlobStore,
        frames: HashMap<String, String>,
        observation_frames: Vec<super::super::client_observation::ObservationFrame>,
        geometry: GeometrySnapshot,
        log: Log,
        replies: Log,
        server: tokio::task::JoinHandle<()>,
    }
    impl Fixture {
        fn context(&self) -> ActionContext<'_> {
            ActionContext {
                observation_after: None,
                observed_revision: 0,
                realm_authority: ActionRealmAuthority::UntrackedFixture,
                page: &self.page,
                operation: &self.op,
                page_state: &self.state,
                refs: &self.refs,
                revision: 1,
                iframe_sessions: &self.frames,
                observation_frames: &self.observation_frames,
                blobs: &self.blobs,
                geometry: &self.geometry,
            }
        }
        fn inputs(&self) -> Vec<Value> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .filter(|r| {
                    r["method"]
                        .as_str()
                        .is_some_and(|m| m.starts_with("Input."))
                })
                .cloned()
                .collect()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }
    async fn fixture(mode: &'static str) -> Fixture {
        fixture_scoped(mode, "scope").await
    }
    async fn fixture_scoped(mode: &'static str, scope: &str) -> Fixture {
        fixture_scoped_with_action_broker(mode, scope, None).await
    }
    async fn fixture_scoped_with_action_broker(
        mode: &'static str,
        scope: &str,
        action_broker: Option<Arc<super::super::client_session::ClientSession>>,
    ) -> Fixture {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let log: Log = Arc::default();
        let captured = log.clone();
        let replies: Log = Arc::default();
        let sent_replies = replies.clone();
        let gate = Arc::new(ExecutionGate::default());
        let server_gate = gate.clone();
        let (cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let server_cancel = cancel.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let observed_since = Instant::now();
            let mut checked_reads = 0;
            let mut query_reads = 0;
            let mut drag_pressed = false;
            let mut drag_objects = 0;
            let mut preparation_scrolls = 0;
            let mut readonly_probes = 0;
            let mut layout_metrics_reads = 0;
            let mut held_focus_probe: Option<Value> = None;
            let mut held_focus_release: Option<Value> = None;
            let mut held_debt_release: Option<Value> = None;
            let mut held_direct_press: Option<Value> = None;
            let mut held_original_pointer_reply: Option<(Value, Value)> = None;
            let mut held_drag_releases: Vec<Value> = Vec::new();
            while let Some(Ok(message)) = socket.next().await {
                if mode.starts_with("preparation-readonly-") && message.is_close() {
                    break;
                }
                let Ok(text) = message.to_text() else {
                    continue;
                };
                let request: Value = serde_json::from_str(text).unwrap();
                let mut observed = legacy_locator_dispatch::observed_request(
                    mode,
                    &request,
                    observed_since.elapsed(),
                )
                .await;
                if mode == direct_point_clicks::MODE || direct_point_clicks::is_pointer_mode(mode) {
                    direct_point_clicks::record_receipt(&mut observed, observed_since.elapsed());
                }
                captured.lock().unwrap().push(observed.clone());
                let method = request["method"].as_str().unwrap();
                if mode == direct_point_clicks::CANCEL_MODE
                    && method == "Input.dispatchMouseEvent"
                    && request["params"]["type"] == "mouseMoved"
                    && request["params"]["x"].as_f64() == Some(30.0)
                {
                    // Cancel only after the real first paced move is submitted,
                    // before its ACK can let the producer submit another move.
                    server_cancel.send_replace(CancelSignal::Requested);
                }
                if method == "Page.getLayoutMetrics" {
                    layout_metrics_reads += 1;
                }
                // Mutate the fixture only when the real action presses. Query
                // count alone must not manufacture the post-press boundary.
                if mode.starts_with("strict-query-drag-")
                    && method == "Input.dispatchMouseEvent"
                    && request["params"]["type"] == "mousePressed"
                {
                    drag_pressed = true;
                    if mode == "strict-query-drag-press-cancel" {
                        server_cancel.send_replace(CancelSignal::Requested);
                    }
                }
                if mode == "strict-query-drag-cleanup-debt"
                    && method == "Input.dispatchMouseEvent"
                    && request["params"]["type"] == "mouseReleased"
                {
                    // Retain every release so a duplicate cannot accidentally
                    // hide by getting an immediate ACK. The fence below ACKs
                    // only the original command, never a replacement status.
                    held_drag_releases.push(request.clone());
                    continue;
                }
                if mode == "strict-query-drag-cleanup-debt"
                    && method == "Browser.getVersion"
                    && !held_drag_releases.is_empty()
                {
                    let release = held_drag_releases.remove(0);
                    let reply =
                        json!({"id":release["id"],"sessionId":release["sessionId"],"result":{}});
                    socket
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            reply.to_string(),
                        ))
                        .await
                        .unwrap();
                    sent_replies
                        .lock()
                        .unwrap()
                        .push(json!({"request":release,"reply":reply}));
                }
                if mode == "direct-point-cancel"
                    && method == "Input.dispatchMouseEvent"
                    && request["params"]["type"] == "mousePressed"
                {
                    held_direct_press = Some(request.clone());
                    server_cancel.send_replace(CancelSignal::Requested);
                    continue;
                }
                if mode == "direct-point-cancel" && method == "Browser.getVersion" {
                    if let Some(press) = held_direct_press.take() {
                        socket.send(tokio_tungstenite::tungstenite::Message::Text(json!({"id":press["id"],"sessionId":press["sessionId"],"result":{}}).to_string())).await.unwrap();
                    }
                }
                let source = request["params"]["functionDeclaration"]
                    .as_str()
                    .unwrap_or("");
                if mode.starts_with("target-revalidation-")
                    && method == "Runtime.releaseObject"
                    && request["params"]["objectId"] == "exact-node"
                {
                    if mode == "target-revalidation-cancelled" {
                        server_cancel.send_replace(CancelSignal::Requested);
                    } else {
                        server_gate.seal();
                    }
                }
                if mode.starts_with("call-revalidation-")
                    && method == "Runtime.releaseObject"
                    && request["params"]["objectId"] == "call-auxiliary"
                {
                    match mode {
                        "call-revalidation-stale" | "call-revalidation-cleanup-failed" => {
                            server_gate.seal();
                        }
                        "call-revalidation-cancelled" => {
                            server_cancel.send_replace(CancelSignal::Requested);
                        }
                        _ => unreachable!(),
                    }
                }
                if mode == "preparation-release-debt" && method == "Runtime.releaseObject" {
                    assert_eq!(request["params"]["objectId"], "exact-node");
                    assert_eq!(request["sessionId"], "page");
                    assert!(held_debt_release.replace(request.clone()).is_none());
                    continue;
                }
                if mode == "preparation-release-debt" && method == "Browser.getVersion" {
                    if let Some(release) = held_debt_release.take() {
                        let reply = json!({"id":release["id"],"result":{}});
                        socket
                            .send(tokio_tungstenite::tungstenite::Message::Text(
                                reply.to_string(),
                            ))
                            .await
                            .unwrap();
                        sent_replies
                            .lock()
                            .unwrap()
                            .push(json!({"request":release,"reply":reply}));
                    }
                }
                // Preparation settlement cases withhold an exact reply, not the
                // entire peer. Owned-handle cleanup must remain serviceable.
                if mode.starts_with("preparation-") {
                    if mode.starts_with("preparation-readonly-")
                        && source.contains("const rect=this.getBoundingClientRect();const style=getComputedStyle(this);")
                        && source.ends_with("return true;}")
                    {
                        readonly_probes += 1;
                        if mode == "preparation-readonly-stale" {
                            server_gate.seal();
                        }
                        if mode == "preparation-readonly-cancel-second"
                            && readonly_probes == 2
                        {
                            // Cancel the actual admitted operation only once a
                            // newer pure probe has really been dispatched.
                            action_broker.as_ref().unwrap().cancel(1, 1).unwrap();
                            continue;
                        }
                    }
                    if (mode == "preparation-readonly-release-held"
                        && request["params"]["objectId"] == "exact-node"
                        || mode == "preparation-readonly-aux-held"
                            && request["params"]["objectId"] == "readonly-auxiliary")
                        && method == "Runtime.releaseObject"
                    {
                        // Withhold only the original exact release ACK. Other
                        // cleanup and the enrollment supervisor remain live.
                        continue;
                    }
                    if method == "DOM.scrollIntoViewIfNeeded" {
                        preparation_scrolls += 1;
                        if (mode == "preparation-slack-exhausted" && preparation_scrolls == 1)
                            || (mode == "preparation-latency-spike" && preparation_scrolls == 2)
                        {
                            tokio::time::sleep(Duration::from_millis(
                                if preparation_scrolls == 1 { 700 } else { 850 },
                            ))
                            .await;
                        }
                        if mode == "preparation-scroll-unacked"
                            || (mode == "preparation-later-scroll-unacked"
                                && preparation_scrolls == 2)
                        {
                            continue;
                        }
                    }
                    if (mode == "preparation-control-unacked"
                        && preparation_scrolls > 0
                        && method == "Page.getLayoutMetrics")
                        || (mode == "preparation-input-unacked"
                            && method == "Input.dispatchMouseEvent"
                            && request["params"]["type"] == "mouseReleased")
                    {
                        continue;
                    }
                    if method == "Page.createIsolatedWorld" {
                        // Supply native lifecycle evidence to the real enrollment
                        // supervisor before its exact-realm resolver ACK.
                        socket
                            .send(tokio_tungstenite::tungstenite::Message::Text(
                                json!({"method":"Runtime.executionContextCreated",
                                "sessionId":"page","params":{"context":{"id":1,
                                "uniqueId":"preparation-realm",
                                "name":"agent-browser-native-observation",
                                "auxData":{"frameId":"main","isDefault":false}}}})
                                .to_string(),
                            ))
                            .await
                            .unwrap();
                    }
                    if mode == "preparation-estimate-overrun"
                        && preparation_scrolls == 2
                        && source.contains("const blocker=")
                    {
                        tokio::time::sleep(Duration::from_millis(850)).await;
                    }
                    if mode == "preparation-authority-lost" && source.contains("const blocker=") {
                        server_gate.seal();
                    }
                }
                if source.contains("return this.nodeType===1") {
                    if mode == "focus-cancel-late" {
                        // Hold only this reply. A real cancellation must unwind
                        // the focus wait and finish owned cleanup. Only a later
                        // drain command releases the successful producer result.
                        assert_eq!(method, "Runtime.callFunctionOn");
                        assert!(held_focus_probe.replace(request.clone()).is_none());
                        server_cancel.send_replace(CancelSignal::Requested);
                        continue;
                    }
                    if mode == "focus-cancel"
                        || (mode == "focus-root-cancel"
                            && request["params"]["objectId"] == "focused-document")
                    {
                        server_cancel.send_replace(CancelSignal::Requested);
                    }
                    if mode == "focus-reset" {
                        server_gate.seal();
                    }
                }
                if method == "Input.dispatchKeyEvent"
                    && request["params"]["type"] == "keyUp"
                    && ((mode == "select-cancel" && request["params"]["code"] == "KeyA")
                        || (mode == "select-modifier-cancel"
                            && matches!(
                                request["params"]["code"].as_str(),
                                Some("ControlLeft" | "MetaLeft")
                            ))
                        || (mode == "delete-cancel" && request["params"]["code"] == "Delete")
                        || (mode == "type-cancel" && request["params"]["code"] == "KeyZ"))
                {
                    server_cancel.send_replace(CancelSignal::Requested);
                }
                if mode == "prefix-cleanup-reset"
                    && method == "Input.dispatchKeyEvent"
                    && request["params"]["type"] == "keyUp"
                    && request["params"]["code"] == "ShiftLeft"
                {
                    server_gate.seal();
                }
                if mode == "prefix-cleanup-disconnected"
                    && method == "Input.dispatchKeyEvent"
                    && request["params"]["type"] == "keyUp"
                    && request["params"]["code"] == "ShiftLeft"
                {
                    break;
                }
                // These are author-controlled query facts, never dispatch receipts.
                let query_name = if mode == "strict-query-misleading-ambiguous" {
                    "click action done"
                } else {
                    "Save"
                };
                let query_text = if mode == "strict-query-misleading-ambiguous" {
                    "performing click action\nclick action done"
                } else {
                    "Save"
                };
                let result = match method {
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"main","loaderId":"doc","url":"about:blank"}}})
                    }
                    "Target.getTargets" if mode.starts_with("preparation-") => {
                        json!({"targetInfos":[{"targetId":"target","browserContextId":"context","type":"page"}]})
                    }
                    "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                    "DOM.resolveNode" if mode.starts_with("strict-query-drag-") => {
                        drag_objects += 1;
                        json!({"object":{"objectId":format!("drag-node-{}-{drag_objects}", request["params"]["backendNodeId"]),"subtype":"node"}})
                    }
                    "DOM.resolveNode" => {
                        if mode == "resolve-cancel" {
                            server_cancel.send_replace(CancelSignal::Requested);
                            tokio::time::sleep(Duration::from_millis(30)).await;
                        }
                        let object = if mode.starts_with("focus-root")
                            && request["params"]["backendNodeId"] == 1
                        {
                            "focused-document"
                        } else {
                            "exact-node"
                        };
                        json!({"object":{"objectId":object,"subtype":"node"}})
                    }
                    "DOM.getBoxModel" if mode.starts_with("strict-query-drag-") => {
                        let object = request["params"]["objectId"].as_str().unwrap();
                        let x = if object.starts_with("drag-node-44-") {
                            240
                        } else if object.starts_with("drag-node-43-") {
                            120
                        } else {
                            0
                        };
                        json!({"model":{"border":[x,0,x+100,0,x+100,50,x,50]}})
                    }
                    "DOM.getBoxModel" => json!({"model":{"border":[0,0,100,0,100,50,0,50]}}),
                    "Page.getLayoutMetrics" if mode == direct_point_clicks::WHEEL_MODE => {
                        json!({"cssVisualViewport":{"clientWidth":800.,"clientHeight":600.,"offsetX":0.,"offsetY":0.,"scale":1.},"cssLayoutViewport":{"clientWidth":800.,"clientHeight":600.}})
                    }
                    "Page.getLayoutMetrics" if mode.starts_with("strict-query-drag-") => {
                        json!({"cssVisualViewport":{"clientWidth":400.,"clientHeight":200.,"offsetX":0.,"offsetY":0.,"scale":1.},"cssLayoutViewport":{"clientWidth":400.,"clientHeight":200.}})
                    }
                    "Page.getLayoutMetrics" => {
                        json!({"cssVisualViewport":{"clientWidth":100.,"clientHeight":200.,"offsetX":0.,"offsetY":0.,"scale":1.},"cssLayoutViewport":{"clientWidth":100.,"clientHeight":200.}})
                    }
                    "Browser.getVersion" => json!({"userAgent":"Synthetic Linux"}),
                    "DOM.getDocument" if mode.starts_with("strict-query-drag-") => {
                        let mut children = vec![
                            json!({"nodeType":1,"backendNodeId":42}),
                            json!({"nodeType":1,"backendNodeId":43}),
                        ];
                        if drag_pressed {
                            children.push(json!({"nodeType":1,"backendNodeId":44}));
                        }
                        json!({"root":{"nodeType":9,"backendNodeId":99,"children":children}})
                    }
                    "DOM.getDocument" if mode.starts_with("strict-query") => {
                        let mut children = vec![
                            json!({"nodeType":1,"backendNodeId":42}),
                            json!({"nodeType":1,"backendNodeId":43}),
                        ];
                        // The second genuine match appears only after publication.
                        if mode == "strict-query-misleading-ambiguous" && query_reads == 0 {
                            children.truncate(1);
                        }
                        json!({"root":{"nodeType":9,"backendNodeId":99,"children":children}})
                    }
                    "Runtime.getProperties" if mode.starts_with("strict-query") => {
                        json!({"result":[{"name":"focused","value":{"type":"object","subtype":"null","value":null}}]})
                    }
                    "Accessibility.getPartialAXTree" if mode.starts_with("strict-query") => {
                        json!({"nodes":[{"nodeId":"a","backendDOMNodeId":request["params"]["backendNodeId"],"role":{"type":"role","value":"button"},"name":{"type":"string","value":query_name}}]})
                    }
                    "Accessibility.getFullAXTree" => {
                        if mode.starts_with("strict-query-drag-") {
                            let mut nodes = vec![
                                json!({"nodeId":"a","backendDOMNodeId":42,"role":{"type":"role","value":"button"},"name":{"type":"string","value":"Drag"}}),
                                json!({"nodeId":"b","backendDOMNodeId":43,"role":{"type":"role","value":"button"},"name":{"type":"string","value":"Drop"}}),
                            ];
                            if drag_pressed {
                                nodes.push(json!({"nodeId":"c","backendDOMNodeId":44,"role":{"type":"role","value":"button"},"name":{"type":"string","value":"Drop"}}));
                            }
                            json!({"nodes":nodes})
                        } else if mode.starts_with("strict-query") {
                            let role = match mode {
                                "strict-query-actionable-up" if query_reads == 0 => "RootWebArea",
                                "strict-query-actionable-down" if query_reads > 0 => "RootWebArea",
                                _ => "button",
                            };
                            let mut nodes = vec![
                                json!({"nodeId":"a","backendDOMNodeId":42,"role":{"type":"role","value":role},"name":{"type":"string","value":query_name}}),
                                json!({"nodeId":"b","backendDOMNodeId":43,"role":{"type":"role","value":role},"name":{"type":"string","value":query_name}}),
                            ];
                            if mode == "strict-query-misleading-ambiguous" && query_reads == 0 {
                                nodes.truncate(1);
                            }
                            json!({"nodes":nodes})
                        } else if mode.starts_with("focus-root") {
                            let mut nodes = vec![
                                json!({"backendDOMNodeId":1,"role":{"value":"RootWebArea"},"properties":[{"name":"focused","value":{"value":true}}]}),
                            ];
                            if mode != "focus-root-only" {
                                nodes.push(json!({"backendDOMNodeId":42,"role":{"value":"textbox"},"properties":[{"name":"focused","value":{"value":true}}]}));
                            }
                            json!({"nodes":nodes})
                        } else {
                            json!({"nodes":[{"backendDOMNodeId":42,"properties":[{"name":"focused","value":{"value":true}}]}]})
                        }
                    }
                    "Runtime.callFunctionOn" if observed.get("legacyScriptResult").is_some() => {
                        json!({"result":{"value":observed["legacyScriptResult"]["result"]}})
                    }
                    "Runtime.callFunctionOn" => {
                        if mode.starts_with("strict-query")
                            && source.starts_with("function(expression")
                        {
                            query_reads += 1;
                            if (query_reads > 1 && mode == "strict-query-cancel")
                                || (drag_pressed && mode == "strict-query-drag-cancel")
                            {
                                server_cancel.send_replace(CancelSignal::Requested);
                            }
                            if query_reads > 1 && mode == "strict-query-cleanup-primary" {
                                json!({"result":{"value":{"error":"stale-reference"}}})
                            } else {
                                let indices = if mode.starts_with("strict-query-drag-") {
                                    if !drag_pressed {
                                        vec![1]
                                    } else {
                                        match mode {
                                            "strict-query-drag-second-drop"
                                            | "strict-query-drag-cleanup-debt" => vec![1, 2],
                                            "strict-query-drag-missing" => vec![],
                                            "strict-query-drag-replaced"
                                            | "strict-query-drag-replaced-detached" => vec![2],
                                            _ => vec![1],
                                        }
                                    }
                                } else if mode == "strict-query-multiple" {
                                    vec![0, 1]
                                } else if matches!(
                                    mode,
                                    "strict-query-nth-shift" | "strict-query-output-filter"
                                ) {
                                    if query_reads == 1 {
                                        vec![0, 1]
                                    } else {
                                        vec![1, 0]
                                    }
                                } else if mode == "strict-query-explicit-nth" {
                                    if query_reads == 1 {
                                        vec![1]
                                    } else {
                                        vec![0]
                                    }
                                } else if query_reads == 1 {
                                    vec![0]
                                } else {
                                    match mode {
                                        "strict-query-ambiguous"
                                        | "strict-query-misleading-ambiguous" => vec![0, 1],
                                        "strict-query-missing" => vec![],
                                        "strict-query-replaced" => vec![1],
                                        _ => vec![0],
                                    }
                                };
                                json!({"result":{"value":{"indices":indices,"redacted":[]}}})
                            }
                        } else if mode.starts_with("strict-query")
                            && source.contains("Array.from(result)")
                        {
                            json!({"result":{"objectId":"security"}})
                        } else if mode.starts_with("strict-query")
                            && source.starts_with("function(testId,secureSelector,...nodes)")
                        {
                            let count =
                                request["params"]["arguments"].as_array().unwrap().len() - 2;
                            let metadata = json!({"author":{"tag":"button","nodeType":1,"action":true,"visible":true},"attributes":{},"labels":[query_name],"states":{"secure":false,"hidden":false},"text":query_text,"value":query_name,"rect":{"x":0,"y":0,"width":100,"height":50}});
                            let mut batch = vec![metadata; count];
                            if mode == "strict-query-output-filter"
                                && query_reads == 0
                                && !batch.is_empty()
                            {
                                // Deliberately inconsistent projected match metadata exercises
                                // the defensive output hold, not normal AST visible narrowing.
                                batch[0]["states"]["hidden"] = json!(true);
                                batch[0]["author"]["visible"] = json!(false);
                            }
                            json!({"result":{"value":batch}})
                        } else if mode.starts_with("focus-root")
                            && source.contains("return this.nodeType===1")
                        {
                            if request["params"]["objectId"] == "focused-document" {
                                // Emulate the native document's null ownerDocument:
                                // only the exact document identity guard avoids stale.
                                let identity = source.find("if(this===document)return false;");
                                let stale = source.find("if(!this.isConnected");
                                if identity
                                    .zip(stale)
                                    .is_some_and(|(identity, stale)| identity < stale)
                                {
                                    json!({"result":{"value":false}})
                                } else {
                                    json!({"result":{"value":{"status":"stale"}}})
                                }
                            } else if matches!(
                                mode,
                                "focus-root-foreign" | "focus-root-disconnected"
                            ) {
                                json!({"result":{"value":{"status":"stale"}}})
                            } else {
                                json!({"result":{"value":true}})
                            }
                        } else if mode.starts_with("target-revalidation-")
                            && source == "function(){if(this!==document||!this.isConnected)return null;return this.documentElement;}"
                        {
                            if mode == "target-revalidation-empty" {
                                json!({"result":{"value":null}})
                            } else {
                                json!({"result":{"objectId":"document-element"}})
                            }
                        } else if mode.starts_with("call-revalidation-")
                            && source == "function(){return 'owned-call-revalidation'}"
                        {
                            json!({"result":{"objectId":"call-auxiliary","value":{"status":"intercepted-pointer"}}})
                        } else if (mode == "no-box-swipe"
                            || (mode.starts_with("preparation-readonly-")
                                && (mode != "preparation-readonly-dynamic" || readonly_probes == 1)))
                            && source.contains("const rect=this.getBoundingClientRect();const style=getComputedStyle(this);")
                            && source.ends_with("return true;}")
                        {
                            // The initial bbox check rejects before any scroll,
                            // while the real action keeps its ordinary retry loop.
                            if mode == "preparation-readonly-aux-held" && readonly_probes == 1 {
                                json!({"result":{"objectId":"readonly-auxiliary","value":{"status":"not-actionable"}}})
                            } else {
                                json!({"result":{"value":{"status":"not-actionable"}}})
                            }
                        } else if drag_pressed
                            && request["params"]["objectId"].as_str().is_some_and(|object| {
                                (mode == "strict-query-drag-observed-detached"
                                    && object.starts_with("drag-node-43-"))
                                    || (mode == "strict-query-drag-replaced-detached"
                                        && object.starts_with("drag-node-44-"))
                            })
                            && source.contains("if(!this.isConnected")
                        {
                            json!({"result":{"value":{"status":"stale"}}})
                        } else if source.contains("const blocker=") {
                            if matches!(
                                mode,
                                "intercepted"
                                    | "preparation-intercepted"
                                    | "preparation-later-scroll-unacked"
                                    | "preparation-handle-cleanup-failed"
                                    | "preparation-authority-lost"
                                    | "preparation-slack-exhausted"
                                    | "preparation-latency-spike"
                                    | "preparation-estimate-overrun"
                                    | "preparation-controlled-inside-window"
                                    | "preparation-controlled-below-floor"
                            ) || (mode == "preparation-retry-success"
                                && preparation_scrolls == 1)
                            {
                                json!({"result":{"value":{"status":"intercepted-pointer"}}})
                            } else if mode == "preparation-not-actionable" {
                                json!({"result":{"value":{"status":"not-actionable"}}})
                            } else {
                                json!({"result":{"value":{"width":100,"height":50}}})
                            }
                        } else if source.contains("const p=Node.prototype")
                            && mode.starts_with("exact-")
                        {
                            match mode {
                                "exact-disconnected" | "exact-cleanup-failed" => {
                                    json!({"result":{"value":false}})
                                }
                                "exact-aux-cleanup-failed" => {
                                    json!({"result":{"objectId":"result-handle"},"exceptionDetails":{"exception":{"objectId":"exception-handle"}}})
                                }
                                "exact-exception" => {
                                    json!({"exceptionDetails":{"text":"synthetic"},"result":{}})
                                }
                                "exact-malformed" => json!({"result":{"value":null}}),
                                _ => json!({"result":{"value":true}}),
                            }
                        } else if source == CHECKED_STATE {
                            checked_reads += 1;
                            if mode == "check-read-stalled" && checked_reads == 2 {
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            }
                            if mode == "check-aux-cleanup-failed" {
                                json!({"result":{},"exceptionDetails":{"exception":{"objectId":"exception-handle"}}})
                            } else if (mode == "check-replaced" && checked_reads > 2)
                                || (mode == "check-immediate-replacement" && checked_reads > 1)
                            {
                                json!({"result":{"value":{"status":"stale"}}})
                            } else {
                                json!({"result":{"value":{"checked":false,"radio":false}}})
                            }
                        } else if source == PREPARE_FILL {
                            json!({"result":{"value":{"complete":false}}})
                        } else {
                            json!({"result":{"value":true}})
                        }
                    }
                    "Runtime.evaluate" => json!({"result":{"value":true}}),
                    _ => json!({}),
                };
                let mut reply = if mode == "recording-first-start-error-ack"
                    && method == "Page.getLayoutMetrics"
                    && layout_metrics_reads > 1
                {
                    // Let fixture geometry initialize; refuse the actual start.
                    json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic recording startup failure"}})
                } else if (mode == "strict-query-drag-release-failed"
                    && drag_pressed
                    && method == "Runtime.releaseObject"
                    && request["params"]["objectId"]
                        .as_str()
                        .is_some_and(|object| object.starts_with("drag-node-43-")))
                    || (mode.starts_with("strict-query-cleanup")
                        && query_reads > 1
                        && method == "Runtime.releaseObjectGroup"
                        && request["params"]["objectGroup"]
                            .as_str()
                            .is_some_and(|group| group.starts_with("native-query-")))
                    || ((mode == "exact-cleanup-failed"
                        || mode == "check-aux-cleanup-failed"
                        || (mode == "focus-root-cleanup-failed"
                            && request["params"]["objectId"] == "focused-document")
                        || (mode == "exact-aux-cleanup-failed"
                            && request["params"]["objectId"] == "result-handle"))
                        && method == "Runtime.releaseObject")
                    || (mode == "call-revalidation-cleanup-failed"
                        && method == "Runtime.releaseObject"
                        && request["params"]["objectId"] == "call-auxiliary")
                    || (mode == "preparation-handle-cleanup-failed"
                        && method == "Runtime.releaseObject"
                        && request["params"]["objectId"] == "exact-node")
                    || (mode == "exact-protocol-error" && method == "DOM.resolveNode")
                    || (mode == "prefix-cleanup-failed"
                        && method == "Input.dispatchKeyEvent"
                        && request["params"]["type"] == "keyUp"
                        && request["params"]["code"] == "ShiftLeft")
                {
                    json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic cleanup failure"}})
                } else {
                    json!({"id":request["id"],"result":result})
                };
                if mode == "recording-first-start-error-ack"
                    || mode.starts_with("direct-point")
                    || mode == "strict-query-drag-cleanup-debt"
                    || mode.starts_with("preparation-readonly-")
                {
                    reply["sessionId"] = request["sessionId"].clone();
                }
                if direct_point_clicks::holds_pointer_reply(mode, &request) {
                    assert!(held_original_pointer_reply
                        .replace((request, reply))
                        .is_none());
                    continue;
                }
                if method == "Browser.getVersion" {
                    if let Some((held, held_reply)) = held_original_pointer_reply.take() {
                        socket
                            .send(tokio_tungstenite::tungstenite::Message::Text(
                                held_reply.to_string(),
                            ))
                            .await
                            .unwrap();
                        sent_replies.lock().unwrap().push(json!({
                            "request":held, "reply":held_reply, "heldUntilRequest":request
                        }));
                    }
                }
                if method == "Runtime.releaseObject" {
                    if let Some(focus_request) = held_focus_probe.as_ref() {
                        assert_eq!(request["sessionId"], focus_request["sessionId"]);
                        assert_eq!(
                            request["params"]["objectId"],
                            focus_request["params"]["objectId"]
                        );
                        assert!(held_focus_release.replace(request.clone()).is_none());
                    }
                }
                if method == "Browser.getVersion" {
                    if let Some(focus_request) = held_focus_probe.take() {
                        let release_request = held_focus_release.take().unwrap();
                        assert!(sent_replies.lock().unwrap().iter().any(|entry| {
                            entry["request"] == release_request
                                && entry["reply"]["result"] == json!({})
                                && entry["reply"].get("error").is_none()
                        }));
                        let focus_reply =
                            json!({"id":focus_request["id"],"result":{"result":{"value":true}}});
                        socket
                            .send(tokio_tungstenite::tungstenite::Message::Text(
                                focus_reply.to_string(),
                            ))
                            .await
                            .unwrap();
                        sent_replies.lock().unwrap().push(json!({
                            "request":focus_request,
                            "reply":focus_reply,
                            "heldUntilRequest":request,
                            "cleanupRequest":release_request
                        }));
                    }
                }
                let ack_started = observed_since.elapsed();
                if socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        reply.to_string(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
                let mut observed_reply = json!({"request":request,"reply":reply});
                if direct_point_clicks::is_pointer_mode(mode) {
                    observed_reply["directPointPeerAckStartNanos"] =
                        json!(u64::try_from(ack_started.as_nanos()).unwrap());
                }
                sent_replies.lock().unwrap().push(observed_reply);
            }
        });
        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        let page = BrowserExecutionLease {
            client,
            page_session_id: "page".into(),
            target_id: "target".into(),
            identity_scope: scope.into(),
            permit: gate.enter(false).unwrap(),
            targets: ClientTargets::new("context".into(), scope.into()),
        };
        let op = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline: Instant::now() + Duration::from_secs(5),
            cancellation,
        };
        let mut refs = RefMap::new();
        refs.begin_observation(scope, op.generation, 1);
        refs.bind_exact(
            42,
            "textbox",
            "",
            ExactBinding {
                page_session: "page".into(),
                session: "page".into(),
                frame: "main".into(),
                loader: "doc".into(),
                actionable: !mode.starts_with("target-revalidation-"),
            },
        );
        let blobs = BlobStore::new(BlobLimits::default()).unwrap();
        blobs
            .activate_scope(BlobScope {
                generation: 1,
                identity_scope: scope.into(),
            })
            .unwrap();
        let geometry = GeometrySnapshot::capture(
            &page.client,
            "page",
            &[super::super::client_observation::ObservationFrame {
                parent_frame_id: None,
                owner_backend_id: None,
                url: "about:blank".into(),
                binding: refs.get("e1").unwrap().exact_binding.clone().unwrap(),
                offset_x: 0.,
                offset_y: 0.,
                frame_path: vec![],
            }],
            &op,
        )
        .await
        .unwrap();
        log.lock().unwrap().clear();
        let observation_frames = vec![super::super::client_observation::ObservationFrame {
            parent_frame_id: None,
            owner_backend_id: None,
            url: "about:blank".into(),
            binding: refs.get("e1").unwrap().exact_binding.clone().unwrap(),
            offset_x: 0.,
            offset_y: 0.,
            frame_path: vec![],
        }];
        Fixture {
            gate,
            geometry,
            page,
            op,
            _cancel: cancel,
            state: ClientPageState::new(scope.into(), "context".into()),
            refs,
            blobs,
            frames: HashMap::new(),
            observation_frames,
            log,
            replies,
            server,
        }
    }
    #[tokio::test]
    async fn direct_point_uses_only_exact_input_and_late_ack_never_resumes_double_tap() {
        for cancelled in [false, true] {
            let mut f = fixture(if cancelled {
                "direct-point-cancel"
            } else {
                "direct-point"
            })
            .await;
            f.page
                .targets
                .attached("context", "target".into(), "page".into(), "page".into())
                .unwrap();
            f.page.targets.configured("target").unwrap();
            f.page
                .targets
                .resume_permit("target")
                .await
                .unwrap()
                .complete()
                .unwrap();
            let ledger = client_debt::OwnerDebtLedger::new(1, "scope".into());
            f.page.client.install_debt_ledger(ledger.clone()).unwrap();
            f.page.client = f.page.client.owner_view(ledger.clone()).unwrap();
            let journal = ledger
                .operation(
                    client_debt::OperationKey {
                        generation: 1,
                        operation_seq: 1,
                    },
                    "target".into(),
                    "page".into(),
                )
                .unwrap();
            journal.bind_operation(&f.op).unwrap();
            let gate = Arc::new(super::super::client_ui::UiGate::default());
            let ui = gate
                .enter(false, false, f.op.deadline, f.op.cancellation.clone())
                .await
                .unwrap();
            let input = tokio::sync::Mutex::new(());
            let result=ClientActions::default().execute_direct_point(DirectPointContext{page:&f.page,operation:&f.op,page_state:&f.state,journal:&journal,ui,input:input.lock().await},&json!({"identityScope":"scope","point":{"x":8,"y":9},"action":{"kind":"doubleTap"}})).await;
            if cancelled {
                assert!(result.is_err());
                assert_eq!(ledger.snapshot().input_debt, 1);
                f.page
                    .client
                    .send_command_no_params("Browser.getVersion", None)
                    .await
                    .unwrap();
                assert_eq!(ledger.snapshot().input_debt, 0);
            } else {
                result.unwrap();
            }
            let log = f.log.lock().unwrap();
            assert!(log.iter().all(|r| r["method"] == "Input.dispatchMouseEvent"
                || r["method"] == "Browser.getVersion"));
            let presses = log
                .iter()
                .filter(|r| r["params"]["type"] == "mousePressed")
                .count();
            assert_eq!(presses, if cancelled { 1 } else { 2 });
            assert!(log
                .iter()
                .filter(|r| r["method"] == "Input.dispatchMouseEvent")
                .all(|r| r["sessionId"] == "page"));
            assert!(journal.snapshot().mutation_dispatched);
        }
    }

    fn live_query_frame(f: &Fixture) -> super::super::client_observation::ObservationFrame {
        super::super::client_observation::ObservationFrame {
            parent_frame_id: None,
            owner_backend_id: None,
            url: "about:blank".into(),
            binding: f.refs.get("e1").unwrap().exact_binding.clone().unwrap(),
            offset_x: 0.,
            offset_y: 0.,
            frame_path: vec![],
        }
    }
    async fn publish_fixture_query(
        f: &mut Fixture,
        expression: Value,
    ) -> Result<
        super::super::client_observation::QueryResult,
        super::super::client_observation::ObservationError,
    > {
        let frame = live_query_frame(f);
        let options = serde_json::from_value(json!({"expression":expression})).unwrap();
        super::super::client_observation::query(
            &f.page.client,
            &[frame],
            &mut f.refs,
            "scope",
            1,
            &options,
            &f.op,
        )
        .await
    }
    fn logged_query_matches(f: &Fixture) -> usize {
        f.log
            .lock()
            .unwrap()
            .iter()
            .filter(|request| {
                request["params"]["functionDeclaration"]
                    .as_str()
                    .is_some_and(|source| source.starts_with("function(expression"))
            })
            .count()
    }

    fn assert_drag_handle_release_attempts(f: &Fixture) {
        let replies = f.replies.lock().unwrap();
        let log = f.log.lock().unwrap();
        for reply in replies.iter().filter(|reply| {
            reply["request"]["method"] == "DOM.resolveNode"
                && reply["request"]["params"]["objectGroup"] == "native-exact"
        }) {
            let object = &reply["reply"]["result"]["object"]["objectId"];
            assert!(object.is_string());
            assert_eq!(
                log.iter()
                    .filter(|request| {
                        request["method"] == "Runtime.releaseObject"
                            && &request["params"]["objectId"] == object
                    })
                    .count(),
                1,
                "exact drag handle {object} needs exactly one release attempt"
            );
        }
    }
    fn assert_drag_press_cleanup_without_destination_move(f: &Fixture) {
        let inputs = f.inputs();
        let kinds: Vec<_> = inputs
            .iter()
            .map(|request| request["params"]["type"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["mouseMoved", "mousePressed", "mouseReleased"]);
        // Failure releases at the last submitted point, never the stale target.
        assert_eq!(inputs[2]["params"]["x"], inputs[1]["params"]["x"]);
        assert_eq!(inputs[2]["params"]["y"], inputs[1]["params"]["y"]);
        assert_eq!(inputs[2]["params"]["buttons"], 0);
        assert_drag_handle_release_attempts(f);
    }
    #[tokio::test]
    async fn live_drag_destination_revalidates_after_press_without_replay() {
        for (mode, expected, queries, cleanup_failed) in [
            (
                "strict-query-drag-second-drop",
                ProtocolError::StaleReference,
                3,
                false,
            ),
            (
                "strict-query-drag-missing",
                ProtocolError::StaleReference,
                3,
                false,
            ),
            (
                "strict-query-drag-cancel",
                ProtocolError::Cancelled,
                3,
                false,
            ),
            (
                "strict-query-drag-press-cancel",
                ProtocolError::Cancelled,
                2,
                false,
            ),
            (
                "strict-query-drag-release-failed",
                ProtocolError::CleanupFailed,
                2,
                true,
            ),
            (
                "strict-query-drag-replaced-detached",
                ProtocolError::StaleReference,
                3,
                false,
            ),
        ] {
            let mut f = fixture(mode).await;
            let query =
                publish_fixture_query(&mut f, json!({"kind":"selector","selector":".drop"}))
                    .await
                    .unwrap();
            let target = query.nodes[0].reference.clone();
            assert!(f
                .refs
                .get(element::parse_ref(&target.id).unwrap().as_str())
                .unwrap()
                .live_query
                .is_some());
            let allocated = f.refs.next_ref_num();
            let retained = f.refs.retained_identity_counts();
            let failure = ClientActions::default()
                .execute(
                    f.context(),
                    "browser.perform",
                    &json!({
                        "identityScope":"scope", "ref":{"id":"@e1","revision":"1"},
                        "action":{"kind":"dragTo","target":target}
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(failure.error, expected, "{mode}");
            assert_eq!(failure.effects, Effects::Unknown, "{mode}");
            assert_eq!(failure.cleanup_failed, cleanup_failed, "{mode}");
            assert_eq!(f.refs.next_ref_num(), allocated);
            assert_eq!(f.refs.retained_identity_counts(), retained);
            assert_eq!(
                logged_query_matches(&f),
                queries,
                "{mode}: publication, preflight, then after press if authorized"
            );
            assert_drag_press_cleanup_without_destination_move(&f);
            let log = f.log.lock().unwrap();
            let press = log
                .iter()
                .position(|request| request["params"]["type"] == "mousePressed")
                .unwrap();
            assert_eq!(
                log[press + 1..]
                    .iter()
                    .filter(|request| request["params"]["functionDeclaration"]
                        .as_str()
                        .is_some_and(|source| source.starts_with("function(expression")))
                    .count(),
                queries - 2
            );
            if queries == 3 {
                assert!(log[press + 1..].iter().any(|request| request["method"]
                    == "Runtime.releaseObjectGroup"
                    && request["params"]["objectGroup"]
                        .as_str()
                        .is_some_and(|group| group.starts_with("native-query-"))));
            }
        }
    }
    #[tokio::test]
    async fn managed_drag_cleanup_keeps_one_release_and_its_original_late_ack() {
        let mut f = fixture("strict-query-drag-cleanup-debt").await;
        let query = publish_fixture_query(&mut f, json!({"kind":"selector","selector":".drop"}))
            .await
            .unwrap();
        f.page
            .targets
            .attached("context", "target".into(), "page".into(), "page".into())
            .unwrap();
        f.page.targets.configured("target").unwrap();
        f.page
            .targets
            .resume_permit("target")
            .await
            .unwrap()
            .complete()
            .unwrap();
        let ledger = client_debt::OwnerDebtLedger::new(1, "scope".into());
        f.page.client.install_debt_ledger(ledger.clone()).unwrap();
        f.page.client = f.page.client.owner_view(ledger.clone()).unwrap();
        let journal = ledger
            .operation(
                client_debt::OperationKey {
                    generation: 1,
                    operation_seq: 1,
                },
                "target".into(),
                "page".into(),
            )
            .unwrap();
        journal.bind_operation(&f.op).unwrap();
        // Exercise the actual outer execute cleanup with the managed operation
        // installed, not execute_inner or an unjournaled action approximation.
        let failure = journal
            .scope(ClientActions::default().execute(
                f.context(),
                "browser.perform",
                &json!({
                    "identityScope":"scope", "ref":{"id":"@e1","revision":"1"},
                    "action":{"kind":"dragTo","target":query.nodes[0].reference}
                }),
            ))
            .await
            .unwrap_err();
        assert_eq!(failure.error, ProtocolError::StaleReference);
        assert_eq!(failure.effects, Effects::Unknown);
        assert!(!failure.cleanup_failed);
        assert_drag_press_cleanup_without_destination_move(&f);
        assert_eq!(journal.snapshot().input_debt, 1);
        assert_eq!(ledger.snapshot().input_debt, 1);
        assert!(!ledger.snapshot().integrity_lost);
        assert_eq!(
            f.state.mouse_state().unwrap().buttons,
            1,
            "unacknowledged cleanup is not clean input"
        );
        let release = f.inputs().last().unwrap().clone();
        assert!(!f
            .replies
            .lock()
            .unwrap()
            .iter()
            .any(|reply| reply["request"] == release));
        // Pending cleanup blocks new input without dispatching any replacement.
        assert_eq!(
            journal
                .scope(f.state.pointer_event(
                    &f.page,
                    &f.op,
                    "mouseMoved",
                    Some((20., 30.)),
                    None,
                    None,
                    None
                ))
                .await,
            Err(ProtocolError::ScopeUnavailable)
        );
        assert_eq!(f.inputs().len(), 3);
        // This fence returns only the first release's real reader ACK. Losing
        // its status handles, or replacing them with a duplicate, cannot pass.
        f.page
            .client
            .send_command_no_params("Browser.getVersion", None)
            .await
            .unwrap();
        assert_eq!(journal.snapshot().input_debt, 0);
        assert_eq!(ledger.snapshot().input_debt, 0);
        assert_eq!(f.state.mouse_state().unwrap().buttons, 0);
        assert!(f
            .replies
            .lock()
            .unwrap()
            .iter()
            .any(|reply| reply["request"] == release));
        assert_eq!(
            f.inputs().len(),
            3,
            "late cleanup ACK must not replay press or release"
        );
        assert_eq!(
            failure.effects,
            Effects::Unknown,
            "late cleanup is not successful drag completion"
        );
    }

    #[tokio::test]
    async fn live_drag_destination_can_follow_unique_replacement_after_press() {
        let mut f = fixture("strict-query-drag-replaced").await;
        let query = publish_fixture_query(&mut f, json!({"kind":"selector","selector":".drop"}))
            .await
            .unwrap();
        ClientActions::default()
            .execute(
                f.context(),
                "browser.perform",
                &json!({
                    "identityScope":"scope", "ref":{"id":"@e1","revision":"1"},
                    "action":{"kind":"dragTo","target":query.nodes[0].reference}
                }),
            )
            .await
            .unwrap();
        let inputs = f.inputs();
        assert_eq!(
            inputs
                .iter()
                .filter(|request| request["params"]["type"] == "mousePressed")
                .count(),
            1
        );
        assert_eq!(inputs.last().unwrap()["params"]["type"], "mouseReleased");
        assert_eq!(inputs.last().unwrap()["params"]["x"].as_f64(), Some(290.));
        assert_eq!(logged_query_matches(&f), 3);
        assert_drag_handle_release_attempts(&f);
    }
    #[tokio::test]
    async fn observed_drag_destination_keeps_exact_identity_after_press() {
        for mode in [
            "strict-query-drag-second-drop",
            "strict-query-drag-observed-detached",
        ] {
            let mut f = fixture(mode).await;
            let binding = f.refs.get("e1").unwrap().exact_binding.clone().unwrap();
            let id = f.refs.bind_exact(43, "button", "Drop", binding);
            assert!(f.refs.get(&id).unwrap().live_query.is_none());
            let result = ClientActions::default()
                .execute(
                    f.context(),
                    "browser.perform",
                    &json!({
                        "identityScope":"scope", "ref":{"id":"@e1","revision":"1"},
                        "action":{"kind":"dragTo","target":{"id":format!("@{id}"),"revision":"1"}}
                    }),
                )
                .await;
            if mode == "strict-query-drag-observed-detached" {
                let failure = result.unwrap_err();
                assert_eq!(failure.error, ProtocolError::StaleReference);
                assert_eq!(failure.effects, Effects::Unknown);
                assert!(!failure.cleanup_failed);
                assert_drag_press_cleanup_without_destination_move(&f);
            } else {
                result.unwrap();
                assert_eq!(
                    f.inputs().last().unwrap()["params"]["x"].as_f64(),
                    Some(170.)
                );
                assert_drag_handle_release_attempts(&f);
            }
            assert_eq!(
                logged_query_matches(&f),
                0,
                "observed identity must not acquire query authority"
            );
            let log = f.log.lock().unwrap();
            assert_eq!(
                log.iter()
                    .filter(|request| request["method"] == "DOM.resolveNode")
                    .count(),
                2,
                "keep the same source and destination objects"
            );
            assert!(!log
                .iter()
                .any(|request| request["method"] == "DOM.resolveNode"
                    && request["params"]["backendNodeId"] == 44));
        }
    }

    #[tokio::test]
    async fn pointer_original_down_swipe_800x600_waits_for_post_wheel_render_ack() {
        let (f, ledger, journal) =
            direct_point_clicks::owned_pointer_fixture(direct_point_clicks::WHEEL_MODE).await;
        let actions = ClientActions::default();
        let args = json!({"identityScope":"scope", "point":{"x":10,"y":20},
            "action":{"kind":"swipe","direction":"down"}});
        let action = journal.scope(actions.execute(f.context(), "browser.pointer", &args));
        tokio::pin!(action);
        let render = tokio::select! {
            result = &mut action => panic!("wheel action settled before its render ACK: {result:?}"),
            request = direct_point_clicks::wait_for_held_pointer_request(
                &f, direct_point_clicks::WHEEL_MODE,
            ) => request,
        };
        assert_eq!(render["sessionId"], "page");
        assert_eq!(render["params"]["awaitPromise"], true);
        assert_eq!(render["params"]["returnByValue"], true);
        assert_eq!(render["params"]["expression"],
            "document.hidden?true:new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>resolve(true))))");
        assert!(tokio::time::timeout(Duration::from_millis(5), &mut action)
            .await
            .is_err());
        let inputs = f.inputs();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0]["params"]["type"], "mouseMoved");
        assert_eq!(inputs[1]["params"]["type"], "mouseWheel");
        for request in &inputs {
            assert_eq!(request["sessionId"], "page");
            assert_eq!(request["params"]["x"].as_f64(), Some(10.0));
            assert_eq!(request["params"]["y"].as_f64(), Some(20.0));
            assert_eq!(request["params"]["modifiers"], 0);
            direct_point_clicks::exact_pointer_ack(&f, request);
        }
        assert_eq!(inputs[1]["params"]["deltaX"].as_f64(), Some(0.0));
        assert_eq!(inputs[1]["params"]["deltaY"].as_f64(), Some(300.0));
        let log = f.log.lock().unwrap().clone();
        let methods: Vec<_> = log
            .iter()
            .map(|request| request["method"].as_str().unwrap())
            .collect();
        assert_eq!(
            methods,
            [
                "Page.getLayoutMetrics",
                "Input.dispatchMouseEvent",
                "Input.dispatchMouseEvent",
                "Runtime.evaluate"
            ]
        );
        let metrics = direct_point_clicks::exact_pointer_ack(&f, &log[0]);
        assert_eq!(
            metrics["reply"]["result"]["cssLayoutViewport"],
            json!({"clientWidth":800.0,"clientHeight":600.0})
        );
        assert!(!f
            .replies
            .lock()
            .unwrap()
            .iter()
            .any(|entry| entry["request"]["id"] == render["id"]));
        assert_eq!(ledger.snapshot().outstanding_commands, 1);
        assert_eq!(journal.snapshot().input_debt, 0);
        f.page
            .client
            .send_command_no_params("Browser.getVersion", None)
            .await
            .unwrap();
        assert_eq!(action.await.unwrap(), Value::Null);
        let ack = direct_point_clicks::exact_pointer_ack(&f, &render);
        assert_eq!(ack["heldUntilRequest"]["method"], "Browser.getVersion");
        assert_eq!(ack["reply"]["result"], json!({"result":{"value":true}}));
        assert_eq!(
            f.inputs(),
            inputs,
            "render settlement must not replay input"
        );
        assert_eq!(f.log.lock().unwrap().len(), 5);
        direct_point_clicks::assert_pointer_settled(&f, &ledger, &journal);
    }

    #[tokio::test]
    async fn pointer_drag_keeps_exact_points_without_destination_resolution() {
        let f = fixture("strict-query-drag-second-drop").await;
        ClientActions::default()
            .execute(
                f.context(),
                "browser.pointer",
                &json!({
                    "identityScope":"scope", "point":{"x":10,"y":20},
                    "action":{"kind":"dragTo","target":{"x":50,"y":60}}
                }),
            )
            .await
            .unwrap();
        let inputs = f.inputs();
        let points: Vec<_> = inputs
            .iter()
            .map(|request| {
                (
                    request["params"]["type"].as_str().unwrap(),
                    request["params"]["x"].as_f64().unwrap(),
                    request["params"]["y"].as_f64().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            points,
            [
                ("mouseMoved", 10., 20.),
                ("mousePressed", 10., 20.),
                ("mouseMoved", 30., 40.),
                ("mouseMoved", 50., 60.),
                ("mouseReleased", 50., 60.),
            ]
        );
        assert!(f
            .log
            .lock()
            .unwrap()
            .iter()
            .all(|request| request["method"] == "Input.dispatchMouseEvent"));
    }

    #[tokio::test]
    async fn live_query_publication_then_tap_refuses_ambiguity_without_input() {
        for (mode, expected, cleanup) in [
            (
                "strict-query-ambiguous",
                ProtocolError::StaleReference,
                false,
            ),
            (
                "strict-query-misleading-ambiguous",
                ProtocolError::StaleReference,
                false,
            ),
            ("strict-query-missing", ProtocolError::StaleReference, false),
            ("strict-query-cancel", ProtocolError::Cancelled, false),
            ("strict-query-cleanup", ProtocolError::CleanupFailed, true),
            (
                "strict-query-cleanup-primary",
                ProtocolError::StaleReference,
                true,
            ),
        ] {
            let mut f = fixture(mode).await;
            let expression = if mode == "strict-query-misleading-ambiguous" {
                json!({"kind":"query","query":{"kind":"text","value":{"kind":"string","value":"performing click action","exact":false}}})
            } else {
                json!({"kind":"query","query":{"kind":"role","value":{"kind":"string","value":"button","exact":true},"name":{"kind":"string","value":"Save","exact":true}}})
            };
            let query = publish_fixture_query(&mut f, expression.clone())
                .await
                .unwrap();
            let reference = &query.nodes[0].reference;
            assert_ne!(
                reference.id, "@e1",
                "Strict and observed authority must not alias"
            );
            let allocated = f.refs.next_ref_num();
            let retained = f.refs.retained_identity_counts();
            let failure = ClientActions::default()
                .execute(
                    f.context(),
                    "browser.perform",
                    &json!({"identityScope":"scope","ref":reference,"action":{"kind":"tap"}}),
                )
                .await
                .unwrap_err();
            assert_eq!(failure.error, expected, "{mode}");
            assert_eq!(failure.effects, Effects::NotDispatched, "{mode}");
            assert_eq!(failure.cleanup_failed, cleanup, "{mode}");
            assert_eq!(
                f.refs.next_ref_num(),
                allocated,
                "Validation must not allocate refs"
            );
            assert_eq!(f.refs.retained_identity_counts(), retained);
            assert_eq!(logged_query_matches(&f), 2);
            let log = f.log.lock().unwrap();
            if mode == "strict-query-misleading-ambiguous" {
                // Acquisition and action-time revalidation retain the text
                // query. The shared assertions below prove typed stale failure
                // and NotDispatched despite action-log words in author data.
                for (index, request) in log
                    .iter()
                    .filter(|request| {
                        request["params"]["functionDeclaration"]
                            .as_str()
                            .is_some_and(|source| source.starts_with("function(expression"))
                    })
                    .enumerate()
                {
                    assert_eq!(request["params"]["arguments"][0]["value"], expression);
                    let arguments = request["params"]["arguments"].as_array().unwrap();
                    assert_eq!(arguments[1]["value"].as_array().unwrap().len(), index + 1);
                    assert_eq!(arguments.len() - 6, index + 1);
                }
                assert!(f.replies.lock().unwrap().iter().any(|reply| {
                    reply["reply"]["result"]["result"]["value"]
                        .as_array()
                        .is_some_and(|metadata| {
                            metadata.iter().any(|node| {
                                node["text"] == "performing click action\nclick action done"
                            })
                        })
                }));
            }
            assert!(
                !log.iter().any(|request| request["method"]
                    .as_str()
                    .is_some_and(|method| method.starts_with("Input.")
                        || method == "DOM.scrollIntoViewIfNeeded")),
                "{mode}: no input or action preparation"
            );
            assert!(
                log.iter()
                    .filter(|request| request["method"] == "Runtime.releaseObjectGroup"
                        && request["params"]["objectGroup"]
                            .as_str()
                            .is_some_and(|group| group.starts_with("native-query-")))
                    .count()
                    >= 2
            );
        }
    }

    #[tokio::test]
    async fn live_query_unique_same_backend_taps_and_keeps_observed_authority() {
        let mut f = fixture("strict-query-one").await;
        let expression = json!({"kind":"selector","selector":"button"});
        let first = publish_fixture_query(&mut f, expression.clone())
            .await
            .unwrap();
        let reference = first.nodes[0].reference.clone();
        let allocated = f.refs.next_ref_num();
        let repeated = publish_fixture_query(&mut f, expression).await.unwrap();
        assert_ne!(repeated.nodes[0].reference.id, reference.id);
        assert_eq!(f.refs.next_ref_num(), allocated + 1);
        assert!(f.refs.get("e1").unwrap().live_query.is_none());
        ClientActions::default()
            .execute(
                f.context(),
                "browser.perform",
                &json!({"identityScope":"scope","ref":reference,"action":{"kind":"tap"}}),
            )
            .await
            .unwrap();
        assert_eq!(f.refs.next_ref_num(), allocated + 1);
        assert_eq!(logged_query_matches(&f), 3);
        assert_eq!(
            f.log
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request["method"] == "Input.dispatchMouseEvent"
                    && request["params"]["type"] == "mousePressed")
                .count(),
            1
        );
        let before = logged_query_matches(&f);
        ClientActions::default().execute(f.context(), "browser.perform", &json!({"identityScope":"scope","ref":{"id":"@e1","revision":"1"},"action":{"kind":"tap"}})).await.unwrap();
        assert_eq!(
            logged_query_matches(&f),
            before,
            "Observed refs must not inherit strict provenance"
        );
    }

    #[tokio::test]
    async fn query_pinned_refs_skip_live_revalidation() {
        for (mode, expression, expected_nodes) in [
            (
                "strict-query-ambiguous",
                json!({"kind":"query","query":{"kind":"displayValue","value":{"kind":"string","value":"Save","exact":true}}}),
                1,
            ),
            (
                "strict-query-ambiguous",
                json!({"kind":"filter","source":{"kind":"index","source":{"kind":"query","query":{"kind":"label","value":{"kind":"string","value":"Save","exact":true}}},"index":"first"},"hasText":{"kind":"string","value":"Save","exact":false}}),
                1,
            ),
        ] {
            let mut f = fixture(mode).await;
            let query = publish_fixture_query(&mut f, expression).await.unwrap();
            assert_eq!(query.nodes.len(), expected_nodes);
            for node in &query.nodes {
                let id = element::parse_ref(&node.reference.id).unwrap();
                assert!(f.refs.get(&id).unwrap().live_query.is_none());
            }
            let allocated = f.refs.next_ref_num();
            ClientActions::default().execute(f.context(), "browser.perform", &json!({"identityScope":"scope","ref":query.nodes[0].reference,"action":{"kind":"tap"}})).await.unwrap();
            assert_eq!(logged_query_matches(&f), 1);
            assert_eq!(f.refs.next_ref_num(), allocated);
            assert!(f
                .log
                .lock()
                .unwrap()
                .iter()
                .any(|request| request["method"] == "Input.dispatchMouseEvent"
                    && request["params"]["type"] == "mousePressed"));
        }
    }

    #[tokio::test]
    async fn live_query_read_preserves_origin_and_reference_without_allocating() {
        let mut f = fixture("strict-query-one").await;
        let query = publish_fixture_query(&mut f, json!({"kind":"selector","selector":"button"}))
            .await
            .unwrap();
        let reference = &query.nodes[0].reference;
        let allocated = f.refs.next_ref_num();
        let retained = f.refs.retained_identity_counts();
        let frame = live_query_frame(&f);
        let options = serde_json::from_value(json!({"ref":reference.id})).unwrap();
        let result = super::super::client_observation::read(
            &f.page.client,
            &[frame],
            &mut f.refs,
            "scope",
            1,
            &options,
            &f.op,
        )
        .await
        .unwrap();
        assert_eq!(result["ref"], serde_json::to_value(reference).unwrap());
        assert_eq!(f.refs.next_ref_num(), allocated);
        assert_eq!(f.refs.retained_identity_counts(), retained);
        assert!(f
            .refs
            .get(&element::parse_ref(&reference.id).unwrap())
            .unwrap()
            .live_query
            .is_some());
    }

    fn output_filter_query_expression() -> Value {
        json!({"kind":"query","query":{"kind":"placeholder","value":{"kind":"string","value":"Save","exact":false},"visible":true}})
    }

    fn observed_fill_request(scope: &str, reference: &NodeReference, value: &str) -> Value {
        json!({"identityScope":scope,"ref":reference,"action":{"kind":"fill","value":value,"sensitive":false}})
    }

    #[test]
    fn observed_fill_and_output_filter_fixture_requests_obey_strict_schemas() {
        use super::super::client_observation::QueryOptions;
        let mut query = json!({"expression":output_filter_query_expression()});
        assert!(serde_json::from_value::<QueryOptions>(query.clone()).is_ok());
        query["expression"]["query"]["value"]
            .as_object_mut()
            .unwrap()
            .remove("exact");
        assert!(serde_json::from_value::<QueryOptions>(query).is_err());

        let reference = NodeReference {
            id: "@e1".into(),
            revision: "1".into(),
        };
        let mut fill = observed_fill_request("scope", &reference, "late");
        let parsed = decode::<Perform>(&fill).unwrap();
        assert_eq!(parsed.identity_scope, "scope");
        assert_eq!(parsed.reference, reference);
        assert!(
            matches!(parsed.action, LocatorAction::Fill { value, sensitive: false } if value == "late")
        );
        fill["action"].as_object_mut().unwrap().remove("sensitive");
        assert_eq!(
            decode::<Perform>(&fill).err(),
            Some(ProtocolError::InvalidArguments)
        );
    }

    #[tokio::test]
    async fn live_query_replacement_and_nth_resolve_temporary_targets_without_new_refs() {
        for (mode, expression, result_index, expected_backend) in [
            (
                "strict-query-replaced",
                json!({"kind":"selector","selector":"button"}),
                0,
                43,
            ),
            (
                "strict-query-nth-shift",
                json!({"kind":"selector","selector":"button"}),
                1,
                42,
            ),
            (
                "strict-query-explicit-nth",
                json!({"kind":"index","source":{"kind":"selector","selector":"button"},"index":1}),
                0,
                42,
            ),
            (
                "strict-query-output-filter",
                output_filter_query_expression(),
                0,
                42,
            ),
        ] {
            let mut f = fixture(mode).await;
            let found = publish_fixture_query(&mut f, expression).await.unwrap();
            let reference = found.nodes[result_index].reference.clone();
            let id = element::parse_ref(&reference.id).unwrap();
            let acquisition = f.refs.get(&id).unwrap().backend_node_id;
            let origin = f.refs.get(&id).unwrap().live_query.clone();
            let before = (
                f.refs.next_ref_num(),
                f.refs.retained_identity_counts(),
                f.refs.retained_query_origin_bytes(),
            );
            ClientActions::default()
                .execute(
                    f.context(),
                    "browser.perform",
                    &json!({"identityScope":"scope","ref":reference,"action":{"kind":"tap"}}),
                )
                .await
                .unwrap();
            let exact_resolve = f
                .log
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|request| request["method"] == "DOM.resolveNode")
                .cloned()
                .unwrap();
            assert_eq!(
                exact_resolve["params"]["backendNodeId"], expected_backend,
                "{mode}"
            );
            assert_ne!(acquisition, Some(expected_backend));
            assert_eq!(f.refs.get(&id).unwrap().backend_node_id, acquisition);
            assert_eq!(f.refs.get(&id).unwrap().live_query, origin);
            assert_eq!(
                (
                    f.refs.next_ref_num(),
                    f.refs.retained_identity_counts(),
                    f.refs.retained_query_origin_bytes()
                ),
                before
            );
            let options = serde_json::from_value(json!({"ref":reference.id})).unwrap();
            let fresh = super::super::client_observation::read(
                &f.page.client,
                &f.observation_frames,
                &mut f.refs,
                "scope",
                9,
                &options,
                &f.op,
            )
            .await
            .unwrap();
            assert_eq!(fresh["ref"], serde_json::to_value(&reference).unwrap());
            assert_eq!(
                f.log
                    .lock()
                    .unwrap()
                    .iter()
                    .rev()
                    .find(|request| request["method"] == "Accessibility.getPartialAXTree")
                    .unwrap()["params"]["backendNodeId"],
                expected_backend
            );
            assert_eq!(
                (
                    f.refs.next_ref_num(),
                    f.refs.retained_identity_counts(),
                    f.refs.retained_query_origin_bytes()
                ),
                before
            );
        }
    }

    #[tokio::test]
    async fn live_actionability_uses_the_current_temporary_binding_not_acquisition_evidence() {
        for (mode, acquired_actionable, current_actionable) in [
            ("strict-query-actionable-up", false, true),
            ("strict-query-actionable-down", true, false),
        ] {
            let mut f = fixture(mode).await;
            let found =
                publish_fixture_query(&mut f, json!({"kind":"selector","selector":"#target"}))
                    .await
                    .unwrap();
            let reference = found.nodes[0].reference.clone();
            let id = element::parse_ref(&reference.id).unwrap();
            assert_eq!(
                f.refs
                    .get(&id)
                    .unwrap()
                    .exact_binding
                    .as_ref()
                    .unwrap()
                    .actionable,
                acquired_actionable
            );
            let result = ClientActions::default()
                .execute(
                    f.context(),
                    "browser.perform",
                    &json!({"identityScope":"scope","ref":reference,"action":{"kind":"tap"}}),
                )
                .await;
            if current_actionable {
                assert!(result.is_ok(), "{mode}: {result:?}");
            } else {
                let failure = result.unwrap_err();
                assert_eq!(failure.error, ProtocolError::NotActionable);
                assert_eq!(failure.effects, Effects::NotDispatched);
            }
            let document_conversion = f.log.lock().unwrap().iter().any(|request| {
                request["params"]["functionDeclaration"]
                    .as_str()
                    .is_some_and(|source| source.contains("return this.documentElement"))
            });
            assert_eq!(document_conversion, !current_actionable);
            assert_eq!(
                f.refs
                    .get(&id)
                    .unwrap()
                    .exact_binding
                    .as_ref()
                    .unwrap()
                    .actionable,
                acquired_actionable
            );
        }
    }

    #[tokio::test]
    async fn located_live_and_pinned_issuance_survives_a_new_observation_revision() {
        for expression in [
            json!({"kind":"selector","selector":"button"}),
            json!({"kind":"query","query":{"kind":"label","value":{"kind":"string","value":"Save","exact":true}}}),
        ] {
            let mut f = fixture("strict-query-one").await;
            let first = publish_fixture_query(&mut f, expression.clone())
                .await
                .unwrap();
            let second = publish_fixture_query(&mut f, expression).await.unwrap();
            let reference = first.nodes[0].reference.clone();
            assert_ne!(reference.id, second.nodes[0].reference.id);
            let id = element::parse_ref(&reference.id).unwrap();
            let source = f.refs.get(&id).unwrap().live_query.clone();
            f.refs.begin_observation("scope", 1, 9);
            assert!(f.refs.get("e1").is_none());
            let observed =
                f.refs
                    .bind_exact(42, "button", "", f.observation_frames[0].binding.clone());
            assert_ne!(format!("@{observed}"), reference.id);
            let before = f.refs.next_ref_num();
            let mut context = f.context();
            context.revision = 9;
            ClientActions::default()
                .execute(
                    context,
                    "browser.perform",
                    &json!({"identityScope":"scope","ref":reference,"action":{"kind":"tap"}}),
                )
                .await
                .unwrap();
            let mut forged = reference.clone();
            forged.revision = "9".into();
            let mut context = f.context();
            context.revision = 9;
            let failure = ClientActions::default()
                .execute(
                    context,
                    "browser.perform",
                    &json!({"identityScope":"scope","ref":forged,"action":{"kind":"tap"}}),
                )
                .await
                .unwrap_err();
            assert_eq!(failure.error, ProtocolError::StaleReference);
            assert_eq!(failure.effects, Effects::NotDispatched);
            let options = serde_json::from_value(json!({"ref":reference.id})).unwrap();
            let fresh = super::super::client_observation::read(
                &f.page.client,
                &f.observation_frames,
                &mut f.refs,
                "scope",
                9,
                &options,
                &f.op,
            )
            .await
            .unwrap();
            assert_eq!(fresh["ref"], serde_json::to_value(&reference).unwrap());
            assert_eq!(f.refs.get(&id).unwrap().live_query, source);
            assert_eq!(f.refs.next_ref_num(), before);
        }
    }

    #[tokio::test]
    async fn query_publication_capacity_refusal_is_atomic_before_ref_allocation() {
        use super::super::client_observation::ObservationError;
        for mode in ["strict-query-one", "strict-query-multiple"] {
            let mut f = fixture(mode).await;
            f.refs.set_exact_limit_for_test(1);
            let before = f.refs.next_ref_num();
            let result =
                publish_fixture_query(&mut f, json!({"kind":"selector","selector":"button"})).await;
            assert_eq!(result.unwrap_err(), ObservationError::ResourceLimit);
            assert_eq!(f.refs.next_ref_num(), before);
            assert_eq!(f.refs.retained_identity_counts(), (1, 1));
            assert!(f.refs.get("e1").unwrap().live_query.is_none());
        }
        let mut f = fixture("strict-query-one").await;
        f.refs.set_query_origin_byte_limit_for_test(0);
        let before = f.refs.next_ref_num();
        assert_eq!(
            publish_fixture_query(&mut f, json!({"kind":"selector","selector":"button"}))
                .await
                .unwrap_err(),
            ObservationError::ResourceLimit
        );
        assert_eq!(f.refs.next_ref_num(), before);
        assert_eq!(f.refs.retained_query_origin_bytes(), 0);
        assert_eq!(f.refs.retained_identity_counts(), (1, 1));
    }

    #[tokio::test]
    async fn exact_resolution_negative_proof_is_stale_but_unknown_is_not() {
        for (mode, expected, cleanup_failed) in [
            ("exact-disconnected", ProtocolError::StaleReference, false),
            ("exact-exception", ProtocolError::BrowserFailure, false),
            ("exact-protocol-error", ProtocolError::BrowserFailure, false),
            ("exact-malformed", ProtocolError::BrowserFailure, false),
            ("exact-cleanup-failed", ProtocolError::StaleReference, true),
            (
                "exact-aux-cleanup-failed",
                ProtocolError::BrowserFailure,
                true,
            ),
        ] {
            let f = fixture(mode).await;
            let failure = ClientActions::default().execute(f.context(), "browser.perform", &json!({
                "identityScope":"scope", "ref":{"id":"@e1","revision":"1"}, "action":{"kind":"check"}
            })).await.unwrap_err();
            assert_eq!(failure.error, expected, "{mode}");
            assert_eq!(failure.effects, Effects::NotDispatched, "{mode}");
            assert_eq!(failure.cleanup_failed, cleanup_failed, "{mode}");
            if mode == "exact-aux-cleanup-failed" {
                let log = f.log.lock().unwrap();
                for handle in ["result-handle", "exception-handle", "exact-node"] {
                    assert!(log.iter().any(|r| r["method"] == "Runtime.releaseObject"
                        && r["params"]["objectId"] == handle));
                }
            }
            assert!(f.inputs().is_empty());
            assert!(!f
                .log
                .lock()
                .unwrap()
                .iter()
                .any(|r| r["method"] == "DOM.scrollIntoViewIfNeeded"));
        }
    }
    #[tokio::test]
    async fn exact_loader_mismatch_is_stale_before_dispatch() {
        let mut f = fixture("normal").await;
        let mut binding = f.refs.get("e1").unwrap().exact_binding.clone().unwrap();
        binding.loader = "retired-document".into();
        let id = f.refs.bind_exact(42, "checkbox", "", binding);
        let failure = ClientActions::default().execute(f.context(), "browser.perform", &json!({
            "identityScope":"scope", "ref":{"id":format!("@{id}"),"revision":"1"}, "action":{"kind":"check"}
        })).await.unwrap_err();
        assert_eq!(failure.error, ProtocolError::StaleReference);
        assert_eq!(failure.effects, Effects::NotDispatched);
        assert!(!failure.cleanup_failed);
        assert!(f.inputs().is_empty());
        assert!(!f
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["method"] == "DOM.resolveNode"));
    }
    #[test]
    fn action_success_cannot_hide_cleanup_integrity_and_primary_error_survives() {
        let d = Dispatch::default();
        d.cleanup.store(true, Ordering::SeqCst);
        let result = finish_dispatch(&d, Ok(Value::Null)).unwrap_err();
        assert_eq!(result.error, ProtocolError::CleanupFailed);
        assert!(result.cleanup_failed);
        assert_eq!(
            finish_dispatch(&d, Err(ProtocolError::BrowserFailure))
                .unwrap_err()
                .error,
            ProtocolError::BrowserFailure
        );
    }
    #[tokio::test]
    async fn direct_browser_fixture_admits_and_settles_real_broker_operations() {
        use super::super::{
            client_browser::ClientBrowser, client_session::ClientSession,
            client_transport::ClientExecutor,
        };
        let broker = Arc::new(ClientSession::new());
        let browser = ClientBrowser::new(broker.clone());
        let mut operations = FixtureOperations::new(broker.clone());
        for _ in 0..2 {
            let outcome = operations
                .execute(
                    &browser,
                    "page.title",
                    json!({"identityScope":"not-open"}),
                    2,
                )
                .await
                .unwrap();
            assert_eq!(outcome.result, Err(ProtocolError::StaleScope));
            assert_eq!(outcome.effects, Effects::NotDispatched);
            assert_eq!(
                broker.cancel(1, operations.sequence),
                Err(ProtocolError::OperationMissing)
            );
        }
        assert_eq!(operations.sequence, 2);
        browser.shutdown().await.unwrap();
        // Unlike a scope mismatch, reuse enters the real lifecycle dispatch and
        // calls broker.start. No retained browser exists, so the expected later
        // failure is ScopeUnavailable, never OperationMissing or pre-start cancel.
        let broker = Arc::new(ClientSession::new());
        let browser = ClientBrowser::new(broker.clone());
        let (sink, _events) =
            super::super::client_transport::ClientEventSink::test_channel(broker.clone());
        browser.set_event_sink(sink).unwrap();
        let mut operations = FixtureOperations::new(broker.clone());
        let outcome = operations
            .execute(
                &browser,
                "scope.open",
                json!({"source":"reuse","context":"isolated"}),
                2,
            )
            .await
            .unwrap();
        assert_eq!(outcome.result, Err(ProtocolError::ScopeUnavailable));
        // Failed mutating lifecycle work quarantines the broker. cancel checks
        // health before operation existence; settle still proves exact removal.
        assert_eq!(outcome.effects, Effects::Unknown);
        assert_eq!(
            broker.health().unwrap().1,
            super::super::client_protocol::ScopeState::Quarantined
        );
        assert_eq!(broker.cancel(1, 1), Err(ProtocolError::ScopeUnavailable));
        assert_eq!(
            broker.settle(1, 1, Effects::NotDispatched),
            Err(ProtocolError::OperationMissing)
        );
        // The deliberately failed mutating startup retains its uncertainty
        // journal. Drain it, but do not relabel that production outcome clean.
        assert_eq!(browser.shutdown().await, Err(ProtocolError::CleanupFailed));
    }
    #[test]
    fn stale_does_not_erase_unknown_effects_after_dispatch() {
        let d = Dispatch::default();
        d.mark();
        assert_eq!(
            d.failure(ProtocolError::StaleReference).effects,
            Effects::Unknown
        );
    }
    #[tokio::test]
    async fn focused_document_is_released_before_editable_leaf_and_keyboard_dispatch() {
        let f = fixture("focus-root-leaf").await;
        ClientActions::default()
            .execute(
                f.context(),
                "browser.keyboard.type",
                &json!({"identityScope":"scope","text":"ok","replace":false}),
            )
            .await
            .unwrap();
        let log = f.log.lock().unwrap();
        let document_release = log
            .iter()
            .position(|r| {
                r["method"] == "Runtime.releaseObject"
                    && r["params"]["objectId"] == "focused-document"
            })
            .unwrap();
        let leaf = log
            .iter()
            .position(|r| r["method"] == "DOM.resolveNode" && r["params"]["backendNodeId"] == 42)
            .unwrap();
        let input = log
            .iter()
            .position(|r| {
                r["method"]
                    .as_str()
                    .is_some_and(|m| m.starts_with("Input."))
            })
            .unwrap();
        assert!(document_release < leaf && leaf < input);
    }
    #[tokio::test]
    async fn focused_document_does_not_hide_missing_leaf_stale_cleanup_or_cancel() {
        for (mode, error, cleanup) in [
            ("focus-root-only", ProtocolError::NotActionable, false),
            ("focus-root-foreign", ProtocolError::StaleReference, false),
            (
                "focus-root-disconnected",
                ProtocolError::StaleReference,
                false,
            ),
            (
                "focus-root-cleanup-failed",
                ProtocolError::CleanupFailed,
                true,
            ),
            ("focus-root-cancel", ProtocolError::Cancelled, false),
        ] {
            let f = fixture(mode).await;
            let failure = ClientActions::default()
                .execute(
                    f.context(),
                    "browser.keyboard.type",
                    &json!({"identityScope":"scope","text":"private synthetic","replace":true}),
                )
                .await
                .unwrap_err();
            assert_eq!(failure.error, error, "{mode}");
            assert_eq!(failure.effects, Effects::NotDispatched, "{mode}");
            assert_eq!(failure.cleanup_failed, cleanup, "{mode}");
            assert!(f.inputs().is_empty(), "{mode}");
            assert!(
                f.log
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|r| r["method"] == "Runtime.releaseObject"
                        && r["params"]["objectId"] == "focused-document"),
                "{mode}"
            );
        }
    }
    #[tokio::test]
    async fn cancelled_exact_resolution_drains_and_releases_late_remote_handle() {
        let f = fixture("resolve-cancel").await;
        let d = Dispatch::default();
        let binding = f.refs.get("e1").unwrap().exact_binding.clone().unwrap();
        let result = resolve_action_object(&f.context(), &d, &binding, 42).await;
        assert_eq!(result, Err(ProtocolError::Cancelled));
        assert!(!d.cleanup.load(Ordering::SeqCst));
        assert!(f.inputs().is_empty());
        assert!(f
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|v| v["method"] == "Runtime.releaseObject"
                && v["params"]["objectId"] == "exact-node"));
    }
    #[test]
    fn observation_cleanup_preserves_primary_and_sets_action_integrity_flag() {
        let dispatch = Dispatch::default();
        let error = observation_action_error(
            super::super::client_observation::ObservationError::CleanupFailed {
                primary: Some(Box::new(
                    super::super::client_observation::ObservationError::Cancelled,
                )),
            },
            &dispatch,
        );
        let failure = dispatch.failure(error);
        assert_eq!(failure.error, ProtocolError::Cancelled);
        assert!(failure.cleanup_failed);
        assert_eq!(failure.effects, Effects::NotDispatched);
    }
    #[test]
    fn upload_paths_refuse_escapes_and_preserve_nested_directory_paths() {
        for path in [
            "", "../a", "a/../b", "/tmp/a", "a\\b", "C:a", "a//b", "a/./b", "a\0b",
        ] {
            assert!(upload_path(path).is_err(), "{path:?}");
        }
        assert_eq!(
            upload_path("nested/data.txt").unwrap(),
            PathBuf::from("nested/data.txt")
        );
    }
    #[test]
    fn select_modes_are_unambiguous_and_string_means_label() {
        assert_eq!(
            decode::<Selection>(&json!("value-looking-label"))
                .unwrap()
                .wire()
                .unwrap(),
            json!({"label":"value-looking-label"})
        );
        assert!(decode::<Selection>(&json!({"label":"a","value":"b"}))
            .unwrap()
            .wire()
            .is_err());
        assert!(decode::<Selection>(&json!({"index":-1})).is_err());
    }
    #[test]
    fn pointer_and_swipe_preserve_public_geometry_contract() {
        assert_eq!(Point { x: 3.7, y: 8.1 }.validate().unwrap().x, 4.0);
        assert!(Point {
            x: f64::NAN,
            y: 0.0
        }
        .validate()
        .is_err());
        assert_eq!(
            wheel(Direction::Down, Momentum::None, 100.0, 200.0).unwrap(),
            (0.0, 100.0)
        );
        assert_eq!(
            wheel(Direction::Left, Momentum::Fast, 100.0, 200.0).unwrap(),
            (-150.0, 0.0)
        );
        assert!(duration(Some(60001), 500).is_err());
    }
    #[tokio::test]
    async fn original_observed_issuance_fills_after_refresh_but_forgery_and_omission_refuse() {
        let mut f = fixture("strict-query-one").await;
        let first = NodeReference {
            id: "@e1".into(),
            revision: "1".into(),
        };
        let binding = f.refs.get("e1").unwrap().exact_binding.clone().unwrap();
        f.refs.begin_observation("scope", 1, 2);
        assert_eq!(f.refs.bind_exact(42, "textbox", "", binding.clone()), "e1");
        let options = serde_json::from_value(json!({"ref":first.id})).unwrap();
        let fresh = super::super::client_observation::read(
            &f.page.client,
            &f.observation_frames,
            &mut f.refs,
            "scope",
            2,
            &options,
            &f.op,
        )
        .await
        .unwrap();
        assert_eq!(fresh["ref"], serde_json::to_value(&first).unwrap());
        let actions = ClientActions::default();
        let mut context = f.context();
        context.revision = 2;
        context.observed_revision = 2;
        actions
            .execute(
                context,
                "browser.perform",
                &observed_fill_request("scope", &first, "late"),
            )
            .await
            .unwrap();
        assert!(f
            .inputs()
            .iter()
            .any(|request| request["method"] == "Input.insertText"
                && request["params"]["text"] == "late"));
        f.log.lock().unwrap().clear();
        for revision in ["2", "01", "999"] {
            let failure = actions
                .execute(
                    f.context(),
                    "browser.perform",
                    &observed_fill_request(
                        "scope",
                        &NodeReference {
                            id: first.id.clone(),
                            revision: revision.into(),
                        },
                        "forged",
                    ),
                )
                .await
                .unwrap_err();
            assert_eq!(failure.error, ProtocolError::StaleReference);
            assert_eq!(failure.effects, Effects::NotDispatched);
        }
        let baseline = f.refs.clone();
        f.refs.begin_observation("scope", 1, 3);
        f.refs.bind_exact(42, "textbox", "", binding);
        f.refs
            .retain_snapshot_entries(&baseline, &Default::default());
        let failure = actions
            .execute(
                f.context(),
                "browser.perform",
                &observed_fill_request("scope", &first, "omitted"),
            )
            .await
            .unwrap_err();
        assert_eq!(failure.error, ProtocolError::StaleReference);
        assert_eq!(failure.effects, Effects::NotDispatched);
        assert!(f.log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn viewport_stable_issuance_uses_current_geometry_and_recovery_publication_gate() {
        let mut f = fixture("normal").await;
        let first = f
            .refs
            .try_viewport_ref("scope", 1, "page", 1)
            .unwrap()
            .clone();
        f.refs.retire_all_references();
        f.refs.begin_observation("scope", 1, 2);
        assert_eq!(
            f.refs.try_viewport_ref("scope", 1, "page", 2).unwrap(),
            &first
        );
        let actions = ClientActions::default();
        let args = json!({"identityScope":"scope","ref":{"id":format!("@{}",first.id),"revision":"1"},"action":{"kind":"swipe","direction":"down"}});
        for revision in ["0", "2", "01"] {
            let mut forged = args.clone();
            forged["ref"]["revision"] = json!(revision);
            assert_eq!(
                actions
                    .execute(f.context(), "browser.perform", &forged)
                    .await
                    .unwrap_err()
                    .error,
                ProtocolError::StaleReference
            );
        }
        let mut blocked = f.context();
        blocked.observation_after = Some(2);
        blocked.observed_revision = 2;
        assert_eq!(
            actions
                .execute(blocked, "browser.perform", &args)
                .await
                .unwrap_err()
                .error,
            ProtocolError::StaleReference
        );
        assert!(f.inputs().is_empty());
        let mut allowed = f.context();
        allowed.revision = 3;
        allowed.observation_after = Some(2);
        allowed.observed_revision = 3;
        actions
            .execute(allowed, "browser.perform", &args)
            .await
            .unwrap();
        assert!(f
            .inputs()
            .iter()
            .any(|request| request["params"]["type"] == "mouseWheel"
                && request["params"]["deltaY"] == 100.));
        assert!(!f
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|request| request["method"] == "DOM.resolveNode"));
        f.refs.retire_owner_references();
        f.log.lock().unwrap().clear();
        assert_eq!(
            actions
                .execute(f.context(), "browser.perform", &args)
                .await
                .unwrap_err()
                .error,
            ProtocolError::StaleReference
        );
        assert!(f.log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn viewport_capability_still_rejects_old_scope_and_dom_actions() {
        let mut f = fixture("normal").await;
        let viewport = f
            .refs
            .try_viewport_ref("scope", 1, "page", 1)
            .unwrap()
            .id
            .clone();
        let actions = ClientActions::default();
        for (scope, kind) in [("old-scope", "swipe"), ("scope", "tap")] {
            let action = if kind == "swipe" {
                json!({"kind":kind,"direction":"down"})
            } else {
                json!({"kind":kind})
            };
            let error=actions.execute(f.context(),"browser.perform",&json!({"identityScope":scope,"ref":{"id":format!("@{viewport}"),"revision":"1"},"action":action})).await.unwrap_err();
            assert_eq!(error.effects, Effects::NotDispatched);
        }
        assert!(f.inputs().is_empty());
    }
    #[tokio::test]
    async fn stale_exact_ref_revision_never_dispatches_or_uses_role_fallback() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        let error=actions.execute(f.context(),"browser.perform",&json!({"identityScope":"scope","ref":{"id":"@e1","revision":"0"},"action":{"kind":"tap"}})).await.unwrap_err();
        assert_eq!(error.error, ProtocolError::StaleReference);
        assert_eq!(error.effects, Effects::NotDispatched);
        assert!(f.log.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn typing_sequence_fences_focus_select_delete_and_scope_reset() {
        for mode in [
            "focus-cancel",
            "select-cancel",
            "select-modifier-cancel",
            "delete-cancel",
            "focus-reset",
        ] {
            let f = fixture(mode).await;
            let actions = ClientActions::default();
            let error = actions
                .execute(
                    f.context(),
                    "browser.keyboard.type",
                    &json!({"identityScope":"scope","replace":true,"text":"Z"}),
                )
                .await
                .unwrap_err();
            let inputs = f.inputs();
            if mode.starts_with("focus-") {
                assert!(inputs.is_empty(), "{mode}");
                assert_eq!(error.effects, Effects::NotDispatched);
            }
            if matches!(mode, "select-cancel" | "select-modifier-cancel") {
                assert!(!inputs.iter().any(|r| r["params"]["code"] == "Delete"));
            }
            if matches!(
                mode,
                "select-cancel" | "select-modifier-cancel" | "delete-cancel"
            ) {
                // The server cancels before replying to keyUp, not between
                // fully acknowledged substeps. Cleanup cannot settle that ACK.
                assert_eq!(error.effects, Effects::Unknown, "{mode}");
            }
            assert!(
                !inputs
                    .iter()
                    .any(|r| r["params"]["code"] == "KeyZ" || r["method"] == "Input.insertText"),
                "{mode}"
            );
            if mode == "focus-reset" {
                assert_eq!(error.error, ProtocolError::StaleScope);
            } else {
                assert_eq!(error.error, ProtocolError::Cancelled);
            }
        }
    }
    #[tokio::test]
    async fn cancelled_focus_probe_discards_late_success_and_releases_exact_object_once() {
        let f = fixture("focus-cancel-late").await;
        let failure = ClientActions::default()
            .execute(
                f.context(),
                "browser.keyboard.type",
                &json!({"identityScope":"scope","replace":true,"text":"Z"}),
            )
            .await
            .unwrap_err();
        assert_eq!(*f.op.cancellation.borrow(), CancelSignal::Requested);
        assert_eq!(failure.error, ProtocolError::Cancelled);
        assert_eq!(failure.effects, Effects::NotDispatched);
        assert!(!failure.cleanup_failed);
        assert!(f.inputs().is_empty());

        let focus_request = f
            .log
            .lock()
            .unwrap()
            .iter()
            .find(|request| {
                request["method"] == "Runtime.callFunctionOn"
                    && request["params"]["functionDeclaration"]
                        .as_str()
                        .is_some_and(|source| source.contains("return this.nodeType===1"))
            })
            .unwrap()
            .clone();
        assert!(f
            .replies
            .lock()
            .unwrap()
            .iter()
            .all(|entry| entry["request"]["id"] != focus_request["id"]));

        // The caller has already rejected cleanly while the focus reply is held.
        // Only this post-terminal round trip releases the late focus success;
        // its ACK drains that reply on the same live connection before checks.
        f.page
            .client
            .send_command("Browser.getVersion", None, Some("page"))
            .await
            .unwrap();
        assert_eq!(f.page.client.pending_len().await, 0);
        assert!(f.inputs().is_empty());
        assert_eq!(f.state.held_modifiers().unwrap(), 0);
        f.page.permit.check().unwrap();

        let log = f.log.lock().unwrap();
        let resolved: Vec<_> = log
            .iter()
            .filter(|request| request["method"] == "DOM.resolveNode")
            .collect();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0]["sessionId"], "page");
        assert_eq!(resolved[0]["params"]["backendNodeId"], 42);
        let releases: Vec<_> = log
            .iter()
            .filter(|request| request["method"] == "Runtime.releaseObject")
            .collect();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0]["sessionId"], "page");
        assert_eq!(releases[0]["params"]["objectId"], "exact-node");

        let replies = f.replies.lock().unwrap();
        let resolved_reply = replies
            .iter()
            .find(|entry| entry["request"]["id"] == resolved[0]["id"])
            .unwrap();
        assert_eq!(
            resolved_reply["reply"]["result"]["object"]["objectId"],
            releases[0]["params"]["objectId"]
        );
        let focus_replies: Vec<_> = replies
            .iter()
            .filter(|entry| entry.get("heldUntilRequest").is_some())
            .collect();
        assert_eq!(focus_replies.len(), 1);
        let focus = focus_replies[0];
        assert_eq!(focus["request"], focus_request);
        assert_eq!(focus["request"]["method"], "Runtime.callFunctionOn");
        assert_eq!(focus["request"]["sessionId"], "page");
        assert_eq!(focus["request"]["params"]["objectId"], "exact-node");
        assert_eq!(focus["request"]["params"]["returnByValue"], true);
        assert_eq!(focus["reply"]["id"], focus["request"]["id"]);
        assert_eq!(focus["reply"]["result"]["result"]["value"], true);
        assert_eq!(&focus["cleanupRequest"], releases[0]);
        assert_eq!(focus["heldUntilRequest"]["method"], "Browser.getVersion");
        assert_eq!(focus["heldUntilRequest"]["sessionId"], "page");
        let cleanup_replies: Vec<_> = replies
            .iter()
            .filter(|entry| entry["request"]["id"] == releases[0]["id"])
            .collect();
        assert_eq!(cleanup_replies.len(), 1);
        assert_eq!(cleanup_replies[0]["reply"]["id"], releases[0]["id"]);
        assert_eq!(cleanup_replies[0]["reply"]["result"], json!({}));
        assert!(cleanup_replies[0]["reply"].get("error").is_none());
        let reply_position = |id: &Value| {
            replies
                .iter()
                .position(|entry| &entry["request"]["id"] == id)
                .unwrap()
        };
        assert!(reply_position(&releases[0]["id"]) < reply_position(&focus_request["id"]));
        assert!(
            reply_position(&focus_request["id"]) < reply_position(&focus["heldUntilRequest"]["id"])
        );
    }
    #[tokio::test]
    async fn replacement_acknowledged_substep_cancel_preserves_settled_prefix() {
        for key in ["ControlOrMeta+A", "Delete"] {
            let scope = format!("settled-prefix-{}", uuid::Uuid::new_v4());
            let f = fixture_scoped("normal", &scope).await;
            let cancel = f._cancel.clone();
            let reached = Arc::new(AtomicBool::new(false));
            let acknowledged = reached.clone();
            let _boundary = ReplacementBoundary::install(&scope, 1, 1, key, move || {
                acknowledged.store(true, Ordering::SeqCst);
                cancel.send_replace(CancelSignal::Requested);
            });
            let failure = ClientActions::default()
                .execute(
                    f.context(),
                    "browser.keyboard.type",
                    &json!({
                        "identityScope":scope, "replace":true, "text":"Z"
                    }),
                )
                .await
                .unwrap_err();
            assert!(reached.load(Ordering::SeqCst));
            assert_eq!(failure.error, ProtocolError::Cancelled);
            assert_eq!(failure.effects, Effects::Completed);
            assert!(!failure.cleanup_failed);
            assert_eq!(f.state.held_modifiers().unwrap(), 0);
            assert_eq!(f.page.client.pending_len().await, 0);
            f.page.permit.check().unwrap();
            let inputs = f.inputs();
            assert!(inputs.iter().all(|request| request["sessionId"] == "page"));
            let modifier = if cfg!(target_os = "macos") {
                "MetaLeft"
            } else {
                "ControlLeft"
            };
            for code in ["KeyA", modifier] {
                assert!(inputs
                    .iter()
                    .any(|request| request["params"]["code"] == code
                        && request["params"]["type"] == "keyUp"));
            }
            assert_eq!(
                inputs
                    .iter()
                    .filter(|request| request["params"]["code"] == "Delete")
                    .count(),
                if key == "Delete" { 2 } else { 0 }
            );
            assert!(!inputs
                .iter()
                .any(|request| request["params"]["code"] == "KeyZ"
                    || request["method"] == "Input.insertText"));
        }
    }

    #[tokio::test]
    async fn replacement_missing_prefix_proof_does_not_interrupt_ordinary_typing() {
        for cancelled in [false, true] {
            let scope = format!("unproved-prefix-{}", uuid::Uuid::new_v4());
            let f = fixture_scoped("normal", &scope).await;
            // Make the optional inventory proof unavailable while leaving the
            // existing action permit and actual keyboard transport intact.
            f.page.targets.seal();
            let cancel = f._cancel.clone();
            let _boundary = ReplacementBoundary::install(&scope, 1, 1, "Delete", move || {
                if cancelled {
                    cancel.send_replace(CancelSignal::Requested);
                }
            });
            let result = ClientActions::default()
                .execute(
                    f.context(),
                    "browser.keyboard.type",
                    &json!({
                        "identityScope":scope, "replace":true, "text":"Z"
                    }),
                )
                .await;
            if cancelled {
                let failure = result.unwrap_err();
                assert_eq!(failure.error, ProtocolError::Cancelled);
                assert_eq!(failure.effects, Effects::Unknown);
            } else {
                result.unwrap();
            }
            assert_eq!(
                f.inputs()
                    .iter()
                    .any(|request| request["params"]["code"] == "KeyZ"),
                !cancelled
            );
        }
    }

    #[tokio::test]
    async fn replacement_prefix_cannot_rebase_after_missing_or_changed_initial_authority() {
        for initially_unavailable in [false, true] {
            let scope = format!("unrebased-prefix-{}", uuid::Uuid::new_v4());
            let f = fixture_scoped("normal", &scope).await;
            let target = f.page.target_id.clone();
            if initially_unavailable {
                f.page
                    .targets
                    .attached(
                        "context",
                        target.clone(),
                        f.page.page_session_id.clone(),
                        "page".into(),
                    )
                    .unwrap();
                assert!(f.page.targets.inventory().is_err());
            }
            let targets = f.page.targets.clone();
            let _selected =
                ReplacementBoundary::install(&scope, 1, 1, "ControlOrMeta+A", move || {
                    if initially_unavailable {
                        targets.configured(&target).unwrap();
                    } else {
                        targets.invalidate_inventory().unwrap();
                    }
                    assert!(targets.inventory().is_ok());
                });
            let cancel = f._cancel.clone();
            let _deleted = ReplacementBoundary::install(&scope, 1, 1, "Delete", move || {
                cancel.send_replace(CancelSignal::Requested);
            });
            let failure = ClientActions::default()
                .execute(
                    f.context(),
                    "browser.keyboard.type",
                    &json!({
                        "identityScope":scope, "replace":true, "text":"Z"
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(failure.error, ProtocolError::Cancelled);
            assert_eq!(failure.effects, Effects::Unknown);
            let inputs = f.inputs();
            assert!(inputs
                .iter()
                .any(|request| request["params"]["code"] == "Delete"
                    && request["params"]["type"] == "keyUp"));
            assert!(!inputs
                .iter()
                .any(|request| request["params"]["code"] == "KeyZ"));
        }
    }

    #[tokio::test]
    async fn replacement_next_pending_mutation_invalidates_acknowledged_prefix() {
        for (mode, key) in [
            ("delete-cancel", "ControlOrMeta+A"),
            ("type-cancel", "Delete"),
        ] {
            let scope = format!("pending-prefix-{}", uuid::Uuid::new_v4());
            let f = fixture_scoped(mode, &scope).await;
            let reached = Arc::new(AtomicBool::new(false));
            let acknowledged = reached.clone();
            let _boundary = ReplacementBoundary::install(&scope, 1, 1, key, move || {
                acknowledged.store(true, Ordering::SeqCst);
            });
            let failure = ClientActions::default()
                .execute(
                    f.context(),
                    "browser.keyboard.type",
                    &json!({
                        "identityScope":scope, "replace":true, "text":"Z"
                    }),
                )
                .await
                .unwrap_err();
            assert!(reached.load(Ordering::SeqCst));
            assert_eq!(failure.error, ProtocolError::Cancelled);
            assert_eq!(failure.effects, Effects::Unknown, "{mode}");
        }
    }

    #[tokio::test]
    async fn replacement_cancelled_prefix_requires_cleanup_ack_and_live_authority() {
        for mode in [
            "normal",
            "prefix-cleanup-failed",
            "prefix-cleanup-reset",
            "prefix-cleanup-disconnected",
        ] {
            let scope = format!("cleanup-prefix-{}", uuid::Uuid::new_v4());
            let f = fixture_scoped(mode, &scope).await;
            // An independently held modifier must also be released before a
            // settled cancellation is reusable, not silently left down.
            f.state
                .execute(
                    &f.page,
                    &[],
                    &f.op,
                    "input.keyboard",
                    &json!({
                        "action":"down", "value":"Shift"
                    }),
                )
                .await
                .unwrap();
            let cancel = f._cancel.clone();
            let _boundary = ReplacementBoundary::install(&scope, 1, 1, "Delete", move || {
                cancel.send_replace(CancelSignal::Requested);
            });
            let failure = ClientActions::default()
                .execute(
                    f.context(),
                    "browser.keyboard.type",
                    &json!({
                        "identityScope":scope, "replace":true, "text":"Z"
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(failure.error, ProtocolError::Cancelled, "{mode}");
            assert_eq!(
                failure.effects,
                if mode == "normal" {
                    Effects::Completed
                } else {
                    Effects::Unknown
                },
                "{mode}"
            );
            assert_eq!(failure.cleanup_failed, mode != "normal", "{mode}");
            assert!(f
                .inputs()
                .iter()
                .any(|request| request["params"]["code"] == "ShiftLeft"
                    && request["params"]["type"] == "keyUp"));
            assert!(!f
                .inputs()
                .iter()
                .any(|request| request["params"]["code"] == "KeyZ"));
            if mode == "normal" {
                assert_eq!(f.state.held_modifiers().unwrap(), 0);
            }
        }
    }

    #[tokio::test]
    async fn replacement_prefix_cancel_cannot_hide_retired_epoch_or_inventory() {
        for retire_permit in [false, true] {
            let scope = format!("authority-prefix-{}", uuid::Uuid::new_v4());
            let f = fixture_scoped("normal", &scope).await;
            let cancel = f._cancel.clone();
            let targets = f.page.targets.clone();
            let gate = f.gate.clone();
            let _boundary =
                ReplacementBoundary::install(&scope, 1, 1, "ControlOrMeta+A", move || {
                    if retire_permit {
                        gate.seal();
                    } else {
                        targets.invalidate_inventory().unwrap();
                    }
                    cancel.send_replace(CancelSignal::Requested);
                });
            let failure = ClientActions::default()
                .execute(
                    f.context(),
                    "browser.keyboard.type",
                    &json!({
                        "identityScope":scope, "replace":true, "text":"Z"
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(
                failure.error,
                if retire_permit {
                    ProtocolError::StaleScope
                } else {
                    ProtocolError::Cancelled
                }
            );
            assert_eq!(failure.effects, Effects::Unknown);
            assert!(!f.inputs().iter().any(|request| matches!(
                request["params"]["code"].as_str(),
                Some("Delete" | "KeyZ")
            )));
        }
    }

    #[tokio::test]
    async fn replacement_prefix_session_close_is_not_reusable_cancellation() {
        let scope = format!("closed-prefix-{}", uuid::Uuid::new_v4());
        let f = fixture_scoped("normal", &scope).await;
        let cancel = f._cancel.clone();
        let _boundary = ReplacementBoundary::install(&scope, 1, 1, "Delete", move || {
            cancel.send_replace(CancelSignal::SessionClosed);
        });
        let failure = ClientActions::default()
            .execute(
                f.context(),
                "browser.keyboard.type",
                &json!({
                    "identityScope":scope, "replace":true, "text":"Z"
                }),
            )
            .await
            .unwrap_err();
        assert_eq!(failure.error, ProtocolError::Cancelled);
        assert_eq!(failure.effects, Effects::Unknown);
        assert!(!f
            .inputs()
            .iter()
            .any(|request| request["params"]["code"] == "KeyZ"));
    }

    #[tokio::test]
    async fn replacement_prefix_receipt_rejects_observed_transport_loss() {
        let mut f = fixture("normal").await;
        let proof = SettledReplacementPrefix::capture(&f.context()).unwrap();
        let mut lost = f.page.client.remote_connection_closed();
        f.server.abort();
        let _ = (&mut f.server).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !*lost.borrow() {
                lost.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(
            proof.check(&f.context()),
            Err(ProtocolError::BrowserFailure)
        );
    }

    #[tokio::test]
    async fn replacement_prefix_receipt_is_exact_and_never_promotes_other_errors() {
        let mut f = fixture("normal").await;
        let proof = SettledReplacementPrefix::capture(&f.context()).unwrap();
        f.page.page_session_id = "other-session".into();
        assert_eq!(proof.check(&f.context()), Err(ProtocolError::StaleScope));
        f.page.page_session_id = "page".into();
        f.op.sequence += 1;
        assert_eq!(proof.check(&f.context()), Err(ProtocolError::StaleScope));
        f.op.sequence -= 1;
        f.op.generation += 1;
        assert_eq!(proof.check(&f.context()), Err(ProtocolError::StaleScope));
        f.op.generation -= 1;
        f.page.identity_scope = "other-scope".into();
        assert_eq!(proof.check(&f.context()), Err(ProtocolError::StaleScope));
        f.page.identity_scope = "scope".into();
        proof.check(&f.context()).unwrap();
        let d = Dispatch::default();
        d.mark();
        *d.settled_replacement_prefix.lock().unwrap() = Some(Arc::new(proof));
        for error in [
            ProtocolError::BrowserFailure,
            ProtocolError::DeadlineExceeded,
            ProtocolError::StaleScope,
            ProtocolError::CleanupFailed,
        ] {
            assert_eq!(
                finish_dispatch(&d, Err(error)).unwrap_err().effects,
                Effects::Unknown
            );
        }
        d.mark();
        assert!(d.settled_replacement_prefix.lock().unwrap().is_none());
    }
    #[tokio::test]
    async fn initial_focused_keyboard_needs_no_snapshot_but_reconnect_does() {
        for (baseline, revision, allowed) in [
            (None, 0, true),
            (Some(0), 0, false),
            (Some(0), 1, true),
            (Some(7), 7, false),
            (Some(7), 8, true),
        ] {
            let f = fixture("normal").await;
            if !allowed {
                for (command, args) in [
                    (
                        "browser.keyboard.press",
                        json!({"identityScope":"scope","key":"Enter"}),
                    ),
                    (
                        "browser.pointer",
                        json!({"identityScope":"scope","point":{"x":10,"y":20},"action":{"kind":"tap"}}),
                    ),
                ] {
                    let mut context = f.context();
                    context.observation_after = baseline;
                    context.observed_revision = revision;
                    let failure = ClientActions::default()
                        .execute(context, command, &args)
                        .await
                        .unwrap_err();
                    assert_eq!(failure.error, ProtocolError::StaleReference);
                    assert_eq!(failure.effects, Effects::NotDispatched);
                    assert!(f.inputs().is_empty());
                }
            }
            let mut context = f.context();
            context.observation_after = baseline;
            context.observed_revision = revision;
            context.revision = revision;
            let result = ClientActions::default()
                .execute(
                    context,
                    "browser.keyboard.type",
                    &json!({"identityScope":"scope","replace":true,"text":"Z"}),
                )
                .await;
            if allowed {
                result.unwrap();
                assert!(!f.inputs().is_empty());
            } else {
                let failure = result.unwrap_err();
                assert_eq!(failure.error, ProtocolError::StaleReference);
                assert_eq!(failure.effects, Effects::NotDispatched);
                assert!(f.inputs().is_empty());
            }
        }
    }
    #[tokio::test]
    async fn replacement_typing_dispatches_select_delete_then_literal_type() {
        let f = fixture("normal").await;
        ClientActions::default()
            .execute(
                f.context(),
                "browser.keyboard.type",
                &json!({"identityScope":"scope","replace":true,"text":"Z"}),
            )
            .await
            .unwrap();
        let input = f.inputs();
        let a = input
            .iter()
            .position(|r| r["params"]["code"] == "KeyA")
            .unwrap();
        let delete = input
            .iter()
            .position(|r| r["params"]["code"] == "Delete")
            .unwrap();
        let text = input
            .iter()
            .position(|r| r["params"]["code"] == "KeyZ")
            .unwrap();
        assert!(a < delete && delete < text);
    }
    #[tokio::test]
    async fn pointer_secondary_and_double_click_have_native_button_counts() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        for kind in ["secondaryTap", "doubleTap"] {
            actions.execute(f.context(),"browser.pointer",&json!({"identityScope":"scope","point":{"x":10,"y":20},"action":{"kind":kind}})).await.unwrap();
        }
        let input = f.inputs();
        let pressed: Vec<_> = input
            .iter()
            .filter(|r| r["params"]["type"] == "mousePressed")
            .collect();
        assert_eq!(pressed.len(), 3);
        assert_eq!(pressed[0]["params"]["button"], "right");
        assert_eq!(pressed[2]["params"]["clickCount"], 2);
    }
    #[tokio::test]
    async fn sensitive_fill_failure_has_only_static_categories() {
        let f = fixture("focus-cancel").await;
        f._cancel.send_replace(CancelSignal::Requested);
        let actions = ClientActions::default();
        let error=actions.execute(f.context(),"browser.perform",&json!({"identityScope":"scope","ref":{"id":"@e1","revision":"1"},"action":{"kind":"fill","value":"synthetic-secret-value","sensitive":true}})).await.unwrap_err();
        assert!(!format!("{error:?}").contains("synthetic-secret-value"));
        assert_eq!(error.error, ProtocolError::Cancelled);
    }

    async fn seed_recording(
        actions: &ClientActions,
        f: &Fixture,
        ordinal: u64,
        bytes: Option<&[u8]>,
        stop_error: bool,
    ) {
        let mut ledger = actions.recording.lock().await;
        if ledger.authority.is_none() {
            ledger.authority = Some(
                f.blobs
                    .begin_artifact_attempt(&f.context().blob_scope())
                    .unwrap(),
            );
        }
        let reservation = f
            .blobs
            .reserve_artifact(
                ledger.authority.as_ref().unwrap(),
                &f.context().blob_scope(),
            )
            .unwrap();
        let directory = OwnedDirectory::create().unwrap();
        let path = directory.path.join(format!("video-part{ordinal}.webm"));
        if let Some(bytes) = bytes {
            std::fs::write(&path, bytes).unwrap();
        }
        let mut state = RecordingState::new();
        state.output_path = path.to_string_lossy().into_owned();
        state.active = true;
        state.frame_count = 1;
        state.capture_task = Some(tokio::spawn(async move {
            if stop_error {
                Err("Synthetic stop failure".into())
            } else {
                Ok(())
            }
        }));
        ledger.armed = true;
        ledger.ordinal = ordinal;
        ledger.current = Some(OwnedRecording {
            state,
            directory,
            reservation: Some(reservation),
            scope: f.context().blob_scope(),
            started_at: format!("2026-10-21T00:00:0{ordinal}.000Z"),
            ordinal,
            read_job: None,
            bytes: None,
            cleanup_complete: Arc::new(AtomicBool::new(true)),
            attachment: None,
        });
    }
    async fn collect_recording(
        actions: &ClientActions,
        f: &Fixture,
    ) -> Result<Value, ActionFailure> {
        actions
            .execute(
                f.context(),
                "recording.stop",
                &json!({"identityScope":f.page.identity_scope}),
            )
            .await
    }
    #[tokio::test]
    async fn recording_ledger_preserves_order_start_instants_and_rotated_scope() {
        let mut f = fixture("normal").await;
        let actions = ClientActions::default();
        let bytes = [0x1a, 0x45, 0xdf, 0xa3, 1];
        seed_recording(&actions, &f, 1, Some(&bytes), false).await;
        actions
            .recording_page_closing("scope", &f.blobs)
            .await
            .unwrap();
        assert!(actions.recording.lock().await.armed);
        f.blobs.revoke_scope(&f.context().blob_scope()).unwrap();
        f.page.identity_scope = "replacement".into();
        f.blobs.activate_scope(f.context().blob_scope()).unwrap();
        seed_recording(&actions, &f, 2, Some(&bytes), false).await;
        let result = collect_recording(&actions, &f).await.unwrap();
        let segments = result["segments"].as_array().unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0]["startedAt"], "2026-10-21T00:00:01.000Z");
        assert_eq!(segments[1]["startedAt"], "2026-10-21T00:00:02.000Z");
        for segment in segments {
            assert_eq!(segment["identityScope"], "replacement");
            let handle = segment["handle"].as_str().unwrap();
            assert_eq!(
                f.blobs
                    .read(&f.context().blob_scope(), handle, 0, 5)
                    .unwrap(),
                bytes
            );
            f.blobs.release(&f.context().blob_scope(), handle).unwrap();
        }
        assert!(!actions.recording.lock().await.armed);
        assert_eq!(
            collect_recording(&actions, &f).await.unwrap()["segments"],
            json!([])
        );
    }
    #[tokio::test]
    async fn recording_batch_rejection_preserves_two_private_segments_for_current_scope() {
        let mut f = fixture("normal").await;
        let actions = ClientActions::default();
        let bytes = [0x1a, 0x45, 0xdf, 0xa3, 1];
        for ordinal in [1, 2] {
            seed_recording(&actions, &f, ordinal, Some(&bytes), false).await;
            actions
                .recording_page_closing("scope", &f.blobs)
                .await
                .unwrap();
        }
        f.blobs.revoke_scope(&f.context().blob_scope()).unwrap();
        assert_eq!(
            collect_recording(&actions, &f).await.unwrap_err().error,
            ProtocolError::StaleScope
        );
        {
            let ledger = actions.recording.lock().await;
            assert_eq!(ledger.finished.len(), 2);
            assert!(ledger
                .finished
                .iter()
                .all(|v| v.reservation.is_some() && v.bytes.as_deref() == Some(&bytes)));
        }
        f.page.identity_scope = "replacement".into();
        f.blobs.activate_scope(f.context().blob_scope()).unwrap();
        let result = collect_recording(&actions, &f).await.unwrap();
        assert_eq!(result["segments"].as_array().unwrap().len(), 2);
        assert_eq!(
            collect_recording(&actions, &f).await.unwrap()["segments"],
            json!([])
        );
    }
    #[tokio::test]
    async fn recording_valid_file_does_not_hide_unproved_capture_cleanup() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        seed_recording(&actions, &f, 1, Some(&[0x1a, 0x45, 0xdf, 0xa3]), true).await;
        actions
            .recording
            .lock()
            .await
            .current
            .as_ref()
            .unwrap()
            .cleanup_complete
            .store(false, Ordering::SeqCst);
        let failure = collect_recording(&actions, &f).await.unwrap_err();
        assert_eq!(failure.error, ProtocolError::CleanupFailed);
        assert!(failure.cleanup_failed);
        assert_eq!(actions.recording.lock().await.finished.len(), 1);
        assert_eq!(
            actions.abandon_recording().await,
            Err(ProtocolError::CleanupFailed)
        );
    }
    #[tokio::test]
    async fn recording_failed_stop_keeps_valid_file_and_reports_missing_once() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        let bytes = [0x1a, 0x45, 0xdf, 0xa3, 1];
        seed_recording(&actions, &f, 1, Some(&bytes), true).await;
        actions
            .recording_page_closing("scope", &f.blobs)
            .await
            .unwrap();
        seed_recording(&actions, &f, 2, None, true).await;
        let missing = collect_recording(&actions, &f).await.unwrap();
        assert_eq!(missing, json!({"identityScope":"scope","missingSegment":2}));
        {
            let ledger = actions.recording.lock().await;
            assert!(!ledger.armed);
            assert!(ledger.current.is_none());
            assert!(!ledger.cleanup_failed);
            assert_eq!(ledger.finished.len(), 1);
            assert!(ledger.finished[0].reservation.is_some());
            assert_eq!(ledger.finished[0].bytes.as_deref(), Some(bytes.as_slice()));
        }
        let result = collect_recording(&actions, &f).await.unwrap();
        assert_eq!(result["segments"].as_array().unwrap().len(), 1);
        assert_eq!(
            result["segments"][0]["startedAt"],
            "2026-10-21T00:00:01.000Z"
        );
        assert_eq!(
            collect_recording(&actions, &f).await.unwrap()["segments"],
            json!([])
        );
    }
    #[tokio::test]
    async fn recording_abandon_joins_and_prevents_late_page_segments() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        seed_recording(&actions, &f, 1, Some(&[0x1a, 0x45, 0xdf, 0xa3]), false).await;
        let path = actions
            .recording
            .lock()
            .await
            .current
            .as_ref()
            .unwrap()
            .directory
            .path
            .clone();
        actions.abandon_recording().await.unwrap();
        assert!(!path.exists());
        actions.recording_page_opened(f.context()).await.unwrap();
        assert!(actions.recording.lock().await.current.is_none());
        assert!(f.log.lock().unwrap().is_empty());
        assert_eq!(
            collect_recording(&actions, &f).await.unwrap()["segments"],
            json!([])
        );
    }
    #[tokio::test]
    async fn recording_failed_first_start_disarms_and_joins_owned_resources() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        seed_recording(&actions, &f, 1, Some(&[0x1a, 0x45, 0xdf, 0xa3]), false).await;
        let path = actions
            .recording
            .lock()
            .await
            .current
            .as_ref()
            .unwrap()
            .directory
            .path
            .clone();
        let d = Dispatch::default();
        let result = actions
            .recording
            .lock()
            .await
            .settle_start(&d, Err(ProtocolError::BrowserFailure))
            .await;
        assert_eq!(result, Err(ProtocolError::BrowserFailure));
        assert!(!actions.recording.lock().await.armed);
        assert!(actions.recording.lock().await.current.is_none());
        assert!(!path.exists());
        actions.recording_page_opened(f.context()).await.unwrap();
        assert_eq!(
            collect_recording(&actions, &f).await.unwrap()["segments"],
            json!([])
        );
        assert!(f.log.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn recording_unarmed_page_hooks_and_stop_are_resource_free_noops() {
        let mut f = fixture("normal").await;
        // Geometry setup already exercised this same peer. Its receipt makes
        // the subsequent complete empty request log a non-vacuous assertion.
        assert!(f.replies.lock().unwrap().iter().any(|entry| {
            entry["request"]["method"] == "Page.getLayoutMetrics"
                && entry["request"]["sessionId"] == "page"
                && entry["reply"]["id"] == entry["request"]["id"]
                && entry["reply"]["result"]["cssLayoutViewport"]["clientWidth"].as_f64()
                    == Some(100.0)
        }));
        let setup_replies = f.replies.lock().unwrap().len();
        f.blobs = BlobStore::new(BlobLimits {
            max_blob_bytes: 4096,
            max_total_bytes: 4096,
            max_handles: 1,
        })
        .unwrap();
        f.blobs.activate_scope(f.context().blob_scope()).unwrap();
        enroll_recording_fixture(&f.page).await;
        let owner = client_debt::OwnerDebtLedger::new(1, "scope".into());
        f.page.client.install_debt_ledger(owner.clone()).unwrap();
        f.page.client = f.page.client.owner_view(owner.clone()).unwrap();
        let journal = owner
            .operation(
                client_debt::OperationKey {
                    generation: 1,
                    operation_seq: 1,
                },
                "target".into(),
                "page".into(),
            )
            .unwrap();
        journal.bind_operation(&f.op).unwrap();
        let actions = ClientActions::default();
        assert!(!actions.is_recording_armed().await.unwrap());
        assert!(f.log.lock().unwrap().is_empty());
        let initial_owner = owner.snapshot();
        assert_eq!(initial_owner.outstanding_commands, 0);
        assert_eq!(initial_owner.input_debt, 0);
        assert_eq!(initial_owner.object_debt, 0);
        assert!(!initial_owner.integrity_lost);
        let initial_operation = journal.snapshot();
        assert!(!initial_operation.mutation_dispatched);
        // Do not seed or arm a recording. Check each real boundary separately,
        // so a later stop cannot hide resources or state created by either hook.
        for hook in ["pageOpened", "pageClosing", "recording.stop"] {
            f.context().check().unwrap();
            match hook {
                "pageOpened" => journal
                    .scope(actions.recording_page_opened(f.context()))
                    .await
                    .unwrap(),
                "pageClosing" => journal
                    .scope(actions.recording_page_closing("scope", &f.blobs))
                    .await
                    .unwrap(),
                "recording.stop" => assert_eq!(
                    journal
                        .scope(collect_recording(&actions, &f))
                        .await
                        .unwrap(),
                    json!({"identityScope":"scope","segments":[]})
                ),
                _ => unreachable!(),
            }
            // The complete request log excludes initial capture, attachment,
            // screencast start/stop, and frame ACKs, not just returned segments.
            assert!(f.log.lock().unwrap().is_empty(), "after {hook}");
            assert_eq!(
                f.replies.lock().unwrap().len(),
                setup_replies,
                "after {hook}"
            );
            assert_eq!(f.page.client.pending_len().await, 0, "after {hook}");
            assert_eq!(owner.snapshot(), initial_owner, "after {hook}");
            assert_eq!(journal.snapshot(), initial_operation, "after {hook}");
            assert!(!actions.is_recording_armed().await.unwrap());
            {
                let ledger = actions.recording.lock().await;
                assert!(ledger.authority.is_none());
                assert!(ledger.options.is_none());
                assert!(ledger.current.is_none());
                assert!(ledger.finished.is_empty());
                assert!(!ledger.armed);
                assert!(!ledger.abandoned);
                assert_eq!(ledger.ordinal, 0);
                assert!(ledger.lost.is_none());
                assert!(!ledger.cleanup_failed);
                assert!(!ledger.filesystem_cleanup_failed);
            }
            assert!(f.page.targets.auxiliary_cleanup_complete().unwrap());
            // A single full-budget handle exposes any retained reservation/blob.
            drop(f.blobs.reserve_producer(f.context().blob_scope()).unwrap());
            f.blobs.check_budget_integrity().unwrap();
        }
    }
    #[tokio::test]
    async fn recording_first_start_failure_dispatch_disarms_without_stop_or_late_segment() {
        let mut f = fixture("recording-first-start-error-ack").await;
        // One full-budget handle makes any retained blob or reservation visible.
        f.blobs = BlobStore::new(BlobLimits {
            max_blob_bytes: 4096,
            max_total_bytes: 4096,
            max_handles: 1,
        })
        .unwrap();
        f.blobs.activate_scope(f.context().blob_scope()).unwrap();
        enroll_recording_fixture(&f.page).await;
        let owner = client_debt::OwnerDebtLedger::new(1, "scope".into());
        f.page.client.install_debt_ledger(owner.clone()).unwrap();
        f.page.client = f.page.client.owner_view(owner.clone()).unwrap();
        let journal = owner
            .operation(
                client_debt::OperationKey {
                    generation: 1,
                    operation_seq: 1,
                },
                "target".into(),
                "page".into(),
            )
            .unwrap();
        journal.bind_operation(&f.op).unwrap();
        let actions = ClientActions::default();
        assert!(actions.recording.lock().await.authority.is_none());
        assert!(!actions.is_recording_armed().await.unwrap());
        // No size: the real dispatch must reach begin_segment's read-only CDP
        // probe before ffmpeg, filesystem output, or capture ownership exists.
        let failure = journal
            .scope(actions.execute(
                f.context(),
                "recording.start",
                &json!({"identityScope":f.page.identity_scope}),
            ))
            .await
            .unwrap_err();
        assert_eq!(failure.error, ProtocolError::BrowserFailure);
        assert_eq!(failure.effects, Effects::NotDispatched);
        assert!(!failure.cleanup_failed);
        assert_eq!(failure.reason, None);
        assert!(!journal.snapshot().mutation_dispatched);
        let requests = f.log.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["method"], "Page.getLayoutMetrics");
        assert_eq!(requests[0]["sessionId"], "page");
        assert_eq!(requests[0]["params"], json!({}));
        assert!(f.replies.lock().unwrap().iter().any(|entry| {
            entry["request"] == requests[0]
                && entry["reply"]
                    == json!({"id":requests[0]["id"],"sessionId":"page",
                        "error":{"code":-32000,"message":"synthetic recording startup failure"}})
        }));
        // The real reader acknowledged the error. NotDispatched means no
        // mutation, not no request, nor an unacknowledged command being forgiven.
        assert_eq!(f.page.client.pending_len().await, 0);
        let settled = owner.snapshot();
        assert_eq!(settled.outstanding_commands, 0);
        assert_eq!(settled.input_debt, 0);
        assert_eq!(settled.object_debt, 0);
        assert!(!settled.integrity_lost);
        {
            let ledger = actions.recording.lock().await;
            assert!(!ledger.armed);
            assert!(ledger.current.is_none());
            assert!(ledger.finished.is_empty());
            assert_eq!(ledger.ordinal, 0);
            assert!(ledger.lost.is_none());
            assert!(!ledger.cleanup_failed);
            assert!(!ledger.filesystem_cleanup_failed);
            // Lightweight attempt authority/options are not segment ownership.
            assert!(ledger.authority.is_some());
        }
        assert!(f.page.targets.auxiliary_cleanup_complete().unwrap());
        drop(f.blobs.reserve_producer(f.context().blob_scope()).unwrap());
        actions.recording_page_opened(f.context()).await.unwrap();
        assert_eq!(*f.log.lock().unwrap(), requests);
        assert_eq!(
            collect_recording(&actions, &f).await.unwrap(),
            json!({"identityScope":"scope","segments":[]})
        );
        // Neither failed-start cleanup, the late hook, nor explicit collection
        // may start or stop a capture that never existed.
        assert_eq!(*f.log.lock().unwrap(), requests);
        assert!(!actions.is_recording_armed().await.unwrap());
        assert!(actions.recording.lock().await.current.is_none());
        assert!(actions.recording.lock().await.finished.is_empty());
        assert!(f.page.targets.auxiliary_cleanup_complete().unwrap());
        assert_eq!(f.page.client.pending_len().await, 0);
        assert_eq!(owner.snapshot(), settled);
        drop(f.blobs.reserve_producer(f.context().blob_scope()).unwrap());
        f.blobs.check_budget_integrity().unwrap();
    }
    async fn enroll_recording_fixture(page: &BrowserExecutionLease) {
        page.targets
            .attached(
                &page.targets.context_id,
                page.target_id.clone(),
                page.page_session_id.clone(),
                "page".into(),
            )
            .unwrap();
        page.targets.configured(&page.target_id).unwrap();
        page.targets
            .resume_permit(&page.target_id)
            .await
            .unwrap()
            .complete()
            .unwrap();
        page.targets.acknowledge_enrollment().unwrap();
    }
    #[test]
    fn recording_start_preflight_reuses_strict_shape_scope_size_quality_validation() {
        for args in [
            json!({"identityScope":"scope"}),
            json!({"identityScope":"scope", "size":{"width":320,"height":200},"quality":70}),
            json!({"identityScope":"scope", "quality":0}),
            json!({"identityScope":"scope", "quality":100}),
        ] {
            assert_eq!(
                ClientActions::validate_recording_start("scope", &args),
                Ok(())
            );
        }
        assert_eq!(
            ClientActions::validate_recording_start("scope", &json!({"identityScope":"other"})),
            Err(ProtocolError::StaleScope)
        );
        for args in [
            Value::Null,
            json!([]),
            json!({}),
            json!({"identityScope":3}),
            json!({"identityScope":"scope","unknown":true}),
            json!({"identityScope":"scope","size":{"width":320}}),
            json!({"identityScope":"scope","size":{"width":320,"height":200,"unknown":0}}),
            json!({"identityScope":"scope","size":{"width":0,"height":200}}),
            json!({"identityScope":"scope","size":{"width":16385,"height":1}}),
            json!({"identityScope":"scope","size":{"width":10000,"height":10000}}),
            json!({"identityScope":"scope","size":{"width":-1,"height":200}}),
            json!({"identityScope":"scope","quality":101}),
            json!({"identityScope":"scope","quality":256}),
            json!({"identityScope":"scope","quality":-1}),
            json!({"identityScope":"scope","quality":70.5}),
            json!({"identityScope":"scope","quality":"70"}),
        ] {
            assert_eq!(
                ClientActions::validate_recording_start("scope", &args),
                Err(ProtocolError::InvalidArguments),
                "{args}"
            );
        }
    }
    fn terminal_recording_proof(
        f: &Fixture,
    ) -> Result<
        (
            super::super::client_enrollment::NativeTerminalProof,
            Arc<super::super::client_network::ClientNetwork>,
        ),
        ProtocolError,
    > {
        use super::super::{
            client_enrollment::NativeTerminalProof,
            client_network::{ClientNetwork, NetworkPolicy},
            client_session::ClientSession,
            client_transport::ClientEventSink,
            client_ui::UiGate,
        };
        let broker = Arc::new(ClientSession::new());
        let (sink, _notices) = ClientEventSink::test_channel(broker.clone());
        let blobs = Arc::new(BlobStore::new(BlobLimits::default()).unwrap());
        let network = Arc::new(ClientNetwork::new(
            f.page.client.clone(),
            broker,
            sink,
            f.context().blob_scope(),
            blobs,
            Arc::new(UiGate::default()),
            NetworkPolicy::default(),
        ));
        let proof = NativeTerminalProof::for_test(
            f.page.client.clone(),
            f.page.targets.clone(),
            &network,
            1,
            "target".into(),
        )?;
        Ok((proof, network))
    }
    async fn seed_terminal_recording(actions: &ClientActions, f: &Fixture) {
        enroll_recording_fixture(&f.page).await;
        seed_recording(actions, f, 1, Some(&[0x1a, 0x45, 0xdf, 0xa3]), false).await;
        let mut reservation = f
            .page
            .targets
            .reserve_auxiliary_attachment("scope", "target", "page")
            .unwrap();
        reservation.claim("recorder").unwrap();
        let mut ledger = actions.recording.lock().await;
        let owned = ledger.current.as_mut().unwrap();
        owned.cleanup_complete.store(false, Ordering::SeqCst);
        owned.attachment = Some(RecordingAttachment {
            client: f.page.client.clone(),
            reservation,
            startup: None,
            session: Some("recorder".into()),
            detached: Arc::new(AtomicBool::new(false)),
            acknowledged_cleanup: HashSet::new(),
            terminal_complete: false,
            cleanup_failed: false,
        });
    }
    async fn disconnect_recording_fixture(f: &Fixture) {
        let mut closed = f.page.client.remote_connection_closed();
        f.server.abort();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !*closed.borrow_and_update() {
                closed.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn ci18_recording_capture_pressure_after_real_finish_and_scope_rotation() {
        use super::super::client_blobs::BlobError;

        // Exercise both ordinary close and exact terminal settlement. These are
        // synthetic bytes accepted by read_recording, not playable-video proof.
        for terminal in [false, true] {
            let mut f = fixture("normal").await;
            let actions = ClientActions::default();
            let bytes = [0x1a, 0x45, 0xdf, 0xa3];
            assert_eq!(f.blobs.producer_limit(), 64 * 1024 * 1024);
            if terminal {
                seed_terminal_recording(&actions, &f).await;
                disconnect_recording_fixture(&f).await;
                actions
                    .settle_terminal_recording(
                        &f.page.client,
                        &terminal_recording_proof(&f).unwrap().0,
                    )
                    .await
                    .unwrap();
            } else {
                seed_recording(&actions, &f, 1, Some(&bytes), false).await;
            }
            let old = f.context().blob_scope();
            // Before rotation one recording and one capture fit exactly. No
            // response blob or borrowed response is involved in this regression.
            drop(f.blobs.reserve_producer(old.clone()).unwrap());
            actions
                .recording_page_closing(&old.identity_scope, &f.blobs)
                .await
                .unwrap();
            {
                let ledger = actions.recording.lock().await;
                assert!(ledger.current.is_none());
                assert!(ledger.lost.is_none());
                assert!(!ledger.cleanup_failed);
                assert_eq!(ledger.finished.len(), 1);
                assert_eq!(ledger.finished[0].bytes.as_deref(), Some(bytes.as_slice()));
                assert!(ledger.finished[0].reservation.is_some());
                assert!(ledger.finished[0].directory.path.exists());
            }
            f.blobs.revoke_scope(&old).unwrap();
            f.page.identity_scope = "replacement".into();
            let next = f.context().blob_scope();
            f.blobs.activate_scope(next.clone()).unwrap();
            assert!(matches!(
                f.blobs.reserve_producer(old),
                Err(BlobError::StaleScope)
            ));
            // The existing fixture reserves through the same reserve_artifact
            // path as begin_segment. It does not execute ffmpeg/page-open CDP.
            // Admission proves finish_current shrank the old 64 MiB charge.
            seed_recording(&actions, &f, 2, Some(&bytes), false).await;
            assert!(matches!(
                f.blobs.try_reserve_producer(next.clone()),
                Err(BlobError::QuotaExceeded)
            ));
            // Protected capture owns its existing 32 MiB encoded-output ceiling,
            // not the generic 64 MiB producer maximum. Neither video is lost.
            let capture = f
                .blobs
                .reserve_bounded_producer(next.clone(), super::super::client_capture::MAX_PNG_BYTES)
                .unwrap();
            let image = f
                .blobs
                .finish_producer(capture, b"synthetic protected image".to_vec())
                .unwrap();
            f.blobs.release(&next, &image.handle).unwrap();
            {
                let ledger = actions.recording.lock().await;
                assert!(ledger.current.as_ref().unwrap().reservation.is_some());
                assert_eq!(ledger.finished[0].bytes.as_deref(), Some(bytes.as_slice()));
                assert!(ledger.lost.is_none());
            }
            // Finishing the second segment, without deleting either segment,
            // removes fixed pressure. Both retained byte charges still survive.
            actions
                .recording_page_closing(&next.identity_scope, &f.blobs)
                .await
                .unwrap();
            drop(f.blobs.reserve_producer(next.clone()).unwrap());
            {
                let ledger = actions.recording.lock().await;
                assert_eq!(ledger.finished.len(), 2);
                for segment in &ledger.finished {
                    assert_eq!(segment.bytes.as_deref(), Some(bytes.as_slice()));
                    assert!(segment.reservation.is_some());
                    assert!(segment.directory.path.exists());
                }
                assert!(ledger.lost.is_none());
            }
            actions.abandon_recording().await.unwrap();
            // Exact teardown frees both artifact charges, not just handles.
            let first = f.blobs.reserve_producer(next.clone()).unwrap();
            let second = f.blobs.reserve_producer(next).unwrap();
            drop((first, second));
            f.blobs.check_budget_integrity().unwrap();
        }
    }
    #[tokio::test]
    async fn terminal_recording_missing_file_retains_attempt_and_failed_start_ownership() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        seed_terminal_recording(&actions, &f).await;
        disconnect_recording_fixture(&f).await;
        {
            let mut ledger = actions.recording.lock().await;
            let owned = ledger.current.as_mut().unwrap();
            std::fs::remove_file(&owned.state.output_path).unwrap();
            owned.state.encoder_complete.store(false, Ordering::SeqCst);
            assert_eq!(
                ledger.finish_current(&f.blobs).await,
                Err(ProtocolError::CleanupFailed)
            );
            assert_eq!(
                ledger.discard_current().await,
                Err(ProtocolError::CleanupFailed)
            );
            assert!(ledger.current.as_ref().unwrap().reservation.is_some());
            assert!(ledger.current.as_ref().unwrap().directory.path.exists());
        }
        assert_eq!(
            actions
                .settle_terminal_recording(&f.page.client, &terminal_recording_proof(&f).unwrap().0)
                .await,
            Err(ProtocolError::CleanupFailed)
        );
        assert!(actions.recording.lock().await.current.is_some());
    }
    #[tokio::test]
    async fn terminal_recording_refuses_live_or_different_native_connection() {
        let f = fixture("normal").await;
        let other = fixture("normal").await;
        let actions = ClientActions::default();
        seed_terminal_recording(&actions, &f).await;
        assert!(matches!(
            terminal_recording_proof(&f),
            Err(ProtocolError::StaleScope)
        ));
        disconnect_recording_fixture(&other).await;
        // Foreign proof is rejected by the scope-authority layer before any
        // recording cleanup. A valid proof for another attachment below is
        // instead a recording cleanup ownership failure.
        assert_eq!(
            actions
                .settle_terminal_recording(
                    &f.page.client,
                    &terminal_recording_proof(&other).unwrap().0
                )
                .await,
            Err(ProtocolError::StaleScope)
        );
        assert_eq!(
            actions
                .settle_terminal_recording(
                    &other.page.client,
                    &terminal_recording_proof(&other).unwrap().0
                )
                .await,
            Err(ProtocolError::CleanupFailed)
        );
        let ledger = actions.recording.lock().await;
        assert!(ledger
            .current
            .as_ref()
            .unwrap()
            .state
            .capture_task
            .is_some());
        assert!(f.log.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn terminal_before_and_after_stop_retains_file_and_does_not_forge_detach_ack() {
        for after_stop in [false, true] {
            let f = fixture("normal").await;
            let actions = ClientActions::default();
            seed_terminal_recording(&actions, &f).await;
            disconnect_recording_fixture(&f).await;
            if after_stop {
                let mut ledger = actions.recording.lock().await;
                ledger.finish_current(&f.blobs).await.unwrap();
                assert!(ledger.cleanup_failed);
                assert_eq!(ledger.finished.len(), 1);
            }
            actions
                .settle_terminal_recording(&f.page.client, &terminal_recording_proof(&f).unwrap().0)
                .await
                .unwrap();
            let ledger = actions.recording.lock().await;
            let owned = ledger
                .current
                .as_ref()
                .unwrap_or_else(|| &ledger.finished[0]);
            assert!(owned.directory.path.exists());
            assert!(owned.reservation.is_some());
            assert!(owned.state.capture_task.is_none());
            assert!(owned.cleanup_complete.load(Ordering::SeqCst));
            let attachment = owned.attachment.as_ref().unwrap();
            assert!(!attachment.detached.load(Ordering::SeqCst));
            assert!(attachment.acknowledged_cleanup.is_empty());
            assert!(f.log.lock().unwrap().is_empty());
        }
    }
    #[tokio::test]
    async fn terminal_recording_cancel_retains_capture_attach_read_and_encoder_proof() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        seed_terminal_recording(&actions, &f).await;
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let (attach_release, attach_wait) = tokio::sync::oneshot::channel::<()>();
        let (read_release, read_wait) = tokio::sync::oneshot::channel::<()>();
        {
            let mut ledger = actions.recording.lock().await;
            let owned = ledger.current.as_mut().unwrap();
            recording::stop_recording_task(&mut owned.state)
                .await
                .unwrap();
            owned.state.encoder_complete.store(false, Ordering::SeqCst);
            owned.state.capture_task = Some(tokio::spawn(async move {
                let _ = wait.await;
                Ok(())
            }));
            owned.attachment.as_mut().unwrap().startup = Some(tokio::spawn(async move {
                let _ = attach_wait.await;
                Err("terminal attach".into())
            }));
            owned.read_job = Some(tokio::spawn(async move {
                let _ = read_wait.await;
                Ok(vec![0x1a, 0x45, 0xdf, 0xa3])
            }));
        }
        disconnect_recording_fixture(&f).await;
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            actions.settle_terminal_recording(
                &f.page.client,
                &terminal_recording_proof(&f).unwrap().0
            )
        )
        .await
        .is_err());
        {
            let ledger = actions.recording.lock().await;
            let owned = ledger.current.as_ref().unwrap();
            assert!(owned.state.capture_task.is_some());
            assert!(owned.attachment.as_ref().unwrap().startup.is_some());
            assert!(owned.read_job.is_some());
            assert!(owned.directory.path.exists());
        }
        release.send(()).unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            actions.settle_terminal_recording(
                &f.page.client,
                &terminal_recording_proof(&f).unwrap().0
            )
        )
        .await
        .is_err());
        attach_release.send(()).unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            actions.settle_terminal_recording(
                &f.page.client,
                &terminal_recording_proof(&f).unwrap().0
            )
        )
        .await
        .is_err());
        assert!(actions
            .recording
            .lock()
            .await
            .current
            .as_ref()
            .unwrap()
            .read_job
            .is_some());
        read_release.send(()).unwrap();
        // A valid file and joined synthetic task cannot substitute for child wait.
        assert_eq!(
            actions
                .settle_terminal_recording(&f.page.client, &terminal_recording_proof(&f).unwrap().0)
                .await,
            Err(ProtocolError::CleanupFailed)
        );
        let ledger = actions.recording.lock().await;
        let owned = ledger.current.as_ref().unwrap();
        assert!(owned.bytes.is_some());
        assert!(!owned.cleanup_complete.load(Ordering::SeqCst));
        assert!(owned.reservation.is_some());
    }
    #[tokio::test]
    async fn recorder_cancelled_attach_retains_ack_and_detaches_exact_session() {
        let f = fixture("normal").await;
        enroll_recording_fixture(&f.page).await;
        let reservation = f
            .page
            .targets
            .reserve_auxiliary_attachment("scope", "target", "page")
            .unwrap();
        let (release, wait) = tokio::sync::oneshot::channel();
        let mut attachment = RecordingAttachment {
            client: f.page.client.clone(),
            reservation,
            startup: Some(tokio::spawn(async move {
                let _ = wait.await;
                Ok("recorder".to_owned())
            })),
            session: None,
            detached: Arc::new(AtomicBool::new(false)),
            acknowledged_cleanup: HashSet::new(),
            terminal_complete: false,
            cleanup_failed: false,
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(10), attachment.settle())
                .await
                .is_err()
        );
        assert!(attachment.startup.is_some());
        release.send(()).unwrap();
        assert!(attachment.settle().await);
        assert!(attachment.startup.is_none());
        let calls = f.log.lock().unwrap().clone();
        let detaches = calls
            .iter()
            .filter(|v| v["method"] == "Target.detachFromTarget")
            .collect::<Vec<_>>();
        assert_eq!(detaches.len(), 1);
        assert_eq!(detaches[0]["params"]["sessionId"], "recorder");
        assert!(f.page.targets.protected_read_barrier().is_err()); // quarantine remains
    }
    #[tokio::test]
    async fn recorder_unknown_attach_is_not_cleaned_by_empty_candidate_list() {
        let f = fixture("normal").await;
        enroll_recording_fixture(&f.page).await;
        let reservation = f
            .page
            .targets
            .reserve_auxiliary_attachment("scope", "target", "page")
            .unwrap();
        let mut attachment = RecordingAttachment {
            client: f.page.client.clone(),
            reservation,
            startup: Some(tokio::spawn(async {
                Err("synthetic unknown ACK".to_owned())
            })),
            session: None,
            detached: Arc::new(AtomicBool::new(false)),
            acknowledged_cleanup: HashSet::new(),
            terminal_complete: false,
            cleanup_failed: false,
        };
        assert!(!attachment.settle().await);
        assert!(attachment.startup.is_none());
        assert!(!attachment.settle().await); // terminal handle was consumed, not polled twice
        assert!(f.log.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn recorder_settlement_drains_owned_candidates_before_completing_exact_ack() {
        let f = fixture("normal").await;
        enroll_recording_fixture(&f.page).await;
        let mut reservation = f
            .page
            .targets
            .reserve_auxiliary_attachment("scope", "target", "page")
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            f.page
                .targets
                .classify_auxiliary_attachment("target", "uncertain")
        )
        .await
        .is_err());
        reservation.quarantine();
        assert!(reservation.claim("recorder").is_err());
        let mut attachment = RecordingAttachment {
            client: f.page.client.clone(),
            reservation,
            startup: None,
            session: Some("recorder".into()),
            detached: Arc::new(AtomicBool::new(true)),
            acknowledged_cleanup: HashSet::new(),
            terminal_complete: false,
            cleanup_failed: false,
        };
        assert!(attachment.settle().await);
        assert!(attachment.settle().await);
        let calls = f.log.lock().unwrap().clone();
        let detaches = calls
            .iter()
            .filter(|v| v["method"] == "Target.detachFromTarget")
            .collect::<Vec<_>>();
        assert_eq!(detaches.len(), 1);
        assert_eq!(detaches[0]["params"]["sessionId"], "uncertain");
        assert!(f.page.targets.protected_read_barrier().is_err());
    }
    #[tokio::test]
    async fn recorder_detach_ack_settles_reservation_without_touching_primary() {
        let f = fixture("normal").await;
        enroll_recording_fixture(&f.page).await;
        let mut reservation = f
            .page
            .targets
            .reserve_auxiliary_attachment("scope", "target", "page")
            .unwrap();
        reservation.claim("recorder").unwrap();
        let mut attachment = RecordingAttachment {
            client: f.page.client.clone(),
            reservation,
            startup: None,
            session: Some("recorder".into()),
            detached: Arc::new(AtomicBool::new(true)),
            acknowledged_cleanup: HashSet::new(),
            terminal_complete: false,
            cleanup_failed: false,
        };
        assert!(attachment.settle().await);
        assert!(f.log.lock().unwrap().is_empty());
        assert!(f.page.targets.protected_read_barrier().is_ok());
    }
    #[tokio::test]
    async fn recording_cancelled_close_retains_join_and_artifact_ownership() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        seed_recording(&actions, &f, 1, Some(&[0x1a, 0x45, 0xdf, 0xa3]), false).await;
        let (release, wait) = tokio::sync::oneshot::channel();
        actions
            .recording
            .lock()
            .await
            .current
            .as_mut()
            .unwrap()
            .state
            .capture_task = Some(tokio::spawn(async move {
            let _ = wait.await;
            Ok(())
        }));
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            actions.recording_page_closing("scope", &f.blobs)
        )
        .await
        .is_err());
        assert!(actions
            .recording
            .lock()
            .await
            .current
            .as_ref()
            .unwrap()
            .state
            .capture_task
            .is_some());
        release.send(()).unwrap();
        actions
            .recording_page_closing("scope", &f.blobs)
            .await
            .unwrap();
        assert_eq!(actions.recording.lock().await.finished.len(), 1);
        actions.abandon_recording().await.unwrap();
    }
    #[tokio::test]
    async fn retired_realm_does_not_erase_failed_exception_handle_cleanup() {
        let f = fixture("check-aux-cleanup-failed").await;
        let node = Resolved {
            realm: None,
            object: "exact-node".into(),
            session: "page".into(),
            binding: f.refs.get("e1").unwrap().exact_binding.clone().unwrap(),
        };
        let d = Dispatch::default();
        let primary = node
            .call(&f.context(), &d, false, CHECKED_STATE, vec![])
            .await;
        assert_eq!(primary, Err(ProtocolError::BrowserFailure));
        assert!(d.cleanup.load(Ordering::SeqCst));
        // Even a subsequently established retirement proof cannot settle this
        // independently failed auxiliary handle by implication.
        assert!(!checked_navigation_recovery_allowed(&d, true));
        assert!(d.failure(ProtocolError::BrowserFailure).cleanup_failed);
    }
    #[tokio::test]
    async fn immediate_click_replacement_preserves_original_success_semantics() {
        let f = fixture("check-immediate-replacement").await;
        let node = Resolved {
            realm: None,
            object: "exact-node".into(),
            session: "page".into(),
            binding: f.refs.get("e1").unwrap().exact_binding.clone().unwrap(),
        };
        let d = Dispatch::default();
        set_checked(&f.context(), &d, &node, true).await.unwrap();
        assert!(d.sent.load(Ordering::SeqCst));
        assert!(!d.checked_replaced.load(Ordering::SeqCst));
    }
    #[test]
    fn checked_poll_admission_reserves_completed_read_latency_without_extending_deadline() {
        let now = Instant::now();
        let deadline = now + Duration::from_millis(35);
        assert!(!checked_poll_fits(
            now,
            deadline,
            Duration::from_millis(20),
            Duration::from_millis(25)
        ));
        assert!(checked_poll_fits(
            now,
            deadline,
            Duration::from_millis(20),
            Duration::from_millis(10)
        ));
        assert!(!checked_poll_fits(
            deadline,
            deadline,
            Duration::ZERO,
            Duration::ZERO
        ));
        let d = Dispatch::default();
        d.mark();
        let failure = d.failure(ProtocolError::DeadlineExceeded);
        assert_eq!(failure.effects, Effects::Unknown);
        assert_eq!(failure.reason, None);
        assert_eq!(checked_unchanged(&d), Err(ProtocolError::NotActionable));
        assert_eq!(
            d.failure(ProtocolError::NotActionable).effects,
            Effects::Completed
        );
    }
    #[tokio::test]
    async fn checked_postconditions_distinguish_replacement_from_unchanged() {
        for (mode, reason) in [
            ("check-replaced", ActionReason::ControlReplacedAfterClick),
            ("check-unchanged", ActionReason::CheckedStateUnchanged),
        ] {
            let mut f = fixture(mode).await;
            f.op.deadline = Instant::now() + Duration::from_millis(350);
            let node = Resolved {
                realm: None,
                object: "exact-node".into(),
                session: "page".into(),
                binding: f.refs.get("e1").unwrap().exact_binding.clone().unwrap(),
            };
            let d = Dispatch::default();
            let error = set_checked(&f.context(), &d, &node, true)
                .await
                .unwrap_err();
            let failure = d.failure(error);
            assert_eq!(failure.error, ProtocolError::NotActionable);
            assert_eq!(failure.reason, Some(reason));
            assert_eq!(failure.effects, Effects::Completed);
            d.cleanup.store(true, Ordering::SeqCst);
            assert_eq!(
                d.failure(ProtocolError::NotActionable).effects,
                Effects::Unknown
            );
            assert_eq!(
                f.inputs()
                    .iter()
                    .filter(|v| v["params"]["type"] == "mouseReleased")
                    .count(),
                1
            );
        }
    }
    #[tokio::test]
    async fn checked_inflight_postcondition_timeout_keeps_unknown_outcome() {
        let mut f = fixture("check-read-stalled").await;
        f.op.deadline = Instant::now() + Duration::from_millis(350);
        let node = Resolved {
            realm: None,
            object: "exact-node".into(),
            session: "page".into(),
            binding: f.refs.get("e1").unwrap().exact_binding.clone().unwrap(),
        };
        let d = Dispatch::default();
        let error = set_checked(&f.context(), &d, &node, true)
            .await
            .unwrap_err();
        assert_eq!(error, ProtocolError::DeadlineExceeded);
        let failure = d.failure(error);
        assert_eq!(failure.effects, Effects::Unknown);
        assert_eq!(failure.reason, None);
        assert_eq!(
            f.inputs()
                .iter()
                .filter(|request| request["params"]["type"] == "mouseReleased")
                .count(),
            1
        );
    }
    #[tokio::test]
    async fn document_action_target_revalidates_after_releasing_original_handle() {
        for (mode, expected, acquired) in [
            ("target-revalidation-stale", ProtocolError::StaleScope, true),
            (
                "target-revalidation-empty",
                ProtocolError::StaleScope,
                false,
            ),
            (
                "target-revalidation-cancelled",
                ProtocolError::Cancelled,
                true,
            ),
        ] {
            let f = fixture(mode).await;
            let d = Dispatch::default();
            let reference = NodeReference {
                id: "@e1".into(),
                revision: "1".into(),
            };
            let error = match action_target(&f.context(), &d, &reference).await {
                Ok(_) => panic!("{mode}: retired target must not escape"),
                Err(error) => error,
            };
            assert_eq!(error, expected, "{mode}");
            assert!(!d.cleanup.load(Ordering::SeqCst), "{mode}");
            let requests = f.log.lock().unwrap();
            let releases: Vec<_> = requests
                .iter()
                .filter(|request| request["method"] == "Runtime.releaseObject")
                .map(|request| request["params"]["objectId"].as_str().unwrap())
                .collect();
            assert_eq!(
                releases,
                if acquired {
                    vec!["exact-node", "document-element"]
                } else {
                    vec!["exact-node"]
                },
                "{mode}"
            );
            assert_eq!(requests.iter().filter(|request|
                request["method"] == "Runtime.callFunctionOn" &&
                request["params"]["functionDeclaration"] ==
                "function(){if(this!==document||!this.isConnected)return null;return this.documentElement;}").count(), 1);
        }
    }
    #[test]
    fn earlier_semantic_reason_cannot_override_a_later_authority_or_cleanup_failure() {
        for reason in 0..3 {
            let d = Dispatch::default();
            d.mark();
            match reason {
                0 => d.intercepted.store(true, Ordering::SeqCst),
                1 => d.checked_unchanged.store(true, Ordering::SeqCst),
                _ => d.checked_replaced.store(true, Ordering::SeqCst),
            }
            assert!(d.failure(ProtocolError::NotActionable).reason.is_some());
            // Retrying preparation retains earlier refusal evidence, but that
            // evidence cannot relabel a different failure on a later attempt.
            d.mark_mutation(true);
            for error in [
                ProtocolError::StaleScope,
                ProtocolError::StaleReference,
                ProtocolError::Cancelled,
                ProtocolError::DeadlineExceeded,
                ProtocolError::BrowserFailure,
                ProtocolError::CleanupFailed,
            ] {
                let failure = d.failure(error.clone());
                assert_eq!(failure.error, error);
                assert_eq!(failure.reason, None);
                assert_eq!(failure.effects, Effects::Unknown);
            }
        }
    }
    #[tokio::test]
    async fn resolved_call_revalidates_after_owned_reply_cleanup_before_semantic_reason() {
        for (mode, expected, cleanup_failed) in [
            ("call-revalidation-stale", ProtocolError::StaleScope, false),
            (
                "call-revalidation-cancelled",
                ProtocolError::Cancelled,
                false,
            ),
            (
                "call-revalidation-cleanup-failed",
                ProtocolError::CleanupFailed,
                true,
            ),
        ] {
            let f = fixture(mode).await;
            let node = Resolved {
                realm: None,
                object: "exact-node".into(),
                session: "page".into(),
                binding: f.refs.get("e1").unwrap().exact_binding.clone().unwrap(),
            };
            let d = Dispatch::default();
            d.mark();
            let result = node
                .call(
                    &f.context(),
                    &d,
                    false,
                    "function(){return 'owned-call-revalidation'}",
                    vec![],
                )
                .await;
            assert_eq!(result, Err(expected.clone()), "{mode}");
            let failure = d.failure(expected);
            assert_eq!(failure.reason, None, "{mode}");
            assert_eq!(failure.effects, Effects::Unknown, "{mode}");
            assert_eq!(failure.cleanup_failed, cleanup_failed, "{mode}");
            let requests = f.log.lock().unwrap();
            let releases: Vec<_> = requests
                .iter()
                .filter(|request| request["method"] == "Runtime.releaseObject")
                .collect();
            assert_eq!(releases.len(), 1, "{mode}");
            assert_eq!(releases[0]["params"]["objectId"], "call-auxiliary");
            assert_eq!(releases[0]["sessionId"], "page");
            assert!(!requests.iter().any(|request| request["method"]
                .as_str()
                .is_some_and(|method| method.starts_with("Input."))));
        }
    }
    #[tokio::test]
    async fn obscured_action_exposes_only_closed_interception_reason() {
        let mut f = fixture("intercepted").await;
        f.op.deadline = Instant::now() + Duration::from_millis(80);
        let error = ClientActions::default().execute(f.context(),"browser.perform",&json!({"identityScope":"scope","ref":{"id":"@e1","revision":"1"},"action":{"kind":"tap"}})).await.unwrap_err();
        assert_eq!(error.error, ProtocolError::NotActionable);
        assert_eq!(error.reason, Some(ActionReason::InterceptedPointer));
        assert!(f.inputs().is_empty());
    }
    #[derive(Debug)]
    struct PreparationSettlementEvidence {
        failure: ActionFailure,
        original_authority: Result<(), ProtocolError>,
        target_revision: Result<(), ProtocolError>,
        before_deadline: bool,
    }

    // These cases deliberately use the real enrolled realm path. The ordinary
    // action peer's UntrackedFixture shortcut cannot certify reusable settlement.
    async fn preparation_settlement_owner(
        f: &Fixture,
        broker: Arc<super::super::client_session::ClientSession>,
    ) -> (
        Arc<super::super::client_enrollment::ClientEnrollment>,
        Arc<ClientPageState>,
        tokio::sync::mpsc::Receiver<super::super::client_protocol::ServerMessage>,
    ) {
        use super::super::{
            client_enrollment::{ClientEnrollment, ScopeConfig, ScopeOwnership},
            client_network::{ClientNetwork, NetworkPolicy},
            client_protocol::{ScopeState, ServerMessage},
            client_transport::ClientEventSink,
            client_ui::UiGate,
        };
        let (sink, notices) = ClientEventSink::test_channel(broker.clone());
        let scoped_sink = sink
            .stage_until_result(&f.op, &f.page.identity_scope)
            .unwrap();
        sink.acknowledge_result_for_test(&ServerMessage::Result {
            id: "preparation-fixture-initialized".into(),
            generation: f.op.generation,
            operation_seq: f.op.sequence,
            ok: true,
            data: Some(json!({"identityScope":f.page.identity_scope})),
            error: None,
            effects: Effects::Completed,
            scope_state: ScopeState::Usable,
            retention: None,
        })
        .unwrap();
        let blobs = Arc::new(BlobStore::new(BlobLimits::default()).unwrap());
        let blob_scope = BlobScope {
            generation: 1,
            identity_scope: f.page.identity_scope.clone(),
        };
        blobs.activate_scope(blob_scope.clone()).unwrap();
        let state = Arc::new(ClientPageState::new(
            f.page.identity_scope.clone(),
            "context".into(),
        ));
        let network = Arc::new(ClientNetwork::new(
            f.page.client.clone(),
            broker,
            scoped_sink,
            blob_scope,
            blobs,
            Arc::new(UiGate::default()),
            NetworkPolicy::default(),
        ));
        let owner = ClientEnrollment::new(
            f.page.client.clone(),
            f.page.targets.clone(),
            state.clone(),
            network,
            f.gate.clone(),
            1,
            "page".into(),
            ScopeConfig::default(),
            ScopeOwnership::IsolatedContext,
            None,
        );
        owner
            .enroll_existing("target", "page", "page", &f.op)
            .await
            .unwrap();
        owner.start(&f.op).await.unwrap();
        let (_, targets) = f.page.targets.inventory().unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].target_id, "target");
        assert_eq!(targets[0].session_id, "page");
        assert_eq!(
            targets[0].purpose,
            Some(super::super::client_targets::TargetPurpose::Application)
        );
        assert!(targets[0].configured && targets[0].resumed);
        assert!(f.page.permit.check().is_ok());
        (owner, state, notices)
    }

    #[tokio::test]
    async fn exact_release_timeout_retains_failure_but_not_a_reusable_debt_receipt() {
        use super::super::client_session::ClientSession;
        let f = fixture_scoped("preparation-release-debt", "release-debt").await;
        let broker = Arc::new(ClientSession::new());
        let (owner, state, _notices) = preparation_settlement_owner(&f, broker).await;
        let ctx = ActionContext {
            realm_authority: ActionRealmAuthority::Enrolled(&owner),
            page_state: &state,
            ..f.context()
        };
        let d = Dispatch::default();
        // Uses the real enrolled resolution and perform cleanup, not a synthetic
        // cleanup flag. Resolved owns the exact realm ticket until perform exits.
        let result = ClientActions::default()
            .execute_inner(
                &ctx,
                &d,
                "browser.perform",
                &json!({
                    "identityScope":"release-debt", "ref":{"id":"@e1","revision":"1"},
                    "action":{"kind":"tap"}
                }),
            )
            .await;
        assert_eq!(result, Err(ProtocolError::CleanupFailed));
        assert!(d.cleanup.load(Ordering::SeqCst));
        assert!(d.failure(ProtocolError::CleanupFailed).cleanup_failed);
        let releases: Vec<Value> = f
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["method"] == "Runtime.releaseObject")
            .cloned()
            .collect();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0]["params"]["objectId"], "exact-node");
        assert_eq!(releases[0]["sessionId"], "page");
        assert!(!f
            .replies
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["request"] == releases[0]));
        assert!(f
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["method"] == "DOM.resolveNode" && r["params"]["executionContextId"] == 1));
        assert_eq!(state.mouse_state().unwrap().buttons, 0);
        assert_eq!(f.inputs().len(), 3);
        assert!(f.inputs().iter().all(|input| f
            .replies
            .lock()
            .unwrap()
            .iter()
            .any(|reply| reply["request"] == *input && reply["reply"].get("error").is_none())));
        // No source-mask holder was ever installed. This is exact object-release
        // debt, not evidence of an unrestored DOM mutation.
        assert!(!f
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["params"]["functionDeclaration"] == "function(){return this.remove()}"));
        let input_count = f.inputs().len();
        f.page
            .client
            .send_command("Browser.getVersion", None, None)
            .await
            .unwrap();
        assert!(f
            .replies
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["request"] == releases[0]));
        assert_eq!(f.inputs().len(), input_count);
        // A late transport ACK cannot clear this already-returned failure, and
        // this test deliberately does not implement a new settlement policy.
        assert!(d.failure(ProtocolError::CleanupFailed).cleanup_failed);
        owner.close().await.unwrap();
    }

    async fn assert_preparation_effect_settlement(mode: &'static str) {
        use super::super::{
            client_protocol::ScopeState, client_session::ClientSession,
            client_tasks::RetainedTasks, client_transport::NativeOutcome,
        };
        let expected_completed = matches!(
            mode,
            "preparation-intercepted" | "preparation-not-actionable"
        );
        let dirty = mode == "preparation-handle-cleanup-failed";
        let expected_reason = matches!(
            mode,
            "preparation-intercepted"
                | "preparation-later-scroll-unacked"
                | "preparation-handle-cleanup-failed"
                | "preparation-slack-exhausted"
                | "preparation-latency-spike"
                | "preparation-estimate-overrun"
        )
        .then_some(ActionReason::InterceptedPointer);
        let expected_primary = match mode {
            "preparation-input-unacked" => ProtocolError::DeadlineExceeded,
            "preparation-authority-lost" => ProtocolError::StaleScope,
            _ => ProtocolError::NotActionable,
        };
        let expected_wire = if expected_reason.is_some() {
            ProtocolError::InterceptedPointer
        } else {
            expected_primary.clone()
        };
        let broker = Arc::new(ClientSession::new());
        let mut f = fixture_scoped(mode, mode).await;
        let (owner, state, _notices) = preparation_settlement_owner(&f, broker.clone()).await;
        // Setup is outside the measured action. This is the actual admitted
        // lease, not a copy with a deadline or cancellation channel rewritten.
        f.op = broker.admit(1, 1, 800).unwrap();
        assert!(broker.start(1, 1).unwrap());
        let original_authority = owner
            .capture_settled_input_authority(&f.page, &f.op)
            .unwrap();
        original_authority.check(&owner, &f.page, &f.op).unwrap();
        let revision = f.page.targets.inventory().unwrap().0;
        assert_eq!(state.held_modifiers().unwrap(), 0);
        assert_eq!(state.mouse_state().unwrap().buttons, 0);
        f.log.lock().unwrap().clear();
        f.replies.lock().unwrap().clear();
        let f = Arc::new(f);
        let evidence = Arc::new(Mutex::new(None));
        let tasks = RetainedTasks::default();
        let captured_targets = f.page.targets.clone();
        let unrelated_targets = ClientTargets::new("other-context".into(), "other-scope".into());
        let action_fixture = f.clone();
        let action_owner = owner.clone();
        let action_state = state.clone();
        let action_evidence = evidence.clone();
        let receive = tasks
            .start(mode.into(), captured_targets.clone(), async move {
                let ctx = ActionContext {
                    realm_authority: ActionRealmAuthority::Enrolled(&action_owner),
                    page_state: &action_state,
                    ..action_fixture.context()
                };
                let failure = ClientActions::default()
                    .execute(
                        ctx,
                        "browser.perform",
                        &json!({"identityScope":mode,"ref":{"id":"@e1","revision":"1"},
                            "action":{"kind":"tap"}}),
                    )
                    .await
                    .expect_err("the exact synthetic action must refuse or remain uncertain");
                // Match ClientBrowser's reason projection, but never manufacture
                // a settled prefix or rewrite the action's effects in this bridge.
                let error = match failure.reason {
                    Some(ActionReason::InterceptedPointer) => ProtocolError::InterceptedPointer,
                    Some(ActionReason::CheckedStateUnchanged) => {
                        ProtocolError::CheckedStateUnchanged
                    }
                    Some(ActionReason::ControlReplacedAfterClick) => {
                        ProtocolError::CheckedControlReplaced
                    }
                    None => failure.error.clone(),
                };
                let outcome = NativeOutcome {
                    result: Err(error),
                    effects: failure.effects,
                    retention: None,
                };
                let cleanup_failed = failure.cleanup_failed;
                *action_evidence.lock().unwrap() = Some(PreparationSettlementEvidence {
                    failure,
                    original_authority: original_authority.check(
                        &action_owner,
                        &action_fixture.page,
                        &action_fixture.op,
                    ),
                    target_revision: action_fixture.page.targets.check_revision(revision),
                    before_deadline: Instant::now() < action_fixture.op.deadline,
                });
                (outcome, cleanup_failed)
            })
            .await
            .unwrap();
        let delivered = receive.await.unwrap();
        // These are the real settlement and next-admission calls, reached even
        // when the desired positive currently returns Unknown. No helper outcome
        // is substituted for the value delivered by retained execution.
        let settled = broker.settle(1, 1, delivered.effects).unwrap();
        let health = broker.health().unwrap();
        let next = broker.admit(1, 2, 1_000);
        let next_error = next.as_ref().err().cloned();
        if next.is_ok() {
            assert!(broker.start(1, 2).unwrap());
            assert_eq!(
                broker.settle(1, 2, Effects::NotDispatched).unwrap(),
                ScopeState::Usable
            );
        }
        let drained = tasks.drain().await;
        let targets_sealed = captured_targets.inventory().is_err();
        let other_usable = unrelated_targets.inventory().is_ok();
        let requests = f.log.lock().unwrap().clone();
        let replies = f.replies.lock().unwrap().clone();
        let evidence = evidence.lock().unwrap().take().unwrap();
        let held_modifiers = state.held_modifiers().unwrap();
        let held_buttons = state.mouse_state().unwrap().buttons;
        // Shut down the enrolled lifecycle task and exact peer before assertions
        // can panic. Missing command ACKs are never supplied during teardown.
        let owner_closed = owner.close().await;
        let mut f = match Arc::try_unwrap(f) {
            Ok(fixture) => fixture,
            Err(_) => panic!("retained execution must release its fixture before peer teardown"),
        };
        f.server.abort();
        let peer_stopped = (&mut f.server).await;

        let method_requests = |method: &str| {
            requests
                .iter()
                .filter(|request| request["method"] == method)
                .collect::<Vec<_>>()
        };
        let acknowledged = |request: &Value| {
            replies.iter().any(|entry| {
                entry["request"]["id"] == request["id"]
                    && entry["reply"].get("result").is_some()
                    && entry["reply"].get("error").is_none()
            })
        };
        let scrolls = method_requests("DOM.scrollIntoViewIfNeeded");
        let inputs = requests
            .iter()
            .filter(|request| {
                request["method"]
                    .as_str()
                    .is_some_and(|method| method.starts_with("Input."))
            })
            .collect::<Vec<_>>();
        let releases = method_requests("Runtime.releaseObject");
        assert!(
            !scrolls.is_empty(),
            "{mode}: preparation must really dispatch"
        );
        assert_eq!(
            releases.len(),
            1,
            "{mode}: exactly the owned node is released"
        );
        assert_eq!(releases[0]["params"]["objectId"], "exact-node");
        assert_eq!(
            acknowledged(releases[0]),
            !dirty,
            "{mode}: cleanup ACK evidence"
        );
        assert!(
            requests
                .iter()
                .filter(|request| request["method"] == "DOM.resolveNode")
                .all(|request| request["params"]["backendNodeId"] == 42
                    && request["params"]["executionContextId"] == 1),
            "{mode}: never re-resolve another identity or bypass enrolled realm"
        );
        assert_eq!(method_requests("DOM.resolveNode").len(), 1);
        match mode {
            "preparation-scroll-unacked" => {
                assert_eq!(scrolls.len(), 1);
                assert!(!acknowledged(scrolls[0]));
            }
            "preparation-later-scroll-unacked" => {
                assert_eq!(scrolls.len(), 2);
                assert!(acknowledged(scrolls[0]));
                assert!(
                    !acknowledged(scrolls[1]),
                    "an earlier receipt cannot cover a later scroll"
                );
            }
            _ => assert!(scrolls.iter().all(|request| acknowledged(request))),
        }
        if mode == "preparation-input-unacked" {
            assert_eq!(inputs.len(), 3, "no replay after uncertain release");
            assert_eq!(inputs[0]["params"]["type"], "mouseMoved");
            assert_eq!(inputs[1]["params"]["type"], "mousePressed");
            assert_eq!(inputs[2]["params"]["type"], "mouseReleased");
            assert!(acknowledged(inputs[0]) && acknowledged(inputs[1]));
            assert!(!acknowledged(inputs[2]));
        } else {
            assert!(
                inputs.is_empty(),
                "{mode}: no mouse, keyboard, wheel or other Input request"
            );
        }
        if mode == "preparation-control-unacked" {
            let controls = method_requests("Page.getLayoutMetrics");
            assert_eq!(controls.len(), 1);
            assert!(!acknowledged(controls[0]));
        }
        if dirty {
            assert!(replies
                .iter()
                .any(|entry| entry["request"]["id"] == releases[0]["id"]
                    && entry["reply"].get("error").is_some()));
        }
        assert_eq!(evidence.failure.error, expected_primary, "{mode}");
        assert_eq!(evidence.failure.reason, expected_reason, "{mode}");
        assert_eq!(evidence.failure.cleanup_failed, dirty, "{mode}");
        assert_eq!(
            delivered.result,
            Err(expected_wire),
            "{mode}: preserve primary wire reason"
        );
        assert_eq!(
            targets_sealed, dirty,
            "{mode}: retained cleanup seals only dirty targets"
        );
        assert!(other_usable, "{mode}: unrelated scope remains untouched");
        assert_eq!(held_modifiers, 0, "{mode}");
        assert_eq!(held_buttons, 0, "{mode}");
        assert_eq!(owner_closed, Ok(()), "{mode}: lifecycle task is joined");
        assert!(
            peer_stopped.is_err_and(|error| error.is_cancelled()),
            "{mode}: exact withheld-ACK peer is cancelled and joined"
        );
        assert_eq!(
            drained,
            if dirty {
                Err(ProtocolError::CleanupFailed)
            } else {
                Ok(())
            },
            "{mode}"
        );
        if expected_completed {
            // CI14 established RED on the original deadline-exhausting path.
            // This regression is now mandatory with the preparation receipt.
            // The desired result requires a genuine predeadline classification
            // window AND an original-authority, fully-ACKed preparation receipt.
            // A scroll may run page business logic; Completed is not no effects,
            // action success, rollback, or permission to replay this tap.
            // Separate assertions preserve the conjunction while the closed
            // harness receipt identifies a failing fact by its tracked line.
            assert_eq!(evidence.failure.effects, Effects::Completed, "{mode}");
            assert_eq!(delivered.effects, Effects::Completed, "{mode}");
            assert_eq!(settled, ScopeState::Usable, "{mode}");
            assert_eq!(health, (1, ScopeState::Usable), "{mode}");
            assert_eq!(next_error, None, "{mode}");
            assert_eq!(evidence.original_authority, Ok(()), "{mode}");
            assert_eq!(evidence.target_revision, Ok(()), "{mode}");
            assert!(evidence.before_deadline, "{mode}");
        } else {
            assert_eq!(evidence.failure.effects, Effects::Unknown, "{mode}");
            assert_eq!(delivered.effects, Effects::Unknown, "{mode}");
            assert_eq!(settled, ScopeState::Quarantined, "{mode}");
            assert_eq!(health, (1, ScopeState::Quarantined), "{mode}");
            assert_eq!(next_error, Some(ProtocolError::ScopeUnavailable), "{mode}");
            if mode == "preparation-authority-lost" {
                assert_eq!(evidence.original_authority, Err(ProtocolError::StaleScope));
            }
        }
    }

    #[derive(Clone, Copy)]
    enum ControlledPreparationSchedule {
        InsideWindow,
        BelowFloor,
    }
    impl ControlledPreparationSchedule {
        fn mode(self) -> &'static str {
            match self {
                Self::InsideWindow => "preparation-controlled-inside-window",
                Self::BelowFloor => "preparation-controlled-below-floor",
            }
        }
        fn case_id(self) -> &'static str {
            match self {
                Self::InsideWindow => "preparation-positive-window",
                Self::BelowFloor => "preparation-lower-floor",
            }
        }
    }

    // This is a diagnostic schedule, not a replacement for any of the original
    // eight mandatory cases or six Unknown controls. All action/settlement
    // results still come from the actual execute -> RetainedTasks -> broker path.
    async fn assert_controlled_preparation_schedule(schedule: ControlledPreparationSchedule) {
        use super::super::{
            client_protocol::ScopeState, client_session::ClientSession,
            client_tasks::RetainedTasks, client_transport::NativeOutcome,
        };
        let mode = schedule.mode();
        let positive = matches!(schedule, ControlledPreparationSchedule::InsideWindow);
        let broker = Arc::new(ClientSession::new());
        let mut f = fixture_scoped(mode, mode).await;
        let (owner, state, _notices) = preparation_settlement_owner(&f, broker.clone()).await;
        f.op = broker.admit(1, 1, 800).unwrap();
        assert!(broker.start(1, 1).unwrap());
        let deadline = f.op.deadline;
        let original_authority = Arc::new(
            owner
                .capture_settled_input_authority(&f.page, &f.op)
                .unwrap(),
        );
        let revision = f.page.targets.inventory().unwrap().0;
        let gate = PreparationClassificationBoundary::install(&f, original_authority.clone());
        f.log.lock().unwrap().clear();
        f.replies.lock().unwrap().clear();
        let f = Arc::new(f);
        let evidence = Arc::new(Mutex::new(None));
        let tasks = RetainedTasks::default();
        let captured_targets = f.page.targets.clone();
        let unrelated_targets = ClientTargets::new("other-context".into(), "other-scope".into());
        let action_fixture = f.clone();
        let action_owner = owner.clone();
        let action_state = state.clone();
        let action_evidence = evidence.clone();
        let receive = tasks
            .start(mode.into(), captured_targets.clone(), async move {
                let ctx = ActionContext {
                    realm_authority: ActionRealmAuthority::Enrolled(&action_owner),
                    page_state: &action_state,
                    ..action_fixture.context()
                };
                let result = ClientActions::default()
                    .execute(
                        ctx,
                        "browser.perform",
                        &json!({"identityScope":mode,"ref":{"id":"@e1","revision":"1"},
                            "action":{"kind":"tap"}}),
                    )
                    .await;
                let failure = match result {
                    Err(failure) => failure,
                    // RetainedTasks observes this failure normally. Never print
                    // an unexpected successful payload in diagnostic output.
                    Ok(_) => panic!("controlled preparation unexpectedly succeeded"),
                };
                let error = match failure.reason {
                    Some(ActionReason::InterceptedPointer) => ProtocolError::InterceptedPointer,
                    Some(ActionReason::CheckedStateUnchanged) => {
                        ProtocolError::CheckedStateUnchanged
                    }
                    Some(ActionReason::ControlReplacedAfterClick) => {
                        ProtocolError::CheckedControlReplaced
                    }
                    None => failure.error.clone(),
                };
                let outcome = NativeOutcome {
                    result: Err(error),
                    effects: failure.effects,
                    retention: None,
                };
                let cleanup_failed = failure.cleanup_failed;
                *action_evidence.lock().unwrap() = Some(PreparationSettlementEvidence {
                    failure,
                    original_authority: original_authority.check(
                        &action_owner,
                        &action_fixture.page,
                        &action_fixture.op,
                    ),
                    target_revision: action_fixture.page.targets.check_revision(revision),
                    before_deadline: Instant::now() < deadline,
                });
                (outcome, cleanup_failed)
            })
            .await
            .unwrap();
        let PreparationClassificationBoundary {
            _registration,
            entered,
            release,
            released,
        } = gate;
        let entered = tokio::time::timeout_at(deadline.into(), entered)
            .await
            .ok()
            .and_then(Result::ok);
        // The entered signal is issued only after the real ACKed semantic
        // refusal and geometry revalidation return. Independently witness the
        // exact peer replies before choosing any scheduling delay.
        let entry_requests = f.log.lock().unwrap().clone();
        let entry_replies = f.replies.lock().unwrap().clone();
        let acked = |request: &Value, replies: &[Value]| {
            replies.iter().any(|entry| {
                entry["request"]["id"] == request["id"]
                    && entry["reply"].get("result").is_some()
                    && entry["reply"].get("error").is_none()
            })
        };
        let entry_scrolls = entry_requests
            .iter()
            .filter(|request| request["method"] == "DOM.scrollIntoViewIfNeeded")
            .collect::<Vec<_>>();
        let entry_refusals = entry_replies
            .iter()
            .filter(|entry| {
                entry["request"]["method"] == "Runtime.callFunctionOn"
                    && entry["request"]["params"]["objectId"] == "exact-node"
                    && entry["request"]["params"]["functionDeclaration"]
                        .as_str()
                        .is_some_and(|source| source.contains("const blocker="))
                    && entry["reply"]["result"]["result"]["value"]["status"]
                        == "intercepted-pointer"
                    && entry["reply"].get("error").is_none()
            })
            .count();
        let entry_ack_receipt = entry_scrolls.len() == 1
            && acked(entry_scrolls[0], &entry_replies)
            && entry_refusals == 1
            && entry_requests
                .iter()
                .all(|request| acked(request, &entry_replies));
        let entry_above_upper = entered.is_some_and(|entry| {
            entry.deadline == deadline
                && entry.authority_valid
                && entry.remaining
                    > Duration::from_millis(282).saturating_add(entry.longest_attempt)
        });
        let entry_preconditions = entry_ack_receipt && entry_above_upper;
        if let Some(entry) = entered.filter(|_| entry_preconditions) {
            let target_remaining = if positive {
                // Midpoint of the original window, not a widened interval.
                // Gate residence is deliberately excluded from longest_attempt.
                Duration::from_millis(266) + (Duration::from_millis(16) + entry.longest_attempt) / 2
            } else {
                Duration::from_millis(240)
            };
            tokio::time::sleep_until((deadline - target_remaining).into()).await;
        }
        // A missed entered/ACK/precondition releases promptly, then fails as
        // inconclusive after real cleanup. It is never retried or silently skipped.
        let release_sent = release.send(()).is_ok();
        let released = tokio::time::timeout_at(deadline.into(), released)
            .await
            .ok()
            .and_then(Result::ok);
        let release_preconditions = entered.zip(released).is_some_and(|(entry, receipt)| {
            receipt.release_received
                && receipt.authority_valid
                && if positive {
                    preparation_classification_window(receipt.remaining, entry.longest_attempt)
                } else {
                    // A late wake is not proof of the requested 240ms
                    // schedule. Admit at most 8ms of timer/poll latency;
                    // anything later is explicitly inconclusive, not retried.
                    receipt.remaining >= Duration::from_millis(232)
                        && receipt.remaining <= Duration::from_millis(240)
                        && receipt.remaining < Duration::from_millis(266)
                }
        });
        let schedule_valid = entry_preconditions && release_sent && release_preconditions;
        let delivered = receive.await.unwrap();
        let settled = broker.settle(1, 1, delivered.effects).unwrap();
        let broker_settled_before_deadline = Instant::now() < deadline;
        let health = broker.health().unwrap();
        let next = broker.admit(1, 2, 1_000);
        let next_error = next.as_ref().err().cloned();
        if next.is_ok() {
            assert!(broker.start(1, 2).unwrap());
            assert_eq!(
                broker.settle(1, 2, Effects::NotDispatched).unwrap(),
                ScopeState::Usable
            );
        }
        let drained = tasks.drain().await;
        let retained_drained_before_deadline = Instant::now() < deadline;
        let targets_unsealed = captured_targets.inventory().is_ok();
        let unrelated_usable = unrelated_targets.inventory().is_ok();
        let evidence = evidence.lock().unwrap().take();
        let requests = f.log.lock().unwrap().clone();
        let replies = f.replies.lock().unwrap().clone();
        let no_held_input =
            state.held_modifiers().unwrap() == 0 && state.mouse_state().unwrap().buttons == 0;
        let owner_closed = owner.close().await.is_ok();
        let mut f = match Arc::try_unwrap(f) {
            Ok(fixture) => fixture,
            Err(_) => panic!("controlled retained execution did not release its fixture"),
        };
        f.server.abort();
        let peer_joined = (&mut f.server)
            .await
            .is_err_and(|error| error.is_cancelled());
        drop(_registration);

        let scrolls = requests
            .iter()
            .filter(|request| request["method"] == "DOM.scrollIntoViewIfNeeded")
            .collect::<Vec<_>>();
        let releases = requests
            .iter()
            .filter(|request| request["method"] == "Runtime.releaseObject")
            .collect::<Vec<_>>();
        let resolutions = requests
            .iter()
            .filter(|request| request["method"] == "DOM.resolveNode")
            .collect::<Vec<_>>();
        let inputs = requests
            .iter()
            .filter(|request| {
                request["method"]
                    .as_str()
                    .is_some_and(|method| method.starts_with("Input."))
            })
            .count();
        let exact_release_acked = releases.len() == 1
            && releases[0]["params"]["objectId"] == "exact-node"
            && releases[0]["sessionId"] == "page"
            && acked(releases[0], &replies);
        let exact_resolution = resolutions.len() == 1
            && resolutions[0]["params"]["backendNodeId"] == 42
            && resolutions[0]["params"]["executionContextId"] == 1;
        let scrolls_acked =
            !scrolls.is_empty() && scrolls.iter().all(|request| acked(request, &replies));
        let expected_effects = if positive {
            Effects::Completed
        } else {
            Effects::Unknown
        };
        let expected_state = if positive {
            ScopeState::Usable
        } else {
            ScopeState::Quarantined
        };
        let original_authority_valid = evidence.as_ref().is_some_and(|evidence| {
            // At gate release the original authority must still be valid. If
            // the unfixed lower-floor loop runs to expiry, the final receipt
            // must honestly report expiry rather than manufacture authority.
            evidence.target_revision.is_ok()
                && if evidence.before_deadline {
                    evidence.original_authority.is_ok()
                } else {
                    !positive && evidence.original_authority == Err(ProtocolError::DeadlineExceeded)
                }
        });
        let action_refusal_valid = evidence.as_ref().is_some_and(|evidence| {
            evidence.failure.error == ProtocolError::NotActionable
                && evidence.failure.reason == Some(ActionReason::InterceptedPointer)
                && !evidence.failure.cleanup_failed
                && evidence.failure.effects == expected_effects
        });
        let actual_settlement_valid = delivered.result == Err(ProtocolError::InterceptedPointer)
            && delivered.effects == expected_effects
            && settled == expected_state
            && health == (1, expected_state)
            && next_error
                == if positive {
                    None
                } else {
                    Some(ProtocolError::ScopeUnavailable)
                };
        let clean_retirement = exact_release_acked
            && drained.is_ok()
            && targets_unsealed
            && unrelated_usable
            && no_held_input
            && owner_closed
            && peer_joined;
        let retired_before_deadline = evidence
            .as_ref()
            .is_some_and(|evidence| evidence.before_deadline)
            && broker_settled_before_deadline
            && retained_drained_before_deadline;
        let counts_bounded = scrolls.len() <= 128 && inputs <= 128 && releases.len() <= 128;
        let contract_valid = action_refusal_valid
            && actual_settlement_valid
            && clean_retirement
            && exact_resolution
            && scrolls_acked
            && original_authority_valid
            && inputs == 0
            && counts_bounded;
        let desired_early_retirement = retired_before_deadline && scrolls.len() == 1;
        // One bounded, closed record. Source/harness hashes and exact-name run
        // completion belong to the external diagnostic receipt, not this process.
        // Missing this footer is incomplete, never evidence of pass or expected RED.
        eprintln!(
            "native-preparation-controlled {}",
            json!({
                "schema": 1,
                "case": schedule.case_id(),
                "status": if !schedule_valid || !counts_bounded { "incomplete" }
                    else if contract_valid && desired_early_retirement { "pass" } else { "fail" },
                "entry_ack": entry_ack_receipt,
                "entry_above_upper": entry_above_upper,
                "release_valid": release_preconditions,
                "entry_remaining_ms": entered.map(|entry| entry.remaining.as_millis().min(800) as u64),
                "longest_attempt_ms": entered.map(|entry| entry.longest_attempt.as_millis().min(800) as u64),
                "release_remaining_ms": released.map(|receipt| receipt.remaining.as_millis().min(800) as u64),
                "scrolls": scrolls.len().min(128),
                "inputs": inputs.min(128),
                "releases": releases.len().min(128),
                "counts_bounded": counts_bounded,
                "exact_release_acked": exact_release_acked,
                "authority_expired_at_retirement": evidence.as_ref().is_some_and(|evidence|
                    evidence.original_authority == Err(ProtocolError::DeadlineExceeded)),
                "action_finished_before_deadline": evidence.as_ref().is_some_and(|evidence| evidence.before_deadline),
                "broker_settled_before_deadline": broker_settled_before_deadline,
                "retained_drained_before_deadline": retained_drained_before_deadline,
                "contract_valid": contract_valid,
                "retired_before_deadline": retired_before_deadline,
                "complete": true
            })
        );
        assert!(
            entry_ack_receipt,
            "controlled preparation schedule inconclusive: entered ACK receipt"
        );
        assert!(
            entry_above_upper,
            "controlled preparation schedule inconclusive: entry above original upper bound"
        );
        assert!(
            release_sent && release_preconditions,
            "controlled preparation schedule inconclusive: original release interval"
        );
        assert!(
            counts_bounded,
            "controlled preparation receipt exceeded closed count bounds"
        );
        assert!(
            action_refusal_valid,
            "controlled preparation actual refusal/effects mismatch"
        );
        assert!(
            actual_settlement_valid,
            "controlled preparation actual broker settlement mismatch"
        );
        assert!(
            clean_retirement,
            "controlled preparation exact release or teardown mismatch"
        );
        assert!(
            exact_resolution && scrolls_acked && original_authority_valid,
            "controlled preparation exact authority/ACK mismatch"
        );
        assert!(
            inputs == 0,
            "controlled preparation must not dispatch any Input or replay tap"
        );
        // In the lower-floor diagnostic, current production is expected RED at
        // this exact assertion after Unknown/quarantine and real cleanup pass.
        // Expected RED is evidence of the gap, never an acceptance exemption.
        assert!(
            retired_before_deadline,
            "controlled preparation did not retire before original deadline"
        );
        assert!(
            scrolls.len() == 1,
            "controlled preparation retried after the controlled refusal"
        );
    }

    #[tokio::test]
    #[ignore = "controlled preparation diagnostic; separate exact-name receipt required"]
    async fn preparation_controlled_inside_window_acked_refusal_is_completed_and_reusable() {
        assert_controlled_preparation_schedule(ControlledPreparationSchedule::InsideWindow).await;
    }

    #[tokio::test]
    #[ignore = "diagnostic expected RED: below-floor refusal must retire before original deadline"]
    async fn preparation_controlled_below_floor_unknown_retires_before_original_deadline() {
        assert_controlled_preparation_schedule(ControlledPreparationSchedule::BelowFloor).await;
    }

    #[tokio::test]
    async fn preparation_effect_settlement_acked_interception_is_completed_and_reusable() {
        assert_preparation_effect_settlement("preparation-intercepted").await;
    }

    #[tokio::test]
    async fn preparation_effect_settlement_acked_not_actionable_is_completed_and_reusable() {
        assert_preparation_effect_settlement("preparation-not-actionable").await;
    }

    #[tokio::test]
    async fn preparation_effect_settlement_unacked_first_scroll_remains_unknown() {
        assert_preparation_effect_settlement("preparation-scroll-unacked").await;
    }

    #[tokio::test]
    async fn preparation_effect_settlement_unacked_later_scroll_invalidates_earlier_prefix() {
        assert_preparation_effect_settlement("preparation-later-scroll-unacked").await;
    }

    #[tokio::test]
    async fn preparation_effect_settlement_unacked_input_release_remains_unknown() {
        assert_preparation_effect_settlement("preparation-input-unacked").await;
    }

    #[tokio::test]
    async fn preparation_effect_settlement_dirty_handle_cleanup_quarantines() {
        assert_preparation_effect_settlement("preparation-handle-cleanup-failed").await;
    }

    #[tokio::test]
    async fn preparation_effect_settlement_unacked_geometry_control_remains_unknown() {
        assert_preparation_effect_settlement("preparation-control-unacked").await;
    }

    #[tokio::test]
    async fn preparation_effect_settlement_lost_original_authority_remains_unknown() {
        assert_preparation_effect_settlement("preparation-authority-lost").await;
    }

    #[tokio::test]
    async fn preparation_optional_receipt_does_not_reject_enrolled_callback_tap() {
        let mut f = fixture_scoped("preparation-callback-success", "callback-tap").await;
        let broker = Arc::new(super::super::client_session::ClientSession::new());
        let (owner, state, _notices) = preparation_settlement_owner(&f, broker).await;
        // Exercise the existing action seam with a callback lease. The broker's
        // callback-token admission is independent and is not simulated here.
        f.op.is_callback = true;
        f.op.deadline = Instant::now() + Duration::from_secs(2);
        assert!(matches!(
            owner.capture_settled_input_authority(&f.page, &f.op),
            Err(ProtocolError::InvalidArguments)
        ));
        let d = Dispatch::default();
        let result = ClientActions::default().execute_inner(&ActionContext {
            realm_authority: ActionRealmAuthority::Enrolled(&owner),
            page_state: &state,
            ..f.context()
        }, &d, "browser.perform", &json!({
            "identityScope":"callback-tap", "ref":{"id":"@e1","revision":"1"}, "action":{"kind":"tap"}
        })).await;
        let inputs = f.inputs();
        let closed = owner.close().await;
        f.server.abort();
        let joined = (&mut f.server).await;
        assert!(
            result.is_ok(),
            "callback tap must retain its original execution path"
        );
        assert!(!d.preparation_enabled.load(Ordering::SeqCst));
        assert!(!d.acknowledged_postcondition.load(Ordering::SeqCst));
        assert_eq!(
            inputs
                .iter()
                .filter(|request| request["params"]["type"] == "mouseReleased")
                .count(),
            1
        );
        assert_eq!(closed, Ok(()));
        assert!(joined.is_err_and(|error| error.is_cancelled()));
    }

    #[test]
    fn preparation_retry_checkpoint_uses_current_ack_without_certifying_completed() {
        let d = Dispatch::default();
        let ms = Duration::from_millis;
        d.preparation_enabled.store(true, Ordering::SeqCst);
        d.begin_preparation_attempt();
        d.mark_mutation(true);
        d.preparation_refusal.store(true, Ordering::SeqCst);
        let checks = std::cell::Cell::new(0);
        let check = || {
            checks.set(checks.get() + 1);
            Ok(())
        };
        // The real attempt ended above its window. A command-free pause may
        // enter that same window before the next attempt invalidates the ACK.
        assert_eq!(
            preparation_refusal_checkpoint(&d, ms(303), ms(20), check),
            Ok(())
        );
        assert_eq!(checks.get(), 0);
        assert!(!d.preparation_stopped.load(Ordering::SeqCst));
        assert_eq!(
            preparation_refusal_checkpoint(&d, ms(280), ms(20), check),
            Err(ProtocolError::NotActionable)
        );
        assert_eq!(checks.get(), 1);
        assert!(d.preparation_stopped.load(Ordering::SeqCst));
        assert!(d.preparation_refusal.load(Ordering::SeqCst));
        // Cleanup/original-authority/reference/realm proof is still required.
        assert!(!d.acknowledged_postcondition.load(Ordering::SeqCst));
        assert_eq!(
            d.failure(ProtocolError::NotActionable).effects,
            Effects::Unknown
        );
    }

    #[test]
    fn preparation_retry_checkpoint_never_covers_a_started_read_or_mutation() {
        let ms = Duration::from_millis;
        let d = Dispatch::default();
        d.preparation_enabled.store(true, Ordering::SeqCst);
        d.mark_mutation(true);
        d.preparation_refusal.store(true, Ordering::SeqCst);
        assert_eq!(
            preparation_refusal_checkpoint(&d, ms(303), ms(20), || Ok(())),
            Ok(())
        );
        // This is the source-shared invalidation used immediately before
        // center_once, whose first command is a read, not another scroll.
        d.begin_preparation_attempt();
        assert_eq!(
            preparation_refusal_checkpoint(&d, ms(280), ms(20), || panic!(
                "old ACK authorized a new read"
            )),
            Ok(())
        );
        d.preparation_refusal.store(true, Ordering::SeqCst);
        d.mark_mutation(true);
        assert_eq!(
            preparation_refusal_checkpoint(&d, ms(280), ms(20), || panic!(
                "old ACK authorized a new scroll"
            )),
            Ok(())
        );
        d.mark();
        d.preparation_refusal.store(true, Ordering::SeqCst);
        assert_eq!(
            preparation_refusal_checkpoint(&d, ms(280), ms(20), || panic!(
                "non-preparation mutation was ignored"
            )),
            Ok(())
        );
        assert!(!d.preparation_stopped.load(Ordering::SeqCst));
        assert_eq!(
            d.failure(ProtocolError::NotActionable).effects,
            Effects::Unknown
        );
    }

    #[test]
    fn preparation_retry_checkpoint_below_floor_retires_unknown_without_new_attempt() {
        let ms = Duration::from_millis;
        for remaining in [Duration::ZERO, ms(265), ms(266) - Duration::from_nanos(1)] {
            let d = Dispatch::default();
            d.preparation_enabled.store(true, Ordering::SeqCst);
            d.mark_mutation(true);
            d.preparation_refusal.store(true, Ordering::SeqCst);
            assert_eq!(
                preparation_refusal_checkpoint(&d, remaining, ms(900), || Ok(())),
                Err(ProtocolError::NotActionable)
            );
            assert!(!d.preparation_stopped.load(Ordering::SeqCst));
            assert_eq!(
                d.failure(ProtocolError::NotActionable).effects,
                Effects::Unknown
            );
        }
    }

    #[test]
    fn preparation_retry_checkpoint_keeps_authority_error_priority() {
        let ms = Duration::from_millis;
        for remaining in [ms(265), ms(266), ms(280)] {
            for error in [
                ProtocolError::Cancelled,
                ProtocolError::StaleScope,
                ProtocolError::DeadlineExceeded,
            ] {
                let d = Dispatch::default();
                d.preparation_enabled.store(true, Ordering::SeqCst);
                d.mark_mutation(true);
                d.preparation_refusal.store(true, Ordering::SeqCst);
                let expected = if remaining < ms(266) && error == ProtocolError::DeadlineExceeded {
                    ProtocolError::NotActionable
                } else {
                    error.clone()
                };
                assert_eq!(
                    preparation_refusal_checkpoint(&d, remaining, ms(20), || Err(error)),
                    Err(expected)
                );
                assert!(!d.preparation_stopped.load(Ordering::SeqCst));
                assert_eq!(
                    d.failure(ProtocolError::NotActionable).effects,
                    Effects::Unknown
                );
            }
        }
    }

    #[test]
    fn preparation_mismatch_trace_is_fixed_size_ordered_numeric_evidence() {
        let mut trace = PreparationTrace::default();
        for remaining_us in 0..12 {
            trace.record(PreparationTraceEvent {
                phase: PreparationTracePhase::BeforeRetry as u8,
                remaining_us,
                longest_attempt_us: 20_000,
                flags: 3,
            });
        }
        let events = trace.ordered();
        assert_eq!(trace.recorded, 12);
        assert_eq!(events.len(), 8);
        assert_eq!(events.first().unwrap().remaining_us, 4);
        assert_eq!(events.last().unwrap().remaining_us, 11);
        for event in serde_json::to_value(events).unwrap().as_array().unwrap() {
            let fields = event.as_object().unwrap();
            assert_eq!(fields.len(), 4);
            assert!(fields.values().all(Value::is_u64));
        }
    }

    #[test]
    fn preparation_low_slack_retires_without_extending_the_classification_window() {
        let ms = Duration::from_millis;
        for (remaining, longest_attempt, has_slack, classify) in [
            (0, 0, false, false),
            (239, 0, false, false),
            (265, 0, false, false),
            (266, 0, true, true),
            (272, 0, true, true),
            (282, 0, true, true),
            (283, 0, true, false),
            (302, 20, true, true),
            (303, 20, true, false),
            (265, 900, false, false),
        ] {
            assert_eq!(
                preparation_has_classification_slack(ms(remaining)),
                has_slack,
                "remaining={remaining}, longest_attempt={longest_attempt}"
            );
            assert_eq!(
                preparation_classification_window(ms(remaining), ms(longest_attempt)),
                classify,
                "remaining={remaining}, longest_attempt={longest_attempt}"
            );
        }
    }

    #[test]
    fn preparation_low_slack_retirement_preserves_cancellation_and_stale_permit_priority() {
        for (check, expected) in [
            (Ok(()), ProtocolError::NotActionable),
            (
                Err(ProtocolError::DeadlineExceeded),
                ProtocolError::NotActionable,
            ),
            (Err(ProtocolError::Cancelled), ProtocolError::Cancelled),
            (Err(ProtocolError::StaleScope), ProtocolError::StaleScope),
        ] {
            assert_eq!(preparation_retirement_error(check), expected);
        }
    }

    #[test]
    fn preparation_receipt_requires_positive_cleanup_slack_and_invalidates_on_any_new_attempt() {
        let ms = Duration::from_millis;
        assert!(!preparation_classification_window(ms(265), ms(20)));
        assert!(preparation_classification_window(ms(280), ms(20)));
        assert!(!preparation_classification_window(ms(500), ms(20)));
        assert!(!preparation_classification_window(Duration::ZERO, ms(900)));
        let d = Dispatch::default();
        d.preparation_refusal.store(true, Ordering::SeqCst);
        d.mark_mutation(true);
        assert!(!d.preparation_refusal.load(Ordering::SeqCst));
        assert!(!d.preparation_disqualified.load(Ordering::SeqCst));
        d.mark();
        d.mark_mutation(true);
        assert!(d.preparation_disqualified.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn preparation_exhausted_slack_and_unpredicted_latency_keep_unknown_settlement() {
        for mode in [
            "preparation-slack-exhausted",
            "preparation-latency-spike",
            "preparation-estimate-overrun",
        ] {
            assert_preparation_effect_settlement(mode).await;
        }
    }

    #[tokio::test]
    async fn preparation_semantic_refusal_still_retries_into_an_ordinary_successful_tap() {
        let f = fixture("preparation-retry-success").await;
        ClientActions::default().execute(f.context(), "browser.perform", &json!({
            "identityScope":"scope", "ref":{"id":"@e1","revision":"1"}, "action":{"kind":"tap"}
        })).await.unwrap();
        let requests = f.log.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["method"] == "DOM.scrollIntoViewIfNeeded")
                .count(),
            3
        );
        drop(requests);
        assert_eq!(
            f.inputs()
                .iter()
                .filter(|request| request["params"]["type"] == "mouseReleased")
                .count(),
            1
        );
    }

    async fn assert_readonly_swipe_settlement(mode: &'static str) {
        use super::super::{
            client_protocol::ScopeState, client_session::ClientSession,
            client_tasks::RetainedTasks, client_transport::NativeOutcome,
        };
        let broker = Arc::new(ClientSession::new());
        let mut f = fixture_scoped_with_action_broker(mode, mode, Some(broker.clone())).await;
        let ledger = client_debt::OwnerDebtLedger::new(1, mode.into());
        ledger.bind_context("context").unwrap();
        f.page.client.install_debt_ledger(ledger.clone()).unwrap();
        // All enrollment services capture this exact bound client. Installing
        // tracking after owner creation would leave them on an ambient handle.
        f.page.client = f.page.client.owner_view(ledger.clone()).unwrap();
        let (owner, state, _notices) = preparation_settlement_owner(&f, broker.clone()).await;
        f.op = broker.admit(1, 1, 1_000).unwrap();
        assert!(broker.start(1, 1).unwrap());
        owner
            .capture_settled_input_authority(&f.page, &f.op)
            .unwrap();
        let journal = ledger
            .operation(
                client_debt::OperationKey {
                    generation: 1,
                    operation_seq: 1,
                },
                "target".into(),
                "page".into(),
            )
            .unwrap();
        journal.bind_operation(&f.op).unwrap();
        f.log.lock().unwrap().clear();
        f.replies.lock().unwrap().clear();
        let f = Arc::new(f);
        let tasks = RetainedTasks::default();
        let action_fixture = f.clone();
        let action_owner = owner.clone();
        let action_state = state.clone();
        let before_deadline = Arc::new(AtomicBool::new(false));
        let action_before_deadline = before_deadline.clone();
        let receive = tasks
            .start_operation(
                mode.into(),
                f.page.targets.clone(),
                broker.clone(),
                journal.clone(),
                f.op.cancellation.clone(),
                async move {
                    let result = ClientActions::default()
                        .execute(
                            ActionContext {
                                realm_authority: ActionRealmAuthority::Enrolled(&action_owner),
                                page_state: &action_state,
                                ..action_fixture.context()
                            },
                            "browser.perform",
                            &json!({"identityScope":mode,"ref":{"id":"@e1","revision":"1"},
                                "action":{"kind":"swipe","direction":"down"}}),
                        )
                        .await;
                    action_before_deadline.store(
                        Instant::now() < action_fixture.op.deadline,
                        Ordering::SeqCst,
                    );
                    // This is ClientBrowser's ordinary action result projection,
                    // independent of mode. RetainedTasks owns final normalization.
                    match result {
                        Ok(value) => (
                            NativeOutcome {
                                result: Ok(value),
                                effects: Effects::Completed,
                                retention: None,
                            },
                            false,
                        ),
                        Err(failure) => (
                            NativeOutcome {
                                result: Err(match failure.reason {
                                    Some(ActionReason::InterceptedPointer) => {
                                        ProtocolError::InterceptedPointer
                                    }
                                    Some(ActionReason::CheckedStateUnchanged) => {
                                        ProtocolError::CheckedStateUnchanged
                                    }
                                    Some(ActionReason::ControlReplacedAfterClick) => {
                                        ProtocolError::CheckedControlReplaced
                                    }
                                    None => failure.error,
                                }),
                                effects: failure.effects,
                                retention: None,
                            },
                            failure.cleanup_failed,
                        ),
                    }
                },
            )
            .await
            .unwrap();
        let delivered = tokio::time::timeout(Duration::from_secs(3), receive)
            .await
            .expect("the original Swipe and its bounded cleanup must settle")
            .unwrap();
        let debt = journal.snapshot();
        let original_permit = f.page.permit.check();
        let scope = broker
            .settle_with_retention(1, 1, delivered.effects, delivered.retention.as_ref())
            .unwrap();
        tasks.fix_operation_result(journal.key());
        let next = broker.admit(1, 2, 1_000);
        if next.is_ok() {
            assert!(broker.start(1, 2).unwrap());
            broker.settle(1, 2, Effects::NotDispatched).unwrap();
        }
        let drained = tasks.drain().await;
        let requests = f.log.lock().unwrap().clone();
        let replies = f.replies.lock().unwrap().clone();
        let closed = owner.close().await;
        f.page.client.close().await;
        f.server.abort();
        let acknowledged = |request: &Value| {
            replies.iter().any(|entry| {
                entry["request"] == *request
                    && entry["reply"]["sessionId"] == request["sessionId"]
                    && entry["reply"].get("error").is_none()
            })
        };
        let probes: Vec<_> = requests.iter().filter(|request| {
            request["method"] == "Runtime.callFunctionOn"
                && request["params"]["functionDeclaration"].as_str().is_some_and(|source| {
                    source.contains("const rect=this.getBoundingClientRect();const style=getComputedStyle(this);")
                        && source.ends_with("return true;}")
                })
        }).collect();
        let scrolls: Vec<_> = requests
            .iter()
            .filter(|request| request["method"] == "DOM.scrollIntoViewIfNeeded")
            .collect();
        let inputs: Vec<_> = requests
            .iter()
            .filter(|request| {
                request["method"]
                    .as_str()
                    .is_some_and(|method| method.starts_with("Input."))
            })
            .collect();
        let releases: Vec<_> = requests
            .iter()
            .filter(|request| {
                request["method"] == "Runtime.releaseObject"
                    && request["params"]["objectId"] == "exact-node"
            })
            .collect();
        if mode == "preparation-readonly-stale" {
            assert_eq!(probes.len(), 1, "stale authority prohibits another probe");
        } else {
            assert!(probes.len() >= 2, "{mode}: refusal must still retry");
        }
        if mode == "preparation-readonly-cancel-second" {
            assert_eq!(probes.len(), 2);
            assert!(acknowledged(probes[0]));
            assert!(!acknowledged(probes[1]));
        } else {
            assert!(probes.iter().all(|request| acknowledged(request)), "{mode}");
        }
        assert_eq!(releases.len(), 1, "{mode}: no duplicate exact release");
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["method"] == "DOM.resolveNode"
                    && request["params"]["backendNodeId"] == 42
                    && request["params"]["executionContextId"] == 1)
                .count(),
            1
        );
        assert_eq!(debt.input_debt, 0, "{mode}");
        if matches!(
            mode,
            "preparation-readonly-release-held" | "preparation-readonly-stale"
        ) {
            assert_eq!(delivered.effects, Effects::Unknown);
            assert_eq!(scope, ScopeState::Quarantined);
            assert!(next.is_err(), "failed cleanup must prohibit new business");
            assert_eq!(drained, Err(ProtocolError::CleanupFailed));
            if mode == "preparation-readonly-release-held" {
                assert_eq!(delivered.result, Err(ProtocolError::CleanupFailed));
                assert!(!acknowledged(releases[0]));
                assert!(debt.object_debt > 0);
            } else {
                // ScopePermit::check returns StaleScope, and execute's required
                // release_input sees the same retired permit. Cleanup makes the
                // real retained outcome Unknown without replacing that primary.
                assert_eq!(original_permit, Err(ProtocolError::StaleScope));
                assert_eq!(delivered.result, Err(ProtocolError::StaleScope));
                assert!(acknowledged(releases[0]));
                assert_eq!(debt.object_debt, 0);
            }
        } else {
            assert_eq!(scope, ScopeState::Usable);
            assert!(next.is_ok());
            assert_eq!(drained, Ok(()));
            assert_eq!(closed, Ok(()));
            assert!(!debt.integrity_lost);
            assert!(acknowledged(releases[0]));
            if matches!(
                mode,
                "preparation-readonly-aux-held" | "preparation-readonly-cancel-second"
            ) {
                // Accounted object debt keeps its existing ownership semantics;
                // it must not be relabeled a clean semantic-refusal receipt.
                assert!(debt.object_debt > 0);
                assert_eq!(delivered.effects, Effects::NotDispatched);
                if mode == "preparation-readonly-cancel-second" {
                    assert_eq!(delivered.result, Err(ProtocolError::Cancelled));
                } else {
                    // The original deadline can be observed by pause's timer or
                    // the journal submission fence, which reports Cancelled.
                    assert!(matches!(
                        delivered.result,
                        Err(ProtocolError::DeadlineExceeded | ProtocolError::Cancelled)
                    ));
                    assert!(!before_deadline.load(Ordering::SeqCst));
                    let auxiliary_releases: Vec<_> = requests
                        .iter()
                        .filter(|request| {
                            request["method"] == "Runtime.releaseObject"
                                && request["params"]["objectId"] == "readonly-auxiliary"
                        })
                        .collect();
                    assert_eq!(auxiliary_releases.len(), 1);
                    assert!(!acknowledged(auxiliary_releases[0]));
                    assert!(replies.iter().any(|entry| entry["request"] == *probes[0]
                        && entry["reply"]["result"]["result"]["objectId"] == "readonly-auxiliary"));
                    assert!(probes.iter().skip(1).all(|probe| replies
                        .iter()
                        .any(|entry| entry["request"] == **probe
                            && entry["reply"]["result"]["result"].get("objectId").is_none())));
                }
            } else {
                assert_eq!(debt.object_debt, 0);
                assert!(
                    before_deadline.load(Ordering::SeqCst),
                    "{mode}: reusable classification must precede the original deadline"
                );
            }
        }
        if mode == "preparation-readonly-dynamic" {
            assert!(delivered.result.is_ok());
            assert_eq!(delivered.effects, Effects::Completed);
            assert!(debt.mutation_dispatched);
            assert_eq!(scrolls.len(), 2);
            assert!(scrolls.iter().all(|request| acknowledged(request)));
            assert_eq!(inputs.len(), 2);
            assert_eq!(
                inputs
                    .iter()
                    .filter(|request| request["params"]["type"] == "mouseWheel")
                    .count(),
                1
            );
            assert!(inputs.iter().all(|request| acknowledged(request)));
        } else {
            assert!(scrolls.is_empty() && inputs.is_empty(), "{mode}");
            assert!(!debt.mutation_dispatched);
            if mode == "preparation-readonly-no-box" {
                assert_eq!(delivered.result, Err(ProtocolError::NotActionable));
                assert_eq!(delivered.effects, Effects::NotDispatched);
            }
        }
    }

    #[tokio::test]
    async fn tracked_no_box_swipe_settles_refusal_before_deadline_and_keeps_scope_usable() {
        assert_readonly_swipe_settlement("preparation-readonly-no-box").await;
    }

    #[tokio::test]
    async fn tracked_no_box_swipe_retries_into_the_original_wheel_action() {
        assert_readonly_swipe_settlement("preparation-readonly-dynamic").await;
    }

    #[tokio::test]
    async fn tracked_no_box_swipe_unsettled_exact_release_is_unknown_and_not_reusable() {
        assert_readonly_swipe_settlement("preparation-readonly-release-held").await;
    }

    #[tokio::test]
    async fn tracked_no_box_swipe_never_reuses_old_ack_after_new_probe_is_cancelled() {
        assert_readonly_swipe_settlement("preparation-readonly-cancel-second").await;
    }

    #[tokio::test]
    async fn tracked_no_box_swipe_preserves_stale_original_permit_and_cleanup_failure() {
        assert_readonly_swipe_settlement("preparation-readonly-stale").await;
    }

    #[tokio::test]
    async fn tracked_no_box_swipe_later_empty_probes_cannot_erase_retained_auxiliary() {
        assert_readonly_swipe_settlement("preparation-readonly-aux-held").await;
    }

    #[tokio::test]
    async fn no_box_swipe_retries_within_its_budget_without_scroll_or_input_dispatch() {
        let mut f = fixture("no-box-swipe").await;
        f.op.deadline = Instant::now() + Duration::from_millis(1_000);
        let failure = tokio::time::timeout(
            Duration::from_secs(2),
            ClientActions::default().execute(
                f.context(),
                "browser.perform",
                &json!({"identityScope":"scope", "ref":{"id":"@e1","revision":"1"}, "action":{"kind":"swipe","direction":"down"}}),
            ),
        )
        .await
        .expect("the real action must settle within its operation and cleanup bounds")
        .unwrap_err();
        assert_eq!(failure.error, ProtocolError::NotActionable);
        assert_eq!(failure.effects, Effects::NotDispatched);
        assert!(!failure.cleanup_failed);
        assert!(f.inputs().is_empty());
        let requests = f.log.lock().unwrap();
        assert!(!requests
            .iter()
            .any(|request| request["method"] == "DOM.scrollIntoViewIfNeeded"));
        let probes = requests
            .iter()
            .filter(|request| {
                request["method"] == "Runtime.callFunctionOn"
                    && request["params"]["functionDeclaration"]
                        .as_str()
                        .is_some_and(|source| {
                            source.contains("const rect=this.getBoundingClientRect();const style=getComputedStyle(this);")
                                && source.ends_with("return true;}")
                        })
            })
            .count();
        assert!(probes >= 2, "no-box refusal must not become fail-fast");
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["method"] == "Runtime.releaseObject"
                    && request["params"]["objectId"] == "exact-node")
                .count(),
            1,
            "the exact resolved handle is released before settlement"
        );
    }

    #[tokio::test]
    async fn readonly_pseudo_action_never_resolves_or_retargets_origin() {
        let mut f = fixture("normal").await;
        let id = f
            .refs
            .try_bind_readonly_pseudo(
                99,
                "ListMarker",
                ExactBinding {
                    page_session: "page".into(),
                    session: "page".into(),
                    frame: "main".into(),
                    loader: "doc".into(),
                    actionable: false,
                },
            )
            .unwrap();
        let error=ClientActions::default().execute(f.context(),"browser.perform",&json!({"identityScope":"scope","ref":{"id":format!("@{id}"),"revision":"1"},"action":{"kind":"tap"}})).await.unwrap_err();
        assert_eq!(error.error, ProtocolError::NotActionable);
        assert_eq!(error.effects, Effects::NotDispatched);
        assert!(f.log.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn invalid_keyboard_chord_is_not_dispatched() {
        let f = fixture("normal").await;
        let error = ClientActions::default()
            .execute(
                f.context(),
                "browser.keyboard.press",
                &json!({"identityScope":"scope","key":"NotARealModifier+Enter"}),
            )
            .await
            .unwrap_err();
        assert_eq!(error.error, ProtocolError::InvalidArguments);
        assert_eq!(error.effects, Effects::NotDispatched);
        assert!(f.inputs().is_empty());
    }
    #[tokio::test]
    async fn cancelled_upload_wait_retains_writer_and_cleanup_drains_error_directory() {
        let directory = OwnedDirectory::create().unwrap();
        let path = directory.path.clone();
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let actions = ClientActions::default();
        actions.uploads.lock().await.push(UploadResource {
            job: Some(tokio::task::spawn_blocking(move || {
                let _ = wait.blocking_recv();
                Ok(StagedUpload {
                    directory,
                    paths: Vec::new(),
                    _leases: Vec::new(),
                    error: Some(ProtocolError::Cancelled),
                })
            })),
            staged: None,
        });
        {
            let mut resources = actions.uploads.lock().await;
            assert!(
                tokio::time::timeout(Duration::from_millis(10), resources[0].settle())
                    .await
                    .is_err()
            );
            assert!(resources[0].job.is_some());
        }
        assert!(path.exists());
        release.send(()).unwrap();
        assert_eq!(
            actions.cleanup().await.unwrap_err(),
            ProtocolError::CleanupFailed
        );
        assert!(!path.exists());
        assert!(actions.uploads.lock().await.is_empty());
    }
    #[tokio::test]
    #[ignore = "requires hosted Chromium: ACKed replacement prefix cancellation preserves renderer state and session reuse"]
    async fn chromium_replacement_acknowledged_prefix_cancel_preserves_selection_and_session() {
        use super::super::{
            client_browser::ClientBrowser,
            client_protocol::ScopeState,
            client_session::ClientSession,
            client_transport::{ClientEventSink, ClientExecutor},
        };
        async fn run(
            browser: &ClientBrowser,
            operations: &mut FixtureOperations,
            sink: &ClientEventSink,
            command: &str,
            args: Value,
            seconds: u64,
        ) -> Result<Value, String> {
            operations
                .execute_written(browser, sink, command, args, seconds)
                .await
                .map_err(|error| format!("{command} admission/settlement: {error:?}"))?
                .result
                .map_err(|error| format!("{command}: {error:?}"))
        }
        let broker = Arc::new(ClientSession::new());
        let browser = ClientBrowser::new(broker.clone());
        let (sink, _events) = ClientEventSink::test_channel(broker.clone());
        browser.set_event_sink(sink.clone()).unwrap();
        let mut operations = FixtureOperations::new(broker.clone());
        let result: Result<(), String> = async {
            let opened = run(&browser, &mut operations, &sink, "scope.open",
                fixture_scope_open("launch", None), 30).await?;
            let scope = opened["identityScope"].as_str().ok_or("missing scope")?.to_owned();
            run(&browser, &mut operations, &sink, "scope.configure",
                fixture_configuration(&scope, None), 30).await?;
            run(&browser, &mut operations, &sink, "network.routes.replace",
                fixture_routes(&scope), 30).await?;
            run(&browser, &mut operations, &sink, "page.activate",
                json!({"identityScope":scope}), 30).await?;
            for key in ["ControlOrMeta+A", "Delete"] {
                let token = uuid::Uuid::new_v4().to_string();
                run(&browser, &mut operations, &sink, "page.evaluate", json!({
                    "identityScope":scope,
                    "source":r#"token=>{
                        document.body.innerHTML='<textarea id="edit">original</textarea>';
                        window.prefixFixture={token,events:[]};
                        const edit=document.querySelector('#edit');
                        for(const type of ['keydown','keyup','input'])
                            edit.addEventListener(type,event=>prefixFixture.events.push({
                                type:event.type,code:event.code??null,inputType:event.inputType??null
                            }));
                        edit.focus();edit.setSelectionRange(2,2);return true;
                    }"#,
                    "argument":token
                }), 2).await?;
                let sequence = operations.sequence + 1;
                let generation = broker.health().map_err(|error| format!("health: {error:?}"))?.0;
                let cancelling = broker.clone();
                let reached = Arc::new(AtomicBool::new(false));
                let acknowledged = reached.clone();
                let _boundary = ReplacementBoundary::install(&scope, generation, sequence, key, move || {
                    acknowledged.store(true, Ordering::SeqCst);
                    cancelling.cancel(generation, sequence).unwrap();
                });
                let outcome = operations.execute_written(&browser, &sink, "browser.keyboard.type",
                    json!({"identityScope":scope,"replace":true,"text":"must-not-type"}), 2).await
                    .map_err(|error| format!("replacement admission/settlement: {error:?}"))?;
                if !reached.load(Ordering::SeqCst)
                    || outcome.result != Err(ProtocolError::Cancelled)
                    || outcome.effects != Effects::Completed
                    || broker.health().map_err(|error| format!("health: {error:?}"))?
                        != (generation, ScopeState::Usable)
                {
                    return Err(format!("{key}: prefix did not settle as cancelled and reusable"));
                }
                // Both reads are fresh, admitted, post-settlement operations on
                // the same live ClientBrowser/scope. No reset, reattach, replay,
                // synthetic renderer result, or independent CDP bypass occurs.
                let inspect = json!({"identityScope":scope,"source":r#"()=>{
                    const edit=document.querySelector('#edit');
                    return {token:prefixFixture.token,value:edit.value,start:edit.selectionStart,
                        end:edit.selectionEnd,active:document.activeElement.id,events:prefixFixture.events};
                }"#,"argument":null});
                let first = run(&browser, &mut operations, &sink, "page.evaluate", inspect.clone(), 2).await?;
                let second = run(&browser, &mut operations, &sink, "page.evaluate", inspect, 2).await?;
                let actual = &first["value"];
                let expected_value = if key == "Delete" { "" } else { "original" };
                if first != second || actual["token"] != token || actual["value"] != expected_value
                    || actual["start"] != 0 || actual["end"] != expected_value.len()
                    || actual["active"] != "edit"
                {
                    return Err(format!("{key}: settled selection/deletion or same-document read changed: {actual}"));
                }
                let events = actual["events"].as_array().ok_or("missing renderer input evidence")?;
                for code in ["KeyA", "Delete"] {
                    let count = events.iter().filter(|event| event["code"] == code).count();
                    let expected = if code == "Delete" && key != "Delete" { 0 } else { 2 };
                    if count != expected {
                        return Err(format!("{key}: renderer {code} event count {count}, expected {expected}"));
                    }
                }
                if !events.iter().any(|event| event["type"] == "keyup"
                    && matches!(event["code"].as_str(), Some("ControlLeft" | "MetaLeft")))
                    || events.iter().any(|event| event["code"].as_str().is_some_and(|code|
                        !matches!(code, "ControlLeft" | "MetaLeft" | "KeyA" | "Delete"))
                        || event["inputType"].as_str().is_some_and(|kind| kind.starts_with("insert")))
                {
                    return Err(format!("{key}: modifier release missing or replacement text was dispatched"));
                }
            }
            Ok(())
        }.await;
        let cleanup = browser.shutdown().await;
        assert!(cleanup.is_ok(), "production scope cleanup: {cleanup:?}");
        assert!(
            result.is_ok(),
            "replacement prefix/session boundary: {result:?}"
        );
    }
    #[tokio::test]
    #[ignore = "requires hosted Chromium: production protected observe then exact checked action with bounded stage evidence"]
    async fn chromium_protected_observe_then_exact_check_uses_committed_snapshot() {
        chromium_checked_action_acquisition("protected").await;
    }
    #[tokio::test]
    #[ignore = "requires hosted Chromium: protected pixels preserve visibility and exact input ACK"]
    async fn chromium_protected_pixels_then_exact_check_uses_committed_snapshot() {
        chromium_checked_action_acquisition("pixels").await;
    }
    #[tokio::test]
    #[ignore = "requires hosted Chromium: production query then checked action baseline"]
    async fn chromium_fixture_query_then_exact_check_without_observation() {
        chromium_checked_action_acquisition("fixture").await;
    }
    #[tokio::test]
    #[ignore = "requires hosted Chromium: production iframe query then checked action without observation"]
    async fn chromium_iframe_query_then_exact_check_without_observation() {
        chromium_checked_action_acquisition("iframe").await;
    }
    async fn chromium_checked_action_acquisition(acquisition: &str) {
        use super::super::{
            client_browser::ClientBrowser,
            client_session::ClientSession,
            client_transport::{ClientEventSink, ClientExecutor},
        };
        async fn run(
            browser: &ClientBrowser,
            operations: &mut FixtureOperations,
            sink: &ClientEventSink,
            command: &str,
            args: Value,
            seconds: u64,
        ) -> Result<Value, String> {
            eprintln!("native-observe-action-stage command.start {command}");
            let outcome = operations
                .execute_written(browser, sink, command, args, seconds)
                .await
                .map_err(|error| format!("fixture admission/settlement: {error:?}"))?;
            eprintln!(
                "native-observe-action-stage command.settled {command} effects={:?}",
                outcome.effects
            );
            outcome
                .result
                .map_err(|error| format!("{command}: {error:?}"))
        }
        async fn inert_after_frame(
            browser: &ClientBrowser,
            operations: &mut FixtureOperations,
            sink: &ClientEventSink,
            scope: &str,
        ) -> Result<(), String> {
            // Preserve the public visibility fixture's preceding document and
            // its only readiness check. This launch fixture exercises the full
            // owner, but does not replace the borrowed-CDP public regression.
            const REPLACE_DOCUMENT: &str =
                "content=>{document.open();document.write(content);document.close();return null}";
            const FRAME: &str = r#"<iframe style="margin:13px;border:7px solid;padding:5px;width:200px;height:100px" srcdoc="<button>Framed</button>"></iframe>"#;
            const INERT: &str = r#"
      <main inert><h2>Behind the drawer</h2><button id="inert-save">Save</button></main>
      <button>Close drawer</button>
    "#;
            run(
                browser,
                operations,
                sink,
                "page.evaluate",
                json!({
                    "identityScope":scope,"source":REPLACE_DOCUMENT,"argument":FRAME
                }),
                10,
            )
            .await?;
            let ready_by = Instant::now() + Duration::from_secs(10);
            loop {
                let ready = run(browser, operations, sink, "page.evaluate", json!({
                    "identityScope":scope,
                    "source":"()=>{const frames=[...document.querySelectorAll('iframe')];return frames.length>0&&frames.every(frame=>frame.contentDocument?.readyState==='complete'&&frame.contentDocument.body.querySelector('button')!==null)}",
                    "argument":null
                }), 2).await?;
                if ready["value"] == true {
                    break;
                }
                if Instant::now() >= ready_by {
                    return Err("preceding iframe document did not become ready".into());
                }
                tokio::task::yield_now().await;
            }
            let observe = json!({"identityScope":scope,"testIdAttribute":"data-testid",
                "secureFieldSelector":FIXTURE_SECURE_SELECTOR,"options":{}});
            let framed = run(
                browser,
                operations,
                sink,
                "browser.observe",
                observe.clone(),
                10,
            )
            .await?;
            fn names<'a>(node: &'a Value, out: &mut Vec<&'a str>) {
                if let Some(name) = node["name"].as_str() {
                    out.push(name);
                }
                if let Some(children) = node["children"].as_array() {
                    for child in children {
                        names(child, out);
                    }
                }
            }
            let mut framed_names = Vec::new();
            names(&framed["root"], &mut framed_names);
            if !framed_names.contains(&"Framed") {
                return Err("preceding protected iframe observation lost its button".into());
            }
            run(
                browser,
                operations,
                sink,
                "page.evaluate",
                json!({
                    "identityScope":scope,"source":REPLACE_DOCUMENT,"argument":INERT
                }),
                10,
            )
            .await?;
            // Intentionally immediate, once: no readiness read, sleep, retry,
            // fallback, or fixture query may make this acquisition pass.
            let snapshot = run(browser, operations, sink, "browser.observe", observe, 10).await?;
            let mut observed_names = Vec::new();
            names(&snapshot["root"], &mut observed_names);
            if !observed_names.contains(&"Close drawer")
                || observed_names.contains(&"Save")
                || observed_names.contains(&"Behind the drawer")
            {
                return Err("inert subtree public semantic assertions failed".into());
            }
            let queried = run(
                browser,
                operations,
                sink,
                "fixture.query",
                json!({
                    "identityScope":scope,"expression":{"kind":"selector","selector":"#inert-save"}
                }),
                10,
            )
            .await?;
            let nodes = queried["nodes"]
                .as_array()
                .ok_or("missing inert fixture nodes")?;
            if nodes.len() != 1 || nodes[0]["states"]["hidden"].as_bool().unwrap_or(false) {
                return Err("inert element must remain visible in trusted fixture reads".into());
            }
            Ok(())
        }
        fn flatten_refs(node: &Value, references: &mut Vec<Value>) {
            if node["ref"].is_object() {
                references.push(node["ref"].clone());
            }
            if let Some(children) = node["children"].as_array() {
                for child in children {
                    flatten_refs(child, references);
                }
            }
        }
        async fn correlated_observed_ref(
            browser: &ClientBrowser,
            operations: &mut FixtureOperations,
            sink: &ClientEventSink,
            scope: &str,
            located: &Value,
            snapshot: &Value,
        ) -> Result<Value, String> {
            let mut observed = Vec::new();
            flatten_refs(&snapshot["root"], &mut observed);
            let result = run(
                browser,
                operations,
                sink,
                "fixture.correlate",
                json!({"identityScope":scope,"located":[located],"observed":observed}),
                2,
            )
            .await?;
            let matches = result["matches"]
                .as_array()
                .ok_or("missing acquisition correlations")?;
            if matches.len() != 1 || matches[0].is_null() || !observed.contains(&matches[0]) {
                return Err(
                    "acquisition did not correlate uniquely to a committed observed ref".into(),
                );
            }
            Ok(matches[0].clone())
        }
        let broker = Arc::new(ClientSession::new());
        let browser = ClientBrowser::new(broker.clone());
        let (sink, _events) = ClientEventSink::test_channel(broker.clone());
        browser.set_event_sink(sink.clone()).unwrap();
        let mut operations = FixtureOperations::new(broker);
        let result: Result<(), String> = async {
            let opened = run(&browser, &mut operations, &sink, "scope.open", fixture_scope_open("launch",None), 30).await?;
            let scope = opened["identityScope"].as_str().ok_or("missing scope")?;
            run(&browser, &mut operations, &sink, "scope.configure", fixture_configuration(scope,None), 30).await?;
            run(&browser, &mut operations, &sink, "page.activate", json!({"identityScope":scope}), 30).await?;
            if acquisition=="protected" {
                inert_after_frame(&browser, &mut operations, &sink, scope).await?;
            }
            run(&browser, &mut operations, &sink, "page.evaluate", json!({"identityScope":scope,"source":"()=>{document.body.innerHTML='<label><input id=box type=checkbox>Notify</label>';return true}","argument":null}), 2).await?;
            if acquisition=="iframe" {
                // Install a same-origin frame synchronously, without timer sleeps.
                run(&browser,&mut operations,&sink,"page.evaluate",json!({"identityScope":scope,"source":"()=>{document.body.innerHTML='<iframe id=child></iframe>';document.querySelector('#child').contentDocument.body.innerHTML='<label><input id=box type=checkbox>Notify</label>';return true}","argument":null}),2).await?;
            }
            eprintln!("native-observe-action-stage acquisition {acquisition}");
            let expression=if acquisition=="iframe" {json!({"kind":"frame","selector":"#child","source":{"kind":"selector","selector":"#box"}})} else {json!({"kind":"selector","selector":"#box"})};
            let query = run(&browser, &mut operations, &sink, "fixture.query", json!({"identityScope":scope,"expression":expression}), 2).await?;
            let nodes = query["nodes"].as_array().ok_or("missing query nodes")?;
            if nodes.len() != 1 { return Err("query did not locate one synthetic checkbox".into()); }
            let reference=if matches!(acquisition,"protected"|"pixels") {
                // Read-only diagnostics on the same active page; never activate
                // a background target to make the subsequent input succeed.
                let visibility_source = "()=>({visibility:document.visibilityState,focused:document.hasFocus(),activeTag:document.activeElement?.tagName??null,activeId:document.activeElement?.id??null,version:navigator.userAgent})";
                let before=run(&browser,&mut operations,&sink,"page.evaluate",json!({"identityScope":scope,"source":visibility_source,"argument":null}),2).await?;
                eprintln!("native-observe-visibility before={}",before["value"]);
                let snapshot = run(&browser, &mut operations, &sink, "browser.observe", json!({"identityScope":scope,"testIdAttribute":"data-testid","secureFieldSelector":FIXTURE_SECURE_SELECTOR,"options":{"pixels":acquisition=="pixels"}}), 2).await?;
                if acquisition=="pixels" && (snapshot["pixels"]["handle"].as_str().is_none() || snapshot["pixels"]["size"].as_u64().is_none_or(|size|size==0)) {return Err("protected pixels were not produced before exact action".into());}
                let after=run(&browser,&mut operations,&sink,"page.evaluate",json!({"identityScope":scope,"source":visibility_source,"argument":null}),2).await?;
                eprintln!("native-observe-visibility after={}",after["value"]);
                if before["value"]!=after["value"] {return Err("protected observation changed visibility, focus, active element or browser identity".into());}
                correlated_observed_ref(&browser, &mut operations, &sink, scope, &nodes[0]["ref"], &snapshot).await?
            } else {nodes[0]["ref"].clone()};
            // Actual central dispatch acquires snapshot_for_action; no supplied
            // ref map, synthetic readiness ACK or protected-read bypass.
            run(&browser, &mut operations, &sink, "browser.perform", json!({"identityScope":scope,"ref":reference,"action":{"kind":"check"}}), 2).await?;
            let source=if acquisition=="iframe" {"()=>document.querySelector('#child').contentDocument.querySelector('#box').checked"} else {"()=>document.querySelector('#box').checked"};
            let state = run(&browser, &mut operations, &sink, "page.evaluate", json!({"identityScope":scope,"source":source,"argument":null}), 2).await?;
            if state["value"] != true { return Err("observed checkbox did not become checked".into()); }
            if acquisition!="protected" {return Ok(());}
            run(&browser, &mut operations, &sink, "page.evaluate", json!({"identityScope":scope,"source":"()=>{document.body.innerHTML='<label><input id=radio type=radio>Navigate</label>';document.querySelector('#radio').addEventListener('click',()=>location.replace('about:blank?native-checked-navigation'));return true}","argument":null}), 2).await?;
            let query=run(&browser,&mut operations,&sink,"fixture.query",json!({"identityScope":scope,"expression":{"kind":"selector","selector":"#radio"}}),2).await?;
            let snapshot=run(&browser,&mut operations,&sink,"browser.observe",json!({"identityScope":scope,"testIdAttribute":"data-testid","secureFieldSelector":FIXTURE_SECURE_SELECTOR,"options":{"pixels":acquisition=="pixels"}}),2).await?;
            let reference=correlated_observed_ref(&browser,&mut operations,&sink,scope,&query["nodes"][0]["ref"],&snapshot).await?;
            run(&browser,&mut operations,&sink,"browser.perform",json!({"identityScope":scope,"ref":reference,"action":{"kind":"check"}}),2).await?;
            let location=run(&browser,&mut operations,&sink,"page.evaluate",json!({"identityScope":scope,"source":"()=>location.href","argument":null}),2).await?;
            if location["value"]!="about:blank?native-checked-navigation" {return Err("checked radio did not navigate".into());}
            Ok(())
        }.await;
        // The direct fixture uses the exact synthetic writer-ACK hook after
        // broker settlement, not a target/readiness bypass or real I/O claim.
        let cleanup = browser.shutdown().await;
        assert!(cleanup.is_ok(), "production scope cleanup: {cleanup:?}");
        assert!(result.is_ok(), "observe/action boundary: {result:?}");
    }
    #[tokio::test]
    #[ignore = "requires real Chromium in hosted CI; native actions, not protocol mocks"]
    async fn chromium_exact_actions_fill_select_check_document_and_stale_ref() {
        use super::super::browser::{evaluate_on, BrowserManager};
        let mut browser = BrowserManager::launch(Default::default(), None)
            .await
            .unwrap();
        let result = async {
            let session = browser.active_session_id()?.to_owned();
            evaluate_on(&browser.client, &session, r#"document.body.innerHTML='<input id="text"><select id="pick"><option value="a">Alpha</option><option value="b">Beta</option></select><input id="check" type="checkbox"><button id="button" onclick="this.dataset.clicked=Number(this.dataset.clicked||0)+1">Click</button>'; true"#).await?;
            let gate = Arc::new(ExecutionGate::default());
            let page = BrowserExecutionLease { client: browser.client.clone(), page_session_id: session.clone(), target_id: browser.active_target_id()?.into(), identity_scope: "fixture-actions".into(), permit: gate.enter(false).unwrap(), targets: ClientTargets::new("fixture-context".into(), "fixture-actions".into()) };
            let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let operation = OperationLease { is_callback: false, generation: 1, sequence: 1, deadline: Instant::now()+Duration::from_secs(30), cancellation };
            let frames = HashMap::new();
            let tree = browser.client.send_command_no_params("Page.getFrameTree",Some(&session)).await?;
            let frame = &tree["frameTree"]["frame"];
            let binding = ExactBinding { page_session: session.clone(), session: session.clone(), frame: frame["id"].as_str().ok_or("missing frame")?.into(), loader: frame["loaderId"].as_str().ok_or("missing loader")?.into(), actionable: true };
            let document = browser.client.send_command("DOM.getDocument",Some(json!({})),Some(&session)).await?;
            let root = document["root"]["nodeId"].as_i64().ok_or("missing document")?;
            let mut refs = RefMap::new();
            refs.begin_observation(&page.identity_scope, operation.generation, 1);
            let mut ids = HashMap::new();
            for selector in ["#text", "#pick", "#check", "#button"] {
                let node = browser.client.send_command("DOM.querySelector",Some(json!({"nodeId":root,"selector":selector})),Some(&session)).await?;
                let described = browser.client.send_command("DOM.describeNode",Some(json!({"nodeId":node["nodeId"]})),Some(&session)).await?;
                let backend = described["node"]["backendNodeId"].as_i64().ok_or("missing backend")?;
                ids.insert(selector, format!("@{}", refs.bind_exact(backend,"generic","",binding.clone())));
            }
            let document_backend = document["root"]["backendNodeId"].as_i64().ok_or("missing document backend")?;
            let mut document_binding = binding.clone(); document_binding.actionable = false;
            let document_ref = format!("@{}",refs.bind_exact(document_backend,"document","",document_binding));
            let blobs = BlobStore::new(BlobLimits::default()).unwrap();
            blobs.activate_scope(BlobScope {generation:1, identity_scope:page.identity_scope.clone()}).unwrap();
            let state = ClientPageState::new(page.identity_scope.clone(), "fixture-context".into());
            let actions = ClientActions::default();
            let geometry = action_fixture_geometry(&page,&operation).await?;
            for (selector, action) in [
                ("#text", json!({"kind":"fill","value":"native synthetic","sensitive":false})),
                ("#pick", json!({"kind":"selectOption","value":{"label":"Beta"}})),
                ("#check", json!({"kind":"check"})),
                ("#button", json!({"kind":"doubleTap"})),
            ] {
                actions.execute(ActionContext { observation_frames: &[], observation_after: None, observed_revision: 0, realm_authority: ActionRealmAuthority::UntrackedFixture, page:&page,operation:&operation,page_state:&state,refs:&refs,revision:1,iframe_sessions:&frames,blobs:&blobs,geometry:&geometry},"browser.perform",&json!({"identityScope":page.identity_scope,"ref":{"id":ids[selector],"revision":"1"},"action":action})).await.map_err(|error|format!("action failed: {:?}",error.error))?;
            }
            let value = evaluate_on(&browser.client,&session,"[document.querySelector('#text').value,document.querySelector('#pick').value,document.querySelector('#check').checked,document.querySelector('#button').dataset.clicked]").await?;
            assert_eq!(value,json!(["native synthetic","b",true,"2"]));
            actions.execute(ActionContext { observation_frames: &[], observation_after: None, observed_revision: 0, realm_authority: ActionRealmAuthority::UntrackedFixture, page:&page,operation:&operation,page_state:&state,refs:&refs,revision:1,iframe_sessions:&frames,blobs:&blobs,geometry:&geometry},"browser.perform",&json!({"identityScope":page.identity_scope,"ref":{"id":document_ref,"revision":"1"},"action":{"kind":"scrollIntoView"}})).await.map_err(|error|format!("document action failed: {:?}",error.error))?;
            // Exercise old observed handles against actual retained/reinserted
            // DOM objects, not a selector or a current-ref substitution.
            use super::super::client_observation::{enumerate_frames, observe, read, ObservationOptions, SemanticNode};
            fn textbox(nodes: &[SemanticNode]) -> Option<NodeReference> {
                for node in nodes {
                    if node.role.as_deref()==Some("textbox") { return Some(node.reference.clone()); }
                    if let Some(found)=textbox(&node.children) { return Some(found); }
                }
                None
            }
            let observation_frames=enumerate_frames(&browser.client,&session,&frames,&operation).await?;
            let first=observe(&browser.client,&observation_frames,&mut refs,&page.identity_scope,2,&ObservationOptions::default(),&operation).await?;
            let original=textbox(&first.roots).ok_or("Missing original observed textbox")?;
            let second=observe(&browser.client,&observation_frames,&mut refs,&page.identity_scope,3,&ObservationOptions::default(),&operation).await?;
            assert_eq!(textbox(&second.roots),Some(original.clone()));
            assert_ne!(first.revision,second.revision);
            macro_rules! observed_context { ($revision:expr) => { ActionContext {
                observation_frames:&observation_frames, observation_after:None, observed_revision:$revision,
                realm_authority:ActionRealmAuthority::UntrackedFixture,page:&page,operation:&operation,
                page_state:&state,refs:&refs,revision:$revision,iframe_sessions:&frames,blobs:&blobs,geometry:&geometry
            } } }
            let fill_original=|value:&str|observed_fill_request(&page.identity_scope, &original, value);
            actions.execute(observed_context!(3),"browser.perform",&fill_original("late")).await.map_err(|error|format!("Original observed fill failed: {:?}",error.error))?;
            assert_eq!(evaluate_on(&browser.client,&session,"document.querySelector('#text').value").await?,json!("late"));
            let read_options=serde_json::from_value(json!({"ref":original.id})).unwrap();
            let fresh=read(&browser.client,&observation_frames,&mut refs,&page.identity_scope,3,&read_options,&operation).await?;
            assert_eq!(fresh["ref"],serde_json::to_value(&original).unwrap());
            evaluate_on(&browser.client,&session,"globalThis.savedObservedInput=document.querySelector('#text');savedObservedInput.remove();true").await?;
            let detached=actions.execute(observed_context!(3),"browser.perform",&fill_original("detached")).await.unwrap_err();
            assert_eq!(detached.error,ProtocolError::StaleReference);assert_eq!(detached.effects,Effects::NotDispatched);
            observe(&browser.client,&observation_frames,&mut refs,&page.identity_scope,4,&ObservationOptions::default(),&operation).await?;
            assert!(refs.get(original.id.trim_start_matches('@')).is_none());
            evaluate_on(&browser.client,&session,"document.body.prepend(savedObservedInput);true").await?;
            let reinserted=observe(&browser.client,&observation_frames,&mut refs,&page.identity_scope,5,&ObservationOptions::default(),&operation).await?;
            assert_eq!(textbox(&reinserted.roots),Some(original.clone()));
            actions.execute(observed_context!(5),"browser.perform",&fill_original("reinserted")).await.map_err(|error|format!("Reinserted original fill failed: {:?}",error.error))?;
            assert_eq!(evaluate_on(&browser.client,&session,"savedObservedInput.value").await?,json!("reinserted"));
            evaluate_on(&browser.client,&session,"savedObservedInput.replaceWith(savedObservedInput.cloneNode(true));true").await?;
            let replaced=observe(&browser.client,&observation_frames,&mut refs,&page.identity_scope,6,&ObservationOptions::default(),&operation).await?;
            assert_ne!(textbox(&replaced.roots),Some(original.clone()));
            let stale=actions.execute(observed_context!(6),"browser.perform",&fill_original("wrong replacement")).await.unwrap_err();
            assert_eq!(stale.error,ProtocolError::StaleReference);assert_eq!(stale.effects,Effects::NotDispatched);
            assert_eq!(evaluate_on(&browser.client,&session,"document.querySelector('#text').value").await?,json!("reinserted"));
            evaluate_on(&browser.client,&session,"document.querySelector('#button').remove(); true").await?;
            assert!(actions.execute(ActionContext { observation_frames: &[], observation_after: None, observed_revision: 0, realm_authority: ActionRealmAuthority::UntrackedFixture, page:&page,operation:&operation,page_state:&state,refs:&refs,revision:1,iframe_sessions:&frames,blobs:&blobs,geometry:&geometry},"browser.perform",&json!({"identityScope":page.identity_scope,"ref":{"id":ids["#button"],"revision":"1"},"action":{"kind":"tap"}})).await.is_err());
            actions.cleanup().await.map_err(|_|"cleanup failed")?;
            Ok::<(),String>(())
        }.await;
        browser.close().await.unwrap();
        result.unwrap();
    }
    #[tokio::test]
    #[ignore = "requires hosted Chromium; transformed nested-frame input and ancestor occlusion"]
    async fn chromium_nested_frame_action_projects_input_and_checks_exact_ancestor_occlusion() {
        use super::super::browser::{evaluate_on, BrowserManager};
        let mut browser = BrowserManager::launch(Default::default(), None)
            .await
            .unwrap();
        let result=async {
            let session=browser.active_session_id()?.to_owned();
            evaluate_on(&browser.client,&session,r#"(async()=>{
              document.body.style.margin='0';const outer=document.createElement('iframe');
              outer.id='outer';outer.style.cssText='position:absolute;left:100px;top:80px;width:300px;height:200px;border:5px solid black;padding:3px;transform:scale(1.25);transform-origin:0 0';
              const loaded=new Promise(r=>outer.onload=r);outer.srcdoc='<body style="margin:0"></body>';document.body.append(outer);await loaded;
              const inner=outer.contentDocument.createElement('iframe');inner.id='inner';inner.style.cssText='position:absolute;left:20px;top:30px;width:160px;height:100px;border:4px solid black;transform:scale(.75);transform-origin:0 0';
              const ready=new Promise(r=>inner.onload=r);inner.srcdoc='<body style="margin:0"><button style="position:absolute;left:12px;top:15px;width:80px;height:30px" onclick="this.dataset.clicks=Number(this.dataset.clicks||0)+1">Nested</button></body>';
              outer.contentDocument.body.append(inner);await ready;return true;
            })()"#).await?;
            let gate=Arc::new(ExecutionGate::default());
            let page=BrowserExecutionLease{client:browser.client.clone(),page_session_id:session.clone(),target_id:browser.active_target_id()?.into(),identity_scope:"nested-actions".into(),permit:gate.enter(false).unwrap(),targets:ClientTargets::new("fixture".into(),"nested-actions".into())};
            let (_cancel,cancellation)=tokio::sync::watch::channel(CancelSignal::None);
            let mut operation=OperationLease{is_callback:false,generation:1,sequence:1,deadline:Instant::now()+Duration::from_secs(20),cancellation};
            let inventory=super::super::client_observation::enumerate_frames(&page.client,&session,&HashMap::new(),&operation).await.map_err(|_|"Frame inventory failed")?;
            assert_eq!(inventory.len(),3);
            let frame=inventory.iter().find(|f|f.parent_frame_id.as_ref().is_some_and(|parent|inventory.iter().any(|p|p.binding.frame==*parent && p.parent_frame_id.is_some()))).ok_or("Nested frame missing")?;
            let world=page.client.send_command("Page.createIsolatedWorld",Some(json!({"frameId":frame.binding.frame,"worldName":"native-action-fixture"})),Some(&frame.binding.session)).await?;
            let object=page.client.send_command("Runtime.evaluate",Some(json!({"contextId":world["executionContextId"],"expression":"document.querySelector('button')"})),Some(&frame.binding.session)).await?;
            let object_id=object["result"]["objectId"].as_str().ok_or("Button handle missing")?;
            let described=page.client.send_command("DOM.describeNode",Some(json!({"objectId":object_id})),Some(&frame.binding.session)).await?;
            page.client.send_command("Runtime.releaseObject",Some(json!({"objectId":object_id})),Some(&frame.binding.session)).await?;
            let backend=described["node"]["backendNodeId"].as_i64().ok_or("Button backend missing")?;
            let mut refs=RefMap::new();refs.begin_observation(&page.identity_scope,operation.generation,1);let mut binding=frame.binding.clone();binding.actionable=true;
            let id=format!("@{}",refs.bind_exact(backend,"button","Nested",binding));
            let geometry=GeometrySnapshot::capture(&page.client,&session,&inventory,&operation).await.map_err(|_|"Geometry proof failed")?;
            let state=ClientPageState::new(page.identity_scope.clone(),"fixture".into());let blobs=BlobStore::new(BlobLimits::default()).unwrap();
            blobs.activate_scope(BlobScope{generation:1,identity_scope:page.identity_scope.clone()}).unwrap();
            let sessions=HashMap::new();let actions=ClientActions::default();
            let args=json!({"identityScope":page.identity_scope,"ref":{"id":id,"revision":"1"},"action":{"kind":"tap"}});
            actions.execute(ActionContext{ observation_frames: &[], observation_after: None, observed_revision: 0,realm_authority: ActionRealmAuthority::UntrackedFixture,page:&page,operation:&operation,page_state:&state,refs:&refs,revision:1,iframe_sessions:&sessions,blobs:&blobs,geometry:&geometry},"browser.perform",&args).await.map_err(|e|format!("Nested action failed: {:?}",e.error))?;
            assert_eq!(evaluate_on(&page.client,&session,"document.querySelector('#outer').contentDocument.querySelector('#inner').contentDocument.querySelector('button').dataset.clicks").await?,json!("1"));
            evaluate_on(&page.client,&session,"const cover=document.createElement('div');cover.style.cssText='position:fixed;inset:0;z-index:999;background:red';document.body.append(cover);true").await?;
            operation.deadline=Instant::now()+Duration::from_secs(2);
            let error=actions.execute(ActionContext{ observation_frames: &[], observation_after: None, observed_revision: 0,realm_authority: ActionRealmAuthority::UntrackedFixture,page:&page,operation:&operation,page_state:&state,refs:&refs,revision:1,iframe_sessions:&sessions,blobs:&blobs,geometry:&geometry},"browser.perform",&args).await.unwrap_err();
            assert_eq!(error.error,ProtocolError::NotActionable);assert_eq!(error.reason,Some(ActionReason::InterceptedPointer));
            assert_eq!(evaluate_on(&page.client,&session,"document.querySelector('#outer').contentDocument.querySelector('#inner').contentDocument.querySelector('button').dataset.clicks").await?,json!("1"));
            actions.cleanup().await.map_err(|_|"Action cleanup failed")?;Ok::<(),String>(())
        }.await;
        browser.close().await.unwrap();
        result.unwrap();
    }
    async fn action_fixture_geometry(
        page: &BrowserExecutionLease,
        operation: &OperationLease,
    ) -> Result<GeometrySnapshot, String> {
        let frames = super::super::client_observation::enumerate_frames(
            &page.client,
            &page.page_session_id,
            &HashMap::new(),
            operation,
        )
        .await
        .map_err(|_| "Fixture frame inventory failed")?;
        GeometrySnapshot::capture(&page.client, &page.page_session_id, &frames, operation)
            .await
            .map_err(|_| "Fixture geometry failed".to_owned())
    }
    #[tokio::test]
    #[ignore = "requires real Chromium and ffmpeg/ffprobe in hosted CI; no mock encoding"]
    async fn chromium_recording_attempt_segments_first_frame_size_and_scope_rotation() {
        use super::super::browser::{evaluate_on, BrowserManager};
        async fn page_lease(browser: &BrowserManager, identity: &str) -> BrowserExecutionLease {
            let gate = Arc::new(ExecutionGate::default());
            let page = BrowserExecutionLease {
                client: browser.client.clone(),
                page_session_id: browser.active_session_id().unwrap().into(),
                target_id: browser.active_target_id().unwrap().into(),
                identity_scope: identity.into(),
                permit: gate.enter(false).unwrap(),
                targets: ClientTargets::new(format!("context-{identity}"), identity.into()),
            };
            enroll_recording_fixture(&page).await;
            page
        }
        let mut first = BrowserManager::launch(Default::default(), None)
            .await
            .unwrap();
        let mut second = BrowserManager::launch(Default::default(), None)
            .await
            .unwrap();
        let actions = ClientActions::default();
        let result = async {
            let first_page = page_lease(&first, "record-first").await;
            let second_page = page_lease(&second, "record-second").await;
            for page in [&first_page, &second_page] {
                evaluate_on(&page.client, &page.page_session_id, "document.documentElement.style.background='rgb(20,40,80)'; document.body.style.margin='0'; document.body.innerHTML='<div style=\"width:100vw;height:100vh;background:rgb(20,40,80)\"></div>'; true").await?;
            }
            let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let operation = OperationLease { is_callback:false, generation:1, sequence:1, deadline:Instant::now()+Duration::from_secs(45), cancellation };
            let refs = RefMap::new(); let frames = HashMap::new();
            let blobs = BlobStore::new(BlobLimits::default()).unwrap();
            let first_state = ClientPageState::new(first_page.identity_scope.clone(), "context-first".into());
            let second_state = ClientPageState::new(second_page.identity_scope.clone(), "context-second".into());
            let first_scope = BlobScope {generation:1,identity_scope:first_page.identity_scope.clone()};
            let second_scope = BlobScope {generation:1,identity_scope:second_page.identity_scope.clone()};
            blobs.activate_scope(first_scope.clone()).unwrap();
            let first_geometry=action_fixture_geometry(&first_page,&operation).await?;
            let second_geometry=action_fixture_geometry(&second_page,&operation).await?;
            let first_context = || ActionContext { observation_frames: &[], observation_after: None, observed_revision: 0, realm_authority: ActionRealmAuthority::UntrackedFixture, page:&first_page,operation:&operation,page_state:&first_state,refs:&refs,revision:1,iframe_sessions:&frames,blobs:&blobs,geometry:&first_geometry};
            actions.execute(first_context(), "recording.start", &json!({"identityScope":first_page.identity_scope,"size":{"width":320,"height":200},"quality":70})).await.map_err(|e|format!("record start {:?}",e.error))?;
            actions.recording_page_closing(&first_page.identity_scope, &blobs).await.map_err(|e|format!("record close {e:?}"))?;
            blobs.revoke_scope(&first_scope).unwrap();
            blobs.activate_scope(second_scope.clone()).unwrap();
            let second_context = || ActionContext { observation_frames: &[], observation_after: None, observed_revision: 0, realm_authority: ActionRealmAuthority::UntrackedFixture, page:&second_page,operation:&operation,page_state:&second_state,refs:&refs,revision:1,iframe_sessions:&frames,blobs:&blobs,geometry:&second_geometry};
            actions.recording_page_opened(second_context()).await.map_err(|e|format!("record reopen {:?}",e.error))?;
            let output = actions.execute(second_context(), "recording.stop", &json!({"identityScope":second_page.identity_scope})).await.map_err(|e|format!("record stop {:?}",e.error))?;
            let segments = output["segments"].as_array().ok_or("missing segments")?;
            assert_eq!(segments.len(), 2);
            let first_instant = chrono::DateTime::parse_from_rfc3339(segments[0]["startedAt"].as_str().unwrap()).unwrap();
            let second_instant = chrono::DateTime::parse_from_rfc3339(segments[1]["startedAt"].as_str().unwrap()).unwrap();
            assert!(first_instant <= second_instant);
            let directory = OwnedDirectory::create().map_err(|_|"test directory")?;
            for (index, segment) in segments.iter().enumerate() {
                assert_eq!(segment["identityScope"], second_page.identity_scope);
                let handle = segment["handle"].as_str().unwrap();
                let size = segment["size"].as_u64().unwrap() as usize;
                let mut bytes = Vec::new();
                while bytes.len() < size { bytes.extend(blobs.read(&second_scope, handle, bytes.len(), (size-bytes.len()).min(super::super::client_blobs::MAX_CHUNK_BYTES)).unwrap()); }
                blobs.release(&second_scope, handle).unwrap();
                let video = directory.path.join(format!("segment-{index}.webm"));
                let image_path = directory.path.join(format!("segment-{index}.png"));
                tokio::fs::write(&video, bytes).await.map_err(|_|"test video write")?;
                let probe = tokio::process::Command::new("ffprobe").args(["-v","error","-select_streams","v:0","-show_entries","stream=codec_name,width,height","-of","json"]).arg(&video).output().await.map_err(|_|"ffprobe required")?;
                assert!(probe.status.success());
                let metadata: Value = serde_json::from_slice(&probe.stdout).unwrap();
                assert_eq!(metadata["streams"][0]["codec_name"], "vp8");
                assert_eq!(metadata["streams"][0]["width"], 320);
                assert_eq!(metadata["streams"][0]["height"], 200);
                let decoded = tokio::process::Command::new("ffmpeg").args(["-v","error","-i"]).arg(&video).args(["-frames:v","1"]).arg(&image_path).output().await.map_err(|_|"ffmpeg required")?;
                assert!(decoded.status.success());
                let image = image::open(&image_path).unwrap().to_rgb8();
                let pixel = image.get_pixel(160,100).0;
                for (actual, expected) in pixel.into_iter().zip([20u8,40,80]) { assert!(actual.abs_diff(expected)<20, "first frame must not be blank"); }
            }
            directory.close().map_err(|_|"test artifact cleanup")?;
            assert_eq!(actions.execute(second_context(), "recording.stop", &json!({"identityScope":second_page.identity_scope})).await.map_err(|_|"second collection")?["segments"], json!([]));
            Ok::<(),String>(())
        }.await;
        let cleanup = actions.cleanup().await;
        let first_closed = first.close().await;
        let second_closed = second.close().await;
        cleanup.unwrap();
        first_closed.unwrap();
        second_closed.unwrap();
        result.unwrap();
    }
}
