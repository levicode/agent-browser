//! Owned target identity and creation-purpose reservations. Browser attachment
//! waits on this registry before configuration/resume; no URL or timing guess
//! assigns a bootstrap target to a generic request handler.
#[path = "client_targets_page_query.rs"]
mod page_query;
use super::client_protocol::ProtocolError;
use super::client_settlement_trace as diagnostic;
use page_query::{AttachmentLineage, ProtectedExclusion};
pub(crate) use page_query::{
    SelectedPageTargetBarrier, SelectedPageTargetCheck, SelectedPageTargetSnapshot,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetPurpose {
    Application,
    StateBootstrap,
}
#[derive(Clone, Debug)]
pub struct OwnedTarget {
    pub target_id: String,
    pub session_id: String,
    pub kind: String,
    pub purpose: Option<TargetPurpose>,
    pub configured: bool,
    pub resumed: bool,
    resume_pending: bool,
    // Minted only by authoritative insertion. Retaining the Arc prevents an
    // identical target/session reattachment from reusing an earlier tenure.
    tenure: Arc<AttachmentTenure>,
    diagnostic: Option<diagnostic::DiagnosticAttachment>,
}
#[derive(Debug, Default)]
struct AttachmentTenure {
    lineage: AttachmentLineage,
    query_revision: AtomicU64,
    query_attribution_invalid: AtomicBool,
    owner: Arc<()>,
    retained_initialization: AtomicBool,
    observed_media_detach: AtomicBool,
    observed_detach: AtomicBool,
    observed_iframe_detach: AtomicBool,
}
/// Non-cloneable custody of one supervisor-retained initializer. This is not
/// configuration, capture, resume, CDP retirement, or owner-retirement proof.
pub(super) struct RetainedInitialization {
    registry: Arc<ClientTargets>,
    target: Option<OwnedTarget>,
    root: Option<OwnedTarget>,
    popup_progress: Option<PopupInitializationReceipt>,
}
struct AttachmentRegistrationContext<'a> {
    retained: bool,
    root: Option<&'a OwnedTarget>,
    enrolled: bool,
    verified_self_root: bool,
}
pub(super) struct AttachmentAncestry {
    pub(super) root: Option<OwnedTarget>,
    pub(super) verified_self_root: bool,
}
/// Read-only evidence from the existing retained initializer, never a second
/// producer. Origin is immutable; only custody can bind its actual tenure once.
#[derive(Clone)]
pub(super) struct PopupInitializationReceipt(Arc<PopupInitializationProgress>);
struct PopupInitializationProgress {
    registry: std::sync::Weak<ClientTargets>,
    ledger: std::sync::Weak<super::client_debt::OwnerDebtLedger>,
    generation: u64,
    stream: super::cdp::client::BoundedEventWatermark,
    origin: u64,
    target: std::sync::OnceLock<OwnedTarget>,
    // 0 unissued, 1 issued, 2 completed, 3 released. No transition repeats.
    stage: AtomicU8,
    // 0 retained, 1 positive after finish, 2 not successful.
    terminal: AtomicU8,
    // Opt-in observation only; never read by admission/completion predicates.
    setup_diagnostic: PopupSetupProgress,
    // Authoritative producer proof, independent of opt-in diagnostic checkpoints.
    configuration_applied: std::sync::OnceLock<PopupConfigurationApplied>,
}
struct PopupConfigurationApplied {
    revision: u64,
    received: u64,
}
impl PopupConfigurationApplied {
    fn matches(&self, (received, revision): (u64, u64)) -> bool {
        self.revision == revision && self.received <= received
    }
}
/// Diagnostic-only monotonic checkpoint. A skipped/duplicate transition loses
/// detail permanently rather than inventing an ACK or silently repairing order.
#[derive(Default)]
struct PopupSetupProgress(AtomicU8);
impl PopupSetupProgress {
    fn observe_bound(
        &self,
        registry: &ClientTargets,
        bound: &OwnedTarget,
        checkpoint: diagnostic::PopupSetupCheckpoint,
    ) {
        // Never wait on diagnostics. Lost observation is explicit and cannot
        // recover into a claim about a replacement or a different owner.
        let Ok(state) = registry.state.try_lock() else {
            self.0.store(u8::MAX, Ordering::Release);
            return;
        };
        if state.sealed
            || state.integrity_lost
            || !Arc::ptr_eq(&registry.attachment_owner, &bound.tenure.owner)
            || !state
                .targets
                .get(&bound.target_id)
                .is_some_and(|current| current.same_initialization_attachment(bound))
        {
            self.0.store(u8::MAX, Ordering::Release);
            return;
        }
        self.advance(checkpoint);
    }
    fn advance(&self, checkpoint: diagnostic::PopupSetupCheckpoint) {
        let next = checkpoint as u8;
        if self
            .0
            .compare_exchange(next - 1, next, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.0.store(u8::MAX, Ordering::Release);
        }
    }
    fn unconfigured_refusal(&self, stage: u8) -> diagnostic::EvalPreparationRefusal {
        match diagnostic::PopupSetupCheckpoint::from_code(self.0.load(Ordering::Acquire)) {
            Some(checkpoint) => diagnostic::EvalPreparationRefusal::UnconfiguredAt(
                checkpoint,
                diagnostic::PopupReceiptStage::from_code(stage),
            ),
            None => diagnostic::EvalPreparationRefusal::Unconfigured,
        }
    }
}
pub(super) struct PopupPreparationFailure {
    pub(super) error: ProtocolError,
    pub(super) reason: diagnostic::EvalPreparationRefusal,
}
impl PopupPreparationFailure {
    pub(super) fn new(error: ProtocolError, reason: diagnostic::EvalPreparationRefusal) -> Self {
        Self { error, reason }
    }
}
impl PopupInitializationReceipt {
    /// Only the existing initializer calls this after all page configuration
    /// ACKs and its revision check, while retaining the original config gate.
    /// This certifies neither recursive attachment nor resume/capture readiness.
    pub(super) fn mark_configuration_applied(
        &self,
        registry: &Arc<ClientTargets>,
        op: &super::client_session::OperationLease,
        revision: u64,
        target: &str,
        session: &str,
    ) -> Result<(), super::client_session::ObservedOperationFailure> {
        if op.is_callback || op.generation != self.0.generation {
            return Err(ProtocolError::StaleScope.into());
        }
        // Preserve the signal observed by this exact guard. A later owner stop
        // must not turn an ordinary failure into lifecycle retirement authority.
        super::client_session::ObservedOperationFailure::check_cancelled(op)?;
        if std::time::Instant::now() >= op.deadline {
            return Err(ProtocolError::DeadlineExceeded.into());
        }
        let ledger = self.0.ledger.upgrade().ok_or(ProtocolError::StaleScope)?;
        if !ledger.matches_owner(self.0.generation, &registry.identity_scope)
            || !ledger.matches_eval_preparation_stream(&self.0.stream)
        {
            return Err(ProtocolError::StaleScope.into());
        }
        registry.require_eval_owner(&ledger)?;
        let received = self
            .0
            .stream
            .received()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if self.0.origin == 0 || self.0.origin == u64::MAX || self.0.origin > received {
            return Err(ProtocolError::StaleScope.into());
        }
        let state = registry
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let current = state.targets.get(target).ok_or(ProtocolError::StaleScope)?;
        if state.sealed
            || state.integrity_lost
            || !self.matches_target(registry, current)
            || current.session_id != session
            || current.kind != "page"
            || current.purpose != Some(TargetPurpose::Application)
            || current.configured
            || current.resumed
            || current.resume_pending
            || self.0.stage.load(Ordering::Acquire) != 0
            || self.0.terminal.load(Ordering::Acquire) != 0
            || !current
                .tenure
                .retained_initialization
                .load(Ordering::Acquire)
        {
            return Err(ProtocolError::ScopeUnavailable.into());
        }
        self.0
            .configuration_applied
            .set(PopupConfigurationApplied { revision, received })
            .map_err(|_| ProtocolError::StaleScope.into())
    }
    /// Only the initializer's already-retained exact receipt is observed. A
    /// stale/wrong receipt cannot alter another cohort or grant any authority.
    pub(super) fn observe_setup_checkpoint(
        &self,
        registry: &ClientTargets,
        target: &str,
        session: &str,
        checkpoint: diagnostic::PopupSetupCheckpoint,
    ) {
        if let Some(bound) = self.0.target.get().filter(|bound| {
            bound.target_id == target
                && bound.session_id == session
                && self.matches_target(registry, bound)
        }) {
            self.0
                .setup_diagnostic
                .observe_bound(registry, bound, checkpoint);
        } else {
            self.0.setup_diagnostic.0.store(u8::MAX, Ordering::Release);
        }
    }
    fn matches_target(&self, registry: &ClientTargets, target: &OwnedTarget) -> bool {
        self.0
            .registry
            .upgrade()
            .is_some_and(|owner| std::ptr::eq(owner.as_ref(), registry))
            && self
                .0
                .target
                .get()
                .is_some_and(|bound| bound.same_initialization_attachment(target))
    }
    pub(super) fn known_origin_for(
        &self,
        ledger: &super::client_debt::OwnerDebtLedger,
    ) -> Option<u64> {
        let owner = self.0.ledger.upgrade()?;
        let registry = self.0.registry.upgrade()?;
        (std::ptr::eq(owner.as_ref(), ledger)
            && ledger.matches_owner(self.0.generation, &registry.identity_scope)
            && ledger.matches_eval_preparation_stream(&self.0.stream)
            && registry.require_eval_owner(&owner).is_ok()
            && self.0.origin > 0
            && self.0.origin < u64::MAX
            && (2..=3).contains(&self.0.stage.load(Ordering::Acquire))
            && self.0.terminal.load(Ordering::Acquire) == 0)
            .then_some(self.0.origin)
    }
    pub(super) fn capture_for_eval(
        &self,
        registry: &Arc<ClientTargets>,
        ledger: &Arc<super::client_debt::OwnerDebtLedger>,
        stream: &super::cdp::client::BoundedEventWatermark,
        received: u64,
        target: &str,
        session: &str,
    ) -> Result<OwnedTarget, ProtocolError> {
        if !self.0.stream.same_subscription(stream)
            || !ledger.matches_eval_preparation_stream(stream)
            || self
                .0
                .ledger
                .upgrade()
                .is_none_or(|owner| !Arc::ptr_eq(&owner, ledger))
            || !ledger.matches_owner(self.0.generation, &registry.identity_scope)
            || self.0.origin == 0
            || self.0.origin > received
            || self.0.origin == u64::MAX
        {
            return Err(ProtocolError::StaleScope);
        }
        registry.require_eval_owner(ledger)?;
        let current = self.current(registry)?;
        if current.target_id != target || current.session_id != session {
            return Err(ProtocolError::StaleScope);
        }
        Ok(current)
    }
    /// Private preparation is a retained wait, not an evaluation grant. Only the
    /// post-configuration-ACK gap before the real resume permit may additionally wait.
    pub(super) fn capture_for_preparation(
        &self,
        registry: &Arc<ClientTargets>,
        ledger: &Arc<super::client_debt::OwnerDebtLedger>,
        stream: &super::cdp::client::BoundedEventWatermark,
        boundary: (u64, u64),
        target: &str,
        session: &str,
    ) -> Result<OwnedTarget, ProtocolError> {
        self.capture_for_preparation_observed(registry, ledger, stream, boundary, target, session)
            .map_err(|failure| failure.error)
    }
    pub(super) fn capture_for_preparation_observed(
        &self,
        registry: &Arc<ClientTargets>,
        ledger: &Arc<super::client_debt::OwnerDebtLedger>,
        stream: &super::cdp::client::BoundedEventWatermark,
        boundary: (u64, u64),
        target: &str,
        session: &str,
    ) -> Result<OwnedTarget, PopupPreparationFailure> {
        let (received, _) = boundary;
        use diagnostic::EvalPreparationRefusal as Refused;
        if !self.0.stream.same_subscription(stream)
            || !ledger.matches_eval_preparation_stream(stream)
            || self
                .0
                .ledger
                .upgrade()
                .is_none_or(|owner| !Arc::ptr_eq(&owner, ledger))
            || !ledger.matches_owner(self.0.generation, &registry.identity_scope)
        {
            return Err(PopupPreparationFailure::new(
                ProtocolError::StaleScope,
                Refused::ReceiptOwner,
            ));
        }
        if self.0.origin == 0 || self.0.origin > received || self.0.origin == u64::MAX {
            return Err(PopupPreparationFailure::new(
                ProtocolError::StaleScope,
                Refused::ReceiptOrigin,
            ));
        }
        registry
            .require_eval_owner(ledger)
            .map_err(|error| PopupPreparationFailure::new(error, Refused::ReceiptOwner))?;
        let current = self.current_observed(registry, Some(boundary))?;
        if current.target_id != target || current.session_id != session {
            return Err(PopupPreparationFailure::new(
                ProtocolError::StaleScope,
                Refused::ReceiptTarget,
            ));
        }
        Ok(current)
    }
    fn current(&self, registry: &Arc<ClientTargets>) -> Result<OwnedTarget, ProtocolError> {
        self.current_for(registry, None)
    }
    fn current_for(
        &self,
        registry: &Arc<ClientTargets>,
        preparation: Option<(u64, u64)>,
    ) -> Result<OwnedTarget, ProtocolError> {
        self.current_observed(registry, preparation)
            .map_err(|failure| failure.error)
    }
    fn current_observed(
        &self,
        registry: &Arc<ClientTargets>,
        preparation: Option<(u64, u64)>,
    ) -> Result<OwnedTarget, PopupPreparationFailure> {
        use diagnostic::EvalPreparationRefusal as Refused;
        let fail = |error, reason| PopupPreparationFailure::new(error, reason);
        let bound = self
            .0
            .target
            .get()
            .ok_or_else(|| fail(ProtocolError::ScopeUnavailable, Refused::ReceiptBinding))?;
        let state = registry
            .state
            .lock()
            .map_err(|_| fail(ProtocolError::ScopeUnavailable, Refused::RegistryHealth))?;
        let current = state
            .targets
            .get(&bound.target_id)
            .ok_or_else(|| fail(ProtocolError::StaleScope, Refused::ReceiptTarget))?;
        let stage = self.0.stage.load(Ordering::Acquire);
        let terminal = self.0.terminal.load(Ordering::Acquire);
        // Only retained stage-zero custody can wait. Configured custody retains
        // its original path; unconfigured custody additionally needs the exact
        // successful configuration producer proof below. Neither grants capture.
        let awaiting_permit = preparation.is_some()
            && stage == 0
            && terminal == 0
            && !current.resumed
            && !current.resume_pending
            && current
                .tenure
                .retained_initialization
                .load(Ordering::Acquire);
        // The fixed entry boundary must include the proof's receive frontier;
        // enrollment additionally requires applied >= that fixed received prefix
        // before preparation completes, not before its wait-only fence is frozen.
        // Later Runtime/foreign events still invalidate the original fence.
        let awaiting_configuration = awaiting_permit
            && preparation.is_some_and(|(received, revision)| {
                self.0
                    .configuration_applied
                    .get()
                    .is_some_and(|proof| proof.matches((received, revision)))
            });
        let reason = if state.sealed || state.integrity_lost {
            Some(Refused::RegistryHealth)
        } else if !self.matches_target(registry, current) {
            Some(Refused::ReceiptBinding)
        } else if current.kind != "page" || current.purpose != Some(TargetPurpose::Application) {
            Some(Refused::ReceiptTarget)
        } else if !current.configured && !awaiting_configuration {
            // Sample once in the actual first-failed branch, before returning.
            Some(self.0.setup_diagnostic.unconfigured_refusal(stage))
        } else if terminal == 2 {
            Some(Refused::ReceiptTerminal)
        } else if !awaiting_permit && !(1..=3).contains(&stage) {
            Some(Refused::ReceiptStage)
        } else if !awaiting_permit
            && stage < 3
            && (!current.resume_pending
                || !current
                    .tenure
                    .retained_initialization
                    .load(Ordering::Acquire))
        {
            Some(Refused::ReceiptCustody)
        } else if stage == 3 && !current.capture_ready() {
            Some(Refused::ReceiptReadiness)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(fail(ProtocolError::ScopeUnavailable, reason));
        }
        Ok(current.clone())
    }
    pub(super) fn same_receipt(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(super) fn completed(&self, registry: &Arc<ClientTargets>) -> Result<bool, ProtocolError> {
        let current = self.current(registry)?;
        let positive = self.0.terminal.load(Ordering::Acquire) == 1;
        if positive
            && (self.0.stage.load(Ordering::Acquire) != 3
                || current
                    .tenure
                    .retained_initialization
                    .load(Ordering::Acquire))
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        Ok(positive)
    }
    pub(super) fn preparation_completed(
        &self,
        registry: &Arc<ClientTargets>,
        boundary: (u64, u64),
    ) -> Result<bool, ProtocolError> {
        if self.0.stage.load(Ordering::Acquire) == 0 {
            self.current_for(registry, Some(boundary))?;
            return Ok(false);
        }
        self.completed(registry)
    }
    fn unsuccessful(&self) {
        let _ = self
            .0
            .terminal
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
    }
}
impl RetainedInitialization {
    pub(super) fn new(registry: Arc<ClientTargets>) -> Self {
        Self {
            registry,
            target: None,
            root: None,
            popup_progress: None,
        }
    }
    pub(super) fn from_received_event(
        registry: Arc<ClientTargets>,
        ledger: Arc<super::client_debt::OwnerDebtLedger>,
        generation: u64,
        stream: super::cdp::client::BoundedEventWatermark,
        event: &super::cdp::client::BoundedCdpEvent,
    ) -> Result<Self, ProtocolError> {
        if !ledger.matches_owner(generation, &registry.identity_scope)
            || !ledger.matches_eval_preparation_stream(&stream)
            || event.sequence() == 0
            || event.sequence() == u64::MAX
            || stream
                .received()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                < event.sequence()
        {
            return Err(ProtocolError::StaleScope);
        }
        let progress = PopupInitializationReceipt(Arc::new(PopupInitializationProgress {
            registry: Arc::downgrade(&registry),
            ledger: Arc::downgrade(&ledger),
            generation,
            stream,
            origin: event.sequence(),
            target: std::sync::OnceLock::new(),
            stage: AtomicU8::new(0),
            terminal: AtomicU8::new(0),
            setup_diagnostic: PopupSetupProgress::default(),
            configuration_applied: std::sync::OnceLock::new(),
        }));
        Ok(Self {
            registry,
            target: None,
            root: None,
            popup_progress: Some(progress),
        })
    }
    pub(super) fn popup_receipt(&self) -> Option<PopupInitializationReceipt> {
        self.popup_progress.clone()
    }
    /// Called only after finish(false) returned for Initialized. The positive
    /// receipt cannot precede the real ResumePermit Drop or custody finish.
    pub(super) fn publish_initialized(&self) {
        let Some(receipt) = &self.popup_progress else {
            return;
        };
        // Failure to certify a receipt must not turn an already-successful
        // initializer into a new error (for example detach just after finish).
        let positive = self.target.is_none()
            && receipt.0.stage.load(Ordering::Acquire) == 3
            && receipt.current(&self.registry).is_ok_and(|current| {
                !current
                    .tenure
                    .retained_initialization
                    .load(Ordering::Acquire)
            });
        if positive {
            let _ = receipt
                .0
                .terminal
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
        } else {
            receipt.unsuccessful();
        }
    }
    pub(super) fn attach(
        &mut self,
        registry: &Arc<ClientTargets>,
        context: &str,
        target: String,
        session: String,
        kind: String,
    ) -> Result<bool, ProtocolError> {
        self.attach_with_root(registry, context, target, session, kind, None)
    }
    pub(super) fn attach_with_root(
        &mut self,
        registry: &Arc<ClientTargets>,
        context: &str,
        target: String,
        session: String,
        kind: String,
        root: Option<OwnedTarget>,
    ) -> Result<bool, ProtocolError> {
        self.attach_with_ancestry(
            registry,
            context,
            target,
            session,
            kind,
            AttachmentAncestry {
                root,
                verified_self_root: false,
            },
        )
    }
    pub(super) fn attach_with_ancestry(
        &mut self,
        registry: &Arc<ClientTargets>,
        context: &str,
        target: String,
        session: String,
        kind: String,
        ancestry: AttachmentAncestry,
    ) -> Result<bool, ProtocolError> {
        self.attach_with_ancestry_observed(
            registry,
            RegistrationAttachment {
                context,
                target,
                session,
                kind,
            },
            ancestry,
            None,
        )
    }
    pub(super) fn attach_with_ancestry_observed(
        &mut self,
        registry: &Arc<ClientTargets>,
        attachment: RegistrationAttachment<'_>,
        ancestry: AttachmentAncestry,
        observation: RegistrationObservation<'_, '_>,
    ) -> Result<bool, ProtocolError> {
        let RegistrationAttachment {
            context,
            target,
            session,
            kind,
        } = attachment;
        let AttachmentAncestry {
            root,
            verified_self_root,
        } = ancestry;
        if self.target.is_some() || !Arc::ptr_eq(&self.registry, registry) {
            return Err(ProtocolError::StaleScope);
        }
        let attached = registry.attach_inner_observed(
            RegistrationAttachment {
                context,
                target,
                session,
                kind,
            },
            AttachmentRegistrationContext {
                retained: true,
                root: root.as_ref(),
                enrolled: true,
                verified_self_root,
            },
            observation,
        )?;
        if let Some(target) = &attached {
            // The registry marked the exact fresh tenure under its insertion
            // lock. No await or fallible work separates insertion and custody.
            if target
                .tenure
                .retained_initialization
                .load(Ordering::Acquire)
            {
                self.target = Some(target.clone());
                self.root = root;
                if let Some(receipt) = &self.popup_progress {
                    receipt
                        .0
                        .target
                        .set(target.clone())
                        .map_err(|_| ProtocolError::StaleScope)?;
                }
            }
        }
        Ok(attached.is_some())
    }
    pub(super) fn finish(&mut self, detached: bool) -> Result<(), ProtocolError> {
        let Some(target) = &self.target else {
            return Ok(());
        };
        let state = self
            .registry
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let original_absent = !state.targets.values().any(|current| {
            current.target_id == target.target_id || current.session_id == target.session_id
        });
        let root_retired = self.root.as_ref().is_some_and(|root| {
            root.tenure.observed_media_detach.load(Ordering::Acquire)
                && !state.targets.values().any(|current| {
                    current.target_id == root.target_id || current.session_id == root.session_id
                })
        });
        let exactly_detached = original_absent
            && (target.tenure.observed_detach.load(Ordering::Acquire)
                || target.tenure.observed_iframe_detach.load(Ordering::Acquire)
                || target.tenure.observed_media_detach.load(Ordering::Acquire)
                || root_retired);
        let valid = exactly_detached
            || (!detached
                && state.targets.get(&target.target_id).is_some_and(|current| {
                    current.same_initialization_attachment(target) && current.capture_ready()
                }));
        if !valid {
            return Err(ProtocolError::ScopeUnavailable);
        }
        target
            .tenure
            .retained_initialization
            .store(false, Ordering::Release);
        drop(state);
        self.target = None;
        Ok(())
    }
    pub(super) fn stop_retired(
        &mut self,
        proof: &super::client_enrollment::ExactOwnerStop,
    ) -> Result<(), ProtocolError> {
        let state = self
            .registry
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if !proof.authorizes_targets(&self.registry) || !state.sealed {
            return Err(ProtocolError::StaleScope);
        }
        // Revoke only ordinary-operation custody. The frozen retirement
        // inventory and all unready attachments/CDP debt remain unchanged.
        if let Some(target) = &self.target {
            target
                .tenure
                .retained_initialization
                .store(false, Ordering::Release);
        }
        drop(state);
        self.target = None;
        Ok(())
    }
}
impl Drop for RetainedInitialization {
    fn drop(&mut self) {
        if let Some(receipt) = &self.popup_progress {
            receipt.unsuccessful();
        }
        if let Some(target) = self.target.take() {
            // Publish loss BEFORE removing custody, including panic/abort.
            self.registry.seal();
            target
                .tenure
                .retained_initialization
                .store(false, Ordering::Release);
        }
    }
}
impl OwnedTarget {
    pub(super) fn same_initialization_attachment(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.tenure, &other.tenure)
            && self.target_id == other.target_id
            && self.session_id == other.session_id
            && self.kind == other.kind
    }
    pub(super) fn diagnostic_snapshot(&self) -> Option<diagnostic::DiagnosticAttachment> {
        let mut value = self.diagnostic?;
        value.kind = diagnostic::DiagnosticTargetKind::from_native(&self.kind);
        value.purpose = match self.purpose {
            None => diagnostic::DiagnosticTargetPurpose::Unclassified,
            Some(TargetPurpose::Application) => diagnostic::DiagnosticTargetPurpose::Application,
            Some(TargetPurpose::StateBootstrap) => {
                diagnostic::DiagnosticTargetPurpose::StateBootstrap
            }
        };
        value.configured = self.configured;
        value.resumed = self.resumed;
        Some(value)
    }
    pub(crate) fn same_attachment(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.tenure, &other.tenure)
            && self.target_id == other.target_id
            && self.session_id == other.session_id
            && self.kind == other.kind
            && self.purpose == other.purpose
            && self.configured == other.configured
            && self.resumed == other.resumed
            && self.resume_pending == other.resume_pending
    }
    pub(crate) fn capture_ready(&self) -> bool {
        self.purpose == Some(TargetPurpose::Application)
            && self.configured
            && self.resumed
            && !self.resume_pending
    }
}
#[derive(Default)]
struct Registry {
    #[cfg(test)]
    inventory_diagnostics_for_test: bool,
    revision: u64,
    query_unknown_revision: u64,
    revision_history: Option<RevisionHistory>,
    sealed: bool,
    integrity_lost: bool,
    first_loss: Option<diagnostic::InventoryFirstLoss>,
    owner_retirement_inventory: Option<bool>,
    reservations: usize,
    creation_sequence: u64,
    bootstrap_creations: HashMap<u64, Option<String>>,
    native_bootstrap_cleanup: HashSet<String>,
    bootstrap_cleanup_reservations: HashSet<u64>,
    unknown_bootstrap_create: bool,
    resuming: usize,
    protected_read: Option<ProtectedExclusion>,
    enrollment_ready: bool,
    targets: HashMap<String, OwnedTarget>,
    diagnostic_identities: Option<HashMap<String, u64>>,
    diagnostic_lost: bool,
    auxiliary_sequence: u64,
    auxiliary: HashMap<u64, AuxiliaryAttachment>,
}
// Opt-in scalar history belongs to this registry only. The empty identity token
// detects cross-registry/reset samples; attachment tokens contain no native IDs.
#[derive(Default)]
struct RevisionHistory {
    identity: Arc<RevisionHistoryIdentity>,
    counts: [u64; 7],
    overflow: bool,
    last_revision: u64,
    last: Option<(
        diagnostic::InventoryRevisionEvent,
        Option<Arc<AttachmentTenure>>,
        Option<u64>,
    )>,
}
#[derive(Default)]
struct RevisionHistoryIdentity;
#[derive(Clone)]
pub(crate) struct RevisionSnapshot {
    identity: Arc<RevisionHistoryIdentity>,
    counts: [u64; 7],
    overflow: bool,
}
// Product classification from the original atomic fence, independent of diagnostics.
pub(crate) struct InventoryRevisionCheck {
    pub result: Result<(), ProtocolError>,
    pub revision_only: bool,
    pub diagnostic: Option<diagnostic::FrameInventoryRejection>,
}
impl Registry {
    fn note_revision_enabled(
        &mut self,
        event: diagnostic::InventoryRevisionEvent,
        attachment: Option<Arc<AttachmentTenure>>,
        attachment_ordinal: Option<u64>,
    ) {
        let history = self
            .revision_history
            .get_or_insert_with(RevisionHistory::default);
        let counter = &mut history.counts[event.index()];
        match counter.checked_add(1) {
            Some(next) => *counter = next,
            None => history.overflow = true,
        }
        history.last_revision = self.revision;
        // Retain the closed ordinal at the same commit as the revision. A later
        // registration emission or identical-text reattachment cannot rewrite it.
        history.last = Some((
            event,
            attachment,
            attachment_ordinal.filter(|value| *value != 0),
        ));
    }
    fn revision_snapshot(&mut self) -> RevisionSnapshot {
        let history = self
            .revision_history
            .get_or_insert_with(RevisionHistory::default);
        RevisionSnapshot {
            identity: history.identity.clone(),
            counts: history.counts,
            overflow: history.overflow,
        }
    }
    fn revision_result(&self, expected: u64) -> Result<(), ProtocolError> {
        if self.sealed || self.revision != expected || self.reservations != 0 {
            Err(ProtocolError::StaleScope)
        } else {
            Ok(())
        }
    }
    fn revision_rejection(
        &self,
        expected: u64,
        before: Option<&RevisionSnapshot>,
        selected: &OwnedTarget,
        pass: diagnostic::FrameInventoryPass,
    ) -> diagnostic::FrameInventoryRejection {
        use diagnostic::{InventoryRevisionEvent as Event, InventoryRevisionTarget as Target};
        let delta = self.revision.checked_sub(expected);
        let history = self.revision_history.as_ref().filter(|history| {
            before.is_some_and(|before| {
                Arc::ptr_eq(&history.identity, &before.identity)
                    && !before.overflow
                    && !history.overflow
            })
        });
        let counts = history.zip(before).and_then(|(history, before)| {
            let mut counts = [0; 7];
            for (index, count) in counts.iter_mut().enumerate() {
                *count = history.counts[index].checked_sub(before.counts[index])?;
            }
            Some(counts)
        });
        let exact = delta.is_some_and(|delta| delta <= u16::MAX as u64)
            && counts.is_some_and(|counts| {
                counts[6] == 0
                    && counts.iter().all(|count| *count <= u16::MAX as u64)
                    && counts
                        .iter()
                        .try_fold(0u64, |sum, count| sum.checked_add(*count))
                        == delta
            });
        let (last_event, last_target, last_attachment) = if delta == Some(0) && counts.is_some() {
            (Event::None, Target::Unknown, None)
        } else if delta.is_some_and(|delta| delta > 0) && counts.is_some() {
            history
                .filter(|history| history.last_revision == self.revision)
                .and_then(|history| history.last.as_ref())
                .map_or(
                    (Event::Unknown, Target::Unknown, None),
                    |(event, attachment, ordinal)| {
                        (
                            *event,
                            attachment.as_ref().map_or(Target::Unknown, |attachment| {
                                if Arc::ptr_eq(attachment, &selected.tenure) {
                                    Target::Same
                                } else {
                                    Target::Other
                                }
                            }),
                            *ordinal,
                        )
                    },
                )
        } else {
            (Event::Unknown, Target::Unknown, None)
        };
        diagnostic::FrameInventoryRejection {
            pass,
            sealed: self.sealed,
            revision_mismatch: self.revision != expected,
            reservations: self.reservations != 0,
            delta: delta.map(|delta| delta.min(u16::MAX as u64) as u16),
            events: counts.map(|counts| counts.map(|count| count.min(u16::MAX as u64) as u16)),
            exact,
            last_event,
            last_target,
            last_attachment,
            selected_attachment: selected
                .diagnostic
                .map(|value| value.attachment)
                .filter(|value| *value != 0),
        }
    }
    // Opt-in history is bounded and cannot return a product error or grant authority.
    fn diagnostic_attachment(&mut self, target: &str) -> Option<diagnostic::DiagnosticAttachment> {
        if !diagnostic::inventory_enabled() {
            #[cfg(not(test))]
            return None;
            #[cfg(test)]
            if !self.inventory_diagnostics_for_test {
                return None;
            }
        }
        let identities = self.diagnostic_identities.get_or_insert_with(HashMap::new);
        let target_ordinal = if let Some(ordinal) = identities.get(target) {
            *ordinal
        } else if identities.len() < 2048 && target.len() <= 1024 {
            let ordinal = diagnostic::next_target_ordinal().unwrap_or(0);
            if ordinal != 0 {
                identities.insert(target.to_owned(), ordinal);
            }
            ordinal
        } else {
            0
        };
        let attachment = diagnostic::next_attachment_ordinal().unwrap_or(0);
        self.diagnostic_lost |= target_ordinal == 0 || attachment == 0;
        Some(diagnostic::DiagnosticAttachment {
            attachment,
            target: target_ordinal,
            classification: if self.reservations == 0 {
                diagnostic::DiagnosticTargetClassification::UnreservedApplication
            } else {
                diagnostic::DiagnosticTargetClassification::PendingReservation
            },
            ..Default::default()
        })
    }
    fn registration_diagnostic(
        &mut self,
        target: &mut OwnedTarget,
        context: &RegistrationDiagnosticContext<'_>,
    ) -> Option<diagnostic::DiagnosticAttachment> {
        let ordinal = |identity: (&str, &str)| {
            if identity == (target.target_id.as_str(), target.session_id.as_str()) {
                return target
                    .diagnostic
                    .map(|value| value.attachment)
                    .filter(|value| *value != 0);
            }
            self.targets
                .get(identity.0)
                .filter(|current| {
                    current.session_id == identity.1
                        && Arc::ptr_eq(&current.tenure.owner, &target.tenure.owner)
                })
                .and_then(|current| current.diagnostic.map(|value| value.attachment))
                .filter(|value| *value != 0)
        };
        let parent = context.parent.map(ordinal).unwrap_or(Some(0));
        let root = context.root.and_then(ordinal);
        let valid = context.lineage_complete && parent.is_some() && root.is_some();
        if let Some(value) = target.diagnostic.as_mut() {
            value.generation = context.generation;
            value.origin = context.origin;
            value.parent = parent.unwrap_or(0);
            value.root = root.unwrap_or(0);
            value.stage = diagnostic::DiagnosticTargetStage::Registered;
        }
        let snapshot = target
            .diagnostic_snapshot()
            .filter(|value| valid && value.attachment != 0 && value.target != 0);
        self.diagnostic_lost |= snapshot.is_none();
        snapshot
    }
    fn diagnostic_inventory(&self) -> diagnostic::InventorySnapshot {
        let mut inventory = diagnostic::DiagnosticTargetInventory {
            observed: !self.diagnostic_lost
                && self.targets.len() <= diagnostic::TARGET_SAMPLE_LIMIT,
            count: self.targets.len(),
            ..Default::default()
        };
        for (index, target) in self.targets.values().enumerate() {
            if index >= diagnostic::TARGET_SAMPLE_LIMIT {
                break;
            }
            inventory.attachments[index] = target.diagnostic_snapshot();
            inventory.observed &=
                inventory.attachments[index].is_some_and(|v| v.attachment > 0 && v.target > 0);
        }
        inventory
            .attachments
            .sort_by_key(|v| v.map_or(u64::MAX, |v| v.attachment));
        diagnostic::InventorySnapshot {
            observed: true,
            sealed: self.sealed,
            integrity_lost: self.integrity_lost,
            first_loss: self.first_loss,
            reservations: self.reservations,
            unconfigured: self
                .targets
                .values()
                .filter(|t| t.purpose.is_none() || !t.configured)
                .count(),
            attachments: diagnostic::inventory_enabled().then_some(inventory),
        }
    }
    fn inventory_complete(&self) -> bool {
        self.reservations == 0
            && self
                .targets
                .values()
                .all(|target| target.purpose.is_some() && target.configured)
    }
    /// Read admission waits for the scope's own enrollment instead of treating
    /// a page's background target work as an unavailable scope. A target that
    /// is still being attached/configured, a resume still in flight, a creation
    /// reservation, or a pending auxiliary/popup claim is normal churn created
    /// by the page being read; it is not evidence that the scope cannot be read.
    /// A configured target whose resume is withheld stays a fail-closed
    /// readiness refusal, a sealed or accounting-lost registry still fails
    /// closed, and the caller's operation deadline still bounds the wait.
    fn read_enrollment_settled(&self) -> bool {
        self.inventory_complete()
            && self.resuming == 0
            && self
                .auxiliary
                .values()
                .all(|entry| entry.detached || entry.claimed_session.is_some())
    }
    fn lose_integrity(&mut self, reason: diagnostic::InventoryFirstLoss) {
        self.first_loss.get_or_insert(reason);
        self.sealed = true;
        self.integrity_lost = true;
    }
}
pub struct ClientTargets {
    pub(crate) protected_read_residual:
        Arc<super::client_protected_read_residual::ProtectedReadResidualSlot>,
    pub context_id: String,
    pub identity_scope: String,
    state: Mutex<Registry>,
    attachment_owner: Arc<()>,
    eval_owner: std::sync::OnceLock<std::sync::Weak<super::client_debt::OwnerDebtLedger>>,
    changed: Notify,
    #[cfg(test)]
    retirement_before_lock: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}
pub struct CreationReservation {
    registry: Arc<ClientTargets>,
    purpose: TargetPurpose,
    bootstrap_nonce: Option<u64>,
    native_created_target: Option<String>,
    claimed: bool,
}
struct AuxiliaryAttachment {
    target: String,
    primary_session: String,
    acknowledged_session: Option<String>,
    claimed_session: Option<String>,
    candidates: HashSet<String>,
    cleanup_owned: HashSet<String>,
    cleanup_acknowledged: HashSet<String>,
    detached: bool,
    terminal_connection_retired: bool,
    failed: bool,
}
/// Retained by the native recording task from before attach dispatch through
/// exact detach acknowledgement. This authority is never exposed on the wire.
pub(crate) struct AuxiliaryAttachmentReservation {
    registry: Arc<ClientTargets>,
    nonce: u64,
    completed: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AuxiliaryDisposition {
    Ordinary,
    RecorderOwned,
}
/// Diagnostic input borrowed from the original enrollment index transaction.
/// No payload identity escapes into the trace; only existing closed ordinals do.
pub(super) struct RegistrationDiagnosticContext<'a> {
    pub generation: u64,
    pub origin: diagnostic::DiagnosticTargetOrigin,
    pub parent: Option<(&'a str, &'a str)>,
    pub root: Option<(&'a str, &'a str)>,
    pub lineage_complete: bool,
}
#[derive(Clone, Copy, Default)]
pub(super) enum RegistrationDiagnosticReceipt {
    #[default]
    NotCommitted,
    Committed(diagnostic::DiagnosticAttachment),
    Lost,
}
impl RegistrationDiagnosticReceipt {
    pub(super) fn snapshot(self) -> Option<diagnostic::DiagnosticAttachment> {
        match self {
            Self::Committed(value) => Some(value),
            _ => None,
        }
    }
    /// Caller must have left all registration locks before this synchronous emit.
    pub(super) fn emit(self, generation: u64, sequence: u64) {
        match self {
            Self::NotCommitted => {}
            Self::Committed(value) => {
                diagnostic::target_lifecycle(generation, sequence, value, None)
            }
            Self::Lost => diagnostic::target_observation_lost(generation, sequence),
        }
    }
}
pub(super) struct RegistrationAttachment<'a> {
    pub context: &'a str,
    pub target: String,
    pub session: String,
    pub kind: String,
}
type RegistrationObservation<'a, 'b> = Option<(
    &'a RegistrationDiagnosticContext<'a>,
    &'b mut RegistrationDiagnosticReceipt,
)>;

pub struct InventoryStamp {
    pub revision: u64,
    pub identity_scope: String,
    pub targets: Vec<OwnedTarget>,
}
pub struct ProtectedTargetBarrier {
    token: Arc<()>,
    registry: Arc<ClientTargets>,
    pub stamp: InventoryStamp,
}
pub struct ResumePermit {
    registry: Arc<ClientTargets>,
    target_id: String,
    session_id: String,
    tenure: Arc<AttachmentTenure>,
    worker_startup: bool,
    completed: bool,
    popup_progress: Option<PopupInitializationReceipt>,
}
impl ProtectedTargetBarrier {
    /// Quarantine exactly the registry captured by this transaction.
    pub fn quarantine(&self) {
        self.registry.seal();
    }
    pub fn check(&self) -> Result<(), ProtocolError> {
        self.registry.check_revision(self.stamp.revision)
    }
}
impl Drop for ProtectedTargetBarrier {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.state.lock() {
            if state
                .protected_read
                .as_ref()
                .is_some_and(|exclusion| exclusion.matches_token(&self.token))
            {
                state.protected_read = None;
            }
        }
        self.registry.changed.notify_waiters();
    }
}
impl ResumePermit {
    /// Observation only: distinguish the retained original attachment from a
    /// reused identity while waiting for its already-received detach to apply.
    pub(super) fn original_worker_attachment_present(&self) -> Result<bool, ProtocolError> {
        let state = self
            .registry
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed || state.integrity_lost || !self.worker_startup || self.completed {
            return Err(ProtocolError::StaleScope);
        }
        match state.targets.get(&self.target_id) {
            Some(target)
                if target.session_id == self.session_id
                    && Arc::ptr_eq(&target.tenure, &self.tenure) =>
            {
                Ok(true)
            }
            None if !state
                .targets
                .values()
                .any(|target| target.session_id == self.session_id) =>
            {
                Ok(false)
            }
            _ => Err(ProtocolError::StaleScope),
        }
    }
    /// Only the CDP retirement consumer calls this while holding the original
    /// ledger. Do not call eval_invalidation or drop this permit in that scope.
    pub(super) fn finish_retired_worker_startup(
        &mut self,
        registry: &Arc<ClientTargets>,
        target: &str,
        session: &str,
        check_bounds: impl FnOnce() -> Result<(), ProtocolError>,
    ) -> Result<(), ProtocolError> {
        if !Arc::ptr_eq(&self.registry, registry)
            || !self.worker_startup
            || self.completed
            || self.target_id != target
            || self.session_id != session
        {
            return Err(ProtocolError::StaleScope);
        }
        #[cfg(test)]
        if let Some(entered) = registry.retirement_before_lock.lock().unwrap().take() {
            let _ = entered.send(());
        }
        let state = registry
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed
            || state.integrity_lost
            || state
                .protected_read
                .as_ref()
                .is_some_and(|exclusion| exclusion.excludes_tenure(&self.tenure))
            || state.resuming == 0
            || !self.tenure.observed_detach.load(Ordering::Acquire)
            || state
                .targets
                .values()
                .any(|entry| entry.target_id == target || entry.session_id == session)
        {
            return Err(ProtocolError::StaleScope);
        }
        // Retirement publishes neither configured nor resumed. Drop releases the
        // original resuming reservation after the outer locks have all gone.
        check_bounds()?;
        self.completed = true;
        Ok(())
    }
    /// Normal all-ACK completion runs under the original transport/ledger
    /// fence. This non-consuming method cannot poison via Drop on a lost target.
    pub(super) fn complete_acknowledged_worker_startup(
        &mut self,
        registry: &Arc<ClientTargets>,
        target: &str,
        session: &str,
        check_bounds: impl FnOnce() -> Result<(), ProtocolError>,
    ) -> Result<Option<diagnostic::DiagnosticAttachment>, ProtocolError> {
        if !Arc::ptr_eq(&self.registry, registry)
            || !self.worker_startup
            || self.completed
            || self.target_id != target
            || self.session_id != session
        {
            return Err(ProtocolError::StaleScope);
        }
        #[cfg(test)]
        if let Some(entered) = registry.retirement_before_lock.lock().unwrap().take() {
            let _ = entered.send(());
        }
        let mut state = registry
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.integrity_lost || state.live_resume_excluded(&self.tenure) || state.resuming == 0 {
            return Err(ProtocolError::StaleScope);
        }
        self.complete_locked(&mut state, check_bounds)
    }
    fn complete_locked(
        &mut self,
        state: &mut Registry,
        check_bounds: impl FnOnce() -> Result<(), ProtocolError>,
    ) -> Result<Option<diagnostic::DiagnosticAttachment>, ProtocolError> {
        if state.sealed {
            return Err(ProtocolError::StaleScope);
        }
        let target = state
            .targets
            .get_mut(&self.target_id)
            .ok_or(ProtocolError::StaleReference)?;
        if target.session_id != self.session_id
            || !Arc::ptr_eq(&target.tenure, &self.tenure)
            || !target.resume_pending
            || target.resumed
            || (!self.worker_startup && !target.configured)
            || (self.worker_startup
                && (target.kind != "service_worker"
                    || target.purpose != Some(TargetPurpose::Application)
                    || target.configured))
        {
            state.lose_integrity(diagnostic::InventoryFirstLoss::ResumeIdentityMismatch);
            return Err(ProtocolError::StaleScope);
        }
        check_bounds()?;
        // The caller retains this permit until the entire fixed startup
        // batch acknowledges. No earlier step advertises full readiness.
        if self.worker_startup {
            target.configured = true;
        }
        target.resumed = true;
        if let Some(value) = &mut target.diagnostic {
            value.stage = diagnostic::DiagnosticTargetStage::Resumed;
        }
        let observed = target.diagnostic_snapshot();
        self.completed = true;
        Ok(observed)
    }
    pub(super) fn complete_retained(&mut self) -> Result<(), ProtocolError> {
        let registry = self.registry.clone();
        let receipt = self.popup_progress.clone();
        let observed = registry.eval_popup_invalidation(receipt.as_ref(), || {
            let Ok(mut state) = registry.state.lock() else {
                return (Err(ProtocolError::ScopeUnavailable), false);
            };
            let eligible = !state.sealed
                && !state.integrity_lost
                && state.resuming > 0
                && receipt.as_ref().is_some_and(|receipt| {
                    state.targets.get(&self.target_id).is_some_and(|target| {
                        receipt.matches_target(&registry, target)
                            && target.kind == "page"
                            && target.purpose == Some(TargetPurpose::Application)
                            && target
                                .tenure
                                .retained_initialization
                                .load(Ordering::Acquire)
                    })
                });
            let result = self.complete_locked(&mut state, || Ok(()));
            let known = eligible
                && result.is_ok()
                && receipt.as_ref().is_some_and(|receipt| {
                    receipt
                        .0
                        .stage
                        .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                });
            (result, known)
        })?;
        if let Some(value) = observed {
            diagnostic::target_lifecycle(value.generation, 0, value, None);
        }
        Ok(())
    }
    pub fn complete(mut self) -> Result<(), ProtocolError> {
        self.complete_retained()
    }
}
impl Drop for ResumePermit {
    fn drop(&mut self) {
        let registry = self.registry.clone();
        let receipt = self.popup_progress.clone();
        registry.eval_popup_invalidation(receipt.as_ref(), || {
            let mut known = false;
            if let Ok(mut state) = self.registry.state.lock() {
                let eligible =
                    self.completed && !state.sealed && !state.integrity_lost && state.resuming > 0;
                if let Some(target) = state.targets.get_mut(&self.target_id) {
                    if target.session_id == self.session_id
                        && Arc::ptr_eq(&target.tenure, &self.tenure)
                    {
                        known = eligible
                            && target.resume_pending
                            && target.resumed
                            && target.configured
                            && target
                                .tenure
                                .retained_initialization
                                .load(Ordering::Acquire)
                            && receipt.as_ref().is_some_and(|receipt| {
                                receipt.matches_target(&registry, target)
                                    && receipt
                                        .0
                                        .stage
                                        .compare_exchange(2, 3, Ordering::AcqRel, Ordering::Acquire)
                                        .is_ok()
                            });
                        target.resume_pending = false;
                    }
                }
                state.resuming = state.resuming.saturating_sub(1);
                if !self.completed {
                    state.lose_integrity(diagnostic::InventoryFirstLoss::ResumePermitDropped);
                }
            }
            self.registry.changed.notify_waiters();
            ((), known)
        })
    }
}
impl ClientTargets {
    pub fn new(context_id: String, identity_scope: String) -> Arc<Self> {
        Self::with_protected_read_mode(
            context_id,
            identity_scope,
            super::client_protected_read_residual::BindingMode::LegacyRecordOnly,
        )
    }
    pub(crate) fn new_managed(context_id: String, identity_scope: String) -> Arc<Self> {
        Self::with_protected_read_mode(
            context_id,
            identity_scope,
            super::client_protected_read_residual::BindingMode::Managed,
        )
    }
    fn with_protected_read_mode(
        context_id: String,
        identity_scope: String,
        mode: super::client_protected_read_residual::BindingMode,
    ) -> Arc<Self> {
        Arc::new(Self {
            protected_read_residual: Arc::new(
                super::client_protected_read_residual::ProtectedReadResidualSlot::new(
                    mode,
                    context_id.clone(),
                    identity_scope.clone(),
                ),
            ),
            context_id,
            identity_scope,
            state: Mutex::new(Registry::default()),
            attachment_owner: Arc::new(()),
            eval_owner: std::sync::OnceLock::new(),
            changed: Notify::new(),
            #[cfg(test)]
            retirement_before_lock: Mutex::new(None),
        })
    }
    /// Owned, test-only observation opt-in, before any registration. This flag
    /// cannot grant target/configuration/read authority or alter another registry.
    #[cfg(test)]
    pub(crate) fn enable_inventory_diagnostics_for_test(&self) {
        let mut state = self.state.lock().unwrap();
        assert!(state.targets.is_empty() && state.revision_history.is_none());
        assert_eq!(state.revision, 0);
        state.inventory_diagnostics_for_test = true;
    }
    /// Deterministic final-lock race fixture; absent from production builds.
    #[cfg(test)]
    pub(crate) fn with_worker_retirement_lock_for_test(
        &self,
        entered: std::sync::mpsc::Sender<()>,
        held: impl FnOnce(),
    ) {
        *self.retirement_before_lock.lock().unwrap() = Some(entered);
        let _state = self.state.lock().unwrap();
        held();
    }
    pub(crate) fn bind_eval_owner(
        &self,
        ledger: &Arc<super::client_debt::OwnerDebtLedger>,
        generation: u64,
    ) -> Result<(), ProtocolError> {
        if !ledger.matches_owner(generation, &self.identity_scope) {
            return Err(ProtocolError::StaleScope);
        }
        if let Some(owner) = self.eval_owner.get() {
            if owner
                .upgrade()
                .is_none_or(|owner| !Arc::ptr_eq(&owner, ledger))
            {
                return Err(ProtocolError::StaleScope);
            }
            return Ok(());
        }
        self.eval_owner
            .set(Arc::downgrade(ledger))
            .map_err(|_| ProtocolError::ScopeUnavailable)
    }
    /// Best-effort diagnostic snapshot only. Never waits or changes registry state.
    pub(crate) fn eval_diagnostic_targets<'a>(
        &self,
        pending: impl Iterator<Item = (&'a str, &'a str)>,
        root_target: &str,
        root_session: &str,
    ) -> Option<([u16; 3], bool)> {
        let state = self.state.try_lock().ok()?;
        let mut counts = [0u16; 3];
        for (target, session) in pending {
            if let Some(target) = state
                .targets
                .get(target)
                .filter(|target| target.session_id == session)
            {
                counts[0] = counts[0].checked_add(u16::from(target.resume_pending))?;
                counts[1] = counts[1].checked_add(u16::from(
                    target
                        .tenure
                        .retained_initialization
                        .load(Ordering::Acquire),
                ))?;
            } else {
                counts[2] = counts[2].checked_add(1)?;
            }
        }
        let root_ready = state
            .targets
            .get(root_target)
            .is_some_and(|target| target.session_id == root_session && target.capture_ready());
        Some((counts, root_ready))
    }
    pub(crate) fn require_eval_owner(
        &self,
        ledger: &Arc<super::client_debt::OwnerDebtLedger>,
    ) -> Result<(), ProtocolError> {
        if self
            .eval_owner
            .get()
            .and_then(std::sync::Weak::upgrade)
            .is_some_and(|owner| Arc::ptr_eq(&owner, ledger))
        {
            Ok(())
        } else {
            Err(ProtocolError::StaleScope)
        }
    }
    /// Called before taking state: initialization already uses ledger -> targets.
    fn eval_invalidation<T>(&self, mutation: impl FnOnce(&mut dyn FnMut()) -> T) -> T {
        if let Some(owner) = self.eval_owner.get().and_then(std::sync::Weak::upgrade) {
            owner.with_eval_target_invalidation(mutation)
        } else {
            // No eval grant can exist without the exact live owner binding.
            mutation(&mut || {})
        }
    }
    fn eval_popup_invalidation<T>(
        &self,
        receipt: Option<&PopupInitializationReceipt>,
        mutation: impl FnOnce() -> (T, bool),
    ) -> T {
        if let Some(owner) = self.eval_owner.get().and_then(std::sync::Weak::upgrade) {
            owner.with_eval_popup_progress(receipt, mutation)
        } else {
            mutation().0
        }
    }
    /// Lifecycle owner calls this only after bounded event routing and recursive
    /// target attachment barriers are installed and initial inventory reconciled.
    pub fn acknowledge_enrollment(&self) -> Result<(), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed
            || state.reservations != 0
            || state.resuming != 0
            || state.protected_read.is_some()
            || state
                .targets
                .values()
                .any(|target| target.purpose.is_none() || !target.configured || !target.resumed)
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        state.enrollment_ready = true;
        Ok(())
    }
    /// Final publication uses index -> targets -> execution-gate ordering.
    /// Holding this registry guard prevents independent auxiliary/creation
    /// retirement from sealing targets between the health check and publish.
    pub(crate) fn publish_initialization(
        self: &Arc<Self>,
        authority: &super::client_browser::LifecycleInitialization,
    ) -> Result<u64, ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed
            || !state.enrollment_ready
            || state.reservations != 0
            || state.resuming != 0
            || state.protected_read.is_some()
            || state
                .targets
                .values()
                .any(|target| target.purpose.is_none() || !target.configured || !target.resumed)
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        drop(authority.enter(self)?);
        authority.publish()
    }
    pub fn protected_read_barrier(
        self: &Arc<Self>,
    ) -> Result<ProtectedTargetBarrier, ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed
            || !state.enrollment_ready
            || state.protected_read.is_some()
            || state.reservations != 0
            || state.resuming != 0
            || state
                .auxiliary
                .values()
                .any(|entry| !entry.detached && entry.claimed_session.is_none())
            || state
                .targets
                .values()
                .any(|target| !target.configured || !target.resumed)
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let token = Arc::new(());
        state.protected_read = Some(ProtectedExclusion::Global {
            token: token.clone(),
        });
        Ok(ProtectedTargetBarrier {
            token,
            registry: self.clone(),
            stamp: InventoryStamp {
                revision: state.revision,
                identity_scope: self.identity_scope.clone(),
                targets: state.targets.values().cloned().collect(),
            },
        })
    }
    /// Hold through Runtime.runIfWaitingForDebugger acknowledgement. Capture
    /// cannot enter between its admission and actual browser completion.
    pub async fn resume_permit(
        self: &Arc<Self>,
        target_id: &str,
    ) -> Result<ResumePermit, ProtocolError> {
        self.resume_permit_inner(target_id, None, None).await
    }

    /// A service worker can exist before its renderer is ready. Security
    /// controls are acknowledged by enrollment before this private admission;
    /// full configuration remains false until the retained startup batch ends.
    pub(crate) async fn service_worker_startup_permit(
        self: &Arc<Self>,
        target_id: &str,
        session_id: &str,
    ) -> Result<ResumePermit, ProtocolError> {
        self.resume_permit_inner(target_id, Some(session_id), None)
            .await
    }

    pub(super) async fn popup_resume_permit(
        self: &Arc<Self>,
        target_id: &str,
        receipt: &PopupInitializationReceipt,
    ) -> Result<ResumePermit, ProtocolError> {
        self.resume_permit_inner(target_id, None, Some(receipt))
            .await
    }
    async fn resume_permit_inner(
        self: &Arc<Self>,
        target_id: &str,
        worker_session: Option<&str>,
        popup: Option<&PopupInitializationReceipt>,
    ) -> Result<ResumePermit, ProtocolError> {
        let mut expected_tenure = None;
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if state.sealed {
                    return Err(ProtocolError::StaleScope);
                }
                let target = state
                    .targets
                    .get(target_id)
                    .ok_or(ProtocolError::StaleReference)?;
                if let Some(expected) = &expected_tenure {
                    if !Arc::ptr_eq(expected, &target.tenure) {
                        return Err(ProtocolError::StaleScope);
                    }
                } else {
                    expected_tenure = Some(target.tenure.clone());
                }
                let eligible = match worker_session {
                    Some(session) => {
                        target.session_id == session
                            && target.kind == "service_worker"
                            && target.purpose == Some(TargetPurpose::Application)
                            && !target.configured
                    }
                    None => target.configured,
                };
                if !eligible || target.resumed || target.resume_pending {
                    return Err(ProtocolError::InvalidArguments);
                }
                if !state.live_resume_excluded(&target.tenure) {
                    let session_id = target.session_id.clone();
                    let tenure = target.tenure.clone();
                    let resuming = state
                        .resuming
                        .checked_add(1)
                        .ok_or(ProtocolError::CapacityExceeded)?;
                    if let Some(receipt) = popup {
                        if !receipt.matches_target(self, target)
                            || target.kind != "page"
                            || target.purpose != Some(TargetPurpose::Application)
                            || !target
                                .tenure
                                .retained_initialization
                                .load(Ordering::Acquire)
                            || receipt.0.terminal.load(Ordering::Acquire) != 0
                            || receipt
                                .0
                                .stage
                                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                                .is_err()
                        {
                            return Err(ProtocolError::StaleScope);
                        }
                    }
                    state
                        .targets
                        .get_mut(target_id)
                        .ok_or(ProtocolError::StaleReference)?
                        .resume_pending = true;
                    state.resuming = resuming;
                    return Ok(ResumePermit {
                        registry: self.clone(),
                        target_id: target_id.into(),
                        session_id,
                        tenure,
                        worker_startup: worker_session.is_some(),
                        completed: false,
                        popup_progress: popup.cloned(),
                    });
                }
            }
            changed.await;
        }
    }
    pub fn reserve_creation(
        self: &Arc<Self>,
        purpose: TargetPurpose,
    ) -> Result<CreationReservation, ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed || state.protected_read.is_some() {
            return Err(ProtocolError::StaleScope);
        }
        let reservations = state
            .reservations
            .checked_add(1)
            .ok_or(ProtocolError::CapacityExceeded)?;
        let bootstrap_nonce = if purpose == TargetPurpose::StateBootstrap {
            if state.bootstrap_creations.len() >= 64
                || state.native_bootstrap_cleanup.len() + state.bootstrap_cleanup_reservations.len()
                    >= 64
            {
                return Err(ProtocolError::CapacityExceeded);
            }
            let nonce = state
                .creation_sequence
                .checked_add(1)
                .ok_or(ProtocolError::IdentifierExhausted)?;
            state.creation_sequence = nonce;
            state.bootstrap_creations.insert(nonce, None);
            state.bootstrap_cleanup_reservations.insert(nonce);
            Some(nonce)
        } else {
            None
        };
        state.reservations = reservations;
        Ok(CreationReservation {
            registry: self.clone(),
            purpose,
            bootstrap_nonce,
            native_created_target: None,
            claimed: false,
        })
    }
    /// Exact native-created temporary resources remain owned after reservation
    /// completion, until the state owner proves close ACK or inventory absence.
    pub(crate) fn native_bootstrap_cleanup_complete(&self) -> Result<bool, ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?;
        Ok(!state.unknown_bootstrap_create
            && state.native_bootstrap_cleanup.is_empty()
            && state.bootstrap_cleanup_reservations.is_empty())
    }
    pub(crate) fn native_bootstrap_cleanup_targets(&self) -> Result<Vec<String>, ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?;
        let mut targets = state
            .native_bootstrap_cleanup
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        targets.sort();
        Ok(targets)
    }
    pub(crate) fn settle_native_bootstrap_cleanup(
        &self,
        target: &str,
    ) -> Result<(), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?;
        if !state.native_bootstrap_cleanup.remove(target) {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    /// Exact ACK-bound native bootstrap admission, never context-wide adoption.
    pub(crate) fn is_native_bootstrap_target(&self, target: &str) -> Result<bool, ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed {
            return Ok(false);
        }
        Ok(state
            .bootstrap_creations
            .values()
            .any(|id| id.as_deref() == Some(target)))
    }
    pub(crate) async fn wait_native_bootstrap_target(
        &self,
        target: &str,
    ) -> Result<bool, ProtocolError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if state.sealed {
                    return Ok(false);
                }
                if state
                    .bootstrap_creations
                    .values()
                    .any(|id| id.as_deref() == Some(target))
                {
                    return Ok(true);
                }
                if !state.bootstrap_creations.values().any(Option::is_none) {
                    return Ok(false);
                }
            }
            changed.await;
        }
    }
    pub(crate) fn reserve_auxiliary_attachment(
        self: &Arc<Self>,
        expected_scope: &str,
        target_id: &str,
        primary_session: &str,
    ) -> Result<AuxiliaryAttachmentReservation, ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if expected_scope != self.identity_scope || state.sealed {
            return Err(ProtocolError::StaleScope);
        }
        let target = state
            .targets
            .get(target_id)
            .ok_or(ProtocolError::StaleReference)?;
        if target.session_id != primary_session
            || target.purpose != Some(TargetPurpose::Application)
            || !target.resumed
            || !target.configured
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if state.protected_read.is_some()
            || state
                .auxiliary
                .values()
                .any(|entry| entry.target == target_id && !entry.detached)
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        // Retain exact-session tombstones for the entire scope tenure. A delayed
        // attach event after detach ACK must never regain generic ownership.
        if state.auxiliary.len() >= 1024 {
            return Err(ProtocolError::CapacityExceeded);
        }
        let nonce = state
            .auxiliary_sequence
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        state.auxiliary_sequence = nonce;
        state.auxiliary.insert(
            nonce,
            AuxiliaryAttachment {
                target: target_id.into(),
                primary_session: primary_session.into(),
                acknowledged_session: None,
                claimed_session: None,
                candidates: HashSet::new(),
                cleanup_owned: HashSet::new(),
                cleanup_acknowledged: HashSet::new(),
                detached: false,
                terminal_connection_retired: false,
                failed: false,
            },
        );
        Ok(AuxiliaryAttachmentReservation {
            registry: self.clone(),
            nonce,
            completed: false,
        })
    }
    /// Resolve only against the attach RPC's exact returned session. Receipt of
    /// a same-target event alone never gives the recorder ownership of it.
    pub(crate) async fn classify_auxiliary_attachment(
        &self,
        target_id: &str,
        session_id: &str,
    ) -> Result<AuxiliaryDisposition, ProtocolError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let disposition = self.eval_invalidation(|revoke| {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if state.auxiliary.values().any(|entry| {
                    entry.target == target_id
                        && (entry.acknowledged_session.as_deref() == Some(session_id)
                            || entry.cleanup_owned.contains(session_id))
                }) {
                    return Ok(Some(AuxiliaryDisposition::RecorderOwned));
                }
                let sealed = state.sealed;
                let pending = state.auxiliary.values_mut().find(|entry| {
                    entry.target == target_id
                        && entry.acknowledged_session.is_none()
                        && !entry.detached
                });
                let Some(pending) = pending else {
                    return Ok(Some(AuxiliaryDisposition::Ordinary));
                };
                if pending.primary_session == session_id {
                    return Ok(Some(AuxiliaryDisposition::Ordinary));
                }
                if session_id.is_empty() || session_id.len() > 1024 {
                    return Err(ProtocolError::InvalidFrame);
                }
                if pending.candidates.len() >= 64 && !pending.candidates.contains(session_id) {
                    revoke();
                    pending.failed = true;
                    state.lose_integrity(diagnostic::InventoryFirstLoss::AuxiliaryCapacity);
                    self.changed.notify_waiters();
                    return Err(ProtocolError::CapacityExceeded);
                }
                if !pending.candidates.contains(session_id) {
                    revoke();
                    pending.candidates.insert(session_id.into());
                }
                if sealed || pending.failed {
                    // The retained recorder supervisor, not generic enrollment,
                    // owns this candidate's detach. A later exact ACK must not
                    // create a second concurrent cleanup owner.
                    if !pending.cleanup_owned.contains(session_id) {
                        revoke();
                        pending.cleanup_owned.insert(session_id.into());
                    }
                    return Ok(Some(AuxiliaryDisposition::RecorderOwned));
                }
                Ok(None)
            })?;
            if let Some(disposition) = disposition {
                return Ok(disposition);
            }
            changed.await;
        }
    }
    pub(crate) fn auxiliary_cleanup_complete(&self) -> Result<bool, ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?;
        Ok(state.auxiliary.values().all(|entry| {
            entry.detached
                && entry.cleanup_owned.iter().all(|session| {
                    entry.acknowledged_session.as_deref() == Some(session)
                        || entry.cleanup_acknowledged.contains(session)
                })
        }))
    }
    /// Retirement checks exact auxiliary cleanup evidence instead of racing
    /// the retained recorder owner with another detach. None is generic-owned.
    pub(crate) fn auxiliary_detach_acknowledged(
        &self,
        target_id: &str,
        session_id: &str,
    ) -> Result<Option<bool>, ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?;
        for entry in state
            .auxiliary
            .values()
            .filter(|entry| entry.target == target_id)
        {
            if entry.acknowledged_session.as_deref() == Some(session_id) {
                return Ok(Some(entry.detached));
            }
            if entry.cleanup_owned.contains(session_id) {
                return Ok(Some(entry.cleanup_acknowledged.contains(session_id)));
            }
        }
        Ok(None)
    }
    /// Return false for another tenant without registering or configuring it.
    pub fn attached(
        &self,
        context_id: &str,
        target_id: String,
        session_id: String,
        kind: String,
    ) -> Result<bool, ProtocolError> {
        self.attach_inner(
            context_id,
            target_id,
            session_id,
            kind,
            AttachmentRegistrationContext {
                retained: false,
                root: None,
                enrolled: false,
                verified_self_root: false,
            },
        )
        .map(|target| target.is_some())
    }
    pub(super) fn attached_enrolled(
        &self,
        context: &str,
        target: String,
        session: String,
        kind: String,
        root: Option<&OwnedTarget>,
    ) -> Result<bool, ProtocolError> {
        self.attached_enrolled_with_ancestry(context, target, session, kind, root, false)
    }
    pub(super) fn attached_enrolled_with_ancestry(
        &self,
        context: &str,
        target: String,
        session: String,
        kind: String,
        root: Option<&OwnedTarget>,
        verified_self_root: bool,
    ) -> Result<bool, ProtocolError> {
        self.attach_inner(
            context,
            target,
            session,
            kind,
            AttachmentRegistrationContext {
                retained: false,
                root,
                enrolled: true,
                verified_self_root,
            },
        )
        .map(|target| target.is_some())
    }
    pub(super) fn attached_enrolled_observed(
        &self,
        attachment: RegistrationAttachment<'_>,
        root: Option<&OwnedTarget>,
        verified_self_root: bool,
        observation: RegistrationObservation<'_, '_>,
    ) -> Result<bool, ProtocolError> {
        let RegistrationAttachment {
            context,
            target,
            session,
            kind,
        } = attachment;
        self.attach_inner_observed(
            RegistrationAttachment {
                context,
                target,
                session,
                kind,
            },
            AttachmentRegistrationContext {
                retained: false,
                root,
                enrolled: true,
                verified_self_root,
            },
            observation,
        )
        .map(|target| target.is_some())
    }
    fn attach_inner(
        &self,
        context_id: &str,
        target_id: String,
        session_id: String,
        kind: String,
        context: AttachmentRegistrationContext<'_>,
    ) -> Result<Option<OwnedTarget>, ProtocolError> {
        self.attach_inner_observed(
            RegistrationAttachment {
                context: context_id,
                target: target_id,
                session: session_id,
                kind,
            },
            context,
            None,
        )
    }
    fn attach_inner_observed(
        &self,
        attachment: RegistrationAttachment<'_>,
        context: AttachmentRegistrationContext<'_>,
        observation: RegistrationObservation<'_, '_>,
    ) -> Result<Option<OwnedTarget>, ProtocolError> {
        let RegistrationAttachment {
            context: context_id,
            target: target_id,
            session: session_id,
            kind,
        } = attachment;
        let AttachmentRegistrationContext {
            retained,
            root,
            enrolled,
            verified_self_root,
        } = context;
        if context_id != self.context_id {
            return Ok(None);
        }
        self.eval_invalidation(|revoke| {
            revoke();
            let mut state = self
                .state
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if state.sealed {
                return Err(ProtocolError::StaleScope);
            }
            if state.targets.len() >= 1024 {
                return Err(ProtocolError::CapacityExceeded);
            }
            if target_id.is_empty()
                || session_id.is_empty()
                || state.targets.contains_key(&target_id)
                || state
                    .targets
                    .values()
                    .any(|target| target.session_id == session_id)
            {
                return Err(ProtocolError::InvalidArguments);
            }
            if let Some(root) = root {
                if root.kind != "page"
                    || !Arc::ptr_eq(&root.tenure.owner, &self.attachment_owner)
                    || !state
                        .targets
                        .get(&root.target_id)
                        .is_some_and(|current| current.same_initialization_attachment(root))
                {
                    return Err(ProtocolError::StaleScope);
                }
            }
            let lineage = if enrolled {
                AttachmentLineage::enrolled(&kind, root, verified_self_root)?
            } else {
                AttachmentLineage::Unknown
            };
            let purpose = if state.reservations == 0 {
                Some(TargetPurpose::Application)
            } else {
                None
            };
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or(ProtocolError::IdentifierExhausted)?;
            state.note_query_membership_change(&lineage)?;
            let diagnostic = state.diagnostic_attachment(&target_id);
            let tenure = Arc::new(AttachmentTenure {
                lineage,
                owner: self.attachment_owner.clone(),
                retained_initialization: AtomicBool::new(
                    retained && purpose == Some(TargetPurpose::Application),
                ),
                ..Default::default()
            });
            let observed_tenure = diagnostic::inventory_enabled().then(|| tenure.clone());
            #[cfg(test)]
            let observed_tenure = observed_tenure
                .or_else(|| state.inventory_diagnostics_for_test.then(|| tenure.clone()));
            let mut target = OwnedTarget {
                target_id,
                session_id,
                kind,
                purpose,
                configured: false,
                resumed: false,
                resume_pending: false,
                tenure,
                diagnostic,
            };
            let observed = observation.map(|(context, slot)| {
                let snapshot = state.registration_diagnostic(&mut target, context);
                (slot, snapshot)
            });
            state
                .targets
                .insert(target.target_id.clone(), target.clone());
            // Written at the actual commit, before any fallible custody/index work.
            if let Some((slot, snapshot)) = observed {
                *slot = snapshot.map_or(
                    RegistrationDiagnosticReceipt::Lost,
                    RegistrationDiagnosticReceipt::Committed,
                );
            }
            if let Some(tenure) = observed_tenure {
                state.note_revision_enabled(
                    diagnostic::InventoryRevisionEvent::Attach,
                    Some(tenure),
                    target.diagnostic.map(|value| value.attachment),
                );
            }
            drop(state);
            self.changed.notify_waiters();
            Ok(Some(target))
        })
    }
    /// The create reply and attach event may arrive in either order. The
    /// lifecycle supervisor retains this wait under its original deadline.
    pub async fn wait_attached(&self, target_id: &str) -> Result<(), ProtocolError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if state.sealed {
                    return Err(ProtocolError::StaleScope);
                }
                if state.targets.contains_key(target_id) {
                    return Ok(());
                }
            }
            changed.await;
        }
    }
    pub async fn purpose(&self, target_id: &str) -> Result<TargetPurpose, ProtocolError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if state.sealed {
                    return Err(ProtocolError::StaleScope);
                }
                let target = state
                    .targets
                    .get(target_id)
                    .ok_or(ProtocolError::StaleReference)?;
                if let Some(purpose) = target.purpose {
                    return Ok(purpose);
                }
            }
            changed.await;
        }
    }
    /// Identity comparison for an already-sealed immutable observation only.
    /// A cleanup quarantine blocks new browser authority, not this comparison.
    /// Removal or replacement still invalidates the exact attachment.
    pub(crate) fn retains_exact_attachment(&self, captured: &OwnedTarget) -> bool {
        self.state.lock().is_ok_and(|state| {
            state
                .targets
                .get(&captured.target_id)
                .is_some_and(|current| captured.same_attachment(current))
        })
    }

    /// Return only the exact attachment after creation purpose is claimed.
    pub fn owned_target(&self, target_id: &str) -> Result<OwnedTarget, ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed {
            return Err(ProtocolError::StaleScope);
        }
        let target = state
            .targets
            .get(target_id)
            .ok_or(ProtocolError::StaleReference)?;
        if target.purpose.is_none() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        Ok(target.clone())
    }
    /// Snapshot the already-owned Application set, never mint capture authority.
    /// Callers hold their enrollment index before this registry (no await).
    pub(crate) fn capture_application_tickets(
        &self,
        target_ids: &[&str],
    ) -> Result<Vec<OwnedTarget>, ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed {
            return Err(ProtocolError::StaleScope);
        }
        let mut seen = HashSet::new();
        let mut tickets = Vec::with_capacity(target_ids.len());
        for target_id in target_ids {
            let target = state
                .targets
                .get(*target_id)
                .ok_or(ProtocolError::StaleScope)?;
            if !seen.insert(*target_id) || !target.capture_ready() {
                return Err(ProtocolError::StaleScope);
            }
            tickets.push(target.clone());
        }
        if state
            .targets
            .values()
            .filter(|target| target.purpose == Some(TargetPurpose::Application))
            .count()
            != tickets.len()
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(tickets)
    }
    /// A saved state is attributed to page/iframe documents only. Auxiliary
    /// browser targets (browser/tab/browser_ui) render no page document and own
    /// no origin storage, so their retirement or replacement must not
    /// invalidate an otherwise stable capture; every document ticket is still
    /// checked exactly, including the sealed and attachment-tenure fence.
    pub(crate) fn check_capture_document_tickets(
        &self,
        tickets: &[OwnedTarget],
    ) -> Result<(), ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed
            || state
                .targets
                .values()
                .filter(|target| {
                    target.purpose == Some(TargetPurpose::Application)
                        && !super::client_enrollment::capture_auxiliary_kind(&target.kind)
                })
                .count()
                != tickets.len()
        {
            return Err(ProtocolError::StaleScope);
        }
        let mut seen = HashSet::new();
        for ticket in tickets {
            let unique = seen.insert(&ticket.target_id);
            let ready = ticket.capture_ready();
            let same = state
                .targets
                .get(&ticket.target_id)
                .is_some_and(|current| current.same_attachment(ticket));
            if !unique || !ready || !same {
                return Err(ProtocolError::StaleScope);
            }
        }
        Ok(())
    }
    /// No registry-wide revision fence: unrelated StateBootstrap churn is valid.
    pub(crate) fn check_capture_tickets(
        &self,
        tickets: &[OwnedTarget],
    ) -> Result<(), ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed
            || state
                .targets
                .values()
                .filter(|target| target.purpose == Some(TargetPurpose::Application))
                .count()
                != tickets.len()
        {
            return Err(ProtocolError::StaleScope);
        }
        let mut seen = HashSet::new();
        for ticket in tickets {
            if !seen.insert(&ticket.target_id)
                || !ticket.capture_ready()
                || !state
                    .targets
                    .get(&ticket.target_id)
                    .is_some_and(|current| current.same_attachment(ticket))
            {
                return Err(ProtocolError::StaleScope);
            }
        }
        Ok(())
    }
    pub fn configured(&self, target_id: &str) -> Result<(), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed {
            return Err(ProtocolError::StaleScope);
        }
        let target = state
            .targets
            .get_mut(target_id)
            .ok_or(ProtocolError::StaleReference)?;
        if target.purpose.is_none() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        target.configured = true;
        if let Some(value) = &mut target.diagnostic {
            value.stage = diagnostic::DiagnosticTargetStage::ConfigureAck;
        }
        let observed = target.diagnostic_snapshot();
        drop(state);
        if let Some(value) = observed {
            diagnostic::target_lifecycle(value.generation, 0, value, None);
        }
        Ok(())
    }
    /// Called only for the event's directly matched worker entry, before its
    /// removal. Cascading/targetDestroyed cleanup never manufactures this bit.
    pub(super) fn observe_worker_detach(
        &self,
        target: &str,
        session: &str,
    ) -> Result<(), ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if let Some(entry) = state.targets.get(target) {
            if entry.kind == "service_worker" && entry.session_id == session {
                entry.tenure.observed_detach.store(true, Ordering::Release);
            }
        }
        Ok(())
    }
    /// Exact page-root identity only, including an unclassified reservation
    /// phase. This grants no Application, Ready, capture or retirement authority.
    pub(super) fn initializing_root_ticket(
        &self,
        target: &str,
        session: &str,
    ) -> Result<OwnedTarget, ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed || state.integrity_lost {
            return Err(ProtocolError::StaleScope);
        }
        let root = state
            .targets
            .get(target)
            .ok_or(ProtocolError::StaleReference)?;
        if root.kind != "page" || root.session_id != session {
            return Err(ProtocolError::StaleScope);
        }
        Ok(root.clone())
    }
    /// Capture registration identity even while a creation reservation has not
    /// classified purpose. This grants neither Application nor Ready authority.
    pub(super) fn initializing_iframe_tickets(
        &self,
        target: &str,
        session: &str,
        root_target: &str,
        root_session: &str,
    ) -> Result<(OwnedTarget, OwnedTarget), ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed || state.integrity_lost {
            return Err(ProtocolError::StaleScope);
        }
        let entry = state
            .targets
            .get(target)
            .ok_or(ProtocolError::StaleReference)?;
        if entry.kind != "iframe"
            || entry.session_id != session
            || entry.resumed
            || entry.resume_pending
        {
            return Err(ProtocolError::StaleScope);
        }
        let root = state
            .targets
            .get(root_target)
            .ok_or(ProtocolError::StaleReference)?;
        if root.kind != "page" || root.session_id != root_session {
            return Err(ProtocolError::StaleScope);
        }
        Ok((entry.clone(), root.clone()))
    }
    /// Only the directly matched iframe event may retire initialization. Generic
    /// removal, ancestor detach and targetDestroyed do not grant this receipt.
    pub(super) fn observe_iframe_detach(
        &self,
        target: &str,
        session: &str,
    ) -> Result<(), ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if let Some(entry) = state.targets.get(target) {
            if entry.kind == "iframe" && entry.session_id == session {
                entry
                    .tenure
                    .observed_iframe_detach
                    .store(true, Ordering::Release);
            }
        }
        Ok(())
    }
    /// Caller holds the enrollment, transport-owner and ledger fences. This
    /// retires only a gone child, never publishes Ready or authorizes a new tab.
    pub(super) fn finish_detached_iframe_initialization(
        self: &Arc<Self>,
        child: &OwnedTarget,
        root: &OwnedTarget,
        permit: Option<&mut ResumePermit>,
        check_bounds: impl FnOnce() -> Result<(), ProtocolError>,
    ) -> Result<(), ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed
            || state.integrity_lost
            || state
                .protected_read
                .as_ref()
                .is_some_and(|exclusion| exclusion.excludes_iframe(child, root))
            || child.kind != "iframe"
            || root.kind != "page"
            || !Arc::ptr_eq(&self.attachment_owner, &child.tenure.owner)
            || !Arc::ptr_eq(&self.attachment_owner, &root.tenure.owner)
            || !child.tenure.observed_iframe_detach.load(Ordering::Acquire)
            || state.targets.values().any(|current| {
                current.target_id == child.target_id || current.session_id == child.session_id
            })
            || !state.targets.get(&root.target_id).is_some_and(|current| {
                current.session_id == root.session_id
                    && current.kind == "page"
                    && current.purpose == Some(TargetPurpose::Application)
                    && Arc::ptr_eq(&current.tenure, &root.tenure)
            })
        {
            return Err(ProtocolError::StaleScope);
        }
        if let Some(permit) = permit {
            if permit.worker_startup
                || !Arc::ptr_eq(&permit.registry, self)
                || permit.target_id != child.target_id
                || permit.session_id != child.session_id
                || !Arc::ptr_eq(&permit.tenure, &child.tenure)
                || state.resuming == 0
            {
                return Err(ProtocolError::StaleScope);
            }
            check_bounds()?;
            // Drop releases the original reservation after the outer locks go.
            // Detached initialization is not a successful resume ACK.
            permit.completed = true;
        } else {
            check_bounds()?;
        }
        Ok(())
    }
    /// No child tenure exists in the queued phase. The enrollment index retains
    /// its direct-detach event and proves registration never started. This fence
    /// checks only original known ancestors and absence, without minting a child.
    pub(super) fn finish_detached_queued_iframe(
        &self,
        target: &str,
        session: &str,
        parent: &OwnedTarget,
        root: &OwnedTarget,
        check_bounds: impl FnOnce() -> Result<(), ProtocolError>,
    ) -> Result<(), ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed
            || state.integrity_lost
            || state.protected_read.as_ref().is_some_and(|exclusion| exclusion.excludes_queued_iframe(parent, root))
            || root.kind != "page"
            || !matches!(parent.kind.as_str(), "page" | "iframe")
            // Auxiliary classification can retain cleanup ownership before
            // ordinary registration. Candidate retirement cannot bypass it.
            || state.auxiliary.values().any(|entry| entry.target == target)
            || state
                .targets
                .values()
                .any(|current| current.target_id == target || current.session_id == session)
            || [parent, root].iter().any(|ticket| {
                !Arc::ptr_eq(&self.attachment_owner, &ticket.tenure.owner)
                    || !state.targets.get(&ticket.target_id).is_some_and(|current| {
                        current.purpose == Some(TargetPurpose::Application)
                            && current.same_initialization_attachment(ticket)
                    })
            })
        {
            return Err(ProtocolError::StaleScope);
        }
        check_bounds()
    }
    /// Only the directly matched application page may carry this receipt.
    /// Registry removal or a cascaded descendant detach is not equivalent proof.
    pub(super) fn observe_media_detach(
        &self,
        target: &str,
        session: &str,
    ) -> Result<(), ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if let Some(entry) = state.targets.get(target) {
            if entry.kind == "page"
                && entry.purpose == Some(TargetPurpose::Application)
                && entry.session_id == session
            {
                entry
                    .tenure
                    .observed_media_detach
                    .store(true, Ordering::Release);
            }
        }
        Ok(())
    }
    pub(crate) fn media_attachment_detached(
        &self,
        ticket: &OwnedTarget,
    ) -> Result<bool, ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed || state.integrity_lost {
            return Err(ProtocolError::StaleScope);
        }
        Ok(Arc::ptr_eq(&self.attachment_owner, &ticket.tenure.owner)
            && ticket.kind == "page"
            && ticket.capture_ready()
            && ticket.tenure.observed_media_detach.load(Ordering::Acquire)
            && !state.targets.values().any(|current| {
                current.target_id == ticket.target_id || current.session_id == ticket.session_id
            }))
    }
    pub fn detach(&self, target_id: &str) -> Result<(), ProtocolError> {
        let observed = self.eval_invalidation(|revoke| {
            revoke();
            let mut state = self
                .state
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            let removed = state.targets.remove(target_id);
            if let Some(target) = &removed {
                state.note_query_membership_change(&target.tenure.lineage)?;
            }
            if removed.is_some() {
                state.revision = state
                    .revision
                    .checked_add(1)
                    .ok_or(ProtocolError::IdentifierExhausted)?;
                if diagnostic::inventory_enabled() {
                    state.note_revision_enabled(
                        diagnostic::InventoryRevisionEvent::Detach,
                        removed.as_ref().map(|target| target.tenure.clone()),
                        removed
                            .as_ref()
                            .and_then(|target| target.diagnostic.map(|value| value.attachment)),
                    );
                }
            }
            drop(state);
            self.changed.notify_waiters();
            Ok(removed.and_then(|target| target.diagnostic_snapshot()))
        })?;
        if let Some(mut value) = observed {
            value.stage = diagnostic::DiagnosticTargetStage::Detached;
            diagnostic::target_lifecycle(value.generation, 0, value, None);
        }
        Ok(())
    }
    pub fn invalidate_inventory(&self) -> Result<(), ProtocolError> {
        self.invalidate_inventory_inner(diagnostic::InventoryRevisionEvent::Unknown, None)
    }
    pub(crate) fn invalidate_inventory_for(
        &self,
        event: diagnostic::InventoryRevisionEvent,
        target: &str,
    ) -> Result<(), ProtocolError> {
        if event == diagnostic::InventoryRevisionEvent::Unknown {
            return self.invalidate_inventory();
        }
        self.invalidate_inventory_inner(event, Some(target))
    }
    fn invalidate_inventory_inner(
        &self,
        event: diagnostic::InventoryRevisionEvent,
        target: Option<&str>,
    ) -> Result<(), ProtocolError> {
        self.eval_invalidation(|revoke| {
            revoke();
            let mut state = self
                .state
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if state.sealed {
                return Err(ProtocolError::StaleScope);
            }
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or(ProtocolError::IdentifierExhausted)?;
            // Query-only exact-document fence; the original global revision
            // and all capture/cleanup consumers remain unchanged.
            if let Some(tenure) = target
                .and_then(|id| state.targets.get(id))
                .map(|target| target.tenure.clone())
            {
                let Some(next) = tenure.query_revision.load(Ordering::Acquire).checked_add(1)
                else {
                    state.lose_integrity(diagnostic::InventoryFirstLoss::QueryRevisionExhausted);
                    return Err(ProtocolError::IdentifierExhausted);
                };
                tenure.query_revision.store(next, Ordering::Release);
            } else {
                let Some(next) = state.query_unknown_revision.checked_add(1) else {
                    state.lose_integrity(
                        diagnostic::InventoryFirstLoss::UnknownQueryRevisionExhausted,
                    );
                    return Err(ProtocolError::IdentifierExhausted);
                };
                state.query_unknown_revision = next;
            }
            if diagnostic::inventory_enabled() {
                let attachment = target
                    .and_then(|target| state.targets.get(target))
                    .map(|target| target.tenure.clone());
                let ordinal = target
                    .and_then(|target| state.targets.get(target))
                    .and_then(|target| target.diagnostic.map(|value| value.attachment));
                state.note_revision_enabled(event, attachment, ordinal);
            }
            Ok(())
        })
    }
    pub(super) fn mark_query_attribution_invalid(&self, target: &str, session: &str) {
        let Ok(state) = self.state.lock() else {
            return;
        };
        if let Some(current) = state
            .targets
            .get(target)
            .filter(|value| value.session_id == session)
        {
            current
                .tenure
                .query_attribution_invalid
                .store(true, Ordering::Release);
        }
    }
    pub(super) fn observe_query_target_info(
        &self,
        target: &str,
        session: &str,
        kind: Option<&str>,
        parentless: bool,
    ) {
        let Ok(state) = self.state.lock() else {
            return;
        };
        let Some(current) = state
            .targets
            .get(target)
            .filter(|value| value.session_id == session)
        else {
            return;
        };
        if kind != Some(current.kind.as_str())
            || (matches!(
                &current.tenure.lineage,
                AttachmentLineage::UnpartitionedDependency
            ) && !parentless)
        {
            current
                .tenure
                .query_attribution_invalid
                .store(true, Ordering::Release);
        }
    }
    pub fn inventory(&self) -> Result<(u64, Vec<OwnedTarget>), ProtocolError> {
        self.inventory_with_diagnostic(false)
            .map(|(revision, targets, _)| (revision, targets))
    }
    pub(crate) fn inventory_with_diagnostic(
        &self,
        observe: bool,
    ) -> Result<(u64, Vec<OwnedTarget>, Option<RevisionSnapshot>), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed || !state.inventory_complete() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let snapshot = observe.then(|| state.revision_snapshot());
        Ok((
            state.revision,
            state.targets.values().cloned().collect(),
            snapshot,
        ))
    }
    /// The inventory a protected read may take, waiting out the page's own
    /// target enrollment. The registry notification is the only wait source;
    /// the caller's operation deadline and cancellation still bound it, and a
    /// sealed or accounting-lost registry returns immediately. This is a
    /// readiness wait, never an extended or re-issued operation.
    pub(crate) async fn wait_read_inventory(
        &self,
        operation: &super::client_session::OperationLease,
        observe: bool,
    ) -> Result<(u64, Vec<OwnedTarget>, Option<RevisionSnapshot>), ProtocolError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if state.sealed || state.integrity_lost {
                    return Err(ProtocolError::ScopeUnavailable);
                }
                if let Some(error) = (*operation.cancellation.borrow()).error() {
                    return Err(error);
                }
                if state.read_enrollment_settled() {
                    let snapshot = observe.then(|| state.revision_snapshot());
                    return Ok((
                        state.revision,
                        state.targets.values().cloned().collect(),
                        snapshot,
                    ));
                }
            }
            let mut cancellation = operation.cancellation.clone();
            tokio::select! {
                _ = &mut changed => {}
                _ = cancellation.changed() => {
                    return Err((*operation.cancellation.borrow()).error().unwrap_or(ProtocolError::Cancelled));
                }
                _ = tokio::time::sleep_until(operation.deadline.into()) => {
                    return Err(ProtocolError::DeadlineExceeded);
                }
            }
        }
    }
    /// Wait until the scope's own enrollment has settled without taking an
    /// inventory. The protected-read barrier uses the same wait as the frame
    /// inventory, so a target the page creates during the read's enumeration
    /// cannot turn a readable scope into an unavailable one.
    pub(crate) async fn wait_read_enrollment(
        &self,
        operation: &super::client_session::OperationLease,
    ) -> Result<(), ProtocolError> {
        self.wait_read_inventory(operation, false).await.map(|_| ())
    }
    /// The target inventory a command takes immediately before dispatch. A
    /// fixed read addresses only the page session, never a frame session, so
    /// the page's own target enrollment is readiness rather than an unavailable
    /// scope: it waits exactly like a protected read. Every other command keeps
    /// the immediate completeness refusal, because its frame-session authority
    /// and fail-closed admission require the complete inventory up front.
    ///
    /// The wait is the same registry notification #72 uses, bounded by the
    /// caller's existing operation deadline and cancellation. A sealed or
    /// accounting-lost registry still fails closed at once.
    pub(crate) async fn dispatch_inventory(
        &self,
        operation: &super::client_session::OperationLease,
        fixed_read: bool,
    ) -> Result<Vec<OwnedTarget>, ProtocolError> {
        if fixed_read {
            self.wait_read_inventory(operation, false)
                .await
                .map(|(_, targets, _)| targets)
        } else {
            self.inventory().map(|(_, targets)| targets)
        }
    }
    /// A read-only inventory can hold a frame session the page has already
    /// retired: the browser destroyed that target, but the registry still lists
    /// it until the supervisor applies the queued `Target.detachedFromTarget`.
    /// A CDP read against that session fails even though the scope itself is
    /// healthy; waiting for the registry to apply the detach the browser
    /// already reported is readiness, not a retry of the failed read.
    ///
    /// Returns `true` once the registry no longer owns `session`, `false` when
    /// the caller's own operation deadline expired first (the caller keeps its
    /// original failure), and an explicit cancellation/scope error otherwise.
    /// The wait never extends the operation's deadline and never masks the
    /// primary failure: this is the same bounded notification wait the read
    /// inventory uses.
    pub(crate) async fn wait_read_session_retired(
        &self,
        operation: &super::client_session::OperationLease,
        session: &str,
    ) -> Result<bool, ProtocolError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if state.sealed || state.integrity_lost {
                    return Err(ProtocolError::ScopeUnavailable);
                }
                if let Some(error) = (*operation.cancellation.borrow()).error() {
                    return Err(error);
                }
                if !state
                    .targets
                    .values()
                    .any(|target| target.session_id == session)
                {
                    return Ok(true);
                }
            }
            let mut cancellation = operation.cancellation.clone();
            tokio::select! {
                _ = &mut changed => {}
                _ = cancellation.changed() => {
                    return Err((*operation.cancellation.borrow()).error().unwrap_or(ProtocolError::Cancelled));
                }
                _ = tokio::time::sleep_until(operation.deadline.into()) => {
                    return Ok(false);
                }
            }
        }
    }
    /// Restart alone may wait for exact, already-observed enrollment work. Keep
    /// the full registry guard through publication; ordinary settlement remains
    /// fail closed and never treats an incomplete inventory as reusable.
    pub(crate) fn publish_restart_ready<T>(
        &self,
        replacement: &OwnedTarget,
        pending: impl Fn(&str) -> bool,
        known: impl Fn(&OwnedTarget) -> bool,
        enrollment_ready: bool,
        publish: impl FnOnce() -> Result<T, ProtocolError>,
    ) -> Result<Option<T>, ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed
            || state.integrity_lost
            || !state.enrollment_ready
            || state.protected_read.is_some()
            || state.reservations != 0
            || state
                .auxiliary
                .values()
                .any(|entry| !entry.detached && entry.claimed_session.is_none())
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let current = state
            .targets
            .get(&replacement.target_id)
            .ok_or(ProtocolError::StaleReference)?;
        if !current.same_attachment(replacement)
            || current.kind != "page"
            || !current.capture_ready()
        {
            return Err(ProtocolError::StaleScope);
        }
        let mut configuring = false;
        for target in state.targets.values() {
            if !known(target) {
                return Err(ProtocolError::ScopeUnavailable);
            }
            if target.purpose.is_none()
                || !target.configured
                || !target.resumed
                || target.resume_pending
            {
                if !pending(&target.session_id) {
                    return Err(ProtocolError::ScopeUnavailable);
                }
                configuring = true;
            }
        }
        if state.resuming
            != state
                .targets
                .values()
                .filter(|target| target.resume_pending)
                .count()
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if configuring || !enrollment_ready {
            return Ok(None);
        }
        // Preserve the original full-inventory contract at the final boundary.
        if !state.inventory_complete() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        publish().map(Some)
    }
    pub(crate) fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.changed.notified()
    }
    pub fn check_revision(&self, revision: u64) -> Result<(), ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        state.revision_result(revision)
    }
    #[cfg(test)]
    pub(crate) fn check_revision_with_diagnostic(
        &self,
        revision: u64,
        before: Option<&RevisionSnapshot>,
        selected: &OwnedTarget,
        pass: diagnostic::FrameInventoryPass,
    ) -> (
        Result<(), ProtocolError>,
        Option<diagnostic::FrameInventoryRejection>,
    ) {
        let check = self.check_acquisition_revision(revision, before, selected, pass, true);
        (check.result, check.diagnostic)
    }
    pub(crate) fn check_acquisition_revision(
        &self,
        revision: u64,
        before: Option<&RevisionSnapshot>,
        selected: &OwnedTarget,
        pass: diagnostic::FrameInventoryPass,
        observe: bool,
    ) -> InventoryRevisionCheck {
        let Ok(state) = self.state.lock() else {
            return InventoryRevisionCheck {
                result: Err(ProtocolError::ScopeUnavailable),
                revision_only: false,
                diagnostic: None,
            };
        };
        let result = state.revision_result(revision);
        let revision_only = !state.sealed && state.reservations == 0 && state.revision != revision;
        let diagnostic = (observe && result.is_err())
            .then(|| state.revision_rejection(revision, before, selected, pass));
        InventoryRevisionCheck {
            result,
            revision_only,
            diagnostic,
        }
    }
    pub fn seal(&self) {
        self.seal_diagnostic(diagnostic::InventoryFirstLoss::ExplicitSeal);
    }
    pub(crate) fn seal_diagnostic(&self, reason: diagnostic::InventoryFirstLoss) {
        self.eval_invalidation(|revoke| {
            revoke();
            if let Ok(mut state) = self.state.lock() {
                state.lose_integrity(reason);
            }
            self.changed.notify_waiters();
        })
    }
    /// Stop admission without inventing either cleanup success or accounting
    /// failure. Only an earlier owner-retirement stamp can certify settlement.
    pub(crate) fn seal_admission(&self) {
        self.eval_invalidation(|revoke| {
            revoke();
            if let Ok(mut state) = self.state.lock() {
                state.sealed = true;
            }
            self.changed.notify_waiters();
        })
    }
    /// Called by the retained lifecycle owner before stopping enrollment. The
    /// first inventory is immutable: later cleanup cannot repair missing proof,
    /// and neither repeated retirement nor this stamp can clear a poison seal.
    pub(crate) fn seal_for_owner_retirement(
        &self,
        authority: &super::client_browser::OwnerRetirement,
    ) {
        self.eval_invalidation(|revoke| {
            revoke();
            if let Ok(mut state) = self.state.lock() {
                if !authority.authorizes(self) {
                    state
                        .lose_integrity(diagnostic::InventoryFirstLoss::InvalidRetirementAuthority);
                    self.changed.notify_waiters();
                    return;
                }
                if state.owner_retirement_inventory.is_none() {
                    state.owner_retirement_inventory =
                        Some(!state.sealed && !state.integrity_lost && state.inventory_complete());
                }
                state.sealed = true;
            }
            self.changed.notify_waiters();
        })
    }
    /// EOF closes admission, not accounting. All ordinary poison paths still
    /// set integrity_lost; this never clears an earlier loss.
    pub(crate) fn seal_remote_connection(&self, ledger: &Arc<super::client_debt::OwnerDebtLedger>) {
        if self.require_eval_owner(ledger).is_ok() && ledger.remote_eof_only() {
            self.seal_admission();
        } else {
            self.seal();
        }
    }
    #[cfg(test)]
    pub(crate) fn check_terminal_read_only(
        &self,
        bindings: &[(String, String, bool)],
    ) -> Result<(), ProtocolError> {
        self.with_terminal_read_only(bindings, || Ok(()))
    }
    pub(crate) fn with_terminal_read_only<T>(
        &self,
        bindings: &[(String, String, bool)],
        commit: impl FnOnce() -> Result<T, ProtocolError>,
    ) -> Result<T, ProtocolError> {
        let (result, observation) = self.with_terminal_read_only_observed(bindings, commit);
        if let Some((reason, counts)) = observation {
            super::client_settlement_trace::terminal_enrollment_refusal(reason, counts);
        }
        result
    }
    pub(crate) fn check_terminal_read_only_observed(
        &self,
        bindings: &[(String, String, bool)],
    ) -> (
        Result<(), ProtocolError>,
        super::client_settlement_trace::TerminalRefusalObservation,
    ) {
        self.with_terminal_read_only_observed(bindings, || Ok(()))
    }
    fn with_terminal_read_only_observed<T>(
        &self,
        bindings: &[(String, String, bool)],
        commit: impl FnOnce() -> Result<T, ProtocolError>,
    ) -> (
        Result<T, ProtocolError>,
        super::client_settlement_trace::TerminalRefusalObservation,
    ) {
        use super::client_settlement_trace::TerminalEnrollmentRefusal;
        let mut refusal = None;
        macro_rules! terminal_guard {
            ($predicate:expr, $reason:ident, $counts:expr) => {{
                let rejected = $predicate;
                if rejected {
                    refusal = Some((TerminalEnrollmentRefusal::$reason, $counts));
                }
                rejected
            }};
        }

        let result = (|| {
            let state = self
                .state
                .lock()
                .map_err(|_| ProtocolError::CleanupFailed)?;
            if terminal_guard!(!state.sealed, RegistryNotSealed, None)
                || terminal_guard!(state.integrity_lost, RegistryIntegrityLost, None)
                || terminal_guard!(!state.enrollment_ready, RegistryNotReady, None)
                || terminal_guard!(
                    state.reservations != 0,
                    RegistryReservations,
                    Some([state.reservations as u64, 0])
                )
                || terminal_guard!(
                    state.resuming != 0,
                    RegistryResuming,
                    Some([state.resuming as u64, 0])
                )
                || terminal_guard!(state.protected_read.is_some(), RegistryProtectedRead, None)
                || terminal_guard!(
                    !state.bootstrap_creations.is_empty(),
                    RegistryBootstrapCreations,
                    Some([state.bootstrap_creations.len() as u64, 0])
                )
                || terminal_guard!(
                    !state.native_bootstrap_cleanup.is_empty(),
                    RegistryBootstrapCleanup,
                    Some([state.native_bootstrap_cleanup.len() as u64, 0])
                )
                || terminal_guard!(
                    !state.bootstrap_cleanup_reservations.is_empty(),
                    RegistryCleanupReservations,
                    Some([state.bootstrap_cleanup_reservations.len() as u64, 0])
                )
                || terminal_guard!(
                    state.unknown_bootstrap_create,
                    RegistryUnknownCreation,
                    None
                )
                || terminal_guard!(
                    !state.auxiliary.is_empty(),
                    RegistryAuxiliary,
                    Some([state.auxiliary.len() as u64, 0])
                )
                || terminal_guard!(
                    state.targets.len()
                        != bindings.iter().filter(|(_, _, observer)| !observer).count(),
                    RegistryTargetCount,
                    Some([
                        state.targets.len() as u64,
                        bindings.iter().filter(|(_, _, observer)| !observer).count() as u64
                    ])
                )
                || terminal_guard!(
                    state.targets.values().any(|target| {
                        !target.capture_ready()
                            || !bindings.iter().any(|(session, id, observer)| {
                                !observer
                                    && session == &target.session_id
                                    && id == &target.target_id
                            })
                    }),
                    RegistryTargetBinding,
                    None
                )
            {
                return Err(ProtocolError::CleanupFailed);
            }
            commit()
        })();
        (result, refusal)
    }
    /// Final-local cleanup only: admission may already be sealed, but no
    /// accounting damage or unsettled exact resource/reservation is waived.
    pub(crate) fn check_final_local_cleanup(&self) -> Result<(), ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?;
        if state.integrity_lost
            || !state.enrollment_ready
            || !state.targets.is_empty()
            || state.reservations != 0
            || state.resuming != 0
            || state.protected_read.is_some()
            || !state.bootstrap_creations.is_empty()
            || !state.native_bootstrap_cleanup.is_empty()
            || !state.bootstrap_cleanup_reservations.is_empty()
            || state.unknown_bootstrap_create
            || state.auxiliary.values().any(|entry| {
                entry.failed
                    || !entry.detached
                    || !entry.cleanup_owned.iter().all(|session| {
                        entry.acknowledged_session.as_deref() == Some(session)
                            || entry.cleanup_acknowledged.contains(session)
                    })
            })
        {
            return Err(ProtocolError::CleanupFailed);
        }
        Ok(())
    }
    /// Settlement is not application admission. A completed local producer may
    /// retire under its original owner after normal lifecycle sealing, but every
    /// accounting failure and incomplete inventory still rejects settlement.
    pub(crate) fn inventory_diagnostic(&self) -> super::client_settlement_trace::InventorySnapshot {
        self.settlement_integrity_diagnostic(true).1
    }
    pub(crate) fn try_inventory_diagnostic(&self) -> diagnostic::InventorySnapshot {
        self.state
            .try_lock()
            .map(|state| state.diagnostic_inventory())
            .unwrap_or_default()
    }
    /// Capture diagnostic identity before an await. This carries no authority,
    /// never waits for the registry, and cannot be rebound to a later attachment.
    pub(crate) fn diagnostic_attachment_for_session(
        &self,
        target_id: &str,
        session_id: &str,
        operation: (u64, u64),
    ) -> Option<diagnostic::DiagnosticAttachment> {
        if !diagnostic::inventory_enabled() {
            return None;
        }
        let observed = self.state.try_lock().ok().and_then(|state| {
            state
                .targets
                .get(target_id)
                .filter(|target| target.session_id == session_id)
                .and_then(|target| target.diagnostic_snapshot())
        });
        if observed.is_none() {
            diagnostic::target_observation_lost(operation.0, operation.1);
        }
        observed
    }
    pub(crate) fn diagnostic_step(
        &self,
        target_id: &str,
        operation: (u64, u64),
        stage: diagnostic::DiagnosticTargetStage,
        error: Option<ProtocolError>,
    ) {
        if !diagnostic::inventory_enabled() {
            return;
        }
        let Ok(mut state) = self.state.try_lock() else {
            diagnostic::target_observation_lost(operation.0, operation.1);
            return;
        };
        let observed = state.targets.get_mut(target_id).and_then(|target| {
            let value = target.diagnostic.as_mut()?;
            value.generation = operation.0;
            value.stage = stage;
            target.diagnostic_snapshot()
        });
        drop(state);
        if let Some(value) = observed {
            diagnostic::target_lifecycle(operation.0, operation.1, value, error);
        } else {
            diagnostic::target_observation_lost(operation.0, operation.1);
        }
    }
    #[cfg(test)]
    pub(super) fn retained_initialization_state_for_test(
        &self,
        target: &str,
    ) -> (bool, Option<bool>, bool) {
        let state = self.state.lock().unwrap();
        (
            state.targets[target]
                .tenure
                .retained_initialization
                .load(Ordering::Acquire),
            state.owner_retirement_inventory,
            state.integrity_lost,
        )
    }
    #[cfg(test)]
    pub(crate) fn check_settlement_integrity(&self) -> Result<(), ProtocolError> {
        self.settlement_integrity_diagnostic(false).0
    }
    pub(crate) fn settlement_integrity_diagnostic(
        &self,
        observe: bool,
    ) -> (
        Result<(), ProtocolError>,
        super::client_settlement_trace::InventorySnapshot,
    ) {
        self.settlement_integrity_diagnostic_inner(observe, false)
    }
    /// Operation-local completion may leave unrelated initialization with its
    /// exact retained producer. This does not relax full inventory callers.
    pub(crate) fn operation_settlement_integrity_diagnostic(
        &self,
        observe: bool,
    ) -> (
        Result<(), ProtocolError>,
        super::client_settlement_trace::InventorySnapshot,
    ) {
        self.settlement_integrity_diagnostic_inner(observe, true)
    }
    fn settlement_integrity_diagnostic_inner(
        &self,
        observe: bool,
        allow_retained_initialization: bool,
    ) -> (
        Result<(), ProtocolError>,
        super::client_settlement_trace::InventorySnapshot,
    ) {
        let Ok(state) = self.state.lock() else {
            return (Err(ProtocolError::ScopeUnavailable), Default::default());
        };
        let snapshot = if observe {
            state.diagnostic_inventory()
        } else {
            Default::default()
        };
        let result = if state.integrity_lost
            || !(state.inventory_complete()
                || (allow_retained_initialization
                    && !state.sealed
                    && state.reservations == 0
                    && state.targets.values().all(|target| {
                        target.purpose.is_some()
                            && (target.configured
                                || (Arc::ptr_eq(&target.tenure.owner, &self.attachment_owner)
                                    && target
                                        .tenure
                                        .retained_initialization
                                        .load(Ordering::Acquire)))
                    })))
            || (state.sealed && state.owner_retirement_inventory != Some(true))
        {
            Err(ProtocolError::ScopeUnavailable)
        } else {
            Ok(())
        };
        (result, snapshot)
    }
}
impl AuxiliaryAttachmentReservation {
    /// Retire local auxiliary ownership only after proven terminal transport.
    /// Does not invent an attach ACK, detach ACK, or remote stop acknowledgement.
    pub(crate) fn settle_terminal_connection(
        &mut self,
        proof: &super::client_enrollment::NativeTerminalProof,
    ) -> Result<(), ProtocolError> {
        proof.check_targets(&self.registry)?;
        let mut state = self
            .registry
            .state
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?;
        let entry = state
            .auxiliary
            .get_mut(&self.nonce)
            .ok_or(ProtocolError::StaleScope)?;
        if entry.terminal_connection_retired {
            self.completed = true;
            return Ok(());
        }
        entry.terminal_connection_retired = true;
        self.completed = true;
        drop(state);
        self.registry.changed.notify_waiters();
        Ok(())
    }
    pub(crate) fn claim(&mut self, session_id: &str) -> Result<(), ProtocolError> {
        let registry = self.registry.clone();
        registry.eval_invalidation(|revoke| {
            revoke();
            let mut state = self
                .registry
                .state
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if self.completed {
                return Err(ProtocolError::StaleScope);
            }
            if session_id.is_empty()
                || session_id.len() > 1024
                || state
                    .targets
                    .values()
                    .any(|target| target.session_id == session_id)
                || state
                    .auxiliary
                    .values()
                    .any(|entry| entry.acknowledged_session.as_deref() == Some(session_id))
            {
                return Err(ProtocolError::InvalidArguments);
            }
            let reserved = state
                .auxiliary
                .get(&self.nonce)
                .ok_or(ProtocolError::StaleScope)?;
            if session_id == reserved.primary_session {
                return Err(ProtocolError::InvalidArguments);
            }
            if reserved.acknowledged_session.is_some() {
                return Err(ProtocolError::StaleScope);
            }
            let valid = !state.sealed
                && !reserved.failed
                && state.targets.get(&reserved.target).is_some_and(|target| {
                    target.session_id == reserved.primary_session
                        && target.purpose == Some(TargetPurpose::Application)
                        && target.configured
                        && target.resumed
                });
            let entry = state
                .auxiliary
                .get_mut(&self.nonce)
                .ok_or(ProtocolError::StaleScope)?;
            // Even a late rejected ACK identifies a session we must clean up. Never
            // lose it merely because its attach notification has not arrived yet.
            entry.acknowledged_session = Some(session_id.into());
            if !valid {
                entry.failed = true;
                state.lose_integrity(diagnostic::InventoryFirstLoss::AuxiliaryAckMismatch);
                drop(state);
                self.registry.changed.notify_waiters();
                return Err(ProtocolError::StaleScope);
            }
            entry.claimed_session = Some(session_id.into());
            drop(state);
            self.registry.changed.notify_waiters();
            Ok(())
        })
    }
    /// Stop new scope work and wake enrollment while retaining this token's
    /// exact candidate journal for the recorder's bounded failure cleanup.
    pub(crate) fn quarantine(&self) {
        let registry = self.registry.clone();
        registry.eval_invalidation(|revoke| {
            revoke();
            if let Ok(mut state) = self.registry.state.lock() {
                if let Some(entry) = state.auxiliary.get_mut(&self.nonce) {
                    entry.failed = true;
                    if entry.acknowledged_session.is_none() {
                        entry.cleanup_owned.extend(entry.candidates.iter().cloned());
                    }
                }
                state.lose_integrity(diagnostic::InventoryFirstLoss::AuxiliaryAbandoned);
            }
            self.registry.changed.notify_waiters();
        })
    }
    /// Only for a retained startup path that proves attach was never sent.
    pub(crate) fn cancel_unsubmitted(mut self) -> Result<(), ProtocolError> {
        let mut state = self
            .registry
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let entry = state
            .auxiliary
            .get(&self.nonce)
            .ok_or(ProtocolError::StaleScope)?;
        if entry.acknowledged_session.is_some() || !entry.candidates.is_empty() {
            return Err(ProtocolError::CleanupFailed);
        }
        state.auxiliary.remove(&self.nonce);
        self.completed = true;
        drop(state);
        self.registry.changed.notify_waiters();
        Ok(())
    }
    /// Cleanup candidates are connection-owned attachments, not owned host
    /// pages. Unknown ACK with an empty list is NOT proof of successful cleanup.
    pub(crate) fn cleanup_sessions(&self) -> Result<Vec<String>, ProtocolError> {
        let state = self
            .registry
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let entry = state
            .auxiliary
            .get(&self.nonce)
            .ok_or(ProtocolError::StaleScope)?;
        let mut sessions: Vec<_> = if let Some(session) = &entry.acknowledged_session {
            vec![session.clone()]
        } else {
            entry.candidates.iter().cloned().collect()
        };
        sessions.extend(entry.cleanup_owned.iter().cloned());
        sessions.retain(|session| !entry.cleanup_acknowledged.contains(session));
        sessions.sort();
        sessions.dedup();
        Ok(sessions)
    }
    /// Record an actual detach ACK for a candidate explicitly handed to this
    /// supervisor. This is not proof that an unknown attach ACK is complete.
    pub(crate) fn candidate_detached(&mut self, session_id: &str) -> Result<(), ProtocolError> {
        let mut state = self
            .registry
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let entry = state
            .auxiliary
            .get_mut(&self.nonce)
            .ok_or(ProtocolError::StaleScope)?;
        if !entry.cleanup_owned.contains(session_id) {
            return Err(ProtocolError::CleanupFailed);
        }
        entry.cleanup_acknowledged.insert(session_id.into());
        Ok(())
    }
    /// Call only after the recorder has joined and exact native detach ACK.
    pub(crate) fn detached(&mut self, session_id: &str) -> Result<(), ProtocolError> {
        let mut state = self
            .registry
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let entry = state
            .auxiliary
            .get_mut(&self.nonce)
            .ok_or(ProtocolError::StaleScope)?;
        // Cleanup acknowledgement does not grant execution authority or clear
        // quarantine. A known ACK rejected during retirement is still ours to
        // detach; unknown-ACK candidate enumeration cannot certify completion.
        if entry.acknowledged_session.as_deref() != Some(session_id) {
            return Err(ProtocolError::CleanupFailed);
        }
        if entry.cleanup_owned.iter().any(|candidate| {
            candidate != session_id && !entry.cleanup_acknowledged.contains(candidate)
        }) {
            return Err(ProtocolError::CleanupFailed);
        }
        entry.detached = true;
        self.completed = true;
        drop(state);
        self.registry.changed.notify_waiters();
        Ok(())
    }
}
impl Drop for AuxiliaryAttachmentReservation {
    fn drop(&mut self) {
        if !self.completed {
            self.quarantine();
        }
    }
}
impl CreationReservation {
    /// Journal the native create RPC's exact ACK before any further await.
    /// Purpose alone never grants cleanup of a preexisting host page.
    pub(crate) fn record_native_created_target(
        &mut self,
        target: &str,
    ) -> Result<(), ProtocolError> {
        if self.purpose != TargetPurpose::StateBootstrap
            || self.claimed
            || self.native_created_target.is_some()
            || target.is_empty()
            || target.len() > 1024
        {
            return Err(ProtocolError::PolicyDenied);
        }
        let mut state = self
            .registry
            .state
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?;
        let nonce = self.bootstrap_nonce.ok_or(ProtocolError::PolicyDenied)?;
        if !state.bootstrap_cleanup_reservations.contains(&nonce) {
            return Err(ProtocolError::StaleScope);
        }
        if state
            .targets
            .get(target)
            .is_some_and(|entry| entry.purpose.is_some())
            || state.native_bootstrap_cleanup.contains(target)
        {
            return Err(ProtocolError::StaleScope);
        }
        state.native_bootstrap_cleanup.insert(target.into());
        state.bootstrap_cleanup_reservations.remove(&nonce);
        self.native_created_target = Some(target.into());
        Ok(())
    }
    /// Called only by native state IO after its create ACK and exact target
    /// metadata recheck. The wire cannot mint this reservation or bind a host page.
    pub(crate) fn acknowledge_native_created_target(
        &mut self,
        info: &serde_json::Value,
    ) -> Result<(), ProtocolError> {
        let target = info
            .get("targetId")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 1024)
            .ok_or(ProtocolError::InvalidFrame)?;
        if self.purpose != TargetPurpose::StateBootstrap
            || self.claimed
            || info
                .get("browserContextId")
                .and_then(serde_json::Value::as_str)
                != Some(self.registry.context_id.as_str())
            || info.get("type").and_then(serde_json::Value::as_str) != Some("page")
            || info.get("url").and_then(serde_json::Value::as_str) != Some("about:blank")
        {
            return Err(ProtocolError::PolicyDenied);
        }
        if self.native_created_target.as_deref() != Some(target) {
            return Err(ProtocolError::PolicyDenied);
        }
        let mut state = self
            .registry
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed
            || state
                .targets
                .get(target)
                .is_some_and(|entry| entry.purpose.is_some())
        {
            return Err(ProtocolError::StaleScope);
        }
        if state
            .bootstrap_creations
            .values()
            .any(|id| id.as_deref() == Some(target))
        {
            return Err(ProtocolError::InvalidArguments);
        }
        let bound = state
            .bootstrap_creations
            .get_mut(&self.bootstrap_nonce.ok_or(ProtocolError::PolicyDenied)?)
            .ok_or(ProtocolError::StaleScope)?;
        if bound.is_some() {
            return Err(ProtocolError::InvalidArguments);
        }
        *bound = Some(target.into());
        drop(state);
        self.registry.changed.notify_waiters();
        Ok(())
    }
    pub fn claim(&mut self, target_id: &str) -> Result<(), ProtocolError> {
        let mut state = self
            .registry
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed || self.claimed {
            return Err(ProtocolError::StaleScope);
        }
        if self
            .bootstrap_nonce
            .and_then(|nonce| state.bootstrap_creations.get(&nonce))
            .and_then(Option::as_deref)
            .is_some_and(|id| id != target_id)
        {
            return Err(ProtocolError::StaleScope);
        }
        let target = state
            .targets
            .get_mut(target_id)
            .ok_or(ProtocolError::StaleReference)?;
        if target.purpose.is_some() {
            return Err(ProtocolError::InvalidArguments);
        }
        target.purpose = Some(self.purpose);
        if let Some(value) = &mut target.diagnostic {
            value.classification = match self.purpose {
                TargetPurpose::Application => {
                    diagnostic::DiagnosticTargetClassification::ReservedApplication
                }
                TargetPurpose::StateBootstrap => {
                    diagnostic::DiagnosticTargetClassification::ReservedBootstrap
                }
            };
            value.stage = diagnostic::DiagnosticTargetStage::PurposeAssigned;
        }
        let observed = target.diagnostic_snapshot();
        self.claimed = true;
        drop(state);
        self.registry.changed.notify_waiters();
        if let Some(value) = observed {
            diagnostic::target_lifecycle(value.generation, 0, value, None);
        }
        Ok(())
    }
}
impl Drop for CreationReservation {
    fn drop(&mut self) {
        let registry = self.registry.clone();
        registry.eval_invalidation(|revoke| {
            revoke();
            if let Ok(mut state) = self.registry.state.lock() {
                // An abandoned create may still produce a late browser target.
                // Never reinterpret that unclaimed bootstrap as application work.
                if !self.claimed {
                    state.lose_integrity(diagnostic::InventoryFirstLoss::CreationAbandoned);
                    if self.purpose == TargetPurpose::StateBootstrap
                        && self.native_created_target.is_none()
                    {
                        // No exact create ACK means no safe target to close. Keep
                        // this uncertainty after the pending reservation is gone.
                        state.unknown_bootstrap_create = true;
                    }
                }
                if let Some(nonce) = self.bootstrap_nonce {
                    state.bootstrap_creations.remove(&nonce);
                    state.bootstrap_cleanup_reservations.remove(&nonce);
                }
                state.reservations = state.reservations.saturating_sub(1);
                if state.reservations == 0 && !state.sealed {
                    for target in state.targets.values_mut() {
                        if target.purpose.is_none() {
                            target.purpose = Some(TargetPurpose::Application);
                            if let Some(value) = &mut target.diagnostic {
                                value.classification = diagnostic::DiagnosticTargetClassification::ReservationRemainder;
                                value.stage = diagnostic::DiagnosticTargetStage::PurposeAssigned;
                            }
                        }
                    }
                }
            }
            self.registry.changed.notify_waiters();
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientTargets, ProtocolError};

    #[test]
    fn retained_initializer_root_ticket_is_exact_and_cascade_releases_no_readiness() {
        for obstruction in ["none", "foreign", "replaced", "detached", "unobserved"] {
            let registry = ClientTargets::new("ctx".into(), "scope".into());
            registry
                .attached("ctx", "root".into(), "root-session".into(), "page".into())
                .unwrap();
            let root = if obstruction == "foreign" {
                let other = ClientTargets::new("ctx".into(), "scope".into());
                other
                    .attached("ctx", "root".into(), "root-session".into(), "page".into())
                    .unwrap();
                other.owned_target("root").unwrap()
            } else {
                registry.owned_target("root").unwrap()
            };
            if obstruction == "replaced" {
                registry.detach("root").unwrap();
                registry
                    .attached("ctx", "root".into(), "root-session".into(), "page".into())
                    .unwrap();
            }
            if obstruction == "detached" {
                registry.detach("root").unwrap();
            }
            let mut custody = super::RetainedInitialization::new(registry.clone());
            let attached = custody.attach_with_root(
                &registry,
                "ctx",
                "child".into(),
                "child-session".into(),
                "iframe".into(),
                Some(root),
            );
            if matches!(obstruction, "foreign" | "replaced" | "detached") {
                assert_eq!(attached, Err(ProtocolError::StaleScope));
                assert!(!registry.state.lock().unwrap().targets.contains_key("child"));
                continue;
            }
            attached.unwrap();
            if obstruction != "unobserved" {
                registry
                    .observe_media_detach("root", "root-session")
                    .unwrap();
            }
            registry.detach("root").unwrap();
            registry.detach("child").unwrap();
            assert_eq!(custody.finish(true).is_ok(), obstruction == "none");
            drop(custody);
            assert_eq!(
                registry.state.lock().unwrap().integrity_lost,
                obstruction == "unobserved"
            );
            assert!(registry.state.lock().unwrap().targets.is_empty());
        }
    }

    #[test]
    fn retained_initializer_unclassified_root_identity_does_not_grant_settlement() {
        let registry = ClientTargets::new("ctx".into(), "scope".into());
        let reservation = registry
            .reserve_creation(super::TargetPurpose::Application)
            .unwrap();
        registry
            .attached("ctx", "root".into(), "root-session".into(), "page".into())
            .unwrap();
        assert!(registry.owned_target("root").is_err());
        let root = registry
            .initializing_root_ticket("root", "root-session")
            .unwrap();
        assert_eq!(root.purpose, None);
        assert!(!root.capture_ready());
        let mut custody = super::RetainedInitialization::new(registry.clone());
        custody
            .attach_with_root(
                &registry,
                "ctx",
                "child".into(),
                "child-session".into(),
                "iframe".into(),
                Some(root),
            )
            .unwrap();
        assert!(registry
            .operation_settlement_integrity_diagnostic(false)
            .0
            .is_err());
        assert!(registry.inventory().is_err());
        assert!(!registry.state.lock().unwrap().integrity_lost);
        drop(reservation);
        // Classification is not configuration, nor a retroactive custody mint.
        assert!(registry
            .operation_settlement_integrity_diagnostic(false)
            .0
            .is_err());
        assert!(!registry.state.lock().unwrap().targets["child"]
            .tenure
            .retained_initialization
            .load(std::sync::atomic::Ordering::Acquire));
        drop(custody);
    }
    fn retained_initializer(
        registry: &std::sync::Arc<ClientTargets>,
    ) -> super::RetainedInitialization {
        let mut custody = super::RetainedInitialization::new(registry.clone());
        custody
            .attach(
                registry,
                "ctx",
                "popup".into(),
                "popup-session".into(),
                "page".into(),
            )
            .unwrap();
        custody
    }
    #[test]
    fn retained_initializer_custody_covers_only_operation_completion() {
        let registry = ClientTargets::new("ctx".into(), "scope".into());
        let custody = retained_initializer(&registry);
        assert!(registry
            .operation_settlement_integrity_diagnostic(false)
            .0
            .is_ok());
        assert!(registry.check_settlement_integrity().is_err());
        assert!(registry.inventory().is_err());
        let target = registry.owned_target("popup").unwrap();
        assert!(!target.configured && !target.resumed && !target.capture_ready());
        drop(custody);
        assert!(registry.state.lock().unwrap().integrity_lost);
        assert!(registry
            .operation_settlement_integrity_diagnostic(false)
            .0
            .is_err());
    }
    #[test]
    fn retained_initializer_never_covers_untracked_or_reserved_work() {
        for reserved in [false, true] {
            let registry = ClientTargets::new("ctx".into(), "scope".into());
            let custody = retained_initializer(&registry);
            let reservation = if reserved {
                Some(
                    registry
                        .reserve_creation(super::TargetPurpose::Application)
                        .unwrap(),
                )
            } else {
                registry
                    .attached(
                        "ctx",
                        "untracked".into(),
                        "untracked-session".into(),
                        "page".into(),
                    )
                    .unwrap();
                None
            };
            assert!(registry
                .operation_settlement_integrity_diagnostic(false)
                .0
                .is_err());
            assert!(!registry.state.lock().unwrap().integrity_lost);
            drop(custody);
            drop(reservation);
        }
    }
    #[tokio::test]
    async fn retained_initializer_success_releases_only_exact_custody() {
        let registry = ClientTargets::new("ctx".into(), "scope".into());
        let mut custody = retained_initializer(&registry);
        assert!(custody.finish(false).is_err());
        registry.configured("popup").unwrap();
        registry
            .resume_permit("popup")
            .await
            .unwrap()
            .complete()
            .unwrap();
        custody.finish(false).unwrap();
        drop(custody);
        assert!(registry.check_settlement_integrity().is_ok());
        assert!(!registry
            .owned_target("popup")
            .unwrap()
            .tenure
            .retained_initialization
            .load(std::sync::atomic::Ordering::Acquire));
        assert!(!registry.state.lock().unwrap().integrity_lost);
    }
    #[test]
    fn retained_initializer_rejects_foreign_registry_and_identical_text_reattachment() {
        let registry = ClientTargets::new("ctx".into(), "scope".into());
        let other = ClientTargets::new("ctx".into(), "scope".into());
        let mut custody = super::RetainedInitialization::new(registry.clone());
        assert_eq!(
            custody.attach(
                &other,
                "ctx",
                "popup".into(),
                "popup-session".into(),
                "page".into()
            ),
            Err(ProtocolError::StaleScope)
        );
        assert!(other.state.lock().unwrap().targets.is_empty());
        custody
            .attach(
                &registry,
                "ctx",
                "popup".into(),
                "popup-session".into(),
                "page".into(),
            )
            .unwrap();
        registry.detach("popup").unwrap();
        registry
            .attached("ctx", "popup".into(), "popup-session".into(), "page".into())
            .unwrap();
        assert!(registry
            .operation_settlement_integrity_diagnostic(false)
            .0
            .is_err());
        assert!(custody.finish(false).is_err());
        assert!(custody.finish(true).is_err());
        drop(custody);
        assert!(registry.state.lock().unwrap().integrity_lost);
    }
    #[tokio::test]
    async fn retained_initializer_abort_and_panic_poison_before_custody_disappears() {
        for panic in [false, true] {
            let registry = ClientTargets::new("ctx".into(), "scope".into());
            let custody = retained_initializer(&registry);
            let (entered, observed) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                let _custody = custody;
                entered.send(()).unwrap();
                if panic {
                    panic!("controlled retained initializer panic");
                }
                std::future::pending::<()>().await;
            });
            observed.await.unwrap();
            if !panic {
                task.abort();
            }
            assert!(task.await.is_err());
            let state = registry.state.lock().unwrap();
            assert!(state.sealed && state.integrity_lost);
            assert!(!state.targets["popup"]
                .tenure
                .retained_initialization
                .load(std::sync::atomic::Ordering::Acquire));
            drop(state);
            assert!(registry
                .operation_settlement_integrity_diagnostic(false)
                .0
                .is_err());
        }
    }
    #[test]
    fn retained_initializer_owner_retirement_keeps_strict_frozen_inventory() {
        let registry = ClientTargets::new("ctx".into(), "scope".into());
        let custody = retained_initializer(&registry);
        registry.seal_for_owner_retirement(
            &super::super::client_browser::OwnerRetirement::for_test(&registry),
        );
        assert_eq!(
            registry.state.lock().unwrap().owner_retirement_inventory,
            Some(false)
        );
        assert!(registry
            .operation_settlement_integrity_diagnostic(false)
            .0
            .is_err());
        assert!(registry.check_settlement_integrity().is_err());
        drop(custody);
        assert_eq!(
            registry.state.lock().unwrap().owner_retirement_inventory,
            Some(false)
        );
    }
    #[test]
    fn retained_initializer_observed_detach_is_not_generic_target_absence() {
        let registry = ClientTargets::new("ctx".into(), "scope".into());
        let mut custody = retained_initializer(&registry);
        registry.detach("popup").unwrap();
        assert!(custody.finish(true).is_err());
        drop(custody);
        assert!(registry.state.lock().unwrap().integrity_lost);
    }

    #[tokio::test]
    async fn sealed_observation_comparison_ignores_only_health_not_attachment_tenure() {
        for mode in ["sealed", "removed", "replacement"] {
            let targets = ClientTargets::new("ctx".into(), "scope".into());
            targets
                .attached("ctx", "tab".into(), "session".into(), "page".into())
                .unwrap();
            targets.configured("tab").unwrap();
            targets
                .resume_permit("tab")
                .await
                .unwrap()
                .complete()
                .unwrap();
            let captured = targets.owned_target("tab").unwrap();
            if mode == "sealed" {
                targets.seal();
            } else {
                targets.detach("tab").unwrap();
                if mode == "replacement" {
                    targets
                        .attached("ctx", "tab".into(), "session".into(), "page".into())
                        .unwrap();
                    targets.configured("tab").unwrap();
                    targets
                        .resume_permit("tab")
                        .await
                        .unwrap()
                        .complete()
                        .unwrap();
                }
            }
            assert_eq!(
                targets.retains_exact_attachment(&captured),
                mode == "sealed"
            );
            if mode == "sealed" {
                assert!(targets.owned_target("tab").is_err());
            }
        }
    }

    #[tokio::test]
    async fn media_detach_receipt_is_bound_to_registry_tenure_and_direct_ready_page() {
        for mode in [
            "exact",
            "missing",
            "wrong-session",
            "replacement",
            "foreign-owner",
            "iframe",
            "pending",
            "sealed",
        ] {
            let targets = ClientTargets::new("ctx".into(), "scope".into());
            let kind = if mode == "iframe" { "iframe" } else { "page" };
            targets
                .attached("ctx", "tab".into(), "session".into(), kind.into())
                .unwrap();
            if mode != "pending" {
                targets.configured("tab").unwrap();
                targets
                    .resume_permit("tab")
                    .await
                    .unwrap()
                    .complete()
                    .unwrap();
            }
            let original = targets.owned_target("tab").unwrap();
            if mode != "missing" {
                targets
                    .observe_media_detach(
                        "tab",
                        if mode == "wrong-session" {
                            "other"
                        } else {
                            "session"
                        },
                    )
                    .unwrap();
            }
            assert!(
                !targets.media_attachment_detached(&original).unwrap(),
                "a live entry is not retired: {mode}"
            );
            targets.detach("tab").unwrap();
            if mode == "replacement" {
                targets
                    .attached("ctx", "tab".into(), "session".into(), "page".into())
                    .unwrap();
                assert!(!targets
                    .owned_target("tab")
                    .unwrap()
                    .same_attachment(&original));
            }
            if mode == "sealed" {
                targets.seal();
                assert!(targets.media_attachment_detached(&original).is_err());
            } else if mode == "foreign-owner" {
                let foreign = ClientTargets::new("ctx".into(), "scope".into());
                assert!(!foreign.media_attachment_detached(&original).unwrap());
            } else {
                assert_eq!(
                    targets.media_attachment_detached(&original).unwrap(),
                    mode == "exact",
                    "{mode}"
                );
            }
        }
    }

    fn startup_worker() -> std::sync::Arc<ClientTargets> {
        let targets = ClientTargets::new("ctx".into(), "scope".into());
        targets
            .attached(
                "ctx",
                "worker".into(),
                "session".into(),
                "service_worker".into(),
            )
            .unwrap();
        targets
    }

    #[test]
    fn terminal_eof_seal_never_clears_real_target_poison_or_grants_admission() {
        use super::super::client_debt::OwnerDebtLedger;
        use super::super::client_session::{CancelSignal, OperationLease};
        for poison_before in [false, true] {
            let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let operation = OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(5),
                cancellation,
            };
            let ledger = OwnerDebtLedger::unpublished(&operation, "scope".into(), false).unwrap();
            ledger.bind_context("context").unwrap();
            let targets = ClientTargets::new_managed("context".into(), "scope".into());
            targets
                .bind_eval_owner(&ledger, operation.generation)
                .unwrap();
            ledger.observe_remote_eof();
            if poison_before {
                targets.seal();
            }
            targets.seal_remote_connection(&ledger);
            {
                let state = targets.state.lock().unwrap();
                assert!(state.sealed);
                assert_eq!(state.integrity_lost, poison_before);
            }
            assert!(targets.inventory().is_err());
            assert!(targets.acknowledge_enrollment().is_err());
            targets.seal();
            targets.seal_remote_connection(&ledger);
            assert!(
                targets.state.lock().unwrap().integrity_lost,
                "later poison must remain sticky"
            );
        }
    }

    #[tokio::test]
    async fn service_worker_retirement_requires_exact_detach_and_absent_original_tenure() {
        for scenario in [
            "exact",
            "missing",
            "wrong-session",
            "target-reused",
            "session-reused",
            "same-ids",
            "sealed",
        ] {
            let targets = startup_worker();
            let mut permit = targets
                .service_worker_startup_permit("worker", "session")
                .await
                .unwrap();
            if scenario != "missing" {
                targets
                    .observe_worker_detach(
                        "worker",
                        if scenario == "wrong-session" {
                            "other"
                        } else {
                            "session"
                        },
                    )
                    .unwrap();
            }
            targets.detach("worker").unwrap();
            if matches!(scenario, "target-reused" | "session-reused" | "same-ids") {
                targets
                    .attached(
                        "ctx",
                        if matches!(scenario, "target-reused" | "same-ids") {
                            "worker"
                        } else {
                            "new-worker"
                        }
                        .into(),
                        if matches!(scenario, "session-reused" | "same-ids") {
                            "session"
                        } else {
                            "new-session"
                        }
                        .into(),
                        "service_worker".into(),
                    )
                    .unwrap();
            }
            if scenario == "sealed" {
                targets.seal();
            }
            let result =
                permit.finish_retired_worker_startup(&targets, "worker", "session", || Ok(()));
            assert_eq!(result.is_ok(), scenario == "exact", "{scenario}");
            assert_eq!(targets.state.lock().unwrap().resuming, 1);
            assert!(!targets
                .state
                .lock()
                .unwrap()
                .targets
                .values()
                .any(|entry| entry.configured || entry.resumed));
            drop(permit);
            let state = targets.state.lock().unwrap();
            assert_eq!(state.resuming, 0);
            assert_eq!(state.integrity_lost, scenario != "exact", "{scenario}");
        }
    }

    #[tokio::test]
    async fn service_worker_startup_keeps_configuration_false_until_complete() {
        let targets = startup_worker();
        let permit = targets
            .service_worker_startup_permit("worker", "session")
            .await
            .unwrap();
        {
            let state = targets.state.lock().unwrap();
            assert!(!state.inventory_complete());
            assert_eq!(state.resuming, 1);
            assert!(!state.targets["worker"].configured);
            assert!(state.targets["worker"].resume_pending);
            assert!(!state.targets["worker"].capture_ready());
        }
        assert!(targets.check_settlement_integrity().is_err());
        assert!(targets
            .service_worker_startup_permit("worker", "session")
            .await
            .is_err());
        permit.complete().unwrap();
        {
            let state = targets.state.lock().unwrap();
            assert!(state.inventory_complete());
            assert_eq!(state.resuming, 0);
            assert!(state.targets["worker"].capture_ready());
        }
        targets.check_settlement_integrity().unwrap();
    }

    #[tokio::test]
    async fn service_worker_startup_refuses_wrong_kind_session_and_retired_owner() {
        for kind in ["page", "iframe", "worker", "shared_worker"] {
            let targets = ClientTargets::new("ctx".into(), "scope".into());
            targets
                .attached("ctx", "worker".into(), "session".into(), kind.into())
                .unwrap();
            assert!(targets
                .service_worker_startup_permit("worker", "session")
                .await
                .is_err());
        }
        let targets = startup_worker();
        assert!(targets
            .service_worker_startup_permit("worker", "foreign")
            .await
            .is_err());
        targets.seal();
        assert!(targets
            .service_worker_startup_permit("worker", "session")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn service_worker_startup_drop_cannot_publish_ready() {
        let targets = startup_worker();
        let permit = targets
            .service_worker_startup_permit("worker", "session")
            .await
            .unwrap();
        drop(permit);
        let state = targets.state.lock().unwrap();
        assert!(state.sealed && state.integrity_lost);
        assert_eq!(state.resuming, 0);
        assert!(!state.targets["worker"].configured);
        assert!(!state.targets["worker"].resumed);
    }

    #[tokio::test]
    async fn service_worker_startup_same_id_replacement_rejects_old_permit() {
        let targets = startup_worker();
        let old = targets
            .service_worker_startup_permit("worker", "session")
            .await
            .unwrap();
        targets.detach("worker").unwrap();
        targets
            .attached(
                "ctx",
                "worker".into(),
                "session".into(),
                "service_worker".into(),
            )
            .unwrap();
        assert_eq!(old.complete(), Err(ProtocolError::StaleScope));
        let state = targets.state.lock().unwrap();
        assert!(!state.targets["worker"].configured);
        assert!(!state.targets["worker"].resumed);
        assert!(state.integrity_lost);
    }

    #[tokio::test]
    async fn service_worker_startup_replacement_while_waiting_is_rejected() {
        let targets = startup_worker();
        targets.state.lock().unwrap().protected_read = Some(ProtectedExclusion::Global {
            token: Arc::new(()),
        });
        let future = targets.service_worker_startup_permit("worker", "session");
        tokio::pin!(future);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut future)
                .await
                .is_err()
        );
        targets.detach("worker").unwrap();
        targets
            .attached(
                "ctx",
                "worker".into(),
                "session".into(),
                "service_worker".into(),
            )
            .unwrap();
        targets.state.lock().unwrap().protected_read = None;
        targets.changed.notify_waiters();
        assert!(matches!(future.await, Err(ProtocolError::StaleScope)));
        assert_eq!(targets.state.lock().unwrap().resuming, 0);
        assert!(!targets.state.lock().unwrap().targets["worker"].resume_pending);
    }

    #[tokio::test]
    async fn service_worker_startup_capacity_failure_does_not_set_pending() {
        let targets = startup_worker();
        targets.state.lock().unwrap().resuming = usize::MAX;
        assert!(matches!(
            targets
                .service_worker_startup_permit("worker", "session")
                .await,
            Err(ProtocolError::CapacityExceeded)
        ));
        assert!(!targets.state.lock().unwrap().targets["worker"].resume_pending);
    }

    #[tokio::test]
    async fn service_worker_startup_waits_for_protected_read_without_setting_configured() {
        let targets = startup_worker();
        targets.state.lock().unwrap().protected_read = Some(ProtectedExclusion::Global {
            token: Arc::new(()),
        });
        let future = targets.service_worker_startup_permit("worker", "session");
        tokio::pin!(future);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut future)
                .await
                .is_err()
        );
        {
            let mut state = targets.state.lock().unwrap();
            assert_eq!(state.resuming, 0);
            assert!(!state.targets["worker"].configured);
            state.protected_read = None;
        }
        targets.changed.notify_waiters();
        let permit = future.await.unwrap();
        permit.complete().unwrap();
    }

    #[test]
    fn eval_owner_binding_requires_exact_ledger_before_enable_and_cannot_be_rebound() {
        let targets = ClientTargets::new("context".into(), "scope".into());
        let ledger = super::super::client_debt::OwnerDebtLedger::new(1, "scope".into());
        let same_labels = super::super::client_debt::OwnerDebtLedger::new(1, "scope".into());
        assert_eq!(
            targets.require_eval_owner(&ledger),
            Err(ProtocolError::StaleScope)
        );
        assert_eq!(
            targets.bind_eval_owner(&ledger, 2),
            Err(ProtocolError::StaleScope)
        );
        targets.bind_eval_owner(&ledger, 1).unwrap();
        targets.require_eval_owner(&ledger).unwrap();
        assert_eq!(
            targets.bind_eval_owner(&same_labels, 1),
            Err(ProtocolError::StaleScope)
        );
        assert_eq!(
            targets.require_eval_owner(&same_labels),
            Err(ProtocolError::StaleScope)
        );
        let revision = ledger.eval_authority_revision().unwrap();
        targets.seal_admission();
        assert!(ledger.eval_authority_revision().unwrap() > revision);
    }

    #[tokio::test]
    async fn eval_target_failure_and_drop_paths_revoke_reserved_child_and_retain_root_debt() {
        use super::super::client_debt::{
            tests::{eval_child, eval_fixture, eval_reservation},
            EvalCommandGrant,
        };
        for mode in [
            "resume-complete",
            "resume-drop",
            "aux-claim",
            "aux-quarantine",
            "aux-overflow",
            "creation-drop",
            "seal",
            "seal-admission",
            "owner-foreign",
            "owner",
            "inventory",
        ] {
            let targets = ClientTargets::new("context".into(), "scope".into());
            targets
                .attached("context", "target".into(), "page".into(), "page".into())
                .unwrap();
            targets.configured("target").unwrap();
            let resume = targets.resume_permit("target").await.unwrap();
            let mut resume = if mode.starts_with("resume-") {
                Some(resume)
            } else {
                resume.complete().unwrap();
                None
            };
            let mut auxiliary = if mode.starts_with("aux-") {
                Some(
                    targets
                        .reserve_auxiliary_attachment("scope", "target", "page")
                        .unwrap(),
                )
            } else {
                None
            };
            let mut creation = if mode == "creation-drop" {
                Some(
                    targets
                        .reserve_creation(super::TargetPurpose::Application)
                        .unwrap(),
                )
            } else {
                None
            };
            // Arrange the exact late failure without triggering its production
            // loss-of-integrity path until after the child has been reserved.
            if mode == "resume-complete" {
                targets
                    .state
                    .lock()
                    .unwrap()
                    .targets
                    .get_mut("target")
                    .unwrap()
                    .session_id = "replacement".into();
            }
            if let Some(auxiliary) = &auxiliary {
                let mut state = targets.state.lock().unwrap();
                let entry = state.auxiliary.get_mut(&auxiliary.nonce).unwrap();
                if mode == "aux-claim" {
                    entry.failed = true;
                }
                if mode == "aux-overflow" {
                    entry
                        .candidates
                        .extend((0..64).map(|n| format!("candidate-{n}")));
                }
            }
            let (ledger, journal, root, window) = eval_fixture();
            targets.bind_eval_owner(&ledger, 7).unwrap();
            let _root = eval_reservation(&ledger, &journal, EvalCommandGrant::Root(window.clone()))
                .await
                .submit()
                .unwrap();
            let (_, child_journal, permit) = eval_child(&ledger, &root, &window);
            let child =
                eval_reservation(&ledger, &child_journal, EvalCommandGrant::Child(permit)).await;
            match mode {
                "resume-complete" => {
                    assert_eq!(
                        resume.take().unwrap().complete(),
                        Err(ProtocolError::StaleScope)
                    );
                }
                "resume-drop" => drop(resume.take()),
                "aux-claim" => {
                    assert_eq!(
                        auxiliary.as_mut().unwrap().claim("late-recorder"),
                        Err(ProtocolError::StaleScope)
                    );
                }
                "aux-quarantine" => auxiliary.as_ref().unwrap().quarantine(),
                "aux-overflow" => {
                    assert_eq!(
                        targets
                            .classify_auxiliary_attachment("target", "new-candidate")
                            .await,
                        Err(ProtocolError::CapacityExceeded)
                    );
                }
                "creation-drop" => drop(creation.take()),
                "seal" => targets.seal(),
                "seal-admission" => targets.seal_admission(),
                "inventory" => targets.invalidate_inventory().unwrap(),
                "owner-foreign" => {
                    let foreign = ClientTargets::new("foreign".into(), "foreign".into());
                    targets.seal_for_owner_retirement(
                        &super::super::client_browser::OwnerRetirement::for_test(&foreign),
                    );
                }
                _ => targets.seal_for_owner_retirement(
                    &super::super::client_browser::OwnerRetirement::for_test(&targets),
                ),
            }
            assert!(
                matches!(child.submit(), Err(ProtocolError::ScopeUnavailable)),
                "{mode}"
            );
            assert_eq!(ledger.snapshot().input_debt, 1, "{mode}");
            assert!(!child_journal.snapshot().mutation_dispatched, "{mode}");
            if let Some(auxiliary) = &mut auxiliary {
                let _ = auxiliary.claim("late-recorder");
                assert!(ledger.issue_eval_child(&window, &root).is_err());
                assert_eq!(ledger.snapshot().input_debt, 1);
            }
        }
    }
    #[tokio::test]
    async fn eval_read_only_auxiliary_classification_does_not_revoke_on_repeat() {
        use futures_util::FutureExt;
        let targets = ClientTargets::new("context".into(), "scope".into());
        targets
            .attached("context", "target".into(), "page".into(), "page".into())
            .unwrap();
        targets.configured("target").unwrap();
        targets
            .resume_permit("target")
            .await
            .unwrap()
            .complete()
            .unwrap();
        let auxiliary = targets
            .reserve_auxiliary_attachment("scope", "target", "page")
            .unwrap();
        targets
            .state
            .lock()
            .unwrap()
            .auxiliary
            .get_mut(&auxiliary.nonce)
            .unwrap()
            .candidates
            .insert("candidate".into());
        let ledger = super::super::client_debt::OwnerDebtLedger::new(7, "scope".into());
        targets.bind_eval_owner(&ledger, 7).unwrap();
        let revision = ledger.eval_authority_revision().unwrap();
        for _ in 0..2 {
            assert_eq!(
                targets
                    .classify_auxiliary_attachment("target", "page")
                    .await,
                Ok(super::AuxiliaryDisposition::Ordinary)
            );
            assert!(targets
                .classify_auxiliary_attachment("target", "candidate")
                .now_or_never()
                .is_none());
            assert_eq!(ledger.eval_authority_revision(), Ok(revision));
        }
        // A genuinely new candidate is a mutation and does revoke once.
        assert!(targets
            .classify_auxiliary_attachment("target", "new-candidate")
            .now_or_never()
            .is_none());
        assert!(ledger.eval_authority_revision().unwrap() > revision);
    }

    #[test]
    fn inventory_diagnostic_preserves_refusal_and_never_seals_pending_inventory() {
        let registry = super::ClientTargets::new("ctx".into(), "scope".into());
        let reservation = registry
            .reserve_creation(super::TargetPurpose::Application)
            .unwrap();
        let (result, snapshot) = registry.settlement_integrity_diagnostic(true);
        assert_eq!(result, Err(super::ProtocolError::ScopeUnavailable));
        assert!(snapshot.observed);
        assert_eq!(snapshot.reservations, 1);
        assert!(!snapshot.sealed && !snapshot.integrity_lost);
        assert_eq!(registry.inventory_diagnostic().reservations, 1);
        registry.seal();
        let (result, snapshot) = registry.settlement_integrity_diagnostic(true);
        assert_eq!(result, Err(super::ProtocolError::ScopeUnavailable));
        assert!(snapshot.sealed && snapshot.integrity_lost);
        drop(reservation);
    }
    fn settlement_registry() -> std::sync::Arc<super::ClientTargets> {
        let registry = super::ClientTargets::new("ctx".into(), "scope".into());
        registry
            .attached("ctx", "target".into(), "session".into(), "page".into())
            .unwrap();
        registry.configured("target").unwrap();
        registry
    }

    #[test]
    fn owner_retirement_preserves_settlement_only_and_never_reopens_admission() {
        let registry = settlement_registry();
        registry.check_settlement_integrity().unwrap();
        registry.seal_for_owner_retirement(
            &super::super::client_browser::OwnerRetirement::for_test(&registry),
        );
        registry.seal_admission();
        registry.seal_for_owner_retirement(
            &super::super::client_browser::OwnerRetirement::for_test(&registry),
        );
        registry.check_settlement_integrity().unwrap();
        assert!(registry.inventory().is_err());
        assert!(registry.owned_target("target").is_err());
        assert!(registry
            .reserve_creation(super::TargetPurpose::Application)
            .is_err());
        assert!(registry
            .attached("ctx", "later".into(), "later-session".into(), "page".into())
            .is_err());
    }

    #[test]
    fn final_local_cleanup_preserves_every_registry_obligation_and_poison() {
        let empty = ClientTargets::new("ctx".into(), "scope".into());
        assert!(empty.check_final_local_cleanup().is_err());
        empty.acknowledge_enrollment().unwrap();
        empty.seal_admission();
        empty.check_final_local_cleanup().unwrap();
        empty.seal();
        assert!(empty.check_final_local_cleanup().is_err());
        for case in [
            "reservation",
            "resuming",
            "protected",
            "bootstrap",
            "cleanup-target",
            "cleanup-reservation",
            "unknown-create",
            "live-target",
        ] {
            let registry = ClientTargets::new("ctx".into(), "scope".into());
            registry.acknowledge_enrollment().unwrap();
            if case == "live-target" {
                registry
                    .attached("ctx", "target".into(), "session".into(), "page".into())
                    .unwrap();
            } else {
                let mut state = registry.state.lock().unwrap();
                match case {
                    "reservation" => state.reservations = 1,
                    "resuming" => state.resuming = 1,
                    "protected" => {
                        state.protected_read = Some(ProtectedExclusion::Global {
                            token: Arc::new(()),
                        })
                    }
                    "bootstrap" => {
                        state.bootstrap_creations.insert(1, None);
                    }
                    "cleanup-target" => {
                        state.native_bootstrap_cleanup.insert("target".into());
                    }
                    "cleanup-reservation" => {
                        state.bootstrap_cleanup_reservations.insert(1);
                    }
                    "unknown-create" => state.unknown_bootstrap_create = true,
                    _ => unreachable!(),
                }
            }
            registry.seal_admission();
            assert!(registry.check_final_local_cleanup().is_err(), "{case}");
        }
    }

    #[test]
    fn owner_retirement_never_clears_earlier_or_later_integrity_sealing() {
        for poison_first in [false, true] {
            let registry = settlement_registry();
            if poison_first {
                registry.seal();
            }
            registry.seal_for_owner_retirement(
                &super::super::client_browser::OwnerRetirement::for_test(&registry),
            );
            registry.seal();
            registry.seal_admission();
            registry.seal_for_owner_retirement(
                &super::super::client_browser::OwnerRetirement::for_test(&registry),
            );
            assert!(registry.check_settlement_integrity().is_err());
        }
        let unowned = settlement_registry();
        unowned.seal_admission();
        unowned.seal_for_owner_retirement(
            &super::super::client_browser::OwnerRetirement::for_test(&unowned),
        );
        assert!(unowned.check_settlement_integrity().is_err());

        let original = settlement_registry();
        let replacement = settlement_registry();
        let foreign = super::super::client_browser::OwnerRetirement::for_test(&original);
        replacement.seal_for_owner_retirement(&foreign);
        assert!(replacement.check_settlement_integrity().is_err());
        assert!(replacement.inventory().is_err());
        original.check_settlement_integrity().unwrap();
    }

    #[test]
    fn owner_retirement_does_not_repair_incomplete_inventory_or_poisoned_lock() {
        let incomplete = settlement_registry();
        incomplete
            .attached(
                "ctx",
                "unfinished".into(),
                "unfinished-session".into(),
                "page".into(),
            )
            .unwrap();
        incomplete.seal_for_owner_retirement(
            &super::super::client_browser::OwnerRetirement::for_test(&incomplete),
        );
        assert!(incomplete.check_settlement_integrity().is_err());
        // Even subsequent cleanup cannot manufacture the missing initial proof.
        incomplete
            .state
            .lock()
            .unwrap()
            .targets
            .remove("unfinished");
        incomplete.seal_for_owner_retirement(
            &super::super::client_browser::OwnerRetirement::for_test(&incomplete),
        );
        assert!(incomplete.check_settlement_integrity().is_err());

        let reserved = settlement_registry();
        let reservation = reserved
            .reserve_creation(super::TargetPurpose::Application)
            .unwrap();
        reserved.seal_for_owner_retirement(
            &super::super::client_browser::OwnerRetirement::for_test(&reserved),
        );
        assert!(reserved.check_settlement_integrity().is_err());
        drop(reservation);
        assert!(reserved.check_settlement_integrity().is_err());

        let poisoned = settlement_registry();
        poisoned.seal_for_owner_retirement(
            &super::super::client_browser::OwnerRetirement::for_test(&poisoned),
        );
        let captured = poisoned.clone();
        let _ = std::thread::spawn(move || {
            let _guard = captured.state.lock().unwrap();
            panic!("synthetic registry lock poison");
        })
        .join();
        assert!(poisoned.check_settlement_integrity().is_err());
        assert!(poisoned.inventory().is_err());
    }

    #[tokio::test]
    async fn capture_ticket_is_insertion_only_and_rejects_same_id_aba_without_epoch() {
        let registry = super::ClientTargets::new("ctx".into(), "scope".into());
        registry
            .attached(
                "ctx",
                "target".into(),
                "session".into(),
                "browser_ui".into(),
            )
            .unwrap();
        registry.configured("target").unwrap();
        registry
            .resume_permit("target")
            .await
            .unwrap()
            .complete()
            .unwrap();
        let original = registry.capture_application_tickets(&["target"]).unwrap();
        let clone = registry.owned_target("target").unwrap();
        assert!(clone.same_attachment(&original[0]));
        registry.check_capture_tickets(&original).unwrap();
        registry.detach("target").unwrap();
        registry
            .attached(
                "ctx",
                "target".into(),
                "session".into(),
                "browser_ui".into(),
            )
            .unwrap();
        registry.configured("target").unwrap();
        registry
            .resume_permit("target")
            .await
            .unwrap()
            .complete()
            .unwrap();
        let replacement = registry.capture_application_tickets(&["target"]).unwrap();
        assert!(!replacement[0].same_attachment(&original[0]));
        assert_eq!(
            registry.check_capture_tickets(&original),
            Err(super::ProtocolError::StaleScope)
        );
        registry.check_capture_tickets(&replacement).unwrap();
    }
    #[tokio::test]
    async fn capture_readiness_rejects_pending_resume_even_with_resumed_flag() {
        let registry = super::ClientTargets::new("ctx".into(), "scope".into());
        registry
            .attached("ctx", "target".into(), "session".into(), "page".into())
            .unwrap();
        registry.configured("target").unwrap();
        let resume = registry.resume_permit("target").await.unwrap();
        let mut pending = registry.owned_target("target").unwrap();
        assert!(!pending.capture_ready());
        // Keep every other readiness term true to prove that the existing
        // private pending bit cannot be bypassed by the exposed predicate.
        pending.resumed = true;
        assert!(!pending.capture_ready());
        resume.complete().unwrap();
        assert!(registry.owned_target("target").unwrap().capture_ready());
        assert!(
            !pending.capture_ready(),
            "old snapshots never gain readiness"
        );
    }

    #[tokio::test]
    async fn capture_ticket_checks_entire_exact_binding_and_rejects_duplicates() {
        let registry = super::ClientTargets::new("ctx".into(), "scope".into());
        for target in ["a", "b"] {
            registry
                .attached(
                    "ctx",
                    target.into(),
                    format!("{target}-session"),
                    "browser_ui".into(),
                )
                .unwrap();
            registry.configured(target).unwrap();
            registry
                .resume_permit(target)
                .await
                .unwrap()
                .complete()
                .unwrap();
        }
        let original = registry.capture_application_tickets(&["a", "b"]).unwrap();
        assert!(registry.capture_application_tickets(&["a", "a"]).is_err());
        assert!(registry
            .check_capture_tickets(&[original[0].clone(), original[0].clone()])
            .is_err());
        for field in [
            "target",
            "session",
            "kind",
            "purpose",
            "configured",
            "resumed",
            "pending",
        ] {
            let mut changed = original.clone();
            match field {
                "target" => changed[0].target_id = "b".into(),
                "session" => changed[0].session_id = "b-session".into(),
                "kind" => changed[0].kind = "worker".into(),
                "purpose" => changed[0].purpose = Some(super::TargetPurpose::StateBootstrap),
                "configured" => changed[0].configured = false,
                "resumed" => changed[0].resumed = false,
                "pending" => changed[0].resume_pending = true,
                _ => unreachable!(),
            }
            assert_eq!(
                registry.check_capture_tickets(&changed),
                Err(super::ProtocolError::StaleScope),
                "{field}"
            );
        }
    }

    #[test]
    fn unknown_bootstrap_ack_cannot_be_certified_by_empty_cleanup_inventory() {
        let registry = super::ClientTargets::new("ctx".into(), "scope".into());
        let reservation = registry
            .reserve_creation(super::TargetPurpose::StateBootstrap)
            .unwrap();
        assert!(!registry.native_bootstrap_cleanup_complete().unwrap());
        drop(reservation);
        assert!(registry
            .native_bootstrap_cleanup_targets()
            .unwrap()
            .is_empty());
        assert!(!registry.native_bootstrap_cleanup_complete().unwrap());
        assert!(registry.state.lock().unwrap().sealed);
    }
    #[test]
    fn native_bootstrap_cleanup_capacity_is_reserved_before_browser_creation() {
        let registry = super::ClientTargets::new("ctx".into(), "scope".into());
        {
            let mut state = registry.state.lock().unwrap();
            state
                .native_bootstrap_cleanup
                .extend((0..63).map(|i| format!("retained-{i}")));
        }
        let mut last = registry
            .reserve_creation(super::TargetPurpose::StateBootstrap)
            .unwrap();
        assert!(matches!(
            registry.reserve_creation(super::TargetPurpose::StateBootstrap),
            Err(super::ProtocolError::CapacityExceeded)
        ));
        last.record_native_created_target("last-ack").unwrap();
        assert_eq!(
            registry.native_bootstrap_cleanup_targets().unwrap().len(),
            64
        );
        assert!(matches!(
            registry.reserve_creation(super::TargetPurpose::StateBootstrap),
            Err(super::ProtocolError::CapacityExceeded)
        ));
    }
    #[tokio::test]
    async fn native_bootstrap_ack_is_exact_and_never_adopts_existing_application() {
        let registry = super::ClientTargets::new("ctx".into(), "scope".into());
        registry
            .attached("ctx", "host".into(), "host-session".into(), "page".into())
            .unwrap();
        let mut reservation = registry
            .reserve_creation(super::TargetPurpose::StateBootstrap)
            .unwrap();
        let info = |target: &str, context: &str| serde_json::json!({"targetId":target,"browserContextId":context,"type":"page","url":"about:blank"});
        assert_eq!(
            reservation.acknowledge_native_created_target(&info("created", "other")),
            Err(super::ProtocolError::PolicyDenied)
        );
        assert_eq!(
            reservation.record_native_created_target("host"),
            Err(super::ProtocolError::StaleScope)
        );
        assert!(!registry.is_native_bootstrap_target("host").unwrap());
        reservation.record_native_created_target("created").unwrap();
        reservation
            .acknowledge_native_created_target(&info("created", "ctx"))
            .unwrap();
        assert!(registry
            .wait_native_bootstrap_target("created")
            .await
            .unwrap());
        assert!(!registry
            .wait_native_bootstrap_target("unrelated")
            .await
            .unwrap());
        registry
            .attached(
                "ctx",
                "created".into(),
                "created-session".into(),
                "page".into(),
            )
            .unwrap();
        assert_eq!(
            reservation.claim("host"),
            Err(super::ProtocolError::StaleScope)
        );
        reservation.claim("created").unwrap();
        drop(reservation);
        assert!(!registry.is_native_bootstrap_target("created").unwrap());
        assert_eq!(
            registry.native_bootstrap_cleanup_targets().unwrap(),
            vec!["created"]
        );
        registry.settle_native_bootstrap_cleanup("created").unwrap();
        assert!(registry
            .native_bootstrap_cleanup_targets()
            .unwrap()
            .is_empty());
        assert_eq!(
            registry.owned_target("host").unwrap().purpose,
            Some(super::TargetPurpose::Application)
        );
        assert_eq!(
            registry.owned_target("created").unwrap().purpose,
            Some(super::TargetPurpose::StateBootstrap)
        );
    }
    #[test]
    fn diagnostic_ordinals_cannot_admit_inventory_or_change_attachment_authority() {
        let registry = super::ClientTargets::new("private-context".into(), "private-scope".into());
        registry
            .attached(
                "private-context",
                "private-target".into(),
                "private-session".into(),
                "worker".into(),
            )
            .unwrap();
        let before = registry.owned_target("private-target").unwrap();
        assert!(registry.check_settlement_integrity().is_err());
        {
            let mut state = registry.state.lock().unwrap();
            state.targets.get_mut("private-target").unwrap().diagnostic =
                Some(super::diagnostic::DiagnosticAttachment {
                    attachment: 7,
                    target: 9,
                    origin: super::diagnostic::DiagnosticTargetOrigin::AutoAttach,
                    classification:
                        super::diagnostic::DiagnosticTargetClassification::ReservedBootstrap,
                    ..Default::default()
                });
        }
        let observed = registry.owned_target("private-target").unwrap();
        assert!(
            before.same_attachment(&observed),
            "diagnostic identity is never ticket authority"
        );
        assert!(
            registry.check_settlement_integrity().is_err(),
            "an unconfigured attachment must still refuse settlement"
        );
        let facts = observed.diagnostic_snapshot().unwrap();
        assert_eq!(facts.kind, super::diagnostic::DiagnosticTargetKind::Worker);
        assert_eq!(
            facts.purpose,
            super::diagnostic::DiagnosticTargetPurpose::Application
        );
        assert!(!facts.configured);
        assert!(!format!("{facts:?}").contains("private-"));
        registry.configured("private-target").unwrap();
        assert!(
            registry.check_settlement_integrity().is_ok(),
            "only the original configured state changes admission"
        );
    }
    fn auxiliary_registry() -> std::sync::Arc<super::ClientTargets> {
        let registry = super::ClientTargets::new("ctx".into(), "scope".into());
        registry
            .attached("ctx", "target".into(), "primary".into(), "page".into())
            .unwrap();
        {
            let mut state = registry.state.lock().unwrap();
            let target = state.targets.get_mut("target").unwrap();
            target.configured = true;
            target.resumed = true;
            state.enrollment_ready = true;
        }
        registry
    }
    #[test]
    fn queued_iframe_retirement_cannot_bypass_auxiliary_cleanup_owner() {
        let registry = auxiliary_registry();
        registry
            .attached("ctx", "root".into(), "root-session".into(), "page".into())
            .unwrap();
        let root = registry.owned_target("root").unwrap();
        let mut auxiliary = registry
            .reserve_auxiliary_attachment("scope", "target", "primary")
            .unwrap();
        auxiliary.claim("recorder").unwrap();
        registry.detach("target").unwrap();
        assert!(registry.owned_target("target").is_err());
        assert_eq!(
            registry.finish_detached_queued_iframe("target", "candidate", &root, &root, || Ok(())),
            Err(super::ProtocolError::StaleScope)
        );
        // Even a completed recorder tombstone is not ordinary queued ownership.
        auxiliary.detached("recorder").unwrap();
        assert_eq!(
            registry.finish_detached_queued_iframe("target", "candidate", &root, &root, || Ok(())),
            Err(super::ProtocolError::StaleScope)
        );
        assert!(registry
            .finish_detached_queued_iframe("new-child", "new-session", &root, &root, || Ok(()))
            .is_ok());
    }

    #[tokio::test]
    async fn auxiliary_event_before_ack_waits_exact_claim_not_next_candidate() {
        let registry = auxiliary_registry();
        let mut reservation = registry
            .reserve_auxiliary_attachment("scope", "target", "primary")
            .unwrap();
        assert!(registry.protected_read_barrier().is_err());
        let owned = registry.classify_auxiliary_attachment("target", "recorder");
        let unrelated = registry.classify_auxiliary_attachment("target", "other");
        tokio::pin!(owned, unrelated);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut owned)
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut unrelated)
                .await
                .is_err()
        );
        reservation.claim("recorder").unwrap();
        assert_eq!(
            owned.await.unwrap(),
            super::AuxiliaryDisposition::RecorderOwned
        );
        assert_eq!(
            unrelated.await.unwrap(),
            super::AuxiliaryDisposition::Ordinary
        );
        assert_eq!(reservation.cleanup_sessions().unwrap(), vec!["recorder"]);
        reservation.detached("recorder").unwrap();
    }
    #[tokio::test]
    async fn auxiliary_ack_before_event_and_detach_tombstone_preserve_exact_identity() {
        let registry = auxiliary_registry();
        let mut reservation = registry
            .reserve_auxiliary_attachment("scope", "target", "primary")
            .unwrap();
        assert!(reservation.claim("primary").is_err());
        reservation.claim("recorder").unwrap();
        reservation.detached("recorder").unwrap();
        drop(reservation);
        let next = registry
            .reserve_auxiliary_attachment("scope", "target", "primary")
            .unwrap();
        assert_eq!(
            registry
                .classify_auxiliary_attachment("target", "recorder")
                .await
                .unwrap(),
            super::AuxiliaryDisposition::RecorderOwned
        );
        next.cancel_unsubmitted().unwrap();
        assert_eq!(
            registry
                .classify_auxiliary_attachment("target", "unrelated")
                .await
                .unwrap(),
            super::AuxiliaryDisposition::Ordinary
        );
    }
    #[tokio::test]
    async fn auxiliary_unknown_ack_retains_candidates_and_seal_wakes_waiter() {
        let registry = auxiliary_registry();
        let mut reservation = registry
            .reserve_auxiliary_attachment("scope", "target", "primary")
            .unwrap();
        let pending = registry.classify_auxiliary_attachment("target", "unknown");
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut pending)
                .await
                .is_err()
        );
        assert_eq!(reservation.cleanup_sessions().unwrap(), vec!["unknown"]);
        assert_eq!(
            reservation.detached("unknown"),
            Err(super::ProtocolError::CleanupFailed)
        );
        drop(reservation);
        assert_eq!(
            pending.await.unwrap(),
            super::AuxiliaryDisposition::RecorderOwned
        );
        assert!(registry
            .reserve_auxiliary_attachment("scope", "target", "primary")
            .is_err());
        assert!(registry
            .state
            .lock()
            .unwrap()
            .targets
            .contains_key("target"));
    }
    #[tokio::test]
    async fn auxiliary_late_ack_after_seal_or_target_replacement_remains_cleanup_owned() {
        for change in ["seal", "remove", "replace"] {
            let registry = auxiliary_registry();
            let mut token = registry
                .reserve_auxiliary_attachment("scope", "target", "primary")
                .unwrap();
            match change {
                "seal" => registry.seal(),
                "remove" => registry.detach("target").unwrap(),
                _ => {
                    registry
                        .state
                        .lock()
                        .unwrap()
                        .targets
                        .get_mut("target")
                        .unwrap()
                        .session_id = "replacement".into()
                }
            }
            assert_eq!(
                token.claim("primary"),
                Err(super::ProtocolError::InvalidArguments)
            );
            assert!(token.cleanup_sessions().unwrap().is_empty());
            assert_eq!(
                token.claim("late-recorder"),
                Err(super::ProtocolError::StaleScope)
            );
            assert_eq!(token.cleanup_sessions().unwrap(), vec!["late-recorder"]);
            assert_eq!(
                registry
                    .classify_auxiliary_attachment("target", "late-recorder")
                    .await
                    .unwrap(),
                super::AuxiliaryDisposition::RecorderOwned
            );
            token.detached("late-recorder").unwrap();
            assert!(registry.state.lock().unwrap().sealed);
            assert_eq!(
                registry
                    .classify_auxiliary_attachment("target", "late-recorder")
                    .await
                    .unwrap(),
                super::AuxiliaryDisposition::RecorderOwned
            );
        }
    }
    #[tokio::test]
    async fn auxiliary_seal_candidate_handoff_then_late_ack_has_one_cleanup_owner() {
        let registry = auxiliary_registry();
        let mut token = registry
            .reserve_auxiliary_attachment("scope", "target", "primary")
            .unwrap();
        registry.seal();
        assert_eq!(
            registry
                .classify_auxiliary_attachment("target", "late")
                .await
                .unwrap(),
            super::AuxiliaryDisposition::RecorderOwned
        );
        assert_eq!(token.cleanup_sessions().unwrap(), vec!["late"]);
        assert_eq!(
            registry
                .classify_auxiliary_attachment("target", "other-unknown")
                .await
                .unwrap(),
            super::AuxiliaryDisposition::RecorderOwned
        );
        assert_eq!(token.claim("late"), Err(super::ProtocolError::StaleScope));
        assert_eq!(
            token.cleanup_sessions().unwrap(),
            vec!["late", "other-unknown"]
        );
        assert_eq!(
            registry
                .classify_auxiliary_attachment("target", "later-unrelated")
                .await
                .unwrap(),
            super::AuxiliaryDisposition::Ordinary
        );

        assert_eq!(
            token.detached("late"),
            Err(super::ProtocolError::CleanupFailed)
        );
        token.candidate_detached("other-unknown").unwrap();
        token.detached("late").unwrap();
        assert_eq!(
            registry
                .classify_auxiliary_attachment("target", "late")
                .await
                .unwrap(),
            super::AuxiliaryDisposition::RecorderOwned
        );
    }
    #[tokio::test]
    async fn completed_auxiliary_cleanup_stays_complete_under_sealed_late_events() {
        let registry = auxiliary_registry();
        let mut token = registry
            .reserve_auxiliary_attachment("scope", "target", "primary")
            .unwrap();
        token.claim("recorder").unwrap();
        token.detached("recorder").unwrap();
        registry.seal();
        assert!(registry.auxiliary_cleanup_complete().unwrap());
        assert_eq!(
            registry
                .classify_auxiliary_attachment("target", "recorder")
                .await
                .unwrap(),
            super::AuxiliaryDisposition::RecorderOwned
        );
        assert_eq!(
            registry
                .classify_auxiliary_attachment("target", "unrelated")
                .await
                .unwrap(),
            super::AuxiliaryDisposition::Ordinary
        );
        assert!(registry
            .reserve_auxiliary_attachment("scope", "target", "primary")
            .is_err());
        assert!(registry.auxiliary_cleanup_complete().unwrap());
    }
    #[test]
    fn auxiliary_reservation_rejects_wrong_scope_primary_and_duplicate_admission() {
        let registry = auxiliary_registry();
        assert!(registry
            .reserve_auxiliary_attachment("other", "target", "primary")
            .is_err());
        assert!(registry
            .reserve_auxiliary_attachment("scope", "target", "other")
            .is_err());
        let token = registry
            .reserve_auxiliary_attachment("scope", "target", "primary")
            .unwrap();
        assert!(registry
            .reserve_auxiliary_attachment("scope", "target", "primary")
            .is_err());
        token.cancel_unsubmitted().unwrap();
        assert!(!registry.state.lock().unwrap().sealed);
    }
    use super::*;
    #[tokio::test]
    async fn creation_reservation_keeps_bootstrap_out_of_generic_request_handling() {
        let registry = ClientTargets::new("owned".into(), "scope".into());
        let mut reservation = registry
            .reserve_creation(TargetPurpose::StateBootstrap)
            .unwrap();
        assert!(!registry
            .attached("other", "foreign".into(), "f".into(), "page".into())
            .unwrap());
        registry
            .attached("owned", "bootstrap".into(), "b".into(), "page".into())
            .unwrap();
        registry
            .attached("owned", "popup".into(), "p".into(), "page".into())
            .unwrap();
        assert!(registry.configured("bootstrap").is_err());
        assert!(registry.owned_target("bootstrap").is_err());
        assert!(registry.inventory().is_err());
        reservation.claim("bootstrap").unwrap();
        assert_eq!(registry.owned_target("bootstrap").unwrap().session_id, "b");
        assert_eq!(
            registry.purpose("bootstrap").await.unwrap(),
            TargetPurpose::StateBootstrap
        );
        drop(reservation);
        assert_eq!(
            registry.purpose("popup").await.unwrap(),
            TargetPurpose::Application
        );
        registry.configured("bootstrap").unwrap();
        registry.configured("popup").unwrap();
        let (revision, targets) = registry.inventory().unwrap();
        assert_eq!(targets.len(), 2);
        registry.invalidate_inventory().unwrap();
        assert!(registry.check_revision(revision).is_err());
    }
    #[tokio::test]
    async fn protected_barrier_waits_for_resume_ack_and_keeps_new_targets_paused() {
        let registry = ClientTargets::new("owned".into(), "scope".into());
        registry
            .attached("owned", "page".into(), "p".into(), "page".into())
            .unwrap();
        registry.configured("page").unwrap();
        let resume = registry.resume_permit("page").await.unwrap();
        assert!(registry.protected_read_barrier().is_err());
        resume.complete().unwrap();
        assert!(registry.protected_read_barrier().is_err());
        registry.acknowledge_enrollment().unwrap();
        let barrier = registry.protected_read_barrier().unwrap();
        registry
            .attached("owned", "child".into(), "c".into(), "iframe".into())
            .unwrap();
        registry.configured("child").unwrap();
        assert!(barrier.check().is_err());
        let pending = {
            let registry = registry.clone();
            tokio::spawn(async move { registry.resume_permit("child").await })
        };
        tokio::task::yield_now().await;
        assert!(!pending.is_finished());
        drop(barrier);
        pending.await.unwrap().unwrap().complete().unwrap();
        registry.protected_read_barrier().unwrap().check().unwrap();
    }
    #[tokio::test]
    async fn old_resume_ack_never_resumes_a_replacement_attachment() {
        let registry = ClientTargets::new("owned".into(), "scope".into());
        registry
            .attached("owned", "page".into(), "old".into(), "page".into())
            .unwrap();
        registry.configured("page").unwrap();
        let old = registry.resume_permit("page").await.unwrap();
        registry.detach("page").unwrap();
        registry
            .attached("owned", "page".into(), "new".into(), "page".into())
            .unwrap();
        registry.configured("page").unwrap();
        assert!(old.complete().is_err());
        let state = registry.state.lock().unwrap();
        assert!(state.sealed);
        assert!(!state.targets["page"].resumed);
        assert_eq!(state.targets["page"].session_id, "new");
    }
    #[test]
    fn protected_transaction_quarantine_seals_only_its_original_scope() {
        let old = ClientTargets::new("owned".into(), "old".into());
        let new = ClientTargets::new("owned".into(), "new".into());
        old.acknowledge_enrollment().unwrap();
        let barrier = old.protected_read_barrier().unwrap();
        assert!(old.reserve_creation(TargetPurpose::StateBootstrap).is_err());
        barrier.quarantine();
        drop(barrier);
        assert!(old.inventory().is_err());
        assert!(new.inventory().is_ok());
    }
    #[test]
    fn abandoned_creation_never_relabels_late_bootstrap_as_application() {
        let registry = ClientTargets::new("owned".into(), "scope".into());
        let reservation = registry
            .reserve_creation(TargetPurpose::StateBootstrap)
            .unwrap();
        registry
            .attached("owned", "late".into(), "session".into(), "page".into())
            .unwrap();
        drop(reservation);
        assert!(registry.configured("late").is_err());
        assert!(registry.inventory().is_err());
    }
    #[test]
    fn old_reservation_cannot_publish_after_scope_seal() {
        let registry = ClientTargets::new("owned".into(), "old".into());
        let mut reservation = registry
            .reserve_creation(TargetPurpose::StateBootstrap)
            .unwrap();
        registry
            .attached("owned", "target".into(), "session".into(), "page".into())
            .unwrap();
        registry.seal();
        assert!(reservation.claim("target").is_err());
        drop(reservation);
        assert!(registry.inventory().is_err());
    }
    #[test]
    fn initialization_publication_rejects_sealed_or_unacknowledged_registry() {
        let registry = ClientTargets::new("owned".into(), "scope".into());
        let gate = Arc::new(super::super::client_browser::ExecutionGate::default());
        gate.begin_transition().unwrap();
        let authority = gate.initialization(registry.clone()).unwrap();
        assert!(registry.publish_initialization(&authority).is_err());
        registry.acknowledge_enrollment().unwrap();
        registry.seal();
        assert!(registry.publish_initialization(&authority).is_err());
        assert!(gate.enter(false).is_err());
    }
    #[test]
    fn initialization_publication_preserves_exact_registry_and_gate_health() {
        let registry = ClientTargets::new("owned".into(), "scope".into());
        let other = ClientTargets::new("owned".into(), "other".into());
        registry.acknowledge_enrollment().unwrap();
        other.acknowledge_enrollment().unwrap();
        let gate = Arc::new(super::super::client_browser::ExecutionGate::default());
        gate.begin_transition().unwrap();
        let authority = gate.initialization(registry.clone()).unwrap();
        assert_eq!(
            other.publish_initialization(&authority),
            Err(ProtocolError::StaleScope)
        );
        let held = authority.enter(&registry).unwrap();
        assert!(registry.publish_initialization(&authority).is_err());
        drop(held);
        registry.publish_initialization(&authority).unwrap();
        drop(gate.enter(false).unwrap());
        gate.seal();
        assert!(registry.publish_initialization(&authority).is_err());
    }
}

#[cfg(test)]
mod atomic_revision_diagnostic_tests {
    use super::diagnostic::{
        FrameInventoryPass as Pass, InventoryRevisionEvent as Event,
        InventoryRevisionTarget as Target,
    };
    use super::*;
    fn selected() -> OwnedTarget {
        OwnedTarget {
            target_id: "private-target".into(),
            session_id: "private-session".into(),
            kind: "page".into(),
            purpose: Some(TargetPurpose::Application),
            configured: true,
            resumed: true,
            resume_pending: false,
            tenure: Arc::new(AttachmentTenure::default()),
            diagnostic: None,
        }
    }
    fn advance(state: &mut Registry, event: Event, target: Option<&OwnedTarget>) {
        state.revision += 1;
        state.note_revision_enabled(
            event,
            target.map(|target| target.tenure.clone()),
            target.and_then(|target| target.diagnostic.map(|value| value.attachment)),
        );
    }
    #[test]
    fn atomic_revision_causes_keep_original_result_and_snapshot() {
        for mask in 0..8 {
            let registry = ClientTargets::new("private-context".into(), "private-scope".into());
            let target = selected();
            registry
                .state
                .lock()
                .unwrap()
                .targets
                .insert(target.target_id.clone(), target.clone());
            let (revision, _, before) = registry.inventory_with_diagnostic(true).unwrap();
            {
                let mut state = registry.state.lock().unwrap();
                state.sealed = mask & 1 != 0;
                if mask & 2 != 0 {
                    advance(&mut state, Event::Navigate, Some(&target));
                }
                state.reservations = usize::from(mask & 4 != 0);
            }
            let original = registry.check_revision(revision);
            let (result, fact) = registry.check_revision_with_diagnostic(
                revision,
                before.as_ref(),
                &target,
                Pass::Protected,
            );
            assert_eq!(result, original);
            assert_eq!(fact.is_some(), mask != 0);
            if let Some(fact) = fact {
                assert_eq!(
                    (fact.sealed, fact.revision_mismatch, fact.reservations),
                    (mask & 1 != 0, mask & 2 != 0, mask & 4 != 0)
                );
                assert!(fact.exact);
                assert_eq!(fact.pass, Pass::Protected);
                registry.state.lock().unwrap().reservations = 0;
                assert_eq!(fact.reservations, mask & 4 != 0);
            }
        }
    }
    #[test]
    fn atomic_revision_events_include_every_bucket_and_same_target() {
        for event in [
            Event::Attach,
            Event::Detach,
            Event::Info,
            Event::Navigate,
            Event::SameDocument,
            Event::FrameDetach,
            Event::Unknown,
        ] {
            let mut state = Registry::default();
            let target = selected();
            let before = state.revision_snapshot();
            advance(
                &mut state,
                event,
                (event != Event::Unknown).then_some(&target),
            );
            let fact = state.revision_rejection(0, Some(&before), &target, Pass::Initial);
            let mut expected = [0; 7];
            expected[event.index()] = 1;
            assert_eq!(fact.events, Some(expected));
            assert_eq!(fact.delta, Some(1));
            assert_eq!(fact.last_event, event);
            assert_eq!(
                fact.last_target,
                if event == Event::Unknown {
                    Target::Unknown
                } else {
                    Target::Same
                }
            );
            assert_eq!(fact.exact, event != Event::Unknown);
        }
    }
    #[test]
    fn atomic_revision_multi_event_window_keeps_other_last_target() {
        let mut state = Registry::default();
        let target = selected();
        let other = selected();
        let before = state.revision_snapshot();
        advance(&mut state, Event::Attach, Some(&other));
        advance(&mut state, Event::Navigate, Some(&target));
        advance(&mut state, Event::Info, Some(&other));
        let fact = state.revision_rejection(0, Some(&before), &target, Pass::Final);
        assert_eq!(fact.events, Some([1, 0, 1, 1, 0, 0, 0]));
        assert_eq!(fact.delta, Some(3));
        assert!(fact.exact);
        assert_eq!(fact.last_target, Target::Other);
        assert_eq!(fact.last_event, Event::Info);
        state.revision += 1;
        let lost = state.revision_rejection(0, Some(&before), &target, Pass::Final);
        assert!(!lost.exact);
        assert_eq!(lost.last_event, Event::Unknown);
        assert_eq!(lost.last_target, Target::Unknown);
    }
    #[test]
    fn atomic_revision_ordinals_follow_commit_not_later_attachment_state() {
        let mut state = Registry::default();
        let mut target = selected();
        target.diagnostic = Some(diagnostic::DiagnosticAttachment {
            attachment: 11,
            ..Default::default()
        });
        let mut other = selected();
        other.diagnostic = Some(diagnostic::DiagnosticAttachment {
            attachment: 22,
            ..Default::default()
        });
        let before = state.revision_snapshot();
        advance(&mut state, Event::Attach, Some(&other));
        let captured = state.revision_rejection(0, Some(&before), &target, Pass::Initial);
        assert_eq!(captured.last_attachment, Some(22));
        assert_eq!(captured.selected_attachment, Some(11));
        assert_eq!(captured.last_target, Target::Other);
        assert_eq!(captured.events, Some([1, 0, 0, 0, 0, 0, 0]));
        assert!(captured.exact);

        // Identical native strings are not attachment identity. A later snapshot
        // or registration receipt cannot retrospectively name the previous event.
        other.tenure = Arc::new(AttachmentTenure::default());
        other.diagnostic.as_mut().unwrap().attachment = 33;
        state.targets.insert(other.target_id.clone(), other.clone());
        let retained = state.revision_rejection(0, Some(&before), &target, Pass::Initial);
        assert_eq!(retained.last_attachment, Some(22));
        advance(&mut state, Event::Attach, Some(&other));
        let later = state.revision_rejection(0, Some(&before), &target, Pass::Initial);
        assert_eq!(later.last_attachment, Some(33));
        assert_eq!(captured.last_attachment, Some(22));
        assert_eq!(captured.selected_attachment, Some(11));
        assert_eq!(captured.delta, Some(1));
        assert_eq!(later.delta, Some(2));
    }
    #[test]
    fn atomic_revision_missing_and_zero_ordinals_never_invent_identity() {
        for ordinal in [None, Some(0)] {
            let mut state = Registry::default();
            let mut target = selected();
            target.diagnostic = ordinal.map(|attachment| diagnostic::DiagnosticAttachment {
                attachment,
                ..Default::default()
            });
            let before = state.revision_snapshot();
            advance(&mut state, Event::Attach, Some(&target));
            let fact = state.revision_rejection(0, Some(&before), &target, Pass::Initial);
            assert_eq!(fact.last_attachment, None);
            assert_eq!(fact.selected_attachment, None);
            // Ordinal availability never changes the authoritative tenure relation.
            assert_eq!(fact.last_target, Target::Same);
            assert!(fact.exact);
        }
    }
    #[test]
    fn atomic_revision_missing_reset_and_overflow_are_unknown_not_zero() {
        let target = selected();
        for mode in ["missing", "reset", "overflow", "underflow", "reverse"] {
            let mut state = Registry::default();
            let mut before = state.revision_snapshot();
            advance(&mut state, Event::Info, Some(&target));
            if mode == "underflow" {
                before.counts[2] = 2;
            }
            if mode == "reset" {
                state.revision_history = Some(RevisionHistory::default());
            }
            if mode == "overflow" {
                state.revision_history.as_mut().unwrap().overflow = true;
            }
            let fact = state.revision_rejection(
                if mode == "reverse" { 2 } else { 0 },
                (mode != "missing").then_some(&before),
                &target,
                Pass::Initial,
            );
            assert!(!fact.exact);
            if mode != "reverse" {
                assert_eq!(fact.events, None);
            } else {
                assert_eq!(fact.delta, None);
            }
            assert_eq!(fact.last_event, Event::Unknown);
            assert_eq!(fact.last_target, Target::Unknown);
            assert_eq!(fact.last_attachment, None);
        }
    }
    #[test]
    fn atomic_revision_bounds_and_counter_overflow_are_explicit() {
        let target = selected();
        let mut state = Registry::default();
        let before = state.revision_snapshot();
        state.revision = 65_536;
        state.revision_history.as_mut().unwrap().counts[2] = 65_535;
        state.note_revision_enabled(Event::Info, Some(target.tenure.clone()), None);
        let fact = state.revision_rejection(0, Some(&before), &target, Pass::Initial);
        assert!(!fact.exact);
        assert_eq!(fact.delta, Some(65_535));
        assert_eq!(fact.events, Some([0, 0, 65_535, 0, 0, 0, 0]));
        state.revision_history.as_mut().unwrap().counts[2] = u64::MAX;
        state.note_revision_enabled(Event::Info, Some(target.tenure.clone()), None);
        assert!(state.revision_history.as_ref().unwrap().overflow);
        assert_eq!(
            state
                .revision_rejection(0, Some(&before), &target, Pass::Initial)
                .events,
            None
        );
    }
    #[test]
    fn atomic_revision_disabled_inventory_keeps_no_history() {
        let registry = ClientTargets::new("private-context".into(), "private-scope".into());
        let target = selected();
        registry
            .state
            .lock()
            .unwrap()
            .targets
            .insert(target.target_id.clone(), target);
        for _ in 0..3 {
            assert!(registry
                .inventory_with_diagnostic(false)
                .unwrap()
                .2
                .is_none());
            assert!(registry.inventory().is_ok());
            assert_eq!(registry.check_revision(0), Ok(()));
        }
        assert!(registry.state.lock().unwrap().revision_history.is_none());
    }
}

#[cfg(test)]
mod eval_diagnostic_target_tests {
    use super::*;
    #[test]
    fn eval_diagnostic_target_lock_contention_is_unknown_and_never_mutates() {
        let targets = ClientTargets::new("synthetic-context".into(), "synthetic-owner".into());
        let guard = targets.state.lock().unwrap();
        assert!(targets
            .eval_diagnostic_targets(std::iter::empty(), "missing", "missing")
            .is_none());
        assert!(guard.targets.is_empty());
        assert!(!guard.integrity_lost);
        drop(guard);
        assert_eq!(
            targets.eval_diagnostic_targets(std::iter::empty(), "missing", "missing"),
            Some(([0; 3], false))
        );
    }
}

#[cfg(test)]
#[path = "client_popup_setup_diagnostic_tests.rs"]
mod popup_setup_diagnostic_tests;

#[cfg(test)]
#[path = "client_popup_configuration_proof_unit_tests.rs"]
mod popup_configuration_proof_unit_tests;

#[cfg(test)]
#[path = "client_registration_receipt_tests.rs"]
mod registration_receipt_tests;

#[cfg(test)]
mod first_loss_diagnostic_tests {
    use super::*;
    #[test]
    fn first_loss_is_immutable_and_does_not_change_seal_semantics() {
        let mut registry = Registry::default();
        assert!(registry.first_loss.is_none());
        registry.lose_integrity(diagnostic::InventoryFirstLoss::ResumePermitDropped);
        assert!(registry.sealed && registry.integrity_lost);
        registry.lose_integrity(diagnostic::InventoryFirstLoss::ExplicitSeal);
        assert_eq!(
            registry.first_loss,
            Some(diagnostic::InventoryFirstLoss::ResumePermitDropped)
        );
        assert!(registry.sealed && registry.integrity_lost);
    }
}

#[cfg(test)]
mod owned_inventory_diagnostic_opt_in_tests {
    use super::*;
    #[test]
    fn owned_inventory_diagnostic_opt_in_is_local_and_records_actual_registration() {
        let enabled = ClientTargets::new("context".into(), "scope".into());
        let untouched = ClientTargets::new("context".into(), "scope".into());
        assert!(!enabled.state.lock().unwrap().inventory_diagnostics_for_test);
        enabled.enable_inventory_diagnostics_for_test();
        assert!(
            !untouched
                .state
                .lock()
                .unwrap()
                .inventory_diagnostics_for_test
        );
        assert!(enabled
            .attached("context", "target".into(), "session".into(), "page".into())
            .unwrap());
        let state = enabled.state.lock().unwrap();
        let history = state.revision_history.as_ref().unwrap();
        assert_eq!(state.revision, 1);
        assert_eq!(history.counts, [1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            history.last.as_ref().unwrap().0,
            diagnostic::InventoryRevisionEvent::Attach
        );
        assert!(state.targets["target"].diagnostic.unwrap().attachment > 0);
        assert!(untouched.state.lock().unwrap().targets.is_empty());
    }

    fn ready_read_registry() -> std::sync::Arc<ClientTargets> {
        let registry = ClientTargets::new("ctx".into(), "scope".into());
        registry
            .attached("ctx", "target".into(), "session".into(), "page".into())
            .unwrap();
        {
            let mut state = registry.state.lock().unwrap();
            let target = state.targets.get_mut("target").unwrap();
            target.configured = true;
            target.resumed = true;
            state.enrollment_ready = true;
        }
        registry
    }

    /// The returned sender keeps the operation's cancellation channel open for
    /// the test's lifetime; dropping it would look like a closed session.
    fn read_operation(
        deadline: std::time::Instant,
    ) -> (
        tokio::sync::watch::Sender<super::super::client_session::CancelSignal>,
        super::super::client_session::OperationLease,
    ) {
        let (cancel, cancellation) =
            tokio::sync::watch::channel(super::super::client_session::CancelSignal::None);
        (
            cancel,
            super::super::client_session::OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline,
                cancellation,
            },
        )
    }

    #[tokio::test]
    async fn read_inventory_waits_for_a_page_created_target_to_finish_enrollment() {
        let registry = ready_read_registry();
        registry
            .attached("ctx", "late".into(), "late-session".into(), "iframe".into())
            .unwrap();
        {
            let state = registry.state.lock().unwrap();
            let late = state.targets.get("late").expect("late target registered");
            assert_eq!(late.purpose, Some(super::TargetPurpose::Application));
            assert!(!late.configured && !late.resumed);
            assert!(!state.read_enrollment_settled());
        }
        let (_cancel, operation) =
            read_operation(std::time::Instant::now() + std::time::Duration::from_secs(5));
        let waiting = {
            let registry = registry.clone();
            tokio::spawn(async move { registry.wait_read_inventory(&operation, false).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !waiting.is_finished(),
            "the read must wait for the page's own target enrollment"
        );
        registry.configured("late").unwrap();
        registry
            .resume_permit("late")
            .await
            .unwrap()
            .complete()
            .unwrap();
        let (_, targets, _) = waiting.await.unwrap().unwrap();
        assert_eq!(targets.len(), 2);
        assert!(targets
            .iter()
            .all(|target| target.configured && target.resumed));
    }

    #[tokio::test]
    async fn read_inventory_refuses_immediately_when_the_registry_sealed() {
        let registry = ready_read_registry();
        registry.seal();
        let (_cancel, operation) =
            read_operation(std::time::Instant::now() + std::time::Duration::from_secs(5));
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            registry.wait_read_inventory(&operation, false),
        )
        .await
        .expect("a sealed registry must not wait for enrollment");
        assert!(matches!(result, Err(ProtocolError::ScopeUnavailable)));
    }

    #[tokio::test]
    async fn read_inventory_honours_the_operations_existing_deadline() {
        let registry = ready_read_registry();
        registry
            .attached("ctx", "late".into(), "late-session".into(), "iframe".into())
            .unwrap();
        let (_cancel, operation) =
            read_operation(std::time::Instant::now() + std::time::Duration::from_millis(40));
        let result = registry.wait_read_inventory(&operation, false).await;
        assert!(matches!(result, Err(ProtocolError::DeadlineExceeded)));
    }

    /// `page.url` and the other fixed reads take this exact inventory. During a
    /// session restore the page's own iframe can still be enrolling, and the
    /// fixed read must wait for it instead of settling `scope-unavailable`.
    #[tokio::test]
    async fn fixed_read_dispatch_inventory_waits_for_a_page_created_target() {
        let registry = ready_read_registry();
        registry
            .attached("ctx", "late".into(), "late-session".into(), "iframe".into())
            .unwrap();
        let (_cancel, operation) =
            read_operation(std::time::Instant::now() + std::time::Duration::from_secs(5));
        let waiting = {
            let registry = registry.clone();
            tokio::spawn(async move { registry.dispatch_inventory(&operation, true).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !waiting.is_finished(),
            "a fixed read must wait for the page's own target enrollment"
        );
        registry.configured("late").unwrap();
        registry
            .resume_permit("late")
            .await
            .unwrap()
            .complete()
            .unwrap();
        let targets = waiting.await.unwrap().unwrap();
        assert_eq!(targets.len(), 2);
        assert!(targets
            .iter()
            .all(|target| target.configured && target.resumed));
    }

    /// Every other command keeps the immediate completeness refusal: a frame
    /// session it may address needs the complete inventory up front.
    #[tokio::test]
    async fn non_fixed_read_dispatch_inventory_keeps_the_immediate_refusal() {
        let registry = ready_read_registry();
        registry
            .attached("ctx", "late".into(), "late-session".into(), "iframe".into())
            .unwrap();
        let (_cancel, operation) =
            read_operation(std::time::Instant::now() + std::time::Duration::from_secs(5));
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            registry.dispatch_inventory(&operation, false),
        )
        .await
        .expect("a non-read command must not wait for enrollment");
        assert!(matches!(result, Err(ProtocolError::ScopeUnavailable)));
    }

    async fn retired_read_registry() -> std::sync::Arc<ClientTargets> {
        let registry = ready_read_registry();
        registry
            .attached(
                "ctx",
                "frame-target".into(),
                "frame-session".into(),
                "iframe".into(),
            )
            .unwrap();
        registry.configured("frame-target").unwrap();
        registry
            .resume_permit("frame-target")
            .await
            .unwrap()
            .complete()
            .unwrap();
        registry
    }

    #[tokio::test]
    async fn retired_read_session_waits_for_the_registry_to_apply_the_detach() {
        let registry = retired_read_registry().await;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let (_cancel, operation) = read_operation(deadline);
        let waiting = {
            let registry = registry.clone();
            tokio::spawn(async move {
                registry
                    .wait_read_session_retired(&operation, "frame-session")
                    .await
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !waiting.is_finished(),
            "a still-owned session must keep the read waiting for its detach"
        );
        registry.detach("frame-target").unwrap();
        assert!(waiting.await.unwrap().unwrap());
        // The same session must not be waited for again once it is gone.
        let (_cancel, operation) = read_operation(deadline);
        assert!(registry
            .wait_read_session_retired(&operation, "frame-session")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn retired_read_session_returns_false_at_the_operations_existing_deadline() {
        let registry = retired_read_registry().await;
        let (_cancel, operation) =
            read_operation(std::time::Instant::now() + std::time::Duration::from_millis(40));
        assert_eq!(
            registry
                .wait_read_session_retired(&operation, "frame-session")
                .await
                .unwrap(),
            false
        );
    }

    #[tokio::test]
    async fn retired_read_session_refuses_immediately_when_the_registry_sealed() {
        let registry = retired_read_registry().await;
        registry.seal();
        let (_cancel, operation) =
            read_operation(std::time::Instant::now() + std::time::Duration::from_secs(5));
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            registry.wait_read_session_retired(&operation, "frame-session"),
        )
        .await
        .expect("a sealed registry must not wait for a detach");
        assert!(matches!(result, Err(ProtocolError::ScopeUnavailable)));
    }
}
