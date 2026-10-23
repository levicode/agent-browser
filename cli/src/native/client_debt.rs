//! Exact-owner command accounting. The response reader, not an RPC waiter,
//! settles submitted commands. Descriptors contain provenance only, never CDP
//! payloads, text, credentials, URLs, screenshots, or command error strings.
use super::cdp::types::{CdpEvent, CdpMessage};
use super::client_protocol::ProtocolError;
use super::client_session::{CancelSignal, OperationLease};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub(crate) const MAX_INPUT_DEBT: u32 = 32;
pub(crate) const MAX_OBJECT_DEBT: u32 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct OperationKey {
    pub generation: u64,
    pub operation_seq: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionClass {
    Input,
    Reference,
    FixedRead,
}
/// Closed native lifecycle obligations. No caller-supplied method, payload or
/// session may acquire post-retirement authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerCleanupCommand {
    DisableAutoAttach,
    CloseBrowser,
}
impl OwnerCleanupCommand {
    pub(crate) fn envelope(self) -> (&'static str, Option<Value>) {
        match self {
            Self::DisableAutoAttach => (
                "Target.setAutoAttach",
                Some(serde_json::json!({
                    "autoAttach":false,"waitForDebuggerOnStart":false,"flatten":true
                })),
            ),
            Self::CloseBrowser => ("Browser.close", None),
        }
    }
    fn category(self) -> CommandCategory {
        match self {
            Self::DisableAutoAttach => CommandCategory::CleanupOther,
            Self::CloseBrowser => CommandCategory::Destroy,
        }
    }
}
/// Existing lifecycle cleanup call sites own the exact resource identifiers.
/// This closed envelope grants no application, acquisition, or post-retirement authority.
pub(crate) enum ScopeCleanupCommand {
    ResumeDebugger {
        session: String,
    },
    Detach {
        session: String,
        parent: Option<String>,
    },
    DisableAutoAttach {
        session: Option<String>,
    },
    RemoveScript {
        session: String,
        identifier: String,
    },
    FailRequest {
        session: String,
        request: String,
    },
    CancelAuth {
        session: String,
        request: String,
    },
    DismissDialog {
        session: String,
    },
    DisableFetch {
        session: String,
    },
    DisableNetwork {
        session: String,
    },
    Inventory,
}
impl ScopeCleanupCommand {
    pub(crate) fn diagnostic_component(&self) -> super::client_settlement_trace::CleanupComponent {
        use super::client_settlement_trace::CleanupComponent as C;
        match self {
            Self::DismissDialog { .. } => C::Dialog,
            Self::FailRequest { .. }
            | Self::CancelAuth { .. }
            | Self::DisableFetch { .. }
            | Self::DisableNetwork { .. } => C::Interception,
            Self::RemoveScript { .. } => C::Script,
            Self::Detach { .. } => C::Detach,
            Self::DisableAutoAttach { .. } | Self::ResumeDebugger { .. } => C::Release,
            Self::Inventory => C::Containment,
        }
    }

    pub(crate) fn envelope(self) -> Result<(&'static str, Value, Option<String>), ProtocolError> {
        use serde_json::json;
        let result = match self {
            Self::ResumeDebugger { session } => {
                ("Runtime.runIfWaitingForDebugger", json!({}), Some(session))
            }
            Self::Detach { session, parent } => {
                checked_cleanup_id(&session)?;
                (
                    "Target.detachFromTarget",
                    json!({"sessionId":session}),
                    parent,
                )
            }
            Self::DisableAutoAttach { session } => (
                "Target.setAutoAttach",
                json!({"autoAttach":false,"waitForDebuggerOnStart":false,"flatten":true}),
                session,
            ),
            Self::RemoveScript {
                session,
                identifier,
            } => {
                checked_cleanup_id(&identifier)?;
                (
                    "Page.removeScriptToEvaluateOnNewDocument",
                    json!({"identifier":identifier}),
                    Some(session),
                )
            }
            Self::FailRequest { session, request } => {
                checked_cleanup_id(&request)?;
                (
                    "Fetch.failRequest",
                    json!({"requestId":request,"errorReason":"Aborted"}),
                    Some(session),
                )
            }
            Self::CancelAuth { session, request } => {
                checked_cleanup_id(&request)?;
                (
                    "Fetch.continueWithAuth",
                    json!({"requestId":request,"authChallengeResponse":{"response":"CancelAuth"}}),
                    Some(session),
                )
            }
            Self::DismissDialog { session } => (
                "Page.handleJavaScriptDialog",
                json!({"accept":false}),
                Some(session),
            ),
            Self::DisableFetch { session } => ("Fetch.disable", json!({}), Some(session)),
            Self::DisableNetwork { session } => ("Network.disable", json!({}), Some(session)),
            Self::Inventory => ("Target.getTargets", json!({}), None),
        };
        if let Some(session) = &result.2 {
            checked_cleanup_id(session)?;
        }
        Ok(result)
    }
}
fn checked_cleanup_id(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > 4096 {
        Err(ProtocolError::InvalidArguments)
    } else {
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CleanupDisposition {
    Complete,
    AccountedRemoteDebt,
    IntegrityLost,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OperationDebtSnapshot {
    pub mutation_dispatched: bool,
    pub input_debt: u32,
    pub object_debt: u32,
    pub integrity_lost: bool,
    pub local_producers_finished: bool,
    pub submission_revoked: bool,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OwnerDebtSnapshot {
    pub input_debt: u32,
    pub object_debt: u32,
    pub outstanding_commands: u32,
    pub descriptor_bytes: usize,
    pub integrity_lost: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandCategory {
    ApplicationInput,
    ApplicationObject,
    ApplicationRead,
    CleanupObject,
    CleanupInput,
    CleanupOther,
    Recording,
    Security,
    Download,
    Enrollment,
    Destroy,
}
impl CommandCategory {
    fn index(self) -> usize {
        self as usize
    }
    fn limits(self) -> (usize, usize) {
        // Non-borrowing pools: application 64/192 KiB, cleanup 64/64 KiB,
        // resident services 128/256 KiB. Final destruction is never borrowed.
        match self {
            Self::ApplicationInput => (16, 64 * 1024),
            Self::ApplicationObject => (32, 96 * 1024),
            Self::ApplicationRead => (16, 32 * 1024),
            Self::CleanupObject => (32, 32 * 1024),
            Self::CleanupInput => (16, 16 * 1024),
            Self::CleanupOther => (16, 16 * 1024),
            Self::Recording => (64, 128 * 1024),
            Self::Security => (32, 64 * 1024),
            Self::Download => (16, 32 * 1024),
            Self::Enrollment => (15, 28 * 1024),
            Self::Destroy => (1, 4 * 1024),
        }
    }
    fn application(self) -> bool {
        matches!(
            self,
            Self::ApplicationInput | Self::ApplicationObject | Self::ApplicationRead
        )
    }
    fn input(self) -> bool {
        matches!(self, Self::ApplicationInput | Self::CleanupInput)
    }
}
#[derive(Clone, Default)]
struct JournalState {
    mutation_dispatched: bool,
    submission_revoked: bool,
    local_producers_finished: bool,
    integrity_lost: bool,
    admission: Option<(Instant, tokio::sync::watch::Receiver<CancelSignal>)>,
}
struct Journal {
    key: OperationKey,
    target: String,
    session: String,
    state: Mutex<JournalState>,
    ledger: std::sync::Weak<OwnerDebtLedger>,
    footprint: usize,
}
impl Drop for Journal {
    fn drop(&mut self) {
        if let Some(ledger) = self.ledger.upgrade() {
            if let Ok(mut state) = ledger.state.lock() {
                state.journal_bytes = state.journal_bytes.saturating_sub(self.footprint);
            }
        }
    }
}
#[derive(Clone)]
pub(crate) struct OperationJournalHandle {
    ledger: Arc<OwnerDebtLedger>,
    journal: Arc<Journal>,
}
tokio::task_local! {
    static CURRENT_OPERATION: OperationJournalHandle;
    static COMMAND_OVERRIDE: CommandOverride;
    static NATIVE_OBJECT_GROUP: String;
    static INITIALIZATION_WORK: (Arc<OwnerDebtLedger>, InitializationWork);
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum InitializationWork {
    StateRestore,
    Recording,
}
/// Only existing native group owners call this; never infer authority from a
/// CDP objectId or a caller-provided group string.
pub(crate) async fn native_object_group<F: Future>(group: &str, future: F) -> F::Output {
    NATIVE_OBJECT_GROUP.scope(group.to_owned(), future).await
}
#[derive(Clone, Copy)]
pub(crate) struct CommandOverride {
    pub category: CommandCategory,
    pub mutation: bool,
}
pub(crate) fn current_operation() -> Option<OperationJournalHandle> {
    CURRENT_OPERATION.try_with(Clone::clone).ok()
}
pub(crate) async fn command_scope<F: Future>(
    category: CommandCategory,
    mutation: bool,
    future: F,
) -> F::Output {
    COMMAND_OVERRIDE
        .scope(CommandOverride { category, mutation }, future)
        .await
}
impl OperationJournalHandle {
    pub(crate) fn current() -> Option<Self> {
        current_operation()
    }
    pub(crate) fn bind_operation(&self, operation: &OperationLease) -> Result<(), ProtocolError> {
        if operation.generation != self.key().generation
            || operation.sequence != self.key().operation_seq
        {
            return Err(ProtocolError::StaleScope);
        }
        let mut state = self
            .journal
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.admission.is_some() {
            return Err(ProtocolError::InvalidArguments);
        }
        state.admission = Some((operation.deadline, operation.cancellation.clone()));
        Ok(())
    }
    pub(crate) fn descriptor_bytes(&self) -> usize {
        self.journal.footprint
    }
    pub(crate) fn key(&self) -> OperationKey {
        self.journal.key
    }
    pub(crate) fn ledger(&self) -> Arc<OwnerDebtLedger> {
        self.ledger.clone()
    }
    pub(crate) async fn scope<F: Future>(&self, future: F) -> F::Output {
        CURRENT_OPERATION.scope(self.clone(), future).await
    }
    pub(crate) fn check_application_submission(&self) -> Result<(), ProtocolError> {
        let state = self
            .journal
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state
            .admission
            .as_ref()
            .is_some_and(|(deadline, cancellation)| {
                Instant::now() >= *deadline || *cancellation.borrow() != CancelSignal::None
            })
        {
            return Err(ProtocolError::Cancelled);
        }
        if state.integrity_lost || state.submission_revoked || state.local_producers_finished {
            Err(ProtocolError::Cancelled)
        } else {
            Ok(())
        }
    }
    pub(crate) fn revoke_application_submission(&self) {
        match self.journal.state.lock() {
            Ok(mut state) => state.submission_revoked = true,
            Err(error) => {
                let mut state = error.into_inner();
                state.submission_revoked = true;
                state.integrity_lost = true;
            }
        }
    }
    pub(crate) fn mark_mutation_maybe_submitted(&self) -> Result<(), ProtocolError> {
        let mut state = self
            .journal
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state
            .admission
            .as_ref()
            .is_some_and(|(deadline, cancellation)| {
                Instant::now() >= *deadline || *cancellation.borrow() != CancelSignal::None
            })
        {
            return Err(ProtocolError::Cancelled);
        }
        if state.integrity_lost || state.submission_revoked || state.local_producers_finished {
            return Err(ProtocolError::Cancelled);
        }
        state.mutation_dispatched = true;
        Ok(())
    }
    pub(crate) fn record_cleanup_disposition(&self, disposition: CleanupDisposition) {
        if disposition == CleanupDisposition::IntegrityLost {
            match self.journal.state.lock() {
                Ok(mut state) => state.integrity_lost = true,
                Err(error) => error.into_inner().integrity_lost = true,
            }
        }
        // Neither a complete local producer nor an accounted-debt classification
        // can clear reader-owned remote obligations or earlier integrity loss.
    }
    pub(crate) fn finish_local_producers(&self) {
        match self.journal.state.lock() {
            Ok(mut state) => {
                state.local_producers_finished = true;
                state.submission_revoked = true;
            }
            Err(error) => {
                let mut state = error.into_inner();
                state.local_producers_finished = true;
                state.submission_revoked = true;
                state.integrity_lost = true;
            }
        }
    }
    pub(crate) fn snapshot(&self) -> OperationDebtSnapshot {
        let (input_debt, object_debt, owner_lost) = self.ledger.operation_counts(self.key());
        match self.journal.state.lock() {
            Ok(state) => OperationDebtSnapshot {
                mutation_dispatched: state.mutation_dispatched,
                input_debt,
                object_debt,
                integrity_lost: owner_lost || state.integrity_lost,
                local_producers_finished: state.local_producers_finished,
                submission_revoked: state.submission_revoked,
            },
            Err(_) => OperationDebtSnapshot {
                input_debt,
                object_debt,
                integrity_lost: true,
                ..Default::default()
            },
        }
    }
    pub(crate) fn register_remote_obligation(
        &self,
        method: &str,
        params: Option<&Value>,
        session: Option<&str>,
    ) -> Result<CommandReservation, ProtocolError> {
        self.ledger
            .reserve_command(Some(self), method, params, session)
    }
    pub(crate) fn has_accounted_object_creation(&self, session: &str) -> bool {
        self.ledger.state.lock().is_ok_and(|state| {
            !state.integrity_lost
                && state.commands.values().any(|command| {
                    command.submitted
                        && command.provenance.operation == Some(self.key())
                        && command.provenance.session.as_deref() == Some(session)
                        && command.creation_slots > 0
                })
        })
    }
}
#[derive(Clone, Eq, PartialEq)]
struct Provenance {
    operation: Option<OperationKey>,
    target: Option<String>,
    session: Option<String>,
    // Realm epoch is captured from reader-observed creation. Numeric IDs alone
    // are never destruction authority across a reused execution context ID.
    realm: Option<(i64, u64)>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CommandStatus {
    Reserved,
    Submitted,
    Acknowledged,
    RetainedRejected,
    Destroyed,
    Abandoned,
    IntegrityLost,
}
#[derive(Clone)]
pub(crate) struct CommandStatusHandle(Arc<AtomicU8>, bool, Arc<tokio::sync::Notify>);
impl CommandStatusHandle {
    fn new(object_only: bool, changed: Arc<tokio::sync::Notify>) -> Self {
        Self(
            Arc::new(AtomicU8::new(CommandStatus::Reserved as u8)),
            object_only,
            changed,
        )
    }
    fn set(&self, status: CommandStatus) {
        self.0.store(status as u8, Ordering::SeqCst);
        self.2.notify_waiters();
    }
    pub(crate) fn snapshot(&self) -> CommandStatus {
        match self.0.load(Ordering::SeqCst) {
            0 => CommandStatus::Reserved,
            1 => CommandStatus::Submitted,
            2 => CommandStatus::Acknowledged,
            3 => CommandStatus::RetainedRejected,
            4 => CommandStatus::Destroyed,
            5 => CommandStatus::Abandoned,
            _ => CommandStatus::IntegrityLost,
        }
    }
    pub(crate) fn accountably_retained(&self) -> bool {
        matches!(
            self.snapshot(),
            CommandStatus::Submitted | CommandStatus::RetainedRejected
        )
    }
    pub(crate) fn accounted_object_debt(&self) -> bool {
        self.1 && self.accountably_retained()
    }
    pub(crate) fn settled(&self) -> bool {
        matches!(
            self.snapshot(),
            CommandStatus::Acknowledged | CommandStatus::Destroyed
        )
    }
}
struct CommandRecord {
    owner_cleanup: bool,
    cleanup_kind: Option<OwnerCleanupCommand>,
    acquisition: Option<LifecycleAcquisition>,
    lifecycle_budget: bool,
    teardown_deadline: Option<Instant>,
    category: CommandCategory,
    status: CommandStatusHandle,
    provenance: Provenance,
    footprint: usize,
    submitted: bool,
    mutation: bool,
    creation_slots: usize,
    release_object: Option<String>,
    object_group: Option<String>,
    release_group: bool,
    release_group_fence: u64,
    group_id: Option<u64>,
    grouped_creation: bool,
    group_release_proven: bool,
    objects_destroyed: bool,
}
/// Only acquisition identities are retained, never the request payload or a
/// continuation. The reader binds these before delivering a possibly late ACK.
enum LifecycleAcquisition {
    Context,
    Target,
    Session(String, bool),
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum LifecycleSessionPurpose {
    Observer,
    StateBootstrap,
    Recording,
}
struct ScopeBootstrap {
    sequence: u64,
    deadline: Instant,
    cancellation: tokio::sync::watch::Receiver<CancelSignal>,
    published: bool,
    owns_context: bool,
}
impl ScopeBootstrap {
    fn check(&self) -> Result<(), ProtocolError> {
        if *self.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(())
    }
}
struct ObjectObligation {
    provenance: Provenance,
    object: Option<String>,
    group: Option<String>,
    serial: u64,
    footprint: usize,
}
struct GroupObligation {
    provenance: Provenance,
    name: String,
    footprint: usize,
    pending_creations: usize,
    submitted_creations: usize,
    ever_submitted: bool,
    sealed: bool,
    release_inflight: bool,
    cleanup_issued: bool,
}
/// Private final-local evidence only. This never restores transport integrity
/// or grants command admission, owner replacement, or remote retirement.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum EofIntegrityCause {
    #[default]
    NotObserved,
    RemoteEofOnly,
    Contaminated,
}
#[derive(Default)]
struct LedgerState {
    next_reservation: u64,
    next_realm_epoch: u64,
    next_object_serial: u64,
    next_group: u64,
    groups: HashMap<u64, GroupObligation>,
    commands: HashMap<u64, CommandRecord>,
    objects: Vec<ObjectObligation>,
    realms: HashMap<(String, i64), u64>,
    targets: HashMap<String, String>,
    counts: [usize; 11],
    bytes: [usize; 11],
    object_bytes: usize,
    journal_bytes: usize,
    integrity_lost: bool,
    eof_integrity_cause: EofIntegrityCause,
    retired: bool,
    context_id: Option<String>,
    final_cleanup_claimed: [bool; 2],
    final_cleanup_acknowledged: [bool; 2],
    bootstrap: Option<ScopeBootstrap>,
    created_targets: HashSet<String>,
    lifecycle_sessions: HashMap<String, LifecycleSessionPurpose>,
    initialization_scripts: HashSet<[u8; 32]>,
    context_creation_claimed: bool,
    root_creation_claimed: bool,
    recording_targets: HashSet<String>,
}
impl LedgerState {
    fn contaminate_integrity(&mut self) {
        self.integrity_lost = true;
        self.eof_integrity_cause = EofIntegrityCause::Contaminated;
    }
}
pub(crate) struct OwnerDebtLedger {
    generation: u64,
    identity_scope: String,
    state: Mutex<LedgerState>,
    changed: Arc<tokio::sync::Notify>,
    pub(crate) cleanup_diagnostics: Arc<super::client_settlement_trace::CleanupDiagnostics>,
}
struct DebtChange<'a>(&'a tokio::sync::Notify);
impl Drop for DebtChange<'_> {
    fn drop(&mut self) {
        self.0.notify_waiters();
    }
}
impl OwnerDebtLedger {
    /// A replacement route transfer belongs to the original unpublished request,
    /// including its cancellation channel. Publication consumes this authority.
    pub(crate) fn check_unpublished_operation(
        &self,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.retired
            || state.integrity_lost
            || operation.is_callback
            || operation.generation != self.generation
        {
            return Err(ProtocolError::StaleScope);
        }
        let bootstrap = state.bootstrap.as_ref().ok_or(ProtocolError::StaleScope)?;
        if bootstrap.published
            || bootstrap.sequence != operation.sequence
            || bootstrap.deadline != operation.deadline
            || !bootstrap.cancellation.same_channel(&operation.cancellation)
        {
            return Err(ProtocolError::InvalidSequence);
        }
        bootstrap.check()
    }

    pub(crate) async fn initialization_work<F: Future>(
        self: &Arc<Self>,
        work: InitializationWork,
        operation: &OperationLease,
        future: F,
    ) -> Result<F::Output, ProtocolError> {
        {
            let state = self
                .state
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if state.retired
                || state.integrity_lost
                || operation.is_callback
                || operation.generation != self.generation
            {
                return Err(ProtocolError::StaleScope);
            }
            if let Some(bootstrap) = &state.bootstrap {
                if !bootstrap.published {
                    bootstrap.check()?;
                    if bootstrap.sequence != operation.sequence
                        || bootstrap.deadline != operation.deadline
                    {
                        return Err(ProtocolError::StaleScope);
                    }
                }
            }
        }
        Ok(INITIALIZATION_WORK
            .scope((self.clone(), work), future)
            .await)
    }
    pub(crate) fn allow_initialization_script(&self, source: &str) -> Result<(), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.retired
            || state
                .bootstrap
                .as_ref()
                .is_some_and(|bootstrap| bootstrap.published)
        {
            return Err(ProtocolError::StaleScope);
        }
        let digest = command_envelope_digest(source, None, None);
        if state.initialization_scripts.contains(&digest) {
            return Ok(());
        }
        // Existing configuration admits 1024 scripts plus the fixed native
        // service-worker policy. Re-authorizing captured configuration is free.
        if state.initialization_scripts.len() >= 1025 {
            return Err(ProtocolError::CapacityExceeded);
        }
        check_metadata_add(&state, 32)?;
        state.initialization_scripts.insert(digest);
        Ok(())
    }
    pub(crate) fn bind_state_bootstrap(
        &self,
        target: &str,
        session: &str,
    ) -> Result<(), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.retired
            || state.targets.get(session).map(String::as_str) != Some(target)
            || !state.created_targets.contains(target)
        {
            return Err(ProtocolError::StaleScope);
        }
        if state.lifecycle_sessions.len() >= 256 {
            return Err(ProtocolError::CapacityExceeded);
        }
        check_metadata_add(
            &state,
            if state.lifecycle_sessions.contains_key(session) {
                0
            } else {
                64 + session.len()
            },
        )?;
        state
            .lifecycle_sessions
            .insert(session.into(), LifecycleSessionPurpose::StateBootstrap);
        Ok(())
    }
    /// Called only after the existing auxiliary-target reservation is owned,
    /// before spawning its attach worker (task-local grants do not propagate).
    pub(crate) fn register_recording_target(
        self: &Arc<Self>,
        target: &str,
    ) -> Result<(), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.retired || !state.targets.values().any(|known| known == target) {
            return Err(ProtocolError::StaleScope);
        }
        if state
            .bootstrap
            .as_ref()
            .is_none_or(|bootstrap| bootstrap.published)
        {
            return Ok(());
        }
        if state
            .bootstrap
            .as_ref()
            .is_some_and(|bootstrap| !bootstrap.published)
        {
            state
                .bootstrap
                .as_ref()
                .ok_or(ProtocolError::ScopeUnavailable)?
                .check()?;
            if !INITIALIZATION_WORK
                .try_with(|(owner, work)| {
                    Arc::ptr_eq(owner, self) && *work == InitializationWork::Recording
                })
                .unwrap_or(false)
            {
                return Err(ProtocolError::PolicyDenied);
            }
        }
        if state.recording_targets.len() >= 64 || state.recording_targets.contains(target) {
            return Err(ProtocolError::CapacityExceeded);
        }
        check_metadata_add(&state, 64 + target.len())?;
        state.recording_targets.insert(target.into());
        Ok(())
    }
    pub(crate) fn unpublished(
        operation: &OperationLease,
        identity_scope: String,
        owns_context: bool,
    ) -> Result<Arc<Self>, ProtocolError> {
        if operation.is_callback || operation.sequence == 0 || identity_scope.is_empty() {
            return Err(ProtocolError::InvalidArguments);
        }
        let ledger = Self::new(operation.generation, identity_scope);
        let bootstrap = ScopeBootstrap {
            sequence: operation.sequence,
            deadline: operation.deadline,
            cancellation: operation.cancellation.clone(),
            published: false,
            owns_context,
        };
        bootstrap.check()?;
        ledger
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .bootstrap = Some(bootstrap);
        Ok(ledger)
    }
    pub(crate) fn initialization_deadline(&self, method: &str) -> Option<Instant> {
        if lifecycle_cleanup(method) {
            return None;
        }
        self.state.lock().ok().and_then(|state| {
            state
                .bootstrap
                .as_ref()
                .filter(|bootstrap| !bootstrap.published)
                .map(|bootstrap| bootstrap.deadline)
        })
    }
    pub(crate) fn publish_initialization<T>(
        &self,
        publish: impl FnOnce() -> Result<T, ProtocolError>,
    ) -> Result<T, ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.retired || state.integrity_lost {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if let Some(bootstrap) = &state.bootstrap {
            if !bootstrap.published {
                bootstrap.check()?;
            }
        }
        // All fallible ledger checks precede the synchronous gate commit.
        // Reservation cannot observe publication until both are committed.
        let result = publish()?;
        if let Some(bootstrap) = &mut state.bootstrap {
            bootstrap.published = true;
        }
        Ok(result)
    }
    pub(crate) fn replacement_ready(&self) -> bool {
        self.state.lock().is_ok_and(|state| {
            state.retired
                && !state.integrity_lost
                && state.final_cleanup_acknowledged[OwnerCleanupCommand::DisableAutoAttach as usize]
                && state.commands.is_empty()
                && state.objects.is_empty()
                && state.groups.is_empty()
        })
    }
    pub(crate) fn bound_context(&self) -> Option<String> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.context_id.clone())
    }
    pub(crate) fn bind_session(
        &self,
        context: &str,
        target: &str,
        session: &str,
    ) -> Result<(), ProtocolError> {
        self.bind_session_kind(context, target, session, None)
    }
    pub(crate) fn bind_observer_session(
        &self,
        context: &str,
        target: &str,
        session: &str,
    ) -> Result<(), ProtocolError> {
        self.bind_session_kind(
            context,
            target,
            session,
            Some(LifecycleSessionPurpose::Observer),
        )
    }
    fn bind_session_kind(
        &self,
        context: &str,
        target: &str,
        session: &str,
        purpose: Option<LifecycleSessionPurpose>,
    ) -> Result<(), ProtocolError> {
        if [target, session]
            .iter()
            .any(|id| id.is_empty() || id.len() > 4096)
        {
            return Err(ProtocolError::StaleScope);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.retired
            || state.integrity_lost
            || state.context_id.as_deref().unwrap_or("") != context
            || state
                .targets
                .get(session)
                .is_some_and(|existing| existing != target)
        {
            return Err(ProtocolError::StaleScope);
        }
        if purpose.is_none()
            && state.lifecycle_sessions.get(session) == Some(&LifecycleSessionPurpose::Observer)
        {
            return Err(ProtocolError::StaleScope);
        }
        let extra = (if state.targets.contains_key(session) {
            0
        } else {
            64 + target.len() + session.len()
        }) + if purpose.is_some() && !state.lifecycle_sessions.contains_key(session) {
            64 + session.len()
        } else {
            0
        };
        if state.targets.len() >= 4096
            || metadata_usage(&state).saturating_add(extra) > 64 * 1024
            || descriptor_usage(&state).saturating_add(extra) > 508 * 1024
        {
            return Err(ProtocolError::CapacityExceeded);
        }
        state.targets.insert(session.into(), target.into());
        if let Some(purpose) = purpose {
            state.lifecycle_sessions.insert(session.into(), purpose);
        }
        state.root_creation_claimed = true;
        Ok(())
    }
    pub(crate) fn new(generation: u64, identity_scope: String) -> Arc<Self> {
        let invalid = generation == 0 || identity_scope.len() > 4096;
        Arc::new(Self {
            generation,
            identity_scope,
            changed: Arc::new(tokio::sync::Notify::new()),
            cleanup_diagnostics: super::client_settlement_trace::CleanupDiagnostics::new(
                generation,
            ),
            state: Mutex::new(LedgerState {
                integrity_lost: invalid,
                eof_integrity_cause: if invalid {
                    EofIntegrityCause::Contaminated
                } else {
                    EofIntegrityCause::NotObserved
                },
                ..Default::default()
            }),
        })
    }
    pub(crate) fn bind_context(&self, context_id: &str) -> Result<(), ProtocolError> {
        if context_id.is_empty() || context_id.len() > 4096 {
            return Err(ProtocolError::StaleScope);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.retired
            || state
                .context_id
                .as_deref()
                .is_some_and(|old| old != context_id)
        {
            return Err(ProtocolError::StaleScope);
        }
        let extra = if state.context_id.is_none() {
            context_id.len()
        } else {
            0
        };
        if metadata_usage(&state).saturating_add(extra) > 64 * 1024
            || descriptor_usage(&state).saturating_add(extra) > 508 * 1024
        {
            return Err(ProtocolError::CapacityExceeded);
        }
        state.context_id = Some(context_id.to_owned());
        Ok(())
    }
    pub(crate) fn same_owner(&self, other: &OwnerDebtLedger) -> bool {
        self.generation == other.generation && self.identity_scope == other.identity_scope
    }
    pub(crate) fn matches_owner(&self, generation: u64, identity_scope: &str) -> bool {
        self.generation == generation && self.identity_scope == identity_scope
    }
    /// A read-only terminal check, never proof that EOF destroyed a borrowed
    /// context. Exact reader events must already have settled every obligation.
    pub(crate) fn check_final_local_eof(
        &self,
        generation: u64,
        identity_scope: &str,
    ) -> Result<(), ProtocolError> {
        if !self.matches_owner(generation, identity_scope) {
            return Err(ProtocolError::StaleScope);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.eof_integrity_cause != EofIntegrityCause::RemoteEofOnly
            || !state.integrity_lost
            || state.retired
            || state
                .bootstrap
                .as_ref()
                .is_none_or(|scope| scope.owns_context)
            || state.context_id.is_none()
            || state.context_creation_claimed
            || !state.commands.is_empty()
            || !state.objects.is_empty()
            || !state.groups.is_empty()
            || !state.realms.is_empty()
            || !state.targets.is_empty()
            || !state.lifecycle_sessions.is_empty()
            || !state.created_targets.is_empty()
            || !state.recording_targets.is_empty()
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        // Bound context identity and script authorization digests are inert
        // metadata, not live resources. Do not require descriptor_bytes == 0.
        Ok(())
    }
    pub(crate) fn operation(
        self: &Arc<Self>,
        key: OperationKey,
        target_id: String,
        session_id: String,
    ) -> Result<OperationJournalHandle, ProtocolError> {
        if key.generation != self.generation
            || key.operation_seq == 0
            || target_id.is_empty()
            || session_id.is_empty()
            || target_id.len() > 4096
            || session_id.len() > 4096
        {
            return Err(ProtocolError::StaleScope);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.retired || state.integrity_lost {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if state.bootstrap.is_some() && state.targets.get(&session_id) != Some(&target_id) {
            return Err(ProtocolError::StaleScope);
        }
        if state
            .targets
            .get(&session_id)
            .is_some_and(|target| target != &target_id)
        {
            return Err(ProtocolError::StaleScope);
        }
        let footprint = 256 + self.identity_scope.len() + target_id.len() + session_id.len();
        let metadata = if state.targets.contains_key(&session_id) {
            0
        } else {
            64 + session_id.len() + target_id.len()
        };
        if state.targets.len() >= 4096
            || metadata_usage(&state).saturating_add(metadata) > 64 * 1024
            || descriptor_usage(&state)
                .saturating_add(footprint)
                .saturating_add(metadata)
                > 508 * 1024
        {
            return Err(ProtocolError::CapacityExceeded);
        }
        state.journal_bytes += footprint;
        state.targets.insert(session_id.clone(), target_id.clone());
        drop(state);
        Ok(OperationJournalHandle {
            ledger: self.clone(),
            journal: Arc::new(Journal {
                key,
                target: target_id,
                session: session_id,
                state: Mutex::new(JournalState::default()),
                ledger: Arc::downgrade(self),
                footprint,
            }),
        })
    }
    /// Native lifecycle owner calls this only after exact context destruction
    /// acknowledgement. It is never a timeout/recovery or waiter-drop shortcut.
    pub(crate) fn retire_after_context_destroy(
        &self,
        context_id: &str,
    ) -> Result<(), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.context_id.as_deref() != Some(context_id) {
            return Err(ProtocolError::StaleScope);
        }
        if state.retired {
            return Ok(());
        }
        state.commands.retain(|_, command| {
            if command.owner_cleanup {
                true
            } else {
                command.status.set(CommandStatus::Destroyed);
                false
            }
        });
        state.objects.clear();
        state.groups.clear();
        state.realms.clear();
        state.targets.clear();
        state.created_targets.clear();
        state.lifecycle_sessions.clear();
        state.initialization_scripts.clear();
        state.recording_targets.clear();
        state.counts = [0; 11];
        state.bytes = [0; 11];
        let remaining: Vec<_> = state
            .commands
            .values()
            .map(|command| (command.category.index(), command.footprint))
            .collect();
        for (index, footprint) in remaining {
            state.counts[index] += 1;
            state.bytes[index] += footprint;
        }
        state.object_bytes = 0;
        state.retired = true;
        self.changed.notify_waiters();
        Ok(())
    }
    pub(crate) fn snapshot(&self) -> OwnerDebtSnapshot {
        match self.state.lock() {
            Ok(state) => OwnerDebtSnapshot {
                input_debt: state
                    .commands
                    .values()
                    .filter(|command| command.submitted && command.category.input())
                    .count() as u32,
                object_debt: object_count(&state) as u32,
                outstanding_commands: state.commands.len() as u32,
                descriptor_bytes: descriptor_usage(&state),
                integrity_lost: state.integrity_lost,
            },
            Err(_) => OwnerDebtSnapshot {
                integrity_lost: true,
                ..Default::default()
            },
        }
    }
    fn admission_ready(&self, category: AdmissionClass) -> Result<bool, ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.retired || state.integrity_lost {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if category != AdmissionClass::FixedRead
            && state
                .commands
                .values()
                .any(|command| command.submitted && command.category.input())
        {
            return Ok(false);
        }
        if category == AdmissionClass::Reference && object_count(&state) >= 32 {
            return Err(ProtocolError::CapacityExceeded);
        }
        Ok(true)
    }
    pub(crate) fn check_admission(&self, category: AdmissionClass) -> Result<(), ProtocolError> {
        if self.admission_ready(category)? {
            Ok(())
        } else {
            Err(ProtocolError::ScopeUnavailable)
        }
    }
    /// Wait only for already-accounted remote input to settle. Notifications
    /// confer no authority: the caller revalidates its immutable owner/attachment
    /// before every admission check. An ACK never revives a poisoned scope.
    pub(crate) async fn wait_admission(
        &self,
        category: AdmissionClass,
        operation: &OperationLease,
        check_authority: impl Fn() -> Result<(), ProtocolError>,
    ) -> Result<(), ProtocolError> {
        let mut cancellation = operation.cancellation.clone();
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if *cancellation.borrow() != CancelSignal::None {
                return Err(ProtocolError::Cancelled);
            }
            if Instant::now() >= operation.deadline {
                return Err(ProtocolError::DeadlineExceeded);
            }
            if operation.generation != self.generation {
                return Err(ProtocolError::StaleScope);
            }
            check_authority()?;
            if self.admission_ready(category)? {
                return Ok(());
            }
            tokio::select! { biased;
                _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                _ = tokio::time::sleep_until(operation.deadline.into()) => return Err(ProtocolError::DeadlineExceeded),
                _ = &mut changed => {},
            }
        }
    }
    fn operation_counts(&self, key: OperationKey) -> (u32, u32, bool) {
        match self.state.lock() {
            Ok(state) => (
                state
                    .commands
                    .values()
                    .filter(|command| {
                        command.submitted
                            && command.provenance.operation == Some(key)
                            && command.category.input()
                    })
                    .count() as u32,
                (state
                    .objects
                    .iter()
                    .filter(|object| object.provenance.operation == Some(key))
                    .count()
                    + state
                        .groups
                        .values()
                        .filter(|group| group.provenance.operation == Some(key))
                        .count()
                    + state
                        .commands
                        .values()
                        .filter(|command| command.provenance.operation == Some(key))
                        .map(|command| command.creation_slots)
                        .sum::<usize>()) as u32,
                state.integrity_lost
                    || state.commands.values().any(|command| {
                        command.submitted
                            && command.provenance.operation == Some(key)
                            && command.mutation
                            && !command.category.input()
                    }),
            ),
            Err(_) => (0, 0, true),
        }
    }
    pub(crate) fn reserve_command(
        self: &Arc<Self>,
        journal: Option<&OperationJournalHandle>,
        method: &str,
        params: Option<&Value>,
        session: Option<&str>,
    ) -> Result<CommandReservation, ProtocolError> {
        self.reserve_command_inner(journal, method, params, session, None, None)
    }
    pub(crate) fn reserve_owner_cleanup(
        self: &Arc<Self>,
        command: OwnerCleanupCommand,
    ) -> Result<CommandReservation, ProtocolError> {
        let (method, params) = command.envelope();
        self.reserve_command_inner(None, method, params.as_ref(), None, Some(command), None)
    }
    pub(super) fn reserve_scope_cleanup(
        self: &Arc<Self>,
        method: &str,
        params: &Value,
        session: Option<&str>,
        deadline: Instant,
    ) -> Result<CommandReservation, ProtocolError> {
        self.reserve_command_inner(None, method, Some(params), session, None, Some(deadline))
    }
    fn reserve_command_inner(
        self: &Arc<Self>,
        journal: Option<&OperationJournalHandle>,
        method: &str,
        params: Option<&Value>,
        session: Option<&str>,
        owner_cleanup: Option<OwnerCleanupCommand>,
        teardown_deadline: Option<Instant>,
    ) -> Result<CommandReservation, ProtocolError> {
        if method.len() > 256 || session.is_some_and(|session| session.len() > 4096) {
            return Err(ProtocolError::CapacityExceeded);
        }
        if journal.is_some_and(|journal| !Arc::ptr_eq(&journal.ledger, self)) {
            return Err(ProtocolError::StaleScope);
        }
        if teardown_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(ProtocolError::DeadlineExceeded);
        }
        let classification = if teardown_deadline.is_some() {
            Classification {
                category: CommandCategory::CleanupOther,
                mutation: false,
            }
        } else {
            owner_cleanup.map_or_else(
                || classify(method, params, journal.is_some()),
                |command| Classification {
                    category: command.category(),
                    mutation: false,
                },
            )
        };
        if classification.category.application() {
            if let Some(journal) = journal {
                journal.check_application_submission()?;
            }
        }
        let release_object = if method == "Runtime.releaseObject" {
            Some(
                params
                    .and_then(|params| params.get("objectId"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty() && value.len() <= 4096)
                    .ok_or(ProtocolError::InvalidArguments)?
                    .to_owned(),
            )
        } else {
            None
        };
        let object_group = params
            .and_then(|params| params.get("objectGroup"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        if object_group
            .as_ref()
            .is_some_and(|group| group.len() > 4096)
        {
            return Err(ProtocolError::CapacityExceeded);
        }
        let native_group = if owner_cleanup.is_none() && teardown_deadline.is_none() {
            NATIVE_OBJECT_GROUP.try_with(Clone::clone).ok()
        } else {
            None
        };
        if native_group
            .as_ref()
            .is_some_and(|group| object_group.as_ref().is_some_and(|actual| actual != group))
        {
            return Err(ProtocolError::StaleScope);
        }
        let envelope = command_envelope_digest(method, params, session);
        let physical_creation_slots = creation_slots(method, params);
        let creation_slots = if native_group.is_some() {
            0
        } else {
            physical_creation_slots
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if matches!(
            method,
            "Target.createBrowserContext" | "Target.disposeBrowserContext"
        ) && state
            .bootstrap
            .as_ref()
            .is_some_and(|bootstrap| !bootstrap.owns_context)
        {
            return Err(ProtocolError::PolicyDenied);
        }
        if (state.retired && owner_cleanup.is_none())
            || owner_cleanup.is_some_and(|command| state.final_cleanup_claimed[command as usize])
            || (state.integrity_lost && classification.category != CommandCategory::Destroy)
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if owner_cleanup.is_none()
            && teardown_deadline.is_none()
            && state
                .bootstrap
                .as_ref()
                .is_some_and(|bootstrap| !bootstrap.published)
        {
            let work = INITIALIZATION_WORK
                .try_with(|(ledger, work)| Arc::ptr_eq(ledger, self).then_some(*work))
                .ok()
                .flatten();
            if !unpublished_admits(&state, method, params, session, work) {
                return Err(ProtocolError::PolicyDenied);
            }
        }
        let acquisition = if state
            .bootstrap
            .as_ref()
            .is_some_and(|bootstrap| !bootstrap.published)
        {
            match method {
                "Target.createBrowserContext" => {
                    if state.context_id.is_some()
                        || state.context_creation_claimed
                        || params != Some(&serde_json::json!({"disposeOnDetach":true}))
                        || session.is_some()
                    {
                        return Err(ProtocolError::PolicyDenied);
                    }
                    Some(LifecycleAcquisition::Context)
                }
                "Target.createTarget" => {
                    if params.and_then(|p| p["browserContextId"].as_str())
                        != state.context_id.as_deref()
                        || params.and_then(|p| p["url"].as_str()) != Some("about:blank")
                        || session.is_some()
                    {
                        return Err(ProtocolError::PolicyDenied);
                    }
                    Some(LifecycleAcquisition::Target)
                }
                "Target.attachToTarget" => {
                    let target = params
                        .and_then(|p| p["targetId"].as_str())
                        .ok_or(ProtocolError::PolicyDenied)?;
                    if !state.created_targets.contains(target)
                        && !state.targets.values().any(|known| known == target)
                    {
                        return Err(ProtocolError::PolicyDenied);
                    }
                    let recording = state.recording_targets.contains(target);
                    if !recording && (state.targets.values().any(|known| known == target) || state.commands.values().any(|command| matches!(&command.acquisition, Some(LifecycleAcquisition::Session(known, _)) if known == target))) {
                        return Err(ProtocolError::PolicyDenied);
                    }
                    Some(LifecycleAcquisition::Session(target.into(), recording))
                }
                _ => None,
            }
        } else {
            None
        };
        let lifecycle_budget = owner_cleanup.is_none()
            && teardown_deadline.is_none()
            && state
                .bootstrap
                .as_ref()
                .is_some_and(|bootstrap| !bootstrap.published)
            && !lifecycle_cleanup(method);
        if lifecycle_budget {
            state
                .bootstrap
                .as_ref()
                .ok_or(ProtocolError::ScopeUnavailable)?
                .check()?;
        }
        let session = session
            .filter(|session| !session.is_empty())
            .map(str::to_owned);
        let target = session
            .as_ref()
            .and_then(|session| state.targets.get(session))
            .cloned()
            .or_else(|| {
                journal
                    .filter(|journal| session.as_deref() == Some(journal.journal.session.as_str()))
                    .map(|journal| journal.journal.target.clone())
            });
        let context = params
            .and_then(|params| {
                params
                    .get("executionContextId")
                    .or_else(|| params.get("contextId"))
            })
            .and_then(Value::as_i64);
        let realm = session
            .as_ref()
            .zip(context)
            .and_then(|(session, context)| {
                state
                    .realms
                    .get(&(session.clone(), context))
                    .map(|epoch| (context, *epoch))
            });
        let provenance = Provenance {
            operation: journal.map(OperationJournalHandle::key),
            target,
            session,
            realm,
        };
        let group_name = native_group.as_ref().or_else(|| {
            (method == "Runtime.releaseObjectGroup")
                .then_some(object_group.as_ref())
                .flatten()
        });
        let existing_group = group_name.and_then(|name| {
            state
                .groups
                .iter()
                .find(|(_, group)| {
                    group.name == *name
                        && group.provenance.session == provenance.session
                        && group.provenance.operation == provenance.operation
                })
                .map(|(id, _)| *id)
        });
        if existing_group
            .and_then(|id| state.groups.get(&id))
            .is_some_and(|group| {
                group.provenance.realm.is_some()
                    && provenance.realm.is_some()
                    && group.provenance.realm != provenance.realm
            })
        {
            return Err(ProtocolError::StaleScope);
        }
        if native_group.is_some() && journal.is_none() {
            return Err(ProtocolError::StaleScope);
        }
        if existing_group.is_some_and(|id| {
            state
                .groups
                .get(&id)
                .is_some_and(|group| group.sealed && method != "Runtime.releaseObjectGroup")
        }) {
            return Err(ProtocolError::Cancelled);
        }
        let new_group_footprint = if native_group.is_some() && existing_group.is_none() {
            256 + self.identity_scope.len()
                + provenance.session.as_ref().map_or(0, String::len)
                + provenance.target.as_ref().map_or(0, String::len)
                + native_group.as_ref().map_or(0, String::len)
        } else {
            0
        };
        let footprint =
            224 + match &acquisition {
                Some(LifecycleAcquisition::Session(target, _)) => target.len(),
                _ => 0,
            } + self.identity_scope.len()
                + provenance.session.as_ref().map_or(0, String::len)
                + provenance.target.as_ref().map_or(0, String::len)
                + release_object.as_ref().map_or(0, String::len)
                + object_group.as_ref().map_or(0, String::len);
        let index = classification.category.index();
        let (maximum_count, maximum_bytes) = classification.category.limits();
        if state.counts[index] >= maximum_count
            || state.bytes[index]
                .checked_add(footprint)
                .is_none_or(|bytes| bytes > maximum_bytes)
            || object_count(&state)
                .checked_add(creation_slots + usize::from(new_group_footprint > 0))
                .is_none_or(|count| count > 32)
            || descriptor_usage(&state)
                .saturating_add(footprint)
                .saturating_add(new_group_footprint)
                .saturating_add(creation_slots * 8448)
                > if classification.category == CommandCategory::Destroy {
                    512 * 1024
                } else {
                    508 * 1024
                }
        {
            return Err(ProtocolError::CapacityExceeded);
        }
        let id = state
            .next_reservation
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        let group_id = if new_group_footprint > 0 {
            let group_id = state
                .next_group
                .checked_add(1)
                .ok_or(ProtocolError::IdentifierExhausted)?;
            state.next_group = group_id;
            state.groups.insert(
                group_id,
                GroupObligation {
                    provenance: provenance.clone(),
                    name: native_group.clone().expect("native group"),
                    footprint: new_group_footprint,
                    pending_creations: 0,
                    submitted_creations: 0,
                    ever_submitted: false,
                    sealed: false,
                    release_inflight: false,
                    cleanup_issued: false,
                },
            );
            Some(group_id)
        } else {
            existing_group
        };
        let grouped_creation = group_id.is_some()
            && physical_creation_slots > 0
            && method != "Runtime.releaseObjectGroup";
        if let Some(group) = group_id.and_then(|id| state.groups.get_mut(&id)) {
            if grouped_creation {
                group.pending_creations += 1;
            }
        }
        if let Some(command) = owner_cleanup {
            state.final_cleanup_claimed[command as usize] = true;
        }
        state.next_reservation = id;
        state.counts[index] += 1;
        state.bytes[index] += footprint;
        let status = CommandStatusHandle::new(
            physical_creation_slots > 0 && !classification.mutation,
            self.changed.clone(),
        );
        match &acquisition {
            Some(LifecycleAcquisition::Context) => state.context_creation_claimed = true,
            Some(LifecycleAcquisition::Target) => state.root_creation_claimed = true,
            Some(LifecycleAcquisition::Session(target, true)) => {
                state.recording_targets.remove(target);
            }
            Some(LifecycleAcquisition::Session(_, false)) | None => {}
        }
        state.commands.insert(
            id,
            CommandRecord {
                owner_cleanup: owner_cleanup.is_some(),
                cleanup_kind: owner_cleanup,
                acquisition,
                lifecycle_budget,
                teardown_deadline,
                category: classification.category,
                status: status.clone(),
                provenance,
                footprint,
                submitted: false,
                mutation: classification.mutation,
                creation_slots,
                release_object,
                object_group,
                release_group: method == "Runtime.releaseObjectGroup",
                release_group_fence: 0,
                group_id,
                grouped_creation,
                group_release_proven: false,
                objects_destroyed: false,
            },
        );
        Ok(CommandReservation {
            owner_cleanup: owner_cleanup.is_some(),
            envelope,
            ledger: self.clone(),
            id,
            journal: journal.cloned(),
            status,
            submitted: false,
        })
    }
    pub(crate) fn accounted_object_release(&self, session: &str, object: &str) -> bool {
        self.state.lock().is_ok_and(|state| {
            !state.integrity_lost
                && state.commands.values().any(|command| {
                    command.submitted
                        && command.provenance.session.as_deref() == Some(session)
                        && command.release_object.as_deref() == Some(object)
                })
        })
    }
    pub(crate) fn connection_lost(&self) {
        let _notification = DebtChange(&self.changed);
        match self.state.lock() {
            Ok(mut state) => state.contaminate_integrity(),
            Err(error) => error.into_inner().contaminate_integrity(),
        }
    }
    /// Only the real transport reader may record this cause. Earlier damage is
    /// irreversible, and EOF itself never acknowledges or clears remote debt.
    pub(crate) fn observe_remote_eof(&self) {
        let _notification = DebtChange(&self.changed);
        match self.state.lock() {
            Ok(mut state) => {
                if state.eof_integrity_cause == EofIntegrityCause::NotObserved {
                    state.eof_integrity_cause = if state.integrity_lost {
                        EofIntegrityCause::Contaminated
                    } else {
                        EofIntegrityCause::RemoteEofOnly
                    };
                }
                state.integrity_lost = true;
            }
            Err(error) => error.into_inner().contaminate_integrity(),
        }
    }
    pub(crate) fn observe_event(&self, event: &CdpEvent) {
        if !matches!(
            event.method.as_str(),
            "Runtime.executionContextCreated"
                | "Runtime.executionContextDestroyed"
                | "Runtime.executionContextsCleared"
                | "Target.detachedFromTarget"
                | "Target.targetDestroyed"
        ) {
            return;
        }
        let _notification = DebtChange(&self.changed);
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.retired {
            return;
        }
        match event.method.as_str() {
            "Runtime.executionContextCreated" => {
                if let (Some(session), Some(context)) =
                    (&event.session_id, event.params["context"]["id"].as_i64())
                {
                    if !state.targets.contains_key(session)
                        || state.lifecycle_sessions.get(session)
                            == Some(&LifecycleSessionPurpose::Observer)
                    {
                        return;
                    }
                    let extra = if state.realms.contains_key(&(session.clone(), context)) {
                        0
                    } else {
                        64 + session.len()
                    };
                    if session.is_empty()
                        || session.len() > 4096
                        || state.realms.len() >= 4096
                        || metadata_usage(&state).saturating_add(extra) > 64 * 1024
                        || descriptor_usage(&state).saturating_add(extra) > 508 * 1024
                    {
                        state.contaminate_integrity();
                        return;
                    }
                    let Some(epoch) = state.next_realm_epoch.checked_add(1) else {
                        state.contaminate_integrity();
                        return;
                    };
                    state.next_realm_epoch = epoch;
                    state.realms.insert((session.clone(), context), epoch);
                }
            }
            "Runtime.executionContextDestroyed" => {
                if let (Some(session), Some(context)) = (
                    &event.session_id,
                    event.params["executionContextId"].as_i64(),
                ) {
                    if let Some(epoch) = state.realms.remove(&(session.clone(), context)) {
                        destroy_matching(
                            &mut state,
                            |provenance| {
                                provenance.session.as_ref() == Some(session)
                                    && provenance.realm == Some((context, epoch))
                            },
                            false,
                        );
                    }
                }
            }
            "Runtime.executionContextsCleared" => {
                if let Some(session) = &event.session_id {
                    state.realms.retain(|(owner, _), _| owner != session);
                    destroy_matching(
                        &mut state,
                        |provenance| provenance.session.as_ref() == Some(session),
                        false,
                    );
                }
            }
            "Target.detachedFromTarget" => {
                if let Some(session) = event.params["sessionId"].as_str() {
                    state.targets.remove(session);
                    state.lifecycle_sessions.remove(session);
                    state.realms.retain(|(owner, _), _| owner != session);
                    destroy_matching(
                        &mut state,
                        |provenance| provenance.session.as_deref() == Some(session),
                        true,
                    );
                }
            }
            "Target.targetDestroyed" => {
                if let Some(target) = event.params["targetId"].as_str() {
                    let sessions: HashSet<String> = state
                        .targets
                        .iter()
                        .filter(|(_, owner)| owner.as_str() == target)
                        .map(|(session, _)| session.clone())
                        .collect();
                    state.targets.retain(|_, owner| owner != target);
                    state
                        .lifecycle_sessions
                        .retain(|session, _| !sessions.contains(session));
                    state
                        .realms
                        .retain(|(session, _), _| !sessions.contains(session));
                    destroy_matching(
                        &mut state,
                        |provenance| provenance.target.as_deref() == Some(target),
                        true,
                    );
                }
            }
            _ => {}
        }
    }
}
fn metadata_usage(state: &LedgerState) -> usize {
    state.context_id.as_ref().map_or(0, String::len)
        + state
            .created_targets
            .iter()
            .map(|target| 64 + target.len())
            .sum::<usize>()
        + state
            .lifecycle_sessions
            .keys()
            .map(|session| 64 + session.len())
            .sum::<usize>()
        + state.initialization_scripts.len() * 32
        + state
            .recording_targets
            .iter()
            .map(|id| 64 + id.len())
            .sum::<usize>()
        + state
            .targets
            .iter()
            .map(|(session, target)| 64 + session.len() + target.len())
            .sum::<usize>()
        + state
            .realms
            .keys()
            .map(|(session, _)| 64 + session.len())
            .sum::<usize>()
}
fn check_metadata_add(state: &LedgerState, extra: usize) -> Result<(), ProtocolError> {
    if metadata_usage(state).saturating_add(extra) > 64 * 1024
        || descriptor_usage(state).saturating_add(extra) > 508 * 1024
    {
        Err(ProtocolError::CapacityExceeded)
    } else {
        Ok(())
    }
}
fn descriptor_usage(state: &LedgerState) -> usize {
    metadata_usage(state)
        + state.journal_bytes
        + state
            .groups
            .values()
            .map(|group| group.footprint)
            .sum::<usize>()
        + state.bytes.iter().sum::<usize>()
        + state.object_bytes
        + state
            .commands
            .values()
            .map(|command| command.creation_slots * 8448)
            .sum::<usize>()
}
fn object_count(state: &LedgerState) -> usize {
    state.objects.len()
        + state.groups.len()
        + state
            .commands
            .values()
            .map(|command| command.creation_slots)
            .sum::<usize>()
}
fn remove_command(state: &mut LedgerState, id: u64) -> Option<CommandRecord> {
    let command = state.commands.remove(&id)?;
    if command.grouped_creation {
        if let Some(group) = command.group_id.and_then(|id| state.groups.get_mut(&id)) {
            group.pending_creations = group.pending_creations.saturating_sub(1);
            if command.submitted {
                group.submitted_creations = group.submitted_creations.saturating_sub(1);
            }
        }
    }
    state.counts[command.category.index()] -= 1;
    state.bytes[command.category.index()] -= command.footprint;
    Some(command)
}
fn destroy_matching(
    state: &mut LedgerState,
    matches: impl Fn(&Provenance) -> bool,
    target_destroyed: bool,
) {
    state.objects.retain(|object| !matches(&object.provenance));
    let groups: HashSet<u64> = state
        .groups
        .iter()
        .filter(|(_, group)| matches(&group.provenance))
        .map(|(id, _)| *id)
        .collect();
    state.groups.retain(|id, _| !groups.contains(id));
    state.object_bytes = state.objects.iter().map(|object| object.footprint).sum();
    // Realm destruction discharges objects, not unrelated input effects. Only
    // exact target/session destruction can discharge pending input commands.
    let ids: Vec<u64> = state
        .commands
        .iter()
        .filter(|(_, command)| {
            matches(&command.provenance)
                && (target_destroyed
                    || (!command.category.input()
                        && (command.creation_slots > 0
                            || command.release_object.is_some()
                            || command.group_id.is_some_and(|id| groups.contains(&id)))))
        })
        .map(|(id, _)| *id)
        .collect();
    if !target_destroyed {
        for command in state.commands.values_mut() {
            if matches(&command.provenance) && command.category.input() {
                command.creation_slots = 0;
                command.objects_destroyed = true;
                command.group_id = None;
                command.grouped_creation = false;
            }
        }
    }
    for id in ids {
        if let Some(command) = remove_command(state, id) {
            command.status.set(CommandStatus::Destroyed);
        }
    }
}
pub(crate) struct CommandReservation {
    owner_cleanup: bool,
    envelope: [u8; 32],
    ledger: Arc<OwnerDebtLedger>,
    id: u64,
    journal: Option<OperationJournalHandle>,
    status: CommandStatusHandle,
    submitted: bool,
}
impl CommandReservation {
    pub(crate) fn initialization_budget(
        &self,
    ) -> Option<(Instant, tokio::sync::watch::Receiver<CancelSignal>)> {
        let state = self.ledger.state.lock().ok()?;
        if !state.commands.get(&self.id)?.lifecycle_budget {
            return None;
        }
        let bootstrap = state.bootstrap.as_ref()?;
        Some((bootstrap.deadline, bootstrap.cancellation.clone()))
    }
    pub(crate) fn matches_envelope(
        &self,
        method: &str,
        params: Option<&Value>,
        session: Option<&str>,
    ) -> bool {
        self.envelope == command_envelope_digest(method, params, session)
    }
    pub(crate) fn belongs_to(&self, ledger: &Arc<OwnerDebtLedger>) -> bool {
        Arc::ptr_eq(&self.ledger, ledger)
    }
    pub(crate) fn is_owner_cleanup(&self) -> bool {
        self.owner_cleanup
            || self.ledger.state.lock().map_or(true, |state| {
                state
                    .commands
                    .get(&self.id)
                    .is_some_and(|command| command.teardown_deadline.is_some())
            })
    }
    pub(crate) fn status(&self) -> CommandStatusHandle {
        self.status.clone()
    }
    /// Called with websocket ownership immediately before the send future can
    /// accept bytes. Failed/maybe sends remain reader-owned debt, not rollback.
    pub(crate) fn submit(mut self) -> Result<SubmittedCommand, ProtocolError> {
        let mut state = self
            .ledger
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let group_fence = state.next_object_serial;
        if state
            .commands
            .get(&self.id)
            .and_then(|command| command.teardown_deadline)
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(ProtocolError::DeadlineExceeded);
        }
        if state
            .commands
            .get(&self.id)
            .is_some_and(|command| command.lifecycle_budget)
        {
            state
                .bootstrap
                .as_ref()
                .ok_or(ProtocolError::ScopeUnavailable)?
                .check()?;
        }
        if let Some(command) = state.commands.get(&self.id) {
            if command.grouped_creation
                && command
                    .group_id
                    .is_some_and(|id| state.groups.get(&id).is_none_or(|group| group.sealed))
            {
                return Err(ProtocolError::Cancelled);
            }
        }
        let release_group = state
            .commands
            .get(&self.id)
            .filter(|command| command.release_group)
            .and_then(|command| command.group_id);
        let group_release_proven = if let Some(group_id) = release_group {
            let group = state
                .groups
                .get_mut(&group_id)
                .ok_or(ProtocolError::StaleScope)?;
            if group.release_inflight {
                return Err(ProtocolError::ScopeUnavailable);
            }
            group.sealed = true;
            group.release_inflight = true;
            group.submitted_creations == 0
        } else {
            false
        };
        let command = state
            .commands
            .get_mut(&self.id)
            .ok_or(ProtocolError::ScopeUnavailable)?;
        if command.category.application() {
            if let Some(journal) = &self.journal {
                if command.mutation {
                    journal.mark_mutation_maybe_submitted()?;
                } else {
                    journal.check_application_submission()?;
                }
            }
        }
        command.release_group_fence = group_fence;
        command.group_release_proven = group_release_proven;
        command.submitted = true;
        command.status.set(CommandStatus::Submitted);
        let group_id = command.group_id;
        let creation = command.grouped_creation;
        if let Some(group) = group_id.and_then(|id| state.groups.get_mut(&id)) {
            group.ever_submitted = true;
            if creation {
                group.submitted_creations += 1;
            }
        }
        self.submitted = true;
        Ok(SubmittedCommand {
            ledger: self.ledger.clone(),
            id: self.id,
        })
    }
}
impl Drop for CommandReservation {
    fn drop(&mut self) {
        if !self.submitted {
            if let Ok(mut state) = self.ledger.state.lock() {
                let removed = remove_command(&mut state, self.id);
                if let Some(id) = removed.and_then(|command| command.group_id) {
                    if state
                        .groups
                        .get(&id)
                        .is_some_and(|group| !group.ever_submitted && group.pending_creations == 0)
                    {
                        state.groups.remove(&id);
                    }
                }
                self.status.set(CommandStatus::Abandoned);
            }
        }
    }
}
fn command_envelope_digest(
    method: &str,
    params: Option<&Value>,
    session: Option<&str>,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(method.as_bytes());
    hash.update([0]);
    hash.update(serde_json::to_vec(&params).unwrap_or_default());
    hash.update([0]);
    hash.update(
        session
            .filter(|session| !session.is_empty())
            .unwrap_or_default()
            .as_bytes(),
    );
    hash.finalize().into()
}
fn lifecycle_cleanup(method: &str) -> bool {
    matches!(
        method,
        "Target.disposeBrowserContext"
            | "Target.closeTarget"
            | "Target.detachFromTarget"
            | "Runtime.releaseObject"
            | "Runtime.releaseObjectGroup"
            | "Page.stopScreencast"
            | "Fetch.failRequest"
            | "Browser.cancelDownload"
            | "IO.close"
    )
}
/// The unpublished owner is not application authority. This list is independent
/// of COMMAND_OVERRIDE, and executable native helpers need an exact-purpose
/// lexical grant as well as an immutable transport owner and registered session.
fn unpublished_admits(
    state: &LedgerState,
    method: &str,
    params: Option<&Value>,
    session: Option<&str>,
    work: Option<InitializationWork>,
) -> bool {
    let p = params.unwrap_or(&Value::Null);
    let known_session = session.is_some_and(|session| state.targets.contains_key(session));
    let state_session = session.is_some_and(|session| {
        state.lifecycle_sessions.get(session) == Some(&LifecycleSessionPurpose::StateBootstrap)
    });
    if session.is_some_and(|session| {
        state.lifecycle_sessions.get(session) == Some(&LifecycleSessionPurpose::Observer)
    }) && !matches!(
        method,
        "Page.enable"
            | "Page.getFrameTree"
            | "Target.setAutoAttach"
            | "Runtime.runIfWaitingForDebugger"
    ) {
        return false;
    }
    let exact_context = p["browserContextId"]
        .as_str()
        .is_some_and(|context| state.context_id.as_deref() == Some(context));
    let exact_target = p["targetId"].as_str().is_some_and(|target| {
        state.created_targets.contains(target)
            || state.targets.values().any(|known| known == target)
    });
    match method {
        "Target.createBrowserContext" => {
            session.is_none()
                && state
                    .bootstrap
                    .as_ref()
                    .is_some_and(|bootstrap| bootstrap.owns_context)
                && state.context_id.is_none()
                && !state.context_creation_claimed
                && p == &serde_json::json!({"disposeOnDetach":true})
        }
        "Target.createTarget" => {
            session.is_none()
                && exact_context
                && p["url"] == "about:blank"
                && (!state.root_creation_claimed || work == Some(InitializationWork::StateRestore))
        }
        "Target.attachToTarget" => session.is_none() && exact_target && p["flatten"] == true,
        "Target.closeTarget" => session.is_none() && exact_target,
        "Target.disposeBrowserContext" => {
            session.is_none()
                && exact_context
                && state
                    .bootstrap
                    .as_ref()
                    .is_some_and(|bootstrap| bootstrap.owns_context)
        }
        "Target.detachFromTarget" => p["sessionId"]
            .as_str()
            .is_some_and(|id| state.targets.contains_key(id)),
        "Target.getTargets" | "Browser.getVersion" => session.is_none(),
        "Target.getTargetInfo" => {
            (known_session && p == &serde_json::json!({}))
                || p["targetId"]
                    .as_str()
                    .is_some_and(|id| !id.is_empty() && id.len() <= 4096)
        }
        "Target.setAutoAttach" => {
            (session.is_none() || known_session)
                && p["autoAttach"] == true
                && p["waitForDebuggerOnStart"] == true
                && p["flatten"] == true
        }
        "Browser.setDownloadBehavior" => session.is_none() && exact_context,
        "Browser.cancelDownload" => session.is_none(),
        "Storage.setCookies" => {
            session.is_none() && exact_context && work == Some(InitializationWork::StateRestore)
        }
        "Page.navigate" => {
            state_session
                && work == Some(InitializationWork::StateRestore)
                && p["url"].as_str().is_some_and(|url| {
                    url.ends_with("/__agent_browser_state_bootstrap__")
                        && (url.starts_with("https://") || url.starts_with("http://"))
                })
        }
        "Runtime.evaluate" => {
            known_session
                && p["returnByValue"] == true
                && match work {
                    Some(InitializationWork::Recording) => {
                        p["expression"] == "[window.innerWidth, window.innerHeight]"
                    }
                    Some(InitializationWork::StateRestore) => {
                        state_session
                            && p["expression"].as_str().is_some_and(
                                super::client_state::is_initialization_state_expression,
                            )
                    }
                    None => false,
                }
        }
        "Runtime.callFunctionOn" => {
            known_session
                && work == Some(InitializationWork::Recording)
                && p["returnByValue"] == true
                && p["functionDeclaration"].as_str().is_some_and(|source| {
                    source == super::client_geometry::BOX_PROOF
                        || source == super::client_observation::FRAME_OWNER_GEOMETRY
                })
        }
        "Page.addScriptToEvaluateOnNewDocument" => {
            known_session
                && p["source"].as_str().is_some_and(|source| {
                    state
                        .initialization_scripts
                        .contains(&command_envelope_digest(source, None, None))
                })
        }
        "Page.createIsolatedWorld" => {
            known_session
                && (p["worldName"] == "agent-browser-native-observation"
                    || (state_session
                        && work == Some(InitializationWork::StateRestore)
                        && p["worldName"] == "agent-browser-state"))
        }
        "Fetch.fulfillRequest" => {
            state_session
                && work == Some(InitializationWork::StateRestore)
                && p["responseCode"] == 200
                && p["body"] == "PCFkb2N0eXBlIGh0bWw+PHRpdGxlPjwvdGl0bGU+"
        }
        "Page.captureScreenshot" => known_session && work == Some(InitializationWork::Recording),
        "Page.startScreencast" | "Page.screencastFrameAck" | "Page.stopScreencast" => session
            .is_some_and(|id| {
                state.lifecycle_sessions.get(id) == Some(&LifecycleSessionPurpose::Recording)
            }),
        "Page.enable"
        | "Runtime.enable"
        | "Network.enable"
        | "DOM.enable"
        | "WebMCP.enable"
        | "Page.getFrameTree"
        | "Page.getLayoutMetrics"
        | "Page.setLifecycleEventsEnabled"
        | "Network.setBypassServiceWorker"
        | "Fetch.enable"
        | "Fetch.failRequest"
        | "Fetch.continueRequest"
        | "Fetch.continueWithAuth"
        | "Emulation.setUserAgentOverride"
        | "Emulation.setLocaleOverride"
        | "Emulation.setTimezoneOverride"
        | "Emulation.setDeviceMetricsOverride"
        | "Emulation.setEmulatedMedia"
        | "Runtime.runIfWaitingForDebugger"
        | "Runtime.getIsolateId"
        | "Runtime.releaseObject"
        | "Runtime.releaseObjectGroup" => known_session,
        "DOM.getFrameOwner" | "DOM.resolveNode" | "DOM.getBoxModel" => {
            known_session && work == Some(InitializationWork::Recording)
        }
        _ => false,
    }
}
pub(crate) struct SubmittedCommand {
    ledger: Arc<OwnerDebtLedger>,
    id: u64,
}
impl SubmittedCommand {
    pub(crate) fn malformed_response(&self) {
        if let Ok(state) = self.ledger.state.lock() {
            if let Some(command) = state.commands.get(&self.id) {
                command.status.set(CommandStatus::IntegrityLost);
            }
        }
        self.ledger.connection_lost();
    }
    pub(crate) fn settle(&self, response: &CdpMessage) {
        let _ = self.settle_for_delivery(response);
    }
    pub(crate) fn settle_for_delivery(&self, response: &CdpMessage) -> Vec<LateDisposal> {
        let _notification = DebtChange(&self.ledger.changed);
        let Ok(mut state) = self.ledger.state.lock() else {
            return Vec::new();
        };
        let Some(command) = state.commands.get(&self.id) else {
            return Vec::new();
        };
        let valid_envelope = response.method.is_none()
            && response.params.is_none()
            && match (&response.result, &response.error) {
                (Some(Value::Object(_)), None) => true,
                (None, Some(error)) => error.code.is_some(),
                _ => false,
            };
        if !valid_envelope {
            command.status.set(CommandStatus::IntegrityLost);
            state.contaminate_integrity();
            return Vec::new();
        }
        if response.session_id.as_deref() != command.provenance.session.as_deref() {
            // Omission is valid only when both sides are browser-level.
            command.status.set(CommandStatus::IntegrityLost);
            state.contaminate_integrity();
            return Vec::new();
        }
        if response.error.is_some()
            && (command.category.input()
                || command.release_object.is_some()
                || command.release_group)
        {
            command.status.set(CommandStatus::RetainedRejected);
            // A failed cleanup is not a successful release. Keep its bounded
            // exact obligation; no waiter can promote it to clean state.
            return Vec::new();
        }
        if response.error.is_none() {
            if let Some(acquisition) = &command.acquisition {
                let result = response.result.as_ref().unwrap_or(&Value::Null);
                let (field, target, recording) = match acquisition {
                    LifecycleAcquisition::Context => ("browserContextId", None, false),
                    LifecycleAcquisition::Target => ("targetId", None, false),
                    LifecycleAcquisition::Session(target, recording) => {
                        ("sessionId", Some(target.clone()), *recording)
                    }
                };
                let Some(identity) = result[field]
                    .as_str()
                    .filter(|id| !id.is_empty() && id.len() <= 4096)
                    .map(str::to_owned)
                else {
                    state.contaminate_integrity();
                    return Vec::new();
                };
                let extra = 64
                    + identity.len()
                    + target.as_ref().map_or(0, String::len)
                    + if recording { 64 + identity.len() } else { 0 };
                if metadata_usage(&state).saturating_add(extra) > 64 * 1024
                    || descriptor_usage(&state).saturating_add(extra) > 508 * 1024
                {
                    state.contaminate_integrity();
                    return Vec::new();
                }
                match field {
                    "browserContextId" => {
                        if state
                            .context_id
                            .as_ref()
                            .is_some_and(|context| context != &identity)
                        {
                            state.contaminate_integrity();
                            return Vec::new();
                        }
                        state.context_id = Some(identity);
                    }
                    "targetId" => {
                        state.created_targets.insert(identity);
                    }
                    _ => {
                        let target = target.expect("session acquisition target");
                        if state
                            .targets
                            .get(&identity)
                            .is_some_and(|known| known != &target)
                        {
                            state.contaminate_integrity();
                            return Vec::new();
                        }
                        if recording {
                            state
                                .lifecycle_sessions
                                .insert(identity.clone(), LifecycleSessionPurpose::Recording);
                        }
                        state.targets.insert(identity, target);
                    }
                }
            }
        }
        let command = remove_command(&mut state, self.id).expect("checked command");
        if response.error.is_none() {
            if let Some(kind) = command.cleanup_kind {
                state.final_cleanup_acknowledged[kind as usize] = true;
            }
        }
        command.status.set(CommandStatus::Acknowledged);
        if let Some(group_id) = command.group_id {
            if command.release_group && command.group_release_proven {
                state.groups.remove(&group_id);
                return Vec::new();
            }
            if let Some(group) = state.groups.get_mut(&group_id) {
                if command.release_group {
                    group.release_inflight = false;
                }
                if group.sealed
                    && group.submitted_creations == 0
                    && !group.release_inflight
                    && !group.cleanup_issued
                {
                    group.cleanup_issued = true;
                    return vec![LateDisposal {
                        ledger: self.ledger.clone(),
                        provenance: group.provenance.clone(),
                        object: None,
                        abandoned_only: false,
                        group: Some((group_id, group.name.clone())),
                    }];
                }
            }
            return Vec::new();
        }
        if command.objects_destroyed {
            return Vec::new();
        }
        let result = response.result.as_ref().unwrap_or(&Value::Null);
        let mut seen = HashSet::new();
        let handles: Vec<&str> = [
            result["result"]["objectId"].as_str(),
            result["object"]["objectId"].as_str(),
            result["exceptionDetails"]["exception"]["objectId"].as_str(),
        ]
        .into_iter()
        .flatten()
        .filter(|object| seen.insert(*object))
        .collect();
        if handles.len() > command.creation_slots
            || handles.iter().any(|object| object.len() > 4096)
        {
            state.contaminate_integrity();
            // Preserve pre-reserved anonymous creation debt if an invalid
            // response cannot safely be represented, rather than truncating it.
            for _ in 0..command.creation_slots {
                state.objects.push(ObjectObligation {
                    provenance: command.provenance.clone(),
                    object: None,
                    group: command.object_group.clone(),
                    serial: 0,
                    footprint: 256,
                });
                state.object_bytes += 256;
            }
            return Vec::new();
        }
        let mut disposals = Vec::new();
        for object in handles {
            if !state.objects.iter().any(|old| {
                old.provenance.session == command.provenance.session
                    && old.object.as_deref() == Some(object)
            }) {
                let footprint =
                    256 + object.len() + command.object_group.as_ref().map_or(0, String::len);
                let Some(serial) = state.next_object_serial.checked_add(1) else {
                    state.contaminate_integrity();
                    return Vec::new();
                };
                state.next_object_serial = serial;
                state.object_bytes += footprint;
                {
                    disposals.push(LateDisposal {
                        ledger: self.ledger.clone(),
                        provenance: command.provenance.clone(),
                        object: Some(object.to_owned()),
                        abandoned_only: true,
                        group: None,
                    });
                }
                state.objects.push(ObjectObligation {
                    provenance: command.provenance.clone(),
                    object: Some(object.to_owned()),
                    group: command.object_group.clone(),
                    serial,
                    footprint,
                });
            }
        }
        if let Some(object) = &command.release_object {
            state.objects.retain(|old| {
                !(old.provenance.session == command.provenance.session
                    && old.object.as_ref() == Some(object))
            });
            state.object_bytes = state.objects.iter().map(|object| object.footprint).sum();
        }
        if command.release_group {
            state.objects.retain(|old| {
                !(old.provenance.session == command.provenance.session
                    && old.group == command.object_group
                    && old.object.is_some()
                    && old.serial <= command.release_group_fence)
            });
            state.object_bytes = state.objects.iter().map(|object| object.footprint).sum();
        }
        // A group ACK only retires already-known handles captured before that
        // release was submitted. Pending/late unknown creation never borrows it.
        disposals
    }
}
/// One-shot cleanup work derived only from an actual reader-correlated reply.
/// It cannot carry a caller continuation or any executable application payload.
pub(crate) struct LateDisposal {
    ledger: Arc<OwnerDebtLedger>,
    provenance: Provenance,
    object: Option<String>,
    abandoned_only: bool,
    group: Option<(u64, String)>,
}
pub(crate) struct ReservedDisposal {
    pub reservation: CommandReservation,
    pub method: &'static str,
    pub params: Value,
    pub session: Option<String>,
}
impl LateDisposal {
    pub(crate) fn needed_after_delivery(&self, abandoned: bool) -> bool {
        !self.abandoned_only || abandoned
    }
    pub(crate) fn reserve(self) -> Result<ReservedDisposal, ProtocolError> {
        let (method, params) = if let Some((_, group)) = &self.group {
            (
                "Runtime.releaseObjectGroup",
                serde_json::json!({"objectGroup":group}),
            )
        } else {
            (
                "Runtime.releaseObject",
                serde_json::json!({"objectId":self.object}),
            )
        };
        let reservation = self.ledger.reserve_command(
            None,
            method,
            Some(&params),
            self.provenance.session.as_deref(),
        )?;
        {
            let mut state = self
                .ledger
                .state
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if let Some((id, _)) = &self.group {
                if !state.groups.contains_key(id) {
                    return Err(ProtocolError::StaleScope);
                }
            }
            let command = state
                .commands
                .get_mut(&reservation.id)
                .ok_or(ProtocolError::ScopeUnavailable)?;
            command.provenance = self.provenance.clone();
            command.group_id = self.group.as_ref().map(|(id, _)| *id);
        }
        Ok(ReservedDisposal {
            reservation,
            method,
            params,
            session: self.provenance.session,
        })
    }
}
struct Classification {
    category: CommandCategory,
    mutation: bool,
}
fn creation_slots(method: &str, params: Option<&Value>) -> usize {
    match method {
        "DOM.resolveNode" => 1,
        "Runtime.evaluate"
        | "Runtime.callFunctionOn"
        | "Runtime.runScript"
        | "Runtime.awaitPromise" => {
            if params
                .and_then(|params| params.get("returnByValue"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                1
            } else {
                2
            }
        }
        // getProperties can return an unbounded array of handles. It must not
        // run on the retained path unless a bounded native consumer is added.
        "Runtime.getProperties" => 33,
        _ => 0,
    }
}
fn classify(method: &str, _params: Option<&Value>, operation: bool) -> Classification {
    if let Ok(explicit) = COMMAND_OVERRIDE.try_with(|value| *value) {
        return Classification {
            category: if explicit.mutation && explicit.category.application() {
                CommandCategory::ApplicationInput
            } else {
                explicit.category
            },
            mutation: explicit.mutation,
        };
    }
    let release = matches!(
        method,
        "Runtime.releaseObject" | "Runtime.releaseObjectGroup"
    );
    let category = if release {
        CommandCategory::CleanupObject
    } else if method == "Target.disposeBrowserContext" || method == "Browser.close" {
        CommandCategory::Destroy
    } else if method == "Fetch.getResponseBody" {
        CommandCategory::Download
    } else if method.starts_with("Fetch.") || method == "Page.handleJavaScriptDialog" {
        CommandCategory::Security
    } else if matches!(
        method,
        "Page.screencastFrameAck" | "Page.startScreencast" | "Page.stopScreencast"
    ) {
        CommandCategory::Recording
    } else if matches!(
        method,
        "Browser.setDownloadBehavior"
            | "Browser.cancelDownload"
            | "Network.getResponseBody"
            | "Fetch.getResponseBody"
            | "IO.read"
            | "IO.close"
    ) {
        CommandCategory::Download
    } else if operation {
        if method.starts_with("Input.") {
            CommandCategory::ApplicationInput
        } else if method.starts_with("DOM.") || method.starts_with("Runtime.") {
            CommandCategory::ApplicationObject
        } else {
            CommandCategory::ApplicationRead
        }
    } else {
        CommandCategory::Enrollment
    };
    // Runtime.evaluate is not a fixed safe read. Native action call sites can
    // narrow this only with a static command_scope override.
    let mutation = !release
        && !matches!(
            method,
            "Browser.getVersion"
                | "Page.getFrameTree"
                | "Page.getLayoutMetrics"
                | "Page.getNavigationHistory"
                | "DOM.describeNode"
                | "DOM.resolveNode"
                | "DOM.getBoxModel"
                | "DOM.getContentQuads"
                | "DOM.getDocument"
                | "Accessibility.getFullAXTree"
                | "Accessibility.getPartialAXTree"
                | "Target.getTargets"
                | "Target.getTargetInfo"
                | "Network.getCookies"
                | "Storage.getCookies"
                | "Runtime.getIsolateId"
                | "Page.createIsolatedWorld"
        );
    let category = if operation && mutation && category.application() {
        CommandCategory::ApplicationInput
    } else {
        category
    };
    Classification { category, mutation }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn owner() -> (Arc<OwnerDebtLedger>, OperationJournalHandle) {
        let ledger = OwnerDebtLedger::new(7, "scope".into());
        let journal = ledger
            .operation(
                OperationKey {
                    generation: 7,
                    operation_seq: 1,
                },
                "target".into(),
                "page".into(),
            )
            .unwrap();
        (ledger, journal)
    }
    fn response(result: Value) -> CdpMessage {
        serde_json::from_value(json!({"id":1,"sessionId":"page","result":result})).unwrap()
    }
    async fn grouped(
        ledger: &Arc<OwnerDebtLedger>,
        journal: &OperationJournalHandle,
        group: &str,
        method: &str,
        params: Value,
    ) -> CommandReservation {
        native_object_group(
            group,
            command_scope(CommandCategory::ApplicationObject, false, async {
                ledger
                    .reserve_command(Some(journal), method, Some(&params), Some("page"))
                    .unwrap()
            }),
        )
        .await
    }
    fn admission_operation(
        timeout_ms: u64,
    ) -> (tokio::sync::watch::Sender<CancelSignal>, OperationLease) {
        let (cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        (
            cancel,
            OperationLease {
                is_callback: false,
                generation: 7,
                sequence: 2,
                deadline: Instant::now() + std::time::Duration::from_millis(timeout_ms),
                cancellation,
            },
        )
    }
    fn pending_input(
        ledger: &Arc<OwnerDebtLedger>,
        journal: &OperationJournalHandle,
    ) -> SubmittedCommand {
        ledger
            .reserve_command(
                Some(journal),
                "Input.dispatchMouseEvent",
                Some(&json!({"type":"mousePressed"})),
                Some("page"),
            )
            .unwrap()
            .submit()
            .unwrap()
    }
    #[tokio::test]
    async fn reference_admission_waiters_all_wake_on_exact_reader_ack_without_forgiving_debt() {
        let (ledger, journal) = owner();
        let submitted = pending_input(&ledger, &journal);
        let (_cancel, operation) = admission_operation(1000);
        let mut first =
            Box::pin(ledger.wait_admission(AdmissionClass::Reference, &operation, || Ok(())));
        let mut second =
            Box::pin(ledger.wait_admission(AdmissionClass::Reference, &operation, || Ok(())));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), first.as_mut())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), second.as_mut())
                .await
                .is_err()
        );
        assert_eq!(ledger.snapshot().input_debt, 1);
        assert!(ledger.check_admission(AdmissionClass::Reference).is_err());
        submitted.settle(&response(json!({})));
        let both = tokio::time::timeout(std::time::Duration::from_millis(100), async {
            tokio::join!(first, second)
        })
        .await
        .unwrap();
        assert_eq!(both, (Ok(()), Ok(())));
        assert!(journal.snapshot().mutation_dispatched);
        assert_eq!(ledger.snapshot().input_debt, 0);
        // ACK before initial polling is equally valid and cannot lose a wake.
        ledger
            .wait_admission(AdmissionClass::Reference, &operation, || Ok(()))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn reference_admission_deadline_and_cancel_keep_unsettled_input_owned() {
        let (ledger, journal) = owner();
        let _submitted = pending_input(&ledger, &journal);
        let (_cancel, operation) = admission_operation(20);
        assert_eq!(
            ledger
                .wait_admission(AdmissionClass::Reference, &operation, || Ok(()))
                .await,
            Err(ProtocolError::DeadlineExceeded)
        );
        assert_eq!(ledger.snapshot().input_debt, 1);
        let (cancel, operation) = admission_operation(1000);
        let mut waiting =
            Box::pin(ledger.wait_admission(AdmissionClass::Reference, &operation, || Ok(())));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), waiting.as_mut())
                .await
                .is_err()
        );
        cancel.send_replace(CancelSignal::Requested);
        assert_eq!(waiting.await, Err(ProtocolError::Cancelled));
        assert_eq!(ledger.snapshot().input_debt, 1);
    }
    #[tokio::test]
    async fn reference_admission_rechecks_authority_after_ack_and_never_revives_failed_owner() {
        let (ledger, journal) = owner();
        let submitted = pending_input(&ledger, &journal);
        let (_cancel, operation) = admission_operation(1000);
        let live = std::sync::atomic::AtomicBool::new(true);
        let mut waiting =
            Box::pin(
                ledger.wait_admission(AdmissionClass::Reference, &operation, || {
                    if live.load(Ordering::SeqCst) {
                        Ok(())
                    } else {
                        Err(ProtocolError::StaleScope)
                    }
                }),
            );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), waiting.as_mut())
                .await
                .is_err()
        );
        live.store(false, Ordering::SeqCst);
        submitted.settle(&response(json!({})));
        assert_eq!(waiting.await, Err(ProtocolError::StaleScope));
        ledger.connection_lost();
        assert_eq!(
            ledger
                .wait_admission(AdmissionClass::Reference, &operation, || Ok(()))
                .await,
            Err(ProtocolError::ScopeUnavailable)
        );
        assert_eq!(ledger.snapshot().input_debt, 0);
    }
    #[tokio::test]
    async fn reference_admission_eof_and_context_retirement_wake_without_admitting() {
        for eof in [false, true] {
            let (ledger, journal) = owner();
            ledger.bind_context("context").unwrap();
            let submitted = pending_input(&ledger, &journal);
            let (_cancel, operation) = admission_operation(1000);
            let mut waiting =
                Box::pin(ledger.wait_admission(AdmissionClass::Reference, &operation, || Ok(())));
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(5), waiting.as_mut())
                    .await
                    .is_err()
            );
            if eof {
                ledger.observe_remote_eof();
            } else {
                ledger.retire_after_context_destroy("context").unwrap();
            }
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_millis(100), waiting)
                    .await
                    .unwrap(),
                Err(ProtocolError::ScopeUnavailable)
            );
            submitted.settle(&response(json!({})));
            assert_eq!(
                ledger.check_admission(AdmissionClass::Reference),
                Err(ProtocolError::ScopeUnavailable)
            );
        }
    }
    #[test]
    fn submission_not_waiter_lifetime_owns_debt_and_ack_does_not_erase_dispatch() {
        let (ledger, journal) = owner();
        let pending = ledger
            .reserve_command(
                Some(&journal),
                "Input.dispatchMouseEvent",
                Some(&json!({"type":"mousePressed"})),
                Some("page"),
            )
            .unwrap();
        assert!(!journal.snapshot().mutation_dispatched);
        assert_eq!(ledger.snapshot().input_debt, 0);
        let submitted = pending.submit().unwrap();
        assert!(journal.snapshot().mutation_dispatched);
        assert_eq!(ledger.snapshot().input_debt, 1);
        drop(submitted);
        assert_eq!(ledger.snapshot().input_debt, 1);
        let id = *ledger.state.lock().unwrap().commands.keys().next().unwrap();
        SubmittedCommand {
            ledger: ledger.clone(),
            id,
        }
        .settle(&response(json!({})));
        assert_eq!(ledger.snapshot().input_debt, 0);
        assert!(journal.snapshot().mutation_dispatched);
    }
    #[test]
    fn quotas_do_not_borrow_recording_security_or_destroy_slots() {
        let (ledger, journal) = owner();
        let mut input = Vec::new();
        for _ in 0..16 {
            input.push(
                ledger
                    .reserve_command(Some(&journal), "Input.dispatchKeyEvent", None, Some("page"))
                    .unwrap()
                    .submit()
                    .unwrap(),
            );
        }
        assert!(ledger
            .reserve_command(Some(&journal), "Input.dispatchKeyEvent", None, Some("page"))
            .is_err());
        let security = ledger
            .reserve_command(None, "Fetch.continueRequest", None, Some("page"))
            .unwrap()
            .submit()
            .unwrap();
        let recording = ledger
            .reserve_command(None, "Page.screencastFrameAck", None, Some("page"))
            .unwrap()
            .submit()
            .unwrap();
        let destroy = ledger
            .reserve_command(None, "Target.disposeBrowserContext", None, None)
            .unwrap();
        assert_eq!(ledger.snapshot().input_debt, 16);
        drop((input, security, recording, destroy));
        assert_eq!(ledger.snapshot().input_debt, 16);
    }
    #[tokio::test]
    async fn native_group_accounts_many_roots_and_property_handles_as_one_obligation() {
        let (ledger, journal) = owner();
        for index in 0..64 {
            let submitted = grouped(
                &ledger,
                &journal,
                "native-security-1",
                "DOM.resolveNode",
                json!({"objectGroup":"native-security-1","backendNodeId":index}),
            )
            .await
            .submit()
            .unwrap();
            submitted.settle(&response(
                json!({"object":{"objectId":format!("root-{index}")}}),
            ));
            assert_eq!(ledger.snapshot().object_debt, 1);
        }
        let properties = grouped(
            &ledger,
            &journal,
            "native-security-1",
            "Runtime.getProperties",
            json!({"objectId":"array","ownProperties":true}),
        )
        .await
        .submit()
        .unwrap();
        properties.settle(&response(json!({"result":(0..64).map(|index|json!({"name":index.to_string(),"value":{"objectId":format!("node-{index}")}})).collect::<Vec<_>>()})));
        assert_eq!(ledger.snapshot().object_debt, 1);
        let release = ledger
            .reserve_command(
                Some(&journal),
                "Runtime.releaseObjectGroup",
                Some(&json!({"objectGroup":"native-security-1"})),
                Some("page"),
            )
            .unwrap()
            .submit()
            .unwrap();
        release.settle(&response(json!({})));
        assert_eq!(ledger.snapshot().object_debt, 0);
        assert!(!journal.snapshot().mutation_dispatched);
    }
    #[tokio::test]
    async fn early_release_ack_cannot_discharge_late_creation_and_disposal_is_once_only() {
        let (ledger, journal) = owner();
        let creation = grouped(
            &ledger,
            &journal,
            "native-query-1",
            "DOM.resolveNode",
            json!({"objectGroup":"native-query-1"}),
        )
        .await
        .submit()
        .unwrap();
        let release = ledger
            .reserve_command(
                Some(&journal),
                "Runtime.releaseObjectGroup",
                Some(&json!({"objectGroup":"native-query-1"})),
                Some("page"),
            )
            .unwrap()
            .submit()
            .unwrap();
        assert!(release.settle_for_delivery(&response(json!({}))).is_empty());
        assert_eq!(ledger.snapshot().object_debt, 1);
        let mut late =
            creation.settle_for_delivery(&response(json!({"object":{"objectId":"late-root"}})));
        assert_eq!(late.len(), 1);
        assert!(creation
            .settle_for_delivery(&response(json!({})))
            .is_empty());
        let disposal = late
            .pop()
            .unwrap()
            .reserve()
            .unwrap()
            .reservation
            .submit()
            .unwrap();
        disposal.settle(&response(json!({})));
        assert_eq!(ledger.snapshot().object_debt, 0);
    }
    #[tokio::test]
    async fn unsent_old_receipt_never_submits_into_or_drops_a_later_group_lifecycle() {
        let (ledger, journal) = owner();
        let old = grouped(
            &ledger,
            &journal,
            "native-security-1",
            "DOM.resolveNode",
            json!({"objectGroup":"native-security-1"}),
        )
        .await;
        let release = ledger
            .reserve_command(
                Some(&journal),
                "Runtime.releaseObjectGroup",
                Some(&json!({"objectGroup":"native-security-1"})),
                Some("page"),
            )
            .unwrap()
            .submit()
            .unwrap();
        release.settle(&response(json!({})));
        let next = grouped(
            &ledger,
            &journal,
            "native-security-1",
            "DOM.resolveNode",
            json!({"objectGroup":"native-security-1"}),
        )
        .await;
        assert!(old.submit().is_err());
        assert_eq!(ledger.snapshot().object_debt, 1);
        next.submit()
            .unwrap()
            .settle(&response(json!({"object":{"objectId":"fresh"}})));
        assert_eq!(ledger.snapshot().object_debt, 1);
    }
    #[tokio::test]
    async fn abandoning_unsubmitted_group_does_not_leak_an_obligation() {
        let (ledger, journal) = owner();
        drop(
            grouped(
                &ledger,
                &journal,
                "native-query-1",
                "DOM.resolveNode",
                json!({"objectGroup":"native-query-1"}),
            )
            .await,
        );
        assert_eq!(ledger.snapshot().object_debt, 0);
    }
    #[test]
    fn realm_destruction_discharges_object_component_but_not_input_effect() {
        let (ledger, journal) = owner();
        ledger.observe_event(&CdpEvent {
            method: "Runtime.executionContextCreated".into(),
            session_id: Some("page".into()),
            params: json!({"context":{"id":9}}),
        });
        let submitted = ledger
            .reserve_command(
                Some(&journal),
                "Runtime.evaluate",
                Some(&json!({"contextId":9,"returnByValue":false})),
                Some("page"),
            )
            .unwrap()
            .submit()
            .unwrap();
        assert_eq!(
            (ledger.snapshot().input_debt, ledger.snapshot().object_debt),
            (1, 2)
        );
        ledger.observe_event(&CdpEvent {
            method: "Runtime.executionContextDestroyed".into(),
            session_id: Some("page".into()),
            params: json!({"executionContextId":9}),
        });
        assert_eq!(
            (ledger.snapshot().input_debt, ledger.snapshot().object_debt),
            (1, 0)
        );
        submitted.settle(&response(json!({"result":{"objectId":"destroyed"}})));
        assert_eq!(
            (ledger.snapshot().input_debt, ledger.snapshot().object_debt),
            (0, 0)
        );
        assert!(journal.snapshot().mutation_dispatched);
    }
    #[test]
    fn only_exact_context_ack_can_retire_owner_and_eof_never_clears_debt() {
        let (ledger, journal) = owner();
        ledger.bind_context("context").unwrap();
        let _command = ledger
            .reserve_command(Some(&journal), "Input.dispatchKeyEvent", None, Some("page"))
            .unwrap()
            .submit()
            .unwrap();
        assert!(ledger.retire_after_context_destroy("different").is_err());
        ledger.connection_lost();
        assert_eq!(ledger.snapshot().input_debt, 1);
        ledger.retire_after_context_destroy("context").unwrap();
        assert_eq!(ledger.snapshot().input_debt, 0);
        assert!(ledger
            .reserve_command(None, "Page.getFrameTree", None, Some("page"))
            .is_err());
    }
    fn borrowed_final_local_owner() -> Arc<OwnerDebtLedger> {
        let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 7,
            sequence: 1,
            deadline: Instant::now() + std::time::Duration::from_secs(30),
            cancellation,
        };
        let ledger = OwnerDebtLedger::unpublished(&operation, "scope".into(), false).unwrap();
        ledger.bind_context("borrowed-context").unwrap();
        ledger
    }
    #[test]
    fn final_local_eof_is_read_only_exact_borrowed_owner_evidence_not_admission() {
        let ledger = borrowed_final_local_owner();
        ledger
            .allow_initialization_script("inert authorization")
            .unwrap();
        ledger
            .bind_session("borrowed-context", "target", "page")
            .unwrap();
        assert!(ledger.check_final_local_eof(7, "scope").is_err());
        ledger.observe_event(&CdpEvent {
            method: "Target.detachedFromTarget".into(),
            session_id: None,
            params: json!({"sessionId":"page"}),
        });
        assert!(ledger.check_final_local_eof(7, "scope").is_err());
        ledger.observe_remote_eof();
        let before = ledger.snapshot();
        assert!(before.integrity_lost);
        assert!(before.descriptor_bytes > 0);
        assert!(ledger.check_final_local_eof(8, "scope").is_err());
        assert!(ledger.check_final_local_eof(7, "replacement").is_err());
        assert!(ledger.check_final_local_eof(7, "scope").is_ok());
        assert_eq!(ledger.snapshot(), before);
        assert_eq!(ledger.bound_context().as_deref(), Some("borrowed-context"));
        assert!(!ledger.replacement_ready());
        assert!(ledger.check_admission(AdmissionClass::FixedRead).is_err());
        assert!(ledger
            .reserve_command(None, "Browser.getVersion", None, None)
            .is_err());
        assert!(ledger
            .bind_session("borrowed-context", "next", "next")
            .is_err());
    }
    #[test]
    fn final_local_eof_refuses_every_live_resource_and_uncertain_context() {
        for obstruction in [
            "object",
            "group",
            "realm",
            "target",
            "lifecycle_session",
            "created_target",
            "recording_target",
            "context_claim",
            "owned",
            "unbound",
            "legacy",
            "retired",
        ] {
            let ledger = borrowed_final_local_owner();
            {
                let mut state = ledger.state.lock().unwrap();
                let provenance = Provenance {
                    operation: None,
                    target: Some("target".into()),
                    session: Some("page".into()),
                    realm: None,
                };
                match obstruction {
                    "object" => state.objects.push(ObjectObligation {
                        provenance,
                        object: Some("object".into()),
                        group: None,
                        serial: 1,
                        footprint: 256,
                    }),
                    "group" => {
                        state.groups.insert(
                            1,
                            GroupObligation {
                                provenance,
                                name: "group".into(),
                                footprint: 256,
                                pending_creations: 0,
                                submitted_creations: 0,
                                ever_submitted: true,
                                sealed: true,
                                release_inflight: false,
                                cleanup_issued: false,
                            },
                        );
                    }
                    "realm" => {
                        state.realms.insert(("page".into(), 1), 1);
                    }
                    "target" => {
                        state.targets.insert("page".into(), "target".into());
                    }
                    "lifecycle_session" => {
                        state
                            .lifecycle_sessions
                            .insert("observer".into(), LifecycleSessionPurpose::Observer);
                    }
                    "created_target" => {
                        state.created_targets.insert("target".into());
                    }
                    "recording_target" => {
                        state.recording_targets.insert("target".into());
                    }
                    "context_claim" => state.context_creation_claimed = true,
                    "owned" => state.bootstrap.as_mut().unwrap().owns_context = true,
                    "unbound" => state.context_id = None,
                    "legacy" => state.bootstrap = None,
                    "retired" => state.retired = true,
                    _ => unreachable!(),
                }
            }
            ledger.observe_remote_eof();
            let before = ledger.snapshot();
            assert!(
                ledger.check_final_local_eof(7, "scope").is_err(),
                "{obstruction}"
            );
            assert_eq!(ledger.snapshot(), before);
        }
    }
    #[test]
    fn eof_never_acknowledges_commands_or_pending_acquisition() {
        for method in [
            "Browser.getVersion",
            "Target.createTarget",
            "Input.dispatchKeyEvent",
        ] {
            let ledger = borrowed_final_local_owner();
            let journal = if method == "Input.dispatchKeyEvent" {
                ledger
                    .bind_session("borrowed-context", "target", "page")
                    .unwrap();
                ledger.publish_initialization(|| Ok(())).unwrap();
                Some(
                    ledger
                        .operation(
                            OperationKey {
                                generation: 7,
                                operation_seq: 1,
                            },
                            "target".into(),
                            "page".into(),
                        )
                        .unwrap(),
                )
            } else {
                None
            };
            let params = (method == "Target.createTarget")
                .then(|| json!({"url":"about:blank","browserContextId":"borrowed-context"}));
            let reservation = ledger
                .reserve_command(
                    journal.as_ref(),
                    method,
                    params.as_ref(),
                    journal.as_ref().map(|_| "page"),
                )
                .unwrap();
            let status = reservation.status();
            let _submitted = reservation.submit().unwrap();
            ledger.observe_remote_eof();
            assert!(ledger.check_final_local_eof(7, "scope").is_err());
            assert_eq!(ledger.snapshot().outstanding_commands, 1);
            assert_eq!(status.snapshot(), CommandStatus::Submitted);
            if journal.is_some() {
                assert_eq!(ledger.snapshot().input_debt, 1);
            }
        }
    }
    #[test]
    fn final_local_eof_contamination_survives_exact_debt_destruction() {
        for damage in ["local_close", "malformed", "correlation", "metadata"] {
            let ledger = borrowed_final_local_owner();
            ledger
                .bind_session("borrowed-context", "target", "page")
                .unwrap();
            ledger.publish_initialization(|| Ok(())).unwrap();
            let journal = ledger
                .operation(
                    OperationKey {
                        generation: 7,
                        operation_seq: 1,
                    },
                    "target".into(),
                    "page".into(),
                )
                .unwrap();
            let command = ledger
                .reserve_command(Some(&journal), "Input.dispatchKeyEvent", None, Some("page"))
                .unwrap()
                .submit()
                .unwrap();
            match damage {
                "local_close" => ledger.connection_lost(),
                "malformed" => command.malformed_response(),
                "correlation" => command.settle(
                    &serde_json::from_value(json!({
                        "id":1,"sessionId":"foreign","result":{}
                    }))
                    .unwrap(),
                ),
                "metadata" => {
                    ledger.state.lock().unwrap().next_realm_epoch = u64::MAX;
                    ledger.observe_event(&CdpEvent {
                        method: "Runtime.executionContextCreated".into(),
                        session_id: Some("page".into()),
                        params: json!({"context":{"id":1}}),
                    });
                }
                _ => unreachable!(),
            }
            ledger.observe_event(&CdpEvent {
                method: "Target.detachedFromTarget".into(),
                session_id: None,
                params: json!({"sessionId":"page"}),
            });
            ledger.observe_remote_eof();
            assert_eq!(ledger.snapshot().outstanding_commands, 0);
            assert!(
                ledger.check_final_local_eof(7, "scope").is_err(),
                "{damage}"
            );
        }
        let ledger = borrowed_final_local_owner();
        ledger.observe_remote_eof();
        assert!(ledger.check_final_local_eof(7, "scope").is_ok());
        ledger.connection_lost();
        ledger.observe_remote_eof();
        assert!(ledger.check_final_local_eof(7, "scope").is_err());
    }
    #[tokio::test]
    async fn retired_owner_cleanup_is_one_shot_accounted_and_not_application_authority() {
        let (ledger, journal) = owner();
        ledger.bind_context("context").unwrap();
        let stale_application = ledger
            .reserve_command(Some(&journal), "Input.insertText", None, Some("page"))
            .unwrap();
        let cleanup = ledger
            .reserve_owner_cleanup(OwnerCleanupCommand::DisableAutoAttach)
            .unwrap();
        let cleanup_status = cleanup.status();
        // First retirement preserves only the registered connection obligation.
        ledger.retire_after_context_destroy("context").unwrap();
        assert!(stale_application.submit().is_err());
        assert_eq!(ledger.snapshot().outstanding_commands, 1);
        assert_eq!(cleanup_status.snapshot(), CommandStatus::Reserved);
        let submitted = cleanup.submit().unwrap();
        ledger.retire_after_context_destroy("context").unwrap();
        assert_eq!(cleanup_status.snapshot(), CommandStatus::Submitted);
        assert_eq!(ledger.snapshot().outstanding_commands, 1);
        assert!(ledger
            .reserve_owner_cleanup(OwnerCleanupCommand::DisableAutoAttach)
            .is_err());
        for (method, params) in [
            ("Browser.close", None),
            (
                "Target.setAutoAttach",
                Some(
                    serde_json::json!({"autoAttach":false,"waitForDebuggerOnStart":false,"flatten":true}),
                ),
            ),
            (
                "Runtime.evaluate",
                Some(serde_json::json!({"expression":"1","returnByValue":true})),
            ),
        ] {
            assert!(ledger
                .reserve_command(None, method, params.as_ref(), None)
                .is_err());
            assert!(command_scope(CommandCategory::Destroy, false, async {
                ledger.reserve_command(Some(&journal), method, params.as_ref(), None)
            })
            .await
            .is_err());
        }
        assert!(ledger
            .operation(
                OperationKey {
                    generation: 7,
                    operation_seq: 2
                },
                "target".into(),
                "page".into()
            )
            .is_err());
        ledger.observe_event(&CdpEvent {
            method: "Runtime.executionContextCreated".into(),
            session_id: Some("page".into()),
            params: serde_json::json!({"context":{"id":1}}),
        });
        assert!(ledger.state.lock().unwrap().realms.is_empty());
        // DisableAutoAttach is browser-level; a page-session reply is not its ACK.
        submitted.settle(&serde_json::from_value(json!({"id":1,"result":{}})).unwrap());
        assert_eq!(ledger.snapshot().outstanding_commands, 0);
        assert_eq!(cleanup_status.snapshot(), CommandStatus::Acknowledged);
        assert!(!ledger.snapshot().integrity_lost);
        let close = ledger
            .reserve_owner_cleanup(OwnerCleanupCommand::CloseBrowser)
            .unwrap();
        drop(close);
        assert!(
            ledger
                .reserve_owner_cleanup(OwnerCleanupCommand::CloseBrowser)
                .is_err(),
            "abandoned cleanup must not silently renew authority"
        );
    }

    #[test]
    fn realm_metadata_is_bounded_and_counted_without_borrowing_destroy_reserve() {
        let (ledger, _journal) = owner();
        for id in 1..4097 {
            ledger.observe_event(&CdpEvent {
                method: "Runtime.executionContextCreated".into(),
                session_id: Some("page".into()),
                params: json!({"context":{"id":id}}),
            });
        }
        let state = ledger.state.lock().unwrap();
        assert!(state.integrity_lost);
        assert!(metadata_usage(&state) <= 64 * 1024);
        assert!(state.realms.len() < 4096);
        drop(state);
        assert!(ledger
            .reserve_command(None, "Target.disposeBrowserContext", None, None)
            .is_ok());
    }
    #[tokio::test]
    async fn thirty_third_group_is_rejected_without_losing_existing_native_groups() {
        let (ledger, journal) = owner();
        for id in 0..32 {
            let name = format!("native-query-{id}");
            grouped(
                &ledger,
                &journal,
                &name,
                "DOM.resolveNode",
                json!({"objectGroup":name}),
            )
            .await
            .submit()
            .unwrap()
            .settle(&response(
                json!({"object":{"objectId":format!("root-{id}")}}),
            ));
        }
        let result = native_object_group("native-query-next", async {
            ledger.reserve_command(
                Some(&journal),
                "DOM.resolveNode",
                Some(&json!({"objectGroup":"native-query-next"})),
                Some("page"),
            )
        })
        .await;
        assert!(matches!(result, Err(ProtocolError::CapacityExceeded)));
        assert_eq!(ledger.snapshot().object_debt, MAX_OBJECT_DEBT);
        assert!(ledger
            .reserve_command(None, "Target.disposeBrowserContext", None, None)
            .is_ok());
    }
    #[test]
    fn malformed_or_foreign_response_never_becomes_an_input_ack() {
        for envelope in [
            json!({"id":1,"sessionId":"page"}),
            json!({"id":1,"sessionId":"page","result":{},"error":{"code":-32000,"message":"synthetic"}}),
            json!({"id":1,"sessionId":"foreign","result":{}}),
            json!({"id":1,"sessionId":"page","result":null}),
        ] {
            let (ledger, journal) = owner();
            let command = ledger
                .reserve_command(
                    Some(&journal),
                    "Input.dispatchMouseEvent",
                    None,
                    Some("page"),
                )
                .unwrap()
                .submit()
                .unwrap();
            command.settle(&serde_json::from_value(envelope).unwrap());
            assert!(ledger.snapshot().integrity_lost);
            assert_eq!(ledger.snapshot().input_debt, 1);
        }
        let (ledger, _journal) = owner();
        let command = ledger
            .reserve_command(None, "Target.disposeBrowserContext", None, None)
            .unwrap()
            .submit()
            .unwrap();
        command.settle(&response(json!({})));
        assert!(ledger.snapshot().integrity_lost);
        assert_eq!(ledger.snapshot().outstanding_commands, 1);
    }
    #[test]
    fn receiver_drop_between_settlement_and_delivery_still_selects_exact_disposal() {
        let (ledger, journal) = owner();
        let command = ledger
            .reserve_command(Some(&journal), "DOM.resolveNode", None, Some("page"))
            .unwrap()
            .submit()
            .unwrap();
        let reply = response(json!({"object":{"objectId":"race-object"}}));
        let (sender, receiver) = tokio::sync::oneshot::channel();
        assert!(!sender.is_closed());
        let mut disposals = command.settle_for_delivery(&reply);
        drop(receiver);
        let delivery_failed = sender.send(reply).is_err();
        assert!(delivery_failed);
        assert_eq!(disposals.len(), 1);
        let disposal = disposals.pop().unwrap();
        assert!(disposal.needed_after_delivery(delivery_failed));
        // A full/stopped queue drops only its unsent reservation, never debt.
        drop(disposal.reserve().unwrap());
        assert_eq!(ledger.snapshot().object_debt, 1);
    }
    #[tokio::test]
    async fn revoked_journal_rejects_old_application_step_but_admits_mandatory_cleanup() {
        let (ledger, journal) = owner();
        let command = ledger
            .reserve_command(Some(&journal), "Input.dispatchKeyEvent", None, Some("page"))
            .unwrap()
            .submit()
            .unwrap();
        let old = ledger
            .reserve_command(Some(&journal), "Input.dispatchKeyEvent", None, Some("page"))
            .unwrap();
        journal.revoke_application_submission();
        command.settle(&response(json!({})));
        assert!(old.submit().is_err());
        assert_eq!(ledger.snapshot().input_debt, 0);
        let cleanup = command_scope(CommandCategory::CleanupOther, false, async {
            ledger.reserve_command(
                Some(&journal),
                "Runtime.callFunctionOn",
                Some(&json!({"returnByValue":true})),
                Some("page"),
            )
        })
        .await
        .unwrap()
        .submit()
        .unwrap();
        cleanup.settle(&response(json!({"result":{"type":"boolean","value":true}})));
        assert_eq!(ledger.snapshot().object_debt, 0);
        assert!(journal.snapshot().mutation_dispatched);
    }
    #[test]
    fn rejected_object_release_is_retained_debt_not_cleanup_success() {
        let (ledger, journal) = owner();
        ledger
            .reserve_command(Some(&journal), "DOM.resolveNode", None, Some("page"))
            .unwrap()
            .submit()
            .unwrap()
            .settle(&response(json!({"object":{"objectId":"kept"}})));
        let reservation = ledger
            .reserve_command(
                Some(&journal),
                "Runtime.releaseObject",
                Some(&json!({"objectId":"kept"})),
                Some("page"),
            )
            .unwrap();
        let status = reservation.status();
        reservation.submit().unwrap().settle(
            &serde_json::from_value(
                json!({"id":2,"sessionId":"page","error":{"code":-32000,"message":"synthetic"}}),
            )
            .unwrap(),
        );
        assert_eq!(status.snapshot(), CommandStatus::RetainedRejected);
        assert!(!status.settled());
        assert_eq!(ledger.snapshot().object_debt, 1);
        assert!(!ledger.snapshot().integrity_lost);
    }
}
