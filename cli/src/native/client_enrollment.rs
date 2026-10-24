//! One scope-owned target enrollment supervisor. Target metadata is inspected
//! before any page/network domain; foreign sessions are detached immediately.
//! The authoritative identity/purpose registry remains ClientTargets.
use super::cdp::client::{BoundedEventWatermark, BoundedMethodEvents, CdpClient};
use super::cdp::types::CdpEvent;
use super::client_app_events::{AppNavigationContext, AppNavigationKind};
use super::client_browser::{
    BrowserExecutionLease, ExecutionGate, InitializationAccess, LifecycleInitialization,
};
use super::client_network::{ApplicationSession, ClientNetwork};
use super::client_page::ClientPageState;
use super::client_protocol::ProtocolError;
use super::client_session::{CancelSignal, OperationLease};
use super::client_settlement_trace::{ServiceWorkerAdmission, WorkerAdmissionStep};
use super::client_targets::{ClientTargets, OwnedTarget, TargetPurpose};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{watch, Notify};
use tokio::task::{JoinHandle, JoinSet};

const EVENTS: &[&str] = &[
    "Target.attachedToTarget",
    "Target.detachedFromTarget",
    "Target.targetInfoChanged",
    #[cfg(test)]
    "Target.targetDestroyed",
    "Runtime.consoleAPICalled",
    "Runtime.exceptionThrown",
    "Runtime.executionContextCreated",
    "Runtime.executionContextDestroyed",
    "Runtime.executionContextsCleared",
    "Page.frameNavigated",
    "Page.frameAttached",
    "Page.navigatedWithinDocument",
    "Page.frameDetached",
    "Network.requestWillBeSent",
    "Network.responseReceived",
    "Network.loadingFinished",
    "Network.loadingFailed",
    "Fetch.requestPaused",
    "Fetch.authRequired",
    "Page.javascriptDialogOpening",
    "Browser.downloadWillBegin",
    "Browser.downloadProgress",
    "Page.downloadWillBegin",
    "Page.downloadProgress",
];
const MAX_SESSIONS: usize = 128;
const MAX_FRAMES: usize = 4096;
const MAX_TASKS: usize = 64;
const INITIALIZE_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub enum ScopeOwnership {
    IsolatedContext,
    TrackedTargets(Vec<String>),
    /// Authorized adopted host pages: attach permission is not lifetime ownership.
    BorrowedTargets(Vec<String>),
}
#[derive(Clone, Debug, Default)]
pub struct CleanupOutcome {
    pub isolated_context_disposed: bool,
    pub closed_targets: Vec<String>,
    pub autoattach_disabled: bool,
    pub borrowed_sessions_detached: Vec<String>,
    pub borrowed_cleanup_failed: bool,
    pub owned_resources_contained: bool,
}
pub struct ContainmentProof {
    debt: Option<Arc<super::client_debt::OwnerDebtLedger>>,
    registry: Arc<ClientTargets>,
    identity_scope: String,
    generation: u64,
}
/// Captured terminal transport identity. This is not remote cleanup ACK evidence.
#[derive(Clone)]
pub(crate) struct NativeTerminalProof {
    client: Arc<CdpClient>,
    targets: Arc<ClientTargets>,
    network: std::sync::Weak<ClientNetwork>,
    generation: u64,
    identity_scope: String,
    active_target: String,
}
impl NativeTerminalProof {
    pub(crate) fn check_client(&self, client: &Arc<CdpClient>) -> Result<(), ProtocolError> {
        if !Arc::ptr_eq(&self.client, client) || !*self.client.remote_connection_closed().borrow() {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    pub(crate) fn check_targets(&self, targets: &Arc<ClientTargets>) -> Result<(), ProtocolError> {
        self.check_client(&self.client)?;
        if !Arc::ptr_eq(&self.targets, targets) || self.identity_scope != targets.identity_scope {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    pub(crate) fn check_network(&self, network: &Arc<ClientNetwork>) -> Result<(), ProtocolError> {
        self.check_targets(&self.targets)?;
        if !self
            .network
            .upgrade()
            .is_some_and(|owner| Arc::ptr_eq(&owner, network))
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    pub(crate) fn check_event_sink(
        &self,
        sink: &super::client_transport::ClientEventSink,
    ) -> Result<(), ProtocolError> {
        let network = self.network.upgrade().ok_or(ProtocolError::StaleScope)?;
        self.check_network(&network)?;
        network.check_event_sink(sink)
    }
    pub(crate) fn targets(&self) -> &Arc<ClientTargets> {
        &self.targets
    }
    pub(crate) fn active_target(&self) -> &str {
        &self.active_target
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    #[cfg(test)]
    pub(crate) fn for_test(
        client: Arc<CdpClient>,
        targets: Arc<ClientTargets>,
        network: &Arc<ClientNetwork>,
        generation: u64,
        active_target: String,
    ) -> Result<Self, ProtocolError> {
        let proof = Self {
            identity_scope: targets.identity_scope.clone(),
            client,
            targets,
            network: Arc::downgrade(network),
            generation,
            active_target,
        };
        proof.check_network(network)?;
        Ok(proof)
    }
}
/// Final-local cleanup identity only. Unlike NativeTerminalProof this has no
/// active target and cannot preserve routes, reconnect, or prove remote ACKs.
#[derive(Clone)]
pub(crate) struct FinalLocalEofProof {
    client: Arc<CdpClient>,
    targets: Arc<ClientTargets>,
    network: std::sync::Weak<ClientNetwork>,
    generation: u64,
    identity_scope: String,
    received: u64,
}
impl FinalLocalEofProof {
    pub(crate) fn check_client(&self, client: &Arc<CdpClient>) -> Result<(), ProtocolError> {
        if !Arc::ptr_eq(&self.client, client) || !*client.remote_connection_closed().borrow() {
            return Err(ProtocolError::StaleScope);
        }
        let debt = client.debt_ledger().ok_or(ProtocolError::StaleScope)?;
        client.check_cleanup_owner(&Some(debt.clone()))?;
        debt.check_final_local_eof(self.generation, &self.identity_scope)
    }
    pub(crate) fn check_targets(&self, targets: &Arc<ClientTargets>) -> Result<(), ProtocolError> {
        self.check_client(&self.client)?;
        if !Arc::ptr_eq(&self.targets, targets) || self.identity_scope != targets.identity_scope {
            return Err(ProtocolError::StaleScope);
        }
        self.targets.check_final_local_cleanup()
    }
    pub(crate) fn check_network(&self, network: &Arc<ClientNetwork>) -> Result<(), ProtocolError> {
        self.check_targets(&self.targets)?;
        if self.identity_scope != self.targets.identity_scope
            || !self
                .network
                .upgrade()
                .is_some_and(|owner| Arc::ptr_eq(&owner, network))
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    pub(crate) fn check_event_sink(
        &self,
        sink: &super::client_transport::ClientEventSink,
    ) -> Result<(), ProtocolError> {
        let network = self.network.upgrade().ok_or(ProtocolError::StaleScope)?;
        self.check_network(&network)?;
        network.check_event_sink(sink)
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn identity_scope(&self) -> &str {
        &self.identity_scope
    }
}
#[derive(Clone, Debug, Default)]
pub struct ScopeConfig {
    pub viewport: Option<(u32, u32)>,
    pub user_agent: Option<String>,
    pub locale: Option<String>,
    pub timezone_id: Option<String>,
    pub block_service_workers: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Attribution {
    target: String,
    session: String,
    parent: Option<String>,
    root: String,
    kind: String,
    application: bool,
    observation_only: bool,
    observer_paused: bool,
    resumed: bool,
}
#[derive(Clone, Debug)]
struct FrameOwner {
    loader: Option<String>,
    name: Option<String>,
    session: String,
    parent: Option<String>,
}
#[derive(Default)]
struct Index {
    realm_serial: u64,
    realm_sessions: HashMap<String, u64>,
    realms: HashMap<(String, i64), Arc<RealmFact>>,
    realm_pending: HashMap<u64, RealmPending>,
    realm_tickets: usize,
    borrowed_restart: Option<u64>,
    borrowed_restart_sequence: u64,
    borrowed_retired_targets: HashSet<String>,
    borrowed_blank: Option<Arc<BorrowedBlankState>>,
    sessions: HashMap<String, Attribution>,
    frames: HashMap<String, FrameOwner>,
    failure: Option<ProtocolError>,
    application_epoch: u64,
    applied_watermark: u64,
    pending_enrollment: HashSet<String>,
    reconciled: bool,
    popup_opened: HashSet<String>,
    retiring_pages: HashMap<String, String>,
    retired_page_sessions: HashSet<String>,
    retired_observer_sessions: HashSet<String>,
    retired_observer_targets: HashSet<String>,
}

const MAX_REALM_HOLDS: usize = 64;
#[derive(Debug)]
struct RealmFact {
    session: String,
    tenure: u64,
    frame: String,
    id: i64,
    unique: String,
    destroyed: AtomicBool,
}
struct RealmPending {
    binding: super::element::ExactBinding,
    tenure: u64,
    records: Vec<Arc<RealmFact>>,
}
pub(crate) struct RealmCaptureGuard {
    owner: Arc<ClientEnrollment>,
    nonce: u64,
    operation: u64,
}
pub(crate) struct ExactRealmTicket {
    owner: Arc<ClientEnrollment>,
    binding: super::element::ExactBinding,
    fact: Arc<RealmFact>,
}
impl Drop for RealmCaptureGuard {
    fn drop(&mut self) {
        if let Ok(mut index) = self.owner.index.lock() {
            index.realm_pending.remove(&self.nonce);
        }
    }
}
impl Drop for ExactRealmTicket {
    fn drop(&mut self) {
        if let Ok(mut index) = self.owner.index.lock() {
            index.realm_tickets = index.realm_tickets.saturating_sub(1);
        }
    }
}
impl RealmCaptureGuard {
    pub(crate) async fn bind(
        self,
        context: i64,
        op: &OperationLease,
    ) -> Result<ExactRealmTicket, ProtocolError> {
        if self.operation != op.sequence {
            return Err(ProtocolError::StaleScope);
        }
        loop {
            self.owner.check_restart_operation(op)?;
            let watermark = self.owner.realm_watermark()?;
            self.owner.drain_capture_watermark(&watermark, op).await?;
            {
                let mut index = self
                    .owner
                    .index
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                self.owner.realm_snapshot_healthy(&index, &watermark)?;
                let pending = index
                    .realm_pending
                    .get(&self.nonce)
                    .ok_or(ProtocolError::StaleScope)?;
                let mut matches = pending.records.iter().filter(|fact| fact.id == context);
                if let Some(fact) = matches.next() {
                    if matches.next().is_some() {
                        return Err(ProtocolError::StaleReference);
                    }
                    if index.realm_tickets >= MAX_REALM_HOLDS {
                        return Err(ProtocolError::CapacityExceeded);
                    }
                    if index.realm_sessions.get(&pending.binding.session) != Some(&pending.tenure) {
                        return Err(ProtocolError::StaleScope);
                    }
                    let ticket = ExactRealmTicket {
                        owner: self.owner.clone(),
                        binding: pending.binding.clone(),
                        fact: fact.clone(),
                    };
                    index.realm_tickets += 1;
                    return Ok(ticket);
                }
            }
            bounded(op, async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                Ok(())
            })
            .await?;
        }
    }
}
impl ExactRealmTicket {
    /// Cleanup identity only. Native realm destruction, not loader change or a
    /// CDP error, invalidates the object handles allocated in this exact realm.
    pub(crate) fn destroyed(&self) -> Result<bool, ProtocolError> {
        self.owner.check()?;
        let watermark = self.owner.realm_watermark()?;
        let index = self
            .owner
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        self.owner.realm_snapshot_healthy(&index, &watermark)?;
        if index.realm_sessions.get(&self.fact.session) != Some(&self.fact.tenure)
            || !index
                .sessions
                .get(&self.fact.session)
                .is_some_and(|entry| entry.application && !entry.observation_only)
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(self.fact.destroyed.load(Ordering::SeqCst))
    }
    /// ResolveNode accepts a numeric ID. Reconcile the original stream after
    /// its ACK before granting the returned object this ticket's cleanup proof.
    pub(crate) async fn verify_resolution_owner(
        &self,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.owner.check_restart_operation(op)?;
        let watermark = self.owner.realm_watermark()?;
        self.owner.drain_capture_watermark(&watermark, op).await?;
        let index = self
            .owner
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        self.owner.realm_snapshot_healthy(&index, &watermark)?;
        if self.fact.destroyed.load(Ordering::SeqCst)
            || index.realm_sessions.get(&self.fact.session) != Some(&self.fact.tenure)
            || !index
                .realms
                .get(&(self.fact.session.clone(), self.fact.id))
                .is_some_and(|fact| Arc::ptr_eq(fact, &self.fact))
        {
            return Err(ProtocolError::StaleReference);
        }
        Ok(())
    }
    pub(crate) async fn document_retired(
        &self,
        op: &OperationLease,
    ) -> Result<bool, ProtocolError> {
        self.owner.check_restart_operation(op)?;
        let watermark = self.owner.realm_watermark()?;
        self.owner.drain_capture_watermark(&watermark, op).await?;
        if !self.destroyed()? {
            return Ok(false);
        }
        let evidence = bounded(op, async {
            Ok(super::element::exact_document_replaced(&self.owner.client, &self.binding).await)
        })
        .await?;
        self.owner.drain_capture_watermark(&watermark, op).await?;
        self.owner.check_restart_operation(op)?;
        if !self.destroyed()? {
            return Ok(false);
        }
        evidence.map_err(|_| ProtocolError::BrowserFailure)
    }
}

/// Explicit restart authority, not ordinary borrowed-resource ownership.
/// It names one original operation and never grants a context disposal right.
pub(crate) struct BorrowedRestartPermit {
    owner: Arc<ClientEnrollment>,
    nonce: u64,
    operation: OperationLease,
    creation_started: AtomicBool,
}
#[derive(Clone)]
enum BorrowedBlankStatus {
    Pending,
    Bound(String),
    Cancelled,
}
struct BorrowedBlankState {
    operation: OperationLease,
    nonce: u64,
    status: watch::Sender<BorrowedBlankStatus>,
}
pub(crate) struct BorrowedBlankAdmission {
    owner: Arc<ClientEnrollment>,
    state: Arc<BorrowedBlankState>,
    operation: OperationLease,
    completed: bool,
}
fn copy_operation(op: &OperationLease) -> OperationLease {
    OperationLease {
        is_callback: op.is_callback,
        generation: op.generation,
        sequence: op.sequence,
        deadline: op.deadline,
        cancellation: op.cancellation.clone(),
    }
}
fn exact_restart_operation(
    owner: &ClientEnrollment,
    captured: &OperationLease,
    op: &OperationLease,
) -> Result<(), ProtocolError> {
    owner.check_restart_operation(op)?;
    if op.is_callback
        || op.generation != captured.generation
        || op.sequence != captured.sequence
        || op.deadline != captured.deadline
        || !op.cancellation.same_channel(&captured.cancellation)
    {
        return Err(ProtocolError::StaleScope);
    }
    Ok(())
}
impl BorrowedRestartPermit {
    pub(crate) fn check(&self, op: &OperationLease) -> Result<(), ProtocolError> {
        exact_restart_operation(&self.owner, &self.operation, op)?;
        if self
            .owner
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .borrowed_restart
            != Some(self.nonce)
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    pub(crate) fn prepare_page_retirement(
        &self,
        info: &Value,
        op: &OperationLease,
    ) -> Result<Option<String>, ProtocolError> {
        self.check(op)?;
        let target = self.owner.exact_borrowed_page(info)?;
        let mut index = self
            .owner
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if index.borrowed_retired_targets.len() >= MAX_SESSIONS
            && !index.borrowed_retired_targets.contains(target)
        {
            return Err(ProtocolError::CapacityExceeded);
        }
        let session = index
            .sessions
            .values()
            .find(|entry| entry.target == target)
            .map(|entry| {
                if entry.kind != "page" || entry.root != entry.session {
                    Err(ProtocolError::PolicyDenied)
                } else {
                    Ok(entry.session.clone())
                }
            })
            .transpose()?;
        if let Some(session) = &session {
            if index.retiring_pages.len() >= MAX_SESSIONS
                && !index.retiring_pages.contains_key(target)
            {
                return Err(ProtocolError::CapacityExceeded);
            }
            if index
                .retiring_pages
                .get(target)
                .is_some_and(|old| old != session)
            {
                return Err(ProtocolError::StaleReference);
            }
            index.retiring_pages.insert(target.into(), session.clone());
        }
        index.borrowed_retired_targets.insert(target.into());
        Ok(session)
    }
    pub(crate) fn reserve_blank_creation(
        &self,
        op: &OperationLease,
    ) -> Result<BorrowedBlankAdmission, ProtocolError> {
        self.check(op)?;
        if self.creation_started.swap(true, Ordering::AcqRel) {
            return Err(ProtocolError::InvalidArguments);
        }
        let mut index = self
            .owner
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if index.borrowed_blank.is_some() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let state = Arc::new(BorrowedBlankState {
            operation: copy_operation(op),
            nonce: self.nonce,
            status: watch::channel(BorrowedBlankStatus::Pending).0,
        });
        index.borrowed_blank = Some(state.clone());
        Ok(BorrowedBlankAdmission {
            owner: self.owner.clone(),
            state,
            operation: copy_operation(op),
            completed: false,
        })
    }
}
impl Drop for BorrowedRestartPermit {
    fn drop(&mut self) {
        let mut unfinished = false;
        if let Ok(mut index) = self.owner.index.lock() {
            if index.borrowed_restart == Some(self.nonce) {
                index.borrowed_restart = None;
                if let Some(state) = index
                    .borrowed_blank
                    .as_ref()
                    .filter(|state| state.nonce == self.nonce)
                {
                    state.status.send_replace(BorrowedBlankStatus::Cancelled);
                    unfinished = true;
                }
            }
        }
        if unfinished {
            self.owner.poison(ProtocolError::CleanupFailed);
        }
        self.owner.changed.notify_waiters();
    }
}

impl BorrowedBlankAdmission {
    pub(crate) fn acknowledge(
        &mut self,
        info: &Value,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        exact_restart_operation(&self.owner, &self.operation, op)?;
        let target = self.owner.exact_borrowed_page(info)?;
        if info.get("url").and_then(Value::as_str) != Some("about:blank") {
            return Err(ProtocolError::PolicyDenied);
        }
        let index = self
            .owner
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if index.borrowed_restart != Some(self.state.nonce)
            || !index
                .borrowed_blank
                .as_ref()
                .is_some_and(|state| Arc::ptr_eq(state, &self.state))
            || index.borrowed_retired_targets.contains(target)
            || index.sessions.values().any(|entry| entry.target == target)
            || !matches!(*self.state.status.borrow(), BorrowedBlankStatus::Pending)
        {
            return Err(ProtocolError::StaleScope);
        }
        self.state
            .status
            .send_replace(BorrowedBlankStatus::Bound(target.into()));
        self.owner.changed.notify_waiters();
        Ok(())
    }
    pub(crate) fn complete(
        mut self,
        target: &str,
        session: &str,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        exact_restart_operation(&self.owner, &self.operation, op)?;
        let mut index = self
            .owner
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if !matches!(&*self.state.status.borrow(),BorrowedBlankStatus::Bound(id) if id==target)
            || !index.sessions.get(session).is_some_and(|entry| {
                entry.target == target
                    && entry.application
                    && entry.resumed
                    && entry.root == session
            })
            || !index
                .borrowed_blank
                .as_ref()
                .is_some_and(|state| Arc::ptr_eq(state, &self.state))
        {
            return Err(ProtocolError::StaleScope);
        }
        index.borrowed_blank = None;
        self.completed = true;
        Ok(())
    }
    /// Only for a caller proving Target.createTarget was never dispatched.
    pub(crate) fn cancel_unsubmitted(mut self) -> Result<(), ProtocolError> {
        if !matches!(*self.state.status.borrow(), BorrowedBlankStatus::Pending) {
            return Err(ProtocolError::StaleScope);
        }
        self.state
            .status
            .send_replace(BorrowedBlankStatus::Cancelled);
        let mut index = self
            .owner
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if index
            .borrowed_blank
            .as_ref()
            .is_some_and(|state| Arc::ptr_eq(state, &self.state))
        {
            index.borrowed_blank = None;
        }
        self.completed = true;
        Ok(())
    }
}
impl Drop for BorrowedBlankAdmission {
    fn drop(&mut self) {
        if !self.completed {
            self.state
                .status
                .send_replace(BorrowedBlankStatus::Cancelled);
            self.owner.poison(ProtocolError::CleanupFailed);
        }
    }
}

/// Private proof for one healthy enrollment tenure, not a wire credential.
/// Covers observed document navigation during this exact attachment tenure;
/// it does not claim pre-attachment profile history.
pub struct EnrollmentAttestation {
    coordinator: std::sync::Weak<ClientEnrollment>,
    targets: Arc<ClientTargets>,
    generation: u64,
    application_epoch: u64,
    frames: Vec<(String, String, String, String)>,
    watermark: BoundedEventWatermark,
    snapshot: CaptureSnapshot,
}
struct CaptureSnapshot {
    epoch: u64,
    entries: Vec<Attribution>,
    // All original Application insertions, including initially enumerable ones.
    // A second inventory must never replace these tickets with matching strings.
    owned: Vec<OwnedTarget>,
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum CaptureTestPoint {
    RestartWaiting,
    AfterInitialDrain,
    BeforeInfo,
    AfterInfoAck,
    AfterFenceDrain,
    DrainWaiting,
    AfterFreshAttestation,
    BeforeReturn,
    BeforeVerifyReturn,
    BeforeEventApply,
    BeforeAttachedProcessing,
}
#[cfg(test)]
struct CaptureTestGate {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}
#[cfg(test)]
impl CaptureTestGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
        })
    }
    async fn wait_entered(&self) {
        tokio::time::timeout(Duration::from_secs(2), self.entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
    }
    fn release(&self) {
        self.release.add_permits(1);
    }
}

/// Read-only, operation-bound application authority for an acknowledged input
/// prefix. It is not permission to execute input after cancellation.
pub(crate) struct SettledInputAuthority {
    owner: Arc<ClientEnrollment>,
    session: String,
    target: String,
    generation: u64,
    sequence: u64,
    deadline: Instant,
    cancellation: watch::Receiver<CancelSignal>,
    application_epoch: u64,
}
impl SettledInputAuthority {
    pub(crate) fn check(
        &self,
        owner: &Arc<ClientEnrollment>,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        if !Arc::ptr_eq(&self.owner, owner)
            || self.session != page.page_session_id
            || self.target != page.target_id
            || self.generation != op.generation
            || self.sequence != op.sequence
            || self.deadline != op.deadline
            || !self.cancellation.same_channel(&op.cancellation)
            || op.is_callback
        {
            return Err(ProtocolError::StaleScope);
        }
        // Requested cancellation may stop a settled prefix. Session retirement
        // and expired operation authority may not authorize reusable settlement.
        if *op.cancellation.borrow() == CancelSignal::SessionClosed {
            return Err(ProtocolError::StaleScope);
        }
        if Instant::now() >= op.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        if owner.settled_input_epoch(page, op.generation)? != self.application_epoch {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
}

#[derive(Default)]
struct ContainmentState {
    task: Option<JoinHandle<Result<(), ProtocolError>>>,
    result: Option<Result<(), ProtocolError>>,
}
pub struct ClientEnrollment {
    client: Arc<CdpClient>,
    targets: Arc<ClientTargets>,
    page: Arc<ClientPageState>,
    network: Arc<ClientNetwork>,
    gate: Arc<ExecutionGate>,
    initialization: Option<InitializationAccess>,
    generation: u64,
    active_root: Mutex<String>,
    config: ScopeConfig,
    ownership: ScopeOwnership,
    cleanup: Mutex<CleanupOutcome>,
    config_gate: Arc<tokio::sync::Mutex<()>>,
    index: Mutex<Index>,
    event_watermark: Mutex<Option<BoundedEventWatermark>>,
    changed: Notify,
    stop: watch::Sender<CancelSignal>,
    started: AtomicBool,
    sealed: AtomicBool,
    supervisor: tokio::sync::Mutex<Option<JoinHandle<Result<(), ProtocolError>>>>,
    containment: tokio::sync::Mutex<ContainmentState>,
    retirement_events: Mutex<Option<BoundedMethodEvents>>,
    terminal_proof: Mutex<Option<NativeTerminalProof>>,
    final_local_proof: Mutex<Option<FinalLocalEofProof>>,
    #[cfg(test)]
    capture_lifecycle: Mutex<CaptureLifecycleTrace>,
    #[cfg(test)]
    capture_test_gates: Mutex<HashMap<CaptureTestPoint, Arc<CaptureTestGate>>>,
}
impl ClientEnrollment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<CdpClient>,
        targets: Arc<ClientTargets>,
        page: Arc<ClientPageState>,
        network: Arc<ClientNetwork>,
        gate: Arc<ExecutionGate>,
        generation: u64,
        active_root: String,
        config: ScopeConfig,
        ownership: ScopeOwnership,
        initialization: Option<InitializationAccess>,
    ) -> Arc<Self> {
        let (stop, _) = watch::channel(CancelSignal::None);
        Arc::new(Self {
            client,
            targets,
            page,
            network,
            gate,
            initialization,
            generation,
            active_root: Mutex::new(active_root),
            config,
            ownership,
            cleanup: Mutex::new(CleanupOutcome::default()),
            config_gate: Arc::new(tokio::sync::Mutex::new(())),
            index: Mutex::new(Index::default()),
            event_watermark: Mutex::new(None),
            changed: Notify::new(),
            stop,
            started: AtomicBool::new(false),
            sealed: AtomicBool::new(false),
            supervisor: tokio::sync::Mutex::new(None),
            containment: tokio::sync::Mutex::new(ContainmentState::default()),
            retirement_events: Mutex::new(None),
            terminal_proof: Mutex::new(None),
            final_local_proof: Mutex::new(None),
            #[cfg(test)]
            capture_lifecycle: Mutex::new(CaptureLifecycleTrace::default()),
            #[cfg(test)]
            capture_test_gates: Mutex::new(HashMap::new()),
        })
    }
    // Diagnostics never grant authority or alter an error. Lock poisoning and
    // capacity loss only reduce evidence; they cannot make capture succeed.
    #[cfg(test)]
    fn trace_capture_event(&self, event: &CdpEvent, watermark: u64) {
        if let (Ok(index), Ok(mut trace)) = (self.index.lock(), self.capture_lifecycle.lock()) {
            trace.event(event, watermark, &index);
        }
    }
    #[cfg(test)]
    fn trace_capture_admission(&self, step: CaptureLifecycleStep, target: &str, session: &str) {
        if let (Ok(index), Ok(mut trace)) = (self.index.lock(), self.capture_lifecycle.lock()) {
            trace.push(
                step,
                Some(target),
                Some(session),
                None,
                index.sessions.get(session),
                &index,
                index.applied_watermark,
            );
        }
    }
    #[cfg(test)]
    fn trace_capture_registry(
        &self,
        step: CaptureLifecycleStep,
        entry: &Attribution,
        index: &Index,
    ) {
        if let Ok(mut trace) = self.capture_lifecycle.lock() {
            trace.registry(step, entry, index);
        }
    }
    #[cfg(test)]
    fn print_capture_lifecycle(&self, entries: &[Attribution], infos: &[Value]) {
        if let (Ok(index), Ok(mut trace)) = (self.index.lock(), self.capture_lifecycle.lock()) {
            for entry in entries.iter().filter(|entry| {
                !infos.iter().any(|info| {
                    info.get("targetId").and_then(Value::as_str) == Some(entry.target.as_str())
                        && info.get("browserContextId").and_then(Value::as_str)
                            == Some(self.targets.context_id.as_str())
                })
            }) {
                trace.registry(CaptureLifecycleStep::MissingInventory, entry, &index);
            }
            eprintln!(
                "state.capture lifecycle native_discovery=not-enabled destroyed_absence=inconclusive dropped={} ids_exhausted={} rows={:?}",
                trace.dropped, trace.ids_exhausted, trace.rows
            );
        }
    }
    // This extra read is test-only evidence after capture has already refused.
    // Never reconcile/adopt inventory, renew the operation, or drain events here.
    #[cfg(test)]
    async fn diagnose_missing_capture_target(
        &self,
        entries: &[Attribution],
        infos: &[Value],
        watermark: &BoundedEventWatermark,
        op: &OperationLease,
    ) -> Option<CaptureMissingTargetDiagnostic> {
        let missing = entries.iter().filter(|entry| {
            !infos.iter().any(|info| {
                info.get("targetId").and_then(Value::as_str) == Some(entry.target.as_str())
                    && info.get("browserContextId").and_then(Value::as_str)
                        == Some(self.targets.context_id.as_str())
            })
        });
        let missing_count = missing.clone().count();
        // Stable selection of one already-retained pair, not arbitrary discovery.
        let entry = missing.min_by(|left, right| {
            (&left.target, &left.session).cmp(&(&right.target, &right.session))
        })?;
        let (target, session, dropped, ids_exhausted) = {
            let mut trace = match self.capture_lifecycle.lock() {
                Ok(trace) => trace,
                Err(poisoned) => {
                    let mut trace = poisoned.into_inner();
                    trace.dropped = trace.dropped.saturating_add(1);
                    trace
                }
            };
            // Reuse lifecycle ordinals only; missing evidence is not an identity.
            let target = trace.targets.get(&entry.target).copied();
            let session = trace.sessions.get(&entry.session).copied();
            if target.is_none() || session.is_none() {
                trace.dropped = trace.dropped.saturating_add(1);
            }
            (target, session, trace.dropped, trace.ids_exhausted)
        };
        let before = self.capture_lookup_snapshot(entry, watermark);
        let lookup = if *op.cancellation.borrow() != CancelSignal::None {
            CaptureTargetLookup::Cancelled
        } else if Instant::now() >= op.deadline {
            CaptureTargetLookup::Deadline
        } else if op.generation != self.generation
            || before.sealed
            || before.coordinator_failed != Some(false)
        {
            CaptureTargetLookup::SkippedCoordinatorUnavailable
        } else if before.binding != Some(CaptureRegistryBinding::MatchingIdsTenureUnknown) {
            CaptureTargetLookup::SkippedBindingUnavailable
        } else {
            // Preserve the existing command/lease path. BrowserFailure combines
            // backend refusal and transport failure; do not parse arbitrary text
            // into a stronger claim that the target no longer exists.
            match self
                .command(
                    op,
                    None,
                    "Target.getTargetInfo",
                    json!({"targetId":entry.target}),
                )
                .await
            {
                Ok(value) => capture_target_lookup(&value, entry, &self.targets.context_id),
                Err(ProtocolError::Cancelled) => CaptureTargetLookup::Cancelled,
                Err(ProtocolError::DeadlineExceeded) => CaptureTargetLookup::Deadline,
                Err(_) => CaptureTargetLookup::CommandFailure,
            }
        };
        let after = self.capture_lookup_snapshot(entry, watermark);
        Some(CaptureMissingTargetDiagnostic {
            target,
            session,
            missing_count,
            truncated: missing_count > 1,
            dropped,
            ids_exhausted,
            lookup,
            before,
            after,
        })
    }
    #[cfg(test)]
    fn capture_lookup_snapshot(
        &self,
        entry: &Attribution,
        watermark: &BoundedEventWatermark,
    ) -> CaptureLookupSnapshot {
        let index = self.index.lock().ok();
        let received = watermark.received().ok();
        let applied = index.as_ref().map(|index| index.applied_watermark);
        CaptureLookupSnapshot {
            received,
            applied,
            event_state: match (received, applied) {
                (Some(received), Some(applied)) if received > applied => {
                    CaptureLookupEventState::ReceivedPending
                }
                (Some(_), Some(_)) => CaptureLookupEventState::NoReceivedPendingUnreceivedUnknown,
                _ => CaptureLookupEventState::Unavailable,
            },
            application_epoch: index.as_ref().map(|index| index.application_epoch),
            binding: index
                .as_ref()
                .map(|index| capture_registry_binding(entry, index)),
            pending_enrollment: index
                .as_ref()
                .map(|index| !index.pending_enrollment.is_empty()),
            retirement_pending: index
                .as_ref()
                .map(|index| !index.retiring_pages.is_empty() || index.borrowed_restart.is_some()),
            retired_binding: index.as_ref().map(|index| {
                index.retired_page_sessions.contains(&entry.session)
                    || index.retired_observer_sessions.contains(&entry.session)
                    || index.retired_observer_targets.contains(&entry.target)
                    || index.borrowed_retired_targets.contains(&entry.target)
            }),
            reconciled: index.as_ref().map(|index| index.reconciled),
            coordinator_failed: index.as_ref().map(|index| index.failure.is_some()),
            sealed: self.sealed.load(Ordering::Acquire),
        }
    }
    #[cfg(test)]
    fn print_missing_capture_target(&self, diagnostic: CaptureMissingTargetDiagnostic) {
        let mut trace = match self.capture_lifecycle.lock() {
            Ok(trace) => trace,
            Err(poisoned) => {
                let mut trace = poisoned.into_inner();
                trace.dropped = trace.dropped.saturating_add(1);
                trace
            }
        };
        trace.record_missing_lookup(diagnostic, &mut std::io::stderr().lock());
    }
    /// Capture before registry retirement. Repeated checks use the original
    /// immutable binding, never a replacement target or current gate epoch.
    pub(crate) fn terminal_connection_proof(&self) -> Result<NativeTerminalProof, ProtocolError> {
        let mut slot = self
            .terminal_proof
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?;
        // A cached identity is sufficient for local cleanup consumers already
        // holding it, not permission to retrieve reconnect authority after a
        // retained enrollment task has failed during terminal drainage.
        if let Some(error) = &self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .failure
        {
            return Err(error.clone());
        }
        if let Some(proof) = slot.as_ref() {
            proof.check_network(&self.network)?;
            return Ok(proof.clone());
        }
        if !*self.client.remote_connection_closed().borrow() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let root = self
            .active_root
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .clone();
        let index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if let Some(error) = &index.failure {
            return Err(error.clone());
        }
        let active = index
            .sessions
            .get(&root)
            .filter(|entry| entry.application && entry.root == entry.session && entry.resumed)
            .ok_or(ProtocolError::StaleScope)?;
        let proof = NativeTerminalProof {
            client: self.client.clone(),
            targets: self.targets.clone(),
            network: Arc::downgrade(&self.network),
            generation: self.generation,
            identity_scope: self.targets.identity_scope.clone(),
            active_target: active.target.clone(),
        };
        *slot = Some(proof.clone());
        Ok(proof)
    }
    fn capture_final_local_eof(&self, received: u64) -> Result<FinalLocalEofProof, ProtocolError> {
        if !matches!(&self.ownership, ScopeOwnership::BorrowedTargets(_)) {
            return Err(ProtocolError::PolicyDenied);
        }
        let index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if let Some(error) = &index.failure {
            return Err(error.clone());
        }
        if !index.reconciled
            || !index.sessions.is_empty()
            || !index.realm_pending.is_empty()
            || index.realm_tickets != 0
            || index.borrowed_blank.is_some()
            || !restart_retirements_settled(&index, received)
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let proof = FinalLocalEofProof {
            client: self.client.clone(),
            targets: self.targets.clone(),
            network: Arc::downgrade(&self.network),
            generation: self.generation,
            identity_scope: self.targets.identity_scope.clone(),
            received,
        };
        proof.check_network(&self.network)?;
        Ok(proof)
    }
    /// Available only after the retained EOF supervisor joined producers and
    /// retired callback authority. It is never reconnect or containment proof.
    pub(crate) fn final_local_connection_proof(&self) -> Result<FinalLocalEofProof, ProtocolError> {
        let proof = self
            .final_local_proof
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?
            .clone()
            .ok_or(ProtocolError::CleanupFailed)?;
        self.capture_final_local_eof(proof.received)?;
        proof.check_targets(&self.targets)?;
        proof.check_network(&self.network)?;
        Ok(proof)
    }
    /// Dispatch holds this only around context configuration mutations. Never
    /// hold it for navigation, evaluate, or a JavaScript callback decision.
    pub fn config_gate(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.config_gate.clone()
    }
    fn operation(&self) -> OperationLease {
        OperationLease {
            is_callback: false,
            generation: self.generation,
            sequence: 0,
            deadline: Instant::now() + INITIALIZE_TIMEOUT,
            cancellation: self.stop.subscribe(),
        }
    }
    fn check(&self) -> Result<(), ProtocolError> {
        if matches!(&self.ownership,ScopeOwnership::TrackedTargets(allowed) | ScopeOwnership::BorrowedTargets(allowed) if allowed.len()>MAX_SESSIONS || allowed.iter().any(|id|valid_id(id).is_err()))
        {
            return Err(ProtocolError::InvalidArguments);
        }
        if matches!(&self.ownership, ScopeOwnership::IsolatedContext)
            && self.targets.context_id.is_empty()
        {
            return Err(ProtocolError::PolicyDenied);
        }
        if let Some(error) = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .failure
            .clone()
        {
            return Err(error);
        }
        if self.sealed.load(Ordering::Acquire) {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    fn poison(&self, error: ProtocolError) {
        if let Ok(mut index) = self.index.lock() {
            self.revoke_eval_authority();
            index.failure.get_or_insert(error);
            for entry in index.sessions.values() {
                let _ = self.page.network_incomplete(&entry.root);
            }
        }
        self.targets.seal();
        self.sealed.store(true, Ordering::Release);
        self.stop.send_replace(CancelSignal::SessionClosed);
        self.changed.notify_waiters();
    }
    fn lease(&self, entry: &Attribution) -> Result<BrowserExecutionLease, ProtocolError> {
        let permit = self
            .check()
            .and_then(|()| {
                // Retain exact registry/epoch authority through publication. Never
                // fall back to a later scope after this access has been retired.
                match &self.initialization {
                    Some(access) => access.enter(&self.targets),
                    None => self.gate.enter(false),
                }
            })
            .map_err(|error| self.admission_error(error))?;
        Ok(BrowserExecutionLease {
            client: self.client.clone(),
            page_session_id: entry.session.clone(),
            target_id: entry.target.clone(),
            identity_scope: self.targets.identity_scope.clone(),
            targets: self.targets.clone(),
            permit,
        })
    }
    /// Only failed admission may become retirement cancellation. Once a permit
    /// exists, browser/cleanup failures keep their original classification.
    fn admission_error(&self, error: ProtocolError) -> ProtocolError {
        if matches!(
            error,
            ProtocolError::StaleScope | ProtocolError::ScopeUnavailable
        ) {
            if let Ok(index) = self.index.lock() {
                if let Some(failure) = &index.failure {
                    return failure.clone();
                }
                if self.sealed.load(Ordering::Acquire) {
                    return ProtocolError::Cancelled;
                }
            }
        }
        error
    }
    fn register_pending_event(&self, event: &CdpEvent) -> Result<Option<String>, ProtocolError> {
        let mut index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let retired_parent = event.session_id.as_ref().is_some_and(|parent| {
            index.retired_page_sessions.contains(parent)
                || index.retired_observer_sessions.contains(parent)
        });
        let observer_parent = event.session_id.as_ref().is_some_and(|parent| {
            index
                .sessions
                .get(parent)
                .is_some_and(|entry| entry.observation_only)
        });
        if event
            .params
            .pointer("/targetInfo/browserContextId")
            .and_then(Value::as_str)
            != Some(self.targets.context_id.as_str())
            && !observer_parent
            && !retired_parent
        {
            return Ok(None);
        }
        let session = field(&event.params, "sessionId")?.to_owned();
        if index.pending_enrollment.len() >= MAX_TASKS {
            return Err(ProtocolError::CapacityExceeded);
        }
        if index.pending_enrollment.contains(&session) {
            return Err(ProtocolError::StaleScope);
        }
        if retired_parent {
            if index.retired_page_sessions.len() >= MAX_FRAMES
                && !index.retired_page_sessions.contains(&session)
            {
                return Err(ProtocolError::CapacityExceeded);
            }
            // Publish cleanup-only ancestry before spawning attached(). A burst
            // grandchild can arrive before its parent's task ever polls. This
            // tombstone grants no context, registration or adoption authority.
            index.retired_page_sessions.insert(session.clone());
        }
        index.pending_enrollment.insert(session.clone());
        Ok(Some(session))
    }
    fn mark_event_applied(&self, sequence: u64) -> Result<(), ProtocolError> {
        let mut index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if sequence
            != index
                .applied_watermark
                .checked_add(1)
                .ok_or(ProtocolError::IdentifierExhausted)?
        {
            return Err(ProtocolError::StaleScope);
        }
        index.applied_watermark = sequence;
        Ok(())
    }
    /// Always index -> ledger, never called by ledger.submit.
    fn revoke_eval_authority(&self) {
        if let Some(ledger) = self.client.debt_ledger() {
            ledger.invalidate_eval_authority();
        }
    }
    pub(crate) fn capture_eval_authority(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<super::client_debt::EvalAuthorityStamp, ProtocolError> {
        self.check_restart_operation(op)?;
        if op.is_callback
            || !Arc::ptr_eq(&page.client, &self.client)
            || !Arc::ptr_eq(&page.targets, &self.targets)
            || page.identity_scope != self.targets.identity_scope
        {
            return Err(ProtocolError::StaleScope);
        }
        page.permit.check()?;
        let ledger = self
            .client
            .debt_ledger()
            .ok_or(ProtocolError::ScopeUnavailable)?;
        self.targets.require_eval_owner(&ledger)?;
        let watermark = self.realm_watermark()?;
        let index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        // Observe the ledger before reading the index/watermark: the reader
        // fences observation before publishing received, with no lock spanning it.
        let revision = ledger.capture_eval_revision(&page.page_session_id, &page.target_id)?;
        self.realm_snapshot_healthy(&index, &watermark)?;
        if !index.pending_enrollment.is_empty()
            || index
                .sessions
                .values()
                .any(|entry| (entry.application || entry.observation_only) && !entry.resumed)
            || !restart_retirements_settled(
                &index,
                watermark
                    .received()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?,
            )
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let entry = index
            .sessions
            .get(&page.page_session_id)
            .ok_or(ProtocolError::StaleScope)?;
        if !entry.application
            || entry.observation_only
            || !entry.resumed
            || entry.target != page.target_id
            || entry.kind != "page"
            || entry.root != entry.session
            || *self
                .active_root
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                != entry.session
        {
            return Err(ProtocolError::StaleScope);
        }
        let mut frames = index
            .frames
            .iter()
            .filter(|(_, frame)| frame.session == entry.session && frame.parent.is_none());
        let (frame, owner) = frames.next().ok_or(ProtocolError::InvalidFrame)?;
        if frames.next().is_some() {
            return Err(ProtocolError::InvalidFrame);
        }
        let loader = owner.loader.clone().ok_or(ProtocolError::InvalidFrame)?;
        let attachment = self.targets.owned_target(&page.target_id)?;
        if attachment.session_id != page.page_session_id
            || !attachment.capture_ready()
            || ledger.capture_eval_revision(&page.page_session_id, &page.target_id)? != revision
        {
            return Err(ProtocolError::StaleScope);
        }
        self.realm_snapshot_healthy(&index, &watermark)?;
        Ok(super::client_debt::EvalAuthorityStamp {
            revision,
            target: entry.target.clone(),
            session: entry.session.clone(),
            frame: frame.clone(),
            loader,
        })
    }
    fn bump_application_epoch(&self) -> Result<(), ProtocolError> {
        let mut index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        self.revoke_eval_authority();
        index.application_epoch = index
            .application_epoch
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        Ok(())
    }
    async fn drain_capture_watermark(
        &self,
        watermark: &BoundedEventWatermark,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        bounded(op, async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                self.check()?;
                {
                    let index = self
                        .index
                        .lock()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?;
                    let received = watermark
                        .received()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?;
                    if capture_admission_ready(&index, received) {
                        return Ok(());
                    }
                }
                #[cfg(test)]
                if let Some(waiting) = self
                    .capture_test_gates
                    .lock()
                    .unwrap()
                    .remove(&CaptureTestPoint::DrainWaiting)
                {
                    waiting.entered.add_permits(1);
                }
                changed.await;
            }
        })
        .await
    }
    fn check_capture_snapshot_locked(
        &self,
        index: &Index,
        watermark: &BoundedEventWatermark,
        snapshot: &CaptureSnapshot,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        if op.generation != self.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if *op.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= op.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        if let Some(error) = &index.failure {
            return Err(error.clone());
        }
        let received = watermark
            .received()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if self.sealed.load(Ordering::Acquire)
            || !index.reconciled
            || !capture_admission_ready(index, received)
            || index.application_epoch != snapshot.epoch
            || index.borrowed_restart.is_some()
            || index
                .sessions
                .values()
                .filter(|entry| entry.application || entry.observation_only)
                .count()
                != snapshot.entries.len()
        {
            return Err(ProtocolError::StaleScope);
        }
        for entry in &snapshot.entries {
            if !entry.resumed
                || entry.application == entry.observation_only
                || index.sessions.get(&entry.session) != Some(entry)
                || index.retiring_pages.iter().any(|(target, session)| {
                    target == &entry.target || session == &entry.session || session == &entry.root
                })
                || index.retired_page_sessions.contains(&entry.session)
                || index.retired_page_sessions.contains(&entry.root)
                || index.retired_observer_sessions.contains(&entry.session)
                || index.retired_observer_sessions.contains(&entry.root)
                || index.retired_observer_targets.contains(&entry.target)
                || index.borrowed_retired_targets.contains(&entry.target)
            {
                return Err(ProtocolError::StaleScope);
            }
        }
        // The caller holds index. Keep the established index -> targets order;
        // no mutex survives a protocol read, drain, or other await.
        self.targets.check_capture_tickets(&snapshot.owned)
    }
    fn check_capture_snapshot(
        &self,
        watermark: &BoundedEventWatermark,
        snapshot: &CaptureSnapshot,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        let index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        self.check_capture_snapshot_locked(&index, watermark, snapshot, op)
    }
    fn capture_snapshot(
        &self,
        watermark: &BoundedEventWatermark,
        op: &OperationLease,
    ) -> Result<CaptureSnapshot, ProtocolError> {
        let index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if !index.reconciled {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let mut entries = index
            .sessions
            .values()
            .filter(|entry| entry.application || entry.observation_only)
            .cloned()
            .collect::<Vec<_>>();
        if entries.len() > MAX_SESSIONS {
            return Err(ProtocolError::CapacityExceeded);
        }
        entries.sort_by(|a, b| (&a.target, &a.session).cmp(&(&b.target, &b.session)));
        let mut targets = HashSet::new();
        let mut sessions = HashSet::new();
        for entry in &entries {
            for value in [&entry.target, &entry.session, &entry.root, &entry.kind] {
                valid_id(value)?;
            }
            if let Some(parent) = &entry.parent {
                valid_id(parent)?;
            }
            if !targets.insert(&entry.target) || !sessions.insert(&entry.session) {
                return Err(ProtocolError::StaleScope);
            }
        }
        let owned_ids = entries
            .iter()
            .filter(|entry| entry.application)
            .map(|entry| entry.target.as_str())
            .collect::<Vec<_>>();
        let owned = self.targets.capture_application_tickets(&owned_ids)?;
        for ticket in &owned {
            if !entries.iter().any(|entry| {
                entry.application
                    && !entry.observation_only
                    && entry.target == ticket.target_id
                    && entry.session == ticket.session_id
                    && entry.kind == ticket.kind
                    && entry.resumed
            }) {
                return Err(ProtocolError::StaleScope);
            }
        }
        let snapshot = CaptureSnapshot {
            epoch: index.application_epoch,
            entries,
            owned,
        };
        self.check_capture_snapshot_locked(&index, watermark, &snapshot, op)?;
        Ok(snapshot)
    }
    async fn fence_capture_snapshot(
        &self,
        watermark: &BoundedEventWatermark,
        snapshot: &CaptureSnapshot,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.drain_capture_watermark(watermark, op).await?;
        #[cfg(test)]
        self.pause_capture_at(CaptureTestPoint::AfterFenceDrain, op)
            .await?;
        // received() is sampled again under index, not reused from the drain.
        // If admission advanced in between, conservatively refuse this capture.
        self.check_capture_snapshot(watermark, snapshot, op)
    }
    async fn fence_capture_result<T>(
        &self,
        watermark: &BoundedEventWatermark,
        snapshot: &CaptureSnapshot,
        op: &OperationLease,
        result: Result<T, ProtocolError>,
    ) -> Result<T, ProtocolError> {
        // A session retirement may settle its raw waiter before the supervisor
        // applies the event. Retain both success and failure until the ORIGINAL
        // capture authority has caught up; never retry or snapshot a replacement.
        let drained = self.drain_capture_watermark(watermark, op).await;
        let index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        // Poison stores its cause before cancelling the owner. Do not let the
        // drain's cancellation precheck hide that exact coordinator failure.
        if let Some(error) = &index.failure {
            return Err(error.clone());
        }
        drained?;
        self.check_capture_snapshot_locked(&index, watermark, snapshot, op)?;
        result
    }
    #[cfg(test)]
    async fn pause_capture_at(
        &self,
        point: CaptureTestPoint,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        let gate = self.capture_test_gates.lock().unwrap().remove(&point);
        if let Some(gate) = gate {
            gate.entered.add_permits(1);
            bounded(op, async {
                gate.release
                    .acquire()
                    .await
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .forget();
                Ok(())
            })
            .await?;
        }
        Ok(())
    }
    pub async fn attest_capture(
        self: &Arc<Self>,
        op: &OperationLease,
    ) -> Result<EnrollmentAttestation, ProtocolError> {
        self.check_restart_operation(op)?;
        if matches!(self.ownership, ScopeOwnership::TrackedTargets(_)) {
            return Err(ProtocolError::UnsupportedCapability);
        }
        let watermark = self
            .event_watermark
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .clone()
            .ok_or(ProtocolError::ScopeUnavailable)?;
        self.drain_capture_watermark(&watermark, op).await?;
        #[cfg(test)]
        self.pause_capture_at(CaptureTestPoint::AfterInitialDrain, op)
            .await?;
        let snapshot = self.capture_snapshot(&watermark, op)?;
        let entries = &snapshot.entries;
        // Include all native kinds; an omitted browser/tab default filter cannot
        // prove absence. Enumeration grants no ownership and is still mandatory.
        let inventory = self
            .command(op, None, "Target.getTargets", json!({"filter":[{}]}))
            .await;
        let inventory = self
            .fence_capture_result(&watermark, &snapshot, op, inventory)
            .await?;
        let infos = inventory
            .get("targetInfos")
            .and_then(Value::as_array)
            .ok_or(ProtocolError::InvalidFrame)?;
        if infos.len() > 8192 {
            return Err(ProtocolError::CapacityExceeded);
        }
        let mut enumerated = HashMap::new();
        for info in infos {
            let target = field(info, "targetId")?;
            field(info, "type")?;
            if enumerated.insert(target, info).is_some() {
                return Err(ProtocolError::StaleScope);
            }
            if info.get("browserContextId").and_then(Value::as_str)
                != Some(self.targets.context_id.as_str())
                || matches!(
                    info.get("type").and_then(Value::as_str),
                    Some("browser" | "tab")
                )
            {
                continue;
            }
            if matches!(self.ownership, ScopeOwnership::BorrowedTargets(_))
                && !self.authorized(target, None, info.get("openerId").and_then(Value::as_str))?
            {
                if info.get("type").and_then(Value::as_str) == Some("page")
                    && !entries.iter().any(|entry| {
                        entry.target == target && entry.observation_only && entry.resumed
                    })
                {
                    return Err(ProtocolError::ScopeUnavailable);
                }
                continue;
            }
            let owned = self.targets.owned_target(target)?;
            if owned.purpose == Some(TargetPurpose::Application)
                && !entries.iter().any(|entry| entry.target == owned.target_id)
            {
                return Err(ProtocolError::StaleScope);
            }
            if owned.purpose.is_none() {
                return Err(ProtocolError::ScopeUnavailable);
            }
        }
        // Finish checking every contradiction before querying any missing target.
        // Missing observer-only targets are required but never eligible to adopt.
        let mut missing = Vec::new();
        for entry in entries {
            if let Some(info) = enumerated.get(entry.target.as_str()) {
                validate_capture_target_info(entry, info, &self.targets.context_id, false)?;
            } else if entry.application
                && !entry.observation_only
                && snapshot.owned.iter().any(|ticket| {
                    ticket.target_id == entry.target && ticket.session_id == entry.session
                })
            {
                missing.push(entry);
            } else {
                return Err(ProtocolError::StaleScope);
            }
        }
        if !missing.is_empty() {
            #[cfg(test)]
            self.print_capture_lifecycle(entries, infos);
        }
        // The fixed, sorted missing set is a subset of the original <=128 entries.
        // One read per entry, no browser-global retry, URL policy, or new subscriber.
        for entry in missing {
            self.fence_capture_snapshot(&watermark, &snapshot, op)
                .await?;
            #[cfg(test)]
            self.pause_capture_at(CaptureTestPoint::BeforeInfo, op)
                .await?;
            self.check_capture_snapshot(&watermark, &snapshot, op)?;
            let reply = self
                .command(op, Some(&entry.session), "Target.getTargetInfo", json!({}))
                .await;
            #[cfg(test)]
            if reply.is_ok() {
                self.pause_capture_at(CaptureTestPoint::AfterInfoAck, op)
                    .await?;
            }
            let reply = self
                .fence_capture_result(&watermark, &snapshot, op, reply)
                .await?;
            let info = reply.get("targetInfo").ok_or(ProtocolError::InvalidFrame)?;
            validate_capture_target_info(entry, info, &self.targets.context_id, true)?;
            // An ACK is not an event-application fence. Count this entry covered
            // only after the retained live watermark and original tickets agree.
            self.fence_capture_snapshot(&watermark, &snapshot, op)
                .await?;
        }
        let mut frames = Vec::new();
        for entry in entries {
            if !matches!(entry.kind.as_str(), "page" | "iframe") {
                continue;
            }
            self.check_restart_operation(op)?;
            let tree = self
                .command(op, Some(&entry.session), "Page.getFrameTree", json!({}))
                .await;
            let tree = self
                .fence_capture_result(&watermark, &snapshot, op, tree)
                .await?;
            capture_frame_fingerprint(
                &entry.session,
                tree.get("frameTree").ok_or(ProtocolError::InvalidFrame)?,
                0,
                &mut frames,
            )?;
        }
        self.fence_capture_snapshot(&watermark, &snapshot, op)
            .await?;
        #[cfg(test)]
        self.pause_capture_at(CaptureTestPoint::BeforeReturn, op)
            .await?;
        self.check_capture_snapshot(&watermark, &snapshot, op)?;
        self.check_restart_operation(op)?;
        frames.sort();
        Ok(EnrollmentAttestation {
            coordinator: Arc::downgrade(self),
            targets: self.targets.clone(),
            generation: self.generation,
            application_epoch: snapshot.epoch,
            frames,
            watermark,
            snapshot,
        })
    }
    pub async fn verify_capture_attestation(
        self: &Arc<Self>,
        previous: &EnrollmentAttestation,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        if previous.generation != self.generation
            || !Arc::ptr_eq(&previous.targets, &self.targets)
            || !previous
                .coordinator
                .upgrade()
                .is_some_and(|owner| Arc::ptr_eq(&owner, self))
        {
            return Err(ProtocolError::StaleScope);
        }
        self.fence_capture_snapshot(&previous.watermark, &previous.snapshot, op)
            .await?;
        let current = self.attest_capture(op).await;
        #[cfg(test)]
        if current.is_ok() {
            self.pause_capture_at(CaptureTestPoint::AfterFreshAttestation, op)
                .await?;
        }
        let current = self
            .fence_capture_result(&previous.watermark, &previous.snapshot, op, current)
            .await?;
        // Retain and recheck ORIGINAL tickets, even when a replacement has become
        // enumerable and the fresh attestation could prove only its newer tenure.
        self.fence_capture_snapshot(&previous.watermark, &previous.snapshot, op)
            .await?;
        if current.application_epoch != previous.application_epoch
            || current.frames != previous.frames
            || current.snapshot.entries != previous.snapshot.entries
            || current.snapshot.owned.len() != previous.snapshot.owned.len()
            || !current
                .snapshot
                .owned
                .iter()
                .zip(&previous.snapshot.owned)
                .all(|(current, previous)| current.same_attachment(previous))
        {
            return Err(ProtocolError::StaleScope);
        }
        #[cfg(test)]
        self.pause_capture_at(CaptureTestPoint::BeforeVerifyReturn, op)
            .await?;
        self.check_capture_snapshot(&previous.watermark, &previous.snapshot, op)?;
        self.check_restart_operation(op)
    }
    fn check_restart_operation(&self, op: &OperationLease) -> Result<(), ProtocolError> {
        self.check()?;
        if op.generation != self.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if *op.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= op.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(())
    }
    pub(crate) fn validate_restart_owner(
        &self,
        page: &BrowserExecutionLease,
        ui_gate: &Arc<super::client_ui::UiGate>,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        if !matches!(self.ownership, ScopeOwnership::IsolatedContext) {
            return Err(ProtocolError::UnsupportedCapability);
        }
        self.validate_restart_page(page, ui_gate, op)
    }
    fn validate_restart_page(
        &self,
        page: &BrowserExecutionLease,
        ui_gate: &Arc<super::client_ui::UiGate>,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.check_restart_operation(op)?;
        page.permit.check()?;
        if !self.network.uses_ui_gate(ui_gate) {
            return Err(ProtocolError::PolicyDenied);
        }
        if !Arc::ptr_eq(&page.client, &self.client)
            || !Arc::ptr_eq(&page.targets, &self.targets)
            || page.identity_scope != self.targets.identity_scope
        {
            return Err(ProtocolError::StaleScope);
        }
        let index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let entry = index
            .sessions
            .get(&page.page_session_id)
            .ok_or(ProtocolError::StaleReference)?;
        if entry.target != page.target_id
            || entry.kind != "page"
            || entry.root != entry.session
            || !entry.application
            || !entry.resumed
            || *self
                .active_root
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                != entry.session
        {
            return Err(ProtocolError::StaleReference);
        }
        Ok(())
    }
    pub(crate) fn borrowed_restart_permit(
        self: &Arc<Self>,
        page: &BrowserExecutionLease,
        ui_gate: &Arc<super::client_ui::UiGate>,
        op: &OperationLease,
    ) -> Result<BorrowedRestartPermit, ProtocolError> {
        if !matches!(self.ownership, ScopeOwnership::BorrowedTargets(_)) {
            return Err(ProtocolError::UnsupportedCapability);
        }
        if op.is_callback || op.sequence == 0 {
            return Err(ProtocolError::InvalidArguments);
        }
        self.validate_restart_page(page, ui_gate, op)?;
        let mut index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if index.borrowed_restart.is_some() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        index.borrowed_restart_sequence = index
            .borrowed_restart_sequence
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        let nonce = index.borrowed_restart_sequence;
        index.borrowed_restart = Some(nonce);
        Ok(BorrowedRestartPermit {
            owner: self.clone(),
            nonce,
            operation: copy_operation(op),
            creation_started: AtomicBool::new(false),
        })
    }
    fn exact_borrowed_page<'a>(&self, info: &'a Value) -> Result<&'a str, ProtocolError> {
        if !matches!(self.ownership, ScopeOwnership::BorrowedTargets(_))
            || info.get("browserContextId").and_then(Value::as_str)
                != Some(self.targets.context_id.as_str())
            || info.get("type").and_then(Value::as_str) != Some("page")
        {
            return Err(ProtocolError::PolicyDenied);
        }
        field(info, "targetId")
    }
    pub(crate) fn install_restart_session_sink(
        &self,
        sink: &super::client_transport::ClientEventSink,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.check_restart_operation(op)?;
        self.network
            .set_future_session_sink(sink.clone(), &self.targets.identity_scope, op)
    }
    async fn borrowed_blank_matches(&self, target: &str) -> Result<bool, ProtocolError> {
        let state = {
            let index = self
                .index
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if index.borrowed_retired_targets.contains(target) {
                return Ok(false);
            }
            index.borrowed_blank.clone()
        };
        let Some(state) = state else {
            return Ok(false);
        };
        let mut status = state.status.subscribe();
        let mut stop = self.stop.subscribe();
        let op = &state.operation;
        loop {
            if *stop.borrow() != CancelSignal::None {
                return Ok(false);
            }
            let current = status.borrow().clone();
            match current {
                BorrowedBlankStatus::Bound(id) => {
                    let index = self
                        .index
                        .lock()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?;
                    if index.borrowed_retired_targets.contains(target) || index.failure.is_some() {
                        return Ok(false);
                    }
                    let pending = index.borrowed_restart == Some(state.nonce)
                        && index
                            .borrowed_blank
                            .as_ref()
                            .is_some_and(|current| Arc::ptr_eq(current, &state));
                    let admitted = index
                        .sessions
                        .values()
                        .any(|entry| entry.target == target && entry.kind == "page");
                    return Ok(id == target && (pending || admitted));
                }
                BorrowedBlankStatus::Cancelled => return Ok(false),
                BorrowedBlankStatus::Pending => {}
            }
            if bounded(op, async {
                tokio::select! {
                    result=status.changed()=>result.map_err(|_|ProtocolError::ScopeUnavailable),
                    _=stop.changed()=>Err(ProtocolError::Cancelled),
                }
            })
            .await
            .is_err()
            {
                return Ok(false);
            }
        }
    }
    /// Caller retains Application creation reservation until this returns, then
    /// claims its exact created target. Initialization cannot race root choice.
    pub(crate) async fn select_registered_restart_page(
        &self,
        target: &str,
        op: &OperationLease,
    ) -> Result<String, ProtocolError> {
        valid_id(target)?;
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.check_restart_operation(op)?;
            let found = self
                .index
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .sessions
                .values()
                .find(|entry| entry.target == target)
                .cloned();
            if let Some(entry) = found {
                if entry.kind != "page" || entry.root != entry.session || entry.application {
                    return Err(ProtocolError::InvalidArguments);
                }
                self.set_active_root(&entry.session)?;
                return Ok(entry.session);
            }
            bounded(op, async {
                changed.await;
                Ok(())
            })
            .await?;
        }
    }
    pub(crate) async fn wait_restart_page_ready(
        &self,
        target: &str,
        session: &str,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.check_restart_operation(op)?;
            let entry = self
                .index
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .sessions
                .get(session)
                .cloned()
                .ok_or(ProtocolError::StaleReference)?;
            if entry.target != target || entry.kind != "page" || entry.root != session {
                return Err(ProtocolError::StaleReference);
            }
            if entry.resumed
                && (entry.application
                    || (entry.observation_only
                        && self
                            .index
                            .lock()
                            .map_err(|_| ProtocolError::ScopeUnavailable)?
                            .retiring_pages
                            .get(target)
                            .map(String::as_str)
                            == Some(session)))
            {
                return Ok(());
            }
            bounded(op, async {
                changed.await;
                Ok(())
            })
            .await?;
        }
    }
    /// Restart publication joins all observed configuration work, not only the
    /// selected page. No index/routes/registry guard survives an await.
    pub(crate) async fn publish_restart_ready<T>(
        &self,
        replacement: &OwnedTarget,
        op: &OperationLease,
        publish: impl FnOnce() -> Result<T, ProtocolError>,
    ) -> Result<T, ProtocolError> {
        let watermark = self.realm_watermark()?;
        let mut publish = Some(publish);
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let targets_changed = self.targets.changed();
            tokio::pin!(targets_changed);
            targets_changed.as_mut().enable();
            self.check_restart_operation(op)?;
            let result = {
                let index = self
                    .index
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if let Some(error) = &index.failure {
                    return Err(error.clone());
                }
                if self.sealed.load(Ordering::Acquire) || !index.reconciled {
                    return Err(ProtocolError::ScopeUnavailable);
                }
                let entry = index
                    .sessions
                    .get(&replacement.session_id)
                    .ok_or(ProtocolError::StaleReference)?;
                if entry.target != replacement.target_id
                    || entry.kind != "page"
                    || entry.root != entry.session
                    || !entry.application
                    || !entry.resumed
                {
                    return Err(ProtocolError::StaleScope);
                }
                // Unknown incompleteness is not permission to wait indefinitely.
                if index.sessions.values().any(|entry| {
                    (entry.application || entry.observation_only)
                        && !entry.resumed
                        && !index.pending_enrollment.contains(&entry.session)
                }) {
                    return Err(ProtocolError::ScopeUnavailable);
                }
                watermark
                    .with_received(|received| {
                        if index.applied_watermark > received {
                            return Err(ProtocolError::StaleScope);
                        }
                        self.targets.publish_restart_ready(
                            replacement,
                            &index.pending_enrollment,
                            |target| {
                                index.sessions.get(&target.session_id).is_some_and(|entry| {
                                    entry.target == target.target_id && entry.kind == target.kind
                                })
                            },
                            index.applied_watermark == received
                                && index.pending_enrollment.is_empty(),
                            || {
                                if *op.cancellation.borrow() != CancelSignal::None {
                                    return Err(ProtocolError::Cancelled);
                                }
                                if Instant::now() >= op.deadline {
                                    return Err(ProtocolError::DeadlineExceeded);
                                }
                                // index -> reader routes -> targets, through result
                                // publication. No newly admitted event can fall in
                                // the gap between this watermark and this inventory.
                                publish.take().ok_or(ProtocolError::StaleScope)?()
                            },
                        )
                    })
                    .map_err(|_| ProtocolError::ScopeUnavailable)??
            };
            if let Some(result) = result {
                return Ok(result);
            }
            #[cfg(test)]
            if let Some(waiting) = self
                .capture_test_gates
                .lock()
                .unwrap()
                .remove(&CaptureTestPoint::RestartWaiting)
            {
                waiting.entered.add_permits(1);
            }
            let waited = bounded(op, async {
                tokio::select! { _ = changed => {}, _ = targets_changed => {} }
                Ok(())
            })
            .await;
            if let Err(error) = waited {
                // poison() also cancels the coordinator's stop channel. Keep
                // the stored cause instead of returning secondary cancellation.
                self.check()?;
                return Err(error);
            }
        }
    }
    /// Explicit exact-page retirement, never permission to close a worker or
    /// adopted host page. Mark before Target.closeTarget dispatch.
    pub(crate) fn expect_restart_page_retirement(
        &self,
        target: &str,
        session: &str,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.check_restart_operation(op)?;
        if !matches!(self.ownership, ScopeOwnership::IsolatedContext) {
            return Err(ProtocolError::UnsupportedCapability);
        }
        if super::client_settlement_trace::inventory_enabled() {
            super::client_settlement_trace::inventory_snapshot(
                op.generation,
                op.sequence,
                super::client_settlement_trace::InventoryPoint::RestartBegin,
                self.targets.try_inventory_diagnostic(),
            );
        }
        let mut index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let entry = index
            .sessions
            .get(session)
            .ok_or(ProtocolError::StaleReference)?;
        if entry.target != target
            || entry.kind != "page"
            || entry.root != session
            || !entry.application
            || !entry.resumed
        {
            return Err(ProtocolError::StaleReference);
        }
        if index.retiring_pages.len() >= MAX_SESSIONS && !index.retiring_pages.contains_key(target)
        {
            return Err(ProtocolError::CapacityExceeded);
        }
        if index
            .retiring_pages
            .get(target)
            .is_some_and(|old| old != session)
        {
            return Err(ProtocolError::StaleReference);
        }
        index.retiring_pages.insert(target.into(), session.into());
        if super::client_settlement_trace::inventory_enabled() {
            drop(index);
            self.targets.diagnostic_step(
                target,
                (op.generation, op.sequence),
                super::client_settlement_trace::DiagnosticTargetStage::RestartRetiring,
                None,
            );
        }
        Ok(())
    }
    pub(crate) async fn wait_restart_page_detached(
        &self,
        target: &str,
        session: &str,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.check_restart_operation(op)?;
            let detached = {
                let index = self
                    .index
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if index.retiring_pages.get(target).map(String::as_str) != Some(session) {
                    return Err(ProtocolError::StaleReference);
                }
                restart_page_pair_retired(&index, target, session)
            };
            if detached {
                let watermark = self
                    .event_watermark
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .clone()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                self.drain_capture_watermark(&watermark, op).await?;
                self.check_restart_operation(op)?;
                let index = self
                    .index
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if !restart_page_pair_retired(&index, target, session)
                    || !capture_admission_ready(
                        &index,
                        watermark
                            .received()
                            .map_err(|_| ProtocolError::ScopeUnavailable)?,
                    )
                {
                    return Err(ProtocolError::StaleReference);
                }
                return Ok(());
            }
            bounded(op, async {
                changed.await;
                Ok(())
            })
            .await?;
        }
    }
    /// The lifecycle owner holds its resource publication lock. Serialize the
    /// final readiness decision against poison(), which records failure here
    /// before sealing the registry. No already-failed coordinator may publish.
    pub(crate) fn publish_initialized(
        &self,
        authority: &LifecycleInitialization,
    ) -> Result<u64, ProtocolError> {
        let index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if let Some(error) = &index.failure {
            return Err(error.clone());
        }
        if self.sealed.load(Ordering::Acquire)
            || !index.reconciled
            || !index.pending_enrollment.is_empty()
            || index
                .sessions
                .values()
                .any(|entry| (entry.application || entry.observation_only) && !entry.resumed)
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if let Some(watermark) = self
            .event_watermark
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .as_ref()
        {
            if !capture_admission_ready(
                &index,
                watermark
                    .received()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?,
            ) {
                return Err(ProtocolError::ScopeUnavailable);
            }
        } else {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if let Some(debt) = self.client.debt_ledger() {
            debt.publish_initialization(|| self.targets.publish_initialization(authority))
        } else {
            self.targets.publish_initialization(authority)
        }
    }
    fn realm_watermark(&self) -> Result<BoundedEventWatermark, ProtocolError> {
        self.event_watermark
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .clone()
            .ok_or(ProtocolError::ScopeUnavailable)
    }
    fn realm_snapshot_healthy(
        &self,
        index: &Index,
        watermark: &BoundedEventWatermark,
    ) -> Result<(), ProtocolError> {
        if let Some(error) = &index.failure {
            return Err(error.clone());
        }
        if self.sealed.load(Ordering::SeqCst) || !index.reconciled {
            return Err(ProtocolError::StaleScope);
        }
        let received = watermark
            .received()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if index.applied_watermark < received {
            return Err(ProtocolError::ScopeUnavailable);
        }
        self.targets.inventory()?;
        Ok(())
    }
    /// Capture only already-current enrollment. Never wait, flush, or start a
    /// second lifecycle stream to turn uncertain authority into settled input.
    pub(crate) fn capture_settled_input_authority(
        self: &Arc<Self>,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<SettledInputAuthority, ProtocolError> {
        self.check_restart_operation(op)?;
        if op.is_callback {
            return Err(ProtocolError::InvalidArguments);
        }
        let application_epoch = self.settled_input_epoch(page, op.generation)?;
        Ok(SettledInputAuthority {
            owner: self.clone(),
            session: page.page_session_id.clone(),
            target: page.target_id.clone(),
            generation: op.generation,
            sequence: op.sequence,
            deadline: op.deadline,
            cancellation: op.cancellation.clone(),
            application_epoch,
        })
    }
    fn settled_input_epoch(
        &self,
        page: &BrowserExecutionLease,
        generation: u64,
    ) -> Result<u64, ProtocolError> {
        self.check()?;
        page.permit.check()?;
        if generation != self.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if !Arc::ptr_eq(&page.client, &self.client)
            || !Arc::ptr_eq(&page.targets, &self.targets)
            || page.identity_scope != self.targets.identity_scope
            || *self.client.remote_connection_closed().borrow()
        {
            return Err(ProtocolError::StaleScope);
        }
        let watermark = self.realm_watermark()?;
        let index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        self.realm_snapshot_healthy(&index, &watermark)?;
        if !index.pending_enrollment.is_empty()
            || index
                .sessions
                .values()
                .any(|entry| (entry.application || entry.observation_only) && !entry.resumed)
            || !restart_retirements_settled(
                &index,
                watermark
                    .received()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?,
            )
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let entry = index
            .sessions
            .get(&page.page_session_id)
            .ok_or(ProtocolError::StaleReference)?;
        if entry.target != page.target_id
            || entry.kind != "page"
            || entry.root != entry.session
            || !entry.application
            || entry.observation_only
            || !entry.resumed
            || *self
                .active_root
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                != entry.session
        {
            return Err(ProtocolError::StaleReference);
        }
        Ok(index.application_epoch)
    }
    pub(crate) fn reserve_exact_realm(
        self: &Arc<Self>,
        page: &BrowserExecutionLease,
        binding: &super::element::ExactBinding,
        op: &OperationLease,
    ) -> Result<RealmCaptureGuard, ProtocolError> {
        self.check_restart_operation(op)?;
        page.permit.check()?;
        if !Arc::ptr_eq(&page.client, &self.client)
            || !Arc::ptr_eq(&page.targets, &self.targets)
            || page.identity_scope != self.targets.identity_scope
            || binding.page_session != page.page_session_id
        {
            return Err(ProtocolError::StaleScope);
        }
        let mut index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if let Some(error) = &index.failure {
            return Err(error.clone());
        }
        if self.sealed.load(Ordering::SeqCst) || !index.reconciled {
            return Err(ProtocolError::StaleScope);
        }
        if !index.sessions.get(&binding.session).is_some_and(|entry| {
            entry.application && !entry.observation_only && entry.root == page.page_session_id
        }) || !index
            .frames
            .get(&binding.frame)
            .is_some_and(|frame| frame.session == binding.session)
        {
            return Err(ProtocolError::StaleReference);
        }
        if index.realm_pending.len() >= MAX_REALM_HOLDS {
            return Err(ProtocolError::CapacityExceeded);
        }
        index.realm_serial = index
            .realm_serial
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        let nonce = index.realm_serial;
        let tenure = *index
            .realm_sessions
            .entry(binding.session.clone())
            .or_insert(nonce);
        let records = index
            .realms
            .values()
            .filter(|fact| {
                fact.session == binding.session
                    && fact.frame == binding.frame
                    && fact.tenure == tenure
            })
            .cloned()
            .collect();
        index.realm_pending.insert(
            nonce,
            RealmPending {
                binding: binding.clone(),
                tenure,
                records,
            },
        );
        Ok(RealmCaptureGuard {
            owner: self.clone(),
            nonce,
            operation: op.sequence,
        })
    }
    fn realm_event(&self, entry: &Attribution, event: &CdpEvent) -> Result<(), ProtocolError> {
        if !entry.application
            || entry.observation_only
            || !matches!(entry.kind.as_str(), "page" | "iframe")
        {
            return Ok(());
        }
        let mut index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        match event.method.as_str() {
            "Runtime.executionContextCreated" => {
                let context = event
                    .params
                    .get("context")
                    .ok_or(ProtocolError::InvalidFrame)?;
                // Only the native resolver's isolated world grants these tickets.
                if context["name"] != "agent-browser-native-observation" {
                    return Ok(());
                }
                let id = context["id"]
                    .as_i64()
                    .filter(|id| *id > 0)
                    .ok_or(ProtocolError::InvalidFrame)?;
                let unique = field(context, "uniqueId")?.to_owned();
                let frame = field(&context["auxData"], "frameId")?.to_owned();
                let key = (entry.session.clone(), id);
                if index
                    .realms
                    .get(&key)
                    .is_some_and(|fact| fact.unique == unique && fact.frame == frame)
                {
                    return Ok(());
                }
                if index.realms.len() >= MAX_FRAMES {
                    return Err(ProtocolError::CapacityExceeded);
                }
                index.realm_serial = index
                    .realm_serial
                    .checked_add(1)
                    .ok_or(ProtocolError::IdentifierExhausted)?;
                let serial = index.realm_serial;
                let tenure = *index
                    .realm_sessions
                    .entry(entry.session.clone())
                    .or_insert(serial);
                let fact = Arc::new(RealmFact {
                    session: entry.session.clone(),
                    tenure,
                    frame,
                    id,
                    unique,
                    destroyed: AtomicBool::new(false),
                });
                for pending in index.realm_pending.values_mut().filter(|pending| {
                    pending.binding.session == fact.session
                        && pending.binding.frame == fact.frame
                        && pending.tenure == tenure
                }) {
                    if pending.records.len() >= MAX_FRAMES {
                        return Err(ProtocolError::CapacityExceeded);
                    }
                    pending.records.push(fact.clone());
                }
                index.realms.insert(key, fact);
            }
            "Runtime.executionContextDestroyed" => {
                let id = event.params["executionContextId"]
                    .as_i64()
                    .ok_or(ProtocolError::InvalidFrame)?;
                let key = (entry.session.clone(), id);
                if let Some(fact) = index.realms.get(&key) {
                    if event.params["executionContextUniqueId"].as_str()
                        != Some(fact.unique.as_str())
                    {
                        return Err(ProtocolError::InvalidFrame);
                    }
                    fact.destroyed.store(true, Ordering::SeqCst);
                    index.realms.remove(&key);
                }
            }
            "Runtime.executionContextsCleared" => {
                index.realms.retain(|(session, _), fact| {
                    if session == &entry.session {
                        fact.destroyed.store(true, Ordering::SeqCst);
                        false
                    } else {
                        true
                    }
                });
            }
            _ => {}
        }
        Ok(())
    }
    pub(crate) async fn flush_app_events(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.check_restart_operation(op)?;
        page.permit.check()?;
        if !Arc::ptr_eq(&page.client, &self.client)
            || !Arc::ptr_eq(&page.targets, &self.targets)
            || page.identity_scope != self.targets.identity_scope
        {
            return Err(ProtocolError::StaleScope);
        }
        let watermark = self
            .event_watermark
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .clone()
            .ok_or(ProtocolError::ScopeUnavailable)?;
        self.drain_capture_watermark(&watermark, op).await?;
        page.permit.check()?;
        self.check_restart_operation(op)
    }
    fn app_navigation(
        &self,
        entry: &Attribution,
        event: &CdpEvent,
    ) -> Result<Option<(AppNavigationKind, Option<String>)>, ProtocolError> {
        let frame_id = match event.method.as_str() {
            "Page.frameNavigated" => event
                .params
                .get("frame")
                .and_then(|frame| frame.get("id"))
                .and_then(Value::as_str),
            "Page.navigatedWithinDocument" => event.params.get("frameId").and_then(Value::as_str),
            _ => return Ok(None),
        }
        .ok_or(ProtocolError::InvalidFrame)?;
        let mut index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let Some(frame) = index.frames.get(frame_id).cloned() else {
            return Ok(None);
        };
        if frame.session != entry.session {
            return Ok(None);
        }
        if entry.kind == "iframe" || frame.parent.is_some() {
            return Ok(Some((AppNavigationKind::Frame, frame.name)));
        }
        if entry.kind != "page" || entry.root != entry.session {
            return Ok(None);
        }
        let active = self
            .active_root
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if *active == entry.session {
            return Ok(Some((AppNavigationKind::Main, None)));
        }
        let url = event
            .params
            .get("frame")
            .and_then(|frame| frame.get("url"))
            .or_else(|| event.params.get("url"))
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidFrame)?;
        if !index.popup_opened.contains(&entry.session) {
            if url.is_empty() || url == "about:blank" {
                return Ok(None);
            }
            if index.popup_opened.len() >= MAX_SESSIONS {
                return Err(ProtocolError::CapacityExceeded);
            }
            index.popup_opened.insert(entry.session.clone());
            return Ok(Some((AppNavigationKind::Popup, None)));
        }
        Ok(Some((AppNavigationKind::PopupNavigation, None)))
    }
    pub fn set_active_root(&self, session: &str) -> Result<(), ProtocolError> {
        self.check()?;
        let index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let entry = index
            .sessions
            .get(session)
            .ok_or(ProtocolError::StaleReference)?;
        if entry.root != session || entry.kind != "page" {
            return Err(ProtocolError::InvalidArguments);
        }
        self.revoke_eval_authority();
        *self
            .active_root
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)? = session.into();
        self.network.set_active_root(session)
    }
    /// The owner passes its exact already-attached blank-page session. No second
    /// Target.attachToTarget is issued. This alone does NOT establish readiness.
    pub async fn enroll_existing(
        self: &Arc<Self>,
        target: &str,
        session: &str,
        kind: &str,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        if !self.authorized(target, None, None)? {
            return Err(ProtocolError::PolicyDenied);
        }
        self.ensure_supervisor().await?;
        #[cfg(test)]
        self.trace_capture_admission(CaptureLifecycleStep::EnrollingExisting, target, session);
        let entry = self
            .register(&self.targets.context_id, target, session, kind, None)?
            .ok_or(ProtocolError::InvalidArguments)?;
        self.diagnostic_registration(
            &entry,
            super::client_settlement_trace::DiagnosticTargetOrigin::InitialDiscovery,
            op.sequence,
        );
        let result = self.initialize(entry, op).await;
        if let Err(error) = &result {
            self.poison(error.clone());
        }
        result
    }
    fn diagnostic_registration(
        &self,
        entry: &Attribution,
        origin: super::client_settlement_trace::DiagnosticTargetOrigin,
        sequence: u64,
    ) {
        if !super::client_settlement_trace::inventory_enabled() {
            return;
        }
        let Ok(index) = self.index.try_lock() else {
            super::client_settlement_trace::target_observation_lost(self.generation, sequence);
            return;
        };
        let parent = entry
            .parent
            .as_ref()
            .and_then(|id| index.sessions.get(id))
            .map(|e| e.target.clone());
        let root = index.sessions.get(&entry.root).map(|e| e.target.clone());
        drop(index);
        self.targets.diagnostic_register(
            &entry.target,
            parent.as_deref(),
            root.as_deref(),
            origin,
            (self.generation, sequence),
        );
    }
    fn register(
        &self,
        context: &str,
        target: &str,
        session: &str,
        kind: &str,
        parent: Option<&str>,
    ) -> Result<Option<Attribution>, ProtocolError> {
        if context != self.targets.context_id {
            return Ok(None);
        }
        // This admission check precedes all owned registration and CDP work.
        // Explicit retirement cancels new owned work, not foreign detach cleanup.
        self.check().map_err(|error| self.admission_error(error))?;
        for value in [target, session, kind] {
            valid_id(value)?;
        }
        let mut index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if index.borrowed_retired_targets.contains(target) {
            return Ok(None);
        }
        if let Some(existing) = index.sessions.get(session) {
            return if existing.target == target {
                Ok(None)
            } else {
                Err(ProtocolError::StaleScope)
            };
        }
        if index.sessions.values().any(|entry| entry.target == target) {
            return Ok(None);
        }
        if index.sessions.len() >= MAX_SESSIONS {
            return Err(ProtocolError::CapacityExceeded);
        }
        if let Some(debt) = self.client.debt_ledger() {
            // Establish exact owned tenure before any domain enable can emit
            // realm events. Reader bookkeeping never adopts unknown sessions.
            debt.bind_session(context, target, session)?;
        }
        let root = if kind == "page" {
            session.to_owned()
        } else {
            match parent {
                Some(id) => index
                    .sessions
                    .get(id)
                    .ok_or(ProtocolError::StaleReference)?
                    .root
                    .clone(),
                None if kind != "iframe" => session.to_owned(),
                None => return Err(ProtocolError::StaleReference),
            }
        };
        self.targets
            .attached(context, target.into(), session.into(), kind.into())?;
        let entry = Attribution {
            target: target.into(),
            session: session.into(),
            parent: parent.map(str::to_owned),
            root,
            kind: kind.into(),
            application: false,
            observation_only: false,
            observer_paused: false,
            resumed: false,
        };
        self.revoke_eval_authority();
        index.sessions.insert(session.into(), entry.clone());
        #[cfg(test)]
        self.trace_capture_registry(CaptureLifecycleStep::Registered, &entry, &index);
        if kind == "iframe" {
            if index.frames.len() >= MAX_FRAMES && !index.frames.contains_key(target) {
                return Err(ProtocolError::CapacityExceeded);
            }
            let parent_frame = index
                .frames
                .get(target)
                .and_then(|frame| frame.parent.clone());
            index.frames.insert(
                target.into(),
                FrameOwner {
                    loader: None,
                    name: None,
                    session: session.into(),
                    parent: parent_frame,
                },
            );
        }
        self.changed.notify_waiters();
        Ok(Some(entry))
    }
    async fn initialize(
        &self,
        entry: Attribution,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.initialize_observed(entry, op, None).await
    }
    async fn initialize_observed(
        &self,
        entry: Attribution,
        op: &OperationLease,
        admission: Option<&ServiceWorkerAdmission>,
    ) -> Result<(), ProtocolError> {
        let result = self.initialize_inner(entry.clone(), op, admission).await;
        let Err(error) = result else {
            return Ok(());
        };
        self.targets.diagnostic_step(
            &entry.target,
            (op.generation, op.sequence),
            super::client_settlement_trace::DiagnosticTargetStage::ConfigureFailed,
            Some(error.clone()),
        );
        if !matches!(
            error,
            ProtocolError::BrowserFailure | ProtocolError::StaleReference
        ) {
            return Err(error);
        }
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let index = self
                    .index
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if let Some(failure) = &index.failure {
                    return Err(failure.clone());
                }
                if !index
                    .retiring_pages
                    .values()
                    .any(|root| root == &entry.root)
                {
                    return Err(error);
                }
                if index.retired_page_sessions.contains(&entry.root)
                    && !index.sessions.contains_key(&entry.session)
                {
                    return Ok(());
                }
            }
            // A close attempt alone is not proof. Only an observed detach of
            // the exact marked root can retire this expected initialization error.
            if bounded(op, async {
                changed.await;
                Ok(())
            })
            .await
            .is_err()
            {
                return Err(error);
            }
        }
    }
    async fn initialize_inner(
        &self,
        mut entry: Attribution,
        op: &OperationLease,
        admission: Option<&ServiceWorkerAdmission>,
    ) -> Result<(), ProtocolError> {
        self.targets.diagnostic_step(
            &entry.target,
            (op.generation, op.sequence),
            super::client_settlement_trace::DiagnosticTargetStage::ConfigureStarted,
            None,
        );
        let purpose = ServiceWorkerAdmission::observe(
            admission,
            WorkerAdmissionStep::Purpose,
            bounded(op, self.targets.purpose(&entry.target)),
        )
        .await?;
        if purpose == TargetPurpose::StateBootstrap {
            return Ok(());
        }
        let lease = self.lease(&entry)?;
        let _config = ServiceWorkerAdmission::observe(
            admission,
            WorkerAdmissionStep::ConfigGate,
            bounded(op, async { Ok(self.config_gate.lock().await) }),
        )
        .await?;
        self.check()?;
        if self.config.block_service_workers {
            self.page.ensure_service_worker_policy(&lease, op)?;
        }
        entry.application = true;
        {
            let mut index = self
                .index
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            let current = index
                .sessions
                .get_mut(&entry.session)
                .ok_or(ProtocolError::StaleReference)?;
            self.revoke_eval_authority();
            current.application = true;
            index.application_epoch = index
                .application_epoch
                .checked_add(1)
                .ok_or(ProtocolError::IdentifierExhausted)?;
        }
        // Register before Network.enable; event accounting must see the first
        // request, including a request emitted during configuration itself.
        self.page
            .register_network_session(&entry.root, &entry.session)?;
        let active = *self
            .active_root
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            == entry.root;
        if entry.kind == "service_worker" {
            self.network
                .prepare_service_worker_session(
                    ApplicationSession {
                        session_id: entry.session.clone(),
                        root_page_session: entry.root.clone(),
                        active_page: active,
                    },
                    op,
                    admission,
                )
                .await?;
            // Browser-side controls and descendant attachment are installed
            // before startup. Renderer-domain replies may depend on the
            // browser-side resume callback, so they form one retained batch.
            self.command(
                op,
                Some(&entry.session),
                "Target.setAutoAttach",
                autoattach(true),
            )
            .await?;
            let permit = bounded(
                op,
                self.targets
                    .service_worker_startup_permit(&entry.target, &entry.session),
            )
            .await?;
            // Fetch policy is installed and this exact attachment owns startup.
            // Its main-script request must pass the normal route/auth handlers
            // before Chromium can create the renderer that acknowledges domains.
            // This opens only network callbacks, not target readiness or capture.
            self.network.configuration_committed(&entry.session, op)?;
            bounded(
                op,
                self.network
                    .initialize_service_worker_observation(&entry.session, op),
            )
            .await?;
            lease.permit.check()?;
            permit.complete()?;
        } else {
            self.network
                .configure_session_observed(
                    ApplicationSession {
                        session_id: entry.session.clone(),
                        root_page_session: entry.root.clone(),
                        active_page: active,
                    },
                    op,
                    admission,
                )
                .await?;
            let page_target = matches!(entry.kind.as_str(), "page" | "iframe");
            if page_target {
                // Chromium fixes includeWhitespace at the first DOM.enable (and
                // DOM.getDocument implicitly enables with the default "none").
                // Set it once on our Application session before any DOM consumer;
                // observer-only host sessions and workers never enter this branch.
                self.command(
                    op,
                    Some(&entry.session),
                    "DOM.enable",
                    json!({"includeWhitespace":"all"}),
                )
                .await?;
                self.initial_settings(&entry, op).await?;
                self.command(op, Some(&entry.session), "Page.enable", json!({}))
                    .await?;
                // Discover existing frames as well as future frame events.
                let tree = self
                    .command(op, Some(&entry.session), "Page.getFrameTree", json!({}))
                    .await?;
                if let Some(tree) = tree.get("frameTree") {
                    self.frame_tree(&entry, tree, 0)?;
                }
            }
            // Runtime.enable creates the paused popup's main world before its first
            // init registration. Chromium runs registrations immediately for paused
            // new windows; creating the world inside that first registration can
            // re-enter new-document injection and execute only script zero twice.
            // Runtime events are already subscribed, and the target stays paused.
            ServiceWorkerAdmission::observe(
                admission,
                WorkerAdmissionStep::RuntimeEnable,
                self.command(op, Some(&entry.session), "Runtime.enable", json!({})),
            )
            .await?;
            if page_target {
                let revision = self
                    .page
                    .apply_to_new_session(&lease, &entry.session, op)
                    .await?;
                if revision != self.page.config_revision()? {
                    return Err(ProtocolError::StaleScope);
                }
            }
            // Autoattach is recursive. Install it while this target is paused.
            ServiceWorkerAdmission::observe(
                admission,
                WorkerAdmissionStep::RecursiveAutoattach,
                self.command(
                    op,
                    Some(&entry.session),
                    "Target.setAutoAttach",
                    autoattach(true),
                ),
            )
            .await?;
            ServiceWorkerAdmission::observe_sync(
                admission,
                WorkerAdmissionStep::Configured,
                || self.targets.configured(&entry.target),
            )?;
            let permit = ServiceWorkerAdmission::observe(
                admission,
                WorkerAdmissionStep::ResumePermit,
                bounded(op, self.targets.resume_permit(&entry.target)),
            )
            .await?;
            ServiceWorkerAdmission::observe(
                admission,
                WorkerAdmissionStep::ResumeDebugger,
                self.command(
                    op,
                    Some(&entry.session),
                    "Runtime.runIfWaitingForDebugger",
                    json!({}),
                ),
            )
            .await?;
            lease.permit.check()?;
            permit.complete()?;
        }
        ServiceWorkerAdmission::observe_sync(
            admission,
            WorkerAdmissionStep::ConfigurationCommitted,
            || self.network.configuration_committed(&entry.session, op),
        )?;
        if let Some(current) = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .sessions
            .get_mut(&entry.session)
        {
            current.resumed = true;
        }
        #[cfg(test)]
        if let Ok(index) = self.index.lock() {
            if let Some(current) = index.sessions.get(&entry.session) {
                self.trace_capture_registry(CaptureLifecycleStep::Resumed, current, &index);
            }
        }
        self.changed.notify_waiters();
        Ok(())
    }
    async fn initial_settings(
        &self,
        entry: &Attribution,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        if self.config.user_agent.is_some() || self.config.locale.is_some() {
            let ua = match &self.config.user_agent {
                Some(ua) => ua.clone(),
                None => self
                    .command(op, None, "Browser.getVersion", json!({}))
                    .await?
                    .get("userAgent")
                    .and_then(Value::as_str)
                    .ok_or(ProtocolError::BrowserFailure)?
                    .to_owned(),
            };
            let mut args = json!({"userAgent":ua});
            if let Some(locale) = &self.config.locale {
                args["acceptLanguage"] = json!(locale);
            }
            self.command(
                op,
                Some(&entry.session),
                "Emulation.setUserAgentOverride",
                args,
            )
            .await?;
        }
        if let Some(locale) = &self.config.locale {
            self.emulation_override(
                op,
                &entry.session,
                "Emulation.setLocaleOverride",
                json!({"locale":locale}),
                "Another locale override is already in effect",
            )
            .await?;
        }
        if let Some(timezone) = &self.config.timezone_id {
            self.emulation_override(
                op,
                &entry.session,
                "Emulation.setTimezoneOverride",
                json!({"timezoneId":timezone}),
                "Timezone override is already in effect",
            )
            .await?;
        }
        if entry.kind == "page" {
            let active = *self
                .active_root
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                == entry.session;
            let viewport = if active {
                self.page.requested_viewport()?.or(self.config.viewport)
            } else {
                self.config.viewport
            };
            if let Some((width, height)) = viewport {
                self.command(
                    op,
                    Some(&entry.session),
                    "Emulation.setDeviceMetricsOverride",
                    json!({"width":width,"height":height,"deviceScaleFactor":1,"mobile":false}),
                )
                .await?;
            }
        }
        Ok(())
    }
    /// Chromium can share an emulation agent across a page and its popup.
    /// Match Playwright's narrow idempotent exception; all other failures,
    /// especially invalid timezone identifiers, remain fatal before resume.
    async fn emulation_override(
        &self,
        op: &OperationLease,
        session: &str,
        method: &str,
        params: Value,
        already_applied: &str,
    ) -> Result<(), ProtocolError> {
        bounded(op, async {
            match self
                .client
                .send_command(method, Some(params), Some(session))
                .await
            {
                Ok(_) => Ok(()),
                Err(error) if error.contains(already_applied) => Ok(()),
                Err(_) => Err(ProtocolError::BrowserFailure),
            }
        })
        .await
    }
    async fn command(
        &self,
        op: &OperationLease,
        session: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<Value, ProtocolError> {
        bounded(op, async {
            self.client
                .send_command(method, Some(params), session)
                .await
                .map_err(|_| ProtocolError::BrowserFailure)
        })
        .await
    }
    fn acknowledge_start(
        &self,
        op: &OperationLease,
        watermark: &BoundedEventWatermark,
    ) -> Result<bool, ProtocolError> {
        let mut index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if let Some(error) = &index.failure {
            return Err(error.clone());
        }
        if self.sealed.load(Ordering::Acquire) {
            return Err(ProtocolError::Cancelled);
        }
        if op.generation != self.generation {
            return Err(ProtocolError::StaleScope);
        }
        if *op.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= op.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        let received = watermark
            .received()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if !capture_admission_ready(&index, received)
            || index
                .sessions
                .values()
                .any(|entry| (entry.application || entry.observation_only) && !entry.resumed)
        {
            return Ok(false);
        }
        // Lock order matches final publication: index -> targets. No await or
        // independent early readiness write can race stored failure/admission.
        self.targets.acknowledge_enrollment()?;
        index.reconciled = true;
        Ok(true)
    }
    pub async fn start(self: &Arc<Self>, op: &OperationLease) -> Result<(), ProtocolError> {
        self.check()?;
        if self.started.swap(true, Ordering::AcqRel) {
            return Err(ProtocolError::InvalidArguments);
        }
        self.ensure_supervisor().await?;
        let result = async {
            self.command(op, None, "Target.setAutoAttach", autoattach(true)).await?;
            // Reconcile exact owned inventory after autoattach, never infer ready
            // from having configured only the initial blank page.
            let inventory = self.command(op, None, "Target.getTargets", json!({"filter":[{"type":"browser","exclude":true},{"type":"tab","exclude":true},{}]})).await?;
            let infos = inventory.get("targetInfos").and_then(Value::as_array).ok_or(ProtocolError::BrowserFailure)?;
            if infos.len() > 8192 { return Err(ProtocolError::CapacityExceeded); }
            for info in infos {
                if info.get("browserContextId").and_then(Value::as_str).unwrap_or("") == self.targets.context_id && !matches!(info.get("type").and_then(Value::as_str),Some("browser"|"tab")) {
                    let target = field(info,"targetId")?;
                    if self.authorized(target,None,info.get("openerId").and_then(Value::as_str))? {
                        bounded(op, self.targets.wait_attached(target)).await?;
                    } else if matches!(self.ownership, ScopeOwnership::BorrowedTargets(_)) && info.get("type").and_then(Value::as_str) == Some("page") {
                        loop {
                            let changed = self.changed.notified(); tokio::pin!(changed); changed.as_mut().enable();
                            self.check()?;
                            if self.index.lock().map_err(|_|ProtocolError::ScopeUnavailable)?.sessions.values().any(|entry|entry.target==target && entry.observation_only && entry.resumed) { break; }
                            let retired = self.index.lock().map_err(|_|ProtocolError::ScopeUnavailable)?.retired_observer_targets.contains(target);
                            if retired && self.observer_target_gone(target, None, op).await? { break; }
                            bounded(op, async { changed.await; Ok(()) }).await?;
                        }
                    }
                }
            }
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed); changed.as_mut().enable();
                self.check()?;
                if let Ok((_, targets)) = self.targets.inventory() {
                    if targets.iter().all(|target|target.resumed) { break; }
                }
                bounded(op, async { tokio::select! { _=changed=>{}, _=tokio::time::sleep(Duration::from_millis(10))=>{} }; Ok(()) }).await?;
            }
            let watermark = self.event_watermark.lock().map_err(|_| ProtocolError::ScopeUnavailable)?.clone().ok_or(ProtocolError::ScopeUnavailable)?;
            loop {
                self.drain_capture_watermark(&watermark, op).await?;
                if self.acknowledge_start(op, &watermark)? { break; }
                bounded(op, async { tokio::time::sleep(Duration::from_millis(10)).await; Ok(()) }).await?;
            }
            Ok(())
        }.await;
        if let Err(error) = &result {
            self.poison(error.clone());
        }
        result
    }
    async fn ensure_supervisor(self: &Arc<Self>) -> Result<(), ProtocolError> {
        self.check()?;
        let mut task = self.supervisor.lock().await;
        if task.is_none() {
            let events = self
                .client
                .subscribe_bounded_methods_with_budget(
                    EVENTS,
                    256,
                    128 * 1024 * 1024,
                    256 * 1024 * 1024,
                )
                .map_err(|_| ProtocolError::CapacityExceeded)?;
            *self
                .event_watermark
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)? = Some(events.watermark());
            // Capture before spawn; run must also inspect the current value in
            // case sealing won the race before this subscription was created.
            let stop = self.stop.subscribe();
            let owner = self.clone();
            *task = Some(tokio::spawn(async move { owner.run(events, stop).await }));
        }
        Ok(())
    }
    async fn run(
        self: Arc<Self>,
        mut events: BoundedMethodEvents,
        mut stop: watch::Receiver<CancelSignal>,
    ) -> Result<(), ProtocolError> {
        let mut tasks = JoinSet::new();
        let mut terminal = None;
        let mut final_local = None;
        let mut result = loop {
            tokio::select! {
                biased;
                _ = async { drop(stop.wait_for(|signal| *signal != CancelSignal::None).await); } => {
                    if *self.client.remote_connection_closed().borrow() {
                        // A lifecycle stop may race delivery of native EOF. Drain
                        // the already bounded dead-connection queue only to learn
                        // its terminal status; overflow must never become EOF.
                        let end = loop {
                            match events.recv().await {
                                Ok(event) => drop(event),
                                Err(error) => break error,
                            }
                        };
                        if end != "control event stream closed" {
                            break Err(ProtocolError::CapacityExceeded);
                        }
                        match self.terminal_connection_proof() {
                            Ok(proof) => terminal = Some(proof),
                            Err(ProtocolError::StaleScope) => match events.terminal_received().map_err(|_| ProtocolError::ScopeUnavailable)
                                .and_then(|received| self.capture_final_local_eof(received)) {
                                Ok(proof) => final_local = Some(proof),
                                Err(error) => break Err(error),
                            },
                            Err(error) => break Err(error),
                        }
                    }
                    break Ok(());
                },
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    match completed { Some(Ok(Ok(()))) => {}, Some(Ok(Err(error))) => break Err(error), Some(Err(_)) => break Err(ProtocolError::BrowserFailure), None=>{} }
                },
                event = events.recv() => {
                    let event = match event {
                        Ok(event) => event,
                        Err("control event stream closed") if *self.client.remote_connection_closed().borrow() => {
                            match self.terminal_connection_proof() {
                                Ok(proof) => terminal = Some(proof),
                                Err(ProtocolError::StaleScope) => match events.terminal_received().map_err(|_| ProtocolError::ScopeUnavailable)
                                .and_then(|received| self.capture_final_local_eof(received)) {
                                    Ok(proof) => final_local = Some(proof),
                                    Err(error) => break Err(error),
                                },
                                Err(error) => break Err(error),
                            }
                            break Ok(());
                        }
                        Err(_) => break Err(ProtocolError::CapacityExceeded),
                    };
                    let sequence=event.sequence();
                    #[cfg(test)]
                    self.trace_capture_event(&event, sequence);
                    #[cfg(test)]
                    if let Err(error) = self.pause_capture_at(CaptureTestPoint::BeforeEventApply, &self.operation()).await { break Err(error); }
                    if event.method == "Target.attachedToTarget" {
                        if tasks.len() >= MAX_TASKS { break Err(ProtocolError::CapacityExceeded); }
                        let pending=match self.register_pending_event(&event) { Ok(pending)=>pending, Err(error)=>break Err(error) };
                        let owner = self.clone();
                        tasks.spawn(async move {
                            let result = owner.attached((*event).clone()).await;
                            if let Err(error)=&result { owner.poison(error.clone()); }
                            if let Some(session)=pending {
                                owner.index.lock().map_err(|_|ProtocolError::ScopeUnavailable)?.pending_enrollment.remove(&session);
                                owner.changed.notify_waiters();
                            }
                            drop(event); result
                        });
                    } else if let Err(error) = self.event_internal(&event, Some(event.budget_lease())) { break Err(error); }
                    if let Err(error)=self.mark_event_applied(sequence) { break Err(error); }
                    self.changed.notify_waiters();
                }
            }
        };
        if let Err(error) = &result {
            self.poison(error.clone());
        }
        // Stop cancellation is observed by initialization waits; retain every
        // task until it has settled rather than dropping effects mid-command.
        self.stop.send_replace(CancelSignal::SessionClosed);
        // Freeze/park the exact route slot and revoke callback admission before
        // waiting on retained initialization work. The network close worker is
        // itself retained; this await cannot abandon its local readers.
        let terminal_close = if let Some(proof) = &terminal {
            self.targets.seal();
            self.sealed.store(true, Ordering::Release);
            Some(
                match self.network.close_for_remote_disconnect(proof).await {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        // Failed parking is not reconnect authority. Abandon any
                        // partial hold and still join all local network owners;
                        // ordinary network close performs no host lifetime RPC.
                        self.poison(error.clone());
                        if self.network.close().await.is_err() {
                            self.poison(ProtocolError::CleanupFailed);
                            Err(ProtocolError::CleanupFailed)
                        } else {
                            Err(error)
                        }
                    }
                },
            )
        } else if let Some(proof) = &final_local {
            self.targets.seal_admission();
            self.sealed.store(true, Ordering::Release);
            let closed = self.network.close_for_final_local_eof(proof).await;
            if let Err(error) = &closed {
                self.poison(error.clone());
                // A refused final identity still cannot abandon local readers.
                if self.network.close().await.is_err() {
                    self.poison(ProtocolError::CleanupFailed);
                }
            }
            Some(closed)
        } else {
            None
        };
        while let Some(completed) = tasks.join_next().await {
            if !matches!(completed, Ok(Ok(())) | Ok(Err(ProtocolError::Cancelled)))
                && result.is_ok()
            {
                self.poison(ProtocolError::CleanupFailed);
            }
        }
        if let Some(closed) = terminal_close {
            // Distinct local retirement. Never run ordinary close (which
            // abandons parked routes), remote containment, or fake detach ACKs.
            closed?;
            if let Some(proof) = final_local {
                // Recheck exact debt/session settlement after retained tasks.
                // Never cache success over an async cleanup failure.
                self.capture_final_local_eof(proof.received)?;
                *self
                    .final_local_proof
                    .lock()
                    .map_err(|_| ProtocolError::CleanupFailed)? = Some(proof);
            }
            let index = self
                .index
                .lock()
                .map_err(|_| ProtocolError::CleanupFailed)?;
            return match &index.failure {
                Some(error) => Err(error.clone()),
                None => result,
            };
        }
        if self.network.close().await.is_err() {
            self.poison(ProtocolError::CleanupFailed);
            result = Err(ProtocolError::CleanupFailed);
        }
        let failed = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .failure
            .is_some();
        if matches!(&self.ownership, ScopeOwnership::BorrowedTargets(_)) {
            *self
                .retirement_events
                .lock()
                .map_err(|_| ProtocolError::CleanupFailed)? = Some(events);
        }
        if failed && self.perform_containment().await.is_err() {
            self.poison(ProtocolError::CleanupFailed);
            return Err(ProtocolError::CleanupFailed);
        }
        // Deliberately retain all autoattach/pause state. The lifecycle owner
        // must establish containment and explicitly release it in phase two.
        result
    }
    /// Called by lifecycle AFTER seal/drain. The returned proof is constructed
    /// only from actual captured-resource cleanup ACKs, never a caller boolean.
    pub async fn contain_owned_resources(
        self: &Arc<Self>,
    ) -> Result<ContainmentProof, ProtocolError> {
        if !self.sealed.load(Ordering::Acquire) {
            return Err(ProtocolError::ScopeUnavailable);
        }
        // Capture the exact owner before containment yields or retires it.
        let debt = self.client.debt_ledger();
        if debt.as_ref().is_some_and(|ledger| {
            !ledger.matches_owner(self.generation, &self.targets.identity_scope)
        }) {
            return Err(ProtocolError::StaleScope);
        }
        let task = self.supervisor.lock().await;
        if task.is_some() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if !self
            .cleanup
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .owned_resources_contained
        {
            self.perform_containment().await?;
        }
        if matches!(&self.ownership, ScopeOwnership::BorrowedTargets(_))
            && (self
                .cleanup
                .lock()
                .map_err(|_| ProtocolError::CleanupFailed)?
                .borrowed_cleanup_failed
                || !self.targets.auxiliary_cleanup_complete()?)
        {
            return Err(ProtocolError::CleanupFailed);
        }
        Ok(ContainmentProof {
            debt,
            registry: self.targets.clone(),
            identity_scope: self.targets.identity_scope.clone(),
            generation: self.generation,
        })
    }
    pub async fn release_after_containment(
        &self,
        proof: ContainmentProof,
    ) -> Result<(), ProtocolError> {
        if !Arc::ptr_eq(&proof.registry, &self.targets)
            || proof.identity_scope != self.targets.identity_scope
            || proof.generation != self.generation
            || !self.sealed.load(Ordering::Acquire)
        {
            return Err(ProtocolError::StaleScope);
        }
        let _task = self.supervisor.lock().await;
        self.client.check_cleanup_owner(&proof.debt)?;
        let outcome = self.cleanup_outcome()?;
        if !outcome.owned_resources_contained {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if outcome.autoattach_disabled {
            return Ok(());
        }
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        tokio::time::timeout_at(
            deadline.into(),
            self.client.send_owner_cleanup(
                proof.debt,
                super::client_debt::OwnerCleanupCommand::DisableAutoAttach,
                deadline,
            ),
        )
        .await
        .map_err(|_| ProtocolError::CleanupFailed)?
        .map_err(|_| ProtocolError::CleanupFailed)?;
        self.cleanup
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .autoattach_disabled = true;
        Ok(())
    }
    fn authorized(
        &self,
        target: &str,
        parent: Option<&str>,
        opener: Option<&str>,
    ) -> Result<bool, ProtocolError> {
        match &self.ownership {
            ScopeOwnership::IsolatedContext => Ok(true),
            ScopeOwnership::TrackedTargets(allowed) | ScopeOwnership::BorrowedTargets(allowed) => {
                let index = self
                    .index
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if index.borrowed_retired_targets.contains(target) {
                    return Ok(false);
                }
                let blank=index.borrowed_blank.as_ref().is_some_and(|state|matches!(&*state.status.borrow(),BorrowedBlankStatus::Bound(id) if id==target));
                Ok(blank
                    || (matches!(self.ownership, ScopeOwnership::BorrowedTargets(_))
                        && self.targets.is_native_bootstrap_target(target)?)
                    || allowed.iter().any(|id| id == target)
                    || index.sessions.values().any(|entry| {
                        !entry.observation_only
                            && (entry.target == target
                                || (entry.application && opener == Some(entry.target.as_str())))
                    })
                    || parent.is_some_and(|session| {
                        index
                            .sessions
                            .get(session)
                            .is_some_and(|entry| entry.application)
                    }))
            }
        }
    }
    async fn cleanup_command(&self, method: &str, args: Value) -> Result<Value, ProtocolError> {
        tokio::time::timeout(CLEANUP_TIMEOUT, async {
            if method == "Target.getTargets" && args == json!({}) {
                self.client
                    .send_scope_cleanup(
                        super::client_debt::ScopeCleanupCommand::Inventory,
                        Instant::now() + CLEANUP_TIMEOUT,
                    )
                    .await
            } else {
                self.client.send_command(method, Some(args), None).await
            }
        })
        .await
        .map_err(|_| ProtocolError::CleanupFailed)?
        .map_err(|_| ProtocolError::CleanupFailed)
    }
    async fn perform_containment(self: &Arc<Self>) -> Result<(), ProtocolError> {
        let diagnostics = self.client.cleanup_observer();
        let mut state = self.containment.lock().await;
        if let Some(result) = &state.result {
            return result.clone();
        }
        if state.task.is_none() {
            let owner = self.clone();
            state.task = Some(tokio::spawn(
                async move { owner.contain_with_events().await },
            ));
        }
        let result = state
            .task
            .as_mut()
            .ok_or(ProtocolError::CleanupFailed)?
            .await
            .map_err(|_| ProtocolError::CleanupFailed)
            .and_then(|result| result);
        state.task = None;
        state.result = Some(result.clone());
        super::client_settlement_trace::observe_cleanup(
            &diagnostics,
            super::client_settlement_trace::CleanupComponent::Containment,
            &result,
        );
        result
    }
    async fn contain_with_events(&self) -> Result<(), ProtocolError> {
        let events = self
            .retirement_events
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?
            .take();
        let Some(mut events) = events else {
            return self.contain_owned().await;
        };
        let deadline = Instant::now() + Duration::from_secs(12);
        let (finished, mut finish_rx) = tokio::sync::watch::channel(false);
        let cleanup = async {
            let result = self.contain_owned_before(deadline).await;
            finished.send_replace(true);
            result
        };
        let pump = async {
            let mut failed = false;
            loop {
                tokio::select! {
                    biased;
                    _=finish_rx.changed()=> {
                        // All initialization tasks have drained before this
                        // pump starts. Known manual sessions were detached
                        // explicitly; the browser-level disable ACK detaches
                        // every remaining automatic session. Queued attachment
                        // notifications cannot recreate ownership after that
                        // ACK, so they need not delay this terminal boundary.
                        let outcome=self.cleanup.lock().map_err(|_|ProtocolError::CleanupFailed)?;
                        return if failed || !outcome.autoattach_disabled || !outcome.owned_resources_contained
                            || !self.targets.auxiliary_cleanup_complete()? {
                            Err(ProtocolError::CleanupFailed)
                        } else { Ok(()) };
                    },
                    _=tokio::time::sleep_until(deadline.into())=>return Err(ProtocolError::CleanupFailed),
                    event=events.recv()=> {
                        let event=match event { Ok(event)=>event, Err(_)=>return Err(ProtocolError::CleanupFailed) };
                        if event.method=="Target.attachedToTarget" {
                            let Ok(session)=field(&event.params,"sessionId") else { failed=true;continue; };
                            let target=event.params.get("targetInfo").and_then(|info|info.get("targetId")).and_then(Value::as_str);
                            if let Some(target)=target {
                                // The retained recorder remains the sole detach
                                // owner, even for a late queued notification.
                                let auxiliary=tokio::time::timeout_at(deadline.into(),self.targets.classify_auxiliary_attachment(target,session)).await;
                                match auxiliary {
                                    Ok(Ok(super::client_targets::AuxiliaryDisposition::RecorderOwned))=> {
                                        failed |= self.targets.auxiliary_detach_acknowledged(target,session)? != Some(true);
                                        continue;
                                    },
                                    Ok(Ok(super::client_targets::AuxiliaryDisposition::Ordinary))=>{},
                                    _=>{failed=true;continue;},
                                }
                            }
                            let known=self.index.lock().map_err(|_|ProtocolError::CleanupFailed)?.sessions.contains_key(session);
                            if !known { failed |= self.detach_borrowed_session(session,event.session_id.as_deref(),deadline).await.is_err(); }
                        } else {
                            let detached=event.session_id.as_ref().is_some_and(|session|self.cleanup.lock().is_ok_and(|outcome|outcome.borrowed_sessions_detached.contains(session)));
                            if !detached {
                                failed |= tokio::time::timeout_at(deadline.into(),self.network.settle_borrowed_event(&event)).await.map_or(true,|result|result.is_err());
                            }
                        }
                    },
                }
            }
        };
        // Fair concurrent polling: host event traffic cannot starve teardown.
        // The cleanup future is never dropped merely because the tap failed.
        let (cleanup, pump) = tokio::join!(cleanup, pump);
        if cleanup.is_err() || pump.is_err() {
            self.cleanup
                .lock()
                .map_err(|_| ProtocolError::CleanupFailed)?
                .borrowed_cleanup_failed = true;
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
    async fn contain_owned(&self) -> Result<(), ProtocolError> {
        self.contain_owned_before(Instant::now() + Duration::from_secs(12))
            .await
    }
    async fn contain_owned_before(&self, deadline: Instant) -> Result<(), ProtocolError> {
        match &self.ownership {
            ScopeOwnership::IsolatedContext => {
                // Capture this exact owner's ledger before yielding. A later
                // replacement on the shared transport cannot be cleared by the
                // old disposal ACK. Identity and context binding are native-only.
                let debt = self.client.debt_ledger();
                if debt.as_ref().is_some_and(|ledger| {
                    !ledger.matches_owner(self.generation, &self.targets.identity_scope)
                }) {
                    return Err(ProtocolError::StaleScope);
                }
                self.cleanup_command(
                    "Target.disposeBrowserContext",
                    json!({"browserContextId":self.targets.context_id}),
                )
                .await?;
                if let Some(debt) = debt {
                    debt.retire_after_context_destroy(&self.targets.context_id)?;
                }
                self.cleanup
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .isolated_context_disposed = true;
            }
            ScopeOwnership::TrackedTargets(allowed) => self.contain_tracked(allowed).await?,
            ScopeOwnership::BorrowedTargets(_) => self.contain_borrowed(deadline).await?,
        }
        self.cleanup
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .owned_resources_contained = true;
        Ok(())
    }
    async fn contain_borrowed(&self, deadline: Instant) -> Result<(), ProtocolError> {
        let diagnostics = self.client.cleanup_observer();
        let session_deadline = deadline
            .checked_sub(Duration::from_secs(2))
            .unwrap_or(deadline);
        let config_deadline = deadline
            .checked_sub(Duration::from_secs(8))
            .unwrap_or(deadline);
        let mut entries: Vec<_> = self
            .index
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?
            .sessions
            .values()
            .cloned()
            .collect();
        let temporary = self.targets.native_bootstrap_cleanup_targets()?;
        let temporary_cleanup_failed = super::client_state::retire_native_bootstrap_pages(
            &self.client,
            &self.targets,
            config_deadline,
        )
        .await
        .is_err();
        let remaining_temporary = self.targets.native_bootstrap_cleanup_targets()?;
        // Earlier entries may have been settled before a later close failed.
        // Do not send generic cleanup RPCs to those already-closed sessions.
        entries.retain(|entry| {
            !temporary.contains(&entry.target) || remaining_temporary.contains(&entry.target)
        });
        // Children first: their parent session remains available for detach.
        let parents: HashMap<_, _> = entries
            .iter()
            .map(|entry| (entry.session.clone(), entry.parent.clone()))
            .collect();
        entries.sort_by_key(|entry| {
            let mut parent = entry.parent.as_ref();
            let mut depth = 0;
            while let Some(id) = parent {
                depth += 1;
                if depth >= MAX_SESSIONS {
                    break;
                }
                parent = parents.get(id).and_then(Option::as_ref);
            }
            std::cmp::Reverse(depth)
        });
        // Browser-wide autoattach disable does not prove cleanup of manually
        // attached recorder sessions. Require their retained owner's ACKs even
        // when the corresponding attach notification is still queued.
        let mut failed = temporary_cleanup_failed || !self.targets.auxiliary_cleanup_complete()?;
        for entry in &entries {
            if entry.application {
                failed |= self
                    .page
                    .release_borrowed_input(
                        &self.client,
                        &self.targets.identity_scope,
                        &entry.session,
                        config_deadline,
                    )
                    .await
                    .inspect_err(|_| {
                        if let Some(cell) = &diagnostics {
                            cell.failure(super::client_settlement_trace::CleanupComponent::Input);
                        }
                    })
                    .is_err();
                failed |= self
                    .network
                    .release_borrowed_interception(
                        &self.targets.identity_scope,
                        &entry.session,
                        config_deadline,
                    )
                    .await
                    .inspect_err(|_| {
                        if let Some(cell) = &diagnostics {
                            cell.failure(
                                super::client_settlement_trace::CleanupComponent::Interception,
                            );
                        }
                    })
                    .is_err();
                failed |= self
                    .page
                    .remove_session_scripts(
                        &self.client,
                        &self.targets.identity_scope,
                        &entry.session,
                        config_deadline,
                    )
                    .await
                    .inspect_err(|_| {
                        if let Some(cell) = &diagnostics {
                            cell.failure(super::client_settlement_trace::CleanupComponent::Script);
                        }
                    })
                    .is_err();
            }
            // Do not release a debugger pause by closing the host page.
            for resume in [true, false] {
                if entry.observation_only && resume && (!entry.observer_paused || entry.resumed) {
                    continue;
                }
                if Instant::now() >= session_deadline {
                    failed = true;
                    break;
                }
                let command = if resume {
                    super::client_debt::ScopeCleanupCommand::ResumeDebugger {
                        session: entry.session.clone(),
                    }
                } else {
                    super::client_debt::ScopeCleanupCommand::DisableAutoAttach {
                        session: Some(entry.session.clone()),
                    }
                };
                failed |= self
                    .client
                    .send_scope_cleanup(
                        command,
                        std::cmp::min(session_deadline, Instant::now() + CLEANUP_TIMEOUT),
                    )
                    .await
                    .is_err();
            }
            match self
                .detach_borrowed_session(&entry.session, entry.parent.as_deref(), session_deadline)
                .await
            {
                Ok(()) => self
                    .cleanup
                    .lock()
                    .map_err(|_| ProtocolError::CleanupFailed)?
                    .borrowed_sessions_detached
                    .push(entry.session.clone()),
                Err(_) => failed = true,
            }
        }
        // Disable only this connection's attachment mechanism. App pages and
        // ongoing host activity remain alive and are not inventory failures.
        if Instant::now() < deadline
            && matches!(
                tokio::time::timeout_at(
                    deadline.into(),
                    self.client.send_scope_cleanup(
                        super::client_debt::ScopeCleanupCommand::DisableAutoAttach {
                            session: None
                        },
                        deadline
                    )
                )
                .await,
                Ok(Ok(_))
            )
        {
            self.cleanup
                .lock()
                .map_err(|_| ProtocolError::CleanupFailed)?
                .autoattach_disabled = true;
        } else {
            failed = true;
        }
        failed |= !self.targets.auxiliary_cleanup_complete()?;
        if failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
    async fn detach_borrowed_session(
        &self,
        session: &str,
        parent: Option<&str>,
        deadline: Instant,
    ) -> Result<(), ProtocolError> {
        if Instant::now() >= deadline {
            return Err(ProtocolError::CleanupFailed);
        }
        tokio::time::timeout_at(deadline.into(), self.detach_foreign(session, parent))
            .await
            .map_err(|_| ProtocolError::CleanupFailed)?
    }
    async fn contain_tracked(&self, allowed: &[String]) -> Result<(), ProtocolError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut owned: std::collections::HashSet<String> = allowed.iter().cloned().collect();
        owned.extend(
            self.index
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .sessions
                .values()
                .map(|entry| entry.target.clone()),
        );
        loop {
            if Instant::now() >= deadline {
                return Err(ProtocolError::CleanupFailed);
            }
            let inventory = self.cleanup_command("Target.getTargets", json!({})).await?;
            let infos = inventory
                .get("targetInfos")
                .and_then(Value::as_array)
                .ok_or(ProtocolError::CleanupFailed)?;
            if infos.len() > 8192 {
                return Err(ProtocolError::CleanupFailed);
            }
            loop {
                let before = owned.len();
                for info in infos {
                    if info
                        .get("browserContextId")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        == self.targets.context_id
                        && info
                            .get("openerId")
                            .and_then(Value::as_str)
                            .is_some_and(|id| owned.contains(id))
                    {
                        owned.insert(field(info, "targetId")?.to_owned());
                    }
                }
                if owned.len() > MAX_SESSIONS {
                    return Err(ProtocolError::CleanupFailed);
                }
                if before == owned.len() {
                    break;
                }
            }
            let mut found = false;
            for info in infos {
                let target = field(info, "targetId")?;
                if info
                    .get("browserContextId")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    == self.targets.context_id
                    && owned.contains(target)
                {
                    found = true;
                    if Instant::now() >= deadline {
                        return Err(ProtocolError::CleanupFailed);
                    }
                    let result = self
                        .cleanup_command("Target.closeTarget", json!({"targetId":target}))
                        .await?;
                    if result.get("success").and_then(Value::as_bool) != Some(true) {
                        return Err(ProtocolError::CleanupFailed);
                    }
                    self.cleanup
                        .lock()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?
                        .closed_targets
                        .push(target.into());
                }
            }
            // Reconcile again AFTER close acknowledgements. A popup created
            // between the first inventory and parent closure must not escape.
            if !found {
                return Ok(());
            }
        }
    }
    pub fn cleanup_outcome(&self) -> Result<CleanupOutcome, ProtocolError> {
        Ok(self
            .cleanup
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .clone())
    }
    async fn attached(&self, event: CdpEvent) -> Result<(), ProtocolError> {
        #[cfg(test)]
        self.pause_capture_at(
            CaptureTestPoint::BeforeAttachedProcessing,
            &self.operation(),
        )
        .await?;
        let session = field(&event.params, "sessionId")?.to_owned();
        let mut info = event
            .params
            .get("targetInfo")
            .ok_or(ProtocolError::InvalidFrame)?
            .clone();
        if info
            .get("browserContextId")
            .and_then(Value::as_str)
            .is_none()
            && info.get("type").and_then(Value::as_str) == Some("iframe")
            && event.session_id.as_ref().is_some_and(|parent| {
                self.index.lock().is_ok_and(|index| {
                    index
                        .sessions
                        .get(parent)
                        .is_some_and(|entry| entry.observation_only)
                })
            })
        {
            let target = field(&info, "targetId")?.to_owned();
            let resolved = self
                .command(
                    &self.operation(),
                    None,
                    "Target.getTargetInfo",
                    json!({"targetId":target}),
                )
                .await?;
            let exact = resolved
                .get("targetInfo")
                .ok_or(ProtocolError::InvalidFrame)?;
            if field(exact, "targetId")? != target || field(exact, "type")? != "iframe" {
                return Err(ProtocolError::StaleScope);
            }
            info = exact.clone();
        }
        let info = &info;
        let target = field(info, "targetId")?;
        let kind = field(info, "type")?;
        // Missing context is not permission to inherit a tenant from an opener.
        let context = info
            .get("browserContextId")
            .and_then(Value::as_str)
            .unwrap_or("");
        if context == self.targets.context_id
            && !self.authorized(
                target,
                event.session_id.as_deref(),
                info.get("openerId").and_then(Value::as_str),
            )?
        {
            let pending_blank = self
                .index
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .borrowed_blank
                .is_some();
            let blank_matches = self.borrowed_blank_matches(target).await?;
            if pending_blank && !blank_matches {
                return self
                    .detach_foreign(&session, event.session_id.as_deref())
                    .await;
            }
            if matches!(self.ownership, ScopeOwnership::BorrowedTargets(_)) {
                if let Err(error) = bounded(
                    &self.operation(),
                    self.targets.wait_native_bootstrap_target(target),
                )
                .await
                {
                    self.detach_foreign(&session, event.session_id.as_deref())
                        .await?;
                    return if error == ProtocolError::Cancelled {
                        Ok(())
                    } else {
                        Err(error)
                    };
                }
            }
        }
        if event.session_id.as_ref().is_some_and(|parent| {
            self.index.lock().is_ok_and(|index| {
                index.retired_page_sessions.contains(parent)
                    || index.retired_observer_sessions.contains(parent)
            })
        }) {
            // Retain descendants too: a later grandchild event is scoped to
            // this immediate parent session, not necessarily the original root.
            {
                let mut index = self
                    .index
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if index.retired_page_sessions.len() >= MAX_FRAMES
                    && !index.retired_page_sessions.contains(&session)
                {
                    return Err(ProtocolError::CapacityExceeded);
                }
                index.retired_page_sessions.insert(session.clone());
            }
            // An already received late child belongs to an explicitly retired
            // root. Detach this connection's session, never adopt it as new.
            return self
                .detach_foreign(&session, event.session_id.as_deref())
                .await;
        }
        if context == self.targets.context_id
            && matches!(self.ownership, ScopeOwnership::BorrowedTargets(_))
            && !self.authorized(
                target,
                event.session_id.as_deref(),
                info.get("openerId").and_then(Value::as_str),
            )?
            && matches!(kind, "page" | "iframe")
        {
            return self
                .observe_context_page(
                    target,
                    &session,
                    kind,
                    event.session_id.as_deref(),
                    event
                        .params
                        .get("waitingForDebugger")
                        .and_then(Value::as_bool)
                        == Some(true),
                )
                .await;
        }
        if context != self.targets.context_id
            || !self.authorized(
                target,
                event.session_id.as_deref(),
                info.get("openerId").and_then(Value::as_str),
            )?
        {
            return self
                .detach_foreign(&session, event.session_id.as_deref())
                .await;
        }
        // Stored scope failure takes precedence over retirement cancellation.
        // Foreign cleanup above must remain live even for a poisoned scope.
        self.check().map_err(|error| self.admission_error(error))?;
        // Only this authorized service-worker attachment receives a diagnostic ordinal.
        let admission = if kind == "service_worker" {
            ServiceWorkerAdmission::start(
                self.generation,
                event
                    .params
                    .get("waitingForDebugger")
                    .and_then(Value::as_bool),
            )
        } else {
            None
        };
        let auxiliary = ServiceWorkerAdmission::observe(
            admission.as_ref(),
            WorkerAdmissionStep::AuxiliaryClassification,
            bounded(
                &self.operation(),
                self.targets.classify_auxiliary_attachment(target, &session),
            ),
        )
        .await?;
        match auxiliary {
            super::client_targets::AuxiliaryDisposition::RecorderOwned => return Ok(()),
            super::client_targets::AuxiliaryDisposition::Ordinary => {}
        }
        #[cfg(test)]
        self.trace_capture_admission(CaptureLifecycleStep::RegisteringAttached, target, &session);
        match ServiceWorkerAdmission::observe_sync(
            admission.as_ref(),
            WorkerAdmissionStep::Register,
            || self.register(context, target, &session, kind, event.session_id.as_deref()),
        )? {
            Some(entry) => {
                self.diagnostic_registration(
                    &entry,
                    super::client_settlement_trace::DiagnosticTargetOrigin::AutoAttach,
                    0,
                );
                self.initialize_observed(entry, &self.operation(), admission.as_ref())
                    .await
            }
            None => {
                let same = self
                    .index
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .sessions
                    .contains_key(&session);
                if same {
                    Ok(())
                } else {
                    self.detach_foreign(&session, event.session_id.as_deref())
                        .await
                }
            }
        }
    }
    fn register_observer(
        &self,
        target: &str,
        session: &str,
        kind: &str,
        parent: Option<&str>,
        paused_by_attachment: bool,
    ) -> Result<Option<Attribution>, ProtocolError> {
        let mut index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if index.retired_observer_sessions.contains(session)
            || index.borrowed_retired_targets.contains(target)
        {
            return Ok(None);
        }
        if index.sessions.contains_key(session) {
            return Err(ProtocolError::StaleScope);
        }
        if index.sessions.values().any(|entry| entry.target == target) {
            return Ok(None);
        }
        if index.sessions.len() >= MAX_SESSIONS {
            return Err(ProtocolError::CapacityExceeded);
        }
        let root = if kind == "page" {
            session.to_owned()
        } else {
            let parent = parent
                .and_then(|id| index.sessions.get(id))
                .filter(|entry| entry.observation_only)
                .ok_or(ProtocolError::StaleReference)?;
            parent.root.clone()
        };
        let entry = Attribution {
            target: target.into(),
            session: session.into(),
            parent: parent.map(str::to_owned),
            root,
            kind: kind.into(),
            application: false,
            observation_only: true,
            observer_paused: paused_by_attachment,
            resumed: false,
        };
        if let Some(debt) = self.client.debt_ledger() {
            debt.bind_observer_session(&self.targets.context_id, target, session)?;
        }
        self.revoke_eval_authority();
        index.sessions.insert(session.into(), entry.clone());
        #[cfg(test)]
        self.trace_capture_registry(CaptureLifecycleStep::Registered, &entry, &index);
        index.application_epoch = index
            .application_epoch
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        Ok(Some(entry))
    }
    /// Same-context storage-origin observation is not Application ownership.
    /// No Fetch, Runtime events, settings, scripts, input or app notices are installed.
    async fn observe_context_page(
        &self,
        target: &str,
        session: &str,
        kind: &str,
        parent: Option<&str>,
        paused_by_attachment: bool,
    ) -> Result<(), ProtocolError> {
        self.check().map_err(|error| self.admission_error(error))?;
        for id in [target, session, kind] {
            valid_id(id)?;
        }
        let Some(entry) =
            self.register_observer(target, session, kind, parent, paused_by_attachment)?
        else {
            return self.detach_foreign(session, parent).await;
        };
        let op = self.operation();
        let result = async {
            let lease = self.lease(&entry)?;
            self.command(&op, Some(session), "Page.enable", json!({}))
                .await?;
            let tree = self
                .command(&op, Some(session), "Page.getFrameTree", json!({}))
                .await?;
            self.frame_tree(
                &entry,
                tree.get("frameTree").ok_or(ProtocolError::InvalidFrame)?,
                0,
            )?;
            self.command(&op, Some(session), "Target.setAutoAttach", autoattach(true))
                .await?;
            if paused_by_attachment {
                self.command(
                    &op,
                    Some(session),
                    "Runtime.runIfWaitingForDebugger",
                    json!({}),
                )
                .await?;
            }
            lease.permit.check()?;
            let mut index = self
                .index
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            let current = index
                .sessions
                .get_mut(session)
                .ok_or(ProtocolError::StaleReference)?;
            if current.target != target || !current.observation_only {
                return Err(ProtocolError::StaleScope);
            }
            current.resumed = true;
            self.changed.notify_waiters();
            Ok(())
        }
        .await;
        match result {
            Err(error @ (ProtocolError::BrowserFailure | ProtocolError::StaleReference)) => {
                if self
                    .observer_target_gone(target, Some(session), &op)
                    .await?
                {
                    Ok(())
                } else {
                    Err(error)
                }
            }
            other => other,
        }
    }
    /// Detach alone may mean lost observation, not host target destruction.
    /// Require authoritative absence too, and never hide another stored failure.
    async fn observer_target_gone(
        &self,
        target: &str,
        session: Option<&str>,
        op: &OperationLease,
    ) -> Result<bool, ProtocolError> {
        self.check()?;
        let inventory = self
            .command(op, None, "Target.getTargets", json!({}))
            .await?;
        let infos = inventory
            .get("targetInfos")
            .and_then(Value::as_array)
            .ok_or(ProtocolError::InvalidFrame)?;
        if infos.len() > 8192 {
            return Err(ProtocolError::CapacityExceeded);
        }
        let mut present = false;
        for info in infos {
            let id = field(info, "targetId")?;
            present |= id == target;
        }
        if present {
            return Ok(false);
        }
        let watermark = self
            .event_watermark
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .clone()
            .ok_or(ProtocolError::ScopeUnavailable)?;
        // Only reader-applied accounting, not pending-job completion: this
        // initialization task may itself be a pending enrollment job.
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.check()?;
            let settled = {
                let index = self
                    .index
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                let received = watermark
                    .received()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                observer_retirement_snapshot(
                    &index,
                    self.sealed.load(Ordering::Acquire),
                    target,
                    session,
                    received,
                )?
            };
            if let Some(gone) = settled {
                return Ok(gone);
            }
            bounded(op, async {
                changed.await;
                Ok(())
            })
            .await?;
        }
    }
    async fn detach_foreign(
        &self,
        session: &str,
        parent: Option<&str>,
    ) -> Result<(), ProtocolError> {
        // Only this exact attachment, obtained from the existing enrollment
        // owner/event, may undo its debugger pause. Never grant Runtime generally.
        let deadline = Instant::now() + CLEANUP_TIMEOUT * 3;
        let detach = || {
            self.client.send_scope_cleanup(
                super::client_debt::ScopeCleanupCommand::Detach {
                    session: session.into(),
                    parent: parent.map(str::to_owned),
                },
                deadline,
            )
        };
        if matches!(
            tokio::time::timeout(CLEANUP_TIMEOUT, detach()).await,
            Ok(Ok(_))
        ) {
            return Ok(());
        }
        let resumed = tokio::time::timeout(
            CLEANUP_TIMEOUT,
            self.client.send_scope_cleanup(
                super::client_debt::ScopeCleanupCommand::ResumeDebugger {
                    session: session.into(),
                },
                deadline,
            ),
        )
        .await;
        let detached = tokio::time::timeout(CLEANUP_TIMEOUT, detach()).await;
        if matches!(resumed, Ok(Ok(_))) && matches!(detached, Ok(Ok(_))) {
            Ok(())
        } else {
            Err(ProtocolError::CleanupFailed)
        }
    }

    fn frame_tree(
        &self,
        entry: &Attribution,
        tree: &Value,
        depth: usize,
    ) -> Result<(), ProtocolError> {
        if depth > 64 {
            return Err(ProtocolError::CapacityExceeded);
        }
        let frame = tree.get("frame").ok_or(ProtocolError::InvalidFrame)?;
        self.record_frame(entry, frame, false)?;
        if let Some(children) = tree.get("childFrames").and_then(Value::as_array) {
            for child in children {
                self.frame_tree(entry, child, depth + 1)?;
            }
        }
        Ok(())
    }
    fn record_frame(
        &self,
        entry: &Attribution,
        frame: &Value,
        new_document: bool,
    ) -> Result<(), ProtocolError> {
        let id = field(frame, "id")?;
        let mut index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if index.frames.len() >= MAX_FRAMES && !index.frames.contains_key(id) {
            return Err(ProtocolError::CapacityExceeded);
        }
        let is_child_session = index.frames.get(id).is_some_and(|frame| {
            frame.session != entry.session
                && index
                    .sessions
                    .get(&frame.session)
                    .is_some_and(|owner| owner.kind == "iframe")
        });
        if !is_child_session {
            let loader = frame
                .get("loaderId")
                .and_then(Value::as_str)
                .filter(|loader| loader.len() <= 4096)
                .map(str::to_owned);
            let parent = frame
                .get("parentId")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if index.frames.get(id).is_none_or(|known| {
                known.session != entry.session || known.loader != loader || known.parent != parent
            }) {
                self.revoke_eval_authority();
            }
            index.frames.insert(
                id.into(),
                FrameOwner {
                    loader,
                    name: frame
                        .get("name")
                        .and_then(Value::as_str)
                        .map(super::client_app_events::diagnostic_frame_name),
                    session: entry.session.clone(),
                    parent,
                },
            );
        }
        drop(index);
        if let Some(url) = frame
            .get("url")
            .and_then(Value::as_str)
            .filter(|_| new_document)
        {
            self.page.record_origin(&self.lease(entry)?, url)?;
        }
        Ok(())
    }
    fn event(&self, event: &CdpEvent) -> Result<(), ProtocolError> {
        self.event_internal(event, None)
    }
    fn event_internal(
        &self,
        event: &CdpEvent,
        budget: Option<super::cdp::client::EventBudgetLease>,
    ) -> Result<(), ProtocolError> {
        if event.method == "Target.detachedFromTarget" {
            let session = field(&event.params, "sessionId")?;
            let entries: Vec<_> = {
                let mut index = self
                    .index
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                let mut removed = Vec::new();
                let mut ids = vec![session.to_owned()];
                while let Some(id) = ids.pop() {
                    ids.extend(
                        index
                            .sessions
                            .values()
                            .filter(|entry| entry.parent.as_deref() == Some(&id))
                            .map(|entry| entry.session.clone()),
                    );
                    if let Some(entry) = index.sessions.remove(&id) {
                        index.realm_sessions.remove(&id);
                        index.realms.retain(|(session, _), _| session != &id);
                        index.popup_opened.remove(&entry.session);
                        removed.push(entry);
                    }
                }
                index
                    .frames
                    .retain(|_, owner| !removed.iter().any(|entry| entry.session == owner.session));
                let retired: Vec<_> = removed
                    .iter()
                    .filter(|entry| {
                        index
                            .retiring_pages
                            .values()
                            .any(|root| root == &entry.root)
                    })
                    .map(|entry| entry.session.clone())
                    .collect();
                if index
                    .retired_page_sessions
                    .len()
                    .saturating_add(retired.len())
                    > MAX_FRAMES
                {
                    return Err(ProtocolError::CapacityExceeded);
                }
                index.retired_page_sessions.extend(retired);
                for entry in removed.iter().filter(|entry| entry.observation_only) {
                    if index.retired_observer_sessions.len() >= MAX_FRAMES {
                        return Err(ProtocolError::CapacityExceeded);
                    }
                    if index.retired_observer_targets.len() >= MAX_FRAMES {
                        return Err(ProtocolError::CapacityExceeded);
                    }
                    index.retired_observer_targets.insert(entry.target.clone());
                    index
                        .retired_observer_sessions
                        .insert(entry.session.clone());
                }
                if removed
                    .iter()
                    .any(|entry| entry.application || entry.observation_only)
                {
                    self.revoke_eval_authority();
                    index.application_epoch = index
                        .application_epoch
                        .checked_add(1)
                        .ok_or(ProtocolError::IdentifierExhausted)?;
                }
                #[cfg(test)]
                for entry in &removed {
                    self.trace_capture_registry(CaptureLifecycleStep::Removed, entry, &index);
                }
                removed
            };
            for entry in entries {
                if !entry.observation_only {
                    self.targets.detach(&entry.target)?;
                }
                self.page.forget_session(&entry.session)?;
                if entry.application {
                    self.network.detach_session(&entry.session)?;
                }
            }
            self.changed.notify_waiters();
            return Ok(());
        }
        if event.method == "Target.targetInfoChanged" {
            let info = event
                .params
                .get("targetInfo")
                .ok_or(ProtocolError::InvalidFrame)?;
            let target = field(info, "targetId")?;
            let entry = self
                .index
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .sessions
                .values()
                .find(|entry| entry.target == target)
                .cloned();
            if entry.is_some_and(|entry| entry.application) {
                self.bump_application_epoch()?;
                self.targets.invalidate_inventory_for(
                    super::client_settlement_trace::InventoryRevisionEvent::Info,
                    target,
                )?;
            }
            return Ok(());
        }
        let mut routed = event.clone();
        if event.method == "Browser.downloadWillBegin" {
            let frame = field(&event.params, "frameId")?;
            let index = self
                .index
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            let Some(session) = index.frames.get(frame) else {
                return Ok(());
            };
            routed.session_id = Some(session.session.clone());
        }
        // Progress is keyed by an already owned GUID inside ClientNetwork.
        if event.method == "Browser.downloadProgress" {
            return match budget {
                Some(budget) => self.network.event_with_budget(&routed, budget),
                None => self.network.event(&routed),
            };
        }
        let entry = {
            let index = self
                .index
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            routed
                .session_id
                .as_ref()
                .and_then(|id| index.sessions.get(id))
                .cloned()
        };
        let Some(entry) = entry else {
            return Ok(());
        };
        if entry.observation_only {
            match event.method.as_str() {
                "Page.frameNavigated" => {
                    self.bump_application_epoch()?;
                    self.record_frame(
                        &entry,
                        event
                            .params
                            .get("frame")
                            .ok_or(ProtocolError::InvalidFrame)?,
                        true,
                    )?;
                }
                "Page.frameDetached" => {
                    self.bump_application_epoch()?;
                    let frame = field(&event.params, "frameId")?;
                    let mut index = self
                        .index
                        .lock()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?;
                    if index
                        .frames
                        .get(frame)
                        .is_some_and(|owner| owner.session == entry.session)
                    {
                        let mut ids = vec![frame.to_owned()];
                        while let Some(id) = ids.pop() {
                            ids.extend(
                                index
                                    .frames
                                    .iter()
                                    .filter(|(_, owner)| owner.parent.as_deref() == Some(&id))
                                    .map(|(id, _)| id.clone()),
                            );
                            index.frames.remove(&id);
                        }
                    }
                }
                "Page.frameAttached" | "Page.navigatedWithinDocument" => {
                    self.bump_application_epoch()?;
                }
                _ => {}
            }
            return Ok(());
        }
        if !entry.application {
            return Ok(());
        }
        if matches!(
            event.method.as_str(),
            "Runtime.executionContextCreated"
                | "Runtime.executionContextDestroyed"
                | "Runtime.executionContextsCleared"
        ) {
            return self.realm_event(&entry, event);
        }
        match event.method.as_str() {
            "Page.frameAttached" => {
                self.bump_application_epoch()?;
            }
            "Page.frameNavigated" => {
                self.bump_application_epoch()?;
                self.targets.invalidate_inventory_for(
                    super::client_settlement_trace::InventoryRevisionEvent::Navigate,
                    &entry.target,
                )?;
                self.record_frame(
                    &entry,
                    event
                        .params
                        .get("frame")
                        .ok_or(ProtocolError::InvalidFrame)?,
                    true,
                )?;
            }
            "Page.navigatedWithinDocument" => {
                self.bump_application_epoch()?;
                self.targets.invalidate_inventory_for(
                    super::client_settlement_trace::InventoryRevisionEvent::SameDocument,
                    &entry.target,
                )?;
            }
            "Page.frameDetached" => {
                self.bump_application_epoch()?;
                self.targets.invalidate_inventory_for(
                    super::client_settlement_trace::InventoryRevisionEvent::FrameDetach,
                    &entry.target,
                )?;
                let frame = field(&event.params, "frameId")?;
                let mut index = self
                    .index
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if index
                    .frames
                    .get(frame)
                    .is_some_and(|owner| owner.session == entry.session)
                {
                    let mut ids = vec![frame.to_owned()];
                    while let Some(id) = ids.pop() {
                        ids.extend(
                            index
                                .frames
                                .iter()
                                .filter(|(_, owner)| owner.parent.as_deref() == Some(&id))
                                .map(|(id, _)| id.clone()),
                        );
                        index.frames.remove(&id);
                    }
                }
            }
            _ => {}
        }
        let navigation = self.app_navigation(&entry, &routed)?;
        let lease = self.lease(&entry)?;
        self.network.publish_app_event(
            &lease,
            &routed,
            navigation
                .as_ref()
                .map(|(kind, name)| AppNavigationContext {
                    kind: *kind,
                    frame_name: name.as_deref(),
                    initiated_by_operation: false,
                }),
        )?;
        lease.permit.check()?;
        self.page.network_event(&entry.root, &routed)?;
        match budget {
            Some(budget) => self.network.event_with_budget(&routed, budget),
            None => self.network.event(&routed),
        }
    }
    pub fn seal(&self) {
        self.targets.seal_admission();
        self.sealed.store(true, Ordering::Release);
        self.stop.send_replace(CancelSignal::SessionClosed);
        self.changed.notify_waiters();
    }
    /// Observe this exact owner's existing terminal signal. This grants no
    /// replacement authority and cannot miss a seal preceding subscription.
    pub(crate) async fn wait_retired(&self) {
        let mut stop = self.stop.subscribe();
        while *stop.borrow() == CancelSignal::None {
            if stop.changed().await.is_err() {
                return;
            }
        }
    }
    /// The lifecycle journal, not a local read or a failing producer, owns this
    /// stamp. Sealing still rejects every new application/observation admission.
    pub(crate) fn retirement_targets(&self) -> &Arc<ClientTargets> {
        &self.targets
    }
    pub(crate) fn seal_for_owner_retirement(
        &self,
        authority: &super::client_browser::OwnerRetirement,
    ) {
        self.targets.seal_for_owner_retirement(authority);
        self.seal();
    }
    pub async fn drain(&self) -> Result<(), ProtocolError> {
        let mut slot = self.supervisor.lock().await;
        if let Some(task) = slot.as_mut() {
            let result = task
                .await
                .map_err(|_| ProtocolError::CleanupFailed)
                .and_then(|value| value);
            *slot = None;
            if let Err(error) = result {
                self.poison(error.clone());
                return Err(error);
            }
        }
        drop(slot);
        let index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        match &index.failure {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
    pub async fn close(&self) -> Result<(), ProtocolError> {
        self.seal();
        self.drain().await
    }
}
fn observer_retirement_snapshot(
    index: &Index,
    sealed: bool,
    target: &str,
    session: Option<&str>,
    received: u64,
) -> Result<Option<bool>, ProtocolError> {
    if let Some(error) = &index.failure {
        return Err(error.clone());
    }
    if sealed {
        return Err(ProtocolError::Cancelled);
    }
    Ok((index.applied_watermark >= received).then(|| {
        index.retired_observer_targets.contains(target)
            && session.is_none_or(|session| index.retired_observer_sessions.contains(session))
            && !index
                .sessions
                .values()
                .any(|entry| entry.target == target || session == Some(entry.session.as_str()))
    }))
}
fn validate_capture_target_info(
    entry: &Attribution,
    info: &Value,
    context: &str,
    require_attached: bool,
) -> Result<(), ProtocolError> {
    let target = field(info, "targetId")?;
    let actual_context = field(info, "browserContextId")?;
    let kind = field(info, "type")?;
    if require_attached {
        match info.get("attached").and_then(Value::as_bool) {
            Some(true) => {}
            Some(false) => return Err(ProtocolError::StaleScope),
            None => return Err(ProtocolError::InvalidFrame),
        }
    }
    if target != entry.target || actual_context != context || kind != entry.kind {
        return Err(ProtocolError::StaleScope);
    }
    Ok(())
}
fn capture_admission_ready(index: &Index, received: u64) -> bool {
    index.applied_watermark >= received && index.pending_enrollment.is_empty()
}
// Retain historical pairs as tombstones. Only exact observed retirement, not
// map removal or absence alone, makes a pair complete for a fresh input lease.
fn restart_page_pair_retired(index: &Index, target: &str, root: &str) -> bool {
    index.retiring_pages.get(target).map(String::as_str) == Some(root)
        && index.retired_page_sessions.contains(root)
        && !index.sessions.contains_key(root)
        && !index
            .sessions
            .values()
            .any(|entry| entry.target == target || entry.root == root)
}
fn restart_retirements_settled(index: &Index, received: u64) -> bool {
    capture_admission_ready(index, received)
        && index.borrowed_restart.is_none()
        && index
            .retiring_pages
            .iter()
            .all(|(target, root)| restart_page_pair_retired(index, target, root))
}
fn capture_frame_fingerprint(
    session: &str,
    tree: &Value,
    depth: usize,
    frames: &mut Vec<(String, String, String, String)>,
) -> Result<(), ProtocolError> {
    if depth > 64 || frames.len() >= MAX_FRAMES {
        return Err(ProtocolError::CapacityExceeded);
    }
    let frame = tree.get("frame").ok_or(ProtocolError::InvalidFrame)?;
    let id = field(frame, "id")?;
    let loader = frame
        .get("loaderId")
        .and_then(Value::as_str)
        .ok_or(ProtocolError::InvalidFrame)?;
    let url = frame
        .get("url")
        .and_then(Value::as_str)
        .ok_or(ProtocolError::InvalidFrame)?;
    if loader.is_empty() && url != "about:blank" {
        return Err(ProtocolError::InvalidFrame);
    }
    if frames
        .iter()
        .any(|(owner, frame, _, _)| owner == session && frame == id)
    {
        return Err(ProtocolError::InvalidFrame);
    }
    if loader.len() > 1024 || url.len() > 65536 {
        return Err(ProtocolError::CapacityExceeded);
    }
    frames.push((
        session.to_owned(),
        id.to_owned(),
        loader.to_owned(),
        url.to_owned(),
    ));
    if let Some(children) = tree.get("childFrames").and_then(Value::as_array) {
        for child in children {
            capture_frame_fingerprint(session, child, depth + 1, frames)?;
        }
    }
    Ok(())
}
// Test-only evidence for the existing hosted state-capture fixture. Private
// lookup keys are never Debug/serialized. Only bounded ordinals, closed tags,
// and validated structural TargetInfo.type tokens reach output. Unknown native
// types are never inferred from the old Other bin.
// Negotiated BrowserManager::connect_owned_browser / launch_owned do not enable
// Target discovery. This tap issues no setDiscoverTargets command: absence of
// targetDestroyed is inconclusive, even though the separate fixture host client
// enables discovery. A received destruction is evidence, never authority here.
#[cfg(test)]
const CAPTURE_TRACE_LIMIT: usize = 128;
#[cfg(test)]
const CAPTURE_TARGET_TYPE_LIMIT: usize = 32;
/// This field is sourced only from TargetInfo.type (or its stored kind), never
/// from URL, title, target/session IDs, or arbitrary event content. Accept only
/// short lowercase ASCII protocol tokens; invalid values are never truncated or
/// echoed. Classification remains diagnostic and grants no target authority.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
enum CaptureStructuralTargetType {
    Token(String),
    Missing,
    Invalid,
    Oversized,
}
#[cfg(test)]
impl CaptureStructuralTargetType {
    fn from_value(value: Option<&Value>) -> Self {
        match value {
            None => Self::Missing,
            Some(Value::String(value)) => Self::from_str(value),
            Some(_) => Self::Invalid,
        }
    }
    fn from_str(value: &str) -> Self {
        if value.len() > CAPTURE_TARGET_TYPE_LIMIT {
            Self::Oversized
        } else if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            Self::Invalid
        } else {
            Self::Token(value.to_owned())
        }
    }
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureTargetKind {
    Page,
    Iframe,
    Worker,
    ServiceWorker,
    SharedWorker,
    Tab,
    Browser,
    BackgroundPage,
    WebView,
    CdpOther,
    Unrecognized,
    Missing,
}
#[cfg(test)]
impl CaptureTargetKind {
    fn from_native(kind: Option<&str>) -> Self {
        match kind {
            Some("page") => Self::Page,
            Some("iframe") => Self::Iframe,
            Some("worker") => Self::Worker,
            Some("service_worker") => Self::ServiceWorker,
            Some("shared_worker") => Self::SharedWorker,
            Some("tab") => Self::Tab,
            Some("browser") => Self::Browser,
            Some("background_page") => Self::BackgroundPage,
            Some("webview") => Self::WebView,
            Some("other") => Self::CdpOther,
            Some(_) => Self::Unrecognized,
            None => Self::Missing,
        }
    }
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureLifecycleStep {
    EnrollingExisting,
    RegisteringAttached,
    Attached,
    InfoChanged,
    Detached,
    Destroyed,
    Registered,
    Resumed,
    Removed,
    MissingInventory,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureRegistryBinding {
    Absent,
    ConflictingIds,
    // A diagnostic snapshot has no insertion-generation credential. Even exact
    // identifiers may have been reused; ordered trace rows expose that history.
    MatchingIdsTenureUnknown,
}
#[cfg(test)]
fn capture_registry_binding(entry: &Attribution, index: &Index) -> CaptureRegistryBinding {
    match index.sessions.get(&entry.session) {
        None => CaptureRegistryBinding::Absent,
        Some(current)
            if entry.target == current.target
                && entry.session == current.session
                && entry.root == current.root
                && entry.parent == current.parent
                && entry.kind == current.kind =>
        {
            CaptureRegistryBinding::MatchingIdsTenureUnknown
        }
        Some(_) => CaptureRegistryBinding::ConflictingIds,
    }
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureInitialToolbarShape {
    InitialToolbarShape,
    Other,
    Missing,
    Invalid,
}
#[cfg(test)]
impl CaptureInitialToolbarShape {
    fn from_value(value: Option<&Value>) -> Self {
        let Some(value) = value else {
            return Self::Missing;
        };
        let Some(value) = value.as_str() else {
            return Self::Invalid;
        };
        if value.len() > 65536 || value.chars().any(char::is_control) {
            return Self::Invalid;
        }
        let Ok(url) = url::Url::parse(value) else {
            return Self::Invalid;
        };
        // Chromium 156.0.8078.47 waap::IsForInitialWebUI also requires effective
        // InitialWebUI and WebUIReloadButton flags. Shape is not that predicate,
        // not proof of the GetTargets exclusion branch, and never authority.
        if url.scheme() == "chrome"
            && url
                .host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case("webui-toolbar.top-chrome"))
        {
            Self::InitialToolbarShape
        } else {
            Self::Other
        }
    }
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
enum CaptureTargetLookup {
    Found {
        target_matches: bool,
        context_matches: bool,
        kind_matches: bool,
        native_type: CaptureStructuralTargetType,
        url_shape: CaptureInitialToolbarShape,
    },
    CommandFailure,
    InvalidShape,
    Cancelled,
    Deadline,
    SkippedBindingUnavailable,
    SkippedCoordinatorUnavailable,
}
#[cfg(test)]
fn capture_target_lookup(value: &Value, entry: &Attribution, context: &str) -> CaptureTargetLookup {
    let Some(info) = value.get("targetInfo").filter(|info| info.is_object()) else {
        return CaptureTargetLookup::InvalidShape;
    };
    let (Ok(target), Ok(returned_context), Ok(kind)) = (
        field(info, "targetId"),
        field(info, "browserContextId"),
        field(info, "type"),
    ) else {
        return CaptureTargetLookup::InvalidShape;
    };
    let native_type = CaptureStructuralTargetType::from_str(kind);
    if !matches!(native_type, CaptureStructuralTargetType::Token(_)) {
        return CaptureTargetLookup::InvalidShape;
    }
    CaptureTargetLookup::Found {
        target_matches: target == entry.target,
        context_matches: returned_context == context,
        kind_matches: kind == entry.kind,
        native_type,
        url_shape: CaptureInitialToolbarShape::from_value(info.get("url")),
    }
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureLookupEventState {
    ReceivedPending,
    NoReceivedPendingUnreceivedUnknown,
    Unavailable,
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CaptureLookupSnapshot {
    application_epoch: Option<u64>,
    received: Option<u64>,
    applied: Option<u64>,
    event_state: CaptureLookupEventState,
    binding: Option<CaptureRegistryBinding>,
    pending_enrollment: Option<bool>,
    retirement_pending: Option<bool>,
    retired_binding: Option<bool>,
    reconciled: Option<bool>,
    coordinator_failed: Option<bool>,
    sealed: bool,
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CaptureMissingTargetDiagnostic {
    target: Option<u16>,
    session: Option<u16>,
    missing_count: usize,
    truncated: bool,
    dropped: usize,
    ids_exhausted: bool,
    lookup: CaptureTargetLookup,
    before: CaptureLookupSnapshot,
    after: CaptureLookupSnapshot,
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CaptureLifecycleRow {
    order: u64,
    elapsed_ms: u64,
    watermark: u64,
    step: CaptureLifecycleStep,
    target: Option<u16>,
    session: Option<u16>,
    native_kind: CaptureTargetKind,
    native_type: CaptureStructuralTargetType,
    registered_kind: CaptureTargetKind,
    registered_type: CaptureStructuralTargetType,
    registry_binding: CaptureRegistryBinding,
    application: bool,
    observation_only: bool,
    resumed: bool,
    parent: bool,
    application_epoch: u64,
}
#[cfg(test)]
struct CaptureLifecycleTrace {
    started: Instant,
    order: u64,
    dropped: usize,
    ids_exhausted: bool,
    targets: HashMap<String, u16>,
    sessions: HashMap<String, u16>,
    rows: std::collections::VecDeque<CaptureLifecycleRow>,
    missing_lookup: Option<CaptureMissingTargetDiagnostic>,
}
#[cfg(test)]
impl Default for CaptureLifecycleTrace {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            order: 0,
            dropped: 0,
            ids_exhausted: false,
            targets: HashMap::new(),
            sessions: HashMap::new(),
            rows: std::collections::VecDeque::new(),
            missing_lookup: None,
        }
    }
}
#[cfg(test)]
impl CaptureLifecycleTrace {
    fn record_missing_lookup(
        &mut self,
        mut diagnostic: CaptureMissingTargetDiagnostic,
        output: &mut impl std::io::Write,
    ) {
        if self.missing_lookup.is_some() {
            self.dropped = self.dropped.saturating_add(1);
        }
        diagnostic.dropped = self.dropped;
        diagnostic.ids_exhausted = self.ids_exhausted;
        // Unlike eprintln!, a failed diagnostic write cannot replace StaleScope.
        if writeln!(output, "state.capture missing_target_lookup={diagnostic:?}").is_err() {
            self.dropped = self.dropped.saturating_add(1);
            diagnostic.dropped = self.dropped;
        }
        self.missing_lookup = Some(diagnostic);
    }
    fn token(
        map: &mut HashMap<String, u16>,
        value: Option<&str>,
        exhausted: &mut bool,
    ) -> Option<u16> {
        let value = value?;
        if let Some(token) = map.get(value) {
            return Some(*token);
        }
        if value.is_empty() || value.len() > 1024 || map.len() >= CAPTURE_TRACE_LIMIT {
            *exhausted = true;
            return None;
        }
        let token = (map.len() + 1) as u16;
        map.insert(value.to_owned(), token);
        Some(token)
    }
    // Keep each closed diagnostic field explicit at test-only call sites.
    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        step: CaptureLifecycleStep,
        target: Option<&str>,
        session: Option<&str>,
        native_type: Option<&Value>,
        entry: Option<&Attribution>,
        index: &Index,
        watermark: u64,
    ) {
        self.order = self.order.saturating_add(1);
        let target = Self::token(&mut self.targets, target, &mut self.ids_exhausted);
        let session = Self::token(&mut self.sessions, session, &mut self.ids_exhausted);
        let row = CaptureLifecycleRow {
            order: self.order,
            elapsed_ms: self.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            watermark,
            step,
            target,
            session,
            native_kind: CaptureTargetKind::from_native(native_type.and_then(Value::as_str)),
            native_type: CaptureStructuralTargetType::from_value(native_type),
            registered_kind: CaptureTargetKind::from_native(entry.map(|entry| entry.kind.as_str())),
            registered_type: entry.map_or(CaptureStructuralTargetType::Missing, |entry| {
                CaptureStructuralTargetType::from_str(&entry.kind)
            }),
            registry_binding: entry.map_or(CaptureRegistryBinding::Absent, |entry| {
                capture_registry_binding(entry, index)
            }),
            application: entry.is_some_and(|entry| entry.application),
            observation_only: entry.is_some_and(|entry| entry.observation_only),
            resumed: entry.is_some_and(|entry| entry.resumed),
            parent: entry.is_some_and(|entry| entry.parent.is_some()),
            application_epoch: index.application_epoch,
        };
        if self.rows.len() == CAPTURE_TRACE_LIMIT {
            self.rows.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.rows.push_back(row);
    }
    fn event(&mut self, event: &CdpEvent, watermark: u64, index: &Index) {
        let step = match event.method.as_str() {
            "Target.attachedToTarget" => CaptureLifecycleStep::Attached,
            "Target.targetInfoChanged" => CaptureLifecycleStep::InfoChanged,
            "Target.detachedFromTarget" => CaptureLifecycleStep::Detached,
            "Target.targetDestroyed" => CaptureLifecycleStep::Destroyed,
            _ => return,
        };
        let info = event.params.get("targetInfo");
        let target = info
            .and_then(|info| info.get("targetId"))
            .or_else(|| event.params.get("targetId"))
            .and_then(Value::as_str);
        let session = event.params.get("sessionId").and_then(Value::as_str);
        let entry = session
            .and_then(|session| index.sessions.get(session))
            .or_else(|| {
                target
                    .and_then(|target| index.sessions.values().find(|entry| entry.target == target))
            });
        self.push(
            step,
            target.or_else(|| entry.map(|entry| entry.target.as_str())),
            session.or_else(|| entry.map(|entry| entry.session.as_str())),
            info.and_then(|info| info.get("type")),
            entry,
            index,
            watermark,
        );
    }
    fn registry(&mut self, step: CaptureLifecycleStep, entry: &Attribution, index: &Index) {
        self.push(
            step,
            Some(&entry.target),
            Some(&entry.session),
            None,
            Some(entry),
            index,
            index.applied_watermark,
        );
    }
}
/// Closed, count-only diagnostics. Never print target/session/context IDs, URLs,
/// titles, or browser-provided type strings when capture refuses inventory.
#[cfg(test)]
#[derive(Debug, Default, PartialEq, Eq)]
struct CaptureInventoryDiagnostic {
    entries: usize,
    inventory: usize,
    missing: usize,
    absent_target: usize,
    missing_context: usize,
    foreign_context: usize,
    application: usize,
    observation_only: usize,
    page: usize,
    iframe: usize,
    worker: usize,
    other: usize,
    parent: usize,
}
#[cfg(test)]
fn capture_inventory_diagnostic(
    entries: &[Attribution],
    infos: &[Value],
    context: &str,
) -> CaptureInventoryDiagnostic {
    let mut result = CaptureInventoryDiagnostic {
        entries: entries.len(),
        inventory: infos.len(),
        ..Default::default()
    };
    for entry in entries {
        let matches = infos.iter().filter(|info| {
            info.get("targetId").and_then(Value::as_str) == Some(entry.target.as_str())
        });
        if matches
            .clone()
            .any(|info| info.get("browserContextId").and_then(Value::as_str) == Some(context))
        {
            continue;
        }
        result.missing += 1;
        if matches.clone().next().is_none() {
            result.absent_target += 1;
        } else if matches.clone().any(|info| {
            info.get("browserContextId")
                .and_then(Value::as_str)
                .is_none()
        }) {
            result.missing_context += 1;
        } else {
            result.foreign_context += 1;
        }
        result.application += usize::from(entry.application);
        result.observation_only += usize::from(entry.observation_only);
        result.parent += usize::from(entry.parent.is_some());
        match entry.kind.as_str() {
            "page" => result.page += 1,
            "iframe" => result.iframe += 1,
            "worker" | "service_worker" | "shared_worker" => result.worker += 1,
            _ => result.other += 1,
        }
    }
    result
}
fn autoattach(enabled: bool) -> Value {
    let mut params = json!({"autoAttach":enabled,"waitForDebuggerOnStart":enabled,"flatten":true});
    if enabled {
        params["filter"] =
            json!([{"type":"browser","exclude":true},{"type":"tab","exclude":true},{}]);
    }
    params
}
fn valid_id(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > 1024 {
        Err(ProtocolError::InvalidFrame)
    } else {
        Ok(())
    }
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, ProtocolError> {
    let value = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ProtocolError::InvalidFrame)?;
    valid_id(value)?;
    Ok(value)
}
async fn bounded<T>(
    op: &OperationLease,
    future: impl std::future::Future<Output = Result<T, ProtocolError>>,
) -> Result<T, ProtocolError> {
    if *op.cancellation.borrow() != CancelSignal::None {
        return Err(ProtocolError::Cancelled);
    }
    if Instant::now() >= op.deadline {
        return Err(ProtocolError::DeadlineExceeded);
    }
    let mut cancellation = op.cancellation.clone();
    tokio::select! { result=future=>result, _=cancellation.changed()=>Err(ProtocolError::Cancelled), _=tokio::time::sleep_until(op.deadline.into())=>Err(ProtocolError::DeadlineExceeded) }
}

#[cfg(test)]
mod tests {
    use super::super::client_blobs::{BlobLimits, BlobScope, BlobStore};
    use super::super::client_protocol::ServerMessage;
    use super::super::client_session::ClientSession;
    use super::super::client_transport::ClientEventSink;
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    type Log = Arc<Mutex<Vec<Value>>>;
    type Notices = tokio::sync::mpsc::Receiver<ServerMessage>;
    include!("client_restart_readiness_tests.rs");
    fn coordinator(
        client: Arc<CdpClient>,
        context: &str,
        scope: &str,
        active: &str,
    ) -> (Arc<ClientEnrollment>, Notices, Arc<ClientSession>) {
        coordinator_with_ui(
            client,
            context,
            scope,
            active,
            Arc::new(super::super::client_ui::UiGate::default()),
        )
    }
    fn coordinator_with_ui(
        client: Arc<CdpClient>,
        context: &str,
        scope: &str,
        active: &str,
        ui: Arc<super::super::client_ui::UiGate>,
    ) -> (Arc<ClientEnrollment>, Notices, Arc<ClientSession>) {
        let broker = Arc::new(ClientSession::new());
        let (sink, notices) = ClientEventSink::test_channel(broker.clone());
        // Match production's scoped, writer-acknowledged lifecycle sink.
        let (_cancel, cancellation) = watch::channel(CancelSignal::None);
        let stage_op = OperationLease {
            generation: 1,
            sequence: 900,
            is_callback: false,
            deadline: Instant::now() + Duration::from_secs(60),
            cancellation,
        };
        let scoped_sink = sink.stage_until_result(&stage_op, scope).unwrap();
        sink.acknowledge_result_for_test(&ServerMessage::Result {
            id: "initial".into(),
            generation: 1,
            operation_seq: 900,
            ok: true,
            data: Some(json!({"identityScope":scope})),
            error: None,
            effects: super::super::client_protocol::Effects::Completed,
            scope_state: super::super::client_protocol::ScopeState::Usable,
            retention: None,
        })
        .unwrap();
        let sink = scoped_sink;
        let blobs = Arc::new(BlobStore::new(BlobLimits::default()).unwrap());
        let blob_scope = BlobScope {
            generation: 1,
            identity_scope: scope.into(),
        };
        blobs.activate_scope(blob_scope.clone()).unwrap();
        let network = Arc::new(ClientNetwork::new(
            client.clone(),
            broker.clone(),
            sink,
            blob_scope,
            blobs,
            ui,
            super::super::client_network::NetworkPolicy::default(),
        ));
        (
            ClientEnrollment::new(
                client,
                ClientTargets::new(context.into(), scope.into()),
                Arc::new(ClientPageState::new(scope.into(), context.into())),
                network,
                Arc::new(ExecutionGate::default()),
                1,
                active.into(),
                ScopeConfig {
                    viewport: Some((700, 500)),
                    locale: Some("en-US".into()),
                    ..Default::default()
                },
                ScopeOwnership::IsolatedContext,
                None,
            ),
            notices,
            broker,
        )
    }
    async fn fixture(
        mode: &'static str,
    ) -> (
        Arc<ClientEnrollment>,
        Notices,
        Log,
        tokio::sync::mpsc::Sender<Value>,
        JoinHandle<()>,
    ) {
        let (owner, notices, log, emit, server, _broker) = fixture_with_broker(mode).await;
        (owner, notices, log, emit, server)
    }
    async fn fixture_with_broker(
        mode: &'static str,
    ) -> (
        Arc<ClientEnrollment>,
        Notices,
        Log,
        tokio::sync::mpsc::Sender<Value>,
        JoinHandle<()>,
        Arc<ClientSession>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let log: Log = Arc::default();
        let recorded = log.clone();
        let (emit, mut emitted) = tokio::sync::mpsc::channel::<Value>(64);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut worker_held = Vec::<Value>::new();
            let mut detach_count = 0;
            let mut inventory_reads = 0;
            let mut realm_loader = "synthetic-loader".to_owned();
            let mut whitespace = HashMap::<String, bool>::new();
            let mut closed_targets = std::collections::HashSet::<String>::new();
            loop {
                tokio::select! {
                    event=emitted.recv()=> {
                        let Some(event)=event else {break};
                        if event["method"]=="Page.frameNavigated" {
                            if let Some(loader)=event["params"]["frame"]["loaderId"].as_str() { realm_loader=loader.to_owned(); }
                        }
                        if socket.send(Message::Text(event.to_string())).await.is_err(){break;}
                    },
                    message=socket.next()=> {
                        let Some(Ok(Message::Text(text)))=message else {break};
                        let request:Value=serde_json::from_str(&text).unwrap();
                        recorded.lock().unwrap().push(request.clone());
                        let method=request["method"].as_str().unwrap();
                        if mode.starts_with("sw-startup-") && request["sessionId"]=="worker-session" {
                            if matches!(method,"Network.enable"|"Network.setBypassServiceWorker"|"Runtime.enable") {
                                worker_held.push(request.clone());
                                continue;
                            }
                            if mode=="sw-startup-main-script" && method=="Runtime.runIfWaitingForDebugger" {
                                socket.send(Message::Text(json!({"method":"Fetch.requestPaused","sessionId":"worker-session","params":{"requestId":"worker-main-script","request":{"url":"https://synthetic.test/sw.js","method":"GET","headers":{}}}}).to_string())).await.unwrap();
                            }
                            if (method=="Runtime.runIfWaitingForDebugger" && mode!="sw-startup-main-script") || (method=="Fetch.continueRequest" && mode=="sw-startup-main-script") {
                                for held in worker_held.drain(..) {
                                    let response = if mode=="sw-startup-observer-fails" && held["method"]=="Runtime.enable" {
                                        json!({"id":held["id"],"sessionId":held["sessionId"],"error":{"code":-32000,"message":"synthetic observer failure"}})
                                    } else { json!({"id":held["id"],"sessionId":held["sessionId"],"result":{}}) };
                                    socket.send(Message::Text(response.to_string())).await.unwrap();
                                }
                            }
                        }

                        if method=="Target.getTargets" { inventory_reads += 1; }
                        // Test-controlled ACK: tests can apply exact lifecycle
                        // events, cancellation, or a deadline before the reply.
                        if mode=="attestation-diagnostic-held" && method=="Target.getTargetInfo" { continue; }
                        if mode=="retired-detach-held" && method=="Target.detachFromTarget" { continue; }
                        if matches!(mode,"observer-close"|"observer-unknown-error"|"observer-detached-live") && method=="Page.enable" && request["sessionId"]=="observer" {
                            if mode!="observer-unknown-error" { socket.send(Message::Text(json!({"method":"Target.detachedFromTarget","params":{"sessionId":"observer","targetId":"other-host"}}).to_string())).await.unwrap(); }
                            socket.send(Message::Text(json!({"id":request["id"],"error":{"code":-32000,"message":"target closed"}}).to_string())).await.unwrap();continue;
                        }
                        if mode=="delayed-dispose" && method=="Target.disposeBrowserContext" {tokio::time::sleep(Duration::from_millis(40)).await;}
                        if mode=="popup-held-dispose" {
                            if method=="Runtime.evaluate" && request["sessionId"]=="initial" && request["params"]["expression"]=="window.open('https://synthetic.test/first')" {
                                socket.send(Message::Text(json!({"method":"Target.attachedToTarget","params":{"sessionId":"popup-session","waitingForDebugger":true,"targetInfo":{"targetId":"popup-target","browserContextId":"owned-context","type":"page","openerId":"initial-target"}}}).to_string())).await.unwrap();
                                // Keep the raw opener reply pending until exact detach.
                                continue;
                            }
                            if method=="Target.disposeBrowserContext" {
                                assert_eq!(request["params"]["browserContextId"], "owned-context");
                                socket.send(Message::Text(json!({"method":"Target.detachedFromTarget","params":{"sessionId":"initial","targetId":"initial-target"}}).to_string())).await.unwrap();
                                // Detach wakes only the opener waiter. The test alone
                                // supplies the independent browser-context disposal ACK.
                                continue;
                            }
                        }
                        if method=="Target.detachFromTarget" {detach_count+=1;}
                        if mode=="hold-timezone" && method=="Emulation.setTimezoneOverride" { continue; }
                        if mode=="popup-runtime-held" && method=="Runtime.enable" && request["sessionId"]=="popup-session" { continue; }
                        let settings_error = match (mode, method) {
                            ("locale-already", "Emulation.setLocaleOverride") => Some("Another locale override is already in effect"),
                            ("timezone-already", "Emulation.setTimezoneOverride") => Some("Timezone override is already in effect"),
                            ("invalid-timezone", "Emulation.setTimezoneOverride") => Some("Invalid timezone"),
                            ("popup-held-dispose", "Emulation.setTimezoneOverride") if request["sessionId"]=="popup-session" => Some("Invalid timezone"),
                            (_, "Target.setAutoAttach") if request["params"]["autoAttach"]==false && request["params"].get("filter").and_then(Value::as_array).is_some_and(|v|!v.is_empty()) => Some("Target filter should be empty when disabling auto-attach"),
                            _=>None,
                        };
                        if let Some(error)=settings_error {
                            socket.send(Message::Text(json!({"id":request["id"],"error":{"code":-32602,"message":error}}).to_string())).await.unwrap();continue;
                        }
                        if method=="Target.closeTarget" {closed_targets.insert(request["params"]["targetId"].as_str().unwrap().to_owned());}
                        if mode=="late-borrowed" && method=="Fetch.disable" {
                            socket.send(Message::Text(json!({"method":"Target.attachedToTarget","params":{"sessionId":"late-borrowed","waitingForDebugger":true,"targetInfo":{"targetId":"late-host-popup","browserContextId":"owned-context","type":"page","openerId":"initial-target"}}}).to_string())).await.unwrap();
                        }
                        if (mode=="fail-remove-script" && method=="Page.removeScriptToEvaluateOnNewDocument") || (mode=="fail-fetch" && method=="Fetch.enable") || (mode=="detach-fallback" && method=="Target.detachFromTarget" && detach_count==1) {
                            socket.send(Message::Text(json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic injected failure"}}).to_string())).await.unwrap();continue;
                        }
                        if (mode=="first-request" || mode=="large-first-request" || mode=="hold-timezone" || (mode=="popup-held-dispose" && request["sessionId"]=="popup-session")) && method=="Fetch.enable" {
                            let body=if mode=="large-first-request" {"b".repeat(1536*1024)} else {String::new()};
                            socket.send(Message::Text(json!({"method":"Fetch.requestPaused","sessionId":request["sessionId"],"params":{"requestId":"first","request":{"url":"https://synthetic.test/first","method":"POST","headers":{},"postData":body}}}).to_string())).await.unwrap();
                        }
                        if mode.starts_with("realm-resolve-reuse") {
                            if method=="Page.createIsolatedWorld" {
                                socket.send(Message::Text(realm_created(7,"before-resolve").to_string())).await.unwrap();
                            }
                            if method=="DOM.resolveNode" {
                                // Hold the successful resolver ACK until native lifecycle
                                // events establish destruction and numeric-ID reuse.
                                socket.send(Message::Text(json!({"method":"Runtime.executionContextDestroyed","sessionId":"initial","params":{"executionContextId":7,"executionContextUniqueId":"before-resolve"}}).to_string())).await.unwrap();
                                socket.send(Message::Text(realm_created(7,"after-resolve").to_string())).await.unwrap();
                            }
                            if mode=="realm-resolve-reuse-release-fails" && method=="Runtime.releaseObject" {
                                socket.send(Message::Text(json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic release failure"}}).to_string())).await.unwrap();continue;
                            }
                        }
                        if mode=="dom-enable-fails" && method=="DOM.enable" {
                            socket.send(Message::Text(json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic DOM enable failure"}}).to_string())).await.unwrap();continue;
                        }
                        if matches!(method,"DOM.enable"|"DOM.getDocument") {
                            let session=request["sessionId"].as_str().unwrap().to_owned();
                            whitespace.entry(session).or_insert(method=="DOM.enable" && request["params"]["includeWhitespace"]=="all");
                        }
                        let mut result=match method {
                            "DOM.getDocument"=>json!({"root":{"nodeId":1,"children":if whitespace.get(request["sessionId"].as_str().unwrap())==Some(&true) {vec![json!({"nodeId":2,"nodeType":3,"nodeValue":" "})]}else{vec![]}}}),
                            "Page.createIsolatedWorld" if mode.starts_with("realm-resolve-reuse")=>json!({"executionContextId":7}),
                            "DOM.resolveNode" if mode.starts_with("realm-resolve-reuse")=>json!({"object":{"objectId":"replacement-handle","subtype":"node"}}),
                            "Runtime.callFunctionOn" if mode.starts_with("realm-resolve-reuse")=>json!({"result":{"value":true}}),
                            "Page.getLayoutMetrics"=>json!({"cssVisualViewport":{"clientWidth":800.,"clientHeight":600.,"offsetX":0.,"offsetY":0.,"scale":1.},"cssLayoutViewport":{"clientWidth":800.,"clientHeight":600.}}),
                            "Target.getTargetInfo" if mode=="observer-context" => json!({"targetInfo":{"targetId":request["params"]["targetId"],"type":"iframe","browserContextId":"owned-context"}}),
                            "Target.getTargetInfo" if mode.starts_with("attestation-") => json!({"targetInfo":{"targetId":"unavailable", "type":"unavailable", "browserContextId":"owned-context", "attached":false}}),
                            "Page.getFrameTree"=>json!({"frameTree":{"frame":{"id":format!("frame-{}",request["sessionId"].as_str().unwrap()),"loaderId":realm_loader,"url":if mode=="borrowed-capture" {"https://initial.test/"} else {"about:blank"}}}}),
                            "Target.getTargets" if mode=="tracked" || mode=="late-popup"=>json!({"targetInfos":[
                                {"targetId":"initial-target","browserContextId":"owned-context","type":"page"},
                                {"targetId":"queued-popup","browserContextId":"owned-context","type":"page","openerId":"initial-target"},
                                {"targetId":"unrelated","browserContextId":"owned-context","type":"page"},
                                {"targetId":"foreign","browserContextId":"other-context","type":"page"}]}),
                            "Target.getTargets" if mode=="observer-detached-live"=>json!({"targetInfos":[{"targetId":"other-host","type":"page","browserContextId":"owned-context"}]}),
                            "Target.getTargets" if mode=="borrowed-capture"=>json!({"targetInfos":[{"targetId":"initial-target","type":"page","browserContextId":"owned-context"},{"targetId":"unadopted-host","type":"page","browserContextId":"owned-context"}]}),
                            "Target.getTargets" if mode=="borrowed-initial"=>json!({"targetInfos":[{"targetId":"initial-target","type":"page","browserContextId":"owned-context"}]}),
                            "Target.getTargets" if mode.starts_with("attestation-complete")=>complete_capture_inventory(mode, &request, inventory_reads),
                            "Target.getTargets" if mode=="attestation-missing-target" && inventory_reads>1=>json!({"targetInfos":[]}),
                            "Target.getTargets" if mode=="attestation-missing-context" && inventory_reads>1=>json!({"targetInfos":[{"targetId":"target","type":"page"}]}),
                            "Target.getTargets" if mode=="attestation-foreign-context" && inventory_reads>1=>json!({"targetInfos":[{"targetId":"target","type":"page","browserContextId":"foreign-context"}]}),
                            "Target.getTargets" if mode=="attestation" || mode.starts_with("attestation-")=>json!({"targetInfos":[{"targetId":"target","type":"page","browserContextId":"owned-context"}]}),
                            "Target.getTargets"=>json!({"targetInfos":[]}),
                            "Target.closeTarget"=>json!({"success":true}),
                            "Browser.getVersion"=>json!({"userAgent":"Synthetic Chromium"}),
                            "Page.addScriptToEvaluateOnNewDocument"=>json!({"identifier":"synthetic-script"}),
                            _=>json!({}),
                        };
                        if method=="Target.getTargets" {if let Some(infos)=result.get_mut("targetInfos").and_then(Value::as_array_mut) {infos.retain(|info|!closed_targets.contains(info["targetId"].as_str().unwrap()) && !(mode=="late-popup" && info["targetId"]=="queued-popup" && !closed_targets.contains("initial-target")));}}
                        if socket.send(Message::Text(json!({"id":request["id"],"result":result}).to_string())).await.is_err(){break;}
                    }
                }
            }
        });
        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        let (owner, notices, broker) =
            coordinator(client, "owned-context", "owned-scope", "initial");
        (owner, notices, log, emit, server, broker)
    }
    // Model the pinned CDP TargetFilter rules, including the default omission
    // of native tab/browser targets. A complete inventory is not an ownership
    // grant: include unrelated targets so production must retain that boundary.
    fn complete_capture_inventory(mode: &str, request: &Value, reads: usize) -> Value {
        let mut tab =
            json!({"targetId":"tab-target","type":"tab","browserContextId":"owned-context"});
        match mode {
            "attestation-complete-missing-context" => {
                tab.as_object_mut().unwrap().remove("browserContextId");
            }
            "attestation-complete-foreign-context" => {
                tab["browserContextId"] = json!("foreign-context");
            }
            _ => {}
        }
        let mut infos = vec![
            json!({"targetId":"target","type":"page","browserContextId":"owned-context"}),
            json!({"targetId":"unowned-tab","type":"tab","browserContextId":"owned-context"}),
            json!({"targetId":"foreign-tab","type":"tab","browserContextId":"foreign-context"}),
            json!({"targetId":"browser","type":"browser"}),
        ];
        if mode != "attestation-complete-missing-target" {
            infos.push(tab);
        }
        if reads > 1 {
            match mode {
                "attestation-complete-unowned-page" => infos.push(json!({
                    "targetId":"unowned-page","type":"page","browserContextId":"owned-context"
                })),
                "attestation-complete-unknown-kind" => infos.push(json!({
                    "targetId":"unknown-kind","type":"future-target-kind","browserContextId":"owned-context"
                })),
                _ => {}
            }
        }
        let default_filter = json!([
            {"type":"browser","exclude":true},
            {"type":"tab","exclude":true},
            {}
        ]);
        let filter = request["params"].get("filter").unwrap_or(&default_filter);
        infos.retain(|info| {
            filter
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry.get("type").is_none() || entry["type"] == info["type"])
                .is_some_and(|entry| entry["exclude"].as_bool() != Some(true))
        });
        json!({"targetInfos":infos})
    }
    fn attach(
        context: &str,
        target: &str,
        session: &str,
        kind: &str,
        parent: Option<&str>,
    ) -> CdpEvent {
        CdpEvent {
            method: "Target.attachedToTarget".into(),
            session_id: parent.map(str::to_owned),
            params: json!({"sessionId":session,"waitingForDebugger":true,"targetInfo":{"targetId":target,"type":kind,"browserContextId":context}}),
        }
    }
    fn diagnostic_url(value: &str) -> String {
        let Ok(parsed) = url::Url::parse(value) else {
            return "[invalid URL]".into();
        };
        if matches!(parsed.scheme(), "http" | "https") {
            let host = parsed.host_str().unwrap_or("");
            if matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1") {
                return format!(
                    "{}://{}{}",
                    parsed.scheme(),
                    host,
                    parsed
                        .path()
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(160)
                        .collect::<String>()
                );
            }
            return format!("{}:[external URL omitted]", parsed.scheme());
        }
        format!(
            "{}:[payload omitted]",
            parsed.scheme().chars().take(24).collect::<String>()
        )
    }
    #[test]
    fn enrollment_diagnostic_urls_are_bounded_and_omit_payload_credentials_and_query() {
        assert_eq!(
            diagnostic_url("http://user:secret@127.0.0.1:1234/must-not-start?token=private#secret"),
            "http://127.0.0.1/must-not-start"
        );
        assert_eq!(
            diagnostic_url(&format!("data:image/png;base64,{}", "a".repeat(100000))),
            "data:[payload omitted]"
        );
        assert_eq!(
            diagnostic_url("https://private.example/path?secret=1"),
            "https:[external URL omitted]"
        );
        assert!(diagnostic_url(&format!("http://127.0.0.1/{}", "a".repeat(100000))).len() < 200);
    }
    async fn realm_test_owner() -> (
        Arc<ClientEnrollment>,
        BrowserExecutionLease,
        Notices,
        tokio::sync::mpsc::Sender<Value>,
        JoinHandle<()>,
    ) {
        let (owner, notices, _log, emit, server) = fixture("normal").await;
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner.start(&owner.operation()).await.unwrap();
        let entry = owner.index.lock().unwrap().sessions["initial"].clone();
        let page = owner.lease(&entry).unwrap();
        (owner, page, notices, emit, server)
    }
    #[tokio::test]
    async fn eval_stamp_uses_native_loader_and_same_identity_refresh_does_not_revoke() {
        let (owner, page, _notices, _emit, server) = realm_test_owner().await;
        let ledger = super::super::client_debt::OwnerDebtLedger::new(
            1,
            owner.targets.identity_scope.clone(),
        );
        owner.client.install_debt_ledger(ledger.clone()).unwrap();
        owner.targets.bind_eval_owner(&ledger, 1).unwrap();
        let mut op = owner.operation();
        op.sequence = 1;
        let _journal = ledger
            .operation(
                super::super::client_debt::OperationKey {
                    generation: op.generation,
                    operation_seq: op.sequence,
                },
                page.target_id.clone(),
                page.page_session_id.clone(),
            )
            .unwrap();
        let stamp = owner.capture_eval_authority(&page, &op).unwrap();
        assert_eq!(stamp.loader, "synthetic-loader");
        let entry = owner.index.lock().unwrap().sessions["initial"].clone();
        owner
            .record_frame(
                &entry,
                &json!({"id":"frame-initial", "loaderId":"synthetic-loader"}),
                false,
            )
            .unwrap();
        assert_eq!(
            owner.capture_eval_authority(&page, &op).unwrap().revision,
            stamp.revision
        );
        owner
            .record_frame(
                &entry,
                &json!({"id":"frame-initial", "loaderId":"replacement-loader"}),
                false,
            )
            .unwrap();
        let next = owner.capture_eval_authority(&page, &op).unwrap();
        assert_eq!(next.loader, "replacement-loader");
        assert!(next.revision > stamp.revision);
        owner
            .record_frame(&entry, &json!({"id":"frame-initial"}), false)
            .unwrap();
        assert!(matches!(
            owner.capture_eval_authority(&page, &op),
            Err(ProtocolError::InvalidFrame)
        ));
        owner.targets.seal_admission();
        assert!(owner.capture_eval_authority(&page, &op).is_err());
        owner.client.close().await;
        server.abort();
    }
    #[tokio::test]
    async fn eval_capture_rejects_observed_unpublished_and_published_unapplied_events() {
        use super::super::client_debt::{OperationKey, OwnerDebtLedger};
        let (owner, page, _notices, emit, server) = realm_test_owner().await;
        let ledger = OwnerDebtLedger::new(1, owner.targets.identity_scope.clone());
        owner.client.install_debt_ledger(ledger.clone()).unwrap();
        owner.targets.bind_eval_owner(&ledger, 1).unwrap();
        let mut op = owner.operation();
        op.sequence = 1;
        let _journal = ledger
            .operation(
                OperationKey {
                    generation: op.generation,
                    operation_seq: op.sequence,
                },
                page.target_id.clone(),
                page.page_session_id.clone(),
            )
            .unwrap();
        let stamp = owner.capture_eval_authority(&page, &op).unwrap();
        let watermark = owner.realm_watermark().unwrap();
        let received = watermark.received().unwrap();
        let event = super::super::cdp::types::CdpEvent {
            method: "Page.frameNavigated".into(),
            session_id: Some("initial".into()),
            params: json!({"frame":{"id":"frame-initial","loaderId":"next-loader","url":"about:blank"}}),
        };
        // Simulate the synchronous reader boundary before any bounded publication.
        let publication = ledger.observe_event_for_publication(&event).unwrap();
        assert_eq!(watermark.received(), Ok(received));
        assert!(owner.capture_eval_authority(&page, &op).is_err());
        publication.complete();
        // Now use the real reader and existing deterministic enrollment gate.
        let gate = CaptureTestGate::new();
        owner
            .capture_test_gates
            .lock()
            .unwrap()
            .insert(CaptureTestPoint::BeforeEventApply, gate.clone());
        emit.send(
            json!({"method":event.method,"sessionId":event.session_id,"params":event.params}),
        )
        .await
        .unwrap();
        gate.wait_entered().await;
        let pending_application = owner.capture_eval_authority(&page, &op);
        assert!(watermark.received().unwrap() > received);
        gate.release();
        owner
            .drain_capture_watermark(&watermark, &op)
            .await
            .unwrap();
        assert!(pending_application.is_err());
        let next = owner.capture_eval_authority(&page, &op).unwrap();
        assert_eq!(next.loader, "next-loader");
        assert!(next.revision > stamp.revision);
        *owner.event_watermark.lock().unwrap() = None;
        assert!(
            owner.capture_eval_authority(&page, &op).is_err(),
            "no subscription is not application proof"
        );
        owner.client.close().await;
        server.abort();
    }

    fn realm_test_binding() -> super::super::element::ExactBinding {
        super::super::element::ExactBinding {
            page_session: "initial".into(),
            session: "initial".into(),
            frame: "frame-initial".into(),
            loader: "synthetic-loader".into(),
            actionable: true,
        }
    }
    fn realm_created(id: i64, unique: &str) -> Value {
        json!({"method":"Runtime.executionContextCreated","sessionId":"initial","params":{"context":{"id":id,"uniqueId":unique,"name":"agent-browser-native-observation","auxData":{"frameId":"frame-initial","isDefault":false}}}})
    }
    async fn realm_emit(
        owner: &Arc<ClientEnrollment>,
        emit: &tokio::sync::mpsc::Sender<Value>,
        event: Value,
    ) {
        let watermark = owner.realm_watermark().unwrap();
        let before = watermark.received().unwrap();
        emit.send(event).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while watermark.received().unwrap() == before {
                tokio::task::yield_now().await;
            }
            owner
                .drain_capture_watermark(&watermark, &owner.operation())
                .await
                .unwrap();
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn settled_input_authority_is_exact_and_ignores_only_requested_cancellation() {
        let (owner, mut page, _notices, _emit, server) = realm_test_owner().await;
        let (cancel, cancellation) = watch::channel(CancelSignal::None);
        let mut op = owner.operation();
        op.sequence = 77;
        op.cancellation = cancellation;
        let mut proof = owner.capture_settled_input_authority(&page, &op).unwrap();
        op.is_callback = true;
        assert!(matches!(
            owner.capture_settled_input_authority(&page, &op),
            Err(ProtocolError::InvalidArguments)
        ));
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::StaleScope)
        );
        op.is_callback = false;
        let captured_deadline = op.deadline;
        op.deadline += Duration::from_secs(1);
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::StaleScope)
        );
        op.deadline = Instant::now();
        assert!(matches!(
            owner.capture_settled_input_authority(&page, &op),
            Err(ProtocolError::DeadlineExceeded)
        ));
        op.deadline = captured_deadline;
        cancel.send_replace(CancelSignal::Requested);
        proof.check(&owner, &page, &op).unwrap();
        assert!(matches!(
            owner.capture_settled_input_authority(&page, &op),
            Err(ProtocolError::Cancelled)
        ));
        op.sequence += 1;
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::StaleScope)
        );
        op.sequence -= 1;
        op.generation += 1;
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::StaleScope)
        );
        op.generation -= 1;
        let (_foreign_cancel, foreign_receiver) = watch::channel(CancelSignal::Requested);
        let original_receiver = std::mem::replace(&mut op.cancellation, foreign_receiver);
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::StaleScope)
        );
        op.cancellation = original_receiver;
        let original_session = std::mem::replace(&mut page.page_session_id, "foreign".into());
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::StaleScope)
        );
        page.page_session_id = original_session;
        let original_scope = std::mem::replace(&mut page.identity_scope, "foreign".into());
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::StaleScope)
        );
        page.identity_scope = original_scope;
        proof.check(&owner, &page, &op).unwrap();
        cancel.send_replace(CancelSignal::SessionClosed);
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::StaleScope)
        );
        cancel.send_replace(CancelSignal::Requested);
        // Isolate the expiry guard without wall-clock sleeps: both exact
        // records now hold the same already-expired captured deadline.
        proof.deadline = Instant::now();
        op.deadline = proof.deadline;
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::DeadlineExceeded)
        );
        drop(page);
        owner.close().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn settled_input_authority_refuses_pending_failed_or_changed_enrollment() {
        let (owner, page, _notices, emit, server) = realm_test_owner().await;
        // Establish a real received/applied watermark through the existing
        // supervisor before modeling a delayed application of that stream.
        realm_emit(&owner, &emit, realm_created(41, "settled-prefix-realm")).await;
        let op = owner.operation();
        let proof = owner.capture_settled_input_authority(&page, &op).unwrap();
        let watermark = owner.realm_watermark().unwrap();
        let applied = owner.index.lock().unwrap().applied_watermark;
        assert!(applied > 0 && applied >= watermark.received().unwrap());
        owner.index.lock().unwrap().applied_watermark = applied - 1;
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::ScopeUnavailable)
        );
        owner.index.lock().unwrap().applied_watermark = applied;
        owner
            .index
            .lock()
            .unwrap()
            .pending_enrollment
            .insert("pending".into());
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::ScopeUnavailable)
        );
        owner.index.lock().unwrap().pending_enrollment.clear();
        owner
            .index
            .lock()
            .unwrap()
            .sessions
            .get_mut("initial")
            .unwrap()
            .resumed = false;
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::ScopeUnavailable)
        );
        owner
            .index
            .lock()
            .unwrap()
            .sessions
            .get_mut("initial")
            .unwrap()
            .resumed = true;
        owner
            .index
            .lock()
            .unwrap()
            .retiring_pages
            .insert("initial-target".into(), "initial".into());
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::ScopeUnavailable)
        );
        owner.index.lock().unwrap().retiring_pages.clear();
        *owner.active_root.lock().unwrap() = "foreign".into();
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::StaleReference)
        );
        *owner.active_root.lock().unwrap() = "initial".into();
        owner.index.lock().unwrap().failure = Some(ProtocolError::BrowserFailure);
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::BrowserFailure)
        );
        owner.index.lock().unwrap().failure = None;
        proof.check(&owner, &page, &op).unwrap();
        // A real lifecycle event changes application authority even when the
        // page session, operation, and browser connection are still the same.
        realm_emit(
            &owner,
            &emit,
            json!({"method":"Page.frameAttached","sessionId":"initial",
            "params":{"frameId":"new-child","parentFrameId":"frame-initial"}}),
        )
        .await;
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::StaleScope)
        );
        let current = owner.capture_settled_input_authority(&page, &op).unwrap();
        owner.seal();
        assert!(current.check(&owner, &page, &op).is_err());
        drop(page);
        let _ = owner.close().await;
        server.abort();
    }

    #[test]
    fn restart_retirement_predicate_requires_every_exact_pair_and_received_boundary() {
        let complete = || {
            let mut index = Index {
                applied_watermark: 7,
                ..Index::default()
            };
            index
                .retiring_pages
                .insert("old-target".into(), "old-root".into());
            index.retired_page_sessions.insert("old-root".into());
            index
        };
        let live = |target: &str, session: &str, root: &str| Attribution {
            target: target.into(),
            session: session.into(),
            parent: (session != root).then(|| root.into()),
            root: root.into(),
            kind: if session == root { "page" } else { "iframe" }.into(),
            application: true,
            observation_only: false,
            observer_paused: false,
            resumed: true,
        };
        let index = complete();
        assert!(restart_retirements_settled(&index, 7));
        assert!(!restart_page_pair_retired(
            &index,
            "missing-target",
            "old-root"
        ));
        assert!(!restart_page_pair_retired(
            &index,
            "old-target",
            "wrong-root"
        ));
        for case in [
            "wrong-pair",
            "no-tombstone",
            "live-root",
            "live-child",
            "same-target",
            "same-session",
            "incomplete-history",
            "pending-enrollment",
            "pending-event",
            "borrowed-restart",
        ] {
            let mut index = complete();
            match case {
                "wrong-pair" => {
                    index
                        .retiring_pages
                        .insert("old-target".into(), "other-root".into());
                }
                "no-tombstone" => {
                    index.retired_page_sessions.remove("old-root");
                }
                "live-root" => {
                    index.sessions.insert(
                        "old-root".into(),
                        live("old-target", "old-root", "old-root"),
                    );
                }
                "live-child" => {
                    index
                        .sessions
                        .insert("child".into(), live("child-target", "child", "old-root"));
                }
                "same-target" => {
                    index.sessions.insert(
                        "new-session".into(),
                        live("old-target", "new-session", "new-session"),
                    );
                }
                "same-session" => {
                    index.sessions.insert(
                        "old-root".into(),
                        live("new-target", "old-root", "new-root"),
                    );
                }
                "incomplete-history" => {
                    index
                        .retiring_pages
                        .insert("older-target".into(), "older-root".into());
                }
                "pending-enrollment" => {
                    index.pending_enrollment.insert("late-child".into());
                }
                "pending-event" => index.applied_watermark = 6,
                "borrowed-restart" => index.borrowed_restart = Some(1),
                _ => unreachable!(),
            }
            let pairs = index.retiring_pages.clone();
            let tombstones = index.retired_page_sessions.clone();
            assert!(!restart_retirements_settled(&index, 7), "{case}");
            assert_eq!(index.retiring_pages, pairs, "{case}");
            assert_eq!(index.retired_page_sessions, tombstones, "{case}");
        }
        let mut index = complete();
        index
            .retiring_pages
            .insert("older-target".into(), "older-root".into());
        index.retired_page_sessions.insert("older-root".into());
        index.sessions.insert(
            "current".into(),
            live("current-target", "current", "current"),
        );
        assert!(restart_retirements_settled(&index, 7));
        assert_eq!(index.retiring_pages.len(), 2);
        assert_eq!(index.retired_page_sessions.len(), 2);
    }

    #[tokio::test]
    async fn settled_input_preserves_retirement_history_and_fences_late_descendants() {
        let (owner, _notices, log, emit, server) = fixture("normal").await;
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner.start(&owner.operation()).await.unwrap();
        let entry = owner.index.lock().unwrap().sessions["initial"].clone();
        let page = owner.lease(&entry).unwrap();
        {
            let mut index = owner.index.lock().unwrap();
            index
                .retiring_pages
                .insert("old-target".into(), "old-root".into());
            index.retired_page_sessions.insert("old-root".into());
        }
        let op = owner.operation();
        let proof = owner.capture_settled_input_authority(&page, &op).unwrap();
        for (parent, session) in [
            ("old-root", "late-child"),
            ("late-child", "late-grandchild"),
        ] {
            let gate = CaptureTestGate::new();
            owner
                .capture_test_gates
                .lock()
                .unwrap()
                .insert(CaptureTestPoint::BeforeEventApply, gate.clone());
            emit.send(json!({
                "method":"Target.attachedToTarget", "sessionId":parent,
                "params":{"sessionId":session,"waitingForDebugger":true,
                    "targetInfo":{"targetId":format!("{session}-target"),"type":"iframe",
                        "browserContextId":"owned-context"}}
            }))
            .await
            .unwrap();
            gate.wait_entered().await;
            let before = log.lock().unwrap().len();
            let blocked = proof.check(&owner, &page, &op);
            assert_eq!(
                log.lock().unwrap().len(),
                before,
                "input checks must not flush events"
            );
            // Always release the retained supervisor before asserting failure.
            gate.release();
            owner
                .drain_capture_watermark(&owner.realm_watermark().unwrap(), &op)
                .await
                .unwrap();
            assert_eq!(blocked, Err(ProtocolError::ScopeUnavailable));
            {
                let index = owner.index.lock().unwrap();
                assert!(index.retired_page_sessions.contains(session));
                assert!(!index.sessions.contains_key(session));
                assert_eq!(
                    index.retiring_pages.get("old-target").map(String::as_str),
                    Some("old-root")
                );
            }
            proof.check(&owner, &page, &op).unwrap();
            let commands = log.lock().unwrap();
            assert!(commands
                .iter()
                .any(|request| request["method"] == "Target.detachFromTarget"
                    && request["params"]["sessionId"] == session));
            assert!(!commands
                .iter()
                .any(|request| request["sessionId"] == session
                    && matches!(
                        request["method"].as_str(),
                        Some("Runtime.enable" | "Page.enable")
                    )));
        }
        assert_eq!(owner.index.lock().unwrap().retiring_pages.len(), 1);
        drop(page);
        owner.close().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn missing_context_retired_descendants_block_input_until_exact_detach_ack() {
        for retired_observer in [false, true] {
            let (owner, _notices, log, emit, server) = fixture("retired-detach-held").await;
            owner
                .enroll_existing("initial-target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            owner.start(&owner.operation()).await.unwrap();
            let entry = owner.index.lock().unwrap().sessions["initial"].clone();
            let page = owner.lease(&entry).unwrap();
            {
                let mut index = owner.index.lock().unwrap();
                index
                    .retiring_pages
                    .insert("old-target".into(), "old-root".into());
                index.retired_page_sessions.insert("old-root".into());
                if retired_observer {
                    index
                        .retired_observer_sessions
                        .insert("old-observer".into());
                }
            }
            let root = if retired_observer {
                "old-observer"
            } else {
                "old-root"
            };
            let op = owner.operation();
            let proof = owner.capture_settled_input_authority(&page, &op).unwrap();
            let watermark = owner.realm_watermark().unwrap();
            for (parent, session) in [(root, "late-child"), ("late-child", "late-grandchild")] {
                emit.send(json!({
                    "method":"Target.attachedToTarget", "sessionId":parent,
                    "params":{"sessionId":session,"waitingForDebugger":true,
                        "targetInfo":{"targetId":format!("{session}-target"),"type":"iframe"}}
                }))
                .await
                .unwrap();
                // The event itself is already applied. Only the real pending
                // detach command, not a watermark backlog, must deny input.
                let request = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let request = log
                            .lock()
                            .unwrap()
                            .iter()
                            .find(|request| {
                                request["method"] == "Target.detachFromTarget"
                                    && request["params"]["sessionId"] == session
                            })
                            .cloned();
                        if let Some(request) = request {
                            let index = owner.index.lock().unwrap();
                            if index.applied_watermark >= watermark.received().unwrap() {
                                break request;
                            }
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert_eq!(request["sessionId"], parent);
                let pending = owner
                    .index
                    .lock()
                    .unwrap()
                    .pending_enrollment
                    .contains(session);
                let blocked = proof.check(&owner, &page, &op);
                // Release the exact command before checking the outcome, so a
                // regression does not strand the retained cleanup task.
                emit.send(json!({"id":request["id"],"sessionId":parent,"result":{}}))
                    .await
                    .unwrap();
                owner
                    .drain_capture_watermark(&watermark, &op)
                    .await
                    .unwrap();
                assert!(
                    pending,
                    "known retired-parent cleanup lost its pending hold"
                );
                assert_eq!(blocked, Err(ProtocolError::ScopeUnavailable));
                {
                    let index = owner.index.lock().unwrap();
                    assert!(!index.pending_enrollment.contains(session));
                    assert!(index.retired_page_sessions.contains(session));
                    assert!(!index.sessions.contains_key(session));
                    assert_eq!(
                        index.retiring_pages.get("old-target").map(String::as_str),
                        Some("old-root")
                    );
                }
                proof.check(&owner, &page, &op).unwrap();
            }
            assert!(!log.lock().unwrap().iter().any(|request| {
                (matches!(
                    request["sessionId"].as_str(),
                    Some("late-child" | "late-grandchild")
                ) && matches!(
                    request["method"].as_str(),
                    Some("Runtime.enable" | "Page.enable")
                )) || (request["method"] == "Target.getTargetInfo"
                    && matches!(
                        request["params"]["targetId"].as_str(),
                        Some("late-child-target" | "late-grandchild-target")
                    ))
            }));
            drop(page);
            owner.close().await.unwrap();
            server.abort();
        }
    }

    #[tokio::test]
    async fn burst_missing_context_grandchild_holds_input_after_parent_detach_ack() {
        for (retired_observer, failed_ack) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let (owner, _notices, log, emit, server) = fixture("retired-detach-held").await;
            owner
                .enroll_existing("initial-target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            owner.start(&owner.operation()).await.unwrap();
            let entry = owner.index.lock().unwrap().sessions["initial"].clone();
            let page = owner.lease(&entry).unwrap();
            let root = if retired_observer {
                "old-observer"
            } else {
                "old-root"
            };
            {
                let mut index = owner.index.lock().unwrap();
                index
                    .retiring_pages
                    .insert("old-target".into(), "old-root".into());
                index.retired_page_sessions.insert("old-root".into());
                if retired_observer {
                    index.retired_observer_sessions.insert(root.into());
                }
            }
            let op = owner.operation();
            let proof = owner.capture_settled_input_authority(&page, &op).unwrap();
            let watermark = owner.realm_watermark().unwrap();
            let before = watermark.received().unwrap();
            // Prevent the child's async classifier from supplying ancestry to
            // the next event. Only synchronous receive registration may do so.
            let gate = CaptureTestGate::new();
            owner
                .capture_test_gates
                .lock()
                .unwrap()
                .insert(CaptureTestPoint::BeforeAttachedProcessing, gate.clone());
            for (parent, session) in [(root, "late-child"), ("late-child", "late-grandchild")] {
                emit.send(json!({
                    "method":"Target.attachedToTarget", "sessionId":parent,
                    "params":{"sessionId":session,"waitingForDebugger":true,
                        "targetInfo":{"targetId":format!("{session}-target"),"type":"iframe"}}
                }))
                .await
                .unwrap();
                if session == "late-child" {
                    gate.wait_entered().await;
                }
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if owner.index.lock().unwrap().applied_watermark >= before + 2 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            gate.release();
            let (child, grandchild) = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let requests = {
                        let log = log.lock().unwrap();
                        let find = |session: &str| {
                            log.iter()
                                .find(|request| {
                                    request["method"] == "Target.detachFromTarget"
                                        && request["params"]["sessionId"] == session
                                })
                                .cloned()
                        };
                        (find("late-child"), find("late-grandchild"))
                    };
                    if let (Some(child), Some(grandchild)) = requests {
                        break (child, grandchild);
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(child["sessionId"], root);
            assert_eq!(grandchild["sessionId"], "late-child");
            emit.send(json!({"id":child["id"],"sessionId":root,"result":{}}))
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if !owner
                        .index
                        .lock()
                        .unwrap()
                        .pending_enrollment
                        .contains("late-child")
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let pending = owner
                .index
                .lock()
                .unwrap()
                .pending_enrollment
                .contains("late-grandchild");
            let blocked = proof.check(&owner, &page, &op);
            if failed_ack {
                emit.send(json!({"id":grandchild["id"],"sessionId":"late-child",
                    "error":{"code":-32000,"message":"synthetic detach failure"}}))
                    .await
                    .unwrap();
                // The retained fallback resumes only this exact paused session
                // and retries detach. Its second failure must poison before the
                // pending token can disappear, never turn failure into success.
                let retry = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let request = log
                            .lock()
                            .unwrap()
                            .iter()
                            .find(|request| {
                                request["method"] == "Target.detachFromTarget"
                                    && request["params"]["sessionId"] == "late-grandchild"
                                    && request["id"] != grandchild["id"]
                            })
                            .cloned();
                        if let Some(request) = request {
                            break request;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert!(proof.check(&owner, &page, &op).is_err());
                emit.send(json!({"id":retry["id"],"sessionId":"late-child",
                    "error":{"code":-32000,"message":"synthetic retained detach failure"}}))
                    .await
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let settled = {
                            let index = owner.index.lock().unwrap();
                            index.failure.is_some()
                                && !index.pending_enrollment.contains("late-grandchild")
                        };
                        if settled {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
            } else {
                emit.send(json!({"id":grandchild["id"],"sessionId":"late-child","result":{}}))
                    .await
                    .unwrap();
                owner
                    .drain_capture_watermark(&watermark, &op)
                    .await
                    .unwrap();
            }
            assert!(
                pending,
                "grandchild cleanup outlived the only pending token"
            );
            assert_eq!(blocked, Err(ProtocolError::ScopeUnavailable));
            {
                let index = owner.index.lock().unwrap();
                for session in ["late-child", "late-grandchild"] {
                    assert!(index.retired_page_sessions.contains(session));
                    assert!(!index.sessions.contains_key(session));
                    assert!(!index.pending_enrollment.contains(session));
                }
                assert_eq!(
                    index.retiring_pages.get("old-target").map(String::as_str),
                    Some("old-root")
                );
                if failed_ack {
                    assert_eq!(index.failure, Some(ProtocolError::CleanupFailed));
                }
            }
            if failed_ack {
                assert!(proof.check(&owner, &page, &op).is_err());
            } else {
                proof.check(&owner, &page, &op).unwrap();
            }
            assert!(!log.lock().unwrap().iter().any(|request| {
                (matches!(
                    request["sessionId"].as_str(),
                    Some("late-child" | "late-grandchild")
                ) && matches!(
                    request["method"].as_str(),
                    Some("Runtime.enable" | "Page.enable")
                )) || (request["method"] == "Target.getTargetInfo"
                    && matches!(
                        request["params"]["targetId"].as_str(),
                        Some("late-child-target" | "late-grandchild-target")
                    ))
            }));
            drop(page);
            if failed_ack {
                assert!(owner.close().await.is_err());
            } else {
                owner.close().await.unwrap();
            }
            server.abort();
        }
    }

    #[tokio::test]
    async fn retired_cleanup_lineage_is_bounded_and_unknown_parents_grant_nothing() {
        let (owner, _notices, _log, emit, server) = fixture("normal").await;
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner.start(&owner.operation()).await.unwrap();
        let entry = owner.index.lock().unwrap().sessions["initial"].clone();
        let page = owner.lease(&entry).unwrap();
        let op = owner.operation();
        let proof = owner.capture_settled_input_authority(&page, &op).unwrap();
        let mut event = CdpEvent {
            method: "Target.attachedToTarget".into(),
            session_id: Some("unknown-parent".into()),
            params: json!({"sessionId":"unknown-child","targetInfo":{
                "targetId":"unknown-target","type":"iframe"}}),
        };
        assert_eq!(owner.register_pending_event(&event), Ok(None));
        {
            let mut index = owner.index.lock().unwrap();
            assert!(!index.retired_page_sessions.contains("unknown-child"));
            assert!(!index.pending_enrollment.contains("unknown-child"));
            assert!(!index.sessions.contains_key("unknown-child"));
            index
                .retiring_pages
                .insert("old-target".into(), "old-root".into());
            index.retired_page_sessions.insert("old-root".into());
            for ordinal in 1..MAX_FRAMES {
                index
                    .retired_page_sessions
                    .insert(format!("retired-{ordinal}"));
            }
        }
        proof.check(&owner, &page, &op).unwrap();
        event.session_id = Some("old-root".into());
        emit.send(
            json!({"method":event.method,"sessionId":event.session_id,"params":event.params}),
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if owner.index.lock().unwrap().failure.is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        {
            let index = owner.index.lock().unwrap();
            assert_eq!(index.failure, Some(ProtocolError::CapacityExceeded));
            // Rejected registration never marks the received event applied:
            // the receipt fence denies input even before poison is observed.
            assert!(index.applied_watermark < owner.realm_watermark().unwrap().received().unwrap());
            assert_eq!(index.retired_page_sessions.len(), MAX_FRAMES);
            assert!(!index.retired_page_sessions.contains("unknown-child"));
            assert!(!index.pending_enrollment.contains("unknown-child"));
        }
        assert!(proof.check(&owner, &page, &op).is_err());
        drop(page);
        assert!(owner.close().await.is_err());
        server.abort();
    }

    #[tokio::test]
    async fn settled_input_authority_rejects_foreign_owner_client_and_registry() {
        let (owner, mut page, _notices, _emit, server) = realm_test_owner().await;
        let (foreign, _notices2, _log, _emit2, server2) = fixture("normal").await;
        let op = owner.operation();
        let proof = owner.capture_settled_input_authority(&page, &op).unwrap();
        assert_eq!(
            proof.check(&foreign, &page, &op),
            Err(ProtocolError::StaleScope)
        );
        let original_client = std::mem::replace(&mut page.client, foreign.client.clone());
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::StaleScope)
        );
        page.client = original_client;
        let original_targets = std::mem::replace(&mut page.targets, foreign.targets.clone());
        assert_eq!(
            proof.check(&owner, &page, &op),
            Err(ProtocolError::StaleScope)
        );
        page.targets = original_targets;
        proof.check(&owner, &page, &op).unwrap();
        drop(page);
        owner.close().await.unwrap();
        foreign.close().await.unwrap();
        server.abort();
        server2.abort();
    }
    #[tokio::test]
    async fn exact_realm_destroy_before_bind_survives_numeric_id_reuse_and_needs_new_document() {
        let (owner, page, _notices, emit, server) = realm_test_owner().await;
        let op = owner.operation();
        let capture = owner
            .reserve_exact_realm(&page, &realm_test_binding(), &op)
            .unwrap();
        realm_emit(&owner, &emit, realm_created(7, "original-unique")).await;
        realm_emit(&owner,&emit,json!({"method":"Runtime.executionContextDestroyed","sessionId":"initial","params":{"executionContextId":7,"executionContextUniqueId":"original-unique"}})).await;
        let original = capture.bind(7, &op).await.unwrap();
        assert_eq!(original.destroyed(), Ok(true));
        // Realm destruction alone is not proof of checked-action navigation.
        assert_eq!(original.document_retired(&op).await, Ok(false));
        let capture = owner
            .reserve_exact_realm(&page, &realm_test_binding(), &op)
            .unwrap();
        realm_emit(&owner, &emit, realm_created(7, "replacement-unique")).await;
        let replacement = capture.bind(7, &op).await.unwrap();
        assert_eq!(replacement.destroyed(), Ok(false));
        realm_emit(&owner,&emit,json!({"method":"Page.frameNavigated","sessionId":"initial","params":{"frame":{"id":"frame-initial","loaderId":"next-loader","url":"https://synthetic.test/next"}}})).await;
        assert_eq!(original.document_retired(&op).await, Ok(true));
        // BFCache/live old realm: loader replacement never waives cleanup.
        assert_eq!(replacement.document_retired(&op).await, Ok(false));
        let (cancel, cancellation) = watch::channel(CancelSignal::Requested);
        let mut cancelled = owner.operation();
        cancelled.cancellation = cancellation;
        assert_eq!(
            original.document_retired(&cancelled).await,
            Err(ProtocolError::Cancelled)
        );
        drop(cancel);
        owner.poison(ProtocolError::BrowserFailure);
        assert_eq!(original.destroyed(), Err(ProtocolError::BrowserFailure));
        drop(page);
        let _ = owner.close().await;
        server.abort();
    }
    #[tokio::test]
    async fn exact_realm_ack_numeric_id_reuse_before_bind_is_ambiguous() {
        for destroy in [false, true] {
            let (owner, page, _notices, emit, server) = realm_test_owner().await;
            let op = owner.operation();
            let capture = owner
                .reserve_exact_realm(&page, &realm_test_binding(), &op)
                .unwrap();
            realm_emit(&owner, &emit, realm_created(7, "original")).await;
            let original = owner
                .index
                .lock()
                .unwrap()
                .realms
                .get(&("initial".into(), 7))
                .unwrap()
                .clone();
            if destroy {
                realm_emit(&owner,&emit,json!({"method":"Runtime.executionContextDestroyed","sessionId":"initial","params":{"executionContextId":7,"executionContextUniqueId":"original"}})).await;
            }
            realm_emit(&owner, &emit, realm_created(7, "reused")).await;
            assert_eq!(original.destroyed.load(Ordering::SeqCst), destroy);
            assert!(matches!(
                capture.bind(7, &op).await,
                Err(ProtocolError::StaleReference)
            ));
            assert_eq!(owner.index.lock().unwrap().realm_tickets, 0);
            drop(page);
            owner.close().await.unwrap();
            server.abort();
        }
    }
    #[tokio::test]
    async fn exact_realm_reuse_after_bind_cannot_own_later_resolution_handle() {
        let (owner, page, _notices, emit, server) = realm_test_owner().await;
        let op = owner.operation();
        let capture = owner
            .reserve_exact_realm(&page, &realm_test_binding(), &op)
            .unwrap();
        realm_emit(&owner, &emit, realm_created(7, "original")).await;
        let ticket = capture.bind(7, &op).await.unwrap();
        assert_eq!(ticket.verify_resolution_owner(&op).await, Ok(()));
        realm_emit(&owner,&emit,json!({"method":"Runtime.executionContextDestroyed","sessionId":"initial","params":{"executionContextId":7,"executionContextUniqueId":"original"}})).await;
        realm_emit(&owner, &emit, realm_created(7, "replacement")).await;
        // A successful numeric-ID ResolveNode ACK does not establish ownership.
        assert_eq!(
            ticket.verify_resolution_owner(&op).await,
            Err(ProtocolError::StaleReference)
        );
        assert_eq!(ticket.destroyed(), Ok(true));
        drop(page);
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn action_resolve_ack_after_realm_reuse_releases_handle_without_input() {
        use super::super::{
            client_actions::{ActionContext, ActionRealmAuthority, ClientActions},
            client_geometry::GeometrySnapshot,
            client_observation::ObservationFrame,
            client_protocol::Effects,
            element::RefMap,
        };
        for failed_release in [false, true] {
            let mode = if failed_release {
                "realm-resolve-reuse-release-fails"
            } else {
                "realm-resolve-reuse"
            };
            let (owner, _notices, log, _emit, server) = fixture(mode).await;
            let op = owner.operation();
            owner
                .enroll_existing("initial-target", "initial", "page", &op)
                .await
                .unwrap();
            owner.start(&op).await.unwrap();
            let entry = owner.index.lock().unwrap().sessions["initial"].clone();
            let page = owner.lease(&entry).unwrap();
            let binding = realm_test_binding();
            let mut refs = RefMap::new();
            refs.begin_observation(&page.identity_scope, op.generation, 1);
            let id = refs.bind_exact(42, "checkbox", "", binding.clone());
            let observation_frames = [ObservationFrame {
                parent_frame_id: None,
                owner_backend_id: None,
                url: "about:blank".into(),
                binding,
                offset_x: 0.,
                offset_y: 0.,
                frame_path: vec![],
            }];
            let geometry =
                GeometrySnapshot::capture(&owner.client, "initial", &observation_frames, &op)
                    .await
                    .unwrap();
            let blobs = BlobStore::new(BlobLimits::default()).unwrap();
            let frames = HashMap::new();
            let failure=ClientActions::default().execute(ActionContext { observation_after: None, observed_revision: 0, observation_frames: &observation_frames,
                realm_authority:ActionRealmAuthority::Enrolled(&owner),page:&page,operation:&op,
                page_state:&owner.page,refs:&refs,revision:1,iframe_sessions:&frames,blobs:&blobs,geometry:&geometry,
            },"browser.perform",&json!({"identityScope":"owned-scope","ref":{"id":format!("@{id}"),"revision":"1"},"action":{"kind":"check"}})).await.unwrap_err();
            assert_eq!(failure.error, ProtocolError::StaleReference);
            assert_eq!(failure.effects, Effects::NotDispatched);
            assert_eq!(failure.cleanup_failed, failed_release);
            let commands = log.lock().unwrap().clone();
            assert!(commands.iter().any(|r| r["method"] == "DOM.resolveNode"));
            assert!(commands
                .iter()
                .any(|r| r["method"] == "Runtime.releaseObject"
                    && r["params"]["objectId"] == "replacement-handle"));
            assert!(!commands.iter().any(|r| r["method"]
                .as_str()
                .is_some_and(|m| m.starts_with("Input."))));
            drop(page);
            owner.close().await.unwrap();
            server.abort();
        }
    }
    #[tokio::test]
    async fn exact_realm_clear_is_session_local_and_cannot_retire_later_context() {
        let (owner, page, _notices, emit, server) = realm_test_owner().await;
        let op = owner.operation();
        let capture = owner
            .reserve_exact_realm(&page, &realm_test_binding(), &op)
            .unwrap();
        realm_emit(&owner, &emit, realm_created(9, "before-clear")).await;
        let first = capture.bind(9, &op).await.unwrap();
        realm_emit(
            &owner,
            &emit,
            json!({"method":"Runtime.executionContextsCleared","sessionId":"foreign","params":{}}),
        )
        .await;
        assert_eq!(first.destroyed(), Ok(false));
        realm_emit(
            &owner,
            &emit,
            json!({"method":"Runtime.executionContextsCleared","sessionId":"initial","params":{}}),
        )
        .await;
        assert_eq!(first.destroyed(), Ok(true));
        let capture = owner
            .reserve_exact_realm(&page, &realm_test_binding(), &op)
            .unwrap();
        realm_emit(&owner, &emit, realm_created(9, "after-clear")).await;
        let later = capture.bind(9, &op).await.unwrap();
        assert_eq!(later.destroyed(), Ok(false));
        assert_eq!(owner.index.lock().unwrap().realm_tickets, 2);
        drop(first);
        drop(later);
        assert_eq!(owner.index.lock().unwrap().realm_tickets, 0);
        drop(page);
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn exact_realm_pending_holds_are_bounded_and_retired_session_never_proves_destruction() {
        let (owner, page, _notices, emit, server) = realm_test_owner().await;
        let op = owner.operation();
        let mut holds = Vec::new();
        for _ in 0..MAX_REALM_HOLDS {
            holds.push(
                owner
                    .reserve_exact_realm(&page, &realm_test_binding(), &op)
                    .unwrap(),
            );
        }
        assert!(matches!(
            owner.reserve_exact_realm(&page, &realm_test_binding(), &op),
            Err(ProtocolError::CapacityExceeded)
        ));
        holds.clear();
        let capture = owner
            .reserve_exact_realm(&page, &realm_test_binding(), &op)
            .unwrap();
        realm_emit(&owner, &emit, realm_created(11, "detached-original")).await;
        let ticket = capture.bind(11, &op).await.unwrap();
        realm_emit(&owner,&emit,json!({"method":"Target.detachedFromTarget","params":{"sessionId":"initial","targetId":"initial-target"}})).await;
        assert!(ticket.destroyed().is_err());
        drop(page);
        let _ = owner.close().await;
        server.abort();
    }
    #[tokio::test]
    async fn first_request_cannot_continue_before_complete_target_configuration() {
        for fail in [false, true] {
            for registered_route in [false, true] {
                let (mut owner, mut notices, log, emit, server, broker) =
                    fixture_with_broker("hold-timezone").await;
                Arc::get_mut(&mut owner).unwrap().config.timezone_id = Some("UTC".into());
                owner
                    .network
                    .replace_routes(
                        1,
                        if registered_route {
                            vec!["route".into()]
                        } else {
                            vec![]
                        },
                    )
                    .unwrap();
                let callbacks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let count = callbacks.clone();
                let policy = tokio::spawn(async move {
                    while let Some(ServerMessage::Event {
                        decision: Some(decision),
                        ..
                    }) = notices.recv().await
                    {
                        count.fetch_add(1, Ordering::SeqCst);
                        let _ = broker.resolve(
                            1,
                            &decision.token,
                            super::super::client_protocol::Decision::Continue {
                                overrides: Default::default(),
                            },
                        );
                    }
                });
                let child = owner.clone();
                let enrollment = tokio::spawn(async move {
                    child
                        .enroll_existing("initial-target", "initial", "page", &child.operation())
                        .await
                });
                let timezone_id = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        if let Some(id) = log
                            .lock()
                            .unwrap()
                            .iter()
                            .find(|v| v["method"] == "Emulation.setTimezoneOverride")
                            .map(|v| v["id"].clone())
                        {
                            break id;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
                let premature_continue = log
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|v| v["method"] == "Fetch.continueRequest");
                let premature_callback = callbacks.load(Ordering::SeqCst) > 0;
                emit.send(if fail {json!({"id":timezone_id,"error":{"code":-32602,"message":"Synthetic timezone rejection"}})} else {json!({"id":timezone_id,"result":{}})}).await.unwrap();
                let outcome = enrollment.await.unwrap();
                assert_eq!(outcome.is_err(), fail);
                if !fail {
                    tokio::time::timeout(Duration::from_secs(2), async {
                        loop {
                            if log
                                .lock()
                                .unwrap()
                                .iter()
                                .any(|v| v["method"] == "Fetch.continueRequest")
                            {
                                break;
                            }
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .unwrap();
                    assert_eq!(callbacks.load(Ordering::SeqCst), 1);
                }
                let _ = owner.close().await;
                let proof = owner.contain_owned_resources().await.unwrap();
                owner.release_after_containment(proof).await.unwrap();
                assert_eq!(owner.network.pending_callbacks().unwrap(), 0);
                let escaped = log
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|v| v["method"] == "Fetch.continueRequest");
                policy.abort();
                server.abort();
                assert!(
                    !premature_continue,
                    "Continue escaped before configuration commit"
                );
                assert!(
                    !premature_callback,
                    "JS callback escaped before configuration commit"
                );
                if fail {
                    assert!(!escaped, "configuration failure released an owned request");
                }
            }
        }
    }
    // A production-path fixture: initial enrollment/start and every later attach
    // pass through the same reader, supervisor, configuration and resume code.
    // Only CDP replies and explicit scheduler gates are controlled by tests.
    struct CaptureWireFixture {
        owner: Arc<ClientEnrollment>,
        _notices: Notices,
        log: Log,
        emit: tokio::sync::mpsc::Sender<Value>,
        inventory: Arc<Mutex<Vec<Value>>>,
        held: Arc<Mutex<HashSet<(String, String)>>>,
        server: JoinHandle<()>,
    }
    fn capture_info(target: &str, kind: &str) -> Value {
        json!({"targetId":target, "type":kind, "browserContextId":"owned-context", "attached":true})
    }
    fn capture_attach_event(target: &str, session: &str, kind: &str) -> Value {
        json!({"method":"Target.attachedToTarget", "params":{
            "sessionId":session, "waitingForDebugger":true, "targetInfo":capture_info(target, kind)
        }})
    }
    impl CaptureWireFixture {
        async fn new(borrowed: bool) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let log: Log = Arc::default();
            let inventory = Arc::new(Mutex::new(vec![capture_info("target", "page")]));
            let held: Arc<Mutex<HashSet<(String, String)>>> = Arc::default();
            let (emit, mut emitted) = tokio::sync::mpsc::channel::<Value>(512);
            let (recorded, native_inventory, native_held) =
                (log.clone(), inventory.clone(), held.clone());
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                loop {
                    tokio::select! {
                        message = emitted.recv() => {
                            let Some(message) = message else { break; };
                            if message.get("fixtureClose").is_some() { break; }
                            if socket.send(Message::Text(message.to_string())).await.is_err() { break; }
                        }
                        message = socket.next() => {
                            let Some(Ok(Message::Text(text))) = message else { break; };
                            let request: Value = serde_json::from_str(&text).unwrap();
                            recorded.lock().unwrap().push(request.clone());
                            let method = request["method"].as_str().unwrap();
                            let session = request["sessionId"].as_str().unwrap_or("");
                            if method == "Target.getTargetInfo" || native_held.lock().unwrap().contains(&(method.to_owned(), session.to_owned())) { continue; }
                            let result = match method {
                                "Target.getTargets" => json!({"targetInfos":native_inventory.lock().unwrap().clone()}),
                                "Page.getFrameTree" => json!({"frameTree":{"frame":{"id":format!("frame-{session}"), "loaderId":"capture-loader", "url":"about:blank"}}}),
                                "Page.getLayoutMetrics" => json!({"cssVisualViewport":{"clientWidth":800., "clientHeight":600., "offsetX":0., "offsetY":0., "scale":1.}, "cssLayoutViewport":{"clientWidth":800., "clientHeight":600.}}),
                                "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":"capture-script"}),
                                "Browser.getVersion" => json!({"userAgent":"Synthetic Chromium"}),
                                "Target.closeTarget" => json!({"success":true}),
                                _ => json!({}),
                            };
                            if socket.send(Message::Text(json!({"id":request["id"], "result":result}).to_string())).await.is_err() { break; }
                        }
                    }
                }
            });
            let client = Arc::new(CdpClient::connect(&url).await.unwrap());
            let (mut owner, notices, _broker) =
                coordinator(client, "owned-context", "owned-scope", "initial");
            if borrowed {
                Arc::get_mut(&mut owner).unwrap().ownership =
                    ScopeOwnership::BorrowedTargets(vec!["target".into()]);
            }
            owner
                .enroll_existing("target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            owner.start(&owner.operation()).await.unwrap();
            Self {
                owner,
                _notices: notices,
                log,
                emit,
                inventory,
                held,
                server,
            }
        }
        async fn attach(&self, target: &str, session: &str, kind: &str) {
            realm_emit(
                &self.owner,
                &self.emit,
                capture_attach_event(target, session, kind),
            )
            .await;
        }
        fn gate(&self, point: CaptureTestPoint) -> Arc<CaptureTestGate> {
            let gate = CaptureTestGate::new();
            assert!(self
                .owner
                .capture_test_gates
                .lock()
                .unwrap()
                .insert(point, gate.clone())
                .is_none());
            gate
        }
        fn requests(&self, method: &str) -> Vec<Value> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request["method"] == method)
                .cloned()
                .collect()
        }
        async fn request(&self, method: &str, count: usize) -> Value {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let requests = self.requests(method);
                    if requests.len() >= count {
                        return requests[count - 1].clone();
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap()
        }
        fn capture(
            &self,
            op: OperationLease,
        ) -> JoinHandle<Result<EnrollmentAttestation, ProtocolError>> {
            let owner = self.owner.clone();
            tokio::spawn(async move { owner.attest_capture(&op).await })
        }
        async fn reply(&self, request: &Value, info: Value) {
            self.emit
                .send(json!({"id":request["id"], "result":{"targetInfo":info}}))
                .await
                .unwrap();
        }
        async fn server_barrier(&self) {
            // A read-only fixture barrier on the same command writer and server.
            // Its ACK proves prior dispatched commands reached the server log;
            // it is never used as capture authority or as an operation renewal.
            self.owner
                .command(
                    &self.owner.operation(),
                    None,
                    "Browser.getVersion",
                    json!({}),
                )
                .await
                .unwrap();
        }
        async fn finish(self) {
            let _ = self.owner.close().await;
            self.server.abort();
        }
        fn assert_no_capture_mutations(&self, before: usize) {
            for request in &self.log.lock().unwrap()[before..] {
                assert!(
                    matches!(
                        request["method"].as_str(),
                        Some("Target.getTargets" | "Target.getTargetInfo" | "Page.getFrameTree")
                    ),
                    "capture dispatched a mutating command"
                );
            }
        }
    }

    // 1. Ordinary and native-tab inventories retain their zero-lookup budget.
    #[tokio::test]
    async fn capture_owned_inventory_complete_needs_no_supplement() {
        let f = CaptureWireFixture::new(false).await;
        f.attach("tab", "tab-session", "tab").await;
        f.inventory.lock().unwrap().push(capture_info("tab", "tab"));
        let before = f.log.lock().unwrap().len();
        let revision = f.owner.targets.inventory().unwrap().0;
        let proof = f.owner.attest_capture(&f.owner.operation()).await.unwrap();
        f.owner
            .verify_capture_attestation(&proof, &f.owner.operation())
            .await
            .unwrap();
        assert!(f.requests("Target.getTargetInfo").is_empty());
        assert_eq!(revision, f.owner.targets.inventory().unwrap().0);
        assert!(!f
            .requests("Page.getFrameTree")
            .iter()
            .any(|request| request["sessionId"] == "tab-session"));
        f.assert_no_capture_mutations(before);
        f.finish().await;
    }

    // 2. Both sides of export require the same original session and tenure.
    #[tokio::test]
    async fn capture_owned_inventory_omitted_ui_is_exact_and_read_only() {
        let f = CaptureWireFixture::new(false).await;
        f.attach("missing-a", "missing-session-a", "browser_ui")
            .await;
        let before = f.log.lock().unwrap().len();
        let revision = f.owner.targets.inventory().unwrap().0;
        let original = f.owner.targets.owned_target("missing-a").unwrap();
        let first = f.capture(f.owner.operation());
        let request = f.request("Target.getTargetInfo", 1).await;
        assert_eq!(request["params"], json!({}));
        assert_eq!(request["sessionId"], "missing-session-a");
        f.reply(&request, capture_info("missing-a", "browser_ui"))
            .await;
        let proof = first.await.unwrap().unwrap();
        let owner = f.owner.clone();
        let verify = tokio::spawn(async move {
            owner
                .verify_capture_attestation(&proof, &owner.operation())
                .await
        });
        let request = f.request("Target.getTargetInfo", 2).await;
        assert_eq!(request["params"], json!({}));
        assert_eq!(request["sessionId"], "missing-session-a");
        f.reply(&request, capture_info("missing-a", "browser_ui"))
            .await;
        verify.await.unwrap().unwrap();
        assert_eq!(f.requests("Target.getTargetInfo").len(), 2);
        assert!(f
            .owner
            .targets
            .owned_target("missing-a")
            .unwrap()
            .same_attachment(&original));
        assert_eq!(f.owner.targets.inventory().unwrap().0, revision);
        assert_eq!(f.owner.targets.inventory().unwrap().1.len(), 2);
        assert!(!f
            .requests("Page.getFrameTree")
            .iter()
            .any(|request| request["sessionId"] == "missing-session-a"));
        f.assert_no_capture_mutations(before);
        f.finish().await;
    }

    // 3. Native identity, not URL telemetry or a display-token whitelist.
    #[tokio::test]
    async fn capture_owned_inventory_url_and_native_kind_are_not_exemptions() {
        for (kind, url) in [
            (
                "browser_ui",
                Some("chrome://webui-toolbar.top-chrome/?private-url-marker"),
            ),
            (
                "browser_ui",
                Some("https://private-url-marker.invalid/secret"),
            ),
            ("browser_ui", None),
            ("worker", None),
            ("future_native_kind_longer_than_32_bytes", None),
        ] {
            let f = CaptureWireFixture::new(false).await;
            f.attach("missing-a", "missing-session-a", kind).await;
            let task = f.capture(f.owner.operation());
            let request = f.request("Target.getTargetInfo", 1).await;
            let mut info = capture_info("missing-a", kind);
            if let Some(url) = url {
                info["url"] = json!(url);
            }
            info["title"] = json!("private-title-marker");
            f.reply(&request, info).await;
            task.await.unwrap().unwrap();
            assert_eq!(f.requests("Target.getTargetInfo").len(), 1);
            f.finish().await;
        }
    }

    // 4. Present-but-contradictory records cannot be healed by exact lookup.
    #[tokio::test]
    async fn capture_owned_inventory_rejects_all_enumerated_contradictions_first() {
        for case in [
            "foreign-context",
            "missing-context",
            "kind",
            "null-kind",
            "null-id",
            "duplicate",
            "duplicate-conflict",
        ] {
            let f = CaptureWireFixture::new(false).await;
            f.attach("missing-a", "missing-session-a", "browser_ui")
                .await;
            // An earlier omission must not trigger a read before a later conflict.
            f.attach("zz-conflict", "conflict-session", "browser_ui")
                .await;
            let mut info = capture_info("zz-conflict", "browser_ui");
            match case {
                "foreign-context" => info["browserContextId"] = json!("foreign"),
                "missing-context" => {
                    info.as_object_mut().unwrap().remove("browserContextId");
                }
                "kind" => info["type"] = json!("worker"),
                "null-kind" => info["type"] = Value::Null,
                "null-id" => info["targetId"] = Value::Null,
                _ => {}
            }
            f.inventory.lock().unwrap().push(info.clone());
            if case.starts_with("duplicate") {
                if case == "duplicate-conflict" {
                    info["browserContextId"] = json!("foreign");
                }
                f.inventory.lock().unwrap().push(info);
            }
            let frames = f.requests("Page.getFrameTree").len();
            assert!(f.owner.attest_capture(&f.owner.operation()).await.is_err());
            assert!(f.requests("Target.getTargetInfo").is_empty());
            assert_eq!(f.requests("Page.getFrameTree").len(), frames);
            f.finish().await;
        }
    }

    // 5. Malformed or failed exact-session replies provide no inventory proof.
    #[tokio::test]
    async fn capture_owned_inventory_exact_info_negative_matrix() {
        for case in [
            "target",
            "context",
            "kind",
            "missing-target",
            "missing-context",
            "missing-kind",
            "null-info",
            "missing-info",
            "false-attached",
            "missing-attached",
            "string-attached",
            "long-id",
            "protocol",
            "unsupported",
            "transport",
        ] {
            let f = CaptureWireFixture::new(false).await;
            f.attach("missing-a", "missing-session-a", "browser_ui")
                .await;
            let revision = f.owner.targets.inventory().unwrap().0;
            let frames = f.requests("Page.getFrameTree").len();
            let task = f.capture(f.owner.operation());
            let request = f.request("Target.getTargetInfo", 1).await;
            let mut info = capture_info("missing-a", "browser_ui");
            let expected = match case {
                "target" => {
                    info["targetId"] = json!("wrong");
                    ProtocolError::StaleScope
                }
                "context" => {
                    info["browserContextId"] = json!("foreign");
                    ProtocolError::StaleScope
                }
                "kind" => {
                    info["type"] = json!("worker");
                    ProtocolError::StaleScope
                }
                "false-attached" => {
                    info["attached"] = json!(false);
                    ProtocolError::StaleScope
                }
                "string-attached" => {
                    info["attached"] = json!("true");
                    ProtocolError::InvalidFrame
                }
                "missing-target" => {
                    info.as_object_mut().unwrap().remove("targetId");
                    ProtocolError::InvalidFrame
                }
                "missing-context" => {
                    info.as_object_mut().unwrap().remove("browserContextId");
                    ProtocolError::InvalidFrame
                }
                "missing-kind" => {
                    info.as_object_mut().unwrap().remove("type");
                    ProtocolError::InvalidFrame
                }
                "missing-attached" => {
                    info.as_object_mut().unwrap().remove("attached");
                    ProtocolError::InvalidFrame
                }
                "null-info" => {
                    info = Value::Null;
                    ProtocolError::InvalidFrame
                }
                "long-id" => {
                    info["targetId"] = json!("x".repeat(1025));
                    ProtocolError::InvalidFrame
                }
                "protocol" | "unsupported" | "transport" => ProtocolError::BrowserFailure,
                _ => ProtocolError::InvalidFrame,
            };
            match case {
                "protocol" | "unsupported" => f.emit.send(json!({"id":request["id"], "error":{"code":if case == "unsupported" {-32601} else {-32000}, "message":"private-error-marker https://secret.invalid"}})).await.unwrap(),
                "transport" => f.emit.send(json!({"fixtureClose":true})).await.unwrap(),
                "missing-info" => f.emit.send(json!({"id":request["id"], "result":{}})).await.unwrap(),
                _ => f.reply(&request, info).await,
            }
            let result = task.await.unwrap().map(|_| ());
            if case == "transport" {
                // EOF removes the original watermark route, so its lost proof
                // wins over the raw waiter error. Actual owner-stop cancellation
                // may win first; neither outcome proves target/session retirement.
                assert!(matches!(
                    result,
                    Err(ProtocolError::ScopeUnavailable | ProtocolError::Cancelled)
                ));
            } else {
                assert_eq!(result, Err(expected), "{case}");
            }
            assert_eq!(f.requests("Target.getTargetInfo").len(), 1);
            assert_eq!(f.requests("Page.getFrameTree").len(), frames);
            assert!(f
                .requests("Target.getTargetInfo")
                .iter()
                .all(|r| r["params"] == json!({}) && r["sessionId"] == "missing-session-a"));
            if case != "transport" {
                assert_eq!(f.owner.targets.inventory().unwrap().0, revision);
            }
            f.finish().await;
        }
    }

    // 6. Coverage and the lookup budget are per original omitted attachment.
    #[tokio::test]
    async fn capture_owned_inventory_multiple_omissions_require_every_reply() {
        for fail_second in [false, true] {
            let f = CaptureWireFixture::new(false).await;
            f.attach("missing-a", "missing-session-a", "browser_ui")
                .await;
            f.attach("missing-b", "missing-session-b", "worker").await;
            let frames = f.requests("Page.getFrameTree").len();
            let task = f.capture(f.owner.operation());
            let first = f.request("Target.getTargetInfo", 1).await;
            assert_eq!(first["sessionId"], "missing-session-a");
            f.reply(&first, capture_info("missing-a", "browser_ui"))
                .await;
            let second = f.request("Target.getTargetInfo", 2).await;
            assert_eq!(second["sessionId"], "missing-session-b");
            assert_eq!(f.requests("Page.getFrameTree").len(), frames);
            f.reply(
                &second,
                capture_info(
                    if fail_second {
                        "unrelated"
                    } else {
                        "missing-b"
                    },
                    "worker",
                ),
            )
            .await;
            assert_eq!(task.await.unwrap().is_err(), fail_second);
            assert_eq!(f.requests("Target.getTargetInfo").len(), 2);
            if fail_second {
                assert_eq!(f.requests("Page.getFrameTree").len(), frames);
            }
            f.finish().await;
        }
    }

    // Deliberately malformed local indexes exercise the explicit snapshot bound
    // and duplicate invariant; these are not claimed as valid enrollment races.
    #[tokio::test]
    async fn capture_owned_inventory_snapshot_cap_and_duplicate_guards() {
        for overflow in [false, true] {
            let f = CaptureWireFixture::new(false).await;
            let original = f.owner.index.lock().unwrap().sessions["initial"].clone();
            {
                let mut index = f.owner.index.lock().unwrap();
                for number in 0..if overflow { MAX_SESSIONS } else { 1 } {
                    let mut entry = original.clone();
                    entry.session = format!("extra-session-{number}");
                    if overflow {
                        entry.target = format!("extra-target-{number}");
                    }
                    index.sessions.insert(entry.session.clone(), entry);
                }
            }
            let before = f.log.lock().unwrap().len();
            assert_eq!(
                f.owner
                    .attest_capture(&f.owner.operation())
                    .await
                    .map(|_| ()),
                Err(if overflow {
                    ProtocolError::CapacityExceeded
                } else {
                    ProtocolError::StaleScope
                })
            );
            assert_eq!(f.log.lock().unwrap().len(), before);
            f.owner
                .index
                .lock()
                .unwrap()
                .sessions
                .retain(|session, _| session == "initial");
            f.finish().await;
        }
    }

    // Failed reads and malformed ACKs are subordinate to the original capture
    // authority, but keep their own error class when that authority is intact.
    #[tokio::test]
    async fn capture_owned_inventory_read_errors_fence_original_authority() {
        for (method, session) in [
            ("Target.getTargets", ""),
            ("Target.getTargetInfo", "missing-session-a"),
            ("Page.getFrameTree", "initial"),
        ] {
            for changed in [false, true] {
                for protocol_failure in [false, true] {
                    let f = CaptureWireFixture::new(false).await;
                    if method == "Target.getTargetInfo" {
                        f.attach("missing-a", "missing-session-a", "browser_ui")
                            .await;
                    }
                    f.held
                        .lock()
                        .unwrap()
                        .insert((method.into(), session.into()));
                    let reads = f.requests(method).len();
                    let inventories = f.requests("Target.getTargets").len();
                    let before = f.log.lock().unwrap().len();
                    let original = f.owner.targets.owned_target("target").unwrap();
                    let watermark = f.owner.realm_watermark().unwrap();
                    let task = f.capture(f.owner.operation());
                    let request = f.request(method, reads + 1).await;
                    if changed {
                        realm_emit(
                            &f.owner,
                            &f.emit,
                            json!({"method":"Target.targetInfoChanged", "params":{
                                "targetInfo":capture_info("target", "page")
                            }}),
                        )
                        .await;
                    }
                    f.emit
                        .send(if protocol_failure {
                            json!({"id":request["id"], "error":{
                                "code":-32000, "message":"synthetic capture read failure"
                            }})
                        } else {
                            json!({"id":request["id"], "result":{}})
                        })
                        .await
                        .unwrap();
                    let result = tokio::time::timeout(Duration::from_secs(2), task)
                        .await
                        .unwrap()
                        .unwrap()
                        .map(|_| ());
                    assert_eq!(
                        result,
                        Err(if changed {
                            ProtocolError::StaleScope
                        } else if protocol_failure {
                            ProtocolError::BrowserFailure
                        } else {
                            ProtocolError::InvalidFrame
                        }),
                        "{method}: changed={changed}, protocol_failure={protocol_failure}"
                    );
                    // Protocol errors on a live wire do not retire capture
                    // authority or become blanket stale-scope failures.
                    assert!(watermark.received().is_ok());
                    assert!(f.owner.index.lock().unwrap().failure.is_none());
                    assert_eq!(f.requests(method).len(), reads + 1);
                    assert_eq!(f.requests("Target.getTargets").len(), inventories + 1);
                    assert_eq!(request["sessionId"].as_str().unwrap_or(""), session);
                    assert!(f
                        .owner
                        .targets
                        .owned_target("target")
                        .unwrap()
                        .same_attachment(&original));
                    f.assert_no_capture_mutations(before);
                    f.finish().await;
                }
            }
        }
    }

    // Distinguish remote EOF from a protocol error on the still-live stream.
    // Hold supervisor application so only the original route's loss decides.
    #[tokio::test]
    async fn capture_owned_inventory_eof_refuses_lost_original_stream() {
        for (method, session) in [
            ("Target.getTargets", ""),
            ("Target.getTargetInfo", "missing-session-a"),
            ("Page.getFrameTree", "initial"),
        ] {
            let f = CaptureWireFixture::new(false).await;
            if method == "Target.getTargetInfo" {
                f.attach("missing-a", "missing-session-a", "browser_ui")
                    .await;
            }
            f.held
                .lock()
                .unwrap()
                .insert((method.into(), session.into()));
            let reads = f.requests(method).len();
            let inventories = f.requests("Target.getTargets").len();
            let before = f.log.lock().unwrap().len();
            let watermark = f.owner.realm_watermark().unwrap();
            let (_sender, cancellation) = watch::channel(CancelSignal::None);
            let mut op = f.owner.operation();
            op.cancellation = cancellation.clone();
            let task = f.capture(op);
            let request = f.request(method, reads + 1).await;
            let event = f.gate(CaptureTestPoint::BeforeEventApply);
            f.emit
                .send(json!({"method":"Target.targetInfoChanged", "params":{
                    "targetInfo":capture_info("unrelated", "browser_ui")
                }}))
                .await
                .unwrap();
            event.wait_entered().await;
            f.emit.send(json!({"fixtureClose":true})).await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .map(|_| ()),
                Err(ProtocolError::ScopeUnavailable),
                "{method}"
            );
            assert!(*f.owner.client.remote_connection_closed().borrow());
            assert!(watermark.received().is_err());
            assert_eq!(*cancellation.borrow(), CancelSignal::None);
            assert!(f.owner.index.lock().unwrap().failure.is_none());
            assert_eq!(f.requests(method).len(), reads + 1);
            assert_eq!(f.requests("Target.getTargets").len(), inventories + 1);
            assert_eq!(request["sessionId"].as_str().unwrap_or(""), session);
            f.assert_no_capture_mutations(before);
            event.release();
            f.finish().await;
        }
    }

    // An error reply still drains pending events on the ORIGINAL operation.
    // It cannot skip cancellation/deadline or renew the lease while fencing.
    #[tokio::test]
    async fn capture_owned_inventory_failed_read_drain_keeps_operation_bounds() {
        for (method, session) in [
            ("Target.getTargets", ""),
            ("Target.getTargetInfo", "missing-session-a"),
            ("Page.getFrameTree", "initial"),
        ] {
            for cancel in [false, true] {
                let f = CaptureWireFixture::new(false).await;
                if method == "Target.getTargetInfo" {
                    f.attach("missing-a", "missing-session-a", "browser_ui")
                        .await;
                }
                f.held
                    .lock()
                    .unwrap()
                    .insert((method.into(), session.into()));
                let reads = f.requests(method).len();
                let (sender, cancellation) = watch::channel(CancelSignal::None);
                let mut op = f.owner.operation();
                op.cancellation = cancellation;
                op.deadline = Instant::now() + Duration::from_secs(3);
                let deadline = op.deadline;
                let task = f.capture(op);
                let request = f.request(method, reads + 1).await;
                let event = f.gate(CaptureTestPoint::BeforeEventApply);
                f.emit
                    .send(json!({"method":"Target.targetInfoChanged", "params":{
                        "targetInfo":capture_info("target", "page")
                    }}))
                    .await
                    .unwrap();
                event.wait_entered().await;
                let draining = f.gate(CaptureTestPoint::DrainWaiting);
                f.emit
                    .send(json!({"id":request["id"], "error":{
                        "code":-32000, "message":"synthetic capture read failure"
                    }}))
                    .await
                    .unwrap();
                draining.wait_entered().await;
                assert!(
                    !task.is_finished(),
                    "{method}: failed read skipped its drain"
                );
                let at_drain = f.log.lock().unwrap().len();
                if cancel {
                    sender.send_replace(CancelSignal::Requested);
                } else {
                    tokio::time::sleep_until(deadline.into()).await;
                }
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(2), task)
                        .await
                        .unwrap()
                        .unwrap()
                        .map(|_| ()),
                    Err(if cancel {
                        ProtocolError::Cancelled
                    } else {
                        ProtocolError::DeadlineExceeded
                    }),
                    "{method}: cancel={cancel}"
                );
                assert_eq!(f.log.lock().unwrap().len(), at_drain);
                assert_eq!(f.requests(method).len(), reads + 1);
                event.release();
                f.finish().await;
            }
        }
    }

    // poison() cancels owner operations as well as storing a cause. The cause,
    // not that secondary cancellation or a raw command error, remains visible.
    #[tokio::test]
    async fn capture_owned_inventory_failed_read_preserves_coordinator_failure() {
        for (method, session) in [
            ("Target.getTargets", ""),
            ("Target.getTargetInfo", "missing-session-a"),
            ("Page.getFrameTree", "initial"),
        ] {
            for failure in [ProtocolError::CleanupFailed, ProtocolError::BrowserFailure] {
                for independent_cancel in [false, true] {
                    let f = CaptureWireFixture::new(false).await;
                    if method == "Target.getTargetInfo" {
                        f.attach("missing-a", "missing-session-a", "browser_ui")
                            .await;
                    }
                    f.held
                        .lock()
                        .unwrap()
                        .insert((method.into(), session.into()));
                    let reads = f.requests(method).len();
                    let inventories = f.requests("Target.getTargets").len();
                    let (_sender, cancellation) = watch::channel(CancelSignal::None);
                    let mut op = f.owner.operation();
                    if independent_cancel {
                        op.cancellation = cancellation;
                    }
                    let task = f.capture(op);
                    let request = f.request(method, reads + 1).await;
                    f.owner.poison(failure.clone());
                    f.emit
                        .send(json!({"id":request["id"], "error":{
                            "code":-32000, "message":"synthetic capture read failure"
                        }}))
                        .await
                        .unwrap();
                    assert_eq!(
                        tokio::time::timeout(Duration::from_secs(2), task)
                            .await
                            .unwrap()
                            .unwrap()
                            .map(|_| ()),
                        Err(failure.clone()),
                        "{method}: failure={failure:?}, independent_cancel={independent_cancel}"
                    );
                    assert_eq!(f.requests(method).len(), reads + 1);
                    assert_eq!(f.requests("Target.getTargets").len(), inventories + 1);
                    assert_eq!(request["sessionId"].as_str().unwrap_or(""), session);
                    f.finish().await;
                }
            }
        }
    }

    // 7. Detach is reconciled before an old positive ACK can count as coverage.
    #[tokio::test]
    async fn capture_owned_inventory_detach_before_ack_and_dead_session_refuse() {
        for protocol_failure in [false, true] {
            let f = CaptureWireFixture::new(false).await;
            f.attach("missing-a", "missing-session-a", "browser_ui")
                .await;
            let task = f.capture(f.owner.operation());
            let request = f.request("Target.getTargetInfo", 1).await;
            realm_emit(&f.owner, &f.emit, json!({"method":"Target.detachedFromTarget", "params":{"sessionId":"missing-session-a", "targetId":"missing-a"}})).await;
            if protocol_failure {
                // A browser-global target may survive; its dead session is not replaced.
                f.inventory
                    .lock()
                    .unwrap()
                    .push(capture_info("missing-a", "browser_ui"));
                f.emit.send(json!({"id":request["id"], "error":{"code":-32000, "message":"session not found"}})).await.unwrap();
            } else {
                f.reply(&request, capture_info("missing-a", "browser_ui"))
                    .await;
            }
            assert_eq!(
                task.await.unwrap().map(|_| ()),
                Err(ProtocolError::StaleScope)
            );
            assert_eq!(f.requests("Target.getTargetInfo").len(), 1);
            assert_eq!(request["sessionId"], "missing-session-a");
            f.finish().await;
        }
    }

    // 8. Production detach/re-enrollment changes tenure even with identical IDs.
    #[tokio::test]
    async fn capture_owned_inventory_same_id_aba_and_new_session_never_redirect() {
        for replacement_session in ["missing-session-a", "replacement-session"] {
            let f = CaptureWireFixture::new(false).await;
            f.attach("missing-a", "missing-session-a", "browser_ui")
                .await;
            let original = f.owner.targets.owned_target("missing-a").unwrap();
            let task = f.capture(f.owner.operation());
            let request = f.request("Target.getTargetInfo", 1).await;
            realm_emit(&f.owner, &f.emit, json!({"method":"Target.detachedFromTarget", "params":{"sessionId":"missing-session-a", "targetId":"missing-a"}})).await;
            f.attach("missing-a", replacement_session, "browser_ui")
                .await;
            let replacement = f.owner.targets.owned_target("missing-a").unwrap();
            assert!(!replacement.same_attachment(&original));
            f.reply(&request, capture_info("missing-a", "browser_ui"))
                .await;
            assert_eq!(
                task.await.unwrap().map(|_| ()),
                Err(ProtocolError::StaleScope)
            );
            assert_eq!(f.requests("Target.getTargetInfo").len(), 1);
            assert_eq!(request["sessionId"], "missing-session-a");
            f.finish().await;
        }
    }

    // 9. Neither an old matching nor a changed reply heals an event epoch change.
    #[tokio::test]
    async fn capture_owned_inventory_context_and_kind_events_invalidate_held_reply() {
        for changed_field in ["browserContextId", "type"] {
            for changed_reply in [false, true] {
                let f = CaptureWireFixture::new(false).await;
                f.attach("missing-a", "missing-session-a", "browser_ui")
                    .await;
                let task = f.capture(f.owner.operation());
                let request = f.request("Target.getTargetInfo", 1).await;
                let mut changed = capture_info("missing-a", "browser_ui");
                changed[changed_field] = json!(if changed_field == "type" {
                    "worker"
                } else {
                    "foreign"
                });
                realm_emit(
                    &f.owner,
                    &f.emit,
                    json!({"method":"Target.targetInfoChanged", "params":{"targetInfo":changed}}),
                )
                .await;
                f.reply(
                    &request,
                    if changed_reply {
                        changed
                    } else {
                        capture_info("missing-a", "browser_ui")
                    },
                )
                .await;
                assert_eq!(
                    task.await.unwrap().map(|_| ()),
                    Err(ProtocolError::StaleScope)
                );
                f.finish().await;
            }
        }
    }

    // 10. Observe the real post-ACK not-ready drain branch while application is
    // gated, then ACK a server barrier before checking for renderer commands.
    #[tokio::test]
    async fn capture_owned_inventory_ack_waits_for_current_reader_watermark() {
        let f = CaptureWireFixture::new(false).await;
        f.attach("missing-a", "missing-session-a", "browser_ui")
            .await;
        let frames = f.requests("Page.getFrameTree").len();
        let ack = f.gate(CaptureTestPoint::AfterInfoAck);
        let event = f.gate(CaptureTestPoint::BeforeEventApply);
        let op = f.owner.operation();
        let capture = f.owner.attest_capture(&op);
        tokio::pin!(capture);
        let request = tokio::select! {
            request = f.request("Target.getTargetInfo", 1) => request,
            _ = &mut capture => panic!("capture completed before the held info request"),
        };
        f.emit.send(json!({"method":"Target.targetInfoChanged", "params":{"targetInfo":capture_info("missing-a", "browser_ui")}})).await.unwrap();
        event.wait_entered().await;
        f.reply(&request, capture_info("missing-a", "browser_ui"))
            .await;
        tokio::select! {
            _ = ack.wait_entered() => {},
            _ = &mut capture => panic!("capture completed before the ACK gate"),
        }
        let watermark = f.owner.realm_watermark().unwrap();
        assert!(watermark.received().unwrap() > f.owner.index.lock().unwrap().applied_watermark);
        let draining = f.gate(CaptureTestPoint::DrainWaiting);
        ack.release();
        tokio::select! {
            _ = draining.wait_entered() => {},
            _ = &mut capture => panic!("capture completed before entering its post-ACK drain wait"),
        }
        f.server_barrier().await;
        assert_eq!(f.requests("Page.getFrameTree").len(), frames);
        event.release();
        assert_eq!(capture.await.map(|_| ()), Err(ProtocolError::StaleScope));
        // The pinned future borrows f, so settle the fixture without moving it.
        let _ = f.owner.close().await;
        f.server.abort();
    }

    // 11. A first completion cannot make a later admitted attach disappear.
    #[tokio::test]
    async fn capture_owned_inventory_new_attach_after_drain_is_not_old_readiness() {
        for hold_before_apply in [false, true] {
            let f = CaptureWireFixture::new(false).await;
            let runtime_before = f.requests("Runtime.enable").len();
            f.held
                .lock()
                .unwrap()
                .insert(("Runtime.enable".into(), "first-session".into()));
            f.emit
                .send(capture_attach_event("first", "first-session", "browser_ui"))
                .await
                .unwrap();
            let first = f.request("Runtime.enable", runtime_before + 1).await;
            let drained = f.gate(CaptureTestPoint::AfterInitialDrain);
            let inventory_before = f.requests("Target.getTargets").len();
            let task = f.capture(f.owner.operation());
            f.emit
                .send(json!({"id":first["id"], "result":{}}))
                .await
                .unwrap();
            drained.wait_entered().await;
            let event_gate = hold_before_apply.then(|| f.gate(CaptureTestPoint::BeforeEventApply));
            f.held
                .lock()
                .unwrap()
                .insert(("Runtime.enable".into(), "second-session".into()));
            f.emit
                .send(capture_attach_event(
                    "second",
                    "second-session",
                    "browser_ui",
                ))
                .await
                .unwrap();
            let second = if let Some(gate) = &event_gate {
                gate.wait_entered().await;
                None
            } else {
                Some(f.request("Runtime.enable", runtime_before + 2).await)
            };
            if !hold_before_apply {
                assert!(f
                    .owner
                    .index
                    .lock()
                    .unwrap()
                    .pending_enrollment
                    .contains("second-session"));
            }
            drained.release();
            assert_eq!(
                task.await.unwrap().map(|_| ()),
                Err(ProtocolError::StaleScope)
            );
            assert_eq!(f.requests("Target.getTargets").len(), inventory_before);
            assert!(f.requests("Target.getTargetInfo").is_empty());
            if let Some(gate) = event_gate {
                gate.release();
            }
            let second = match second {
                Some(request) => request,
                None => f.request("Runtime.enable", runtime_before + 2).await,
            };
            f.emit
                .send(json!({"id":second["id"], "result":{}}))
                .await
                .unwrap();
            f.owner
                .drain_capture_watermark(&f.owner.realm_watermark().unwrap(), &f.owner.operation())
                .await
                .unwrap();
            f.finish().await;
        }
    }

    #[tokio::test]
    async fn capture_owned_inventory_admission_after_fence_drain_refuses_before_dispatch() {
        let f = CaptureWireFixture::new(false).await;
        f.attach("missing-a", "missing-session-a", "browser_ui")
            .await;
        let drained = f.gate(CaptureTestPoint::AfterFenceDrain);
        let event = f.gate(CaptureTestPoint::BeforeEventApply);
        let task = f.capture(f.owner.operation());
        drained.wait_entered().await;
        f.emit
            .send(capture_attach_event(
                "new-target",
                "new-session",
                "browser_ui",
            ))
            .await
            .unwrap();
        event.wait_entered().await;
        assert!(
            f.owner.realm_watermark().unwrap().received().unwrap()
                > f.owner.index.lock().unwrap().applied_watermark
        );
        drained.release();
        assert_eq!(
            task.await.unwrap().map(|_| ()),
            Err(ProtocolError::StaleScope)
        );
        assert!(f.requests("Target.getTargetInfo").is_empty());
        event.release();
        f.owner
            .drain_capture_watermark(&f.owner.realm_watermark().unwrap(), &f.owner.operation())
            .await
            .unwrap();
        f.finish().await;
    }

    #[tokio::test]
    async fn capture_owned_inventory_cancel_or_deadline_during_post_ack_drain() {
        for cancel in [false, true] {
            let f = CaptureWireFixture::new(false).await;
            f.attach("missing-a", "missing-session-a", "browser_ui")
                .await;
            let frames = f.requests("Page.getFrameTree").len();
            let event = f.gate(CaptureTestPoint::BeforeEventApply);
            let ack = f.gate(CaptureTestPoint::AfterInfoAck);
            let (sender, cancellation) = watch::channel(CancelSignal::None);
            let mut op = f.owner.operation();
            op.cancellation = cancellation;
            op.deadline = Instant::now() + Duration::from_secs(3);
            let capture = f.owner.attest_capture(&op);
            tokio::pin!(capture);
            let request = tokio::select! {
                request = f.request("Target.getTargetInfo", 1) => request,
                _ = &mut capture => panic!("capture completed before info dispatch"),
            };
            f.emit.send(json!({"method":"Target.targetInfoChanged", "params":{"targetInfo":capture_info("missing-a", "browser_ui")}})).await.unwrap();
            event.wait_entered().await;
            f.reply(&request, capture_info("missing-a", "browser_ui"))
                .await;
            tokio::select! {
                _ = ack.wait_entered() => {},
                _ = &mut capture => panic!("capture completed before the ACK gate"),
            }
            let draining = f.gate(CaptureTestPoint::DrainWaiting);
            ack.release();
            tokio::select! {
                _ = draining.wait_entered() => {},
                _ = &mut capture => panic!("capture completed before entering its post-ACK drain wait"),
            }
            f.server_barrier().await;
            assert_eq!(f.requests("Page.getFrameTree").len(), frames);
            if cancel {
                sender.send_replace(CancelSignal::Requested);
            } else {
                tokio::time::sleep_until(op.deadline.into()).await;
            }
            assert_eq!(
                capture.await.map(|_| ()),
                Err(if cancel {
                    ProtocolError::Cancelled
                } else {
                    ProtocolError::DeadlineExceeded
                })
            );
            assert_eq!(f.requests("Page.getFrameTree").len(), frames);
            assert_eq!(f.requests("Target.getTargetInfo").len(), 1);
            event.release();
            let _ = f.owner.close().await;
            f.server.abort();
        }
    }

    // 12. Only relevant retirement fails; historical unrelated tombstones and
    // StateBootstrap churn do not become a registry-global revision fence.
    #[tokio::test]
    async fn capture_owned_inventory_retirement_health_and_original_stream() {
        for case in [
            "target-retirement",
            "root-retirement",
            "retired-session",
            "borrowed-restart",
            "sealed",
            "poisoned",
            "dropped-stream",
            "replaced-stream",
            "overflow",
            "unrelated-retirement",
            "bootstrap",
        ] {
            let f = CaptureWireFixture::new(false).await;
            f.attach("missing-a", "missing-session-a", "browser_ui")
                .await;
            let task = f.capture(f.owner.operation());
            let request = f.request("Target.getTargetInfo", 1).await;
            let mut event_gate = None;
            let mut replacement_stream = None;
            let original_watermark = f.owner.realm_watermark().unwrap();
            match case {
                "target-retirement" => {
                    f.owner
                        .index
                        .lock()
                        .unwrap()
                        .retiring_pages
                        .insert("missing-a".into(), "missing-session-a".into());
                }
                "root-retirement" => {
                    f.owner
                        .index
                        .lock()
                        .unwrap()
                        .retiring_pages
                        .insert("other".into(), "missing-session-a".into());
                }
                "retired-session" => {
                    f.owner
                        .index
                        .lock()
                        .unwrap()
                        .retired_page_sessions
                        .insert("missing-session-a".into());
                }
                "borrowed-restart" => f.owner.index.lock().unwrap().borrowed_restart = Some(1),
                "sealed" => f.owner.sealed.store(true, Ordering::Release),
                "poisoned" => f.owner.poison(ProtocolError::BrowserFailure),
                "dropped-stream" | "replaced-stream" => {
                    let supervisor = f.owner.supervisor.lock().await.take().unwrap();
                    supervisor.abort();
                    let _ = supervisor.await;
                    assert!(original_watermark.received().is_err());
                    if case == "replaced-stream" {
                        let events = f
                            .owner
                            .client
                            .subscribe_bounded_methods(EVENTS, 256, 128 * 1024 * 1024)
                            .unwrap();
                        *f.owner.event_watermark.lock().unwrap() = Some(events.watermark());
                        assert!(f.owner.realm_watermark().unwrap().received().is_ok());
                        replacement_stream = Some(events);
                    }
                }
                "overflow" => {
                    let gate = f.gate(CaptureTestPoint::BeforeEventApply);
                    f.emit.send(json!({"method":"Target.targetInfoChanged", "params":{"targetInfo":capture_info("unrelated", "browser_ui")}})).await.unwrap();
                    gate.wait_entered().await;
                    for _ in 0..257 {
                        f.emit.send(json!({"method":"Target.targetInfoChanged", "params":{"targetInfo":capture_info("unrelated", "browser_ui")}})).await.unwrap();
                    }
                    let watermark = f.owner.realm_watermark().unwrap();
                    tokio::time::timeout(Duration::from_secs(2), async {
                        while watermark.received().is_ok() {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .unwrap();
                    event_gate = Some(gate);
                }
                "unrelated-retirement" => {
                    let mut index = f.owner.index.lock().unwrap();
                    index
                        .retiring_pages
                        .insert("old-target".into(), "old-session".into());
                    index.retired_page_sessions.insert("old-session".into());
                }
                "bootstrap" => {
                    let mut reservation = f
                        .owner
                        .targets
                        .reserve_creation(TargetPurpose::StateBootstrap)
                        .unwrap();
                    f.owner
                        .targets
                        .attached(
                            "owned-context",
                            "bootstrap".into(),
                            "bootstrap-session".into(),
                            "page".into(),
                        )
                        .unwrap();
                    reservation.claim("bootstrap").unwrap();
                    drop(reservation);
                    f.owner.targets.configured("bootstrap").unwrap();
                    f.owner.targets.detach("bootstrap").unwrap();
                }
                _ => unreachable!(),
            }
            f.reply(&request, capture_info("missing-a", "browser_ui"))
                .await;
            let result = task.await.unwrap();
            assert_eq!(
                result.is_ok(),
                matches!(case, "unrelated-retirement" | "bootstrap"),
                "{case}"
            );
            if let Some(gate) = event_gate {
                gate.release();
            }
            drop(replacement_stream);
            f.finish().await;
        }
    }

    // 13. The same operation deadline and cancellation gate every boundary.
    #[tokio::test]
    async fn capture_owned_inventory_original_lease_bounds_every_stage() {
        for cancel in [false, true] {
            for stage in [
                "before-inventory",
                "before-info",
                "held-info",
                "after-ack",
                "before-return",
                "before-verify-return",
            ] {
                let f = CaptureWireFixture::new(false).await;
                f.attach("missing-a", "missing-session-a", "browser_ui")
                    .await;
                let (sender, cancellation) = watch::channel(CancelSignal::None);
                let mut op = f.owner.operation();
                op.cancellation = cancellation;
                op.deadline = if stage == "before-inventory" && !cancel {
                    Instant::now()
                } else {
                    Instant::now() + Duration::from_secs(3)
                };
                let deadline = op.deadline;
                let before = f.log.lock().unwrap().len();
                if stage == "before-inventory" {
                    if cancel {
                        sender.send_replace(CancelSignal::Requested);
                    }
                    assert_eq!(
                        f.owner.attest_capture(&op).await.map(|_| ()),
                        Err(if cancel {
                            ProtocolError::Cancelled
                        } else {
                            ProtocolError::DeadlineExceeded
                        })
                    );
                    assert_eq!(f.log.lock().unwrap().len(), before);
                    f.finish().await;
                    continue;
                }
                let point = match stage {
                    "before-info" => Some(CaptureTestPoint::BeforeInfo),
                    "after-ack" => Some(CaptureTestPoint::AfterInfoAck),
                    "before-return" => Some(CaptureTestPoint::BeforeReturn),
                    "before-verify-return" => Some(CaptureTestPoint::BeforeVerifyReturn),
                    _ => None,
                };
                let gate = point.map(|point| f.gate(point));
                let task = if stage == "before-verify-return" {
                    let first = f.capture(f.owner.operation());
                    let request = f.request("Target.getTargetInfo", 1).await;
                    f.reply(&request, capture_info("missing-a", "browser_ui"))
                        .await;
                    let proof = first.await.unwrap().unwrap();
                    f.inventory
                        .lock()
                        .unwrap()
                        .push(capture_info("missing-a", "browser_ui"));
                    let owner = f.owner.clone();
                    tokio::spawn(async move { owner.verify_capture_attestation(&proof, &op).await })
                } else {
                    let capture = f.capture(op);
                    tokio::spawn(async move { capture.await.unwrap().map(|_| ()) })
                };
                if stage != "before-info" && stage != "before-verify-return" {
                    let request = f.request("Target.getTargetInfo", 1).await;
                    if stage != "held-info" {
                        f.reply(&request, capture_info("missing-a", "browser_ui"))
                            .await;
                    }
                }
                if let Some(gate) = &gate {
                    gate.wait_entered().await;
                }
                let at_invalidation = f.log.lock().unwrap().len();
                if cancel {
                    sender.send_replace(CancelSignal::Requested);
                } else {
                    tokio::time::sleep_until(deadline.into()).await;
                }
                if let Some(gate) = &gate {
                    gate.release();
                }
                assert_eq!(
                    task.await.unwrap(),
                    Err(if cancel {
                        ProtocolError::Cancelled
                    } else {
                        ProtocolError::DeadlineExceeded
                    }),
                    "{stage}"
                );
                assert_eq!(f.log.lock().unwrap().len(), at_invalidation);
                f.finish().await;
            }
        }
    }

    // 14. Post-export proof compares the original tickets even if enumeration
    // now includes the same string IDs. Include an epoch-independent ABA case.
    #[tokio::test]
    async fn capture_owned_inventory_post_export_keeps_original_owner_when_enumerable() {
        for case in ["unchanged", "event-aba", "registry-aba", "context-event"] {
            let f = CaptureWireFixture::new(false).await;
            f.attach("missing-a", "missing-session-a", "browser_ui")
                .await;
            let task = f.capture(f.owner.operation());
            let request = f.request("Target.getTargetInfo", 1).await;
            f.reply(&request, capture_info("missing-a", "browser_ui"))
                .await;
            let proof = task.await.unwrap().unwrap();
            let epoch = f.owner.index.lock().unwrap().application_epoch;
            match case {
                "event-aba" => {
                    realm_emit(&f.owner, &f.emit, json!({"method":"Target.detachedFromTarget", "params":{"sessionId":"missing-session-a", "targetId":"missing-a"}})).await;
                    f.attach("missing-a", "missing-session-a", "browser_ui")
                        .await;
                }
                "registry-aba" => {
                    // Authoritative insertion only, no epoch edits: isolate tenure.
                    f.owner.targets.detach("missing-a").unwrap();
                    f.owner
                        .targets
                        .attached(
                            "owned-context",
                            "missing-a".into(),
                            "missing-session-a".into(),
                            "browser_ui".into(),
                        )
                        .unwrap();
                    f.owner.targets.configured("missing-a").unwrap();
                    f.owner
                        .targets
                        .resume_permit("missing-a")
                        .await
                        .unwrap()
                        .complete()
                        .unwrap();
                    assert_eq!(f.owner.index.lock().unwrap().application_epoch, epoch);
                }
                "context-event" => {
                    let mut info = capture_info("missing-a", "browser_ui");
                    info["browserContextId"] = json!("foreign");
                    realm_emit(
                        &f.owner,
                        &f.emit,
                        json!({"method":"Target.targetInfoChanged", "params":{"targetInfo":info}}),
                    )
                    .await;
                }
                _ => {}
            }
            f.inventory
                .lock()
                .unwrap()
                .push(capture_info("missing-a", "browser_ui"));
            let result = f
                .owner
                .verify_capture_attestation(&proof, &f.owner.operation())
                .await;
            assert_eq!(result.is_ok(), case == "unchanged", "{case}");
            assert_eq!(f.requests("Target.getTargetInfo").len(), 1);
            f.finish().await;
        }
    }

    #[tokio::test]
    async fn capture_owned_inventory_fresh_second_attestation_cannot_replace_original_ticket() {
        let f = CaptureWireFixture::new(false).await;
        f.attach("missing-a", "missing-session-a", "browser_ui")
            .await;
        let first = f.capture(f.owner.operation());
        let request = f.request("Target.getTargetInfo", 1).await;
        f.reply(&request, capture_info("missing-a", "browser_ui"))
            .await;
        let proof = first.await.unwrap().unwrap();
        let original = f.owner.targets.owned_target("missing-a").unwrap();
        let original_epoch = f.owner.index.lock().unwrap().application_epoch;
        let frames_before_verify = f.requests("Page.getFrameTree").len();
        let before_fresh_snapshot = f.gate(CaptureTestPoint::AfterInitialDrain);
        let fresh_completed = f.gate(CaptureTestPoint::AfterFreshAttestation);
        let owner = f.owner.clone();
        let verify = tokio::spawn(async move {
            owner
                .verify_capture_attestation(&proof, &owner.operation())
                .await
        });
        before_fresh_snapshot.wait_entered().await;
        // Verify's first original-ticket fence has passed. Replace only through
        // authoritative registry insertion during the second attestation, before
        // it snapshots the new tenure. No hand-edited epoch can cause rejection.
        f.owner.targets.detach("missing-a").unwrap();
        f.owner
            .targets
            .attached(
                "owned-context",
                "missing-a".into(),
                "missing-session-a".into(),
                "browser_ui".into(),
            )
            .unwrap();
        f.owner.targets.configured("missing-a").unwrap();
        f.owner
            .targets
            .resume_permit("missing-a")
            .await
            .unwrap()
            .complete()
            .unwrap();
        assert!(!f
            .owner
            .targets
            .owned_target("missing-a")
            .unwrap()
            .same_attachment(&original));
        assert_eq!(
            f.owner.index.lock().unwrap().application_epoch,
            original_epoch
        );
        f.inventory
            .lock()
            .unwrap()
            .push(capture_info("missing-a", "browser_ui"));
        before_fresh_snapshot.release();
        fresh_completed.wait_entered().await;
        // The fresh attestation succeeded with a new, now-enumerable ticket.
        // Its own final checks therefore cannot be the source of this refusal.
        f.server_barrier().await;
        assert_eq!(
            f.requests("Page.getFrameTree").len(),
            frames_before_verify + 1
        );
        assert_eq!(f.requests("Target.getTargetInfo").len(), 1);
        assert_eq!(
            f.owner.index.lock().unwrap().application_epoch,
            original_epoch
        );
        fresh_completed.release();
        assert_eq!(verify.await.unwrap(), Err(ProtocolError::StaleScope));
        f.finish().await;
    }

    // A failed fresh attestation still checks the PREVIOUS proof. Replacing
    // only registry tenure before the fresh snapshot isolates this outer fence.
    #[tokio::test]
    async fn capture_owned_inventory_failed_fresh_attestation_keeps_original_ticket() {
        for replace in [false, true] {
            for protocol_failure in [false, true] {
                let f = CaptureWireFixture::new(false).await;
                f.attach("missing-a", "missing-session-a", "browser_ui")
                    .await;
                let first = f.capture(f.owner.operation());
                let request = f.request("Target.getTargetInfo", 1).await;
                f.reply(&request, capture_info("missing-a", "browser_ui"))
                    .await;
                let proof = tokio::time::timeout(Duration::from_secs(2), first)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                let original = f.owner.targets.owned_target("missing-a").unwrap();
                let epoch = f.owner.index.lock().unwrap().application_epoch;
                let inventories = f.requests("Target.getTargets").len();
                let frames = f.requests("Page.getFrameTree").len();
                f.inventory
                    .lock()
                    .unwrap()
                    .push(capture_info("missing-a", "browser_ui"));
                f.held
                    .lock()
                    .unwrap()
                    .insert(("Target.getTargets".into(), "".into()));
                let before_snapshot = f.gate(CaptureTestPoint::AfterInitialDrain);
                let owner = f.owner.clone();
                let task = tokio::spawn(async move {
                    owner
                        .verify_capture_attestation(&proof, &owner.operation())
                        .await
                });
                before_snapshot.wait_entered().await;
                if replace {
                    // No index/epoch edits and no session redirect: only an
                    // authoritative reinsertion of the identical target/session.
                    f.owner.targets.detach("missing-a").unwrap();
                    f.owner
                        .targets
                        .attached(
                            "owned-context",
                            "missing-a".into(),
                            "missing-session-a".into(),
                            "browser_ui".into(),
                        )
                        .unwrap();
                    f.owner.targets.configured("missing-a").unwrap();
                    f.owner
                        .targets
                        .resume_permit("missing-a")
                        .await
                        .unwrap()
                        .complete()
                        .unwrap();
                }
                assert_eq!(
                    f.owner
                        .targets
                        .owned_target("missing-a")
                        .unwrap()
                        .same_attachment(&original),
                    !replace
                );
                assert_eq!(f.owner.index.lock().unwrap().application_epoch, epoch);
                before_snapshot.release();
                let request = f.request("Target.getTargets", inventories + 1).await;
                f.emit
                    .send(if protocol_failure {
                        json!({"id":request["id"], "error":{
                            "code":-32000, "message":"synthetic fresh inventory failure"
                        }})
                    } else {
                        json!({"id":request["id"], "result":{}})
                    })
                    .await
                    .unwrap();
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(2), task)
                        .await
                        .unwrap()
                        .unwrap(),
                    Err(if replace {
                        ProtocolError::StaleScope
                    } else if protocol_failure {
                        ProtocolError::BrowserFailure
                    } else {
                        ProtocolError::InvalidFrame
                    }),
                    "replace={replace}, protocol_failure={protocol_failure}"
                );
                assert_eq!(f.requests("Target.getTargets").len(), inventories + 1);
                assert_eq!(f.requests("Target.getTargetInfo").len(), 1);
                assert_eq!(f.requests("Page.getFrameTree").len(), frames);
                assert_eq!(f.owner.index.lock().unwrap().application_epoch, epoch);
                f.finish().await;
            }
        }
    }

    #[tokio::test]
    async fn capture_owned_inventory_failed_fresh_attestation_preserves_coordinator_failure() {
        for failure in [ProtocolError::CleanupFailed, ProtocolError::BrowserFailure] {
            let f = CaptureWireFixture::new(false).await;
            let proof = f.owner.attest_capture(&f.owner.operation()).await.unwrap();
            let inventories = f.requests("Target.getTargets").len();
            let before_snapshot = f.gate(CaptureTestPoint::AfterInitialDrain);
            let owner = f.owner.clone();
            let task = tokio::spawn(async move {
                owner
                    .verify_capture_attestation(&proof, &owner.operation())
                    .await
            });
            before_snapshot.wait_entered().await;
            f.owner.poison(failure.clone());
            before_snapshot.release();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap(),
                Err(failure)
            );
            assert_eq!(f.requests("Target.getTargets").len(), inventories);
            f.finish().await;
        }
    }

    // 15. Unknown same-context and observer-only omissions never gain ownership.
    #[tokio::test]
    async fn capture_owned_inventory_never_expands_authority() {
        for case in [
            "unowned-page",
            "unowned-kind",
            "missing-observer",
            "foreign-tab-browser",
        ] {
            let f = CaptureWireFixture::new(case == "missing-observer").await;
            if case == "missing-observer" {
                f.attach("other-host", "observer-session", "page").await;
                assert!(
                    f.owner.index.lock().unwrap().sessions["observer-session"].observation_only
                );
            } else if case == "foreign-tab-browser" {
                let mut foreign = capture_info("foreign", "page");
                foreign["browserContextId"] = json!("foreign-context");
                f.inventory.lock().unwrap().extend([
                    foreign,
                    capture_info("unowned-tab", "tab"),
                    json!({"targetId":"browser", "type":"browser"}),
                ]);
            } else {
                f.inventory.lock().unwrap().push(capture_info(
                    "unowned",
                    if case == "unowned-page" {
                        "page"
                    } else {
                        "future-kind"
                    },
                ));
            }
            let before = f.log.lock().unwrap().len();
            let revision = f.owner.targets.inventory().unwrap().0;
            let result = f.owner.attest_capture(&f.owner.operation()).await;
            assert_eq!(result.is_ok(), case == "foreign-tab-browser", "{case}");
            assert!(f.requests("Target.getTargetInfo").is_empty());
            assert_eq!(f.owner.targets.inventory().unwrap().0, revision);
            assert_eq!(f.owner.targets.inventory().unwrap().1.len(), 1);
            f.assert_no_capture_mutations(before);
            f.finish().await;
        }
    }

    // 16. Production reads do not invoke the historical global diagnostic read.
    #[tokio::test]
    async fn capture_owned_inventory_reports_are_private_and_budget_is_exact() {
        let f = CaptureWireFixture::new(false).await;
        f.attach("missing-a", "missing-session-a", "browser_ui")
            .await;
        let before = f.log.lock().unwrap().len();
        let task = f.capture(f.owner.operation());
        let request = f.request("Target.getTargetInfo", 1).await;
        let mut info = capture_info("missing-a", "browser_ui");
        info["url"] = json!("https://private-url-marker.invalid/secret");
        info["title"] = json!("private-title-marker");
        f.reply(&request, info).await;
        task.await.unwrap().unwrap();
        let printed = format!("{:?}", f.owner.capture_lifecycle.lock().unwrap().rows);
        for secret in [
            "private-url-marker",
            "private-title-marker",
            "missing-a",
            "missing-session-a",
            "owned-context",
            "https://",
        ] {
            assert!(!printed.contains(secret));
        }
        assert!(f
            .owner
            .capture_lifecycle
            .lock()
            .unwrap()
            .missing_lookup
            .is_none());
        assert_eq!(f.requests("Target.getTargetInfo").len(), 1);
        assert_eq!(
            f.log.lock().unwrap()[before..]
                .iter()
                .map(|r| r["method"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "Target.getTargets",
                "Target.getTargetInfo",
                "Page.getFrameTree"
            ]
        );
        f.assert_no_capture_mutations(before);
        f.finish().await;
    }

    #[tokio::test]
    async fn capture_attestation_requires_reconciliation_and_exact_healthy_tenure() {
        let (owner, _notices, _log, _emit, server) = fixture("attestation").await;
        owner
            .enroll_existing("target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        assert!(matches!(
            owner.attest_capture(&owner.operation()).await,
            Err(ProtocolError::ScopeUnavailable)
        ));
        owner.start(&owner.operation()).await.unwrap();
        let proof = owner.attest_capture(&owner.operation()).await.unwrap();
        owner
            .verify_capture_attestation(&proof, &owner.operation())
            .await
            .unwrap();
        let (other, _n, _l, _e, other_server) = fixture("attestation").await;
        assert_eq!(
            other
                .verify_capture_attestation(&proof, &other.operation())
                .await,
            Err(ProtocolError::StaleScope)
        );
        owner.close().await.unwrap();
        assert!(owner
            .verify_capture_attestation(&proof, &owner.operation())
            .await
            .is_err());
        server.abort();
        other_server.abort();
    }
    async fn enroll_capture_tab(
        owner: &Arc<ClientEnrollment>,
        emit: &tokio::sync::mpsc::Sender<Value>,
    ) {
        owner
            .enroll_existing("target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner.start(&owner.operation()).await.unwrap();
        // Exercise the production reader, supervisor, context admission,
        // initialization and resume path, not a handcrafted Attribution.
        realm_emit(
            owner,
            emit,
            json!({
                "method":"Target.attachedToTarget",
                "params":{
                    "sessionId":"tab-session",
                    "waitingForDebugger":true,
                    "targetInfo":{
                        "targetId":"tab-target","type":"tab","browserContextId":"owned-context"
                    }
                }
            }),
        )
        .await;
        let owned = owner.targets.owned_target("tab-target").unwrap();
        assert_eq!(owned.kind, "tab");
        assert_eq!(owned.purpose, Some(TargetPurpose::Application));
        assert!(owned.configured && owned.resumed);
        let entry = owner.index.lock().unwrap().sessions["tab-session"].clone();
        assert_eq!(entry.kind, "tab");
        assert!(entry.application && entry.resumed);
        assert!(!entry.observation_only);
    }
    #[tokio::test]
    async fn capture_attestation_complete_inventory_includes_native_tab_without_adoption() {
        let (owner, _notices, log, emit, server) = fixture("attestation-complete").await;
        enroll_capture_tab(&owner, &emit).await;
        let entries = owner
            .index
            .lock()
            .unwrap()
            .sessions
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let default_inventory = owner
            .command(&owner.operation(), None, "Target.getTargets", json!({}))
            .await
            .unwrap();
        assert_eq!(
            capture_inventory_diagnostic(
                &entries,
                default_inventory["targetInfos"].as_array().unwrap(),
                "owned-context"
            ),
            CaptureInventoryDiagnostic {
                entries: 2,
                inventory: 1,
                missing: 1,
                absent_target: 1,
                application: 1,
                other: 1,
                ..Default::default()
            }
        );
        let revision = owner.targets.inventory().unwrap().0;
        let epoch = owner.index.lock().unwrap().application_epoch;
        let proof = owner.attest_capture(&owner.operation()).await.unwrap();
        owner
            .verify_capture_attestation(&proof, &owner.operation())
            .await
            .unwrap();
        assert_eq!(owner.targets.inventory().unwrap().0, revision);
        assert_eq!(owner.targets.inventory().unwrap().1.len(), 2);
        assert_eq!(owner.index.lock().unwrap().application_epoch, epoch);
        assert_eq!(owner.index.lock().unwrap().sessions.len(), 2);
        for target in ["unowned-tab", "foreign-tab", "browser"] {
            assert!(matches!(
                owner.targets.owned_target(target),
                Err(ProtocolError::StaleReference)
            ));
        }
        {
            let requests = log.lock().unwrap();
            let inventories = requests
                .iter()
                .filter(|request| request["method"] == "Target.getTargets")
                .collect::<Vec<_>>();
            assert_eq!(inventories.len(), 4);
            assert_eq!(
                inventories[0]["params"],
                json!({"filter":[{"type":"browser","exclude":true},{"type":"tab","exclude":true},{}]})
            );
            assert_eq!(inventories[1]["params"], json!({}));
            for request in &inventories[2..] {
                assert_eq!(request["params"], json!({"filter":[{}]}));
            }
            assert!(!requests
                .iter()
                .any(|request| request["method"] == "Page.getFrameTree"
                    && request["sessionId"] == "tab-session"));
            assert!(requests
                .iter()
                .filter(|request| request["method"] == "Target.setAutoAttach")
                .all(|request| request["params"] == autoattach(true)));
        }
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn capture_attestation_complete_inventory_rejects_missing_foreign_and_unowned_targets() {
        for (mode, expected) in [
            (
                "attestation-complete-missing-target",
                ProtocolError::StaleScope,
            ),
            (
                "attestation-complete-missing-context",
                ProtocolError::InvalidFrame,
            ),
            (
                "attestation-complete-foreign-context",
                ProtocolError::StaleScope,
            ),
            (
                "attestation-complete-unowned-page",
                ProtocolError::StaleReference,
            ),
            (
                "attestation-complete-unknown-kind",
                ProtocolError::StaleReference,
            ),
        ] {
            let (owner, _notices, log, emit, server) = fixture(mode).await;
            enroll_capture_tab(&owner, &emit).await;
            let revision = owner.targets.inventory().unwrap().0;
            let epoch = owner.index.lock().unwrap().application_epoch;
            let frames_before = log
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request["method"] == "Page.getFrameTree")
                .count();
            assert!(
                matches!(owner.attest_capture(&owner.operation()).await, Err(error) if error == expected),
                "accepted {mode}"
            );
            assert_eq!(
                log.lock()
                    .unwrap()
                    .iter()
                    .filter(|request| request["method"] == "Page.getFrameTree")
                    .count(),
                frames_before,
                "{mode} reached renderer capture before inventory proof"
            );
            assert_eq!(owner.targets.inventory().unwrap().0, revision);
            assert_eq!(owner.targets.inventory().unwrap().1.len(), 2);
            assert_eq!(owner.index.lock().unwrap().application_epoch, epoch);
            assert_eq!(owner.index.lock().unwrap().sessions.len(), 2);
            for target in [
                "unowned-tab",
                "foreign-tab",
                "browser",
                "unowned-page",
                "unknown-kind",
            ] {
                assert!(matches!(
                    owner.targets.owned_target(target),
                    Err(ProtocolError::StaleReference)
                ));
            }
            owner.close().await.unwrap();
            server.abort();
        }
    }
    #[tokio::test]
    async fn capture_attestation_rejects_each_missing_target_inventory_category() {
        for (mode, absent_target, missing_context, foreign_context) in [
            ("attestation-missing-target", 1, 0, 0),
            ("attestation-missing-context", 0, 1, 0),
            ("attestation-foreign-context", 0, 0, 1),
        ] {
            let (owner, _notices, log, _emit, server) = fixture(mode).await;
            owner
                .enroll_existing("target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            owner.start(&owner.operation()).await.unwrap();
            let frames_before = log
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request["method"] == "Page.getFrameTree")
                .count();
            assert!(
                matches!(
                    owner.attest_capture(&owner.operation()).await,
                    Err(error) if error == if missing_context != 0 { ProtocolError::InvalidFrame } else { ProtocolError::StaleScope }
                ),
                "accepted {mode}"
            );
            assert_eq!(
                log.lock()
                    .unwrap()
                    .iter()
                    .filter(|request| request["method"] == "Page.getFrameTree")
                    .count(),
                frames_before,
                "{mode} reached renderer capture before inventory proof"
            );
            let inventory = owner
                .command(&owner.operation(), None, "Target.getTargets", json!({}))
                .await
                .unwrap();
            let entries = owner
                .index
                .lock()
                .unwrap()
                .sessions
                .values()
                .cloned()
                .collect::<Vec<_>>();
            let diagnostic = capture_inventory_diagnostic(
                &entries,
                inventory["targetInfos"].as_array().unwrap(),
                "owned-context",
            );
            assert_eq!(
                diagnostic,
                CaptureInventoryDiagnostic {
                    entries: 1,
                    inventory: usize::from(absent_target == 0),
                    missing: 1,
                    absent_target,
                    missing_context,
                    foreign_context,
                    application: 1,
                    page: 1,
                    ..Default::default()
                }
            );
            owner.close().await.unwrap();
            server.abort();
        }
    }
    async fn enroll_capture_browser_ui(
        owner: &Arc<ClientEnrollment>,
        emit: &tokio::sync::mpsc::Sender<Value>,
    ) {
        owner
            .enroll_existing("target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner.start(&owner.operation()).await.unwrap();
        realm_emit(owner, emit, json!({"method":"Target.attachedToTarget", "params":{
            "sessionId":"browser-ui-session", "waitingForDebugger":true,
            "targetInfo":{"targetId":"browser-ui-target", "type":"browser_ui", "browserContextId":"owned-context"}
        }})).await;
        let entry = owner.index.lock().unwrap().sessions["browser-ui-session"].clone();
        assert!(entry.application && entry.resumed);
        assert_eq!(entry.kind, "browser_ui");
    }
    async fn wait_capture_lookup(log: &Log, count: usize) -> Value {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let requests = log
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|request| request["method"] == "Target.getTargetInfo")
                    .cloned()
                    .collect::<Vec<_>>();
                if requests.len() >= count {
                    return requests[count - 1].clone();
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap()
    }
    fn capture_lookup_reply() -> Value {
        json!({"targetInfo":{
            "targetId":"browser-ui-target", "type":"browser_ui", "browserContextId":"owned-context",
            "url":"chrome://webui-toolbar.top-chrome/?private-url-marker",
            "title":"private-title-marker"
        }})
    }
    // Historical CI11 diagnostic tests are deliberately not acceptance tests.
    // Keep their browser-global diagnostic seam separate from production capture;
    // it cannot add an extra RPC to the supplementation command budget.
    impl ClientEnrollment {
        async fn diagnostic_capture_only(&self, op: &OperationLease) -> Result<(), ProtocolError> {
            let entries = self
                .index
                .lock()
                .unwrap()
                .sessions
                .values()
                .filter(|entry| entry.application || entry.observation_only)
                .cloned()
                .collect::<Vec<_>>();
            let watermark = self.realm_watermark()?;
            let inventory = self
                .command(op, None, "Target.getTargets", json!({"filter":[{}]}))
                .await?;
            let infos = inventory["targetInfos"].as_array().unwrap();
            self.print_capture_lifecycle(&entries, infos);
            if let Some(diagnostic) = self
                .diagnose_missing_capture_target(&entries, infos, &watermark, op)
                .await
            {
                self.print_missing_capture_target(diagnostic);
            }
            Err(ProtocolError::StaleScope)
        }
    }
    fn last_capture_lookup(owner: &ClientEnrollment) -> CaptureMissingTargetDiagnostic {
        owner
            .capture_lifecycle
            .lock()
            .unwrap()
            .missing_lookup
            .clone()
            .unwrap()
    }
    fn assert_capture_lookup_private(diagnostic: &CaptureMissingTargetDiagnostic) {
        let printed = format!("{diagnostic:?}");
        for secret in [
            "browser-ui-target",
            "browser-ui-session",
            "owned-context",
            "foreign-context",
            "wrong-target",
            "chrome://",
            "https://",
            "webui-toolbar.top-chrome",
            "private-",
        ] {
            assert!(
                !printed.contains(secret),
                "diagnostic leaked a private field"
            );
        }
        assert!(
            printed.len() < 2048,
            "diagnostic is not fixed-shape bounded output"
        );
    }
    #[test]
    fn capture_missing_lookup_shape_is_not_a_kind_exemption_or_feature_flag_claim() {
        assert_eq!(
            CaptureInitialToolbarShape::from_value(None),
            CaptureInitialToolbarShape::Missing
        );
        for value in [
            json!(null),
            json!(false),
            json!({}),
            json!("not a URL"),
            json!("chrome://webui-toolbar.top-chrome/\nprivate-marker"),
            json!("a".repeat(65537)),
        ] {
            assert_eq!(
                CaptureInitialToolbarShape::from_value(Some(&value)),
                CaptureInitialToolbarShape::Invalid
            );
        }
        for value in [
            "chrome://webui-toolbar.top-chrome/",
            "chrome://webui-toolbar.top-chrome/?private-marker",
        ] {
            assert_eq!(
                CaptureInitialToolbarShape::from_value(Some(&json!(value))),
                CaptureInitialToolbarShape::InitialToolbarShape
            );
        }
        for value in [
            "https://webui-toolbar.top-chrome/",
            "chrome://webui-toolbar.top-chrome.evil.invalid/",
            "chrome://other/",
        ] {
            assert_eq!(
                CaptureInitialToolbarShape::from_value(Some(&json!(value))),
                CaptureInitialToolbarShape::Other
            );
        }
    }
    #[tokio::test]
    async fn capture_missing_lookup_is_one_exact_read_and_never_releases_refusal() {
        for case in [
            "initial-toolbar",
            "ordinary-url",
            "missing-url",
            "invalid-url",
            "absent",
            "malformed",
            "null-info",
            "missing-context",
            "invalid-type",
            "wrong-target",
            "foreign-context",
            "different-type",
        ] {
            let (owner, _notices, log, emit, server) = fixture("attestation-diagnostic-held").await;
            enroll_capture_browser_ui(&owner, &emit).await;
            let revision = owner.targets.inventory().unwrap().0;
            let epoch = owner.index.lock().unwrap().application_epoch;
            let before = log.lock().unwrap().len();
            let task_owner = owner.clone();
            let task = tokio::spawn(async move {
                task_owner
                    .diagnostic_capture_only(&task_owner.operation())
                    .await
                    .map(|_| ())
            });
            let request = wait_capture_lookup(&log, 1).await;
            assert_eq!(request["params"], json!({"targetId":"browser-ui-target"}));
            assert!(request.get("sessionId").is_none());
            let mut result = capture_lookup_reply();
            let expected = match case {
                "absent" => CaptureTargetLookup::CommandFailure,
                "malformed" => {
                    result = json!({"private-error-marker":true});
                    CaptureTargetLookup::InvalidShape
                }
                "null-info" => {
                    result["targetInfo"] = Value::Null;
                    CaptureTargetLookup::InvalidShape
                }
                "missing-context" => {
                    result["targetInfo"]
                        .as_object_mut()
                        .unwrap()
                        .remove("browserContextId");
                    CaptureTargetLookup::InvalidShape
                }
                "invalid-type" => {
                    result["targetInfo"]["type"] = json!("private-type-marker/invalid");
                    CaptureTargetLookup::InvalidShape
                }
                _ => {
                    let mut target_matches = true;
                    let mut context_matches = true;
                    let mut kind_matches = true;
                    let mut kind = "browser_ui";
                    let url_shape = match case {
                        "ordinary-url" => {
                            result["targetInfo"]["url"] =
                                json!("https://private-url-marker.invalid/secret");
                            CaptureInitialToolbarShape::Other
                        }
                        "missing-url" => {
                            result["targetInfo"].as_object_mut().unwrap().remove("url");
                            CaptureInitialToolbarShape::Missing
                        }
                        "invalid-url" => {
                            result["targetInfo"]["url"] = json!({"private-url-marker":true});
                            CaptureInitialToolbarShape::Invalid
                        }
                        _ => CaptureInitialToolbarShape::InitialToolbarShape,
                    };
                    match case {
                        "wrong-target" => {
                            result["targetInfo"]["targetId"] = json!("wrong-target");
                            target_matches = false;
                        }
                        "foreign-context" => {
                            result["targetInfo"]["browserContextId"] = json!("foreign-context");
                            context_matches = false;
                        }
                        "different-type" => {
                            result["targetInfo"]["type"] = json!("worker");
                            kind_matches = false;
                            kind = "worker";
                        }
                        _ => {}
                    }
                    CaptureTargetLookup::Found {
                        target_matches,
                        context_matches,
                        kind_matches,
                        native_type: CaptureStructuralTargetType::Token(kind.into()),
                        url_shape,
                    }
                }
            };
            let response = if case == "absent" {
                json!({"id":request["id"], "error":{"code":-32000,"message":"private-error-marker target not found https://private-url-marker.invalid"}})
            } else {
                json!({"id":request["id"], "result":result})
            };
            emit.send(response).await.unwrap();
            assert_eq!(
                task.await.unwrap(),
                Err(ProtocolError::StaleScope),
                "{case}"
            );
            let diagnostic = last_capture_lookup(&owner);
            assert_eq!(diagnostic.lookup, expected, "{case}");
            assert_eq!(diagnostic.missing_count, 1);
            assert!(!diagnostic.truncated);
            assert_eq!(diagnostic.before, diagnostic.after);
            assert_eq!(
                diagnostic.after.binding,
                Some(CaptureRegistryBinding::MatchingIdsTenureUnknown)
            );
            assert_eq!(
                diagnostic.after.event_state,
                CaptureLookupEventState::NoReceivedPendingUnreceivedUnknown
            );
            assert_capture_lookup_private(&diagnostic);
            {
                let trace = owner.capture_lifecycle.lock().unwrap();
                assert_eq!(
                    diagnostic.target,
                    trace.targets.get("browser-ui-target").copied()
                );
                assert_eq!(
                    diagnostic.session,
                    trace.sessions.get("browser-ui-session").copied()
                );
            }
            assert_eq!(owner.targets.inventory().unwrap().0, revision);
            assert_eq!(owner.targets.inventory().unwrap().1.len(), 2);
            assert_eq!(owner.index.lock().unwrap().application_epoch, epoch);
            assert_eq!(owner.index.lock().unwrap().sessions.len(), 2);
            {
                let log = log.lock().unwrap();
                assert_eq!(
                    log[before..]
                        .iter()
                        .map(|request| request["method"].as_str().unwrap())
                        .collect::<Vec<_>>(),
                    vec!["Target.getTargets", "Target.getTargetInfo"]
                );
                assert_eq!(log[before]["params"], json!({"filter":[{}]}));
                assert!(!log
                    .iter()
                    .any(|request| request["method"] == "Target.setDiscoverTargets"));
            }
            owner.close().await.unwrap();
            server.abort();
        }
    }
    #[tokio::test]
    async fn capture_missing_lookup_preserves_detach_reregistration_and_replacement_uncertainty() {
        for case in ["detach", "same-ids", "replacement-session"] {
            let (owner, _notices, log, emit, server) = fixture("attestation-diagnostic-held").await;
            enroll_capture_browser_ui(&owner, &emit).await;
            let task_owner = owner.clone();
            let task = tokio::spawn(async move {
                task_owner
                    .diagnostic_capture_only(&task_owner.operation())
                    .await
                    .map(|_| ())
            });
            let request = wait_capture_lookup(&log, 1).await;
            realm_emit(
                &owner,
                &emit,
                json!({"method":"Target.detachedFromTarget", "params":{
                    "sessionId":"browser-ui-session", "targetId":"browser-ui-target"
                }}),
            )
            .await;
            if case != "detach" {
                realm_emit(&owner, &emit, json!({"method":"Target.attachedToTarget", "params":{
                    "sessionId":if case == "same-ids" {"browser-ui-session"} else {"replacement-session"},
                    "waitingForDebugger":true,
                    "targetInfo":{"targetId":"browser-ui-target", "type":"browser_ui", "browserContextId":"owned-context"}
                }})).await;
            }
            emit.send(json!({"id":request["id"], "result":capture_lookup_reply()}))
                .await
                .unwrap();
            assert_eq!(task.await.unwrap(), Err(ProtocolError::StaleScope));
            let diagnostic = last_capture_lookup(&owner);
            assert_eq!(
                diagnostic.before.binding,
                Some(CaptureRegistryBinding::MatchingIdsTenureUnknown)
            );
            assert_eq!(
                diagnostic.after.binding,
                Some(if case == "same-ids" {
                    CaptureRegistryBinding::MatchingIdsTenureUnknown
                } else {
                    CaptureRegistryBinding::Absent
                })
            );
            assert!(diagnostic.after.application_epoch > diagnostic.before.application_epoch);
            assert!(diagnostic.after.received > diagnostic.before.received);
            assert!(matches!(
                diagnostic.lookup,
                CaptureTargetLookup::Found {
                    target_matches: true,
                    context_matches: true,
                    kind_matches: true,
                    ..
                }
            ));
            assert_capture_lookup_private(&diagnostic);
            assert_eq!(
                log.lock()
                    .unwrap()
                    .iter()
                    .filter(|request| request["method"] == "Target.getTargetInfo")
                    .count(),
                1
            );
            owner.close().await.unwrap();
            server.abort();
        }
    }
    #[tokio::test]
    async fn capture_missing_lookup_reports_pending_events_and_retirement_without_draining() {
        let (owner, _notices, log, emit, server) = fixture("attestation-diagnostic-held").await;
        enroll_capture_browser_ui(&owner, &emit).await;
        let task_owner = owner.clone();
        let task = tokio::spawn(async move {
            task_owner
                .diagnostic_capture_only(&task_owner.operation())
                .await
                .map(|_| ())
        });
        let request = wait_capture_lookup(&log, 1).await;
        realm_emit(&owner, &emit, json!({"method":"Target.targetInfoChanged", "params":{"targetInfo":{
            "targetId":"browser-ui-target", "type":"browser_ui", "browserContextId":"owned-context"
        }}})).await;
        // Model the already-received but unapplied boundary deterministically,
        // using the existing coordinator counter (no second subscriber). Real
        // TCP lifecycle delivery above establishes the received watermark.
        let applied = {
            let mut index = owner.index.lock().unwrap();
            let applied = index.applied_watermark;
            assert!(applied > 0);
            index.applied_watermark -= 1;
            index
                .pending_enrollment
                .insert("private-pending-session".into());
            index
                .retiring_pages
                .insert("browser-ui-target".into(), "browser-ui-session".into());
            applied
        };
        emit.send(json!({"id":request["id"], "result":capture_lookup_reply()}))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap(),
            Err(ProtocolError::StaleScope)
        );
        let diagnostic = last_capture_lookup(&owner);
        assert_eq!(
            diagnostic.before.event_state,
            CaptureLookupEventState::NoReceivedPendingUnreceivedUnknown
        );
        assert_eq!(
            diagnostic.after.event_state,
            CaptureLookupEventState::ReceivedPending
        );
        assert_eq!(diagnostic.after.pending_enrollment, Some(true));
        assert_eq!(diagnostic.after.retirement_pending, Some(true));
        assert_eq!(owner.index.lock().unwrap().applied_watermark, applied - 1);
        assert_capture_lookup_private(&diagnostic);
        {
            let mut index = owner.index.lock().unwrap();
            index.applied_watermark = applied;
            index.pending_enrollment.clear();
            index.retiring_pages.clear();
        }
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn capture_missing_lookup_pre_refused_leases_and_absent_binding_send_nothing() {
        let (owner, _notices, log, emit, server) = fixture("attestation-diagnostic-held").await;
        enroll_capture_browser_ui(&owner, &emit).await;
        let entries = vec![owner.index.lock().unwrap().sessions["browser-ui-session"].clone()];
        let watermark = owner.realm_watermark().unwrap();
        for case in ["cancelled", "deadline", "generation", "absent-binding"] {
            let (cancel, cancellation) = watch::channel(CancelSignal::None);
            let mut op = owner.operation();
            op.cancellation = cancellation;
            let expected = match case {
                "cancelled" => {
                    cancel.send_replace(CancelSignal::Requested);
                    CaptureTargetLookup::Cancelled
                }
                "deadline" => {
                    op.deadline = Instant::now();
                    CaptureTargetLookup::Deadline
                }
                "generation" => {
                    op.generation += 1;
                    CaptureTargetLookup::SkippedCoordinatorUnavailable
                }
                _ => {
                    realm_emit(
                        &owner,
                        &emit,
                        json!({"method":"Target.detachedFromTarget", "params":{
                            "sessionId":"browser-ui-session", "targetId":"browser-ui-target"
                        }}),
                    )
                    .await;
                    CaptureTargetLookup::SkippedBindingUnavailable
                }
            };
            // Exercise only the diagnostic seam after a missing-target decision;
            // ordinary attestation may refuse an expired lease even earlier.
            let diagnostic = owner
                .diagnose_missing_capture_target(&entries, &[], &watermark, &op)
                .await
                .unwrap();
            assert_eq!(diagnostic.lookup, expected);
            assert_capture_lookup_private(&diagnostic);
        }
        assert!(!log
            .lock()
            .unwrap()
            .iter()
            .any(|request| request["method"] == "Target.getTargetInfo"));
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn capture_missing_lookup_inflight_cancel_and_deadline_keep_original_stale_scope() {
        for cancel_during in [true, false] {
            let (owner, _notices, log, emit, server) = fixture("attestation-diagnostic-held").await;
            enroll_capture_browser_ui(&owner, &emit).await;
            let (cancel, cancellation) = watch::channel(CancelSignal::None);
            let mut op = owner.operation();
            op.cancellation = cancellation;
            op.deadline = Instant::now() + Duration::from_secs(3);
            let deadline = op.deadline;
            let task_owner = owner.clone();
            let task =
                tokio::spawn(
                    async move { task_owner.diagnostic_capture_only(&op).await.map(|_| ()) },
                );
            wait_capture_lookup(&log, 1).await;
            if cancel_during {
                cancel.send_replace(CancelSignal::Requested);
            }
            // The server withholds ACK. Completion must use the original lease,
            // not a retry, fresh initialization operation, or renewed budget.
            assert_eq!(
                tokio::time::timeout_at((deadline + Duration::from_secs(1)).into(), task)
                    .await
                    .unwrap()
                    .unwrap(),
                Err(ProtocolError::StaleScope)
            );
            let diagnostic = last_capture_lookup(&owner);
            assert_eq!(
                diagnostic.lookup,
                if cancel_during {
                    CaptureTargetLookup::Cancelled
                } else {
                    CaptureTargetLookup::Deadline
                }
            );
            assert_eq!(
                log.lock()
                    .unwrap()
                    .iter()
                    .filter(|request| request["method"] == "Target.getTargetInfo")
                    .count(),
                1
            );
            assert_capture_lookup_private(&diagnostic);
            owner.close().await.unwrap();
            server.abort();
        }
    }
    #[tokio::test]
    async fn capture_missing_lookup_caps_multiple_missing_entries_and_reuses_ordinals() {
        let (owner, _notices, log, emit, server) = fixture("attestation-diagnostic-held").await;
        enroll_capture_browser_ui(&owner, &emit).await;
        realm_emit(&owner, &emit, json!({"method":"Target.attachedToTarget", "params":{
            "sessionId":"second-session", "waitingForDebugger":true,
            "targetInfo":{"targetId":"second-target", "type":"browser_ui", "browserContextId":"owned-context"}
        }})).await;
        let revision = owner.targets.inventory().unwrap().0;
        let task_owner = owner.clone();
        let task = tokio::spawn(async move {
            task_owner
                .diagnostic_capture_only(&task_owner.operation())
                .await
                .map(|_| ())
        });
        let request = wait_capture_lookup(&log, 1).await;
        assert_eq!(request["params"], json!({"targetId":"browser-ui-target"}));
        emit.send(json!({"id":request["id"], "result":capture_lookup_reply()}))
            .await
            .unwrap();
        assert_eq!(task.await.unwrap(), Err(ProtocolError::StaleScope));
        let diagnostic = last_capture_lookup(&owner);
        assert_eq!(diagnostic.missing_count, 2);
        assert!(diagnostic.truncated);
        struct FailedWriter;
        impl std::io::Write for FailedWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("private-write-error-marker"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut trace = CaptureLifecycleTrace::default();
        trace.record_missing_lookup(diagnostic.clone(), &mut FailedWriter);
        assert_eq!(trace.dropped, 1);
        assert_eq!(trace.missing_lookup.as_ref().unwrap().dropped, 1);
        let mut output = Vec::new();
        trace.record_missing_lookup(diagnostic.clone(), &mut output);
        assert_eq!(trace.dropped, 2);
        assert!(String::from_utf8(output).unwrap().contains("dropped: 2"));
        assert_capture_lookup_private(trace.missing_lookup.as_ref().unwrap());
        assert_eq!(owner.targets.inventory().unwrap().0, revision);
        assert_eq!(owner.targets.inventory().unwrap().1.len(), 3);
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|request| request["method"] == "Target.getTargetInfo")
                .count(),
            1
        );
        assert_capture_lookup_private(&diagnostic);
        owner.close().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn capture_lifecycle_trace_correlates_native_type_and_exact_registry_tenure() {
        let (owner, _notices, log, emit, server) =
            fixture("attestation-complete-missing-target").await;
        enroll_capture_tab(&owner, &emit).await;
        realm_emit(
            &owner,
            &emit,
            json!({"method":"Target.targetInfoChanged", "params":{"targetInfo":{
                "targetId":"tab-target", "type":"worker", "browserContextId":"owned-context",
                "url":"https://private.invalid/secret", "title":"private-title"
            }}}),
        )
        .await;
        realm_emit(
            &owner,
            &emit,
            json!({"method":"Target.targetDestroyed", "params":{"targetId":"tab-target"}}),
        )
        .await;
        assert!(owner
            .index
            .lock()
            .unwrap()
            .sessions
            .contains_key("tab-session"));
        assert!(matches!(
            owner.attest_capture(&owner.operation()).await,
            Err(ProtocolError::StaleScope)
        ));
        realm_emit(&owner, &emit, json!({"method":"Target.detachedFromTarget", "params":{"sessionId":"tab-session", "targetId":"tab-target"}})).await;
        assert!(!owner
            .index
            .lock()
            .unwrap()
            .sessions
            .contains_key("tab-session"));
        owner.attest_capture(&owner.operation()).await.unwrap();
        let rows = owner.capture_lifecycle.lock().unwrap().rows.clone();
        let attached = rows
            .iter()
            .find(|row| row.step == CaptureLifecycleStep::Attached)
            .unwrap();
        assert_eq!(attached.native_kind, CaptureTargetKind::Tab);
        assert_eq!(attached.registry_binding, CaptureRegistryBinding::Absent);
        let target = attached.target.unwrap();
        let session = attached.session.unwrap();
        let relevant = rows
            .iter()
            .filter(|row| row.target == Some(target))
            .collect::<Vec<_>>();
        assert_eq!(
            relevant.iter().map(|row| row.step).collect::<Vec<_>>(),
            vec![
                CaptureLifecycleStep::Attached,
                CaptureLifecycleStep::RegisteringAttached,
                CaptureLifecycleStep::Registered,
                CaptureLifecycleStep::Resumed,
                CaptureLifecycleStep::InfoChanged,
                CaptureLifecycleStep::Destroyed,
                CaptureLifecycleStep::MissingInventory,
                CaptureLifecycleStep::Detached,
                CaptureLifecycleStep::Removed,
            ]
        );
        assert!(relevant
            .iter()
            .all(|row| row.session == Some(session) && !row.parent));
        assert!(relevant
            .windows(2)
            .all(|pair| pair[0].order < pair[1].order && pair[0].elapsed_ms <= pair[1].elapsed_ms));
        let changed = relevant
            .iter()
            .find(|row| row.step == CaptureLifecycleStep::InfoChanged)
            .unwrap();
        assert_eq!(changed.native_kind, CaptureTargetKind::Worker);
        assert_eq!(changed.registered_kind, CaptureTargetKind::Tab);
        assert_eq!(
            changed.registry_binding,
            CaptureRegistryBinding::MatchingIdsTenureUnknown
        );
        assert!(changed.application && changed.resumed);
        assert_eq!(
            relevant
                .iter()
                .find(|row| row.step == CaptureLifecycleStep::Destroyed)
                .unwrap()
                .registry_binding,
            CaptureRegistryBinding::MatchingIdsTenureUnknown
        );
        assert_eq!(
            relevant.last().unwrap().registry_binding,
            CaptureRegistryBinding::Absent
        );
        assert!(rows
            .iter()
            .any(|row| row.step == CaptureLifecycleStep::EnrollingExisting
                && row.target != Some(target)));
        let printed = format!("{rows:?}");
        for secret in [
            "tab-target",
            "tab-session",
            "owned-context",
            "private",
            "https://",
        ] {
            assert!(!printed.contains(secret));
        }
        assert!(!log
            .lock()
            .unwrap()
            .iter()
            .any(|request| request["method"] == "Target.setDiscoverTargets"));
        owner.close().await.unwrap();
        server.abort();
    }

    #[test]
    fn capture_lifecycle_trace_does_not_confuse_session_membership_with_exact_tenure() {
        let retained = Attribution {
            target: "private-target".into(),
            session: "private-session".into(),
            root: "private-root".into(),
            parent: Some("private-parent".into()),
            kind: "page".into(),
            application: true,
            observation_only: false,
            observer_paused: false,
            resumed: true,
        };
        for mismatch in ["target", "root", "parent", "kind"] {
            let mut current = retained.clone();
            match mismatch {
                "target" => current.target = "replacement-target".into(),
                "root" => current.root = "replacement-root".into(),
                "parent" => current.parent = None,
                "kind" => current.kind = "tab".into(),
                _ => unreachable!(),
            }
            let mut index = Index::default();
            index.sessions.insert(current.session.clone(), current);
            let mut trace = CaptureLifecycleTrace::default();
            trace.registry(CaptureLifecycleStep::MissingInventory, &retained, &index);
            assert_eq!(
                trace.rows.back().unwrap().registry_binding,
                CaptureRegistryBinding::ConflictingIds,
                "{mismatch}"
            );
        }
        let mut index = Index::default();
        let mut trace = CaptureLifecycleTrace::default();
        trace.registry(CaptureLifecycleStep::Removed, &retained, &index);
        assert_eq!(
            trace.rows.back().unwrap().registry_binding,
            CaptureRegistryBinding::Absent
        );
        // Reusing every identifier is not enough to prove an old snapshot's
        // insertion tenure. Keep the uncertainty explicit in closed output.
        index
            .sessions
            .insert(retained.session.clone(), retained.clone());
        trace.registry(CaptureLifecycleStep::Registered, &retained, &index);
        trace.registry(CaptureLifecycleStep::MissingInventory, &retained, &index);
        assert_eq!(
            trace.rows.back().unwrap().registry_binding,
            CaptureRegistryBinding::MatchingIdsTenureUnknown
        );
        assert!(!format!("{:?}", trace.rows).contains("private"));
    }

    #[test]
    fn capture_lifecycle_trace_is_bounded_and_never_echoes_invalid_native_metadata() {
        let mut trace = CaptureLifecycleTrace::default();
        let index = Index::default();
        for (offset, kind) in ["tab", "browser", "other", "future-private-kind"]
            .into_iter()
            .enumerate()
        {
            trace.event(&CdpEvent { method:"Target.attachedToTarget".into(), session_id:None,
                params:json!({"sessionId":"private-session", "targetInfo":{"targetId":"private-target", "type":kind,
                    "url":"https://private.invalid", "title":"private-title"}}) }, offset as u64, &index);
        }
        assert_eq!(
            trace
                .rows
                .iter()
                .map(|row| row.native_kind)
                .collect::<Vec<_>>(),
            vec![
                CaptureTargetKind::Tab,
                CaptureTargetKind::Browser,
                CaptureTargetKind::CdpOther,
                CaptureTargetKind::Unrecognized
            ]
        );
        assert!(!format!("{:?}", trace.rows).contains("private"));
        for offset in 0..CAPTURE_TRACE_LIMIT + 5 {
            trace.event(
                &CdpEvent {
                    method: "Target.targetDestroyed".into(),
                    session_id: None,
                    params: json!({"targetId":format!("private-{offset}")}),
                },
                offset as u64,
                &index,
            );
        }
        assert_eq!(trace.rows.len(), CAPTURE_TRACE_LIMIT);
        assert_eq!(trace.targets.len(), CAPTURE_TRACE_LIMIT);
        assert_eq!(trace.dropped, 9);
        assert!(trace.ids_exhausted);
        assert_eq!(trace.rows.back().unwrap().target, None);
        let oversized = "private".repeat(1024);
        trace.event(&CdpEvent { method:"Target.attachedToTarget".into(), session_id:None,
            params:json!({"sessionId":oversized, "targetInfo":{"targetId":oversized,"type":oversized}}) }, u64::MAX, &index);
        assert_eq!(
            trace.rows.back().unwrap().native_kind,
            CaptureTargetKind::Unrecognized
        );
        assert_eq!(trace.sessions.len(), 1);
        assert!(!format!("{:?}", trace.rows).contains("private"));
    }

    #[test]
    fn capture_structural_target_type_is_strictly_bounded() {
        use CaptureStructuralTargetType::{Invalid, Missing, Oversized, Token};
        assert_eq!(CaptureStructuralTargetType::from_value(None), Missing);
        for value in [json!(null), json!(false), json!(42), json!([]), json!({})] {
            assert_eq!(
                CaptureStructuralTargetType::from_value(Some(&value)),
                Invalid
            );
        }
        for value in [
            "",
            "Page",
            "kind1",
            "private-kind",
            "private/path",
            "private:type",
            "private title",
            "private\nvalue",
            "týpe",
        ] {
            assert_eq!(CaptureStructuralTargetType::from_str(value), Invalid);
        }
        for value in ["page", "service_worker", "future_worklet"] {
            assert_eq!(
                CaptureStructuralTargetType::from_str(value),
                Token(value.into())
            );
        }
        let exact = "a".repeat(CAPTURE_TARGET_TYPE_LIMIT);
        assert_eq!(
            CaptureStructuralTargetType::from_str(&exact),
            Token(exact.clone())
        );
        assert_eq!(
            CaptureStructuralTargetType::from_str(&(exact + "a")),
            Oversized
        );
        assert_eq!(
            CaptureStructuralTargetType::from_str(&"private".repeat(1024)),
            Oversized
        );
    }

    #[tokio::test]
    async fn capture_lifecycle_trace_retains_structural_unknown_type_without_changing_admission() {
        let (owner, _notices, log, emit, server) =
            fixture("attestation-complete-missing-target").await;
        owner
            .enroll_existing("target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner.start(&owner.operation()).await.unwrap();
        realm_emit(
            &owner,
            &emit,
            json!({
                "method":"Target.attachedToTarget", "params":{
                    "sessionId":"private-session", "waitingForDebugger":true,
                    "targetInfo":{"targetId":"private-target", "type":"future_worklet",
                        "browserContextId":"owned-context", "url":"https://private.invalid/secret",
                        "title":"private-title"}
                }
            }),
        )
        .await;
        let owned = owner.targets.owned_target("private-target").unwrap();
        assert_eq!(owned.kind, "future_worklet");
        assert_eq!(owned.purpose, Some(TargetPurpose::Application));
        assert!(owned.configured && owned.resumed);
        assert!(matches!(
            owner.attest_capture(&owner.operation()).await,
            Err(ProtocolError::StaleScope)
        ));
        let rows = owner.capture_lifecycle.lock().unwrap().rows.clone();
        let attached = rows
            .iter()
            .find(|row| row.step == CaptureLifecycleStep::Attached)
            .unwrap();
        assert_eq!(attached.native_kind, CaptureTargetKind::Unrecognized);
        assert_eq!(
            attached.native_type,
            CaptureStructuralTargetType::Token("future_worklet".into())
        );
        assert_eq!(
            attached.registered_type,
            CaptureStructuralTargetType::Missing
        );
        let relevant = rows
            .iter()
            .filter(|row| row.target == attached.target)
            .collect::<Vec<_>>();
        assert_eq!(
            relevant.iter().map(|row| row.step).collect::<Vec<_>>(),
            vec![
                CaptureLifecycleStep::Attached,
                CaptureLifecycleStep::RegisteringAttached,
                CaptureLifecycleStep::Registered,
                CaptureLifecycleStep::Resumed,
                CaptureLifecycleStep::MissingInventory,
            ]
        );
        for row in relevant.iter().skip(2) {
            assert_eq!(row.registered_kind, CaptureTargetKind::Unrecognized);
            assert_eq!(
                row.registered_type,
                CaptureStructuralTargetType::Token("future_worklet".into())
            );
            assert_eq!(
                row.registry_binding,
                CaptureRegistryBinding::MatchingIdsTenureUnknown
            );
        }
        assert!(relevant.last().unwrap().application && relevant.last().unwrap().resumed);
        let printed = format!("{rows:?}");
        assert!(printed.contains("future_worklet"));
        for secret in ["private", "owned-context", "https://"] {
            assert!(!printed.contains(secret));
        }
        assert!(!log
            .lock()
            .unwrap()
            .iter()
            .any(|request| request["method"] == "Target.setDiscoverTargets"));
        owner.close().await.unwrap();
        server.abort();
    }

    #[test]
    fn capture_inventory_diagnostic_uses_only_closed_roles_and_counts() {
        let mut entry = Attribution {
            target: "private-target".into(),
            session: "private-session".into(),
            parent: Some("private-parent".into()),
            root: "private-root".into(),
            kind: "private-browser-provided-type".into(),
            application: false,
            observation_only: true,
            observer_paused: false,
            resumed: true,
        };
        let diagnostic = capture_inventory_diagnostic(&[entry.clone()], &[], "private-context");
        assert_eq!(
            diagnostic,
            CaptureInventoryDiagnostic {
                entries: 1,
                missing: 1,
                absent_target: 1,
                observation_only: 1,
                other: 1,
                parent: 1,
                ..Default::default()
            }
        );
        assert!(!format!("{diagnostic:?}").contains("private"));
        for (kind, page, iframe, worker) in [
            ("page", 1, 0, 0),
            ("iframe", 0, 1, 0),
            ("worker", 0, 0, 1),
            ("service_worker", 0, 0, 1),
            ("shared_worker", 0, 0, 1),
        ] {
            entry.kind = kind.into();
            let diagnostic = capture_inventory_diagnostic(&[entry.clone()], &[], "private-context");
            assert_eq!(
                (
                    diagnostic.page,
                    diagnostic.iframe,
                    diagnostic.worker,
                    diagnostic.other
                ),
                (page, iframe, worker, 0)
            );
        }
        let exact = json!({"targetId":"private-target","browserContextId":"private-context"});
        assert_eq!(
            capture_inventory_diagnostic(&[entry], &[exact], "private-context"),
            CaptureInventoryDiagnostic {
                entries: 1,
                inventory: 1,
                ..Default::default()
            }
        );
    }
    #[tokio::test]
    async fn dequeued_attach_is_pending_before_async_target_registration() {
        let (owner, _notices, _log, _emit, server) = fixture("attestation").await;
        owner
            .enroll_existing("target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner.start(&owner.operation()).await.unwrap();
        let event = attach("owned-context", "new-popup", "new-session", "page", None);
        // This is the synchronous admission step performed before task spawn.
        owner.register_pending_event(&event).unwrap();
        assert!(!owner
            .index
            .lock()
            .unwrap()
            .sessions
            .contains_key("new-session"));
        let mut op = owner.operation();
        op.deadline = Instant::now() + Duration::from_millis(10);
        assert!(matches!(
            owner.attest_capture(&op).await,
            Err(ProtocolError::DeadlineExceeded)
        ));
        owner
            .index
            .lock()
            .unwrap()
            .pending_enrollment
            .remove("new-session");
        owner.changed.notify_waiters();
        owner.attest_capture(&owner.operation()).await.unwrap();
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn bootstrap_registry_churn_preserves_application_attestation_but_navigation_does_not() {
        let (owner, _notices, _log, _emit, server) = fixture("attestation").await;
        owner
            .enroll_existing("target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner.start(&owner.operation()).await.unwrap();
        let proof = owner.attest_capture(&owner.operation()).await.unwrap();
        let mut reservation = owner
            .targets
            .reserve_creation(TargetPurpose::StateBootstrap)
            .unwrap();
        owner
            .targets
            .attached(
                "owned-context",
                "bootstrap".into(),
                "bootstrap-session".into(),
                "page".into(),
            )
            .unwrap();
        reservation.claim("bootstrap").unwrap();
        drop(reservation);
        owner.targets.configured("bootstrap").unwrap();
        owner.targets.detach("bootstrap").unwrap();
        owner
            .verify_capture_attestation(&proof, &owner.operation())
            .await
            .unwrap();
        owner
            .event(&CdpEvent {
                method: "Page.navigatedWithinDocument".into(),
                session_id: Some("initial".into()),
                params: json!({"frameId":"frame-initial","url":"https://synthetic.test/next"}),
            })
            .unwrap();
        assert_eq!(
            owner
                .verify_capture_attestation(&proof, &owner.operation())
                .await,
            Err(ProtocolError::StaleScope)
        );
        owner.close().await.unwrap();
        server.abort();
    }
    #[test]
    fn new_queued_attach_cannot_hide_behind_an_older_pending_completion() {
        let mut index = Index {
            applied_watermark: 1,
            ..Default::default()
        };
        index.pending_enrollment.insert("first".into());
        assert!(!capture_admission_ready(&index, 1));
        index.pending_enrollment.remove("first");
        // A second event is reader-admitted but not yet synchronously applied.
        assert!(!capture_admission_ready(&index, 2));
        index.applied_watermark = 2;
        index.pending_enrollment.insert("second".into());
        assert!(!capture_admission_ready(&index, 2));
        index.pending_enrollment.remove("second");
        assert!(capture_admission_ready(&index, 2));
    }
    #[test]
    fn frame_fingerprint_rejects_missing_fields_and_duplicate_identity() {
        for frame in [
            json!({"id":"x","url":"about:blank"}),
            json!({"id":"x","loaderId":"l"}),
        ] {
            assert_eq!(
                capture_frame_fingerprint("s", &json!({"frame":frame}), 0, &mut Vec::new()),
                Err(ProtocolError::InvalidFrame)
            );
        }
        let frame = json!({"id":"x","loaderId":"l","url":"about:blank"});
        assert_eq!(
            capture_frame_fingerprint(
                "s",
                &json!({"frame":frame,"childFrames":[{"frame":frame}]}),
                0,
                &mut Vec::new()
            ),
            Err(ProtocolError::InvalidFrame)
        );
    }
    #[test]
    fn frame_loader_fingerprint_is_bounded_and_detects_same_url_reload() {
        let mut before = Vec::new();
        let mut after = Vec::new();
        capture_frame_fingerprint(
            "session",
            &json!({"frame":{"id":"frame","loaderId":"old","url":"https://synthetic.test"}}),
            0,
            &mut before,
        )
        .unwrap();
        capture_frame_fingerprint(
            "session",
            &json!({"frame":{"id":"frame","loaderId":"new","url":"https://synthetic.test"}}),
            0,
            &mut after,
        )
        .unwrap();
        assert_ne!(before, after);
        assert_eq!(
            capture_frame_fingerprint("session", &json!({"frame":{"id":"frame"}}), 65, &mut after),
            Err(ProtocolError::CapacityExceeded)
        );
    }
    async fn borrowed_restart_fixture() -> (
        Arc<ClientEnrollment>,
        Arc<super::super::client_ui::UiGate>,
        Log,
        tokio::sync::mpsc::Sender<Value>,
        JoinHandle<()>,
        Notices,
    ) {
        let (original, _notices, log, emit, server) = fixture("normal").await;
        let ui = Arc::new(super::super::client_ui::UiGate::default());
        let (mut owner, notices, _broker) = coordinator_with_ui(
            original.client.clone(),
            "owned-context",
            "owned-scope",
            "initial",
            ui.clone(),
        );
        Arc::get_mut(&mut owner).unwrap().ownership =
            ScopeOwnership::BorrowedTargets(vec!["initial-target".into()]);
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        (owner, ui, log, emit, server, notices)
    }
    fn borrowed_info(target: &str) -> Value {
        json!({"targetId":target,"browserContextId":"owned-context","type":"page","url":"about:blank"})
    }
    #[test]
    fn observer_retirement_snapshot_preserves_concurrent_failure_and_seal() {
        let mut index = Index::default();
        index.retired_observer_targets.insert("target".into());
        index.retired_observer_sessions.insert("session".into());
        assert_eq!(
            observer_retirement_snapshot(&index, false, "target", Some("session"), 0),
            Ok(Some(true))
        );
        assert_eq!(
            observer_retirement_snapshot(&index, true, "target", Some("session"), 0),
            Err(ProtocolError::Cancelled)
        );
        index.failure = Some(ProtocolError::StaleScope);
        assert_eq!(
            observer_retirement_snapshot(&index, true, "target", Some("session"), 0),
            Err(ProtocolError::StaleScope)
        );
    }
    #[tokio::test]
    async fn observer_initialization_failure_requires_exact_detach_and_target_absence() {
        for mode in [
            "observer-close",
            "observer-unknown-error",
            "observer-detached-live",
        ] {
            let (mut owner, _notices, log, _emit, server) = fixture(mode).await;
            Arc::get_mut(&mut owner).unwrap().ownership =
                ScopeOwnership::BorrowedTargets(vec!["initial-target".into()]);
            owner
                .enroll_existing("initial-target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            let result = owner
                .attached(attach(
                    "owned-context",
                    "other-host",
                    "observer",
                    "page",
                    None,
                ))
                .await;
            if mode == "observer-close" {
                result.unwrap();
                assert!(owner
                    .observer_target_gone("other-host", Some("observer"), &owner.operation())
                    .await
                    .unwrap());
                owner.poison(ProtocolError::StaleScope);
                assert_eq!(
                    owner
                        .observer_target_gone("other-host", Some("observer"), &owner.operation())
                        .await,
                    Err(ProtocolError::StaleScope)
                );
            } else {
                assert_eq!(result, Err(ProtocolError::BrowserFailure));
            }
            assert!(!log.lock().unwrap().iter().any(|cmd| matches!(
                cmd["method"].as_str(),
                Some("Target.closeTarget" | "Target.disposeBrowserContext" | "Browser.close")
            )));
            let _ = owner.close().await;
            server.abort();
        }
    }
    #[tokio::test]
    async fn observer_oopif_missing_context_requires_exact_native_metadata() {
        let (mut owner, _notices, log, _emit, server) = fixture("observer-context").await;
        Arc::get_mut(&mut owner).unwrap().ownership =
            ScopeOwnership::BorrowedTargets(vec!["initial-target".into()]);
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner
            .attached(attach(
                "owned-context",
                "other-host",
                "observer",
                "page",
                None,
            ))
            .await
            .unwrap();
        owner.attached(CdpEvent {method:"Target.attachedToTarget".into(),session_id:Some("observer".into()),params:json!({"sessionId":"child-observer","waitingForDebugger":true,"targetInfo":{"targetId":"child-target","type":"iframe"}})}).await.unwrap();
        assert!(owner.index.lock().unwrap().sessions["child-observer"].observation_only);
        assert!(owner.targets.owned_target("child-target").is_err());
        owner.event(&CdpEvent {method:"Page.frameNavigated".into(),session_id:Some("child-observer".into()),params:json!({"frame":{"id":"child-frame","loaderId":"new","url":"https://iframe-origin.test/"}})}).unwrap();
        assert_eq!(
            owner.page.visited_origins().unwrap(),
            vec!["https://iframe-origin.test"]
        );
        assert!(log
            .lock()
            .unwrap()
            .iter()
            .any(|cmd| cmd["method"] == "Target.getTargetInfo"
                && cmd["params"]["targetId"] == "child-target"));
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn context_observer_never_gains_application_authority_and_rejects_late_events() {
        let (owner, _ui, log, _emit, server, _notices) = borrowed_restart_fixture().await;
        let mut event = attach("owned-context", "other-host", "observer", "page", None);
        event.params["waitingForDebugger"] = json!(false);
        owner.attached(event).await.unwrap();
        assert!(owner.targets.owned_target("other-host").is_err());
        assert!(!owner.authorized("other-host", None, None).unwrap());
        assert!(!owner
            .authorized("popup", Some("observer"), Some("other-host"))
            .unwrap());
        assert!(owner.page.visited_origins().unwrap().is_empty());
        owner.event(&CdpEvent { method:"Page.frameNavigated".into(), session_id:Some("observer".into()), params:json!({"frame":{"id":"frame-observer","loaderId":"l2","url":"https://observed.test/a"}}) }).unwrap();
        assert_eq!(
            owner.page.visited_origins().unwrap(),
            vec!["https://observed.test"]
        );
        owner
            .event(&CdpEvent {
                method: "Target.detachedFromTarget".into(),
                session_id: None,
                params: json!({"sessionId":"observer"}),
            })
            .unwrap();
        owner.event(&CdpEvent { method:"Page.frameNavigated".into(), session_id:Some("observer".into()),params:json!({"frame":{"id":"frame-observer","loaderId":"l3","url":"https://late.test/"}}) }).unwrap();
        assert_eq!(
            owner.page.visited_origins().unwrap(),
            vec!["https://observed.test"]
        );
        owner
            .attached(attach(
                "owned-context",
                "replacement",
                "observer",
                "page",
                None,
            ))
            .await
            .unwrap();
        assert!(!owner
            .index
            .lock()
            .unwrap()
            .sessions
            .contains_key("observer"));
        assert!(owner
            .index
            .lock()
            .unwrap()
            .retired_observer_sessions
            .contains("observer"));
        owner
            .attached(attach(
                "owned-context",
                "late-child",
                "late-child-session",
                "iframe",
                Some("observer"),
            ))
            .await
            .unwrap();
        assert!(!owner
            .index
            .lock()
            .unwrap()
            .sessions
            .contains_key("late-child-session"));
        assert!(!log
            .lock()
            .unwrap()
            .iter()
            .any(|cmd| cmd["sessionId"] == "late-child-session"));
        owner
            .attached(attach(
                "owned-context",
                "late-grandchild",
                "late-grandchild-session",
                "iframe",
                Some("late-child-session"),
            ))
            .await
            .unwrap();
        assert!(!owner
            .index
            .lock()
            .unwrap()
            .sessions
            .contains_key("late-grandchild-session"));
        assert!(!log
            .lock()
            .unwrap()
            .iter()
            .any(|cmd| cmd["sessionId"] == "late-grandchild-session"));
        let observer_commands: Vec<_> = log
            .lock()
            .unwrap()
            .iter()
            .filter(|cmd| cmd["sessionId"] == "observer")
            .cloned()
            .collect();
        // A child-session detach is routed through its exact parent session.
        // This is cleanup authority, not a Runtime/Fetch/settings operation.
        assert!(observer_commands
            .iter()
            .any(|cmd| cmd["method"] == "Target.detachFromTarget"
                && cmd["params"]["sessionId"] == "late-child-session"));
        assert!(observer_commands.iter().all(|cmd| matches!(
            cmd["method"].as_str(),
            Some("Page.enable" | "Page.getFrameTree" | "Target.setAutoAttach")
        ) || (cmd["method"]
            == "Target.detachFromTarget"
            && cmd["params"]["sessionId"] == "late-child-session")));
        owner.close().await.unwrap();
        assert!(!log.lock().unwrap().iter().any(|cmd| matches!(
            cmd["method"].as_str(),
            Some("Target.closeTarget" | "Target.disposeBrowserContext" | "Browser.close")
        )));
        server.abort();
    }
    #[tokio::test]
    async fn context_observer_cleanup_only_detaches_and_never_resumes_external_pause() {
        let (owner, _ui, log, _emit, server, _notices) = borrowed_restart_fixture().await;
        let mut event = attach("owned-context", "other-host", "observer", "page", None);
        event.params["waitingForDebugger"] = json!(false);
        owner.attached(event).await.unwrap();
        owner
            .attached(attach(
                "other-context",
                "foreign-host",
                "foreign-observer",
                "page",
                None,
            ))
            .await
            .unwrap();
        owner.event(&CdpEvent { method:"Page.frameNavigated".into(),session_id:Some("foreign-observer".into()),params:json!({"frame":{"id":"foreign","loaderId":"l","url":"https://foreign.test/"}}) }).unwrap();
        assert!(owner.page.visited_origins().unwrap().is_empty());
        owner.close().await.unwrap();
        let proof = owner.contain_owned_resources().await.unwrap();
        owner.release_after_containment(proof).await.unwrap();
        let commands = log.lock().unwrap();
        assert!(commands
            .iter()
            .any(|cmd| cmd["method"] == "Target.detachFromTarget"
                && cmd["params"]["sessionId"] == "observer"));
        assert!(!commands.iter().any(|cmd| cmd["sessionId"] == "observer"
            && !matches!(
                cmd["method"].as_str(),
                Some("Page.enable" | "Page.getFrameTree" | "Target.setAutoAttach")
            )));
        assert!(!commands
            .iter()
            .any(|cmd| cmd["sessionId"] == "foreign-observer"));
        assert!(!commands.iter().any(|cmd| matches!(
            cmd["method"].as_str(),
            Some("Target.closeTarget" | "Target.disposeBrowserContext" | "Browser.close")
        )));
        server.abort();
    }
    #[tokio::test]
    async fn observer_navigation_during_initial_tree_read_is_not_initial_history() {
        let (owner, _ui, _log, _emit, server, _notices) = borrowed_restart_fixture().await;
        // Registration precedes Page.enable/getFrameTree; a real new-document
        // event interleaved with those replies must remain observed history.
        let entry = owner
            .register_observer("other-host", "observer", "page", None, false)
            .unwrap()
            .unwrap();
        owner.event(&CdpEvent {method:"Page.frameNavigated".into(),session_id:Some("observer".into()),params:json!({"frame":{"id":"other-frame","loaderId":"new","url":"https://during-init.test/"}})}).unwrap();
        owner.frame_tree(&entry,&json!({"frame":{"id":"other-frame","loaderId":"initial","url":"https://historical.test/"}}),0).unwrap();
        assert_eq!(
            owner.page.visited_origins().unwrap(),
            vec!["https://during-init.test"]
        );
        assert!(!owner.index.lock().unwrap().sessions["observer"].resumed);
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn borrowed_capture_attests_only_observed_document_origins_not_initial_profile() {
        let (mut owner, _notices, _log, _emit, server) = fixture("borrowed-capture").await;
        Arc::get_mut(&mut owner).unwrap().ownership =
            ScopeOwnership::BorrowedTargets(vec!["initial-target".into()]);
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner.index.lock().unwrap().reconciled = true;
        assert!(matches!(
            owner.attest_capture(&owner.operation()).await,
            Err(ProtocolError::ScopeUnavailable)
        ));
        owner.index.lock().unwrap().reconciled = false;
        owner.attached(CdpEvent { method: "Target.attachedToTarget".into(), session_id: None, params: json!({"sessionId":"observer", "waitingForDebugger":false,"targetInfo":{"targetId":"unadopted-host","type":"page","browserContextId":"owned-context"}}) }).await.unwrap();
        owner.start(&owner.operation()).await.unwrap();
        assert!(owner.page.visited_origins().unwrap().is_empty());
        let proof = owner.attest_capture(&owner.operation()).await.unwrap();
        owner
            .verify_capture_attestation(&proof, &owner.operation())
            .await
            .unwrap();
        assert!(
            owner.page.visited_origins().unwrap().is_empty(),
            "frame reconciliation must not add initial profile origins"
        );
        owner.event(&CdpEvent { method:"Target.targetInfoChanged".into(), session_id:None,
            params:json!({"targetInfo":{"targetId":"initial-target","url":"https://metadata.test/"}}) }).unwrap();
        owner
            .event(&CdpEvent {
                method: "Page.navigatedWithinDocument".into(),
                session_id: Some("initial".into()),
                params: json!({"frameId":"frame-initial","url":"https://initial.test/#hash"}),
            })
            .unwrap();
        assert!(owner.page.visited_origins().unwrap().is_empty());
        owner.event(&CdpEvent { method:"Page.frameNavigated".into(), session_id:Some("initial".into()),
            params:json!({"frame":{"id":"frame-initial","loaderId":"new-loader","url":"https://visited.test/"}}) }).unwrap();
        assert_eq!(
            owner.page.visited_origins().unwrap(),
            vec!["https://visited.test"]
        );
        assert!(owner.index.lock().unwrap().sessions["observer"].observation_only);
        assert!(owner.targets.owned_target("unadopted-host").is_err());
        owner.event(&CdpEvent { method:"Page.frameNavigated".into(), session_id:Some("observer".into()), params:json!({"frame":{"id":"frame-observer","loaderId":"other-new","url":"https://other-page.test/"}}) }).unwrap();
        let origins = owner.page.visited_origins().unwrap();
        assert!(origins.contains(&"https://other-page.test".into()));
        assert!(origins.contains(&"https://visited.test".into()));
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn borrowed_export_bootstrap_waits_exact_created_ack_without_host_adoption() {
        let (owner, _ui, log, _emit, server, _notices) = borrowed_restart_fixture().await;
        let mut reservation = owner
            .targets
            .reserve_creation(TargetPurpose::StateBootstrap)
            .unwrap();
        let child = owner.clone();
        let bootstrap = tokio::spawn(async move {
            child
                .attached(attach(
                    "owned-context",
                    "export-created",
                    "export-session",
                    "page",
                    None,
                ))
                .await
        });
        let child = owner.clone();
        let unrelated = tokio::spawn(async move {
            child
                .attached(attach(
                    "owned-context",
                    "host-unrelated",
                    "host-session",
                    "page",
                    None,
                ))
                .await
        });
        tokio::task::yield_now().await;
        assert!(!bootstrap.is_finished());
        assert!(!owner.authorized("host-unrelated", None, None).unwrap());
        reservation
            .record_native_created_target("export-created")
            .unwrap();
        reservation
            .acknowledge_native_created_target(&borrowed_info("export-created"))
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            owner.targets.wait_attached("export-created"),
        )
        .await
        .unwrap()
        .unwrap();
        reservation.claim("export-created").unwrap();
        drop(reservation);
        bootstrap.await.unwrap().unwrap();
        unrelated.await.unwrap().unwrap();
        assert_eq!(
            owner
                .targets
                .owned_target("export-created")
                .unwrap()
                .purpose,
            Some(TargetPurpose::StateBootstrap)
        );
        assert!(owner.index.lock().unwrap().sessions["host-session"].observation_only);
        assert!(owner.targets.owned_target("host-unrelated").is_err());
        assert!(!owner.authorized("host-unrelated", None, None).unwrap());
        assert!(!log
            .lock()
            .unwrap()
            .iter()
            .any(|cmd| cmd["sessionId"] == "export-session"
                && matches!(
                    cmd["method"].as_str(),
                    Some("Page.enable" | "Fetch.enable" | "Runtime.runIfWaitingForDebugger")
                )));
        assert!(!log
            .lock()
            .unwrap()
            .iter()
            .any(|cmd| cmd["method"] == "Target.closeTarget"));
        owner.close().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn borrowed_restart_permission_never_expands_ordinary_close_ownership() {
        let (owner, ui, log, _emit, server, _notices) = borrowed_restart_fixture().await;
        let entry = owner.index.lock().unwrap().sessions["initial"].clone();
        let page = owner.lease(&entry).unwrap();
        let mut op = owner.operation();
        op.sequence = 1;
        assert_eq!(
            owner.validate_restart_owner(&page, &ui, &op),
            Err(ProtocolError::UnsupportedCapability)
        );
        let permit = owner.borrowed_restart_permit(&page, &ui, &op).unwrap();
        let mut wrong = copy_operation(&op);
        wrong.sequence += 1;
        assert_eq!(permit.check(&wrong), Err(ProtocolError::StaleScope));
        let mut foreign = borrowed_info("host");
        foreign["browserContextId"] = json!("foreign");
        assert_eq!(
            permit.prepare_page_retirement(&foreign, &op),
            Err(ProtocolError::PolicyDenied)
        );
        let mut worker = borrowed_info("worker");
        worker["type"] = json!("service_worker");
        assert_eq!(
            permit.prepare_page_retirement(&worker, &op),
            Err(ProtocolError::PolicyDenied)
        );
        assert_eq!(
            permit
                .prepare_page_retirement(&borrowed_info("unadopted-host"), &op)
                .unwrap(),
            None
        );
        owner
            .attached(attach(
                "owned-context",
                "unadopted-host",
                "late-host",
                "page",
                None,
            ))
            .await
            .unwrap();
        assert!(!owner
            .index
            .lock()
            .unwrap()
            .sessions
            .contains_key("late-host"));
        assert_eq!(
            permit
                .prepare_page_retirement(&borrowed_info("initial-target"), &op)
                .unwrap(),
            Some("initial".into())
        );
        drop(permit);
        drop(page);
        owner.close().await.unwrap();
        let proof = owner.contain_owned_resources().await.unwrap();
        owner.release_after_containment(proof).await.unwrap();
        assert!(!log.lock().unwrap().iter().any(|entry| matches!(
            entry["method"].as_str(),
            Some("Target.closeTarget" | "Target.disposeBrowserContext" | "Browser.close")
        )));
        server.abort();
    }
    #[tokio::test]
    async fn borrowed_blank_attach_waits_exact_ack_and_unrelated_candidate_detaches() {
        let (owner, ui, log, _emit, server, _notices) = borrowed_restart_fixture().await;
        let entry = owner.index.lock().unwrap().sessions["initial"].clone();
        let page = owner.lease(&entry).unwrap();
        let mut op = owner.operation();
        op.sequence = 1;
        let permit = owner.borrowed_restart_permit(&page, &ui, &op).unwrap();
        let mut admission = permit.reserve_blank_creation(&op).unwrap();
        let mut reservation = owner
            .targets
            .reserve_creation(TargetPurpose::Application)
            .unwrap();
        let child = owner.clone();
        let attached = tokio::spawn(async move {
            child
                .attached(attach(
                    "owned-context",
                    "blank",
                    "blank-session",
                    "page",
                    None,
                ))
                .await
        });
        let child = owner.clone();
        let unrelated = tokio::spawn(async move {
            child
                .attached(attach(
                    "owned-context",
                    "other-host",
                    "other-session",
                    "page",
                    None,
                ))
                .await
        });
        tokio::task::yield_now().await;
        assert!(!owner
            .index
            .lock()
            .unwrap()
            .sessions
            .contains_key("blank-session"));
        admission.acknowledge(&borrowed_info("blank"), &op).unwrap();
        tokio::time::timeout(Duration::from_secs(2), owner.targets.wait_attached("blank"))
            .await
            .unwrap()
            .unwrap();
        let session = owner
            .select_registered_restart_page("blank", &op)
            .await
            .unwrap();
        reservation.claim("blank").unwrap();
        drop(reservation);
        attached.await.unwrap().unwrap();
        unrelated.await.unwrap().unwrap();
        owner
            .wait_restart_page_ready("blank", &session, &op)
            .await
            .unwrap();
        admission.complete("blank", &session, &op).unwrap();
        permit.check(&op).unwrap();
        assert!(!owner
            .index
            .lock()
            .unwrap()
            .sessions
            .contains_key("other-session"));
        assert!(log
            .lock()
            .unwrap()
            .iter()
            .any(|entry| entry["method"] == "Target.detachFromTarget"
                && entry["params"]["sessionId"] == "other-session"));
        drop(permit);
        drop(page);
        owner.close().await.unwrap();
        let proof = owner.contain_owned_resources().await.unwrap();
        owner.release_after_containment(proof).await.unwrap();
        assert!(!log
            .lock()
            .unwrap()
            .iter()
            .any(|entry| entry["method"] == "Target.closeTarget"));
        server.abort();
    }
    #[tokio::test]
    async fn borrowed_blank_late_waiter_cannot_reenter_retired_ack_target() {
        let (owner, ui, _log, _emit, server, _notices) = borrowed_restart_fixture().await;
        let entry = owner.index.lock().unwrap().sessions["initial"].clone();
        let page = owner.lease(&entry).unwrap();
        let mut op = owner.operation();
        op.sequence = 1;
        let permit = owner.borrowed_restart_permit(&page, &ui, &op).unwrap();
        let mut admission = permit.reserve_blank_creation(&op).unwrap();
        let waiting = owner.borrowed_blank_matches("blank");
        tokio::pin!(waiting);
        assert!(futures_util::poll!(&mut waiting).is_pending());
        admission.acknowledge(&borrowed_info("blank"), &op).unwrap();
        permit
            .prepare_page_retirement(&borrowed_info("blank"), &op)
            .unwrap();
        assert!(!waiting.await.unwrap());
        drop(admission);
        assert_eq!(owner.check(), Err(ProtocolError::CleanupFailed));
        drop(permit);
        drop(page);
        let _ = owner.close().await;
        server.abort();
    }
    #[tokio::test]
    async fn borrowed_unsubmitted_creation_cancels_without_remote_lifetime_effects() {
        let (owner, ui, log, _emit, server, _notices) = borrowed_restart_fixture().await;
        let entry = owner.index.lock().unwrap().sessions["initial"].clone();
        let page = owner.lease(&entry).unwrap();
        let mut op = owner.operation();
        op.sequence = 1;
        let permit = owner.borrowed_restart_permit(&page, &ui, &op).unwrap();
        permit
            .reserve_blank_creation(&op)
            .unwrap()
            .cancel_unsubmitted()
            .unwrap();
        drop(permit);
        owner.check().unwrap();
        drop(page);
        owner.close().await.unwrap();
        assert!(!log.lock().unwrap().iter().any(|entry| matches!(
            entry["method"].as_str(),
            Some("Target.closeTarget" | "Target.createTarget" | "Target.disposeBrowserContext")
        )));
        server.abort();
    }
    #[tokio::test]
    async fn borrowed_host_cleanup_removes_only_our_registrations_and_never_closes_pages() {
        for mode in ["normal", "late-borrowed", "fail-remove-script"] {
            let (mut owner, _notices, log, _emit, server) = fixture(mode).await;
            let state = Arc::get_mut(&mut owner).unwrap();
            state.ownership = ScopeOwnership::BorrowedTargets(vec!["initial-target".into()]);
            state.config.block_service_workers = true;
            owner
                .enroll_existing("initial-target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            owner.close().await.unwrap();
            assert!(!log
                .lock()
                .unwrap()
                .iter()
                .any(|v| v["method"] == "Target.detachFromTarget"
                    && v["params"]["sessionId"] == "initial"));
            if mode == "fail-remove-script" {
                assert!(owner.contain_owned_resources().await.is_err());
            } else {
                let proof = owner.contain_owned_resources().await.unwrap();
                owner.release_after_containment(proof).await.unwrap();
            }
            let commands = log.lock().unwrap().clone();
            assert!(!commands.iter().any(|v| matches!(
                v["method"].as_str(),
                Some("Target.closeTarget" | "Target.disposeBrowserContext" | "Browser.close")
            )));
            let removal = commands
                .iter()
                .position(|v| v["method"] == "Page.removeScriptToEvaluateOnNewDocument")
                .unwrap();
            let detach = commands
                .iter()
                .position(|v| {
                    v["method"] == "Target.detachFromTarget"
                        && v["params"]["sessionId"] == "initial"
                })
                .unwrap();
            assert!(removal < detach);
            assert_eq!(
                commands[removal]["params"]["identifier"],
                "synthetic-script"
            );
            assert!(commands.iter().any(|v| v["method"] == "Fetch.disable"));
            if mode == "late-borrowed" {
                assert!(commands
                    .iter()
                    .any(|v| v["method"] == "Target.detachFromTarget"
                        && v["params"]["sessionId"] == "late-borrowed"));
            }
            assert!(owner.cleanup_outcome().unwrap().closed_targets.is_empty());
            server.abort();
        }
    }
    #[tokio::test]
    async fn borrowed_retirement_requires_auxiliary_detach_proof_without_double_detach() {
        for complete in [true, false] {
            let (mut owner, _notices, log, emit, server) = fixture("normal").await;
            Arc::get_mut(&mut owner).unwrap().ownership =
                ScopeOwnership::BorrowedTargets(vec!["initial-target".into()]);
            owner
                .enroll_existing("initial-target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            let mut auxiliary = owner
                .targets
                .reserve_auxiliary_attachment(
                    &owner.targets.identity_scope,
                    "initial-target",
                    "initial",
                )
                .unwrap();
            auxiliary.claim("recorder").unwrap();
            if complete {
                auxiliary.detached("recorder").unwrap();
            }
            owner.close().await.unwrap();
            emit.send(json!({"method":"Target.attachedToTarget","params":{
                "sessionId":"recorder","waitingForDebugger":false,
                "targetInfo":{"targetId":"initial-target","browserContextId":"owned-context","type":"page"}}})).await.unwrap();
            let result = owner.contain_owned_resources().await;
            assert_eq!(result.is_ok(), complete);
            assert!(!log
                .lock()
                .unwrap()
                .iter()
                .any(|event| event["method"] == "Target.detachFromTarget"
                    && event["params"]["sessionId"] == "recorder"));
            assert!(!log.lock().unwrap().iter().any(|event| matches!(
                event["method"].as_str(),
                Some("Target.closeTarget" | "Target.disposeBrowserContext" | "Browser.close")
            )));
            server.abort();
        }
    }
    #[tokio::test]
    async fn borrowed_pending_request_is_aborted_before_interception_detaches() {
        let (mut owner, mut notices, log, _emit, server) = fixture("first-request").await;
        Arc::get_mut(&mut owner).unwrap().ownership =
            ScopeOwnership::BorrowedTargets(vec!["initial-target".into()]);
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), notices.recv())
            .await
            .unwrap()
            .unwrap();
        owner.close().await.unwrap();
        let proof = owner.contain_owned_resources().await.unwrap();
        owner.release_after_containment(proof).await.unwrap();
        let commands = log.lock().unwrap().clone();
        let abort = commands
            .iter()
            .position(|v| v["method"] == "Fetch.failRequest" && v["params"]["requestId"] == "first")
            .unwrap();
        let disable = commands
            .iter()
            .position(|v| v["method"] == "Fetch.disable")
            .unwrap();
        assert!(abort < disable);
        assert!(!commands.iter().any(|v| v["method"] == "Target.closeTarget"));
        server.abort();
    }
    #[tokio::test]
    async fn retirement_before_registration_preserves_failure_and_foreign_cleanup() {
        let (owner, _notices, log, _emit, server) = fixture("normal").await;
        owner.seal();
        assert_eq!(
            owner
                .attached(attach(
                    "owned-context",
                    "late-owned",
                    "late-session",
                    "page",
                    None
                ))
                .await,
            Err(ProtocolError::Cancelled)
        );
        assert!(owner.index.lock().unwrap().sessions.is_empty());
        assert!(log.lock().unwrap().is_empty());
        owner
            .attached(attach(
                "foreign-context",
                "foreign-target",
                "foreign-session",
                "page",
                None,
            ))
            .await
            .unwrap();
        let requests = log.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["method"], "Target.detachFromTarget");
        owner.poison(ProtocolError::StaleScope);
        assert_eq!(
            owner
                .attached(attach(
                    "owned-context",
                    "late-owned",
                    "late-session",
                    "page",
                    None
                ))
                .await,
            Err(ProtocolError::StaleScope)
        );
        assert!(owner.index.lock().unwrap().sessions.is_empty());
        assert_eq!(log.lock().unwrap().len(), 1);
        server.abort();
    }
    #[tokio::test]
    async fn explicit_retirement_only_cancels_unissued_admission_and_preserves_failure() {
        let (owner, _notices, _log, _emit, server) = fixture("normal").await;
        owner.seal();
        owner.gate.seal();
        assert_eq!(
            owner.admission_error(ProtocolError::StaleScope),
            ProtocolError::Cancelled
        );
        assert_eq!(
            owner.admission_error(ProtocolError::BrowserFailure),
            ProtocolError::BrowserFailure
        );
        owner.poison(ProtocolError::StaleScope);
        assert_eq!(
            owner.admission_error(ProtocolError::StaleScope),
            ProtocolError::StaleScope
        );
        server.abort();
    }
    #[test]
    fn disable_autoattach_omits_chromium_forbidden_filter() {
        assert!(autoattach(true).get("filter").is_some());
        assert!(autoattach(false).get("filter").is_none());
    }
    #[tokio::test]
    async fn shared_renderer_emulation_is_idempotent_but_invalid_timezone_never_resumes() {
        for mode in ["locale-already", "timezone-already", "invalid-timezone"] {
            let (mut owner, _notices, log, _emit, server) = fixture(mode).await;
            Arc::get_mut(&mut owner).unwrap().config.timezone_id = Some("Europe/Paris".into());
            let result = owner
                .attached(attach(
                    "owned-context",
                    "initial-target",
                    "initial-session",
                    "page",
                    None,
                ))
                .await;
            if mode == "invalid-timezone" {
                assert_eq!(result, Err(ProtocolError::BrowserFailure));
                assert!(!log
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|r| r["method"] == "Runtime.runIfWaitingForDebugger"));
            } else {
                result.unwrap();
                assert!(log
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|r| r["method"] == "Runtime.runIfWaitingForDebugger"));
            }
            owner.close().await.unwrap();
            server.abort();
        }
    }
    #[tokio::test]
    async fn auxiliary_recording_session_never_enters_generic_configuration_or_detach() {
        let (owner, _notices, log, _emit, server) = fixture("normal").await;
        owner
            .attached(attach(
                "owned-context",
                "initial-target",
                "primary",
                "page",
                None,
            ))
            .await
            .unwrap();
        let mut token = owner
            .targets
            .reserve_auxiliary_attachment(
                &owner.targets.identity_scope,
                "initial-target",
                "primary",
            )
            .unwrap();
        token.claim("recorder").unwrap();
        log.lock().unwrap().clear();
        owner
            .attached(attach(
                "owned-context",
                "initial-target",
                "recorder",
                "page",
                None,
            ))
            .await
            .unwrap();
        token.detached("recorder").unwrap();
        drop(token);
        owner
            .attached(attach(
                "owned-context",
                "initial-target",
                "recorder",
                "page",
                None,
            ))
            .await
            .unwrap();
        assert!(log.lock().unwrap().is_empty());
        assert_eq!(owner.index.lock().unwrap().sessions.len(), 1);
        owner
            .attached(attach(
                "owned-context",
                "initial-target",
                "unrelated",
                "page",
                None,
            ))
            .await
            .unwrap();
        let events = log.lock().unwrap().clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["method"], "Target.detachFromTarget");
        assert_eq!(events[0]["params"]["sessionId"], "unrelated");
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn restart_selects_reserved_root_before_configuration_and_preserves_scope() {
        let (fixture_owner, _old_notices, _log, _emit, server) = fixture("normal").await;
        let ui = Arc::new(super::super::client_ui::UiGate::default());
        let (owner, _notices, _broker) = coordinator_with_ui(
            fixture_owner.client.clone(),
            "owned-context",
            "restart-scope",
            "",
            ui.clone(),
        );
        owner
            .attached(attach("owned-context", "old-target", "old", "page", None))
            .await
            .unwrap();
        owner.set_active_root("old").unwrap();
        let entry = owner
            .index
            .lock()
            .unwrap()
            .sessions
            .get("old")
            .unwrap()
            .clone();
        let lease = owner.lease(&entry).unwrap();
        owner
            .validate_restart_owner(&lease, &ui, &owner.operation())
            .unwrap();
        assert_eq!(
            owner.validate_restart_owner(
                &lease,
                &Arc::new(super::super::client_ui::UiGate::default()),
                &owner.operation()
            ),
            Err(ProtocolError::PolicyDenied)
        );
        let mut stale = owner.operation();
        stale.generation += 1;
        assert_eq!(
            owner.validate_restart_owner(&lease, &ui, &stale),
            Err(ProtocolError::StaleGeneration)
        );
        let mut reservation = owner
            .targets
            .reserve_creation(TargetPurpose::Application)
            .unwrap();
        let new = owner
            .register("owned-context", "new-target", "new", "page", None)
            .unwrap()
            .unwrap();
        assert_eq!(
            owner
                .select_registered_restart_page("new-target", &owner.operation())
                .await
                .unwrap(),
            "new"
        );
        assert_eq!(*owner.active_root.lock().unwrap(), "new");
        reservation.claim("new-target").unwrap();
        drop(reservation);
        owner.initialize(new, &owner.operation()).await.unwrap();
        owner
            .wait_restart_page_ready("new-target", "new", &owner.operation())
            .await
            .unwrap();
        assert_eq!(
            owner.validate_restart_owner(&lease, &ui, &owner.operation()),
            Err(ProtocolError::StaleReference)
        );
        drop(lease);
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn restart_retirement_requires_exact_application_root_and_observed_detach() {
        let (owner, _notices, _log, _emit, server) = fixture("normal").await;
        owner
            .attached(attach("owned-context", "old-target", "old", "page", None))
            .await
            .unwrap();
        let entry = owner
            .index
            .lock()
            .unwrap()
            .sessions
            .get("old")
            .unwrap()
            .clone();
        assert_eq!(
            owner.expect_restart_page_retirement("other", "old", &owner.operation()),
            Err(ProtocolError::StaleReference)
        );
        owner
            .expect_restart_page_retirement("old-target", "old", &owner.operation())
            .unwrap();
        assert!(!owner
            .index
            .lock()
            .unwrap()
            .retired_page_sessions
            .contains("old"));
        owner
            .register(
                "owned-context",
                "child-target",
                "child",
                "iframe",
                Some("old"),
            )
            .unwrap();
        owner
            .event(&CdpEvent {
                method: "Target.detachedFromTarget".into(),
                params: json!({"sessionId":"old"}),
                session_id: None,
            })
            .unwrap();
        assert!(owner
            .index
            .lock()
            .unwrap()
            .retired_page_sessions
            .contains("old"));
        assert!(owner
            .index
            .lock()
            .unwrap()
            .retired_page_sessions
            .contains("child"));
        owner
            .attached(attach(
                "owned-context",
                "grandchild-target",
                "grandchild",
                "iframe",
                Some("child"),
            ))
            .await
            .unwrap();
        assert!(owner
            .index
            .lock()
            .unwrap()
            .retired_page_sessions
            .contains("grandchild"));
        assert!(!owner
            .index
            .lock()
            .unwrap()
            .sessions
            .contains_key("grandchild"));
        // Missing target now causes StaleReference inside initialize. Only the
        // explicit observed retirement may discharge this obsolete page work.
        owner
            .initialize(entry.clone(), &owner.operation())
            .await
            .unwrap();
        let mut unrelated = entry;
        unrelated.root = "other-root".into();
        assert_eq!(
            owner.initialize(unrelated, &owner.operation()).await,
            Err(ProtocolError::StaleReference)
        );
        owner.poison(ProtocolError::BrowserFailure);
        assert_eq!(
            owner
                .wait_restart_page_ready("old-target", "old", &owner.operation())
                .await,
            Err(ProtocolError::BrowserFailure)
        );
        assert_eq!(owner.close().await, Err(ProtocolError::BrowserFailure));
        server.abort();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn supervisor_stop_before_first_poll_drains_idle_live_connection() {
        for already_seen in [false, true] {
            let (owner, _notices, log, _emit, server) = fixture("normal").await;
            if already_seen {
                // Model sealing between ensure_supervisor's initial check and
                // receiver creation: subscribe marks the current value seen.
                let events = owner
                    .client
                    .subscribe_bounded_methods_with_budget(
                        EVENTS,
                        256,
                        128 * 1024 * 1024,
                        256 * 1024 * 1024,
                    )
                    .unwrap();
                owner.seal();
                let stop = owner.stop.subscribe();
                assert_eq!(*stop.borrow(), CancelSignal::SessionClosed);
                let retained = owner.clone();
                *owner.supervisor.lock().await =
                    Some(tokio::spawn(
                        async move { retained.run(events, stop).await },
                    ));
            } else {
                // Current-thread scheduling and no intervening await/yield mean
                // the spawned supervisor cannot have subscribed/polled yet.
                owner.ensure_supervisor().await.unwrap();
                owner.seal();
            }
            tokio::time::timeout(Duration::from_secs(2), owner.drain())
                .await
                .expect("idle live peer must not be needed to wake stopped enrollment")
                .unwrap();
            assert!(!server.is_finished());
            assert!(!*owner.client.remote_connection_closed().borrow());
            assert!(owner.supervisor.lock().await.is_none());
            assert!(!log.lock().unwrap().iter().any(|cmd| matches!(
                cmd["method"].as_str(),
                Some("Target.closeTarget" | "Target.disposeBrowserContext" | "Browser.close")
            )));
            server.abort();
        }
    }
    #[tokio::test]
    async fn start_readiness_rejects_pending_cancelled_and_failed_before_ack() {
        for case in ["pending", "cancelled", "failed"] {
            let (mut owner, _notices, _log, _emit, server) = fixture("normal").await;
            owner.gate.begin_transition().unwrap();
            let authority = owner.gate.initialization(owner.targets.clone()).unwrap();
            Arc::get_mut(&mut owner).unwrap().initialization = Some(authority.access());
            owner.ensure_supervisor().await.unwrap();
            let watermark = owner.event_watermark.lock().unwrap().clone().unwrap();
            let mut op = owner.operation();
            let (_cancel, rx) = watch::channel(CancelSignal::Requested);
            match case {
                "pending" => {
                    owner
                        .index
                        .lock()
                        .unwrap()
                        .pending_enrollment
                        .insert("pending".into());
                }
                "cancelled" => {
                    op.cancellation = rx;
                }
                _ => owner.poison(ProtocolError::BrowserFailure),
            }
            let result = owner.acknowledge_start(&op, &watermark);
            if case == "pending" {
                assert_eq!(result, Ok(false));
            } else {
                assert!(result.is_err());
            }
            assert!(!owner.index.lock().unwrap().reconciled);
            assert!(owner.targets.publish_initialization(&authority).is_err());
            owner.index.lock().unwrap().pending_enrollment.clear();
            let _ = owner.close().await;
            server.abort();
        }
    }
    #[tokio::test]
    async fn initialized_publication_rejects_late_failure_and_pending_events() {
        for failed in [false, true] {
            let (mut owner, _notices, _log, _emit, server) = fixture("normal").await;
            owner.gate.begin_transition().unwrap();
            let authority = owner.gate.initialization(owner.targets.clone()).unwrap();
            Arc::get_mut(&mut owner).unwrap().initialization = Some(authority.access());
            assert!(owner.publish_initialized(&authority).is_err());
            owner
                .enroll_existing("initial-target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            owner.start(&owner.operation()).await.unwrap();
            // Production start itself must establish readiness, with no manual
            // test-only acknowledge_enrollment masking a missing lifecycle step.
            let held = authority.enter(&owner.targets).unwrap();
            assert!(owner.publish_initialized(&authority).is_err());
            drop(held);
            owner
                .index
                .lock()
                .unwrap()
                .pending_enrollment
                .insert("pending".into());
            assert!(owner.publish_initialized(&authority).is_err());
            owner.index.lock().unwrap().pending_enrollment.clear();
            if failed {
                owner.poison(ProtocolError::BrowserFailure);
                assert_eq!(
                    owner.publish_initialized(&authority),
                    Err(ProtocolError::BrowserFailure)
                );
                assert!(owner.gate.enter(false).is_err());
            } else {
                owner.publish_initialized(&authority).unwrap();
                drop(owner.gate.enter(false).unwrap());
            }
            let _ = owner.close().await;
            server.abort();
        }
    }
    #[tokio::test]
    async fn terminal_reader_retirement_drains_without_remote_containment_ack_claims() {
        let (owner, _notices, log, _emit, server) = fixture("normal").await;
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        let before = log.lock().unwrap().len();
        server.abort();
        let _ = server.await;
        tokio::time::timeout(Duration::from_secs(2), owner.drain())
            .await
            .unwrap()
            .unwrap();
        let proof = owner.terminal_connection_proof().unwrap();
        proof.check_network(&owner.network).unwrap();
        assert_eq!(log.lock().unwrap().len(), before);
        let outcome = owner.cleanup_outcome().unwrap();
        assert!(!outcome.isolated_context_disposed);
        assert!(!outcome.autoattach_disabled);
        assert!(!outcome.owned_resources_contained);
        assert!(outcome.closed_targets.is_empty());
        assert!(outcome.borrowed_sessions_detached.is_empty());
    }

    #[tokio::test]
    async fn terminal_proof_requires_remote_eof_and_retains_exact_original_bindings() {
        let (owner, _notices, _log, _emit, server) = fixture("normal").await;
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        assert!(matches!(
            owner.terminal_connection_proof(),
            Err(ProtocolError::ScopeUnavailable)
        ));
        let (other, _other_notices, _other_log, _other_emit, other_server) =
            fixture("normal").await;
        server.abort();
        let _ = server.await;
        let mut remote = owner.client.remote_connection_closed();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !*remote.borrow_and_update() {
                remote.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let proof = owner.terminal_connection_proof().unwrap();
        assert_eq!(proof.active_target(), "initial-target");
        assert_eq!(proof.generation(), owner.generation);
        assert!(Arc::ptr_eq(proof.targets(), &owner.targets));
        assert!(matches!(
            proof.check_client(&other.client),
            Err(ProtocolError::StaleScope)
        ));
        assert!(matches!(
            proof.check_targets(&other.targets),
            Err(ProtocolError::StaleScope)
        ));
        assert!(matches!(
            proof.check_network(&other.network),
            Err(ProtocolError::StaleScope)
        ));
        owner.seal();
        owner.index.lock().unwrap().sessions.clear();
        *owner.active_root.lock().unwrap() = "replacement-must-not-be-consulted".into();
        proof.check_network(&owner.network).unwrap();
        assert_eq!(
            owner.terminal_connection_proof().unwrap().active_target(),
            "initial-target"
        );
        owner.poison(ProtocolError::CleanupFailed);
        assert!(matches!(
            owner.terminal_connection_proof(),
            Err(ProtocolError::CleanupFailed)
        ));
        // Existing cleanup identity remains valid without certifying success.
        proof.check_network(&owner.network).unwrap();
        other_server.abort();
    }

    #[tokio::test]
    async fn app_events_use_exact_application_session_and_runtime_precedes_resume() {
        let (owner, mut notices, log, _emit, server) = fixture("normal").await;
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        let commands = log.lock().unwrap().clone();
        assert!(
            commands
                .iter()
                .position(|v| v["method"] == "Runtime.enable")
                .unwrap()
                < commands
                    .iter()
                    .position(|v| v["method"] == "Runtime.runIfWaitingForDebugger")
                    .unwrap()
        );
        let mut event = CdpEvent {
            method: "Runtime.consoleAPICalled".into(),
            session_id: Some("foreign".into()),
            params: json!({"type":"log","args":[{"type":"string","value":"synthetic console"}]}),
        };
        owner.event(&event).unwrap();
        assert!(notices.try_recv().is_err());
        event.session_id = Some("initial".into());
        owner.event(&event).unwrap();
        let ServerMessage::Event {
            event: name,
            payload,
            ..
        } = notices.try_recv().unwrap()
        else {
            panic!("expected app event")
        };
        assert_eq!(name, "app.log");
        assert_eq!(payload["identityScope"], "owned-scope");
        assert_eq!(payload["text"], "synthetic console");
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn own_navigation_guard_covers_queued_tap_events_until_flush() {
        let (owner, mut notices, _log, emit, server) = fixture("normal").await;
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner.start(&owner.operation()).await.unwrap();
        let entry = owner
            .index
            .lock()
            .unwrap()
            .sessions
            .get("initial")
            .unwrap()
            .clone();
        let lease = owner.lease(&entry).unwrap();
        let operation = owner.operation();
        let guard = owner
            .network
            .begin_app_navigation(&lease, &operation)
            .unwrap();
        let watermark = owner.event_watermark.lock().unwrap().clone().unwrap();
        let before = watermark.received().unwrap();
        emit.send(json!({"method":"Page.frameNavigated","sessionId":"initial",
            "params":{"frame":{"id":"main-frame","loaderId":"new-loader","url":"https://synthetic.test/owned"}}})).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while watermark.received().unwrap() == before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        owner.flush_app_events(&lease, &operation).await.unwrap();
        drop(guard);
        let ServerMessage::Event { event, payload, .. } = notices.try_recv().unwrap() else {
            panic!("expected navigation")
        };
        assert_eq!(event, "app.navigation");
        assert_eq!(payload["kind"], "main");
        assert_eq!(payload["initiatedByOperation"], true);
        owner
            .event(&CdpEvent {
                method: "Page.navigatedWithinDocument".into(),
                session_id: Some("initial".into()),
                params: json!({"frameId":"main-frame","url":"https://synthetic.test/app"}),
            })
            .unwrap();
        let ServerMessage::Event { payload, .. } = notices.try_recv().unwrap() else {
            panic!("expected app navigation")
        };
        assert_eq!(payload["initiatedByOperation"], false);
        drop(lease);
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn app_navigation_distinguishes_initial_popup_later_popup_and_frames() {
        let (owner, _notices, _log, _emit, server) = fixture("normal").await;
        let popup = Attribution {
            target: "popup-target".into(),
            session: "popup".into(),
            root: "popup".into(),
            parent: None,
            kind: "page".into(),
            application: true,
            observation_only: false,
            observer_paused: false,
            resumed: true,
        };
        owner.index.lock().unwrap().frames.insert(
            "popup-frame".into(),
            FrameOwner {
                loader: None,
                name: None,
                session: "popup".into(),
                parent: None,
            },
        );
        let mut event = CdpEvent {
            method: "Page.frameNavigated".into(),
            session_id: Some("popup".into()),
            params: json!({"frame":{"id":"popup-frame","url":"about:blank"}}),
        };
        assert_eq!(owner.app_navigation(&popup, &event).unwrap(), None);
        event.params["frame"]["url"] = json!("https://synthetic.test/tab");
        assert_eq!(
            owner.app_navigation(&popup, &event).unwrap(),
            Some((AppNavigationKind::Popup, None))
        );
        assert_eq!(
            owner.app_navigation(&popup, &event).unwrap(),
            Some((AppNavigationKind::PopupNavigation, None))
        );
        owner.index.lock().unwrap().frames.insert(
            "child".into(),
            FrameOwner {
                loader: None,
                name: Some("checkout".into()),
                session: "popup".into(),
                parent: Some("popup-frame".into()),
            },
        );
        event.params["frame"]["id"] = json!("child");
        assert_eq!(
            owner.app_navigation(&popup, &event).unwrap(),
            Some((AppNavigationKind::Frame, Some("checkout".into())))
        );
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn application_dom_whitespace_is_enabled_before_first_document_and_resume() {
        let (owner, _notices, log, _emit, server) = fixture("normal").await;
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner
            .attached(attach(
                "owned-context",
                "child-target",
                "child",
                "iframe",
                Some("initial"),
            ))
            .await
            .unwrap();
        owner
            .attached(attach(
                "owned-context",
                "worker-target",
                "worker",
                "worker",
                Some("initial"),
            ))
            .await
            .unwrap();
        for session in ["initial", "child"] {
            let tree = owner
                .client
                .send_command_no_params("DOM.getDocument", Some(session))
                .await
                .unwrap();
            assert_eq!(tree["root"]["children"][0]["nodeValue"], " ");
            let commands = log
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r["sessionId"] == session)
                .cloned()
                .collect::<Vec<_>>();
            let enabled = commands
                .iter()
                .position(|r| r["method"] == "DOM.enable")
                .unwrap();
            assert_eq!(
                commands[enabled]["params"],
                json!({"includeWhitespace":"all"})
            );
            let first_dom = commands
                .iter()
                .position(|r| r["method"].as_str().is_some_and(|m| m.starts_with("DOM.")))
                .unwrap();
            assert_eq!(enabled, first_dom);
            for method in ["DOM.getDocument", "Runtime.runIfWaitingForDebugger"] {
                assert!(enabled < commands.iter().position(|r| r["method"] == method).unwrap());
            }
            assert!(!commands.iter().any(|r| r["method"] == "DOM.disable"));
        }
        assert!(!log
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["sessionId"] == "worker"
                && r["method"].as_str().is_some_and(|m| m.starts_with("DOM."))));
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn failed_initial_dom_enable_does_not_resume_application() {
        let (owner, _notices, log, _emit, server) = fixture("dom-enable-fails").await;
        assert_eq!(
            owner
                .enroll_existing("initial-target", "initial", "page", &owner.operation())
                .await,
            Err(ProtocolError::BrowserFailure)
        );
        let commands = log.lock().unwrap().clone();
        assert!(commands.iter().any(|r| r["method"] == "DOM.enable"));
        assert!(!commands.iter().any(|r| matches!(
            r["method"].as_str(),
            Some("DOM.getDocument" | "DOM.disable" | "Runtime.runIfWaitingForDebugger")
        )));
        let _ = owner.close().await;
        server.abort();
    }
    #[tokio::test]
    async fn owned_target_configures_before_publication_with_private_authority() {
        let (mut owner, _notices, log, _emit, server) = fixture("normal").await;
        owner.gate.begin_transition().unwrap();
        let authority = owner.gate.initialization(owner.targets.clone()).unwrap();
        Arc::get_mut(&mut owner).unwrap().initialization = Some(authority.access());
        assert!(owner.gate.enter(false).is_err());
        owner
            .attached(attach(
                "owned-context",
                "initial-target",
                "initial-session",
                "page",
                None,
            ))
            .await
            .unwrap();
        let methods = log
            .lock()
            .unwrap()
            .iter()
            .map(|r| r["method"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let configured = methods.iter().position(|m| m == "Fetch.enable").unwrap();
        let resumed = methods
            .iter()
            .position(|m| m == "Runtime.runIfWaitingForDebugger")
            .unwrap();
        assert!(configured < resumed);
        authority.publish().unwrap();
        owner.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn lifecycle_authority_survives_publication_but_never_next_scope() {
        let (mut owner, _notices, log, _emit, server) = fixture("normal").await;
        owner.gate.begin_transition().unwrap();
        let authority = owner.gate.initialization(owner.targets.clone()).unwrap();
        Arc::get_mut(&mut owner).unwrap().initialization = Some(authority.access());
        let entry = Attribution {
            target: "initial-target".into(),
            session: "initial-session".into(),
            parent: None,
            root: "initial-session".into(),
            kind: "page".into(),
            application: true,
            observation_only: false,
            observer_paused: false,
            resumed: false,
        };
        let lease = owner.lease(&entry).unwrap();
        assert!(authority.publish().is_err());
        drop(lease);
        authority.publish().unwrap();
        drop(owner.lease(&entry).unwrap());
        owner.gate.begin_transition().unwrap();
        assert!(owner.lease(&entry).is_err());
        let replacement = owner
            .gate
            .initialization(ClientTargets::new(
                "next-context".into(),
                "next-scope".into(),
            ))
            .unwrap();
        replacement.publish().unwrap();
        assert!(owner.lease(&entry).is_err());
        assert!(log.lock().unwrap().is_empty());
        server.abort();
    }
    #[tokio::test]
    async fn service_worker_enrollment_joins_observers_after_resume_in_fixed_order() {
        let (owner, _notices, log, _emit, server) = fixture("sw-startup-held").await;
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            owner.attached(attach(
                "owned-context",
                "worker-target",
                "worker-session",
                "service_worker",
                None,
            )),
        )
        .await
        .expect("startup must not await renderer ACK before resume")
        .unwrap();
        assert!(owner
            .targets
            .owned_target("worker-target")
            .unwrap()
            .capture_ready());
        assert!(owner.index.lock().unwrap().sessions["worker-session"].resumed);
        let methods: Vec<String> = log
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request["sessionId"] == "worker-session")
            .map(|request| request["method"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            methods,
            vec![
                "Fetch.enable",
                "Target.setAutoAttach",
                "Network.enable",
                "Runtime.enable",
                "Runtime.runIfWaitingForDebugger"
            ]
        );
        // Repeated identical attachment cannot initialize or resume twice.
        owner
            .attached(attach(
                "owned-context",
                "worker-target",
                "worker-session",
                "service_worker",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|request| request["sessionId"] == "worker-session"
                    && request["method"] == "Runtime.runIfWaitingForDebugger")
                .count(),
            1
        );
        server.abort();
    }

    #[tokio::test]
    async fn service_worker_enrollment_main_script_policy_runs_before_observer_acks() {
        let (owner, mut notices, log, _emit, server, broker) =
            fixture_with_broker("sw-startup-main-script").await;
        let callback_owner = owner.clone();
        let policy = tokio::spawn(async move {
            let notice = tokio::time::timeout(Duration::from_secs(1), notices.recv())
                .await
                .unwrap()
                .unwrap();
            let ServerMessage::Event {
                event,
                decision: Some(decision),
                ..
            } = notice
            else {
                panic!("expected managed request decision")
            };
            assert_eq!(event, "network.request");
            assert!(!callback_owner
                .targets
                .owned_target("worker-target")
                .unwrap()
                .capture_ready());
            broker
                .resolve(
                    1,
                    &decision.token,
                    super::super::client_protocol::Decision::Continue {
                        overrides: Default::default(),
                    },
                )
                .unwrap();
        });
        owner.ensure_supervisor().await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            owner.attached(attach(
                "owned-context",
                "worker-target",
                "worker-session",
                "service_worker",
                None,
            )),
        )
        .await
        .expect("main-script interception must not await renderer creation")
        .unwrap();
        assert!(owner
            .targets
            .owned_target("worker-target")
            .unwrap()
            .capture_ready());
        let commands = log.lock().unwrap().clone();
        let resume = commands
            .iter()
            .position(|request| {
                request["sessionId"] == "worker-session"
                    && request["method"] == "Runtime.runIfWaitingForDebugger"
            })
            .unwrap();
        let continued = commands
            .iter()
            .position(|request| {
                request["sessionId"] == "worker-session"
                    && request["method"] == "Fetch.continueRequest"
                    && request["params"]["requestId"] == "worker-main-script"
            })
            .unwrap();
        assert!(resume < continued);
        policy.await.unwrap();
        owner.close().await.unwrap();
        let proof = owner.contain_owned_resources().await.unwrap();
        owner.release_after_containment(proof).await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn service_worker_enrollment_fetch_failure_never_resumes() {
        let (owner, _notices, log, _emit, server) = fixture("fail-fetch").await;
        assert!(owner
            .attached(attach(
                "owned-context",
                "worker-target",
                "worker-session",
                "service_worker",
                None
            ))
            .await
            .is_err());
        assert!(!log
            .lock()
            .unwrap()
            .iter()
            .any(|request| request["sessionId"] == "worker-session"
                && matches!(
                    request["method"].as_str(),
                    Some("Network.enable" | "Runtime.enable" | "Runtime.runIfWaitingForDebugger")
                )));
        assert!(!owner
            .targets
            .owned_target("worker-target")
            .is_ok_and(|target| target.capture_ready()));
        server.abort();
    }

    #[tokio::test]
    async fn service_worker_enrollment_observer_failure_never_publishes_ready() {
        let (owner, _notices, log, _emit, server) = fixture("sw-startup-observer-fails").await;
        assert!(tokio::time::timeout(
            std::time::Duration::from_secs(1),
            owner.attached(attach(
                "owned-context",
                "worker-target",
                "worker-session",
                "service_worker",
                None
            ))
        )
        .await
        .unwrap()
        .is_err());
        assert!(log
            .lock()
            .unwrap()
            .iter()
            .any(|request| request["sessionId"] == "worker-session"
                && request["method"] == "Runtime.runIfWaitingForDebugger"));
        assert!(!owner
            .targets
            .owned_target("worker-target")
            .is_ok_and(|target| target.capture_ready()));
        assert!(!owner
            .index
            .lock()
            .unwrap()
            .sessions
            .get("worker-session")
            .is_some_and(|entry| entry.resumed));
        server.abort();
    }

    #[tokio::test]
    async fn foreign_context_only_detaches_without_domains_or_resume() {
        let (owner, _notices, log, _emit, server) = fixture("normal").await;
        owner
            .attached(attach(
                "other-context",
                "other-target",
                "other-session",
                "page",
                None,
            ))
            .await
            .unwrap();
        let commands = log.lock().unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0]["method"], "Target.detachFromTarget");
        assert_eq!(commands[0]["params"]["sessionId"], "other-session");
        assert!(owner.index.lock().unwrap().sessions.is_empty());
        drop(commands);
        server.abort();
    }
    #[tokio::test]
    async fn foreign_detach_failure_only_undoes_our_pause_before_retry() {
        let (owner, _notices, log, _emit, server) = fixture("detach-fallback").await;
        owner
            .attached(attach("other", "target", "foreign", "page", None))
            .await
            .unwrap();
        let methods: Vec<_> = log
            .lock()
            .unwrap()
            .iter()
            .map(|entry| entry["method"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            methods,
            vec![
                "Target.detachFromTarget",
                "Runtime.runIfWaitingForDebugger",
                "Target.detachFromTarget"
            ]
        );
        server.abort();
    }
    #[tokio::test]
    async fn large_original_request_before_fetch_ack_reaches_scoped_alias() {
        use base64::Engine;
        let (owner, mut notices, _log, _emit, server) = fixture("large-first-request").await;
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner.start(&owner.operation()).await.unwrap();
        let event = tokio::time::timeout(Duration::from_secs(2), notices.recv())
            .await
            .unwrap()
            .unwrap();
        let ServerMessage::Event {
            event,
            payload,
            decision: Some(_),
            ..
        } = event
        else {
            panic!("expected request callback")
        };
        assert_eq!(event, "network.request");
        assert_eq!(payload["identityScope"], "owned-scope");
        assert!(payload["request"].get("postData").is_none());
        let handle = payload["request"]["postDataHandle"].as_str().unwrap();
        let chunk = owner.network.read_body(handle, 0, 256 * 1024).unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(chunk.base64)
                .unwrap(),
            vec![b'b'; 256 * 1024]
        );
        assert!(!chunk.eof);
        owner.close().await.unwrap();
        let proof = owner.contain_owned_resources().await.unwrap();
        owner.release_after_containment(proof).await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn borrowed_initial_page_without_viewport_is_never_resized_during_enrollment() {
        for viewport in [None, Some((390, 600))] {
            let (mut owner, _notices, log, _emit, server) = fixture("borrowed-initial").await;
            let settings = Arc::get_mut(&mut owner).unwrap();
            settings.ownership = ScopeOwnership::BorrowedTargets(vec!["initial-target".into()]);
            settings.config.viewport = viewport;
            owner
                .enroll_existing("initial-target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            // Execute the real reconciliation/readiness path, not a test-only
            // ready flag. The TCP peer advertises this exact borrowed target.
            owner.start(&owner.operation()).await.unwrap();
            let inventory = owner.targets.inventory().unwrap().1;
            assert_eq!(inventory.len(), 1);
            assert_eq!(inventory[0].target_id, "initial-target");
            assert_eq!(inventory[0].session_id, "initial");
            assert!(inventory[0].configured && inventory[0].resumed);
            let requests = log.lock().unwrap().clone();
            let resized = requests
                .iter()
                .filter(|request| {
                    matches!(
                        request["method"].as_str(),
                        Some(
                            "Emulation.setDeviceMetricsOverride"
                                | "Emulation.clearDeviceMetricsOverride"
                        )
                    )
                })
                .collect::<Vec<_>>();
            if let Some((width, height)) = viewport {
                assert_eq!(resized.len(), 1);
                assert_eq!(resized[0]["method"], "Emulation.setDeviceMetricsOverride");
                assert_eq!(resized[0]["sessionId"], "initial");
                assert_eq!(
                    resized[0]["params"],
                    json!({"width":width,"height":height,"deviceScaleFactor":1,"mobile":false})
                );
            } else {
                assert!(resized.is_empty());
            }
            for method in ["Page.enable", "Runtime.runIfWaitingForDebugger"] {
                let routed = requests
                    .iter()
                    .filter(|request| request["method"] == method)
                    .collect::<Vec<_>>();
                assert_eq!(routed.len(), 1, "{method}");
                assert_eq!(routed[0]["sessionId"], "initial", "{method}");
            }
            assert!(requests
                .iter()
                .any(|request| request["method"] == "Target.getTargets"));
            assert!(requests.iter().all(|request| {
                request["method"] != "Target.createTarget"
                    && request["method"] != "Target.attachToTarget"
            }));
            owner.close().await.unwrap();
            server.abort();
        }
    }
    #[tokio::test]
    async fn config_and_first_request_handler_precede_resume_ack() {
        let (owner, mut notices, log, _emit, server) = fixture("first-request").await;
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner.start(&owner.operation()).await.unwrap();
        let notice = tokio::time::timeout(Duration::from_secs(2), notices.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(notice,ServerMessage::Event {event, decision:Some(_),..} if event=="network.request")
        );
        assert_eq!(owner.network.pending_callbacks().unwrap(), 1);
        let commands = log.lock().unwrap().clone();
        let resume = commands
            .iter()
            .position(|entry| entry["method"] == "Runtime.runIfWaitingForDebugger")
            .unwrap();
        for method in [
            "Network.enable",
            "Fetch.enable",
            "Emulation.setDeviceMetricsOverride",
            "Page.enable",
            "Target.setAutoAttach",
        ] {
            assert!(
                commands
                    .iter()
                    .position(|entry| entry["method"] == method)
                    .unwrap()
                    < resume,
                "{method}"
            );
        }
        assert!(owner
            .targets
            .inventory()
            .unwrap()
            .1
            .iter()
            .all(|target| target.configured && target.resumed));
        owner.close().await.unwrap();
        owner.network.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn failed_network_configuration_never_resumes_owned_script() {
        let (owner, _notices, log, _emit, server) = fixture("fail-fetch").await;
        assert!(owner
            .enroll_existing("target", "initial", "page", &owner.operation())
            .await
            .is_err());
        assert!(!log
            .lock()
            .unwrap()
            .iter()
            .any(|entry| entry["method"] == "Runtime.runIfWaitingForDebugger"));
        assert!(owner.close().await.is_err());
        let proof = owner.contain_owned_resources().await.unwrap();
        owner.release_after_containment(proof).await.unwrap();
        let commands = log.lock().unwrap().clone();
        let disposed = commands
            .iter()
            .position(|entry| entry["method"] == "Target.disposeBrowserContext")
            .unwrap();
        let detached = commands
            .iter()
            .position(|entry| {
                entry["method"] == "Target.setAutoAttach" && entry["params"]["autoAttach"] == false
            })
            .unwrap();
        assert!(disposed < detached);
        assert!(owner.cleanup_outcome().unwrap().isolated_context_disposed);
        let _ = owner.network.close().await;
        server.abort();
    }
    #[tokio::test]
    async fn bootstrap_exclusively_waits_for_state_owner_without_generic_cdp() {
        let (owner, _notices, log, _emit, server) = fixture("normal").await;
        let mut reservation = owner
            .targets
            .reserve_creation(TargetPurpose::StateBootstrap)
            .unwrap();
        let entry = owner
            .register(
                "owned-context",
                "bootstrap",
                "bootstrap-session",
                "page",
                None,
            )
            .unwrap()
            .unwrap();
        reservation.claim("bootstrap").unwrap();
        drop(reservation);
        owner.initialize(entry, &owner.operation()).await.unwrap();
        assert!(log.lock().unwrap().is_empty());
        assert!(!owner.index.lock().unwrap().sessions["bootstrap-session"].application);
        server.abort();
    }
    #[tokio::test]
    async fn child_frame_and_popup_have_exact_separate_roots_and_detach_inventory() {
        let (owner, _notices, _log, _emit, server) = fixture("normal").await;
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner
            .attached(attach(
                "owned-context",
                "iframe-target",
                "child",
                "iframe",
                Some("initial"),
            ))
            .await
            .unwrap();
        owner
            .attached(attach(
                "owned-context",
                "popup-target",
                "popup",
                "page",
                Some("initial"),
            ))
            .await
            .unwrap();
        assert_eq!(
            owner.index.lock().unwrap().sessions["child"].root,
            "initial"
        );
        assert_eq!(owner.index.lock().unwrap().sessions["popup"].root, "popup");
        let revision = owner.targets.inventory().unwrap().0;
        owner
            .event(&CdpEvent {
                method: "Page.navigatedWithinDocument".into(),
                session_id: Some("child".into()),
                params: json!({"frameId":"iframe-target","url":"https://synthetic.test/#next"}),
            })
            .unwrap();
        assert!(owner.targets.inventory().unwrap().0 > revision);
        owner
            .event(&CdpEvent {
                method: "Target.detachedFromTarget".into(),
                session_id: Some("initial".into()),
                params: json!({"sessionId":"child"}),
            })
            .unwrap();
        assert!(!owner.index.lock().unwrap().sessions.contains_key("child"));
        assert!(owner.index.lock().unwrap().sessions.contains_key("popup"));
        owner.close().await.unwrap();
        owner.network.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn context_config_lock_serializes_resume_not_foreign_cleanup() {
        let (owner, _notices, log, _emit, server) = fixture("normal").await;
        let gate = owner.config_gate();
        let held = gate.lock().await;
        let child = owner.clone();
        let initializing = tokio::spawn(async move {
            child
                .enroll_existing("target", "initial", "page", &child.operation())
                .await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        owner
            .attached(attach(
                "foreign",
                "foreign-target",
                "foreign-session",
                "page",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(log.lock().unwrap().len(), 1);
        drop(held);
        initializing.await.unwrap().unwrap();
        owner.close().await.unwrap();
        owner.network.close().await.unwrap();
        server.abort();
    }
    #[test]
    fn invalid_metadata_is_rejected_and_autoattach_is_explicitly_paused() {
        assert!(field(&json!({"id":""}), "id").is_err());
        assert!(valid_id(&"x".repeat(1025)).is_err());
        assert_eq!(autoattach(true)["waitForDebuggerOnStart"], true);
        assert_eq!(autoattach(false)["waitForDebuggerOnStart"], false);
    }

    #[tokio::test]
    async fn persistent_context_failure_closes_only_authorized_and_queued_descendants() {
        let (mut owner, _notices, log, _emit, server) = fixture("tracked").await;
        Arc::get_mut(&mut owner).unwrap().ownership =
            ScopeOwnership::TrackedTargets(vec!["initial-target".into()]);
        owner.contain_with_events().await.unwrap();
        let outcome = owner.cleanup_outcome().unwrap();
        assert!(!outcome.isolated_context_disposed);
        assert_eq!(
            outcome.closed_targets,
            vec!["initial-target", "queued-popup"]
        );
        assert!(log
            .lock()
            .unwrap()
            .iter()
            .all(|entry| entry["method"] != "Target.disposeBrowserContext"
                && entry["method"] != "Browser.close"));
        server.abort();
    }
    #[tokio::test]
    async fn persistent_same_context_unrelated_page_is_foreign() {
        let (mut owner, _notices, log, _emit, server) = fixture("normal").await;
        Arc::get_mut(&mut owner).unwrap().ownership =
            ScopeOwnership::TrackedTargets(vec!["authorized".into()]);
        owner
            .attached(attach(
                "owned-context",
                "unrelated",
                "unrelated-session",
                "page",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(log.lock().unwrap()[0]["method"], "Target.detachFromTarget");
        assert!(owner.index.lock().unwrap().sessions.is_empty());
        server.abort();
    }
    #[tokio::test]
    async fn cancelled_drain_retains_supervisor_until_later_drain_proves_completion() {
        let (owner, _notices, _log, _emit, server) = fixture("normal").await;
        let (release, waiting) = tokio::sync::oneshot::channel::<()>();
        *owner.supervisor.lock().await = Some(tokio::spawn(async move {
            waiting.await.unwrap();
            Ok(())
        }));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), owner.drain())
                .await
                .is_err()
        );
        assert!(owner.supervisor.lock().await.is_some());
        release.send(()).unwrap();
        owner.drain().await.unwrap();
        assert!(owner.supervisor.lock().await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn popup_runtime_ack_precedes_every_script_and_failure_never_resumes() {
        for fail in [false, true] {
            let (owner, _notices, log, emit, server) = fixture("popup-runtime-held").await;
            owner
                .enroll_existing("initial-target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            let initial = owner.index.lock().unwrap().sessions["initial"].clone();
            let lease = owner.lease(&initial).unwrap();
            for ordinal in 0..4 {
                owner
                    .page
                    .execute(
                        &lease,
                        &["initial".into()],
                        &owner.operation(),
                        "context.init-script",
                        &json!({"source":format!("window.syntheticTrail.push({ordinal})")}),
                    )
                    .await
                    .unwrap();
            }
            log.lock().unwrap().clear();
            let task_owner = owner.clone();
            let task = tokio::spawn(async move {
                task_owner
                    .attached(attach(
                        "owned-context",
                        "popup",
                        "popup-session",
                        "page",
                        None,
                    ))
                    .await
            });
            let runtime = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(request) = log
                        .lock()
                        .unwrap()
                        .iter()
                        .find(|request| request["method"] == "Runtime.enable")
                        .cloned()
                    {
                        break request;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(!task.is_finished());
            assert!(!log.lock().unwrap().iter().any(|request| matches!(
                request["method"].as_str(),
                Some("Page.addScriptToEvaluateOnNewDocument" | "Runtime.runIfWaitingForDebugger")
            )));
            let response = if fail {
                json!({"id":runtime["id"],"error":{"code":-32000,"message":"synthetic runtime refusal"}})
            } else {
                json!({"id":runtime["id"],"result":{}})
            };
            emit.send(response).await.unwrap();
            let result = task.await.unwrap();
            let commands = log.lock().unwrap().clone();
            let scripts: Vec<_> = commands
                .iter()
                .filter(|request| request["method"] == "Page.addScriptToEvaluateOnNewDocument")
                .collect();
            if fail {
                assert!(result.is_err());
                assert!(scripts.is_empty());
                assert!(!commands
                    .iter()
                    .any(|request| request["method"] == "Runtime.runIfWaitingForDebugger"));
            } else {
                result.unwrap();
                assert_eq!(scripts.len(), 4);
                for (ordinal, request) in scripts.iter().enumerate() {
                    assert_eq!(
                        request["params"]["source"],
                        format!("window.syntheticTrail.push({ordinal})")
                    );
                }
                let runtime_pos = commands
                    .iter()
                    .position(|request| request["method"] == "Runtime.enable")
                    .unwrap();
                let resume_pos = commands
                    .iter()
                    .position(|request| request["method"] == "Runtime.runIfWaitingForDebugger")
                    .unwrap();
                for (position, request) in commands.iter().enumerate() {
                    if request["method"] == "Page.addScriptToEvaluateOnNewDocument" {
                        assert!(runtime_pos < position && position < resume_pos);
                    }
                }
            }
            drop(lease);
            let _ = owner.close().await;
            server.abort();
        }
    }

    #[tokio::test]
    async fn protected_registration_policy_uses_single_context_init_inventory() {
        let (mut owner, _notices, log, _emit, server) = fixture("normal").await;
        Arc::get_mut(&mut owner)
            .unwrap()
            .config
            .block_service_workers = true;
        owner
            .enroll_existing("target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner
            .attached(attach(
                "owned-context",
                "popup",
                "popup-session",
                "page",
                None,
            ))
            .await
            .unwrap();
        let commands = log.lock().unwrap().clone();
        let scripts: Vec<_> = commands
            .iter()
            .filter(|entry| entry["method"] == "Page.addScriptToEvaluateOnNewDocument")
            .collect();
        assert_eq!(scripts.len(), 2);
        assert_eq!(
            scripts[0]["params"]["source"],
            scripts[1]["params"]["source"]
        );
        assert!(scripts[0]["params"]["source"]
            .as_str()
            .unwrap()
            .contains("ServiceWorkerContainer.prototype.register"));
        assert_eq!(owner.page.config_revision().unwrap(), 1);
        owner.close().await.unwrap();
        owner.network.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn network_policy_update_is_acknowledged_for_current_and_future_sessions() {
        use super::super::client_network::NetworkPolicy;
        let (owner, _notices, log, _emit, server) = fixture("normal").await;
        owner
            .enroll_existing("target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        assert!(!log
            .lock()
            .unwrap()
            .iter()
            .any(|entry| entry["method"] == "Network.setBypassServiceWorker"
                && entry["params"]["bypass"] == true));
        let config_gate = owner.config_gate();
        let guard = config_gate.lock().await;
        owner
            .network
            .update_policy(
                NetworkPolicy {
                    bypass_service_worker: true,
                },
                &owner.operation(),
            )
            .await
            .unwrap();
        drop(guard);
        assert!(log
            .lock()
            .unwrap()
            .iter()
            .any(|entry| entry["method"] == "Network.setBypassServiceWorker"
                && entry["sessionId"] == "initial"
                && entry["params"]["bypass"] == true));
        owner
            .attached(attach(
                "owned-context",
                "popup",
                "popup-session",
                "page",
                None,
            ))
            .await
            .unwrap();
        assert!(log
            .lock()
            .unwrap()
            .iter()
            .any(|entry| entry["method"] == "Network.setBypassServiceWorker"
                && entry["sessionId"] == "popup-session"
                && entry["params"]["bypass"] == true));
        let count = log.lock().unwrap().len();
        let mut wrong = owner.operation();
        wrong.generation += 1;
        assert!(owner
            .network
            .update_policy(NetworkPolicy::default(), &wrong)
            .await
            .is_err());
        let mut cancelled = owner.operation();
        let (cancel, receiver) = watch::channel(CancelSignal::Requested);
        cancelled.cancellation = receiver;
        assert!(owner
            .network
            .update_policy(NetworkPolicy::default(), &cancelled)
            .await
            .is_err());
        assert_eq!(log.lock().unwrap().len(), count);
        drop(cancel);
        owner.close().await.unwrap();
        owner.network.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn normal_shutdown_retains_pauses_until_exact_containment_proof() {
        let (owner, _notices, log, _emit, server) = fixture("normal").await;
        owner
            .enroll_existing("target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner
            .attached(attach(
                "owned-context",
                "child-target",
                "child",
                "iframe",
                Some("initial"),
            ))
            .await
            .unwrap();
        owner.close().await.unwrap();
        assert!(!log
            .lock()
            .unwrap()
            .iter()
            .any(|entry| entry["method"] == "Target.setAutoAttach"
                && entry["params"]["autoAttach"] == false));
        let proof = owner.contain_owned_resources().await.unwrap();
        owner.release_after_containment(proof).await.unwrap();
        let commands = log.lock().unwrap().clone();
        let contained = commands
            .iter()
            .position(|entry| entry["method"] == "Target.disposeBrowserContext")
            .unwrap();
        let released = commands
            .iter()
            .position(|entry| {
                entry["method"] == "Target.setAutoAttach" && entry["params"]["autoAttach"] == false
            })
            .unwrap();
        assert!(contained < released);
        assert!(owner.cleanup_outcome().unwrap().owned_resources_contained);
        server.abort();
    }
    #[tokio::test]
    async fn cancelled_containment_retains_exact_ack_and_does_not_dispose_twice() {
        let (owner, _notices, log, _emit, server) = fixture("delayed-dispose").await;
        owner
            .enroll_existing("target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner.close().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(5), owner.contain_owned_resources())
                .await
                .is_err()
        );
        let proof = owner.contain_owned_resources().await.unwrap();
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|entry| entry["method"] == "Target.disposeBrowserContext")
                .count(),
            1
        );
        owner.release_after_containment(proof).await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn popup_opener_detach_does_not_prove_context_disposal() {
        for ack in ["success", "error", "missing"] {
            let (mut owner, _notices, log, emit, server) = fixture("popup-held-dispose").await;
            Arc::get_mut(&mut owner).unwrap().config.timezone_id = Some("UTC".into());
            owner
                .enroll_existing("initial-target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            owner.start(&owner.operation()).await.unwrap();
            let opener = owner.index.lock().unwrap().sessions["initial"].clone();
            let mut events = owner
                .client
                .subscribe_bounded_methods(
                    &["Target.attachedToTarget", "Test.disposalReplyBarrier"],
                    8,
                    8192,
                )
                .unwrap();
            let client = owner.client.clone();
            let evaluation = tokio::spawn(async move {
                client.send_command(
                    "Runtime.evaluate",
                    Some(json!({"expression":"window.open('https://synthetic.test/first')","returnByValue":true})),
                    Some("initial"),
                ).await
            });
            let attached = tokio::time::timeout(Duration::from_secs(2), events.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(attached.method, "Target.attachedToTarget");
            assert_eq!(attached.params["sessionId"], "popup-session");
            assert_eq!(attached.params["targetInfo"]["targetId"], "popup-target");
            assert_eq!(attached.params["targetInfo"]["openerId"], "initial-target");
            assert_eq!(
                attached.params["targetInfo"]["browserContextId"],
                "owned-context"
            );
            assert_eq!(attached.params["waitingForDebugger"], true);
            let error = tokio::time::timeout(Duration::from_secs(1), evaluation)
                .await
                .expect(
                    "exact opener detach must wake the raw evaluation before its command timeout",
                )
                .unwrap()
                .unwrap_err();
            assert_eq!(error, "CDP response channel closed");
            let dispose = log
                .lock()
                .unwrap()
                .iter()
                .find(|request| request["method"] == "Target.disposeBrowserContext")
                .cloned()
                .expect("failed popup initialization must request containment");
            assert_eq!(dispose["params"]["browserContextId"], "owned-context");
            let popup = owner.index.lock().unwrap().sessions["popup-session"].clone();
            assert_eq!(popup.target, "popup-target");
            assert!(popup.application && !popup.resumed);
            assert!(owner.sealed.load(Ordering::Acquire));
            assert!(owner.lease(&opener).is_err());
            let outcome = owner.cleanup_outcome().unwrap();
            assert!(!outcome.isolated_context_disposed);
            assert!(!outcome.owned_resources_contained);
            assert!(!outcome.autoattach_disabled);

            // Retain the real drain and proof futures. A failed raw waiter must
            // not complete either while the exact disposal reply is withheld.
            let drain = owner.drain();
            tokio::pin!(drain);
            assert!(futures_util::poll!(&mut drain).is_pending());
            let containment = owner.contain_owned_resources();
            tokio::pin!(containment);
            assert!(futures_util::poll!(&mut containment).is_pending());
            emit.send(json!({"id":dispose["id"].as_u64().unwrap() + 1_000_000,"result":{}}))
                .await
                .unwrap();
            emit.send(json!({"method":"Test.disposalReplyBarrier","params":{}}))
                .await
                .unwrap();
            // Ordered read-side barrier proves the wrong ACK was consumed;
            // neither elapsed time nor sending it is acknowledgment evidence.
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), events.recv())
                    .await
                    .unwrap()
                    .unwrap()
                    .method,
                "Test.disposalReplyBarrier"
            );
            assert!(futures_util::poll!(&mut drain).is_pending());
            assert!(futures_util::poll!(&mut containment).is_pending());
            let outcome = owner.cleanup_outcome().unwrap();
            assert!(!outcome.isolated_context_disposed);
            assert!(!outcome.owned_resources_contained);
            assert!(!outcome.autoattach_disabled);
            assert!(!log
                .lock()
                .unwrap()
                .iter()
                .any(|request| request["method"] == "Target.setAutoAttach"
                    && request["params"]["autoAttach"] == false));

            match ack {
                "success" => emit.send(json!({"id":dispose["id"],"result":{}})).await.unwrap(),
                "error" => emit.send(json!({"id":dispose["id"],"error":{"code":-32000,"message":"synthetic disposal rejection"}})).await.unwrap(),
                "missing" => {},
                _ => unreachable!(),
            }
            assert!(tokio::time::timeout(Duration::from_secs(3), &mut drain)
                .await
                .expect("disposal error or missing ACK must settle fail-closed")
                .is_err());
            let proof = tokio::time::timeout(Duration::from_secs(1), &mut containment)
                .await
                .expect("proof must settle after the retained drain");
            if ack == "success" {
                let proof = proof.unwrap();
                assert!(Arc::ptr_eq(&proof.registry, &owner.targets));
                assert_eq!(proof.identity_scope, "owned-scope");
                assert_eq!(proof.generation, owner.generation);
                let outcome = owner.cleanup_outcome().unwrap();
                assert!(outcome.isolated_context_disposed && outcome.owned_resources_contained);
                assert!(!outcome.autoattach_disabled);
                owner.release_after_containment(proof).await.unwrap();
                assert!(owner.cleanup_outcome().unwrap().autoattach_disabled);
            } else {
                assert!(matches!(proof, Err(ProtocolError::CleanupFailed)));
                let outcome = owner.cleanup_outcome().unwrap();
                assert!(!outcome.isolated_context_disposed);
                assert!(!outcome.owned_resources_contained);
                assert!(!outcome.autoattach_disabled);
                assert!(owner.contain_owned_resources().await.is_err());
            }
            // Even an exact successful cleanup ACK authorizes only retirement,
            // never reuse of this failed application's admission or popup pause.
            assert!(owner.sealed.load(Ordering::Acquire));
            assert!(owner.lease(&opener).is_err());
            assert!(owner
                .enroll_existing(
                    "replacement",
                    "replacement-session",
                    "page",
                    &owner.operation()
                )
                .await
                .is_err());
            let commands = log.lock().unwrap().clone();
            assert_eq!(
                commands
                    .iter()
                    .filter(|request| request["method"] == "Target.disposeBrowserContext")
                    .count(),
                1
            );
            assert_eq!(
                commands
                    .iter()
                    .filter(|request| request["method"] == "Target.setAutoAttach"
                        && request["params"]["autoAttach"] == false)
                    .count(),
                usize::from(ack == "success")
            );
            assert!(!commands
                .iter()
                .any(|request| request["sessionId"] == "popup-session"
                    && matches!(
                        request["method"].as_str(),
                        Some("Runtime.runIfWaitingForDebugger" | "Fetch.continueRequest")
                    )));
            assert!(owner
                .client
                .send_command("Browser.getVersion", Some(json!({})), None)
                .await
                .is_ok());
            owner.client.close().await;
            server.abort();
        }
    }
    #[tokio::test]
    async fn containment_proof_cannot_release_another_scope() {
        let (owner, _notices, _log, _emit, server) = fixture("normal").await;
        owner.close().await.unwrap();
        let proof = owner.contain_owned_resources().await.unwrap();
        let (other, _notices2, log2, _emit2, server2) = fixture("normal").await;
        other.close().await.unwrap();
        assert_eq!(
            other.release_after_containment(proof).await,
            Err(ProtocolError::StaleScope)
        );
        assert!(log2.lock().unwrap().is_empty());
        server.abort();
        server2.abort();
    }
    #[tokio::test]
    async fn tracked_cleanup_reconciles_popup_created_after_initial_inventory() {
        let (mut owner, _notices, log, _emit, server) = fixture("late-popup").await;
        Arc::get_mut(&mut owner).unwrap().ownership =
            ScopeOwnership::TrackedTargets(vec!["initial-target".into()]);
        owner.close().await.unwrap();
        let proof = owner.contain_owned_resources().await.unwrap();
        assert_eq!(
            owner.cleanup_outcome().unwrap().closed_targets,
            vec!["initial-target", "queued-popup"]
        );
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|entry| entry["method"] == "Target.getTargets")
                .count(),
            3
        );
        owner.release_after_containment(proof).await.unwrap();
        server.abort();
    }
    #[tokio::test]
    #[ignore = "requires hosted Chromium: borrowed observed-origin export and temporary-page lifetime"]
    async fn e2e_borrowed_capture_observed_origins_and_native_bootstrap_lifetime() {
        use super::super::cdp::chrome::{launch_chrome, LaunchOptions};
        use super::super::client_state::{export_state, NativeStateContext};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let http = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 8192];
                let _ = stream.read(&mut request).await;
                let body = "<html><body>synthetic borrowed capture</body></html>";
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        let mut chrome = launch_chrome(&LaunchOptions {
            headless: true,
            ..Default::default()
        })
        .unwrap();
        let host = Arc::new(CdpClient::connect(&chrome.ws_url).await.unwrap());
        let context = host
            .send_command("Target.createBrowserContext", Some(json!({})), None)
            .await
            .unwrap()["browserContextId"]
            .as_str()
            .unwrap()
            .to_owned();
        let target = host
            .send_command(
                "Target.createTarget",
                Some(json!({"browserContextId":context,"url":"about:blank"})),
                None,
            )
            .await
            .unwrap()["targetId"]
            .as_str()
            .unwrap()
            .to_owned();
        let unrelated = host
            .send_command(
                "Target.createTarget",
                Some(json!({"browserContextId":context,"url":"about:blank"})),
                None,
            )
            .await
            .unwrap()["targetId"]
            .as_str()
            .unwrap()
            .to_owned();
        let host_session = host
            .send_command(
                "Target.attachToTarget",
                Some(json!({"targetId":target,"flatten":true})),
                None,
            )
            .await
            .unwrap()["sessionId"]
            .as_str()
            .unwrap()
            .to_owned();
        host.send_command("Page.enable", Some(json!({})), Some(&host_session))
            .await
            .unwrap();
        host.send_command(
            "Page.navigate",
            Some(json!({"url":format!("{origin}/before-attachment")})),
            Some(&host_session),
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let result = host.send_command("Runtime.evaluate",Some(json!({"expression":format!("location.origin === {} && document.readyState === 'complete'",serde_json::to_string(&origin).unwrap()),"returnByValue":true})),Some(&host_session)).await.unwrap();
                if result["result"]["value"]==true { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        host.send_command("Runtime.evaluate",Some(json!({"expression":"localStorage.setItem('synthetic','retained')","returnByValue":true})),Some(&host_session)).await.unwrap();
        let client = Arc::new(CdpClient::connect(&chrome.ws_url).await.unwrap());
        let session = client
            .send_command(
                "Target.attachToTarget",
                Some(json!({"targetId":target,"flatten":true})),
                None,
            )
            .await
            .unwrap()["sessionId"]
            .as_str()
            .unwrap()
            .to_owned();
        let (mut owner, mut notices, broker) = coordinator(
            client.clone(),
            &context,
            "borrowed-capture-hosted",
            &session,
        );
        Arc::get_mut(&mut owner).unwrap().ownership =
            ScopeOwnership::BorrowedTargets(vec![target.clone()]);
        let policy = tokio::spawn(async move {
            while let Some(message) = notices.recv().await {
                if let ServerMessage::Event {
                    decision: Some(decision),
                    ..
                } = message
                {
                    broker
                        .resolve(
                            1,
                            &decision.token,
                            super::super::client_protocol::Decision::Continue {
                                overrides: Default::default(),
                            },
                        )
                        .unwrap();
                }
            }
        });
        owner
            .enroll_existing(&target, &session, "page", &owner.operation())
            .await
            .unwrap();
        owner.start(&owner.operation()).await.unwrap();
        owner.attest_capture(&owner.operation()).await.unwrap();
        let initial_origins = owner.page.visited_origins().unwrap();
        assert!(
            initial_origins.is_empty(),
            "initial loaded profile must not become observed history"
        );
        let initial = export_state(
            &NativeStateContext {
                client: &client,
                context_id: &context,
                targets: &owner.targets,
                origins: &initial_origins,
                origins_complete: true,
            },
            &owner.operation(),
        )
        .await
        .unwrap();
        assert!(initial.origins.is_empty());
        let entry = owner.index.lock().unwrap().sessions[&session].clone();
        let page = owner.lease(&entry).unwrap();
        owner
            .page
            .execute(
                &page,
                std::slice::from_ref(&session),
                &owner.operation(),
                "page.navigate",
                &json!({"url":format!("{origin}/observed"),"waitUntil":"load"}),
            )
            .await
            .unwrap();
        drop(page);
        let before = owner.attest_capture(&owner.operation()).await.unwrap();
        let origins = owner.page.visited_origins().unwrap();
        assert_eq!(origins, vec![origin.clone()]);
        let exported = export_state(
            &NativeStateContext {
                client: &client,
                context_id: &context,
                targets: &owner.targets,
                origins: &origins,
                origins_complete: true,
            },
            &owner.operation(),
        )
        .await
        .unwrap();
        owner
            .verify_capture_attestation(&before, &owner.operation())
            .await
            .unwrap();
        let encoded = serde_json::to_value(&exported).unwrap();
        assert!(
            encoded.to_string().contains("retained"),
            "observed origin storage was not exported"
        );
        let inventory = host
            .send_command("Target.getTargets", Some(json!({})), None)
            .await
            .unwrap();
        let pages = inventory["targetInfos"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|info| info["browserContextId"] == context && info["type"] == "page")
            .collect::<Vec<_>>();
        assert_eq!(pages.len(), 2, "temporary export page must close itself");
        for expected in [&target, &unrelated] {
            assert!(pages
                .iter()
                .any(|info| info["targetId"].as_str() == Some(expected.as_str())));
        }
        owner.close().await.unwrap();
        let contained = owner.contain_owned_resources().await.unwrap();
        owner.release_after_containment(contained).await.unwrap();
        let alive = host
            .send_command(
                "Runtime.evaluate",
                Some(
                    json!({"expression":"localStorage.getItem('synthetic')","returnByValue":true}),
                ),
                Some(&host_session),
            )
            .await
            .unwrap();
        assert_eq!(alive["result"]["value"], "retained");
        policy.abort();
        http.abort();
        client.close().await;
        host.close().await;
        chrome.kill();
    }

    #[tokio::test]
    #[ignore = "requires hosted Chromium: borrowed host survives exact detach and future scripts are removed"]
    async fn e2e_borrowed_host_survives_detach_and_keeps_unrelated_page() {
        use super::super::cdp::chrome::{launch_chrome, LaunchOptions};
        let mut chrome = launch_chrome(&LaunchOptions {
            headless: true,
            ..Default::default()
        })
        .unwrap();
        let host = Arc::new(CdpClient::connect(&chrome.ws_url).await.unwrap());
        let client = Arc::new(CdpClient::connect(&chrome.ws_url).await.unwrap());
        let context = host
            .send_command("Target.createBrowserContext", Some(json!({})), None)
            .await
            .unwrap()["browserContextId"]
            .as_str()
            .unwrap()
            .to_owned();
        let target = host
            .send_command(
                "Target.createTarget",
                Some(json!({"browserContextId":context,"url":"about:blank"})),
                None,
            )
            .await
            .unwrap()["targetId"]
            .as_str()
            .unwrap()
            .to_owned();
        let unrelated = host
            .send_command(
                "Target.createTarget",
                Some(json!({"browserContextId":context,"url":"about:blank"})),
                None,
            )
            .await
            .unwrap()["targetId"]
            .as_str()
            .unwrap()
            .to_owned();
        let host_session = host
            .send_command(
                "Target.attachToTarget",
                Some(json!({"targetId":target,"flatten":true})),
                None,
            )
            .await
            .unwrap()["sessionId"]
            .as_str()
            .unwrap()
            .to_owned();
        let session = client
            .send_command(
                "Target.attachToTarget",
                Some(json!({"targetId":target,"flatten":true})),
                None,
            )
            .await
            .unwrap()["sessionId"]
            .as_str()
            .unwrap()
            .to_owned();
        let (mut owner, _notices, _broker) =
            coordinator(client.clone(), &context, "borrowed-hosted", &session);
        Arc::get_mut(&mut owner).unwrap().ownership =
            ScopeOwnership::BorrowedTargets(vec![target.clone()]);
        owner
            .enroll_existing(&target, &session, "page", &owner.operation())
            .await
            .unwrap();
        let entry = owner.index.lock().unwrap().sessions[&session].clone();
        let lease = owner.lease(&entry).unwrap();
        owner
            .page
            .execute(
                &lease,
                std::slice::from_ref(&session),
                &owner.operation(),
                "context.init-script",
                &json!({"source":"globalThis.__borrowed_test = true"}),
            )
            .await
            .unwrap();
        drop(lease);
        owner.start(&owner.operation()).await.unwrap();
        owner.close().await.unwrap();
        // Arrives after the ordinary enrollment reader has stopped, so this
        // target is paused but unclassified in the retained retirement tap.
        let unclassified = host
            .send_command(
                "Target.createTarget",
                Some(json!({
                    "browserContextId":context,
                    "url":"data:text/html,<script>globalThis.hostUsableAfterDetach=true</script>"
                })),
                None,
            )
            .await
            .unwrap()["targetId"]
            .as_str()
            .unwrap()
            .to_owned();
        let proof = owner.contain_owned_resources().await.unwrap();
        owner.release_after_containment(proof).await.unwrap();
        let inventory = host
            .send_command("Target.getTargets", Some(json!({})), None)
            .await
            .unwrap();
        for expected in [&target, &unrelated, &unclassified] {
            assert!(inventory["targetInfos"]
                .as_array()
                .unwrap()
                .iter()
                .any(|info| info["targetId"].as_str() == Some(expected.as_str())));
        }
        let unknown_session = host
            .send_command(
                "Target.attachToTarget",
                Some(json!({
                    "targetId":unclassified,"flatten":true
                })),
                None,
            )
            .await
            .unwrap()["sessionId"]
            .as_str()
            .unwrap()
            .to_owned();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let result=host.send_command("Runtime.evaluate",Some(json!({
                    "expression":"globalThis.hostUsableAfterDetach === true","returnByValue":true
                })),Some(&unknown_session)).await.unwrap();
                if result["result"]["value"] == true {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("unclassified host target remained paused after detach");
        host.send_command(
            "Page.navigate",
            Some(json!({"url":"data:text/html,<title>host-still-alive</title>"})),
            Some(&host_session),
        )
        .await
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let result=host.send_command("Runtime.evaluate",Some(json!({"expression":"document.title === 'host-still-alive' && typeof globalThis.__borrowed_test === 'undefined'","returnByValue":true})),Some(&host_session)).await.unwrap();
            if result["result"]["value"] == true {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "host stopped or future init registration survived detach"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        host.send_command(
            "Target.disposeBrowserContext",
            Some(json!({"browserContextId":context})),
            None,
        )
        .await
        .unwrap();
        chrome.kill();
    }
    #[derive(Default)]
    struct ForeignDefaultContext {
        current: Option<(i64, String)>,
    }
    impl ForeignDefaultContext {
        fn apply(&mut self, event: &CdpEvent, session: &str, frame: &str) -> Result<(), String> {
            if event.method == "Target.detachedFromTarget"
                && event.params["sessionId"].as_str() == Some(session)
            {
                return Err("foreign session detached during readiness".into());
            }
            if event.session_id.as_deref() != Some(session) {
                return Ok(());
            }
            match event.method.as_str() {
                "Runtime.executionContextCreated" => {
                    let context = &event.params["context"];
                    if context["auxData"]["isDefault"] != true
                        || context["auxData"]["frameId"].as_str() != Some(frame)
                    {
                        return Ok(());
                    }
                    let id = context["id"]
                        .as_i64()
                        .filter(|id| *id > 0)
                        .ok_or("foreign default context omitted its numeric identity")?;
                    let unique = context["uniqueId"]
                        .as_str()
                        .filter(|id| !id.is_empty())
                        .ok_or("foreign default context omitted its unique identity")?;
                    self.current = Some((id, unique.to_owned()));
                }
                "Runtime.executionContextDestroyed" => {
                    if self.current.as_ref().is_some_and(|(id, unique)| {
                        // An old destruction must not erase a new incarnation
                        // reusing the numeric ID. Without a unique ID, discard
                        // conservatively and await another authoritative event.
                        match event.params["executionContextUniqueId"].as_str() {
                            Some(destroyed) => destroyed == unique.as_str(),
                            None => event.params["executionContextId"].as_i64() == Some(*id),
                        }
                    }) {
                        self.current = None;
                    }
                }
                "Runtime.executionContextsCleared" => self.current = None,
                "Page.frameNavigated" if event.params["frame"]["id"].as_str() == Some(frame) => {
                    return Err("foreign document changed during context readiness".into());
                }
                "Page.frameDetached" if event.params["frameId"].as_str() == Some(frame) => {
                    return Err("foreign main frame detached during readiness".into());
                }
                _ => {}
            }
            Ok(())
        }
    }

    struct ForeignDocument {
        frame: String,
        loader: String,
        url: String,
    }
    impl ForeignDocument {
        fn from_frame(frame: &Value) -> Result<Self, String> {
            let required = |key: &str| {
                frame[key]
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| "foreign document identity was incomplete".to_owned())
            };
            Ok(Self {
                frame: required("id")?,
                loader: required("loaderId")?,
                url: required("url")?,
            })
        }
        fn reconcile(
            &self,
            context: &mut ForeignDefaultContext,
            event: &CdpEvent,
            session: &str,
        ) -> Result<(), String> {
            if event.session_id.as_deref() == Some(session) && event.method == "Page.frameNavigated"
            {
                let frame = &event.params["frame"];
                if frame.get("parentId").is_none()
                    || frame["id"].as_str() == Some(self.frame.as_str())
                {
                    if frame["id"].as_str() != Some(self.frame.as_str())
                        || frame["loaderId"].as_str() != Some(self.loader.as_str())
                        || frame["url"].as_str() != Some(self.url.as_str())
                    {
                        return Err("foreign document changed across readiness snapshot".into());
                    }
                    // A matching event received after the pre-query fence can
                    // describe the very document returned by the snapshot.
                    return Ok(());
                }
            }
            context.apply(event, session, &self.frame)
        }
    }
    type ForeignTreeAckHook = (
        tokio::sync::oneshot::Sender<BoundedEventWatermark>,
        tokio::sync::oneshot::Receiver<()>,
    );

    // A fresh foreign observer session has no Runtime domain enabled. Attach
    // ACK alone proves neither navigation commit nor a default execution realm.
    // This helper owns no enrollment/configuration and never resumes the target.
    async fn foreign_first_script_after_document_ready(
        client: &CdpClient,
        session: &str,
        expected_url: &str,
    ) -> Result<Value, String> {
        foreign_first_script_with_tree_ack_hook(client, session, expected_url, None).await
    }
    // The hook exists solely to force the response/event race in the TCP test.
    async fn foreign_first_script_with_tree_ack_hook(
        client: &CdpClient,
        session: &str,
        expected_url: &str,
        tree_ack_hook: Option<ForeignTreeAckHook>,
    ) -> Result<Value, String> {
        let mut events = client.subscribe_bounded_methods(
            &[
                "Page.frameNavigated",
                "Page.frameDetached",
                "Target.detachedFromTarget",
                "Runtime.executionContextCreated",
                "Runtime.executionContextDestroyed",
                "Runtime.executionContextsCleared",
            ],
            64,
            65536,
        )?;
        let watermark = events.watermark();
        client
            .send_command("Page.enable", Some(json!({})), Some(session))
            .await?;
        // Fence BEFORE issuing the snapshot. Only earlier events can be
        // superseded by that query. Events received after its ACK are never
        // silently absorbed into the snapshot's document identity.
        let mut committed_through = watermark.received()?;
        let tree = client
            .send_command("Page.getFrameTree", Some(json!({})), Some(session))
            .await?;
        if let Some((acknowledged, release)) = tree_ack_hook {
            acknowledged
                .send(watermark.clone())
                .map_err(|_| "tree ACK observer ended")?;
            release.await.map_err(|_| "tree ACK release ended")?;
        }
        let frame = tree["frameTree"]["frame"]["id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or("foreign main frame was unavailable")?
            .to_owned();
        let mut consumed = 0;
        let mut document = if tree["frameTree"]["frame"]["url"].as_str() == Some(expected_url) {
            Some(ForeignDocument::from_frame(&tree["frameTree"]["frame"])?)
        } else {
            None
        };
        while document.is_none() {
            let event = events.recv().await?;
            consumed = event.sequence();
            if consumed <= committed_through {
                continue;
            }
            if event.method == "Target.detachedFromTarget"
                && event.params["sessionId"].as_str() == Some(session)
            {
                return Err("foreign session detached before document commit".into());
            }
            if event.session_id.as_deref() != Some(session) {
                continue;
            }
            if event.method == "Page.frameDetached"
                && event.params["frameId"].as_str() == Some(frame.as_str())
            {
                return Err("foreign main frame detached before document commit".into());
            }
            if event.method == "Page.frameNavigated"
                && event.params["frame"]["id"].as_str() == Some(frame.as_str())
                && event.params["frame"].get("parentId").is_none()
                && event.params["frame"]["url"].as_str() == Some(expected_url)
            {
                document = Some(ForeignDocument::from_frame(&event.params["frame"])?);
                // This exact event, not a later sampled watermark, is the new
                // document proof. Any queued successor still needs checking.
                committed_through = consumed;
            }
        }
        let document = document.ok_or("foreign document commit was unavailable")?;
        // Runtime replay begins after document proof. Reconcile every later
        // main-frame event against the exact frame/loader/URL tuple, including
        // events queued between the frame-tree ACK and this task resuming.
        client
            .send_command("Runtime.enable", Some(json!({})), Some(session))
            .await?;
        let mut context = ForeignDefaultContext::default();
        let unique = loop {
            // Drain through reader admission after the enable ACK, including
            // any queued destruction/replacement, before selecting a context.
            let received = watermark.received()?;
            while consumed < received {
                let event = events.recv().await?;
                consumed = event.sequence();
                if consumed > committed_through {
                    document.reconcile(&mut context, &event, session)?;
                }
            }
            if let Some((_, unique)) = &context.current {
                break unique.clone();
            }
            let event = events.recv().await?;
            consumed = event.sequence();
            if consumed > committed_through {
                document.reconcile(&mut context, &event, session)?;
            }
        };
        // DOMContentLoaded settles the first inline script without polling its
        // value. Unique identity forbids silently evaluating in a replacement
        // realm; destruction during evaluation remains an ordinary test failure.
        client.send_command("Runtime.evaluate", Some(json!({
            "expression":"(async () => { if (document.readyState === 'loading') await new Promise(resolve => document.addEventListener('DOMContentLoaded', resolve, {once: true})); return [window.foreignRan, typeof window.ownedSyntheticInit]; })()",
            "uniqueContextId":unique, "returnByValue":true, "awaitPromise":true,
        })), Some(session)).await
    }

    #[test]
    fn foreign_context_readiness_requires_exact_identity_and_tracks_replacement() {
        let created = |session: &str, frame: &str, is_default: bool, unique: &str| CdpEvent {
            method: "Runtime.executionContextCreated".into(),
            session_id: Some(session.into()),
            params: json!({"context":{"id":7,"uniqueId":unique,"auxData":{"frameId":frame,"isDefault":is_default}}}),
        };
        let mut state = ForeignDefaultContext::default();
        for event in [
            created("other", "main", true, "wrong-session"),
            created("foreign", "child", true, "wrong-frame"),
            created("foreign", "main", false, "isolated"),
        ] {
            state.apply(&event, "foreign", "main").unwrap();
            assert!(state.current.is_none());
        }
        state
            .apply(&created("foreign", "main", true, "old"), "foreign", "main")
            .unwrap();
        state
            .apply(
                &CdpEvent {
                    method: "Runtime.executionContextsCleared".into(),
                    session_id: Some("foreign".into()),
                    params: json!({}),
                },
                "foreign",
                "main",
            )
            .unwrap();
        assert!(state.current.is_none());
        state
            .apply(&created("foreign", "main", true, "new"), "foreign", "main")
            .unwrap();
        let mut destroyed = CdpEvent {
            method: "Runtime.executionContextDestroyed".into(),
            session_id: Some("foreign".into()),
            params: json!({"executionContextId":7,"executionContextUniqueId":"old"}),
        };
        state.apply(&destroyed, "foreign", "main").unwrap();
        assert_eq!(state.current, Some((7, "new".into())));
        destroyed.params["executionContextUniqueId"] = json!("new");
        state.apply(&destroyed, "foreign", "main").unwrap();
        assert!(state.current.is_none());
        assert!(state
            .apply(&created("foreign", "main", true, ""), "foreign", "main")
            .is_err());
        assert!(state
            .apply(
                &CdpEvent {
                    method: "Page.frameNavigated".into(),
                    session_id: Some("foreign".into()),
                    params: json!({"frame":{"id":"main"}})
                },
                "foreign",
                "main"
            )
            .is_err());
    }

    #[tokio::test]
    async fn foreign_first_script_waits_for_document_and_exact_context_ack() {
        for (committed_in_snapshot, mode) in [
            (false, "replace-before-ack"),
            (true, "replace-before-ack"),
            (true, "replace-after-ack"),
            (true, "destroyed"),
            (true, "enable-error"),
            (true, "evaluate-error"),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut methods = Vec::new();
                while let Some(Ok(Message::Text(text))) = socket.next().await {
                    let request: Value = serde_json::from_str(&text).unwrap();
                    let method = request["method"].as_str().unwrap();
                    assert_eq!(request["sessionId"], "foreign");
                    methods.push(method.to_owned());
                    if (mode == "enable-error" && method == "Runtime.enable")
                        || (mode == "evaluate-error" && method == "Runtime.evaluate")
                    {
                        socket.send(Message::Text(json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic readiness failure"}}).to_string())).await.unwrap();
                        return methods;
                    }
                    let result = match method {
                        "Page.enable" => json!({}),
                        "Page.getFrameTree" => {
                            json!({"frameTree":{"frame":{"id":"main","loaderId":"expected-loader","url":if committed_in_snapshot {"data:text/html,synthetic"} else {"about:blank"}}}})
                        }
                        "Runtime.enable" => {
                            for event in [
                                json!({"method":"Runtime.executionContextCreated","sessionId":"foreign","params":{"context":{"id":7,"uniqueId":"old","auxData":{"frameId":"main","isDefault":true}}}}),
                                json!({"method":"Runtime.executionContextDestroyed","sessionId":"foreign","params":{"executionContextId":7,"executionContextUniqueId":"old"}}),
                            ] {
                                socket.send(Message::Text(event.to_string())).await.unwrap();
                            }
                            if !matches!(mode, "replace-after-ack" | "destroyed") {
                                socket.send(Message::Text(json!({"method":"Runtime.executionContextCreated","sessionId":"foreign","params":{"context":{"id":7,"uniqueId":"replacement","auxData":{"frameId":"main","isDefault":true}}}}).to_string())).await.unwrap();
                            }
                            json!({})
                        }
                        "Runtime.evaluate" => {
                            assert_eq!(request["params"]["uniqueContextId"], "replacement");
                            assert!(request["params"].get("contextId").is_none());
                            assert_eq!(request["params"]["awaitPromise"], true);
                            assert!(request["params"]["expression"]
                                .as_str()
                                .unwrap()
                                .contains("DOMContentLoaded"));
                            json!({"result":{"value":[73,"undefined"]}})
                        }
                        _ => panic!("unexpected foreign readiness method"),
                    };
                    socket
                        .send(Message::Text(
                            json!({"id":request["id"],"result":result}).to_string(),
                        ))
                        .await
                        .unwrap();
                    if method == "Runtime.enable" {
                        if mode == "replace-after-ack" {
                            socket.send(Message::Text(json!({"method":"Runtime.executionContextCreated","sessionId":"foreign","params":{"context":{"id":7,"uniqueId":"replacement","auxData":{"frameId":"main","isDefault":true}}}}).to_string())).await.unwrap();
                        } else if mode == "destroyed" {
                            socket.send(Message::Text(json!({"method":"Target.detachedFromTarget","params":{"sessionId":"foreign"}}).to_string())).await.unwrap();
                            return methods;
                        }
                    }
                    if method == "Page.getFrameTree" && !committed_in_snapshot {
                        for event in [
                            json!({"method":"Page.frameNavigated","sessionId":"other","params":{"frame":{"id":"main","loaderId":"expected-loader","url":"data:text/html,synthetic"}}}),
                            json!({"method":"Page.frameNavigated","sessionId":"foreign","params":{"frame":{"id":"child","parentId":"main","url":"data:text/html,synthetic"}}}),
                            json!({"method":"Page.frameNavigated","sessionId":"foreign","params":{"frame":{"id":"main","loaderId":"expected-loader","url":"data:text/html,synthetic"}}}),
                        ] {
                            socket.send(Message::Text(event.to_string())).await.unwrap();
                        }
                    }
                    if method == "Runtime.evaluate" {
                        return methods;
                    }
                }
                panic!("foreign readiness connection ended before evaluation");
            });
            let client = CdpClient::connect(&url).await.unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                foreign_first_script_after_document_ready(
                    &client,
                    "foreign",
                    "data:text/html,synthetic",
                ),
            )
            .await
            .unwrap();
            if matches!(mode, "enable-error" | "evaluate-error" | "destroyed") {
                assert!(result.is_err(), "{mode}");
            } else {
                assert_eq!(result.unwrap()["result"]["value"], json!([73, "undefined"]));
            }
            let mut expected = vec!["Page.enable", "Page.getFrameTree", "Runtime.enable"];
            if !matches!(mode, "enable-error" | "destroyed") {
                expected.push("Runtime.evaluate");
            }
            assert_eq!(server.await.unwrap(), expected, "{mode}");
            client.close().await;
        }
    }

    #[tokio::test]
    async fn foreign_first_script_does_not_swallow_navigation_after_tree_ack() {
        for mode in [
            "same-document",
            "different-url",
            "same-url-new-loader",
            "detached",
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let (inject, injected) = tokio::sync::oneshot::channel::<Value>();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut injection = Some(injected);
                let mut methods = Vec::new();
                while let Some(Ok(Message::Text(text))) = socket.next().await {
                    let request: Value = serde_json::from_str(&text).unwrap();
                    let method = request["method"].as_str().unwrap();
                    methods.push(method.to_owned());
                    assert_eq!(request["sessionId"], "foreign");
                    let result = match method {
                        "Page.enable" => json!({}),
                        "Page.getFrameTree" => json!({"frameTree":{"frame":{
                            "id":"main", "loaderId":"original-loader", "url":"data:text/html,synthetic"
                        }}}),
                        "Runtime.enable" => {
                            // This context has the same frame ID and could
                            // return the original assertion even in a new loader.
                            socket
                                .send(Message::Text(
                                    json!({"method":"Runtime.executionContextCreated",
                                        "sessionId":"foreign", "params":{"context":{"id":7,
                                            "uniqueId":"current-foreign-context",
                                            "auxData":{"frameId":"main","isDefault":true}}}
                                    })
                                    .to_string(),
                                ))
                                .await
                                .unwrap();
                            json!({})
                        }
                        "Runtime.evaluate" => {
                            assert_eq!(
                                request["params"]["uniqueContextId"],
                                "current-foreign-context"
                            );
                            json!({"result":{"value":[73,"undefined"]}})
                        }
                        _ => panic!("unexpected foreign readiness method"),
                    };
                    socket
                        .send(Message::Text(
                            json!({"id":request["id"],"result":result}).to_string(),
                        ))
                        .await
                        .unwrap();
                    if method == "Page.getFrameTree" {
                        let event = injection.take().unwrap().await.unwrap();
                        socket.send(Message::Text(event.to_string())).await.unwrap();
                    }
                    if method == "Runtime.evaluate" {
                        break;
                    }
                }
                methods
            });
            let client = Arc::new(CdpClient::connect(&url).await.unwrap());
            let (tree_acked, ack_observed) = tokio::sync::oneshot::channel();
            let (release, released) = tokio::sync::oneshot::channel();
            let observer = client.clone();
            let readiness = tokio::spawn(async move {
                tokio::time::timeout(
                    Duration::from_secs(2),
                    foreign_first_script_with_tree_ack_hook(
                        &observer,
                        "foreign",
                        "data:text/html,synthetic",
                        Some((tree_acked, released)),
                    ),
                )
                .await
                .unwrap()
            });
            // The helper has received the tree ACK but cannot progress. Force
            // a later event into its own retained reader lane before releasing
            // it. This deterministically exercises the old post-ACK watermark gap.
            let watermark = ack_observed.await.unwrap();
            let before = watermark.received().unwrap();
            let event = if mode == "detached" {
                json!({"method":"Page.frameDetached","sessionId":"foreign","params":{"frameId":"main"}})
            } else {
                json!({"method":"Page.frameNavigated","sessionId":"foreign","params":{"frame":{
                    "id":"main", "loaderId":if mode == "same-document" {"original-loader"} else {"replacement-loader"},
                    "url":if mode == "different-url" {"data:text/html,replacement"} else {"data:text/html,synthetic"}
                }}})
            };
            inject.send(event).unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while watermark.received().unwrap() == before {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            release.send(()).unwrap();
            let result = readiness.await.unwrap();
            if mode == "same-document" {
                assert_eq!(result.unwrap()["result"]["value"], json!([73, "undefined"]));
            } else {
                let error = result.unwrap_err();
                assert_eq!(
                    error,
                    if mode == "detached" {
                        "foreign main frame detached during readiness"
                    } else {
                        "foreign document changed across readiness snapshot"
                    },
                    "{mode}"
                );
            }
            client.close().await;
            let mut expected = vec!["Page.enable", "Page.getFrameTree", "Runtime.enable"];
            if mode == "same-document" {
                expected.push("Runtime.evaluate");
            }
            assert_eq!(server.await.unwrap(), expected, "{mode}");
        }
    }

    // Run only on the hosted Chromium gate; never substitute mock success for
    // two real browser contexts sharing the same host process.
    #[tokio::test]
    #[ignore = "requires hosted Chromium: two tenants and first-request initialization"]
    async fn e2e_enrollment_two_tenants_and_popup_first_script() {
        // Both modes are required: a policy at registry ordinal zero is
        // idempotent and can hide a first-registration-only double execution.
        for block_service_workers in [true, false] {
            hosted_popup_first_script(block_service_workers).await;
        }
    }
    async fn hosted_popup_first_script(block_service_workers: bool) {
        use super::super::cdp::chrome::{launch_chrome, LaunchOptions};
        let mut chrome = launch_chrome(&LaunchOptions {
            headless: true,
            ..Default::default()
        })
        .unwrap();
        let client = Arc::new(CdpClient::connect(&chrome.ws_url).await.unwrap());
        let foreign = Arc::new(CdpClient::connect(&chrome.ws_url).await.unwrap());
        let context = client
            .send_command(
                "Target.createBrowserContext",
                Some(json!({"disposeOnDetach":true})),
                None,
            )
            .await
            .unwrap()["browserContextId"]
            .as_str()
            .unwrap()
            .to_owned();
        let other = foreign
            .send_command(
                "Target.createBrowserContext",
                Some(json!({"disposeOnDetach":true})),
                None,
            )
            .await
            .unwrap()["browserContextId"]
            .as_str()
            .unwrap()
            .to_owned();
        let target = client
            .send_command(
                "Target.createTarget",
                Some(json!({"browserContextId":context,"url":"about:blank"})),
                None,
            )
            .await
            .unwrap()["targetId"]
            .as_str()
            .unwrap()
            .to_owned();
        let session = client
            .send_command(
                "Target.attachToTarget",
                Some(json!({"targetId":target,"flatten":true})),
                None,
            )
            .await
            .unwrap()["sessionId"]
            .as_str()
            .unwrap()
            .to_owned();
        let (mut owner, mut notices, broker) =
            coordinator(client.clone(), &context, "hosted-owned-scope", &session);
        Arc::get_mut(&mut owner)
            .unwrap()
            .config
            .block_service_workers = block_service_workers;
        let policy = tokio::spawn(async move {
            while let Some(message) = notices.recv().await {
                if let ServerMessage::Event {
                    decision: Some(decision),
                    ..
                } = message
                {
                    broker
                        .resolve(
                            1,
                            &decision.token,
                            super::super::client_protocol::Decision::Continue {
                                overrides: Default::default(),
                            },
                        )
                        .unwrap();
                }
            }
        });
        owner
            .enroll_existing(&target, &session, "page", &owner.operation())
            .await
            .unwrap();
        let initial = owner.index.lock().unwrap().sessions[&session].clone();
        let lease = owner.lease(&initial).unwrap();
        let op = owner.operation();
        // Add the witness to the FIRST script itself, not a later companion that
        // could miss a first-registration-only duplicate; preserve its =41 effect.
        // Document ordinals are local to a realm; CDP realm ordinals below distinguish
        // a new global from repeated execution in the same initial popup document.
        for ordinal in 0..4 {
            let source = format!(
                r#"(() => {{
                if ({ordinal} === 0) window.ownedSyntheticInit=41;
                const w = window.__nativePopupWitness ??= {{ documents: new WeakMap(), next: 0, trail: [] }};
                if (!w.documents.has(document)) w.documents.set(document, w.next++);
                const record = [{ordinal}, w.documents.get(document), document.URL === 'about:blank'];
                w.trail.push(record);
                console.debug('__native_popup_witness_v1__', ...record);
            }})();"#
            );
            owner
                .page
                .execute(
                    &lease,
                    std::slice::from_ref(&session),
                    &op,
                    "context.init-script",
                    &json!({"source":source}),
                )
                .await
                .unwrap();
        }
        let mut witness_events = client.subscribe_methods(&[
            "Runtime.executionContextCreated",
            "Runtime.executionContextDestroyed",
            "Runtime.executionContextsCleared",
            "Runtime.consoleAPICalled",
        ]);
        owner.start(&op).await.unwrap();
        // This foreign target is created AFTER global pause-and-filter starts.
        // Its first inline script must still run, without our init/config.
        let foreign_url = "data:text/html,<script>window.foreignRan=73</script>";
        let other_target = foreign
            .send_command(
                "Target.createTarget",
                Some(json!({"browserContextId":other,"url":foreign_url})),
                None,
            )
            .await
            .unwrap()["targetId"]
            .as_str()
            .unwrap()
            .to_owned();
        let other_session = foreign
            .send_command(
                "Target.attachToTarget",
                Some(json!({"targetId":other_target,"flatten":true})),
                None,
            )
            .await
            .unwrap()["sessionId"]
            .as_str()
            .unwrap()
            .to_owned();
        let first_script = tokio::time::timeout(
            Duration::from_secs(10),
            foreign_first_script_after_document_ready(&foreign, &other_session, foreign_url),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(first_script["result"]["value"], json!([73, "undefined"]));
        // An HTTP popup's first script records whether init ran before it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/popup", listener.local_addr().unwrap());
        let http = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                let body =
                    "<script>window.firstScriptSawInit=window.ownedSyntheticInit;window.popupBootWitness=window.__nativePopupWitness?.trail.slice()</script>synthetic";
                let response=format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body);
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        owner
            .page
            .execute(
                &lease,
                &[],
                &op,
                "page.evaluate",
                &json!({"source":"url=>{window.open(url);return true}","argument":url}),
            )
            .await
            .unwrap();
        let popup=tokio::time::timeout(Duration::from_secs(10),async {
            loop {
                let entries=owner.index.lock().unwrap().sessions.values().cloned().collect::<Vec<_>>();
                for entry in entries {
                    if entry.kind=="page" && entry.session!=session && entry.application {
                        let value=client.send_command("Runtime.evaluate",Some(json!({"expression":"window.firstScriptSawInit","returnByValue":true})),Some(&entry.session)).await.unwrap();
                        if value["result"]["value"]==41 {return entry;}
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        let boot = client
            .send_command(
                "Runtime.evaluate",
                Some(json!({
                    "expression":"window.popupBootWitness", "returnByValue":true
                })),
                Some(&popup.session),
            )
            .await
            .unwrap();
        let acks = owner
            .page
            .script_registration_ack_ordinals(&popup.session)
            .unwrap();
        // Correlate only this owned synthetic popup; never print source, URLs or CDP IDs.
        let mut realms = HashMap::new();
        let mut unique_realms = HashMap::new();
        let mut records = Vec::new();
        while let Ok(event) = witness_events.try_recv() {
            if event.session_id.as_deref() != Some(popup.session.as_str()) {
                continue;
            }
            if event.method == "Runtime.executionContextCreated" {
                let context = &event.params["context"];
                if context["auxData"]["isDefault"] == true {
                    if let (Some(id), Some(unique)) = (
                        context["id"].as_i64(),
                        context["uniqueId"].as_str().filter(|id| !id.is_empty()),
                    ) {
                        let next = unique_realms.len();
                        let ordinal = *unique_realms.entry(unique.to_owned()).or_insert(next);
                        realms.insert(id, ordinal);
                    }
                }
            } else if event.method == "Runtime.executionContextDestroyed" {
                if let Some(id) = event.params["executionContextId"].as_i64() {
                    realms.remove(&id);
                }
            } else if event.method == "Runtime.executionContextsCleared" {
                realms.clear();
            } else if event.method == "Runtime.consoleAPICalled" {
                let args = &event.params["args"];
                if args[0]["value"] == "__native_popup_witness_v1__" {
                    let realm = event.params["executionContextId"]
                        .as_i64()
                        .and_then(|id| realms.get(&id).copied());
                    records.push(json!({"realmOrdinal":realm,
                        "scriptOrdinal":args[1]["value"], "documentOrdinal":args[2]["value"],
                        "initialBlank":args[3]["value"]}));
                }
            }
        }
        eprintln!(
            "native popup synthetic witness: {}",
            json!({
                "blockServiceWorkers":block_service_workers, "registrationAckOrdinals":acks, "executions":records,
                "bootTrail":boot["result"]["value"]
            })
        );
        assert_eq!(
            boot["result"]["value"],
            json!([[0, 0, false], [1, 0, false], [2, 0, false], [3, 0, false]])
        );
        // Policy, then four scripts; script 0 retains the original =41 effect.
        assert_eq!(
            acks,
            (0..if block_service_workers { 5 } else { 4 }).collect::<Vec<usize>>()
        );
        assert_eq!(popup.root, popup.session);
        assert_eq!(*owner.active_root.lock().unwrap(), session);
        assert!(!owner
            .index
            .lock()
            .unwrap()
            .sessions
            .values()
            .any(|entry| entry.target == other_target));
        drop(lease);
        owner.close().await.unwrap();
        owner.network.close().await.unwrap();
        let proof = owner.contain_owned_resources().await.unwrap();
        owner.release_after_containment(proof).await.unwrap();
        // Coordinator close must not close the shared browser or foreign page.
        let still_live = foreign
            .send_command(
                "Runtime.evaluate",
                Some(json!({"expression":"window.foreignRan","returnByValue":true})),
                Some(&other_session),
            )
            .await
            .unwrap();
        assert_eq!(still_live["result"]["value"], 73);
        foreign
            .send_command(
                "Target.disposeBrowserContext",
                Some(json!({"browserContextId":other})),
                None,
            )
            .await
            .unwrap();
        policy.abort();
        http.abort();
        chrome.kill();
    }

    #[tokio::test]
    #[ignore = "known external CDP ingress limitation: deliberately red manual diagnostic, NOT a containment acceptance gate"]
    async fn diagnostic_external_direct_url_ingress_precedes_enrollment() {
        hosted_initial_request_failure("raw-direct-url").await;
    }
    #[tokio::test]
    #[ignore = "requires hosted Chromium: managed creation contains failed initialization before navigation"]
    async fn e2e_managed_blank_initialization_failure_prevents_navigation_request() {
        hosted_initial_request_failure("managed").await;
    }
    #[tokio::test]
    #[ignore = "requires hosted Chromium: window.open first request is held through failed popup configuration"]
    async fn e2e_popup_initial_request_is_contained_when_configuration_fails() {
        hosted_initial_request_failure("popup").await;
    }
    async fn hosted_initial_request_failure(mode: &str) {
        use super::super::cdp::chrome::{launch_chrome, LaunchOptions};
        use std::sync::atomic::AtomicUsize;
        let mut chrome = launch_chrome(&LaunchOptions {
            headless: true,
            ..Default::default()
        })
        .unwrap();
        let client = Arc::new(CdpClient::connect(&chrome.ws_url).await.unwrap());
        let version = client
            .send_command("Browser.getVersion", Some(json!({})), None)
            .await
            .unwrap();
        eprintln!(
            "containment mode={mode} product={} revision={}",
            version["product"]
                .as_str()
                .unwrap_or("")
                .chars()
                .take(100)
                .collect::<String>(),
            version["revision"]
                .as_str()
                .unwrap_or("")
                .chars()
                .take(100)
                .collect::<String>()
        );
        let context = client
            .send_command(
                "Target.createBrowserContext",
                Some(json!({"disposeOnDetach":true})),
                None,
            )
            .await
            .unwrap()["browserContextId"]
            .as_str()
            .unwrap()
            .to_owned();
        let trace: Arc<Mutex<Vec<String>>> = Arc::default();
        let trace_started = Instant::now();
        let mut events = client
            .subscribe_bounded_methods(
                &[
                    "Target.attachedToTarget",
                    "Network.requestWillBeSent",
                    "Fetch.requestPaused",
                    "Network.loadingFailed",
                ],
                256,
                65536,
            )
            .unwrap();
        let popup_links: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
        let recorded_links = popup_links.clone();
        let event_trace = trace.clone();
        let event_reader = tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                if event.method == "Target.attachedToTarget" {
                    if let (Some(target), Some(opener)) = (
                        event
                            .params
                            .pointer("/targetInfo/targetId")
                            .and_then(Value::as_str),
                        event
                            .params
                            .pointer("/targetInfo/openerId")
                            .and_then(Value::as_str),
                    ) {
                        let mut links = recorded_links.lock().unwrap();
                        if links.len() < 64 {
                            links.push((target.to_owned(), opener.to_owned()));
                        }
                    }
                }
                let url = event
                    .params
                    .pointer("/request/url")
                    .or_else(|| event.params.pointer("/targetInfo/url"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let url = diagnostic_url(url);
                let mut trace = event_trace.lock().unwrap();
                if trace.len() < 64 {
                    trace.push(format!(
                        "t={:?} cdp {} session={:?} waiting={:?} target_type={:?} resource_type={} url={url}",
                        trace_started.elapsed(),
                        event.method,
                        event.session_id,
                        event.params.get("waitingForDebugger"),
                        event.params.pointer("/targetInfo/type"),
                        event
                            .params
                            .get("type")
                            .or_else(|| event.params.get("resourceType"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                    ));
                }
            }
        });
        let (mut owner, mut notices, broker) =
            coordinator(client.clone(), &context, "hosted-failure-scope", "");
        let policy_trace = trace.clone();
        let policy = tokio::spawn(async move {
            while let Some(message) = notices.recv().await {
                if let ServerMessage::Event {
                    decision: Some(decision),
                    event,
                    payload,
                    ..
                } = message
                {
                    {
                        let mut trace = policy_trace.lock().unwrap();
                        if trace.len() < 64 {
                            trace.push(format!(
                                "t={:?} decision Continue event={event} url={}",
                                trace_started.elapsed(),
                                diagnostic_url(
                                    payload
                                        .pointer("/request/url")
                                        .and_then(Value::as_str)
                                        .unwrap_or("")
                                )
                            ));
                        }
                    }
                    let _ = broker.resolve(
                        1,
                        &decision.token,
                        super::super::client_protocol::Decision::Continue {
                            overrides: Default::default(),
                        },
                    );
                }
            }
        });
        let popup_parent = if mode == "popup" {
            let target = client
                .send_command(
                    "Target.createTarget",
                    Some(json!({"browserContextId":context,"url":"about:blank"})),
                    None,
                )
                .await
                .unwrap()["targetId"]
                .as_str()
                .unwrap()
                .to_owned();
            let session = client
                .send_command(
                    "Target.attachToTarget",
                    Some(json!({"targetId":target,"flatten":true})),
                    None,
                )
                .await
                .unwrap()["sessionId"]
                .as_str()
                .unwrap()
                .to_owned();
            // Initialize the opener using the production registration and
            // configuration methods before starting the retained supervisor.
            // Only future popup configuration is fault-injected below.
            let entry = owner
                .register(&context, &target, &session, "page", None)
                .unwrap()
                .unwrap();
            owner.initialize(entry, &owner.operation()).await.unwrap();
            Some((target, session))
        } else {
            None
        };
        Arc::get_mut(&mut owner).unwrap().config.timezone_id =
            Some("Synthetic/Invalid-Timezone".into());
        if mode != "managed" {
            owner.start(&owner.operation()).await.unwrap();
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/must-not-start", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let http_trace = trace.clone();
        let http = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut bytes = [0; 4096];
                let read = stream.read(&mut bytes).await.unwrap_or(0);
                if read > 0 {
                    count.fetch_add(1, Ordering::SeqCst);
                    let line = String::from_utf8_lossy(&bytes[..read])
                        .lines()
                        .next()
                        .unwrap_or("")
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(240)
                        .collect::<String>();
                    let mut trace = http_trace.lock().unwrap();
                    if trace.len() < 64 {
                        trace.push(format!(
                            "t={:?} http read={read} first_line={line:?}",
                            trace_started.elapsed()
                        ));
                    }
                }
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        });
        let mut opener_evaluation = None;
        match mode {
            "raw-direct-url" => {
                let _ = client
                    .send_command(
                        "Target.createTarget",
                        Some(json!({"browserContextId":context,"url":url})),
                        None,
                    )
                    .await;
            }
            "managed" => {
                let target = client
                    .send_command(
                        "Target.createTarget",
                        Some(json!({"browserContextId":context,"url":"about:blank"})),
                        None,
                    )
                    .await
                    .unwrap()["targetId"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let session = client
                    .send_command(
                        "Target.attachToTarget",
                        Some(json!({"targetId":target,"flatten":true})),
                        None,
                    )
                    .await
                    .unwrap()["sessionId"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let initialized = owner
                    .enroll_existing(&target, &session, "page", &owner.operation())
                    .await;
                // This is the managed lifecycle contract: never dispatch the
                // requested navigation if owned blank-page initialization fails.
                if initialized.is_ok() {
                    client
                        .send_command("Page.navigate", Some(json!({"url":url})), Some(&session))
                        .await
                        .unwrap();
                }
                assert!(initialized.is_err());
            }
            "popup" => {
                let expression = format!(
                    "(() => {{ const popup=window.open({}); return popup !== null; }})()",
                    serde_json::to_string(&url).unwrap()
                );
                let opener_client = client.clone();
                let opener_session = popup_parent.as_ref().unwrap().1.clone();
                opener_evaluation = Some(tokio::spawn(async move {
                    // window.open may remain blocked while its child is paused.
                    // Failed child configuration can dispose this opener before
                    // its evaluate reply. Retain the command concurrently rather
                    // than making that reply a prerequisite for containment.
                    opener_client.send_command("Runtime.evaluate",
                        Some(json!({"expression":expression,"userGesture":true,"returnByValue":true})),
                        Some(&opener_session)).await
                }));
                let parent = &popup_parent.as_ref().unwrap().0;
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        if popup_links
                            .lock()
                            .unwrap()
                            .iter()
                            .any(|(target, opener)| target != parent && opener == parent)
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("window.open produced no distinct popup with exact opener attribution");
            }
            _ => unreachable!(),
        }
        assert!(tokio::time::timeout(Duration::from_secs(15), owner.drain())
            .await
            .unwrap()
            .is_err());
        if let Some((parent, _)) = &popup_parent {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if popup_links
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|(_, opener)| opener == parent)
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("no popup with exact opener attribution was observed");
            let index = owner.index.lock().unwrap();
            let links = popup_links.lock().unwrap();
            assert!(
                index.sessions.values().any(|entry| entry.target != *parent
                    && entry.application
                    && !entry.resumed
                    && links
                        .iter()
                        .any(|(target, opener)| target == &entry.target && opener == parent)),
                "configuration failure was not attributed to the newly created popup"
            );
        }
        let proof = owner.contain_owned_resources().await.unwrap();
        owner.release_after_containment(proof).await.unwrap();
        let outcome = owner.cleanup_outcome().unwrap();
        assert!(outcome.isolated_context_disposed && outcome.autoattach_disabled);
        if let Some(evaluation) = opener_evaluation {
            let result = evaluation
                .await
                .expect("retained opener evaluation task failed");
            match result {
                Ok(value) => {
                    assert!(
                        value.get("exceptionDetails").is_none(),
                        "unexpected opener JavaScript exception"
                    );
                    assert_eq!(
                        value["result"]["value"], true,
                        "window.open returned no popup handle"
                    );
                    eprintln!("popup opener evaluation: successful non-null handle");
                }
                Err(error) => {
                    // Exact opener detach may wake this raw waiter before the
                    // disposal ACK publishes cleanup. Its error proves neither
                    // creation nor containment: exact popup/opener attribution,
                    // failed unresumed enrollment, and this owner's actual
                    // containment proof and phase-two release are required above.
                    let expected = error.contains("timed out")
                        || error.contains("closed")
                        || error.contains("Session with given id not found")
                        || error.contains("Cannot find context with specified id");
                    assert!(
                        expected,
                        "unexpected opener failure after verifying containment: {error}"
                    );
                    eprintln!("popup opener evaluation: expected closed/timeout outcome; exact context disposal independently acknowledged");
                }
            }
        }
        eprintln!(
            "first-request containment trace: {:#?}",
            trace.lock().unwrap()
        );
        {
            let index = owner.index.lock().unwrap();
            eprintln!(
                "first-request containment failure: {:?}; resumed entries: {:?}",
                index.failure,
                index
                    .sessions
                    .values()
                    .map(|entry| (entry.kind.clone(), entry.application, entry.resumed))
                    .collect::<Vec<_>>()
            );
        }
        event_reader.abort();
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        assert!(client
            .send_command("Browser.getVersion", Some(json!({})), None)
            .await
            .is_ok());
        let _ = owner.network.close().await;
        policy.abort();
        http.abort();
        chrome.kill();
    }
}
