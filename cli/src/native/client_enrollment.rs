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
use super::client_targets::{ClientTargets, TargetPurpose};
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
    "Runtime.consoleAPICalled",
    "Runtime.exceptionThrown",
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
#[derive(Clone, Debug, Default)]
pub struct ScopeConfig {
    pub viewport: Option<(u32, u32)>,
    pub user_agent: Option<String>,
    pub locale: Option<String>,
    pub timezone_id: Option<String>,
    pub block_service_workers: bool,
}
#[derive(Clone, Debug)]
struct Attribution {
    target: String,
    session: String,
    parent: Option<String>,
    root: String,
    kind: String,
    application: bool,
    resumed: bool,
}
#[derive(Clone, Debug)]
struct FrameOwner {
    name: Option<String>,
    session: String,
    parent: Option<String>,
}
#[derive(Default)]
struct Index {
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
        })
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
        if event
            .params
            .pointer("/targetInfo/browserContextId")
            .and_then(Value::as_str)
            != Some(self.targets.context_id.as_str())
        {
            return Ok(None);
        }
        let session = field(&event.params, "sessionId")?.to_owned();
        let mut index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if index.pending_enrollment.len() >= MAX_TASKS {
            return Err(ProtocolError::CapacityExceeded);
        }
        if !index.pending_enrollment.insert(session.clone()) {
            return Err(ProtocolError::StaleScope);
        }
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
    fn bump_application_epoch(&self) -> Result<(), ProtocolError> {
        let mut index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
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
                changed.await;
            }
        })
        .await
    }
    pub async fn attest_capture(
        self: &Arc<Self>,
        op: &OperationLease,
    ) -> Result<EnrollmentAttestation, ProtocolError> {
        self.check()?;
        if op.generation != self.generation {
            return Err(ProtocolError::StaleGeneration);
        }
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
        let (epoch, entries) = {
            let index = self
                .index
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if !index.reconciled
                || !index.pending_enrollment.is_empty()
                || index
                    .sessions
                    .values()
                    .any(|entry| entry.application && !entry.resumed)
            {
                return Err(ProtocolError::ScopeUnavailable);
            }
            (
                index.application_epoch,
                index
                    .sessions
                    .values()
                    .filter(|entry| entry.application)
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        };
        // Browser inventory alone is not a renderer flush. Reconcile each
        // exact application session's frame/loader tree as well.
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
        for info in infos {
            if info.get("browserContextId").and_then(Value::as_str)
                != Some(self.targets.context_id.as_str())
                || matches!(
                    info.get("type").and_then(Value::as_str),
                    Some("browser" | "tab")
                )
            {
                continue;
            }
            let target = field(info, "targetId")?;
            if matches!(self.ownership, ScopeOwnership::BorrowedTargets(_))
                && !self.authorized(target, None, info.get("openerId").and_then(Value::as_str))?
            {
                // Preexisting unadopted host pages are not this attachment
                // tenure's observation authority, nor bootstrap ownership.
                // An authorized popup not yet enrolled must still fail below.
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
        if entries.iter().any(|entry| {
            !infos.iter().any(|info| {
                info.get("targetId").and_then(Value::as_str) == Some(entry.target.as_str())
                    && info.get("browserContextId").and_then(Value::as_str)
                        == Some(self.targets.context_id.as_str())
            })
        }) {
            return Err(ProtocolError::StaleScope);
        }
        let mut frames = Vec::new();
        for entry in &entries {
            if !matches!(entry.kind.as_str(), "page" | "iframe") {
                continue;
            }
            let tree = self
                .command(op, Some(&entry.session), "Page.getFrameTree", json!({}))
                .await?;
            capture_frame_fingerprint(
                &entry.session,
                tree.get("frameTree").ok_or(ProtocolError::InvalidFrame)?,
                0,
                &mut frames,
            )?;
        }
        self.drain_capture_watermark(&watermark, op).await?;
        let index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let received = watermark
            .received()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if index.application_epoch != epoch
            || !capture_admission_ready(&index, received)
            || index
                .sessions
                .values()
                .any(|entry| entry.application && !entry.resumed)
        {
            return Err(ProtocolError::StaleScope);
        }
        drop(index);
        self.check()?;
        frames.sort();
        Ok(EnrollmentAttestation {
            coordinator: Arc::downgrade(self),
            targets: self.targets.clone(),
            generation: self.generation,
            application_epoch: epoch,
            frames,
            watermark,
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
        previous
            .watermark
            .received()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let current = self.attest_capture(op).await?;
        if current.application_epoch != previous.application_epoch
            || current.frames != previous.frames
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
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
            if entry.application && entry.resumed {
                return Ok(());
            }
            bounded(op, async {
                changed.await;
                Ok(())
            })
            .await?;
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
                index.retired_page_sessions.contains(session)
                    && !index
                        .sessions
                        .values()
                        .any(|entry| entry.target == target || entry.root == session)
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
                if index.retiring_pages.get(target).map(String::as_str) != Some(session)
                    || !index.retired_page_sessions.contains(session)
                    || index
                        .sessions
                        .values()
                        .any(|entry| entry.target == target || entry.root == session)
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
                .any(|entry| entry.application && !entry.resumed)
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
        self.targets.publish_initialization(authority)
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
        let entry = self
            .register(&self.targets.context_id, target, session, kind, None)?
            .ok_or(ProtocolError::InvalidArguments)?;
        let result = self.initialize(entry, op).await;
        if let Err(error) = &result {
            self.poison(error.clone());
        }
        result
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
            resumed: false,
        };
        index.sessions.insert(session.into(), entry.clone());
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
        let result = self.initialize_inner(entry.clone(), op).await;
        let Err(error) = result else {
            return Ok(());
        };
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
    ) -> Result<(), ProtocolError> {
        let purpose = bounded(op, self.targets.purpose(&entry.target)).await?;
        if purpose == TargetPurpose::StateBootstrap {
            return Ok(());
        }
        let lease = self.lease(&entry)?;
        let _config = bounded(op, async { Ok(self.config_gate.lock().await) }).await?;
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
        self.network
            .configure_session(
                ApplicationSession {
                    session_id: entry.session.clone(),
                    root_page_session: entry.root.clone(),
                    active_page: active,
                },
                op,
            )
            .await?;
        let page_target = matches!(entry.kind.as_str(), "page" | "iframe");
        if page_target {
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
            let revision = self
                .page
                .apply_to_new_session(&lease, &entry.session, op)
                .await?;
            if revision != self.page.config_revision()? {
                return Err(ProtocolError::StaleScope);
            }
        }
        // Runtime event routing is already subscribed on the same retained tap.
        // Enable before resume so first-script console/errors are observable.
        self.command(op, Some(&entry.session), "Runtime.enable", json!({}))
            .await?;
        // Autoattach is recursive. Install it while this target is paused.
        self.command(
            op,
            Some(&entry.session),
            "Target.setAutoAttach",
            autoattach(true),
        )
        .await?;
        self.targets.configured(&entry.target)?;
        let permit = bounded(op, self.targets.resume_permit(&entry.target)).await?;
        self.command(
            op,
            Some(&entry.session),
            "Runtime.runIfWaitingForDebugger",
            json!({}),
        )
        .await?;
        lease.permit.check()?;
        permit.complete()?;
        self.network.configuration_committed(&entry.session, op)?;
        if let Some(current) = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .sessions
            .get_mut(&entry.session)
        {
            current.resumed = true;
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
            Ok(())
        }.await;
        if let Err(error) = &result {
            self.poison(error.clone());
        } else {
            self.index
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .reconciled = true;
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
            let owner = self.clone();
            *task = Some(tokio::spawn(async move { owner.run(events).await }));
        }
        Ok(())
    }
    async fn run(self: Arc<Self>, mut events: BoundedMethodEvents) -> Result<(), ProtocolError> {
        let mut tasks = JoinSet::new();
        let mut stop = self.stop.subscribe();
        let mut terminal = None;
        let mut result = loop {
            tokio::select! {
                biased;
                _ = stop.changed() => {
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
                                Err(error) => break Err(error),
                            }
                            break Ok(());
                        }
                        Err(_) => break Err(ProtocolError::CapacityExceeded),
                    };
                    let sequence=event.sequence();
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
        let outcome = self.cleanup_outcome()?;
        if !outcome.owned_resources_contained {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if outcome.autoattach_disabled {
            return Ok(());
        }
        self.cleanup_command("Target.setAutoAttach", autoattach(false))
            .await?;
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
                        entry.target == target || opener == Some(entry.target.as_str())
                    })
                    || parent.is_some_and(|session| index.sessions.contains_key(session)))
            }
        }
    }
    async fn cleanup_command(&self, method: &str, args: Value) -> Result<Value, ProtocolError> {
        tokio::time::timeout(
            CLEANUP_TIMEOUT,
            self.client.send_command(method, Some(args), None),
        )
        .await
        .map_err(|_| ProtocolError::CleanupFailed)?
        .map_err(|_| ProtocolError::CleanupFailed)
    }
    async fn perform_containment(self: &Arc<Self>) -> Result<(), ProtocolError> {
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
                self.cleanup_command(
                    "Target.disposeBrowserContext",
                    json!({"browserContextId":self.targets.context_id}),
                )
                .await?;
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
                    .is_err();
                failed |= self
                    .network
                    .release_borrowed_interception(
                        &self.targets.identity_scope,
                        &entry.session,
                        config_deadline,
                    )
                    .await
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
                    .is_err();
            }
            // Do not release a debugger pause by closing the host page.
            for (method, args) in [
                ("Runtime.runIfWaitingForDebugger", json!({})),
                ("Target.setAutoAttach", autoattach(false)),
            ] {
                if Instant::now() >= session_deadline {
                    failed = true;
                    break;
                }
                failed |= !matches!(
                    tokio::time::timeout_at(
                        std::cmp::min(session_deadline, Instant::now() + CLEANUP_TIMEOUT).into(),
                        self.client
                            .send_command(method, Some(args), Some(&entry.session))
                    )
                    .await,
                    Ok(Ok(_))
                );
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
                    self.client
                        .send_command("Target.setAutoAttach", Some(autoattach(false)), None)
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
        let session = field(&event.params, "sessionId")?.to_owned();
        let info = event
            .params
            .get("targetInfo")
            .ok_or(ProtocolError::InvalidFrame)?;
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
            let _ = self.borrowed_blank_matches(target).await?;
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
        if event.session_id.as_ref().is_some_and(|parent| {
            self.index
                .lock()
                .is_ok_and(|index| index.retired_page_sessions.contains(parent))
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
        // Stored scope failure takes precedence over retirement cancellation.
        // Foreign cleanup above must remain live even for a poisoned scope.
        self.check().map_err(|error| self.admission_error(error))?;
        let auxiliary = bounded(
            &self.operation(),
            self.targets.classify_auxiliary_attachment(target, &session),
        )
        .await?;
        match auxiliary {
            super::client_targets::AuxiliaryDisposition::RecorderOwned => return Ok(()),
            super::client_targets::AuxiliaryDisposition::Ordinary => {}
        }
        match self.register(context, target, &session, kind, event.session_id.as_deref())? {
            Some(entry) => self.initialize(entry, &self.operation()).await,
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
    async fn detach_foreign(
        &self,
        session: &str,
        parent: Option<&str>,
    ) -> Result<(), ProtocolError> {
        // Cleanup is independent of a cancelled owned operation.
        let detach = || {
            self.client.send_command(
                "Target.detachFromTarget",
                Some(json!({"sessionId":session})),
                parent,
            )
        };
        if matches!(
            tokio::time::timeout(CLEANUP_TIMEOUT, detach()).await,
            Ok(Ok(_))
        ) {
            return Ok(());
        }
        // Undo ONLY our debugger pause, never evaluate foreign JavaScript.
        let resumed = tokio::time::timeout(
            CLEANUP_TIMEOUT,
            self.client.send_command(
                "Runtime.runIfWaitingForDebugger",
                Some(json!({})),
                Some(session),
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
            index.frames.insert(
                id.into(),
                FrameOwner {
                    name: frame
                        .get("name")
                        .and_then(Value::as_str)
                        .map(super::client_app_events::diagnostic_frame_name),
                    session: entry.session.clone(),
                    parent: frame
                        .get("parentId")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
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
                if removed.iter().any(|entry| entry.application) {
                    index.application_epoch = index
                        .application_epoch
                        .checked_add(1)
                        .ok_or(ProtocolError::IdentifierExhausted)?;
                }
                removed
            };
            for entry in entries {
                self.targets.detach(&entry.target)?;
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
                self.targets.invalidate_inventory()?;
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
        if !entry.application {
            return Ok(());
        }
        match event.method.as_str() {
            "Page.frameAttached" => {
                self.bump_application_epoch()?;
            }
            "Page.frameNavigated" => {
                self.bump_application_epoch()?;
                self.targets.invalidate_inventory()?;
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
                self.targets.invalidate_inventory()?;
            }
            "Page.frameDetached" => {
                self.bump_application_epoch()?;
                self.targets.invalidate_inventory()?;
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
        self.targets.seal();
        self.sealed.store(true, Ordering::Release);
        self.stop.send_replace(CancelSignal::SessionClosed);
        self.changed.notify_waiters();
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
fn capture_admission_ready(index: &Index, received: u64) -> bool {
    index.applied_watermark >= received && index.pending_enrollment.is_empty()
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
            let mut detach_count = 0;
            let mut closed_targets = std::collections::HashSet::<String>::new();
            loop {
                tokio::select! {
                    event=emitted.recv()=> { let Some(event)=event else {break}; if socket.send(Message::Text(event.to_string())).await.is_err(){break;} },
                    message=socket.next()=> {
                        let Some(Ok(Message::Text(text)))=message else {break};
                        let request:Value=serde_json::from_str(&text).unwrap();
                        recorded.lock().unwrap().push(request.clone());
                        let method=request["method"].as_str().unwrap();
                        if mode=="delayed-dispose" && method=="Target.disposeBrowserContext" {tokio::time::sleep(Duration::from_millis(40)).await;}
                        if method=="Target.detachFromTarget" {detach_count+=1;}
                        if mode=="hold-timezone" && method=="Emulation.setTimezoneOverride" { continue; }
                        let settings_error = match (mode, method) {
                            ("locale-already", "Emulation.setLocaleOverride") => Some("Another locale override is already in effect"),
                            ("timezone-already", "Emulation.setTimezoneOverride") => Some("Timezone override is already in effect"),
                            ("invalid-timezone", "Emulation.setTimezoneOverride") => Some("Invalid timezone"),
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
                        if (mode=="first-request" || mode=="large-first-request" || mode=="hold-timezone") && method=="Fetch.enable" {
                            let body=if mode=="large-first-request" {"b".repeat(1536*1024)} else {String::new()};
                            socket.send(Message::Text(json!({"method":"Fetch.requestPaused","sessionId":request["sessionId"],"params":{"requestId":"first","request":{"url":"https://synthetic.test/first","method":"POST","headers":{},"postData":body}}}).to_string())).await.unwrap();
                        }
                        let mut result=match method {
                            "Page.getFrameTree"=>json!({"frameTree":{"frame":{"id":format!("frame-{}",request["sessionId"].as_str().unwrap()),"loaderId":"synthetic-loader","url":if mode=="borrowed-capture" {"https://initial.test/"} else {"about:blank"}}}}),
                            "Target.getTargets" if mode=="tracked" || mode=="late-popup"=>json!({"targetInfos":[
                                {"targetId":"initial-target","browserContextId":"owned-context","type":"page"},
                                {"targetId":"queued-popup","browserContextId":"owned-context","type":"page","openerId":"initial-target"},
                                {"targetId":"unrelated","browserContextId":"owned-context","type":"page"},
                                {"targetId":"foreign","browserContextId":"other-context","type":"page"}]}),
                            "Target.getTargets" if mode=="borrowed-capture"=>json!({"targetInfos":[{"targetId":"initial-target","type":"page","browserContextId":"owned-context"},{"targetId":"unadopted-host","type":"page","browserContextId":"owned-context"}]}),
                            "Target.getTargets" if mode=="attestation"=>json!({"targetInfos":[{"targetId":"target","type":"page","browserContextId":"owned-context"}]}),
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
    #[tokio::test]
    async fn borrowed_capture_attests_only_observed_document_origins_not_initial_profile() {
        let (mut owner, _notices, _log, _emit, server) = fixture("borrowed-capture").await;
        Arc::get_mut(&mut owner).unwrap().ownership =
            ScopeOwnership::BorrowedTargets(vec!["initial-target".into()]);
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
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
        assert!(!owner
            .index
            .lock()
            .unwrap()
            .sessions
            .values()
            .any(|entry| entry.target == "unadopted-host"));
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
        assert!(!owner
            .index
            .lock()
            .unwrap()
            .sessions
            .contains_key("host-session"));
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
    #[tokio::test]
    async fn initialized_publication_rejects_late_failure_and_pending_events() {
        for failed in [false, true] {
            let (mut owner, _notices, _log, _emit, server) = fixture("normal").await;
            owner.gate.begin_transition().unwrap();
            let authority = owner.gate.initialization(owner.targets.clone()).unwrap();
            Arc::get_mut(&mut owner).unwrap().initialization = Some(authority.access());
            assert!(owner.publish_initialized(&authority).is_err());
            owner.start(&owner.operation()).await.unwrap();
            owner.targets.acknowledge_enrollment().unwrap();
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
            resumed: true,
        };
        owner.index.lock().unwrap().frames.insert(
            "popup-frame".into(),
            FrameOwner {
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
    // Run only on the hosted Chromium gate; never substitute mock success for
    // two real browser contexts sharing the same host process.
    #[tokio::test]
    #[ignore = "requires hosted Chromium: two tenants and first-request initialization"]
    async fn e2e_enrollment_two_tenants_and_popup_first_script() {
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
            .block_service_workers = true;
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
        owner
            .page
            .execute(
                &lease,
                std::slice::from_ref(&session),
                &op,
                "context.init-script",
                &json!({"source":"window.ownedSyntheticInit=41"}),
            )
            .await
            .unwrap();
        owner.start(&op).await.unwrap();
        // This foreign target is created AFTER global pause-and-filter starts.
        // Its first inline script must still run, without our init/config.
        let other_target=foreign.send_command("Target.createTarget",Some(json!({"browserContextId":other,"url":"data:text/html,<script>window.foreignRan=73</script>"})),None).await.unwrap()["targetId"].as_str().unwrap().to_owned();
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
        tokio::time::timeout(Duration::from_secs(10),async {
            loop {
                let value=foreign.send_command("Runtime.evaluate",Some(json!({"expression":"[window.foreignRan, typeof window.ownedSyntheticInit]","returnByValue":true})),Some(&other_session)).await.unwrap();
                if value["result"]["value"]==json!([73,"undefined"]) {break;}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
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
                    "<script>window.firstScriptSawInit=window.ownedSyntheticInit</script>synthetic";
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
                let opener_owner = owner.clone();
                let opener_session = popup_parent.as_ref().unwrap().1.clone();
                opener_evaluation = Some(tokio::spawn(async move {
                    // window.open may remain blocked while its child is paused.
                    // Failed child configuration can dispose this opener before
                    // its evaluate reply. Retain the command concurrently rather
                    // than making that reply a prerequisite for containment.
                    let result = opener_client.send_command("Runtime.evaluate",
                        Some(json!({"expression":expression,"userGesture":true,"returnByValue":true})),
                        Some(&opener_session)).await;
                    let disposed_at_reply = opener_owner
                        .cleanup_outcome()
                        .is_ok_and(|outcome| outcome.isolated_context_disposed);
                    (result, disposed_at_reply)
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
            let (result, disposed_at_reply) = evaluation
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
                    // Do not accept timeout alone as creation evidence: exact
                    // popup/opener attribution and failed unresumed enrollment
                    // were independently required above. Unexpected failures
                    // before acknowledged containment still fail this fixture.
                    assert!(
                        disposed_at_reply,
                        "opener evaluation failed before acknowledged context containment: {error}"
                    );
                    let expected = error.contains("timed out")
                        || error.contains("closed")
                        || error.contains("Session with given id not found")
                        || error.contains("Cannot find context with specified id");
                    assert!(
                        expected,
                        "unexpected post-containment opener failure: {error}"
                    );
                    eprintln!("popup opener evaluation: expected closed/timeout outcome after acknowledged context disposal");
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
