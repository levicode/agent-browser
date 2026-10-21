//! One scope-owned target enrollment supervisor. Target metadata is inspected
//! before any page/network domain; foreign sessions are detached immediately.
//! The authoritative identity/purpose registry remains ClientTargets.
use super::cdp::client::{BoundedMethodEvents, CdpClient};
use super::cdp::types::CdpEvent;
use super::client_browser::{BrowserExecutionLease, ExecutionGate, InitializationAccess};
use super::client_network::{ApplicationSession, ClientNetwork};
use super::client_page::ClientPageState;
use super::client_protocol::ProtocolError;
use super::client_session::{CancelSignal, OperationLease};
use super::client_targets::{ClientTargets, TargetPurpose};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{watch, Notify};
use tokio::task::{JoinHandle, JoinSet};

const EVENTS: &[&str] = &[
    "Target.attachedToTarget",
    "Target.detachedFromTarget",
    "Target.targetInfoChanged",
    "Page.frameNavigated",
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
}
#[derive(Clone, Debug, Default)]
pub struct CleanupOutcome {
    pub isolated_context_disposed: bool,
    pub closed_targets: Vec<String>,
    pub autoattach_disabled: bool,
    pub owned_resources_contained: bool,
}
pub struct ContainmentProof {
    registry: Arc<ClientTargets>,
    identity_scope: String,
    generation: u64,
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
    session: String,
    parent: Option<String>,
}
#[derive(Default)]
struct Index {
    sessions: HashMap<String, Attribution>,
    frames: HashMap<String, FrameOwner>,
    failure: Option<ProtocolError>,
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
    changed: Notify,
    stop: watch::Sender<CancelSignal>,
    started: AtomicBool,
    policy_installed: AtomicBool,
    sealed: AtomicBool,
    supervisor: tokio::sync::Mutex<Option<JoinHandle<Result<(), ProtocolError>>>>,
    containment: tokio::sync::Mutex<ContainmentState>,
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
            changed: Notify::new(),
            stop,
            started: AtomicBool::new(false),
            policy_installed: AtomicBool::new(false),
            sealed: AtomicBool::new(false),
            supervisor: tokio::sync::Mutex::new(None),
            containment: tokio::sync::Mutex::new(ContainmentState::default()),
        })
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
        if matches!(&self.ownership,ScopeOwnership::TrackedTargets(allowed) if allowed.len()>MAX_SESSIONS || allowed.iter().any(|id|valid_id(id).is_err()))
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
        if self.config.block_service_workers && !self.policy_installed.load(Ordering::Acquire) {
            self.page.execute(&lease,&[],op,"context.init-script",&json!({"source":"if (globalThis.ServiceWorkerContainer) ServiceWorkerContainer.prototype.register = async () => { console.warn('Service Worker registration blocked by agent-browser'); };"})).await?;
            self.policy_installed.store(true, Ordering::Release);
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
            let owner = self.clone();
            *task = Some(tokio::spawn(async move { owner.run(events).await }));
        }
        Ok(())
    }
    async fn run(self: Arc<Self>, mut events: BoundedMethodEvents) -> Result<(), ProtocolError> {
        let mut tasks = JoinSet::new();
        let mut stop = self.stop.subscribe();
        let mut result = loop {
            tokio::select! {
                biased;
                _ = stop.changed() => break Ok(()),
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    match completed { Some(Ok(Ok(()))) => {}, Some(Ok(Err(error))) => break Err(error), Some(Err(_)) => break Err(ProtocolError::BrowserFailure), None=>{} }
                },
                event = events.recv() => {
                    let event = match event { Ok(event)=>event, Err(_)=>break Err(ProtocolError::CapacityExceeded) };
                    if event.method == "Target.attachedToTarget" {
                        if tasks.len() >= MAX_TASKS { break Err(ProtocolError::CapacityExceeded); }
                        let owner = self.clone();
                        tasks.spawn(async move { let result = owner.attached((*event).clone()).await; drop(event); result });
                    } else if let Err(error) = self.event_internal(&event, Some(event.budget_lease())) { break Err(error); }
                }
            }
        };
        if let Err(error) = &result {
            self.poison(error.clone());
        }
        // Stop cancellation is observed by initialization waits; retain every
        // task until it has settled rather than dropping effects mid-command.
        self.stop.send_replace(CancelSignal::SessionClosed);
        while let Some(completed) = tasks.join_next().await {
            if !matches!(completed, Ok(Ok(())) | Ok(Err(ProtocolError::Cancelled)))
                && result.is_ok()
            {
                self.poison(ProtocolError::CleanupFailed);
            }
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
            ScopeOwnership::TrackedTargets(allowed) => {
                let index = self
                    .index
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                Ok(allowed.iter().any(|id| id == target)
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
            state.task = Some(tokio::spawn(async move { owner.contain_owned().await }));
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
    async fn contain_owned(&self) -> Result<(), ProtocolError> {
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
        }
        self.cleanup
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .owned_resources_contained = true;
        Ok(())
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
        self.record_frame(entry, frame)?;
        if let Some(children) = tree.get("childFrames").and_then(Value::as_array) {
            for child in children {
                self.frame_tree(entry, child, depth + 1)?;
            }
        }
        Ok(())
    }
    fn record_frame(&self, entry: &Attribution, frame: &Value) -> Result<(), ProtocolError> {
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
                    session: entry.session.clone(),
                    parent: frame
                        .get("parentId")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                },
            );
        }
        drop(index);
        if let Some(url) = frame.get("url").and_then(Value::as_str) {
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
                        removed.push(entry);
                    }
                }
                index
                    .frames
                    .retain(|_, owner| !removed.iter().any(|entry| entry.session == owner.session));
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
            if let Some(entry) = entry.filter(|entry| entry.application) {
                self.targets.invalidate_inventory()?;
                if let Some(url) = info.get("url").and_then(Value::as_str) {
                    self.page.record_origin(&self.lease(&entry)?, url)?;
                }
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
            "Page.frameNavigated" => {
                self.targets.invalidate_inventory()?;
                self.record_frame(
                    &entry,
                    event
                        .params
                        .get("frame")
                        .ok_or(ProtocolError::InvalidFrame)?,
                )?;
            }
            "Page.navigatedWithinDocument" => {
                self.targets.invalidate_inventory()?;
                if let Some(url) = event.params.get("url").and_then(Value::as_str) {
                    self.page.record_origin(&self.lease(&entry)?, url)?;
                }
            }
            "Page.frameDetached" => {
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
        let broker = Arc::new(ClientSession::new());
        let (sink, notices) = ClientEventSink::test_channel(broker.clone());
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
            Arc::new(super::super::client_ui::UiGate::default()),
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
                        if (mode=="fail-fetch" && method=="Fetch.enable") || (mode=="detach-fallback" && method=="Target.detachFromTarget" && detach_count==1) {
                            socket.send(Message::Text(json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic injected failure"}}).to_string())).await.unwrap();continue;
                        }
                        if (mode=="first-request" || mode=="large-first-request" || mode=="hold-timezone") && method=="Fetch.enable" {
                            let body=if mode=="large-first-request" {"b".repeat(1536*1024)} else {String::new()};
                            socket.send(Message::Text(json!({"method":"Fetch.requestPaused","sessionId":request["sessionId"],"params":{"requestId":"first","request":{"url":"https://synthetic.test/first","method":"POST","headers":{},"postData":body}}}).to_string())).await.unwrap();
                        }
                        let mut result=match method {
                            "Page.getFrameTree"=>json!({"frameTree":{"frame":{"id":format!("frame-{}",request["sessionId"].as_str().unwrap()),"url":"about:blank"}}}),
                            "Target.getTargets" if mode=="tracked" || mode=="late-popup"=>json!({"targetInfos":[
                                {"targetId":"initial-target","browserContextId":"owned-context","type":"page"},
                                {"targetId":"queued-popup","browserContextId":"owned-context","type":"page","openerId":"initial-target"},
                                {"targetId":"unrelated","browserContextId":"owned-context","type":"page"},
                                {"targetId":"foreign","browserContextId":"other-context","type":"page"}]}),
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
        owner.contain_owned().await.unwrap();
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
    #[ignore = "requires hosted Chromium: initialization failure contains first request"]
    async fn e2e_enrollment_configuration_failure_contains_owned_first_request() {
        use super::super::cdp::chrome::{launch_chrome, LaunchOptions};
        use std::sync::atomic::AtomicUsize;
        let mut chrome = launch_chrome(&LaunchOptions {
            headless: true,
            ..Default::default()
        })
        .unwrap();
        let client = Arc::new(CdpClient::connect(&chrome.ws_url).await.unwrap());
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
        let event_trace = trace.clone();
        let event_reader = tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                let url = event
                    .params
                    .pointer("/request/url")
                    .or_else(|| event.params.pointer("/targetInfo/url"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
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
                                payload
                                    .pointer("/request/url")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
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
        Arc::get_mut(&mut owner).unwrap().config.timezone_id =
            Some("Synthetic/Invalid-Timezone".into());
        owner.start(&owner.operation()).await.unwrap();
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
                        .to_owned();
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
        let _ = client
            .send_command(
                "Target.createTarget",
                Some(json!({"browserContextId":context,"url":url})),
                None,
            )
            .await;
        assert!(tokio::time::timeout(Duration::from_secs(15), owner.drain())
            .await
            .unwrap()
            .is_err());
        let proof = owner.contain_owned_resources().await.unwrap();
        owner.release_after_containment(proof).await.unwrap();
        let outcome = owner.cleanup_outcome().unwrap();
        assert!(outcome.isolated_context_disposed && outcome.autoattach_disabled);
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
