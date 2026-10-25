//! Native request ownership and token dispatch. ECMAScript route matching and
//! callbacks stay in e2e; no JavaScript function or matcher is interpreted here.
use super::cdp::client::CdpClient;
use super::cdp::types::CdpEvent;
use super::client_app_events::{
    AppEventContext, AppEventProjector, AppNavigationContext, OwnNavigationGuard,
};
use super::client_blobs::{
    BlobChunk, BlobError, BlobLease, BlobProducer, BlobScope, BlobStore, MAX_CHUNK_BYTES,
};
use super::client_browser::BrowserExecutionLease;
use super::client_debt::ScopeCleanupCommand;
use super::client_protocol::{Decision, DecisionNotice, ProtocolError, RequestOverrides};
use super::client_session::{
    CancelSignal, ClientSession, DecisionKind, DecisionLease, DecisionOutcome, DecisionOwner,
    OperationLease, ParkedRouteRegistry, RouteRegistryTransfer,
};
use super::client_settlement_trace::{ServiceWorkerAdmission, WorkerAdmissionStep};
use super::client_transport::ClientEventSink;
use base64::Engine;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub struct ClientNetwork {
    pub client: Arc<CdpClient>,
    broker: Arc<ClientSession>,
    future_session_sink: Mutex<ClientEventSink>,
    retirement_sink: ClientEventSink,
    app_events: AppEventProjector,
    registry: Mutex<Option<u64>>,
    disconnected_routes: Mutex<DisconnectedRouteSlot>,
    routes_frozen: AtomicBool,
    close_gate: tokio::sync::Mutex<NetworkCloseState>,
    cleanup_drained: AtomicBool,
    tokens: Mutex<HashMap<String, String>>,
    scope: BlobScope,
    policy: Mutex<NetworkPolicy>,
    blobs: Arc<BlobStore>,
    aliases: Mutex<HashMap<String, Arc<BlobLease>>>,
    sealed: AtomicBool,
    ui_gate: Arc<super::client_ui::UiGate>,
    cancellation: tokio::sync::watch::Sender<CancelSignal>,
    sessions: Mutex<HashMap<String, EnrolledSession>>,
    tasks: Mutex<tokio::task::JoinSet<Result<(), ProtocolError>>>,
    blocking_reads: Mutex<tokio::task::JoinSet<()>>,
    dialog_enabled: AtomicBool,
    auth_attempts: Mutex<std::collections::HashSet<(String, String)>>,
    request_ids: Mutex<HashMap<(String, String), String>>,
    pending_interceptions: Mutex<HashMap<(String, String, String), ()>>,
    response_subscriptions: Mutex<std::collections::HashSet<String>>,
    responses: Mutex<HashMap<(String, String), String>>,
    resources: Mutex<HashMap<String, Arc<BodyResource>>>,
    downloads: Mutex<HashMap<String, DownloadEntry>>,
    download_source: Mutex<Option<DownloadSource>>,
    download_context: Mutex<Option<String>>,
    download_ready: AtomicBool,
    download_subscriptions: Mutex<std::collections::HashSet<String>>,
}

enum NetworkCloseState {
    Open,
    Running(tokio::task::JoinHandle<Result<(), ProtocolError>>),
    Finished(Result<(), ProtocolError>),
}

/// Native private authority across one exact old-to-new scope transition.
/// Failed bind/adopt keeps this guard available for explicit restore/retire.
/// Drop always retires, never silently reactivates an abandoned route list.
pub(crate) struct RouteTransfer {
    source: Arc<ClientNetwork>,
    replacement: Option<Arc<ClientNetwork>>,
    registry: Option<RouteRegistryTransfer>,
    sequence: u64,
    deadline: std::time::Instant,
    cancellation: tokio::sync::watch::Receiver<CancelSignal>,
    active: bool,
}
impl RouteTransfer {
    fn check_operation(&self, operation: &OperationLease) -> Result<(), ProtocolError> {
        if !self.active {
            return Err(ProtocolError::StaleScope);
        }
        if operation.generation != self.source.scope.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if operation.is_callback
            || operation.sequence != self.sequence
            || operation.deadline != self.deadline
            || !operation.cancellation.same_channel(&self.cancellation)
        {
            return Err(ProtocolError::InvalidSequence);
        }
        if *self.cancellation.borrow() != CancelSignal::None
            || *operation.cancellation.borrow() != CancelSignal::None
        {
            return Err(ProtocolError::Cancelled);
        }
        if std::time::Instant::now() >= self.deadline
            || std::time::Instant::now() >= operation.deadline
        {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(())
    }
    /// Bind once to the exact replacement, not a string token supplied by a
    /// client. Its route slot is frozen until successful adoption/publication.
    pub(super) fn bind_replacement(
        &mut self,
        replacement: &Arc<ClientNetwork>,
        owner: &super::client_browser::ReplacementLease,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.check_operation(operation)?;
        owner.check_route_replacement(
            &self.source.client,
            &replacement.client,
            &replacement.scope.identity_scope,
            operation,
        )?;
        self.bind_checked(replacement)
    }

    // Existing protocol-only fixtures have no lifecycle manager or managed
    // owner. They retain the old same-handle guard; production has no such path.
    #[cfg(test)]
    fn bind_unmanaged(&mut self, replacement: &Arc<ClientNetwork>) -> Result<(), ProtocolError> {
        if self.source.client.debt_ledger().is_some()
            || replacement.client.debt_ledger().is_some()
            || !Arc::ptr_eq(&self.source.client, &replacement.client)
        {
            return Err(ProtocolError::StaleScope);
        }
        self.bind_checked(replacement)
    }

    fn bind_checked(&mut self, replacement: &Arc<ClientNetwork>) -> Result<(), ProtocolError> {
        if !self.active || self.replacement.is_some() {
            return Err(ProtocolError::StaleScope);
        }
        if *self.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if std::time::Instant::now() >= self.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        if replacement.scope.generation != self.source.scope.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if Arc::ptr_eq(&self.source, replacement)
            || replacement.scope.identity_scope.is_empty()
            || replacement.scope.identity_scope == self.source.scope.identity_scope
            || !Arc::ptr_eq(&self.source.broker, &replacement.broker)
            || !Arc::ptr_eq(&self.source.blobs, &replacement.blobs)
        {
            return Err(ProtocolError::StaleScope);
        }
        replacement.check()?;
        let current = replacement
            .registry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if current.is_some() || replacement.routes_frozen.load(Ordering::Acquire) {
            return Err(ProtocolError::RegistryInUse);
        }
        replacement.routes_frozen.store(true, Ordering::Release);
        self.replacement = Some(replacement.clone());
        Ok(())
    }
    /// Old native callbacks and blocking readers must have actually settled.
    /// No version is re-registered; the broker moves its immutable snapshot.
    pub(crate) fn adopt(&mut self, operation: &OperationLease) -> Result<(), ProtocolError> {
        self.check_operation(operation)?;
        let replacement = self
            .replacement
            .as_ref()
            .ok_or(ProtocolError::InvalidArguments)?;
        replacement.check()?;
        if !self.source.sealed.load(Ordering::Acquire)
            || !self.source.cleanup_drained.load(Ordering::Acquire)
        {
            return Err(ProtocolError::RegistryInUse);
        }
        if !self
            .source
            .tokens
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .is_empty()
        {
            return Err(ProtocolError::RegistryInUse);
        }
        let mut current = replacement
            .registry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if current.is_some() || !replacement.routes_frozen.load(Ordering::Acquire) {
            return Err(ProtocolError::RegistryInUse);
        }
        if let Some(registry) = &mut self.registry {
            self.source.broker.adopt_registry_transfer(
                registry,
                &replacement.scope.identity_scope,
                operation,
            )?;
            *current = Some(registry.version());
        }
        replacement.routes_frozen.store(false, Ordering::Release);
        self.active = false;
        Ok(())
    }
    /// Explicit failure recovery before source revocation only. Cancellation,
    /// expired operations, and post-teardown failures must retire instead.
    pub(crate) fn restore(&mut self, operation: &OperationLease) -> Result<(), ProtocolError> {
        self.check_operation(operation)?;
        self.source.check()?;
        let mut current = self
            .source
            .registry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if current.is_some() || !self.source.routes_frozen.load(Ordering::Acquire) {
            return Err(ProtocolError::RegistryInUse);
        }
        if let Some(registry) = &mut self.registry {
            self.source
                .broker
                .restore_registry_transfer(registry, operation)?;
            *current = Some(registry.version());
        }
        self.source.routes_frozen.store(false, Ordering::Release);
        self.active = false;
        Ok(())
    }
    pub(crate) fn retire(&mut self) -> Result<(), ProtocolError> {
        if !self.active {
            return Err(ProtocolError::StaleScope);
        }
        if let Some(registry) = &mut self.registry {
            self.source.broker.retire_registry_transfer(registry)?;
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for RouteTransfer {
    fn drop(&mut self) {
        if self.active {
            let _ = self.retire();
        }
    }
}

/// A terminal route slot is never reconstructed after ordinary revocation.
/// The network retains it until reconnect takes the exact guard or final close
/// explicitly retires it. Empty route lists still have a one-shot authority.
enum DisconnectedRouteSlot {
    Uncaptured,
    Parked(ParkedRoutes),
    Taken,
    Retired,
}
struct ParkedRoutes {
    targets: Arc<super::client_targets::ClientTargets>,
    target_id: String,
    registry: Option<ParkedRouteRegistry>,
}
/// Native-only journal entry for a verified terminal old connection. There is
/// no restore operation: cancellation/failure must explicitly retire this hold.
/// Drop is only a last-resort retirement attempt, never cleanup success proof.
pub(crate) struct DisconnectedRoutes {
    source: Arc<ClientNetwork>,
    parked: ParkedRoutes,
    replacement: Option<(
        Arc<ClientNetwork>,
        Arc<super::client_targets::ClientTargets>,
    )>,
    sequence: u64,
    deadline: std::time::Instant,
    cancellation: tokio::sync::watch::Receiver<CancelSignal>,
    active: bool,
}
impl DisconnectedRoutes {
    fn check_operation(&self, operation: &OperationLease) -> Result<(), ProtocolError> {
        if !self.active {
            return Err(ProtocolError::StaleScope);
        }
        if operation.generation != self.source.scope.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if operation.sequence != self.sequence
            || operation.deadline != self.deadline
            || !operation.cancellation.same_channel(&self.cancellation)
        {
            return Err(ProtocolError::InvalidSequence);
        }
        self.source.broker.validate_reconnect_operation(operation)
    }
    /// Bind once to the exact freshly verified transport and retained host
    /// identity. String equality alone never authorizes a new CDP client.
    pub(super) fn bind(
        &mut self,
        replacement: &Arc<ClientNetwork>,
        targets: &Arc<super::client_targets::ClientTargets>,
        verified: &super::client_reconnect::VerifiedReconnectProof,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.check_operation(operation)?;
        if self.replacement.is_some() {
            return Err(ProtocolError::StaleScope);
        }
        if replacement.scope.generation != self.source.scope.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if Arc::ptr_eq(&self.source, replacement)
            || Arc::ptr_eq(&self.source.client, &replacement.client)
            || !Arc::ptr_eq(&self.source.broker, &replacement.broker)
            || !Arc::ptr_eq(&self.source.blobs, &replacement.blobs)
            || Arc::ptr_eq(&self.parked.targets, targets)
            || replacement.scope.identity_scope.is_empty()
            || replacement.scope.identity_scope == self.source.scope.identity_scope
            || targets.identity_scope != replacement.scope.identity_scope
            || targets.context_id != self.parked.targets.context_id
            || *replacement.client.remote_connection_closed().borrow()
        {
            return Err(ProtocolError::StaleScope);
        }
        verified.check(
            &replacement.client,
            &self.parked.targets.context_id,
            &self.parked.target_id,
            operation,
        )?;
        let owner = replacement
            .client
            .debt_ledger()
            .ok_or(ProtocolError::StaleScope)?;
        if !owner.matches_owner(
            replacement.scope.generation,
            &replacement.scope.identity_scope,
        ) {
            return Err(ProtocolError::StaleScope);
        }
        owner.check_unpublished_operation(operation)?;
        replacement.client.check_cleanup_owner(&Some(owner))?;
        replacement.check()?;
        let current = replacement
            .registry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        replacement.check()?;
        if current.is_some() || replacement.routes_frozen.load(Ordering::Acquire) {
            return Err(ProtocolError::RegistryInUse);
        }
        replacement.routes_frozen.store(true, Ordering::Release);
        self.replacement = Some((replacement.clone(), targets.clone()));
        Ok(())
    }
    pub(crate) fn adopt(
        &mut self,
        targets: &Arc<super::client_targets::ClientTargets>,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.check_operation(operation)?;
        let (replacement, captured_targets) = self
            .replacement
            .as_ref()
            .ok_or(ProtocolError::InvalidArguments)?;
        if !Arc::ptr_eq(targets, captured_targets)
            || *replacement.client.remote_connection_closed().borrow()
        {
            return Err(ProtocolError::StaleScope);
        }
        self.source.check_disconnected_drain()?;
        let mut current = replacement
            .registry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        replacement.check()?;
        if current.is_some() || !replacement.routes_frozen.load(Ordering::Acquire) {
            return Err(ProtocolError::RegistryInUse);
        }
        if let Some(registry) = &mut self.parked.registry {
            self.source.broker.adopt_parked_registry(
                registry,
                &replacement.scope.identity_scope,
                operation,
            )?;
            *current = Some(registry.version());
        } else {
            self.source.broker.validate_reconnect_operation(operation)?;
        }
        replacement.routes_frozen.store(false, Ordering::Release);
        self.active = false;
        Ok(())
    }
    pub(crate) fn retire(&mut self) -> Result<(), ProtocolError> {
        if !self.active {
            return Err(ProtocolError::StaleScope);
        }
        if let Some(registry) = &mut self.parked.registry {
            self.source.broker.retire_parked_registry(registry)?;
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for DisconnectedRoutes {
    fn drop(&mut self) {
        if self.active {
            let _ = self.retire();
        }
    }
}

impl ClientNetwork {
    pub fn new(
        client: Arc<CdpClient>,
        broker: Arc<ClientSession>,
        sink: ClientEventSink,
        scope: BlobScope,
        blobs: Arc<BlobStore>,
        ui_gate: Arc<super::client_ui::UiGate>,
        policy: NetworkPolicy,
    ) -> Self {
        let (cancellation, _) = tokio::sync::watch::channel(CancelSignal::None);
        Self {
            client,
            broker,
            retirement_sink: sink.clone(),
            future_session_sink: Mutex::new(sink),
            app_events: AppEventProjector::new(),
            registry: Mutex::new(None),
            disconnected_routes: Mutex::new(DisconnectedRouteSlot::Uncaptured),
            routes_frozen: AtomicBool::new(false),
            close_gate: tokio::sync::Mutex::new(NetworkCloseState::Open),
            cleanup_drained: AtomicBool::new(false),
            tokens: Mutex::new(HashMap::new()),
            scope,
            policy: Mutex::new(policy),
            blobs,
            aliases: Mutex::new(HashMap::new()),
            sealed: AtomicBool::new(false),
            ui_gate,
            cancellation,
            sessions: Mutex::new(HashMap::new()),
            tasks: Mutex::new(tokio::task::JoinSet::new()),
            blocking_reads: Mutex::new(tokio::task::JoinSet::new()),
            dialog_enabled: AtomicBool::new(false),
            auth_attempts: Mutex::new(std::collections::HashSet::new()),
            request_ids: Mutex::new(HashMap::new()),
            pending_interceptions: Mutex::new(HashMap::new()),
            response_subscriptions: Mutex::new(std::collections::HashSet::new()),
            responses: Mutex::new(HashMap::new()),
            resources: Mutex::new(HashMap::new()),
            downloads: Mutex::new(HashMap::new()),
            download_source: Mutex::new(None),
            download_context: Mutex::new(None),
            download_ready: AtomicBool::new(false),
            download_subscriptions: Mutex::new(std::collections::HashSet::new()),
        }
    }

    pub(crate) fn check_event_sink(&self, sink: &ClientEventSink) -> Result<(), ProtocolError> {
        if !self.retirement_sink.same_client(sink) {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    /// Enrollment is supplied by the scope owner. This module never discovers
    /// targets, changes purposes, adopts bootstrap pages, or resumes execution.
    /// Lifecycle selects only the default for targets enrolled after this
    /// exact operation. Existing sessions and retained callbacks keep theirs.
    pub(crate) fn set_future_session_sink(
        &self,
        staged: ClientEventSink,
        identity_scope: &str,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.check()?;
        if operation.is_callback {
            return Err(ProtocolError::InvalidArguments);
        }
        if identity_scope != self.scope.identity_scope {
            return Err(ProtocolError::StaleScope);
        }
        if operation.generation != self.scope.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if *operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if std::time::Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        let mut source = self
            .future_session_sink
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        staged.validate_stage(&source, operation, identity_scope)?;
        self.check()?;
        *source = staged;
        Ok(())
    }
    #[cfg(test)]
    pub async fn configure_session(
        &self,
        session: ApplicationSession,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.configure_session_observed(session, operation, None)
            .await
    }
    pub(crate) async fn configure_session_observed(
        &self,
        session: ApplicationSession,
        operation: &OperationLease,
        admission: Option<&ServiceWorkerAdmission>,
    ) -> Result<(), ProtocolError> {
        self.prepare_session(session, operation, admission, false)
            .await
    }

    /// Service-worker security controls are browser-side and must acknowledge
    /// before startup is released. Renderer-domain acknowledgements may need
    /// that release, so enrollment completes those in its retained startup batch.
    pub(crate) async fn prepare_service_worker_session(
        &self,
        session: ApplicationSession,
        operation: &OperationLease,
        admission: Option<&ServiceWorkerAdmission>,
    ) -> Result<(), ProtocolError> {
        self.prepare_session(session, operation, admission, true)
            .await
    }

    pub(crate) fn check_worker_startup(
        &self,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.check()?;
        if operation.generation != self.scope.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if *operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if std::time::Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(())
    }
    pub(crate) async fn initialize_service_worker_observation(
        &self,
        session: &str,
        operation: &OperationLease,
    ) -> Result<
        super::cdp::client::ServiceWorkerStartupOutcome,
        super::cdp::client::ServiceWorkerStartupFailure,
    > {
        self.check_worker_startup(operation)?;
        let bypass_service_worker = self
            .policy
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .bypass_service_worker;
        let result = self.client.initialize_service_worker_domains(
            session,
            json!({"maxTotalBufferSize": self.blobs.producer_limit().saturating_mul(2), "maxResourceBufferSize": self.blobs.producer_limit()}),
            bypass_service_worker,
            operation.deadline,
        ).await;
        match result {
            Err(failure) => {
                // Enrollment retains the original failure/permit while a
                // qualified pending attachment awaits exact detach. Neither
                // kind grants Ready or clears quarantine or its CDP message.
                let check = if failure.has_retirement() || failure.has_pending_retirement() {
                    self.check_worker_startup(operation)
                } else {
                    Err(failure.error())
                };
                if let Err(error) = check {
                    let error = self.broker.quarantine().err().unwrap_or(error);
                    return Err(failure.fail_closed(error));
                }
                Err(failure)
            }
            Ok(outcome) => {
                self.check_worker_startup(operation)?;
                Ok(outcome)
            }
        }
    }

    pub(crate) fn quarantine_worker_startup(&self) -> Result<(), ProtocolError> {
        self.broker.quarantine()
    }

    async fn prepare_session(
        &self,
        session: ApplicationSession,
        operation: &OperationLease,
        admission: Option<&ServiceWorkerAdmission>,
        service_worker: bool,
    ) -> Result<(), ProtocolError> {
        self.check()?;
        if operation.generation != self.scope.generation
            || *operation.cancellation.borrow() != CancelSignal::None
        {
            return Err(ProtocolError::Cancelled);
        }
        let policy = *self
            .policy
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let id = session.session_id.clone();
        {
            let sink = self
                .future_session_sink
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if sessions.len() >= 128 || sessions.contains_key(&id) {
                return Err(ProtocolError::CapacityExceeded);
            }
            let (configuration_ready, _) = tokio::sync::watch::channel(false);
            sessions.insert(
                id.clone(),
                EnrolledSession {
                    sink: sink.clone(),
                    application: session,
                    configuration_ready,
                },
            );
        }
        let result = tokio::time::timeout_at(operation.deadline.into(), async {
            if !service_worker {
                ServiceWorkerAdmission::observe(admission, WorkerAdmissionStep::NetworkEnable,
                    self.client.send_command("Network.enable", Some(json!({"maxTotalBufferSize": self.blobs.producer_limit().saturating_mul(2), "maxResourceBufferSize": self.blobs.producer_limit()})), Some(&id))).await?;
            }
            if policy.bypass_service_worker && !service_worker { ServiceWorkerAdmission::observe(admission, WorkerAdmissionStep::NetworkBypass,
                self.client.send_command("Network.setBypassServiceWorker",Some(json!({"bypass":true})),Some(&id))).await?; }
            ServiceWorkerAdmission::observe(admission, WorkerAdmissionStep::FetchEnable,
                self.client.send_command("Fetch.enable", Some(json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}],"handleAuthRequests":true})), Some(&id))).await?;
            Ok::<(), String>(())
        }).await;
        if !matches!(result, Ok(Ok(()))) {
            self.broker.quarantine()?;
            return Err(ProtocolError::BrowserFailure);
        }
        self.check()
    }

    /// Opens this exact session's managed network callbacks. Page enrollment
    /// waits for full configuration; service-worker enrollment opens after
    /// Fetch policy and recursive attachment ACKs, while its retained startup
    /// permit still blocks target readiness until all observer ACKs arrive.
    /// Existing route/auth policy, publication, UI and tenure guards remain.
    pub(crate) fn configuration_committed(
        &self,
        session: &str,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.check()?;
        if operation.generation != self.scope.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if *operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if std::time::Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        self.check()?;
        let session = sessions.get(session).ok_or(ProtocolError::StaleScope)?;
        session.configuration_ready.send_replace(true);
        Ok(())
    }
    async fn wait_for_configuration(
        &self,
        mut ready: tokio::sync::watch::Receiver<bool>,
        deadline: std::time::Instant,
    ) -> Result<(), ProtocolError> {
        let mut cancellation = self.cancellation.subscribe();
        loop {
            self.check()?;
            if *cancellation.borrow() != CancelSignal::None {
                return Err(ProtocolError::Cancelled);
            }
            if std::time::Instant::now() >= deadline {
                return Err(ProtocolError::DeadlineExceeded);
            }
            if *ready.borrow() {
                return Ok(());
            }
            tokio::select! {
                changed=ready.changed()=>changed.map_err(|_|ProtocolError::StaleScope)?,
                _=cancellation.changed()=>return Err(ProtocolError::Cancelled),
                _=tokio::time::sleep_until(deadline.into())=>return Err(ProtocolError::DeadlineExceeded),
            }
        }
    }
    /// Caller holds the enrollment configuration gate, so no new target can
    /// install an old policy between existing-session ACKs and this publication.
    pub async fn update_policy(
        &self,
        policy: NetworkPolicy,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.check()?;
        if operation.generation != self.scope.generation {
            return Err(ProtocolError::StaleScope);
        }
        if *operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if std::time::Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        let sessions: Vec<_> = self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .keys()
            .cloned()
            .collect();
        let mut cancellation = operation.cancellation.clone();
        let update = async {
            for session in sessions {
                self.client
                    .send_command(
                        "Network.setBypassServiceWorker",
                        Some(json!({"bypass":policy.bypass_service_worker})),
                        Some(&session),
                    )
                    .await
                    .map_err(|_| ProtocolError::BrowserFailure)?;
            }
            self.check()?;
            *self
                .policy
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)? = policy;
            Ok(())
        };
        let result = tokio::select! {
            result=update=>result,
            _=tokio::time::sleep_until(operation.deadline.into())=>Err(ProtocolError::DeadlineExceeded),
            _=cancellation.changed()=>Err(ProtocolError::Cancelled),
        };
        // Some sessions may already have accepted the new policy. Never expose
        // an incompletely configured scope as safely reusable.
        if result.is_err() {
            self.broker.quarantine()?;
        }
        result
    }

    /// Native owner identity check only; this does not grant or change UI admission.
    pub(crate) fn uses_ui_gate(&self, gate: &Arc<super::client_ui::UiGate>) -> bool {
        Arc::ptr_eq(&self.ui_gate, gate)
    }

    fn validate_app_page(&self, page: &BrowserExecutionLease) -> Result<(), ProtocolError> {
        page.permit.check()?;
        self.check()?;
        if page.identity_scope != self.scope.identity_scope
            || !Arc::ptr_eq(&page.client, &self.client)
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    pub(crate) fn begin_app_navigation(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<OwnNavigationGuard, ProtocolError> {
        self.validate_app_page(page)?;
        if op.generation != self.scope.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if *op.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if std::time::Instant::now() >= op.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let session = sessions
            .get(&page.page_session_id)
            .ok_or(ProtocolError::StaleReference)?;
        if !session.application.active_page
            || session.application.root_page_session != page.page_session_id
        {
            return Err(ProtocolError::StaleReference);
        }
        self.app_events.begin_navigation(&page.page_session_id)
    }
    /// Existing enrollment event pump supplies exact Application/frame identity.
    /// Keep its lease alive through the synchronous projection and publication.
    pub(crate) fn publish_app_event(
        &self,
        page: &BrowserExecutionLease,
        event: &CdpEvent,
        navigation: Option<AppNavigationContext<'_>>,
    ) -> Result<(), ProtocolError> {
        self.validate_app_page(page)?;
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if !sessions.contains_key(&page.page_session_id)
            || event.session_id.as_deref() != Some(page.page_session_id.as_str())
        {
            return Err(ProtocolError::StaleReference);
        }
        let projected = self.app_events.project(
            event,
            AppEventContext {
                session_id: &page.page_session_id,
                navigation,
            },
        )?;
        self.validate_app_page(page)?;
        if let Some(projected) = projected {
            let (name, payload) = projected.into_wire(&self.scope.identity_scope)?;
            sessions
                .get(&page.page_session_id)
                .ok_or(ProtocolError::StaleReference)?
                .sink
                .emit(name.into(), payload, None)?;
        }
        Ok(())
    }
    pub fn set_active_root(&self, root: &str) -> Result<(), ProtocolError> {
        self.check()?;
        for session in self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .values_mut()
        {
            session.application.active_page = session.application.root_page_session == root;
        }
        Ok(())
    }
    pub fn detach_session(&self, session: &str) -> Result<(), ProtocolError> {
        self.request_ids
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .retain(|(owner, _), _| owner != session);
        self.auth_attempts
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .retain(|(owner, _)| owner != session);
        self.sessions
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .remove(session);
        let tokens: Vec<_> = {
            let mut tokens = self
                .tokens
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            let removed: Vec<_> = tokens
                .iter()
                .filter(|(_, owner)| owner.as_str() == session)
                .map(|(token, _)| token.clone())
                .collect();
            for token in &removed {
                tokens.remove(token);
            }
            removed
        };
        for token in tokens {
            self.broker.revoke_decision(&token)?;
            self.blobs
                .discard_reserved(&token)
                .map_err(|_| ProtocolError::CleanupFailed)?;
        }
        let handles: Vec<_> = {
            let mut responses = self
                .responses
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            let keys: Vec<_> = responses
                .keys()
                .filter(|(owner, _)| owner == session)
                .cloned()
                .collect();
            keys.into_iter()
                .filter_map(|key| responses.remove(&key))
                .collect()
        };
        for handle in handles {
            self.finish_resource(&handle, Err(ProtocolError::StaleScope))?;
        }
        self.app_events.forget_session(session)
    }

    pub fn register_dialog(&self, enabled: bool) -> Result<(), ProtocolError> {
        self.check()?;
        self.dialog_enabled.store(enabled, Ordering::Release);
        Ok(())
    }

    pub fn subscribe_responses(&self) -> Result<String, ProtocolError> {
        self.check()?;
        let mut subscriptions = self
            .response_subscriptions
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if subscriptions.len() >= 64 {
            return Err(ProtocolError::CapacityExceeded);
        }
        let id = uuid::Uuid::new_v4().to_string();
        subscriptions.insert(id.clone());
        Ok(id)
    }
    pub fn unsubscribe_responses(&self, id: &str) -> Result<(), ProtocolError> {
        self.response_subscriptions
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .remove(id);
        Ok(())
    }

    /// Paths come from the scope owner/provider configuration, never a public
    /// file-read command. Remote directories are never opened on this host.
    pub async fn configure_downloads(
        &self,
        context_id: &str,
        source: DownloadSource,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.check_download_operation(operation)?;
        if context_id.is_empty() || context_id.len() > 1024 || context_id.contains('\0') {
            return Err(ProtocolError::InvalidArguments);
        }
        let mut cancellation = operation.cancellation.clone();
        let mut scope_cancellation = self.cancellation.subscribe();
        let directory = match &source {
            DownloadSource::Local(directory) => {
                let directory = directory.clone();
                let (sent, received) = tokio::sync::oneshot::channel();
                // Even cancellation of setup cannot detach an outstanding
                // filesystem job from the scope's retained reader drain.
                {
                    let mut readers = self
                        .blocking_reads
                        .lock()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?;
                    self.check_download_operation(operation)?;
                    while let Some(result) = readers.try_join_next() {
                        result.map_err(|_| ProtocolError::CleanupFailed)?;
                    }
                    if readers.len() >= 64 {
                        return Err(ProtocolError::CapacityExceeded);
                    }
                    readers.spawn_blocking(move || {
                        let result = std::fs::canonicalize(&directory)
                            .map_err(|_| ProtocolError::InvalidArguments)
                            .and_then(|canonical| {
                                if canonical != directory || !canonical.is_dir() {
                                    Err(ProtocolError::InvalidArguments)
                                } else {
                                    Ok(canonical.to_string_lossy().into_owned())
                                }
                            });
                        let _ = sent.send(result);
                    });
                }
                tokio::select! {
                    biased;
                    _=cancellation.changed()=>return Err(ProtocolError::Cancelled),
                    _=scope_cancellation.changed()=>return Err(ProtocolError::Cancelled),
                    _=tokio::time::sleep_until(operation.deadline.into())=>return Err(ProtocolError::DeadlineExceeded),
                    result=received=>result.map_err(|_|ProtocolError::BrowserFailure)??,
                }
            }
            DownloadSource::Provider(directory) => {
                if directory.is_empty() || directory.contains('\0') {
                    return Err(ProtocolError::InvalidArguments);
                }
                directory.clone()
            }
        };
        self.check_download_operation(operation)?;
        {
            let mut current = self
                .download_source
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            let mut context = self
                .download_context
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if current.is_some() || context.is_some() {
                return Err(ProtocolError::InvalidArguments);
            }
            // Journal before dispatch: lost ACK never relinquishes the source
            // or allows a second setup to overwrite uncertain browser policy.
            *context = Some(context_id.into());
            *current = Some(source);
        }
        let mut dispatched = DownloadSetupDispatch {
            broker: &self.broker,
            completed: false,
        };
        let result = tokio::select! {
            biased;
            _=cancellation.changed()=>Err(ProtocolError::Cancelled),
            _=scope_cancellation.changed()=>Err(ProtocolError::Cancelled),
            _=tokio::time::sleep_until(operation.deadline.into())=>Err(ProtocolError::DeadlineExceeded),
            result=self.client.send_command("Browser.setDownloadBehavior",Some(json!({"behavior":"allowAndName","browserContextId":context_id,"downloadPath":directory,"eventsEnabled":true})),None)=>result.map(|_|()).map_err(|_|ProtocolError::BrowserFailure),
        };
        result?;
        self.check_download_operation(operation)?;
        self.download_ready.store(true, Ordering::Release);
        dispatched.completed = true;
        Ok(())
    }
    fn check_download_operation(&self, operation: &OperationLease) -> Result<(), ProtocolError> {
        self.check()?;
        if operation.generation != self.scope.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if *operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if std::time::Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(())
    }
    pub fn subscribe_downloads(&self) -> Result<String, ProtocolError> {
        self.check()?;
        if !self.download_ready.load(Ordering::Acquire) {
            return Err(ProtocolError::UnsupportedCapability);
        }
        let mut subscriptions = self
            .download_subscriptions
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if subscriptions.len() >= 64 {
            return Err(ProtocolError::CapacityExceeded);
        }
        let id = uuid::Uuid::new_v4().to_string();
        subscriptions.insert(id.clone());
        Ok(id)
    }
    pub fn unsubscribe_downloads(&self, id: &str) -> Result<(), ProtocolError> {
        self.download_subscriptions
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .remove(id);
        Ok(())
    }

    fn download_started(
        &self,
        session: &ApplicationSession,
        params: &Value,
        sink: &ClientEventSink,
    ) -> Result<(), ProtocolError> {
        if self
            .download_source
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .is_none()
        {
            return Err(ProtocolError::UnsupportedCapability);
        }
        let guid = required_string(params, "guid")?;
        if !safe_basename(guid) {
            return Err(ProtocolError::InvalidArguments);
        }
        let published = !self
            .download_subscriptions
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .is_empty();
        let mut downloads = self
            .downloads
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if downloads.len() >= 128 || downloads.contains_key(guid) {
            return Err(ProtocolError::CapacityExceeded);
        }
        let reservation = self
            .blobs
            .reserve_producer(self.scope.clone())
            .map_err(producer_error)?;
        let (handle, resource) = self.new_resource()?;
        downloads.insert(
            guid.into(),
            DownloadEntry {
                handle: handle.clone(),
                resource,
                completed: false,
                terminal_started: false,
                published,
                reservation: Some(reservation),
            },
        );
        if !published {
            return Ok(());
        }
        sink.emit("download.started".into(),json!({"identityScope":self.scope.identity_scope,"activePage":session.active_page,"handle":handle,"suggestedFilename":required_string(params,"suggestedFilename")?}),None)
    }
    async fn download_finished(&self, params: Value) -> Result<(), ProtocolError> {
        let guid = required_string(&params, "guid")?;
        let state = required_string(&params, "state")?;
        let oversized = params
            .get("receivedBytes")
            .and_then(Value::as_f64)
            .is_some_and(|size| size > self.blobs.producer_limit() as f64);
        if oversized {
            let context = self
                .download_context
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .clone()
                .ok_or(ProtocolError::StaleScope)?;
            self.client
                .send_command(
                    "Browser.cancelDownload",
                    Some(json!({"guid":guid,"browserContextId":context})),
                    None,
                )
                .await
                .map_err(|_| ProtocolError::BrowserFailure)?;
            let handle = {
                let mut downloads = self
                    .downloads
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                let Some(entry) = downloads.get_mut(guid) else {
                    return Ok(());
                };
                entry.completed = true;
                entry.handle.clone()
            };
            return self.finish_download(&handle, Err(ProtocolError::CapacityExceeded));
        }
        if !matches!(state, "completed" | "canceled") {
            return Ok(());
        }
        let handle = {
            let mut downloads = self
                .downloads
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            let Some(entry) = downloads.get_mut(guid) else {
                return Ok(());
            };
            if entry.completed {
                return Ok(());
            }
            entry.completed = true;
            entry.handle.clone()
        };
        if state == "canceled" {
            return self.finish_download(&handle, Err(ProtocolError::BrowserFailure));
        }
        let source = self
            .download_source
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .clone()
            .ok_or(ProtocolError::UnsupportedCapability)?;
        match source {
            DownloadSource::Provider(_) => {
                self.finish_download(&handle, Ok(format!("provider:{guid}")))
            }
            DownloadSource::Local(directory) => {
                let result = async {
                    let producer = self
                        .downloads
                        .lock()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?
                        .get_mut(guid)
                        .and_then(|entry| entry.reservation.take())
                        .ok_or(ProtocolError::CapacityExceeded)?;
                    let limit = self.blobs.producer_limit();
                    let basename = guid.to_owned();
                    let (sender, receiver) = tokio::sync::oneshot::channel();
                    {
                        let mut readers = self
                            .blocking_reads
                            .lock()
                            .map_err(|_| ProtocolError::ScopeUnavailable)?;
                        while let Some(result) = readers.try_join_next() {
                            if result.is_err() {
                                return Err(ProtocolError::CleanupFailed);
                            }
                        }
                        if readers.len() >= 2 {
                            return Err(ProtocolError::CapacityExceeded);
                        }
                        readers.spawn_blocking(move || {
                            let bytes = read_owned_download(&directory, &basename, limit);
                            let _ = sender.send((producer, bytes));
                        });
                    }
                    let (producer, bytes) =
                        receiver.await.map_err(|_| ProtocolError::BrowserFailure)?;
                    let bytes = bytes?;
                    self.check()?;
                    self.blobs
                        .finish_producer(producer, bytes)
                        .map(|blob| blob.handle)
                        .map_err(producer_error)
                }
                .await;
                self.finish_download(&handle, result)
            }
        }
    }
    fn finish_download(
        &self,
        handle: &str,
        result: Result<String, ProtocolError>,
    ) -> Result<(), ProtocolError> {
        if result.is_err() {
            if let Some(entry) = self
                .downloads
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .values_mut()
                .find(|entry| entry.handle == handle)
            {
                entry.reservation.take();
            }
        }
        self.finish_resource(handle, result)?;
        let published = self
            .downloads
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .values()
            .find(|entry| entry.handle == handle)
            .is_some_and(|entry| entry.published);
        if !published {
            self.release_body(handle)?;
        }
        Ok(())
    }
    pub async fn download_metadata(
        &self,
        handle: &str,
        operation: &OperationLease,
    ) -> Result<Value, ProtocolError> {
        self.check()?;
        let (guid, resource) = {
            let downloads = self
                .downloads
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            downloads
                .iter()
                .find(|(_, entry)| entry.handle == handle)
                .map(|(guid, entry)| (guid.clone(), entry.resource.clone()))
                .ok_or(ProtocolError::InvalidArguments)?
        };
        let mut receiver = resource.completed.subscribe();
        let mut cancellation = operation.cancellation.clone();
        loop {
            self.check()?;
            if *cancellation.borrow() != CancelSignal::None {
                return Err(ProtocolError::Cancelled);
            }
            if let Some(result) = receiver.borrow().clone() {
                let value = result?;
                return if value.starts_with("provider:") {
                    Ok(
                        json!({"identityScope":self.scope.identity_scope,"source":"provider","basename":guid}),
                    )
                } else {
                    Ok(json!({"identityScope":self.scope.identity_scope,"source":"local"}))
                };
            }
            tokio::select! { _=tokio::time::sleep_until(operation.deadline.into())=>return Err(ProtocolError::DeadlineExceeded), _=cancellation.changed()=>return Err(ProtocolError::Cancelled), result=receiver.changed()=> { result.map_err(|_|ProtocolError::ScopeUnavailable)?; } }
        }
    }

    /// Called by the one owner event pump. Never awaits a JavaScript callback.
    /// Bounded task overflow poisons the scope instead of dropping paused work.
    pub fn event(self: &Arc<Self>, event: &CdpEvent) -> Result<(), ProtocolError> {
        self.event_internal(event, None)
    }
    pub fn event_with_budget(
        self: &Arc<Self>,
        event: &CdpEvent,
        budget: super::cdp::client::EventBudgetLease,
    ) -> Result<(), ProtocolError> {
        self.event_internal(event, Some(budget))
    }
    fn event_internal(
        self: &Arc<Self>,
        event: &CdpEvent,
        budget: Option<super::cdp::client::EventBudgetLease>,
    ) -> Result<(), ProtocolError> {
        self.check()?;
        // configure_downloads requires Browser.setDownloadBehavior with eventsEnabled
        // before subscription. The deprecated Page stream reports the same GUID
        // and must not create or complete a second resource, even after release.
        if matches!(
            event.method.as_str(),
            "Page.downloadWillBegin" | "Page.downloadProgress"
        ) {
            return Ok(());
        }
        if event.method == "Browser.downloadProgress" {
            let guid = required_string(&event.params, "guid")?;
            let terminal = matches!(
                event.params.get("state").and_then(Value::as_str),
                Some("completed" | "canceled")
            ) || event
                .params
                .get("receivedBytes")
                .and_then(Value::as_f64)
                .is_some_and(|size| size > self.blobs.producer_limit() as f64);
            if !terminal {
                return Ok(());
            }
            {
                let mut downloads = self
                    .downloads
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                let Some(entry) = downloads.get_mut(guid) else {
                    return Ok(());
                };
                if entry.terminal_started {
                    return Ok(());
                }
                entry.terminal_started = true;
            }
            let mut tasks = self
                .tasks
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if self.sealed.load(Ordering::Acquire) {
                return Err(ProtocolError::StaleScope);
            }
            while let Some(result) = tasks.try_join_next() {
                if !matches!(result, Ok(Ok(()))) {
                    self.broker.quarantine()?;
                    return Err(ProtocolError::BrowserFailure);
                }
            }
            if tasks.len() >= 64 {
                self.broker.quarantine()?;
                return Err(ProtocolError::CapacityExceeded);
            }
            let this = self.clone();
            let params = event.params.clone();
            tasks.spawn(async move {
                let _budget = budget;
                this.download_finished(params).await
            });
            return Ok(());
        }
        let Some(session_id) = event.session_id.as_deref() else {
            return Ok(());
        };
        let session = self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .get(session_id)
            .cloned();
        let Some(session) = session else {
            return Ok(());
        };
        let sink = session.sink.clone();
        let configuration_ready = session.configuration_ready.subscribe();
        let session_tenure = configuration_ready.clone();
        let session = session.application;
        if event.method == "Browser.downloadWillBegin" {
            return self.download_started(&session, &event.params, &sink);
        }
        let supported = matches!(
            event.method.as_str(),
            "Fetch.requestPaused"
                | "Fetch.authRequired"
                | "Page.javascriptDialogOpening"
                | "Network.responseReceived"
                | "Network.requestWillBeSent"
                | "Network.loadingFinished"
                | "Network.loadingFailed"
        );
        if !supported {
            return Ok(());
        }
        if event.method == "Network.requestWillBeSent" {
            if let Some(response) = event.params.get("redirectResponse") {
                if !self
                    .response_subscriptions
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .is_empty()
                {
                    let (handle, _) = self.new_resource()?;
                    self.finish_resource(&handle, Err(ProtocolError::RedirectBodyUnavailable))?;
                    sink.emit("network.response".into(),json!({"identityScope":self.scope.identity_scope,"activePage":session.active_page,"handle":handle,"url":required_string(response,"url")?,"status":response.get("status"),"headers":response.get("headers")}),None)?;
                }
            }
            return Ok(());
        }
        let pending_key = match event.method.as_str() {
            "Fetch.requestPaused" | "Fetch.authRequired" => Some((
                session_id.to_owned(),
                event.method.clone(),
                required_string(&event.params, "requestId")?.to_owned(),
            )),
            "Page.javascriptDialogOpening" => {
                Some((session_id.to_owned(), event.method.clone(), String::new()))
            }
            _ => None,
        };
        if let Some(key) = &pending_key {
            let mut pending = self
                .pending_interceptions
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if pending.len() >= 2048 {
                return Err(ProtocolError::CapacityExceeded);
            }
            pending.insert(key.clone(), ());
        }
        // Accounting happens in event order before tasks are launched.
        if event.method == "Fetch.requestPaused" {
            if let Some(network_id) = event.params.get("networkId").and_then(Value::as_str) {
                let fetch_id = required_string(&event.params, "requestId")?;
                let mut ids = self
                    .request_ids
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if ids.len() >= 2048 {
                    return Err(ProtocolError::CapacityExceeded);
                }
                if let Some(previous) =
                    ids.insert((session_id.into(), network_id.into()), fetch_id.into())
                {
                    self.auth_attempts
                        .lock()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?
                        .remove(&(session_id.into(), previous));
                }
            }
        }
        if matches!(
            event.method.as_str(),
            "Network.loadingFinished" | "Network.loadingFailed"
        ) {
            let network_id = required_string(&event.params, "requestId")?;
            if let Some(fetch_id) = self
                .request_ids
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .remove(&(session_id.into(), network_id.into()))
            {
                self.auth_attempts
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .remove(&(session_id.into(), fetch_id));
            }
        }

        if event.method == "Network.responseReceived" {
            if self
                .response_subscriptions
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .is_empty()
            {
                return Ok(());
            }
            let id = required_string(&event.params, "requestId")?;
            let response = event
                .params
                .get("response")
                .cloned()
                .ok_or(ProtocolError::InvalidArguments)?;
            let mut responses = self
                .responses
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if responses.len() >= 128 {
                self.broker.quarantine()?;
                return Err(ProtocolError::CapacityExceeded);
            }
            let (handle, _) = self.new_resource()?;
            responses.insert((session_id.into(), id.into()), handle.clone());
            sink.emit("network.response".into(),json!({"identityScope":self.scope.identity_scope,"activePage":session.active_page,"handle":handle,"url":required_string(&response,"url")?,"status":response.get("status"),"headers":response.get("headers")}),None)?;
            return Ok(());
        }
        if event.method == "Network.loadingFinished" {
            let id = required_string(&event.params, "requestId")?;
            if !self
                .responses
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .contains_key(&(session_id.into(), id.into()))
            {
                return Ok(());
            }
        }
        if event.method == "Network.loadingFailed" {
            let id = required_string(&event.params, "requestId")?;
            if let Some(handle) = self
                .responses
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .remove(&(session_id.into(), id.into()))
            {
                // Exact native net-error allowlist, never expose arbitrary backend text.
                let error = match event.params.get("errorText").and_then(Value::as_str) {
                    Some("net::ERR_CONTENT_LENGTH_MISMATCH") => {
                        ProtocolError::ContentLengthMismatch
                    }
                    _ => ProtocolError::BrowserFailure,
                };
                self.finish_resource(&handle, Err(error))?;
            }
            return Ok(());
        }
        let mut tasks = self
            .tasks
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if self.sealed.load(Ordering::Acquire) {
            return Err(ProtocolError::StaleScope);
        }
        while let Some(result) = tasks.try_join_next() {
            if !matches!(result, Ok(Ok(()))) {
                self.broker.quarantine()?;
                return Err(ProtocolError::BrowserFailure);
            }
        }
        if tasks.len() >= 64 {
            self.broker.quarantine()?;
            return Err(ProtocolError::CapacityExceeded);
        }
        let callback_event = matches!(
            event.method.as_str(),
            "Fetch.requestPaused" | "Fetch.authRequired" | "Page.javascriptDialogOpening"
        );
        let unpublished_callback = callback_event && sink.is_publication_pending()?;
        // A paused request from an unpublished page must not reserve UI ahead
        // of the lifecycle owner's exclusive restore/import work. Live-session
        // callbacks retain their original immediate reservation ordering.
        let callback_reservation = if callback_event && !unpublished_callback {
            Some(self.ui_gate.reserve_callback()?)
        } else {
            None
        };
        let captured = if event.method == "Fetch.requestPaused" {
            Some(self.capture_request(&session.session_id, DecisionOwner::Scope, 30_000)?)
        } else {
            None
        };
        let this = self.clone();
        let event = event.clone();
        tasks.spawn(async move {
            let _budget = budget;
            let deadline = captured
                .as_ref()
                .map(|lease| lease.deadline)
                .unwrap_or_else(|| std::time::Instant::now() + std::time::Duration::from_secs(30));
            let _pending_token_cleanup = captured.as_ref().map(|lease| TokenCleanup {
                network: &this,
                token: lease.token.clone(),
            });
            if callback_event {
                if let Err(error) = this
                    .wait_for_configuration(configuration_ready, deadline)
                    .await
                {
                    if !this.session_tenure_live(&session.session_id, &session_tenure)? {
                        return Ok(());
                    }
                    // No callback/default Continue is emitted before commit.
                    // A timed-out admission can only abort the held request.
                    if event.method == "Fetch.requestPaused" {
                        let request_id = required_string(&event.params, "requestId")?;
                        if matches!(
                            tokio::time::timeout(
                                std::time::Duration::from_secs(2),
                                this.abort_request(&session.session_id, request_id),
                            )
                            .await,
                            Ok(Ok(()))
                        ) {
                            if let Some(key) = &pending_key {
                                this.pending_interceptions
                                    .lock()
                                    .map_err(|_| ProtocolError::CleanupFailed)?
                                    .remove(key);
                            }
                        }
                    }
                    return Err(error);
                }
            }
            let callback_reservation = if unpublished_callback {
                if let Err(error) = sink
                    .wait_publication(deadline, this.cancellation.subscribe())
                    .await
                {
                    if !this.session_tenure_live(&session.session_id, &session_tenure)? {
                        return Ok(());
                    }
                    return Err(error);
                }
                if !this.session_tenure_live(&session.session_id, &session_tenure)? {
                    return Ok(());
                }
                Some(this.ui_gate.reserve_callback()?)
            } else {
                callback_reservation
            };
            let _callback_permit = if let Some(reservation) = callback_reservation {
                match reservation
                    .enter(deadline, this.cancellation.subscribe())
                    .await
                {
                    Ok(permit) => Some(permit),
                    Err(error) => {
                        if !this.session_tenure_live(&session.session_id, &session_tenure)? {
                            return Ok(());
                        }
                        if !this.sealed.load(Ordering::Acquire) {
                            let _ = this.broker.quarantine();
                        }
                        return Err(error);
                    }
                }
            } else {
                None
            };
            // An exclusive page replacement may retire this session while its
            // callback waits. Neither the same scope nor a reused textual ID
            // grants the old event authority over the replacement document.
            if !this.session_tenure_live(&session.session_id, &session_tenure)? {
                return Ok(());
            }
            let result = match event.method.as_str() {
                "Fetch.requestPaused" => {
                    this.paused_request_captured(
                        &session.session_id,
                        event.params,
                        captured.ok_or(ProtocolError::DecisionMissing)?,
                        &sink,
                    )
                    .await
                }
                "Fetch.authRequired" => {
                    this.authentication(&session.session_id, event.params, &sink)
                        .await
                }
                "Page.javascriptDialogOpening" => {
                    this.dialog(&session.session_id, event.params, &sink).await
                }
                "Network.loadingFinished" => {
                    this.response_finished(&session, event.params, deadline, &session_tenure)
                        .await
                }
                _ => Ok(()),
            };
            if result.is_ok() {
                if let Some(key) = pending_key {
                    this.pending_interceptions
                        .lock()
                        .map_err(|_| ProtocolError::CleanupFailed)?
                        .remove(&key);
                }
            }
            if !this
                .sessions
                .lock()
                .is_ok_and(|sessions| sessions.contains_key(&session.session_id))
            {
                return Ok(());
            }
            if result.is_err()
                && !this.sealed.load(Ordering::Acquire)
                && this
                    .sessions
                    .lock()
                    .is_ok_and(|sessions| sessions.contains_key(&session.session_id))
            {
                let _ = this.broker.quarantine();
            }
            result
        });
        Ok(())
    }

    pub(crate) async fn settle_borrowed_event(
        &self,
        event: &CdpEvent,
    ) -> Result<(), ProtocolError> {
        let Some(session) = event.session_id.as_deref() else {
            return Ok(());
        };
        if !self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?
            .contains_key(session)
        {
            return Ok(());
        }
        let command = match event.method.as_str() {
            "Fetch.requestPaused" => ScopeCleanupCommand::FailRequest {
                session: session.to_owned(),
                request: required_string(&event.params, "requestId")?.to_owned(),
            },
            "Fetch.authRequired" => ScopeCleanupCommand::CancelAuth {
                session: session.to_owned(),
                request: required_string(&event.params, "requestId")?.to_owned(),
            },
            "Page.javascriptDialogOpening" => ScopeCleanupCommand::DismissDialog {
                session: session.to_owned(),
            },
            _ => return Ok(()),
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        tokio::time::timeout_at(
            deadline.into(),
            self.client.send_scope_cleanup(command, deadline),
        )
        .await
        .map_err(|_| ProtocolError::CleanupFailed)?
        .map_err(|_| ProtocolError::CleanupFailed)?;
        Ok(())
    }
    /// After the event reader and retained callbacks have drained, undo only
    /// interception installed by this connection. Never closes a host target.
    /// Caller still detaches if any acknowledgement below is unknown.
    pub(crate) async fn release_borrowed_interception(
        &self,
        identity_scope: &str,
        session: &str,
        deadline: std::time::Instant,
    ) -> Result<(), ProtocolError> {
        if identity_scope != self.scope.identity_scope {
            return Err(ProtocolError::StaleScope);
        }
        if !self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?
            .contains_key(session)
        {
            return Err(ProtocolError::StaleScope);
        }
        let pending: Vec<_> = self
            .pending_interceptions
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?
            .keys()
            .filter(|(owner, _, _)| owner == session)
            .cloned()
            .collect();
        let mut failed = false;
        for key in pending {
            if std::time::Instant::now() >= deadline {
                failed = true;
                break;
            }
            let command = match key.1.as_str() {
                "Fetch.requestPaused" => ScopeCleanupCommand::FailRequest {
                    session: session.to_owned(),
                    request: key.2.clone(),
                },
                "Fetch.authRequired" => ScopeCleanupCommand::CancelAuth {
                    session: session.to_owned(),
                    request: key.2.clone(),
                },
                "Page.javascriptDialogOpening" => ScopeCleanupCommand::DismissDialog {
                    session: session.to_owned(),
                },
                _ => return Err(ProtocolError::CleanupFailed),
            };
            if matches!(
                tokio::time::timeout_at(
                    deadline.into(),
                    self.client.send_scope_cleanup(command, deadline)
                )
                .await,
                Ok(Ok(_))
            ) {
                self.pending_interceptions
                    .lock()
                    .map_err(|_| ProtocolError::CleanupFailed)?
                    .remove(&key);
            } else {
                failed = true;
            }
        }
        for command in [
            ScopeCleanupCommand::DisableFetch {
                session: session.to_owned(),
            },
            ScopeCleanupCommand::DisableNetwork {
                session: session.to_owned(),
            },
        ] {
            if std::time::Instant::now() >= deadline {
                failed = true;
                break;
            }
            if !matches!(
                tokio::time::timeout_at(
                    deadline.into(),
                    self.client.send_scope_cleanup(command, deadline)
                )
                .await,
                Ok(Ok(_))
            ) {
                failed = true;
            }
        }
        if failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
    fn session_tenure_live(
        &self,
        session: &str,
        captured: &tokio::sync::watch::Receiver<bool>,
    ) -> Result<bool, ProtocolError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        Ok(sessions.get(session).is_some_and(|current| {
            current
                .configuration_ready
                .subscribe()
                .same_channel(captured)
        }))
    }

    fn check_terminal_proof(
        self: &Arc<Self>,
        proof: &super::client_enrollment::NativeTerminalProof,
    ) -> Result<(), ProtocolError> {
        proof.check_network(self)?;
        proof.check_client(&self.client)?;
        if proof.generation() != self.scope.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if proof.targets().identity_scope != self.scope.identity_scope
            || proof.targets().context_id.is_empty()
            || proof.active_target().is_empty()
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    fn park_disconnected_routes(
        self: &Arc<Self>,
        proof: &super::client_enrollment::NativeTerminalProof,
    ) -> Result<(), ProtocolError> {
        self.check_terminal_proof(proof)?;
        let mut slot = self
            .disconnected_routes
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if !matches!(*slot, DisconnectedRouteSlot::Uncaptured) {
            return Err(ProtocolError::StaleScope);
        }
        let mut current = self
            .registry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        self.check()?;
        if self.routes_frozen.load(Ordering::Acquire) {
            return Err(ProtocolError::RegistryInUse);
        }
        let registry = current
            .map(|version| {
                self.broker.park_registry(
                    self.scope.generation,
                    version,
                    &self.scope.identity_scope,
                )
            })
            .transpose()?;
        self.routes_frozen.store(true, Ordering::Release);
        *current = None;
        *slot = DisconnectedRouteSlot::Parked(ParkedRoutes {
            targets: proof.targets().clone(),
            target_id: proof.active_target().to_owned(),
            registry,
        });
        Ok(())
    }
    fn check_disconnected_drain(&self) -> Result<(), ProtocolError> {
        if !*self.client.remote_connection_closed().borrow()
            || !self.sealed.load(Ordering::Acquire)
            || !self.cleanup_drained.load(Ordering::Acquire)
            || !self
                .tokens
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .is_empty()
        {
            return Err(ProtocolError::RegistryInUse);
        }
        Ok(())
    }
    /// Called by the retained reconnect supervisor, after terminal retirement
    /// has joined every old callback and body reader. Rejections leave the exact
    /// hold in this owner; success moves it once into the supervisor journal.
    pub(crate) fn take_disconnected_routes(
        self: &Arc<Self>,
        targets: &Arc<super::client_targets::ClientTargets>,
        operation: &OperationLease,
    ) -> Result<DisconnectedRoutes, ProtocolError> {
        if operation.generation != self.scope.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        self.broker.validate_reconnect_operation(operation)?;
        self.check_disconnected_drain()?;
        let mut slot = self
            .disconnected_routes
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let DisconnectedRouteSlot::Parked(parked) = &mut *slot else {
            return Err(ProtocolError::StaleScope);
        };
        if !Arc::ptr_eq(targets, &parked.targets)
            || targets.identity_scope != self.scope.identity_scope
        {
            return Err(ProtocolError::StaleScope);
        }
        if let Some(registry) = &mut parked.registry {
            self.broker.bind_parked_registry(registry, operation)?;
        }
        let DisconnectedRouteSlot::Parked(parked) =
            std::mem::replace(&mut *slot, DisconnectedRouteSlot::Taken)
        else {
            unreachable!("parked route slot checked under lock")
        };
        Ok(DisconnectedRoutes {
            source: self.clone(),
            parked,
            replacement: None,
            sequence: operation.sequence,
            deadline: operation.deadline,
            cancellation: operation.cancellation.clone(),
            active: true,
        })
    }
    fn retire_disconnected_routes(&self) -> Result<(), ProtocolError> {
        let mut slot = self
            .disconnected_routes
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if let DisconnectedRouteSlot::Parked(parked) = &mut *slot {
            if let Some(registry) = &mut parked.registry {
                self.broker.retire_parked_registry(registry)?;
            }
        }
        // A moved guard remains in the lifecycle journal, not this network.
        if !matches!(*slot, DisconnectedRouteSlot::Taken) {
            *slot = DisconnectedRouteSlot::Retired;
        }
        Ok(())
    }
    /// Verified remote EOF is the only close path which preserves a route
    /// snapshot. Local close, overflow, and final abandonment always retire it.
    pub(crate) async fn close_for_remote_disconnect(
        self: &Arc<Self>,
        proof: &super::client_enrollment::NativeTerminalProof,
    ) -> Result<(), ProtocolError> {
        self.check_terminal_proof(proof)?;
        self.close_with_terminal_proof(Some(proof), None).await
    }

    /// Rootless final close retires routes instead of parking them. The distinct
    /// proof carries no target recovery or remote cleanup acknowledgement.
    pub(crate) async fn close_for_final_local_eof(
        self: &Arc<Self>,
        proof: &super::client_enrollment::FinalLocalEofProof,
    ) -> Result<(), ProtocolError> {
        proof.check_network(self)?;
        proof.check_client(&self.client)?;
        if proof.generation() != self.scope.generation
            || proof.identity_scope() != self.scope.identity_scope
        {
            return Err(ProtocolError::StaleScope);
        }
        self.close_with_terminal_proof(None, Some(proof)).await
    }

    /// Keep the close worker retained if its caller is cancelled or dropped.
    /// A second close awaits that same worker rather than treating moved-out
    /// task/reader sets as proof that their work already completed.
    pub async fn close(self: &Arc<Self>) -> Result<(), ProtocolError> {
        self.close_with_terminal_proof(None, None).await
    }
    async fn close_with_terminal_proof(
        self: &Arc<Self>,
        proof: Option<&super::client_enrollment::NativeTerminalProof>,
        final_local: Option<&super::client_enrollment::FinalLocalEofProof>,
    ) -> Result<(), ProtocolError> {
        let diagnostics = self.client.cleanup_observer();
        let mut state = self.close_gate.lock().await;
        // Only the EOF supervisor starts this once. Cached ordinary close is
        // not evidence that the final-local callback fence was performed.
        if final_local.is_some() && (proof.is_some() || !matches!(*state, NetworkCloseState::Open))
        {
            return Err(ProtocolError::StaleScope);
        }
        let retire_failed = if let Some(proof) = proof {
            self.check_terminal_proof(proof)?;
            if matches!(*state, NetworkCloseState::Open) {
                self.park_disconnected_routes(proof)?;
            } else if !matches!(
                *self
                    .disconnected_routes
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?,
                DisconnectedRouteSlot::Parked(_) | DisconnectedRouteSlot::Taken
            ) {
                return Err(ProtocolError::StaleScope);
            }
            false
        } else {
            // Even a completed terminal drain must explicitly retire its hold
            // when this is final close, rather than return cached success.
            self.retire_disconnected_routes().is_err()
        };
        if matches!(*state, NetworkCloseState::Open) {
            // Preserve the original close admission boundary: revoke and abort
            // owner tasks before yielding to the retained drain worker. In
            // particular, quarantined readiness waiters must not get a new
            // scheduling turn to emit cleanup commands before they are aborted.
            let revoke_failed = self.revoke_resources().is_err();
            let mut failed = retire_failed || revoke_failed;
            match self.tasks.lock() {
                Ok(mut tasks) => tasks.abort_all(),
                Err(poisoned) => {
                    failed = true;
                    poisoned.into_inner().abort_all();
                }
            }
            let network = self.clone();
            let terminal = proof.cloned();
            let final_local = final_local.cloned();
            *state = NetworkCloseState::Running(tokio::spawn(async move {
                network
                    .close_retained(failed, terminal, final_local, diagnostics)
                    .await
            }));
        }
        let result = match &mut *state {
            NetworkCloseState::Finished(result) => {
                return if retire_failed {
                    Err(ProtocolError::CleanupFailed)
                } else {
                    result.clone()
                };
            }
            NetworkCloseState::Running(task) => match task.await {
                Ok(result) => result,
                Err(_) => Err(ProtocolError::CleanupFailed),
            },
            NetworkCloseState::Open => unreachable!("close worker was started"),
        };
        *state = NetworkCloseState::Finished(result.clone());
        if retire_failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            result
        }
    }
    async fn close_retained(
        self: &Arc<Self>,
        mut failed: bool,
        terminal: Option<super::client_enrollment::NativeTerminalProof>,
        final_local: Option<super::client_enrollment::FinalLocalEofProof>,
        diagnostics: Option<super::client_settlement_trace::CleanupObserver>,
    ) -> Result<(), ProtocolError> {
        // Cleanup failure never short-circuits owned-task drainage. In
        // particular spawn_blocking cannot be canceled by dropping its handle.
        let mut tasks = {
            let mut current = match self.tasks.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    failed = true;
                    poisoned.into_inner()
                }
            };
            std::mem::take(&mut *current)
        };
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                if !error.is_cancelled() {
                    if let Some(cell) = &diagnostics {
                        cell.failure(super::client_settlement_trace::CleanupComponent::Callback);
                    }
                    failed = true;
                }
            }
        }
        if let Some(proof) = terminal {
            // Enrollment has stopped intake and every asynchronous emitter has
            // joined. Revoke once more after joins to catch a token captured in
            // the pre-abort interval; no future event producer can mint another.
            // This fence retires callbacks only. File readers and recorders may
            // still be running, and route adoption still requires full cleanup.
            let retired = proof
                .check_network(self)
                .and_then(|()| {
                    self.broker
                        .revoke_scope_decisions(&self.scope.identity_scope)
                })
                .and_then(|()| {
                    self.retirement_sink
                        .retire_callbacks_after_terminal_drain(&proof)
                });
            if retired.is_err() {
                failed = true;
            }
        }
        if let Some(proof) = final_local {
            // The exact same producer-join boundary, without route preservation
            // or a synthetic active target. File readers still join below.
            let retired = proof
                .check_network(self)
                .and_then(|()| {
                    self.broker
                        .revoke_scope_decisions(&self.scope.identity_scope)
                })
                .and_then(|()| {
                    self.retirement_sink
                        .retire_callbacks_after_final_local_drain(&proof)
                });
            if retired.is_err() {
                failed = true;
            }
        }
        let mut readers = {
            let mut current = match self.blocking_reads.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    failed = true;
                    poisoned.into_inner()
                }
            };
            std::mem::take(&mut *current)
        };
        while let Some(result) = readers.join_next().await {
            if result.is_err() {
                failed = true;
            }
        }
        match self.downloads.lock() {
            Ok(mut entries) => entries.clear(),
            Err(poisoned) => {
                failed = true;
                poisoned.into_inner().clear();
            }
        }
        match self.responses.lock() {
            Ok(mut entries) => entries.clear(),
            Err(poisoned) => {
                failed = true;
                poisoned.into_inner().clear();
            }
        }
        if failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            self.cleanup_drained.store(true, Ordering::Release);
            Ok(())
        }
    }

    async fn authentication(
        &self,
        session: &str,
        params: Value,
        sink: &ClientEventSink,
    ) -> Result<(), ProtocolError> {
        let request_id = required_string(&params, "requestId")?;
        let challenge = params
            .get("authChallenge")
            .ok_or(ProtocolError::InvalidArguments)?;
        if challenge.get("source").and_then(Value::as_str) != Some("Server") {
            return self.client.send_command("Fetch.continueWithAuth",Some(json!({"requestId":request_id,"authChallengeResponse":{"response":"CancelAuth"}})),Some(session)).await.map(|_|()).map_err(|_|ProtocolError::BrowserFailure);
        }
        let origin = required_string(challenge, "origin")?;
        let parsed = url::Url::parse(origin).map_err(|_| ProtocolError::InvalidArguments)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(ProtocolError::PolicyDenied);
        }
        let request_url = params
            .get("request")
            .and_then(|request| request.get("url"))
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidArguments)?;
        let request_origin = url::Url::parse(request_url)
            .map_err(|_| ProtocolError::InvalidArguments)?
            .origin();
        let attempted = {
            let mut attempts = self
                .auth_attempts
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if attempts.len() >= 1024 {
                return Err(ProtocolError::CapacityExceeded);
            }
            !attempts.insert((session.into(), request_id.into()))
        };
        if request_origin != parsed.origin() || attempted {
            return self.client.send_command("Fetch.continueWithAuth",Some(json!({"requestId":request_id,"authChallengeResponse":{"response":"CancelAuth"}})),Some(session)).await.map(|_|()).map_err(|_|ProtocolError::BrowserFailure);
        }
        let lease = self.broker.decision_scoped_with_eval(
            self.scope.generation,
            DecisionOwner::Scope,
            DecisionKind::Authentication,
            30_000,
            None,
            Some(self.scope.identity_scope.clone()),
            self.client.debt_ledger().and_then(|ledger| {
                ledger.capturable_eval_window(&self.scope.identity_scope, session)
            }),
        )?;
        let _token = self.track_token(session, &lease.token)?;
        sink.emit("network.auth".into(),json!({"identityScope":self.scope.identity_scope,"origin":parsed.origin().ascii_serialization(),"source":"Server","scheme":challenge.get("scheme"),"realm":challenge.get("realm")}),Some(DecisionNotice{token:lease.token,timeout_ms:30_000}))?;
        let response = match lease
            .outcome
            .await
            .map_err(|_| ProtocolError::ScopeUnavailable)?
        {
            DecisionOutcome::Selected(Decision::Auth { username, password }) => {
                json!({"response":"ProvideCredentials","username":username,"password":password})
            }
            _ => json!({"response":"CancelAuth"}),
        };
        self.client
            .send_command(
                "Fetch.continueWithAuth",
                Some(json!({"requestId":request_id,"authChallengeResponse":response})),
                Some(session),
            )
            .await
            .map(|_| ())
            .map_err(|_| ProtocolError::BrowserFailure)
    }

    async fn dialog(
        &self,
        session: &str,
        params: Value,
        sink: &ClientEventSink,
    ) -> Result<(), ProtocolError> {
        let kind = required_string(&params, "type")?;
        if !matches!(kind, "alert" | "confirm" | "prompt" | "beforeunload") {
            return Err(ProtocolError::InvalidArguments);
        }
        let message = required_string(&params, "message")?;
        let lease = self.broker.decision_scoped_with_eval(
            self.scope.generation,
            DecisionOwner::Scope,
            DecisionKind::Dialog,
            30_000,
            None,
            Some(self.scope.identity_scope.clone()),
            self.client.debt_ledger().and_then(|ledger| {
                ledger.capturable_eval_window(&self.scope.identity_scope, session)
            }),
        )?;
        let _token = self.track_token(session, &lease.token)?;
        sink.emit(
            "dialog.opened".into(),
            json!({"identityScope":self.scope.identity_scope,"type":kind,"message":message}),
            Some(DecisionNotice {
                token: lease.token,
                timeout_ms: 30_000,
            }),
        )?;
        let (accept, prompt) = match lease
            .outcome
            .await
            .map_err(|_| ProtocolError::ScopeUnavailable)?
        {
            DecisionOutcome::Selected(Decision::Dialog {
                accept,
                prompt_text,
            }) => (accept, prompt_text),
            _ => (false, None),
        };
        super::network::handle_dialog(&self.client, session, accept, prompt.as_deref())
            .await
            .map_err(|_| ProtocolError::BrowserFailure)
    }

    fn new_resource(&self) -> Result<(String, Arc<BodyResource>), ProtocolError> {
        self.check()?;
        let mut resources = self
            .resources
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if self.sealed.load(Ordering::Acquire) {
            return Err(ProtocolError::StaleScope);
        }
        if resources.len() >= 128 {
            return Err(ProtocolError::CapacityExceeded);
        }
        let handle = format!("resource-{}", uuid::Uuid::new_v4());
        let (sender, _) = tokio::sync::watch::channel(None);
        let resource = Arc::new(BodyResource { completed: sender });
        resources.insert(handle.clone(), resource.clone());
        Ok((handle, resource))
    }
    fn finish_resource(
        &self,
        handle: &str,
        result: Result<String, ProtocolError>,
    ) -> Result<(), ProtocolError> {
        let resources = self
            .resources
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if self.sealed.load(Ordering::Acquire) {
            if let Ok(blob) = result {
                if !blob.starts_with("provider:") {
                    let _ = self.blobs.release(&self.scope, &blob);
                }
            }
            return Err(ProtocolError::StaleScope);
        }
        if let Some(resource) = resources.get(handle) {
            resource.completed.send_replace(Some(result));
        } else if let Ok(blob) = result {
            if blob.starts_with("provider:") {
                return Ok(());
            }
            self.blobs
                .release(&self.scope, &blob)
                .map_err(|_| ProtocolError::CleanupFailed)?;
        }
        Ok(())
    }
    pub async fn read_resource(
        &self,
        handle: &str,
        offset: usize,
        max_bytes: usize,
        operation: &OperationLease,
    ) -> Result<BlobChunk, ProtocolError> {
        self.check()?;
        let resource = self
            .resources
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .get(handle)
            .cloned();
        let Some(resource) = resource else {
            return self.read_body(handle, offset, max_bytes);
        };
        let mut completion = resource.completed.subscribe();
        let mut cancellation = operation.cancellation.clone();
        loop {
            self.check()?;
            if *cancellation.borrow() != CancelSignal::None {
                return Err(ProtocolError::Cancelled);
            }
            if let Some(result) = completion.borrow().clone() {
                return self.read_body(&result?, offset, max_bytes);
            }
            tokio::select! {
                _ = tokio::time::sleep_until(operation.deadline.into()) => return Err(ProtocolError::DeadlineExceeded),
                _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                result = completion.changed() => { result.map_err(|_|ProtocolError::ScopeUnavailable)?; }
            }
        }
    }
    pub fn release_body(&self, handle: &str) -> Result<(), ProtocolError> {
        self.check()?;
        // Request aliases are native-owned, never releasable or consumable by JS.
        if self
            .aliases
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .contains_key(handle)
        {
            return Err(ProtocolError::PolicyDenied);
        }
        // Same nested order as download_started: downloads then resources.
        // finish_resource/revoke serialize completion under resources; neither
        // holds that lock while acquiring downloads. All fallible locks and
        // backing-store release precede infallible map/watch mutations.
        let mut downloads = self
            .downloads
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let mut resources = self
            .resources
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if let Some(resource) = resources.get(handle) {
            let completed = resource.completed.borrow().clone();
            if let Some(Ok(blob)) = completed {
                if !blob.starts_with("provider:") {
                    self.blobs
                        .release(&self.scope, &blob)
                        .map_err(|_| ProtocolError::CleanupFailed)?;
                }
            }
            resource
                .completed
                .send_replace(Some(Err(ProtocolError::StaleScope)));
        }
        resources.remove(handle);
        downloads.retain(|_, entry| entry.handle != handle);
        Ok(())
    }
    async fn reserve_response_producer(
        &self,
        deadline: std::time::Instant,
        session_id: &str,
        captured_tenure: &tokio::sync::watch::Receiver<bool>,
    ) -> Result<BlobProducer, ProtocolError> {
        // Subscribe before the first check: finish/release between check and await
        // cannot be lost. Wait itself owns no quota, UI permit or store lock.
        let mut tenure = captured_tenure.clone();
        let mut changes = self.blobs.budget_changes().map_err(producer_error)?;
        let mut cancellation = self.cancellation.subscribe();
        loop {
            changes.borrow_and_update();
            self.check()?;
            if !self.session_tenure_live(session_id, &tenure)? {
                return Err(ProtocolError::StaleScope);
            }
            if *cancellation.borrow() != CancelSignal::None {
                return Err(ProtocolError::Cancelled);
            }
            if std::time::Instant::now() >= deadline {
                return Err(ProtocolError::DeadlineExceeded);
            }
            if let Some(producer) = self
                .blobs
                .try_reserve_producer(self.scope.clone())
                .map_err(producer_error)?
            {
                self.check()?;
                if *cancellation.borrow() != CancelSignal::None {
                    return Err(ProtocolError::Cancelled);
                }
                if std::time::Instant::now() >= deadline {
                    return Err(ProtocolError::DeadlineExceeded);
                }
                return Ok(producer);
            }
            tokio::select! {
                biased;
                _ = cancellation.changed() => {},
                _ = tenure.changed() => {},
                _ = tokio::time::sleep_until(deadline.into()) => return Err(ProtocolError::DeadlineExceeded),
                result = changes.changed() => { result.map_err(|_| ProtocolError::ScopeUnavailable)?; },
            }
        }
    }

    async fn response_finished(
        &self,
        session: &ApplicationSession,
        params: Value,
        deadline: std::time::Instant,
        session_tenure: &tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), ProtocolError> {
        let id = required_string(&params, "requestId")?;
        let handle = self
            .responses
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .remove(&(session.session_id.clone(), id.into()));
        let Some(handle) = handle else {
            return Ok(());
        };
        let result = async {
            let producer = self
                .reserve_response_producer(deadline, &session.session_id, session_tenure)
                .await?;
            if !self.session_tenure_live(&session.session_id, session_tenure)? {
                return Err(ProtocolError::StaleScope);
            }
            let mut cancellation = self.cancellation.subscribe();
            let mut tenure = session_tenure.clone();
            if *cancellation.borrow() != CancelSignal::None { return Err(ProtocolError::Cancelled); }
            if std::time::Instant::now() >= deadline { return Err(ProtocolError::DeadlineExceeded); }
            // Admission does not replenish collection's budget. This is a read;
            // CdpClient's PendingGuard owns cancelled pending-response removal.
            let body_read = self.client.send_command("Network.getResponseBody",
                Some(json!({"requestId":id})), Some(&session.session_id));
            tokio::pin!(body_read);
            let result = loop {
                tokio::select! {
                    biased;
                    _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                    _ = tenure.changed() => {
                        if !self.session_tenure_live(&session.session_id, &tenure)? {
                            return Err(ProtocolError::StaleScope);
                        }
                        // Configuration false→true is not retirement. Keep the
                        // same pending read and original deadline; never replay.
                    },
                    _ = tokio::time::sleep_until(deadline.into()) => return Err(ProtocolError::DeadlineExceeded),
                    result = &mut body_read => break result.map_err(|_| ProtocolError::BrowserFailure)?,
                }
            };
            let body = required_string(&result, "body")?;
            if body.len() > self.blobs.producer_limit().div_ceil(3) * 4 {
                return Err(ProtocolError::CapacityExceeded);
            }
            let bytes = if result.get("base64Encoded").and_then(Value::as_bool) == Some(true) {
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .map_err(|_| ProtocolError::BrowserFailure)?
            } else {
                body.as_bytes().to_vec()
            };
            self.check()?;
            if !self.session_tenure_live(&session.session_id, session_tenure)? { return Err(ProtocolError::StaleScope); }
            if *cancellation.borrow() != CancelSignal::None { return Err(ProtocolError::Cancelled); }
            if std::time::Instant::now() >= deadline { return Err(ProtocolError::DeadlineExceeded); }
            self.blobs
                .finish_producer(producer, bytes)
                .map(|blob| blob.handle)
                .map_err(producer_error)
        }
        .await;
        // Accounting corruption is not an expected capacity/cancellation refusal.
        // Leave quarantine to the retained event task rather than certifying reuse.
        self.blobs
            .check_budget_integrity()
            .map_err(|_| ProtocolError::CleanupFailed)?;
        // A missing/failed response body is a resource error, not evidence that
        // the browser context itself has unknown mutation effects.
        self.finish_resource(&handle, result)
    }

    pub fn pending_callbacks(&self) -> Result<usize, ProtocolError> {
        Ok(self
            .tokens
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .len())
    }
    fn track_token(&self, session: &str, token: &str) -> Result<TokenCleanup<'_>, ProtocolError> {
        if !self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .contains_key(session)
        {
            self.broker.revoke_decision(token)?;
            return Err(ProtocolError::StaleScope);
        }
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if self.sealed.load(Ordering::Acquire) {
            self.broker.revoke_decision(token)?;
            return Err(ProtocolError::StaleScope);
        }
        tokens.insert(token.into(), session.into());
        Ok(TokenCleanup {
            network: self,
            token: token.into(),
        })
    }
    /// Bind a dispatch context to this exact captured resource generation.
    pub fn validate_scope(&self, scope: &BlobScope) -> Result<(), ProtocolError> {
        if scope != &self.scope {
            return Err(ProtocolError::StaleScope);
        }
        self.check()
    }
    fn check(&self) -> Result<(), ProtocolError> {
        if self.sealed.load(Ordering::Acquire) {
            return Err(ProtocolError::StaleScope);
        }
        let (generation, health) = self.broker.health()?;
        if generation != self.scope.generation
            || health != super::client_protocol::ScopeState::Usable
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }

    /// Lifecycle owner calls this before context disposal. Read aliases carry no
    /// upload authority and are removed even when callback tasks are cancelled.
    pub fn revoke(&self) -> Result<(), ProtocolError> {
        let routes = self.retire_disconnected_routes();
        let resources = self.revoke_resources();
        routes.and(resources)
    }
    fn revoke_resources(&self) -> Result<(), ProtocolError> {
        self.sealed.store(true, Ordering::Release);
        self.cancellation.send_replace(CancelSignal::SessionClosed);
        self.broker
            .revoke_scope_decisions(&self.scope.identity_scope)?;
        let tokens: Vec<_> = self
            .tokens
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .drain()
            .map(|(token, _)| token)
            .collect();
        for token in tokens {
            self.broker.revoke_decision(&token)?;
            self.blobs
                .discard_reserved(&token)
                .map_err(|_| ProtocolError::CleanupFailed)?;
        }
        if let Some(version) = self
            .registry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .take()
        {
            if self.broker.health()?.1 == super::client_protocol::ScopeState::Usable {
                self.broker
                    .retire_registry(self.scope.generation, version)?;
            }
        }
        for resource in self
            .resources
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .values()
        {
            if let Some(Ok(blob)) = resource
                .completed
                .send_replace(Some(Err(ProtocolError::StaleScope)))
            {
                if !blob.starts_with("provider:") {
                    self.blobs
                        .release(&self.scope, &blob)
                        .map_err(|_| ProtocolError::CleanupFailed)?;
                }
            }
        }
        self.aliases
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .clear();
        self.app_events.clear()
    }

    pub fn read_body(
        &self,
        handle: &str,
        offset: usize,
        max_bytes: usize,
    ) -> Result<BlobChunk, ProtocolError> {
        self.check()?;
        if max_bytes == 0 || max_bytes > MAX_CHUNK_BYTES {
            return Err(ProtocolError::InvalidArguments);
        }
        let alias = self
            .aliases
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .get(handle)
            .cloned();
        if let Some(alias) = alias {
            let bytes = alias.bytes();
            if offset > bytes.len() {
                return Err(ProtocolError::InvalidArguments);
            }
            let end = bytes.len().min(offset.saturating_add(max_bytes));
            return Ok(BlobChunk {
                base64: base64::engine::general_purpose::STANDARD.encode(&bytes[offset..end]),
                next_offset: end,
                eof: end == bytes.len(),
            });
        }
        self.blobs
            .read_chunk(&self.scope, handle, offset, max_bytes)
            .map_err(|_| ProtocolError::InvalidArguments)
    }

    fn take_body(
        &self,
        token: &str,
        overrides: &mut RequestOverrides,
    ) -> Result<Option<Arc<BlobLease>>, ProtocolError> {
        if let Some(handle) = overrides.body_handle.take() {
            let lease = self
                .blobs
                .commit(&self.scope, &handle, token)
                .map_err(|_| ProtocolError::InvalidArguments)?;
            Ok(Some(Arc::new(lease)))
        } else {
            Ok(None)
        }
    }

    /// The retained lifecycle supervisor captures this before source teardown.
    /// Remove its route slot under the same lock that excludes new captures, so
    /// a late source revoke cannot retire the eventual replacement's registry.
    pub(crate) fn capture_route_transfer(
        self: &Arc<Self>,
        operation: &OperationLease,
    ) -> Result<RouteTransfer, ProtocolError> {
        self.check()?;
        if operation.generation != self.scope.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if operation.is_callback {
            return Err(ProtocolError::InvalidArguments);
        }
        if *operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if std::time::Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        let mut current = self
            .registry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        self.check()?;
        if self.routes_frozen.load(Ordering::Acquire) {
            return Err(ProtocolError::RegistryInUse);
        }
        let registry = current
            .map(|version| {
                self.broker.capture_registry_transfer(
                    version,
                    &self.scope.identity_scope,
                    operation,
                )
            })
            .transpose()?;
        self.routes_frozen.store(true, Ordering::Release);
        *current = None;
        Ok(RouteTransfer {
            source: self.clone(),
            replacement: None,
            registry,
            sequence: operation.sequence,
            deadline: operation.deadline,
            cancellation: operation.cancellation.clone(),
            active: true,
        })
    }

    /// Replacement affects future captures only. Broker retains retired
    /// snapshots until every paused request/fallback chain releases them.
    pub fn replace_routes(
        &self,
        version: u64,
        registrations: Vec<String>,
    ) -> Result<(), ProtocolError> {
        self.check()?;
        let mut current = self
            .registry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        self.check()?;
        if self.routes_frozen.load(Ordering::Acquire) {
            return Err(ProtocolError::StaleScope);
        }
        self.broker.replace_routes_scoped(
            self.scope.generation,
            version,
            registrations,
            Some(self.scope.identity_scope.clone()),
            *current,
        )?;
        *current = Some(version);
        Ok(())
    }

    fn capture_request(
        &self,
        session: &str,
        owner: DecisionOwner,
        timeout_ms: u64,
    ) -> Result<DecisionLease, ProtocolError> {
        self.check()?;
        let current = self
            .registry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if self.routes_frozen.load(Ordering::Acquire) {
            return Err(ProtocolError::StaleScope);
        }
        let lease = self.broker.decision_scoped_with_eval(
            self.scope.generation,
            owner,
            DecisionKind::Request,
            timeout_ms,
            *current,
            Some(self.scope.identity_scope.clone()),
            self.client.debt_ledger().and_then(|ledger| {
                ledger.capturable_eval_window(&self.scope.identity_scope, session)
            }),
        )?;
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if self.sealed.load(Ordering::Acquire) {
            self.broker.revoke_decision(&lease.token)?;
            return Err(ProtocolError::StaleScope);
        }
        tokens.insert(lease.token.clone(), session.into());
        Ok(lease)
    }

    async fn paused_request_captured(
        &self,
        session: &str,
        params: Value,
        mut lease: DecisionLease,
        sink: &ClientEventSink,
    ) -> Result<(), ProtocolError> {
        self.check()?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidArguments)?
            .to_owned();
        let source = params
            .get("request")
            .ok_or(ProtocolError::InvalidArguments)?;
        let url = source
            .get("url")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidArguments)?;
        let method = source
            .get("method")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidArguments)?;
        let headers = source
            .get("headers")
            .filter(|value| value.is_object())
            .ok_or(ProtocolError::InvalidArguments)?;
        let mut request = json!({"url": url, "method": method, "headers": headers});
        let initial_body = source.get("postData").and_then(Value::as_str);
        if let Some(body) = initial_body {
            if body.len() <= 128 * 1024 {
                request["postData"] = json!(body);
            }
        }
        let mut overrides = RequestOverrides::default();
        let mut fallback_of: Option<String> = None;
        let mut body_lease: Option<Arc<BlobLease>> = None;
        let alias = format!("body-{}", uuid::Uuid::new_v4());
        let _alias_cleanup = AliasCleanup {
            aliases: &self.aliases,
            handle: alias.clone(),
        };
        if let Some(body) = initial_body.filter(|body| body.len() > 128 * 1024) {
            let blob = self
                .blobs
                .insert_sealed(self.scope.clone(), body.as_bytes())
                .map_err(|_| ProtocolError::CapacityExceeded)?;
            self.blobs
                .reserve(&self.scope, &blob.handle, &lease.token)
                .map_err(|_| ProtocolError::CapacityExceeded)?;
            let original = Arc::new(
                self.blobs
                    .commit(&self.scope, &blob.handle, &lease.token)
                    .map_err(|_| ProtocolError::BrowserFailure)?,
            );
            self.aliases
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .insert(alias.clone(), original);
            request["postDataHandle"] = json!(alias);
        }

        loop {
            let remaining = lease
                .deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis()
                .min(u64::MAX as u128) as u64;
            if remaining == 0 {
                return self.abort_request(session, &request_id).await;
            }
            let token = lease.token.clone();
            let _token_cleanup = self.track_token(session, &token)?;
            let mut payload = json!({"identityScope": self.scope.identity_scope, "version": lease.registry_version.unwrap_or(0),
                "registrationIds": lease.registrations.as_ref(), "request": request});
            if let Some(previous) = &fallback_of {
                payload["fallbackOf"] = json!(previous);
            }
            sink.emit(
                "network.request".into(),
                payload,
                Some(DecisionNotice {
                    token: token.clone(),
                    timeout_ms: remaining,
                }),
            )?;
            match lease
                .outcome
                .await
                .map_err(|_| ProtocolError::ScopeUnavailable)?
            {
                DecisionOutcome::Fallback {
                    overrides: mut next_overrides,
                    next,
                } => {
                    if let Some(body) = self.take_body(&token, &mut next_overrides)? {
                        body_lease = Some(body);
                        next_overrides.body_base64 = None;
                        overrides.body_base64 = None;
                    } else if next_overrides.body_base64.is_some() {
                        body_lease = None;
                    }
                    merge_overrides(&mut overrides, next_overrides);
                    update_request(&mut request, &overrides);
                    if let Some(body) = &body_lease {
                        self.aliases
                            .lock()
                            .map_err(|_| ProtocolError::ScopeUnavailable)?
                            .insert(alias.clone(), body.clone());
                        request.as_object_mut().unwrap().remove("postData");
                        request.as_object_mut().unwrap().remove("postDataBase64");
                        request["postDataHandle"] = json!(alias);
                    } else if overrides.body_base64.is_some() {
                        request.as_object_mut().unwrap().remove("postDataHandle");
                        self.aliases
                            .lock()
                            .map_err(|_| ProtocolError::ScopeUnavailable)?
                            .remove(&alias);
                    }
                    fallback_of = Some(token);
                    lease = *next;
                }
                DecisionOutcome::Selected(Decision::Continue {
                    overrides: mut final_overrides,
                }) => {
                    if let Some(body) = self.take_body(&token, &mut final_overrides)? {
                        body_lease = Some(body);
                        overrides.body_base64 = None;
                    } else if final_overrides.body_base64.is_some() {
                        body_lease = None;
                    }
                    merge_overrides(&mut overrides, final_overrides);
                    let mut command = json!({"requestId": request_id});
                    if let Some(url) = overrides.url {
                        command["url"] = json!(url);
                    }
                    if let Some(method) = overrides.method {
                        command["method"] = json!(method);
                    }
                    let changed_body = body_lease.is_some() || overrides.body_base64.is_some();
                    if let Some(headers) =
                        continue_headers(overrides.headers, headers, changed_body)?
                    {
                        command["headers"] = json!(headers);
                    }
                    if let Some(body) = &body_lease {
                        command["postData"] =
                            json!(base64::engine::general_purpose::STANDARD.encode(body.bytes()));
                    } else if let Some(body) = overrides.body_base64 {
                        command["postData"] = json!(body);
                    }
                    return self
                        .client
                        .send_command("Fetch.continueRequest", Some(command), Some(session))
                        .await
                        .map(|_| ())
                        .map_err(|_| ProtocolError::BrowserFailure);
                }
                DecisionOutcome::Selected(Decision::Fulfill {
                    status,
                    headers,
                    body_base64,
                    body_handle,
                }) => {
                    let committed = if let Some(handle) = body_handle {
                        Some(
                            self.blobs
                                .commit(&self.scope, &handle, &token)
                                .map_err(|_| ProtocolError::InvalidArguments)?,
                        )
                    } else {
                        None
                    };
                    let body_base64 = if let Some(body) = &committed {
                        base64::engine::general_purpose::STANDARD.encode(body.bytes())
                    } else {
                        body_base64.ok_or(ProtocolError::InvalidArguments)?
                    };
                    return self
                        .client
                        .send_command(
                            "Fetch.fulfillRequest",
                            Some(json!({"requestId": request_id,
                        "responseCode": status, "responseHeaders": headers, "body": body_base64})),
                            Some(session),
                        )
                        .await
                        .map(|_| ())
                        .map_err(|_| ProtocolError::BrowserFailure);
                }
                DecisionOutcome::Selected(Decision::Abort {})
                | DecisionOutcome::Expired
                | DecisionOutcome::Cancelled
                | DecisionOutcome::SessionClosed => {
                    self.blobs
                        .discard_reserved(&token)
                        .map_err(|_| ProtocolError::CleanupFailed)?;
                    return self.abort_request(session, &request_id).await;
                }
                _ => return Err(ProtocolError::DecisionKindMismatch),
            }
        }
    }

    async fn abort_request(&self, session: &str, request_id: &str) -> Result<(), ProtocolError> {
        self.client
            .send_command(
                "Fetch.failRequest",
                Some(json!({"requestId": request_id, "errorReason": "Aborted"})),
                Some(session),
            )
            .await
            .map(|_| ())
            .map_err(|_| ProtocolError::BrowserFailure)
    }
}

fn merge_overrides(current: &mut RequestOverrides, next: RequestOverrides) {
    if next.url.is_some() {
        current.url = next.url;
    }
    if next.method.is_some() {
        current.method = next.method;
    }
    if next.headers.is_some() {
        current.headers = next.headers;
    }
    if next.body_base64.is_some() || next.body_handle.is_some() {
        current.body_base64 = next.body_base64;
        current.body_handle = next.body_handle;
    }
}
fn update_request(request: &mut Value, overrides: &RequestOverrides) {
    if let Some(url) = &overrides.url {
        request["url"] = json!(url);
    }
    if let Some(method) = &overrides.method {
        request["method"] = json!(method);
    }
    if let Some(headers) = &overrides.headers {
        let mut values = serde_json::Map::new();
        for header in headers {
            values.insert(header.name.clone(), json!(header.value));
        }
        request["headers"] = Value::Object(values);
    }
    if let Some(body) = &overrides.body_base64 {
        request["postDataBase64"] = json!(body);
        request
            .as_object_mut()
            .map(|object| object.remove("postData"));
    }
}

// Preserve store authority failures: only genuine reservation pressure is capacity.
// This deliberately does not change full-size producer reservation accounting.
fn producer_error(error: BlobError) -> ProtocolError {
    match error {
        BlobError::StaleScope => ProtocolError::StaleScope,
        BlobError::QuotaExceeded => ProtocolError::CapacityExceeded,
        BlobError::Closed => ProtocolError::ScopeUnavailable,
        BlobError::Reserved => ProtocolError::PolicyDenied,
        BlobError::InvalidInput
        | BlobError::Missing
        | BlobError::OffsetMismatch
        | BlobError::Unsealed
        | BlobError::IntegrityMismatch => ProtocolError::InvalidArguments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn producer_errors_do_not_hide_scope_or_integrity_as_capacity() {
        for (error, expected) in [
            (BlobError::StaleScope, ProtocolError::StaleScope),
            (BlobError::QuotaExceeded, ProtocolError::CapacityExceeded),
            (BlobError::Closed, ProtocolError::ScopeUnavailable),
            (BlobError::Reserved, ProtocolError::PolicyDenied),
            (BlobError::InvalidInput, ProtocolError::InvalidArguments),
            (BlobError::Missing, ProtocolError::InvalidArguments),
            (BlobError::OffsetMismatch, ProtocolError::InvalidArguments),
            (BlobError::Unsealed, ProtocolError::InvalidArguments),
            (
                BlobError::IntegrityMismatch,
                ProtocolError::InvalidArguments,
            ),
        ] {
            assert_eq!(producer_error(error), expected);
        }
    }

    #[test]
    fn small_retained_body_causes_real_full_producer_reservation_pressure() {
        let store = BlobStore::new(super::super::client_blobs::BlobLimits {
            max_blob_bytes: 8,
            max_total_bytes: 16,
            max_handles: 8,
        })
        .unwrap();
        let scope = BlobScope {
            generation: 1,
            identity_scope: "body-pressure".into(),
        };
        store.activate_scope(scope.clone()).unwrap();
        let small = store.insert_sealed(scope.clone(), b"x").unwrap();
        let collecting = store.reserve_producer(scope.clone()).unwrap();
        // 1 retained byte + 8 reserved bytes leaves 7, even for a future tiny body.
        assert!(matches!(
            store
                .reserve_producer(scope.clone())
                .map_err(producer_error),
            Err(ProtocolError::CapacityExceeded)
        ));
        let wrong = BlobScope {
            generation: 1,
            identity_scope: "retired".into(),
        };
        assert!(matches!(
            store.reserve_producer(wrong).map_err(producer_error),
            Err(ProtocolError::StaleScope)
        ));
        let finished = store.finish_producer(collecting, b"y".to_vec()).unwrap();
        // Finishing shrinks the reservation, and releasing both retains no hidden charge.
        let next = store.reserve_producer(scope.clone()).unwrap();
        drop(next);
        store.release(&scope, &small.handle).unwrap();
        store.release(&scope, &finished.handle).unwrap();
        let first = store.reserve_producer(scope.clone()).unwrap();
        let second = store.reserve_producer(scope.clone()).unwrap();
        store.revoke_scope(&scope).unwrap();
        assert_eq!(
            store
                .finish_producer(first, b"late".to_vec())
                .map_err(producer_error),
            Err(ProtocolError::StaleScope)
        );
        drop(second);
    }

    #[test]
    fn fallback_overrides_accumulate_without_erasing_previous_fields() {
        let mut current = RequestOverrides {
            url: Some("https://example.test/changed".into()),
            ..Default::default()
        };
        merge_overrides(
            &mut current,
            RequestOverrides {
                method: Some("POST".into()),
                ..Default::default()
            },
        );
        assert_eq!(current.url.as_deref(), Some("https://example.test/changed"));
        assert_eq!(current.method.as_deref(), Some("POST"));
    }
}

struct AliasCleanup<'a> {
    aliases: &'a Mutex<HashMap<String, Arc<BlobLease>>>,
    handle: String,
}
impl Drop for AliasCleanup<'_> {
    fn drop(&mut self) {
        if let Ok(mut aliases) = self.aliases.lock() {
            aliases.remove(&self.handle);
        }
    }
}

#[derive(Clone)]
struct EnrolledSession {
    sink: ClientEventSink,
    application: ApplicationSession,
    configuration_ready: tokio::sync::watch::Sender<bool>,
}
#[derive(Clone)]
pub struct ApplicationSession {
    pub session_id: String,
    pub root_page_session: String,
    pub active_page: bool,
}
fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, ProtocolError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ProtocolError::InvalidArguments)
}

struct BodyResource {
    completed: tokio::sync::watch::Sender<Option<Result<String, ProtocolError>>>,
}

/// A caller dropping its retained setup task cannot certify a lost ACK.
struct DownloadSetupDispatch<'a> {
    broker: &'a ClientSession,
    completed: bool,
}
impl Drop for DownloadSetupDispatch<'_> {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.broker.quarantine();
        }
    }
}

#[derive(Clone)]
pub enum DownloadSource {
    Local(std::path::PathBuf),
    Provider(String),
}
struct DownloadEntry {
    handle: String,
    resource: Arc<BodyResource>,
    completed: bool,
    terminal_started: bool,
    published: bool,
    reservation: Option<BlobProducer>,
}
fn safe_basename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}
fn read_owned_download(
    directory: &std::path::Path,
    basename: &str,
    limit: usize,
) -> Result<Vec<u8>, ProtocolError> {
    use std::io::Read;
    if !safe_basename(basename) {
        return Err(ProtocolError::InvalidArguments);
    }
    let path = directory.join(basename);
    if std::fs::symlink_metadata(&path)
        .map_err(|_| ProtocolError::BrowserFailure)?
        .file_type()
        .is_symlink()
    {
        return Err(ProtocolError::PolicyDenied);
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(&path)
        .map_err(|_| ProtocolError::BrowserFailure)?;
    let metadata = file.metadata().map_err(|_| ProtocolError::BrowserFailure)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(ProtocolError::PolicyDenied);
        }
    }
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(ProtocolError::CapacityExceeded);
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProtocolError::BrowserFailure)?;
    if bytes.len() > limit {
        return Err(ProtocolError::CapacityExceeded);
    }
    std::fs::remove_file(&path).map_err(|_| ProtocolError::CleanupFailed)?;
    Ok(bytes)
}

struct TokenCleanup<'a> {
    network: &'a ClientNetwork,
    token: String,
}
impl Drop for TokenCleanup<'_> {
    fn drop(&mut self) {
        if let Ok(mut tokens) = self.network.tokens.lock() {
            tokens.remove(&self.token);
        }
        let _ = self.network.broker.revoke_decision(&self.token);
        let _ = self.network.blobs.discard_reserved(&self.token);
    }
}

fn continue_headers(
    headers: Option<Vec<super::client_protocol::Header>>,
    original: &Value,
    body_changed: bool,
) -> Result<Option<Vec<super::client_protocol::Header>>, ProtocolError> {
    let mut headers = match headers {
        Some(headers) => headers,
        None if body_changed => original
            .as_object()
            .ok_or(ProtocolError::InvalidArguments)?
            .iter()
            .map(|(name, value)| {
                Ok(super::client_protocol::Header {
                    name: name.clone(),
                    value: value
                        .as_str()
                        .ok_or(ProtocolError::InvalidArguments)?
                        .into(),
                })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?,
        None => return Ok(None),
    };
    if body_changed {
        headers.retain(|header| !header.name.eq_ignore_ascii_case("content-length"));
    }
    Ok(Some(headers))
}

#[cfg(test)]
mod resource_tests {
    use super::*;
    #[test]
    fn changed_upload_does_not_reuse_stale_content_length() {
        let headers = continue_headers(None, &json!({"Content-Length":"8","X-Test":"kept"}), true)
            .unwrap()
            .unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, "X-Test");
        let explicit = vec![super::super::client_protocol::Header {
            name: "content-LENGTH".into(),
            value: "8".into(),
        }];
        assert!(continue_headers(Some(explicit), &json!({}), true)
            .unwrap()
            .unwrap()
            .is_empty());
        assert!(continue_headers(None, &json!({}), false).unwrap().is_none());
    }
    #[test]
    fn download_basename_cannot_escape_owned_directory() {
        for name in ["", "..", "../secret", "a/b", "a\\b", "C:secret", "a\0b"] {
            assert!(!safe_basename(name), "{name:?}");
        }
        assert!(safe_basename("12345678-abcd-4567-abcd-123456789abc"));
    }
}

#[cfg(test)]
mod bridge_tests {
    use super::super::client_protocol::ServerMessage;
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    async fn fixture() -> (
        Arc<ClientNetwork>,
        tokio::sync::mpsc::Receiver<ServerMessage>,
        tokio::sync::mpsc::Receiver<Value>,
        tokio::task::JoinHandle<()>,
    ) {
        fixture_with_download_delay(false).await
    }
    async fn fixture_with_download_delay(
        delay: bool,
    ) -> (
        Arc<ClientNetwork>,
        tokio::sync::mpsc::Receiver<ServerMessage>,
        tokio::sync::mpsc::Receiver<Value>,
        tokio::task::JoinHandle<()>,
    ) {
        fixture_with_delays(delay, false).await
    }
    async fn fixture_with_delays(
        delay: bool,
        hold_input: bool,
    ) -> (
        Arc<ClientNetwork>,
        tokio::sync::mpsc::Receiver<ServerMessage>,
        tokio::sync::mpsc::Receiver<Value>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (commands, received) = tokio::sync::mpsc::channel(64);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                let tokio_tungstenite::tungstenite::Message::Text(text) = message else {
                    continue;
                };
                let command: Value = serde_json::from_str(&text).unwrap();
                let result = if command["method"] == "Network.getResponseBody" {
                    json!({"body":"synthetic-response","base64Encoded":false})
                } else {
                    json!({})
                };
                commands.send(command.clone()).await.unwrap();
                if hold_input && command["method"] == "Input.dispatchMouseEvent" {
                    // Keep the actual submitted command unacknowledged while
                    // the socket still services unrelated owner cleanup.
                    continue;
                }
                if delay && command["method"] == "Browser.setDownloadBehavior" {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                }
                let mut reply = json!({"id":command["id"],"result":result});
                if let Some(session) = command.get("sessionId") {
                    reply["sessionId"] = session.clone();
                }
                if socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        reply.to_string(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let client = Arc::new(
            CdpClient::connect(&format!("ws://{address}"))
                .await
                .unwrap(),
        );
        let broker = Arc::new(ClientSession::new());
        let (sink, events) = ClientEventSink::test_channel(broker.clone());
        let scope = BlobScope {
            generation: 1,
            identity_scope: "synthetic-owned-context".into(),
        };
        let blobs =
            Arc::new(BlobStore::new(super::super::client_blobs::BlobLimits::default()).unwrap());
        blobs.activate_scope(scope.clone()).unwrap();
        let network = Arc::new(ClientNetwork::new(
            client,
            broker,
            sink,
            scope,
            blobs,
            Arc::new(super::super::client_ui::UiGate::default()),
            NetworkPolicy::default(),
        ));
        network.sessions.lock().unwrap().insert(
            "owned".into(),
            EnrolledSession {
                sink: network.future_session_sink.lock().unwrap().clone(),
                application: ApplicationSession {
                    session_id: "owned".into(),
                    root_page_session: "owned".into(),
                    active_page: true,
                },
                configuration_ready: tokio::sync::watch::channel(true).0,
            },
        );
        (network, events, received, server)
    }

    #[derive(Clone, Copy, Debug)]
    enum RetirementWatchCase {
        Clean,
        UnownedSeal,
        PoisonBefore,
        PoisonAfter,
        IncompleteInventory,
        LostAccounting,
        MutatingPrefix,
        InputDebt,
    }

    async fn retained_body_watch_retirement(case: RetirementWatchCase) {
        use super::super::client_browser::ExecutionGate;
        use super::super::client_debt::{OperationKey, OwnerDebtLedger};
        use super::super::client_protocol::{Effects, ScopeState};
        use super::super::client_resource_dispatch::{execute, ResourceContext};
        use super::super::client_targets::ClientTargets;
        use super::super::client_tasks::RetainedTasks;
        use super::super::client_transport::NativeOutcome;
        use std::future::Future;
        use std::time::Duration;

        let input_debt = matches!(case, RetirementWatchCase::InputDebt);
        let (network, mut events, mut commands, server) =
            fixture_with_delays(false, input_debt).await;
        network.subscribe_responses().unwrap();
        network.event(&CdpEvent {
            method: "Network.responseReceived".into(),
            session_id: Some("owned".into()),
            params: json!({"requestId":"endless","response":{"url":"https://synthetic.test/endless","status":200,"headers":{}}}),
        }).unwrap();
        let (_, payload, _) = next_event(&mut events).await;
        let handle = payload["handle"].as_str().unwrap().to_owned();
        let resource = network
            .resources
            .lock()
            .unwrap()
            .get(&handle)
            .unwrap()
            .clone();
        assert!(resource.completed.borrow().is_none());
        // No loadingFinished event: the real resource dispatcher must park on
        // the pending body watch, not a substituted future or fabricated error.
        let targets = ClientTargets::new("ctx".into(), network.scope.identity_scope.clone());
        targets
            .attached("ctx", "page".into(), "owned".into(), "page".into())
            .unwrap();
        targets.configured("page").unwrap();
        let gate = Arc::new(ExecutionGate::default());
        let permit = gate.enter(false).unwrap();
        let tasks = RetainedTasks::default();
        let ledger = OwnerDebtLedger::new(1, network.scope.identity_scope.clone());
        network.client.install_debt_ledger(ledger.clone()).unwrap();
        let operation = network.broker.admit(1, 1, 5_000).unwrap();
        let deadline = operation.deadline;
        assert!(network.broker.start(1, 1).unwrap());
        let journal = ledger
            .operation(
                OperationKey {
                    generation: 1,
                    operation_seq: 1,
                },
                "page".into(),
                "owned".into(),
            )
            .unwrap();
        journal.bind_operation(&operation).unwrap();
        let (watch_ready, waiting_watch) = tokio::sync::oneshot::channel();
        let (body_returned, waiting_body) = tokio::sync::oneshot::channel();
        let (finish, finishing) = tokio::sync::oneshot::channel();
        let (input_seen, waiting_input) = tokio::sync::oneshot::channel();
        let captured = network.clone();
        let receive = tasks.start_operation(
            network.scope.identity_scope.clone(), targets.clone(), network.broker.clone(),
            journal.clone(), operation.cancellation.clone(), async move {
                if matches!(case, RetirementWatchCase::MutatingPrefix) {
                    captured.client.send_command("Runtime.evaluate", Some(json!({"expression":"globalThis.retirementWitness = true","returnByValue":true})), Some("owned")).await.unwrap();
                }
                if input_debt {
                    let input = captured.client.send_command("Input.dispatchMouseEvent", Some(json!({"type":"mousePressed","x":1,"y":1,"button":"left"})), Some("owned"));
                    tokio::pin!(input);
                    tokio::select! {
                        _ = waiting_input => {},
                        result = &mut input => panic!("held input unexpectedly settled: {result:?}"),
                    }
                    // Dropping the local waiter does not erase submitted debt.
                }
                let result = {
                    let args = json!({"handle":handle,"offset":0,"maxBytes":32});
                    let read = execute(ResourceContext {
                        network: &captured, blobs: &captured.blobs, scope: &captured.scope,
                        operation: &operation, permit: &permit,
                    }, "network.body.read", &args);
                    tokio::pin!(read);
                    let mut watch_ready = Some(watch_ready);
                    std::future::poll_fn(|cx| {
                        let poll = read.as_mut().poll(cx);
                        if poll.is_pending() {
                            if let Some(ready) = watch_ready.take() { let _ = ready.send(()); }
                        }
                        poll
                    }).await
                };
                body_returned.send(()).unwrap();
                finishing.await.unwrap();
                let outcome = match result {
                    Ok(value) => NativeOutcome { retention: None, result: Ok(value), effects: Effects::Completed },
                    Err(failure) => NativeOutcome { retention: None, result: Err(failure.error), effects: failure.effects },
                };
                drop(permit);
                (outcome, false)
            },
        ).await.unwrap();
        if input_debt {
            let sent = tokio::time::timeout(Duration::from_secs(1), commands.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(sent["method"], "Input.dispatchMouseEvent");
            input_seen.send(()).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(1), waiting_watch)
            .await
            .unwrap()
            .unwrap();
        if matches!(case, RetirementWatchCase::MutatingPrefix) {
            assert_eq!(commands.recv().await.unwrap()["method"], "Runtime.evaluate");
        }
        let before = journal.snapshot();
        assert_eq!(
            before.mutation_dispatched,
            input_debt || matches!(case, RetirementWatchCase::MutatingPrefix)
        );
        assert_eq!(before.input_debt > 0, input_debt);
        assert_eq!(before.object_debt, 0);
        assert!(!before.integrity_lost);
        assert!(!before.local_producers_finished);

        if matches!(case, RetirementWatchCase::IncompleteInventory) {
            targets
                .attached(
                    "ctx",
                    "unfinished".into(),
                    "unfinished-session".into(),
                    "page".into(),
                )
                .unwrap();
        }
        if matches!(case, RetirementWatchCase::PoisonBefore) {
            targets.seal();
        }
        if matches!(case, RetirementWatchCase::UnownedSeal) {
            targets.seal_admission();
        } else {
            targets.seal_for_owner_retirement(
                &super::super::client_browser::OwnerRetirement::for_test(&targets),
            );
        }
        if matches!(case, RetirementWatchCase::PoisonAfter) {
            targets.seal();
        }
        if matches!(case, RetirementWatchCase::LostAccounting) {
            ledger.connection_lost();
        }
        gate.begin_transition().unwrap();
        assert!(gate.enter(false).is_err());
        assert!(targets.inventory().is_err());
        let drained = gate.drained();
        tokio::pin!(drained);
        assert!(futures_util::poll!(&mut drained).is_pending());
        tokio::time::timeout(Duration::from_secs(1), network.close())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            *resource.completed.borrow(),
            Some(Err(ProtocolError::StaleScope))
        );
        tokio::time::timeout(Duration::from_secs(1), waiting_body)
            .await
            .unwrap()
            .unwrap();
        // Revocation wakes the real local watch, but cannot drop its producer's
        // captured permit or claim completion before that owner has returned.
        assert!(futures_util::poll!(&mut drained).is_pending());
        assert!(!journal.snapshot().local_producers_finished);
        assert!(
            std::time::Instant::now() < deadline,
            "retirement must not wait for the body deadline"
        );
        finish.send(()).unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(1), receive)
            .await
            .unwrap()
            .unwrap();
        let dirty = matches!(
            case,
            RetirementWatchCase::UnownedSeal
                | RetirementWatchCase::PoisonBefore
                | RetirementWatchCase::PoisonAfter
                | RetirementWatchCase::IncompleteInventory
                | RetirementWatchCase::LostAccounting
        );
        let unknown = dirty || input_debt || matches!(case, RetirementWatchCase::MutatingPrefix);
        assert_eq!(outcome.result, Err(ProtocolError::StaleScope));
        assert_eq!(
            outcome.effects,
            if unknown {
                Effects::Unknown
            } else {
                Effects::NotDispatched
            },
            "{case:?}"
        );
        assert_eq!(
            tasks.drain().await,
            if dirty {
                Err(ProtocolError::CleanupFailed)
            } else {
                Ok(())
            }
        );
        drained.await.unwrap();
        assert!(journal.snapshot().local_producers_finished);
        assert_eq!(
            journal.snapshot().input_debt > 0,
            input_debt,
            "retirement must not erase real input debt"
        );
        assert_eq!(
            network.broker.health().unwrap().1,
            if dirty {
                ScopeState::Quarantined
            } else {
                ScopeState::Usable
            }
        );
        // Exercise the delivered result's broker settlement as well. Unknown
        // without a completed publication-retirement handshake stays terminal.
        assert_eq!(
            network.broker.settle(1, 1, outcome.effects).unwrap(),
            if unknown {
                ScopeState::Quarantined
            } else {
                ScopeState::Usable
            }
        );
        tasks.fix_operation_result(journal.key());
        if !unknown {
            gate.commit_transition().unwrap();
        }
        assert!(
            targets.inventory().is_err(),
            "retirement never reopens old scope admission"
        );
        let (_cancel, retired_read) = download_operation();
        assert!(network
            .read_resource(payload["handle"].as_str().unwrap(), 0, 32, &retired_read)
            .await
            .is_err());
        assert!(
            commands.try_recv().is_err(),
            "body watch/retirement must not replay input or fetch a body"
        );
        server.abort();
    }

    #[tokio::test]
    async fn normal_owner_retirement_drains_pending_body_watch_without_false_unknown() {
        retained_body_watch_retirement(RetirementWatchCase::Clean).await;
    }

    #[tokio::test]
    async fn pending_body_retirement_keeps_poison_incomplete_inventory_and_debt_unknown() {
        for case in [
            RetirementWatchCase::UnownedSeal,
            RetirementWatchCase::PoisonBefore,
            RetirementWatchCase::PoisonAfter,
            RetirementWatchCase::IncompleteInventory,
            RetirementWatchCase::LostAccounting,
            RetirementWatchCase::MutatingPrefix,
            RetirementWatchCase::InputDebt,
        ] {
            retained_body_watch_retirement(case).await;
        }
    }
    async fn pressure_fixture() -> (
        Arc<ClientNetwork>,
        tokio::sync::mpsc::Receiver<ServerMessage>,
        tokio::sync::mpsc::Receiver<Value>,
        tokio::task::JoinHandle<()>,
        super::super::client_blobs::BlobInfo,
        BlobProducer,
    ) {
        let (mut network, events, commands, server) = fixture().await;
        let blobs = Arc::new(
            BlobStore::new(super::super::client_blobs::BlobLimits {
                max_blob_bytes: 32,
                max_total_bytes: 64,
                max_handles: 8,
            })
            .unwrap(),
        );
        blobs.activate_scope(network.scope.clone()).unwrap();
        let small = blobs.insert_sealed(network.scope.clone(), b"x").unwrap();
        let producer = blobs.reserve_producer(network.scope.clone()).unwrap();
        Arc::get_mut(&mut network).unwrap().blobs = blobs;
        (network, events, commands, server, small, producer)
    }

    #[tokio::test]
    async fn response_collection_waits_for_transient_bytes_without_dispatch_or_ui_lock() {
        let (network, _events, mut commands, server, small, held) = pressure_fixture().await;
        let session = ApplicationSession {
            session_id: "owned".into(),
            root_page_session: "owned".into(),
            active_page: true,
        };
        network
            .sessions
            .lock()
            .unwrap()
            .get("owned")
            .unwrap()
            .configuration_ready
            .send_replace(false);
        let tenure = network
            .sessions
            .lock()
            .unwrap()
            .get("owned")
            .unwrap()
            .configuration_ready
            .subscribe();
        // Capture predates the legitimate ready notification. This notification
        // must not be mistaken for session retirement or replay the body read.
        network
            .sessions
            .lock()
            .unwrap()
            .get("owned")
            .unwrap()
            .configuration_ready
            .send_replace(true);
        let (handle, resource) = network.new_resource().unwrap();
        network
            .responses
            .lock()
            .unwrap()
            .insert(("owned".into(), "response".into()), handle.clone());
        let collect = network.response_finished(
            &session,
            json!({"requestId":"response"}),
            std::time::Instant::now() + std::time::Duration::from_secs(2),
            &tenure,
        );
        tokio::pin!(collect);
        assert!(futures_util::poll!(&mut collect).is_pending());
        assert!(commands.try_recv().is_err());
        let ui = network
            .ui_gate
            .enter(
                true,
                false,
                std::time::Instant::now() + std::time::Duration::from_secs(1),
                network.cancellation.subscribe(),
            )
            .await
            .unwrap();
        drop(ui);
        let finished = network.blobs.finish_producer(held, b"y".to_vec()).unwrap();
        collect.await.unwrap();
        assert_eq!(
            commands.recv().await.unwrap()["method"],
            "Network.getResponseBody"
        );
        assert!(commands.try_recv().is_err());
        let blob = resource.completed.borrow().clone().unwrap().unwrap();
        let bytes = network.blobs.read(&network.scope, &blob, 0, 32).unwrap();
        assert_eq!(bytes, b"synthetic-response");
        network.release_body(&handle).unwrap();
        network
            .blobs
            .release(&network.scope, &small.handle)
            .unwrap();
        network
            .blobs
            .release(&network.scope, &finished.handle)
            .unwrap();
        assert!(network.check().is_ok());
        server.abort();
    }

    #[tokio::test]
    async fn response_admission_cancel_and_deadline_settle_only_resource_with_zero_cdp() {
        for cancel in [false, true] {
            let (network, _events, mut commands, server, small, held) = pressure_fixture().await;
            let session = ApplicationSession {
                session_id: "owned".into(),
                root_page_session: "owned".into(),
                active_page: true,
            };
            let tenure = network
                .sessions
                .lock()
                .unwrap()
                .get("owned")
                .unwrap()
                .configuration_ready
                .subscribe();
            let (handle, resource) = network.new_resource().unwrap();
            network
                .responses
                .lock()
                .unwrap()
                .insert(("owned".into(), "response".into()), handle.clone());
            let deadline = std::time::Instant::now()
                + std::time::Duration::from_millis(if cancel { 2000 } else { 10 });
            let collect = network.response_finished(
                &session,
                json!({"requestId":"response"}),
                deadline,
                &tenure,
            );
            tokio::pin!(collect);
            assert!(futures_util::poll!(&mut collect).is_pending());
            if cancel {
                network
                    .cancellation
                    .send_replace(CancelSignal::SessionClosed);
            }
            collect.await.unwrap();
            assert_eq!(
                resource.completed.borrow().clone().unwrap(),
                Err(if cancel {
                    ProtocolError::Cancelled
                } else {
                    ProtocolError::DeadlineExceeded
                })
            );
            assert!(commands.try_recv().is_err());
            assert!(network.check().is_ok()); // No broker quarantine for expected refusal.
            network.release_body(&handle).unwrap();
            drop(held);
            network
                .blobs
                .release(&network.scope, &small.handle)
                .unwrap();
            server.abort();
        }
    }

    #[tokio::test]
    async fn response_wait_revoke_cannot_collect_into_replacement_scope() {
        let (network, _events, mut commands, server, _small, held) = pressure_fixture().await;
        let tenure = network
            .sessions
            .lock()
            .unwrap()
            .get("owned")
            .unwrap()
            .configuration_ready
            .subscribe();
        let wait = network.reserve_response_producer(
            std::time::Instant::now() + std::time::Duration::from_secs(2),
            "owned",
            &tenure,
        );
        tokio::pin!(wait);
        assert!(futures_util::poll!(&mut wait).is_pending());
        network.blobs.revoke_scope(&network.scope).unwrap();
        network
            .blobs
            .activate_scope(BlobScope {
                generation: 1,
                identity_scope: "replacement".into(),
            })
            .unwrap();
        assert!(matches!(wait.await, Err(ProtocolError::StaleScope)));
        assert!(commands.try_recv().is_err());
        drop(held);
        server.abort();
    }

    #[tokio::test]
    async fn response_wait_retired_session_wakes_without_capacity_change() {
        let (network, _events, mut commands, server, small, held) = pressure_fixture().await;
        let tenure = network
            .sessions
            .lock()
            .unwrap()
            .get("owned")
            .unwrap()
            .configuration_ready
            .subscribe();
        let wait = network.reserve_response_producer(
            std::time::Instant::now() + std::time::Duration::from_secs(2),
            "owned",
            &tenure,
        );
        tokio::pin!(wait);
        assert!(futures_util::poll!(&mut wait).is_pending());
        network.sessions.lock().unwrap().remove("owned");
        assert!(matches!(wait.await, Err(ProtocolError::StaleScope)));
        assert!(commands.try_recv().is_err());
        drop(held);
        network
            .blobs
            .release(&network.scope, &small.handle)
            .unwrap();
        server.abort();
    }

    fn route_replacement(source: &Arc<ClientNetwork>, identity: &str) -> Arc<ClientNetwork> {
        Arc::new(ClientNetwork::new(
            source.client.clone(),
            source.broker.clone(),
            source.future_session_sink.lock().unwrap().clone(),
            BlobScope {
                generation: source.scope.generation,
                identity_scope: identity.into(),
            },
            source.blobs.clone(),
            Arc::new(super::super::client_ui::UiGate::default()),
            NetworkPolicy::default(),
        ))
    }
    struct TerminalFixture {
        source: Arc<ClientNetwork>,
        targets: Arc<super::super::client_targets::ClientTargets>,
        retained: super::super::client_reconnect::RetainedIdentity,
        endpoint: String,
        disconnect: tokio::sync::watch::Sender<bool>,
        server: tokio::task::JoinHandle<()>,
        _events: tokio::sync::mpsc::Receiver<ServerMessage>,
    }
    async fn terminal_fixture() -> TerminalFixture {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let (disconnect, closed) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for connection in 0..2 {
                let (socket, _) = listener.accept().await.unwrap();
                let mut closed = closed.clone();
                tasks.spawn(async move {
                    let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
                    loop {
                        let incoming = tokio::select! {
                            _ = closed.changed(), if connection == 0 => break,
                            message = socket.next() => message,
                        };
                        let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) = incoming else { break };
                        let command: Value = serde_json::from_str(&text).unwrap();
                        let result = match command["method"].as_str() {
                            Some("Target.attachToTarget") => json!({"sessionId":if connection == 0 {"owned"} else {"new-session"}}),
                            Some("Target.getTargetInfo") => json!({"targetInfo":{"targetId":"retained-page","type":"page","browserContextId":"retained-context"}}),
                            Some("Target.getBrowserContexts") => json!({"browserContextIds":[],"defaultBrowserContextId":"retained-context"}),
                            _ => json!({}),
                        };
                        if socket.send(tokio_tungstenite::tungstenite::Message::Text(json!({"id":command["id"],"result":result}).to_string())).await.is_err() { break; }
                    }
                });
            }
            while tasks.join_next().await.is_some() {}
        });
        let mut manager =
            super::super::browser::BrowserManager::connect_owned_browser(&endpoint, None)
                .await
                .unwrap();
        manager
            .adopt_verified_page("retained-page", "retained-context")
            .await
            .unwrap();
        let retained =
            super::super::client_reconnect::RetainedIdentity::capture(&manager, "retained-context")
                .unwrap();
        let broker = Arc::new(ClientSession::new());
        let (sink, events) = ClientEventSink::test_channel(broker.clone());
        let scope = BlobScope {
            generation: 1,
            identity_scope: "terminal-source".into(),
        };
        let (_stage_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let stage_op = OperationLease {
            generation: 1,
            sequence: 900,
            is_callback: false,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(60),
            cancellation,
        };
        let scoped_sink = sink
            .stage_until_result(&stage_op, &scope.identity_scope)
            .unwrap();
        sink.acknowledge_result_for_test(&ServerMessage::Result {
            retention: None,
            id: "initial".into(),
            generation: 1,
            operation_seq: 900,
            ok: true,
            data: Some(json!({"identityScope":scope.identity_scope})),
            error: None,
            effects: super::super::client_protocol::Effects::Completed,
            scope_state: super::super::client_protocol::ScopeState::Usable,
        })
        .unwrap();
        let sink = scoped_sink;
        let blobs =
            Arc::new(BlobStore::new(super::super::client_blobs::BlobLimits::default()).unwrap());
        blobs.activate_scope(scope.clone()).unwrap();
        let source = Arc::new(ClientNetwork::new(
            manager.client.clone(),
            broker,
            sink,
            scope.clone(),
            blobs,
            Arc::new(super::super::client_ui::UiGate::default()),
            NetworkPolicy::default(),
        ));
        source.sessions.lock().unwrap().insert(
            "owned".into(),
            EnrolledSession {
                sink: source.future_session_sink.lock().unwrap().clone(),
                application: ApplicationSession {
                    session_id: "owned".into(),
                    root_page_session: "owned".into(),
                    active_page: true,
                },
                configuration_ready: tokio::sync::watch::channel(true).0,
            },
        );
        let targets = super::super::client_targets::ClientTargets::new(
            "retained-context".into(),
            scope.identity_scope,
        );
        TerminalFixture {
            source,
            targets,
            retained,
            endpoint,
            disconnect,
            server,
            _events: events,
        }
    }
    async fn disconnect_terminal(
        fixture: &TerminalFixture,
    ) -> super::super::client_enrollment::NativeTerminalProof {
        fixture.disconnect.send_replace(true);
        let mut closed = fixture.source.client.remote_connection_closed();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !*closed.borrow_and_update() {
                closed.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        super::super::client_enrollment::NativeTerminalProof::for_test(
            fixture.source.client.clone(),
            fixture.targets.clone(),
            &fixture.source,
            1,
            "retained-page".into(),
        )
        .unwrap()
    }
    async fn reconnected_network(
        fixture: &TerminalFixture,
        operation: &OperationLease,
    ) -> (
        Arc<ClientNetwork>,
        Arc<super::super::client_targets::ClientTargets>,
        super::super::client_reconnect::VerifiedReconnectProof,
        super::super::browser::BrowserManager,
    ) {
        let verified = super::super::client_reconnect::reconnect(
            &fixture.endpoint,
            &fixture.retained,
            operation,
            "terminal-replacement",
        )
        .await
        .unwrap();
        let (manager, context, target, proof) = verified.into_parts();
        assert_eq!(target, "retained-page");
        let replacement = Arc::new(ClientNetwork::new(
            manager.client.clone(),
            fixture.source.broker.clone(),
            fixture.source.future_session_sink.lock().unwrap().clone(),
            BlobScope {
                generation: 1,
                identity_scope: "terminal-replacement".into(),
            },
            fixture.source.blobs.clone(),
            Arc::new(super::super::client_ui::UiGate::default()),
            NetworkPolicy::default(),
        ));
        let targets = super::super::client_targets::ClientTargets::new(
            context,
            replacement.scope.identity_scope.clone(),
        );
        (replacement, targets, proof, manager)
    }
    #[tokio::test]
    async fn terminal_routes_hold_release_until_exact_reconnect_and_ignore_late_old_scope() {
        let fixture = terminal_fixture().await;
        let source = &fixture.source;
        source
            .replace_routes(7, vec!["first".into(), "second".into()])
            .unwrap();
        let pending = source
            .capture_request("owned", DecisionOwner::Scope, 1000)
            .unwrap();
        let registrations = pending.registrations.clone();
        let terminal = disconnect_terminal(&fixture).await;
        source.close_for_remote_disconnect(&terminal).await.unwrap();
        assert!(matches!(
            pending.outcome.await.unwrap(),
            DecisionOutcome::Cancelled
        ));
        assert_eq!(
            source.broker.decision_resource_scope(1, &pending.token),
            Err(ProtocolError::DecisionMissing)
        );
        assert!(source.tokens.lock().unwrap().is_empty());
        assert!(source
            .broker
            .take_released_registry_events(8)
            .unwrap()
            .is_empty());
        let operation = source.broker.admit(1, 1, 5000).unwrap();
        let wrong_targets = super::super::client_targets::ClientTargets::new(
            "retained-context".into(),
            source.scope.identity_scope.clone(),
        );
        assert!(matches!(
            source.take_disconnected_routes(&wrong_targets, &operation),
            Err(ProtocolError::StaleScope)
        ));
        let mut routes = source
            .take_disconnected_routes(&fixture.targets, &operation)
            .unwrap();
        assert!(source
            .take_disconnected_routes(&fixture.targets, &operation)
            .is_err());
        let (replacement, targets, verified, manager) =
            reconnected_network(&fixture, &operation).await;
        routes
            .bind(&replacement, &targets, &verified, &operation)
            .unwrap();
        let wrong_targets = super::super::client_targets::ClientTargets::new(
            targets.context_id.clone(),
            targets.identity_scope.clone(),
        );
        assert_eq!(
            routes.adopt(&wrong_targets, &operation),
            Err(ProtocolError::StaleScope)
        );
        routes.adopt(&targets, &operation).unwrap();
        assert_eq!(*replacement.registry.lock().unwrap(), Some(7));
        let next = replacement
            .capture_request("new-session", DecisionOwner::Scope, 1000)
            .unwrap();
        assert!(Arc::ptr_eq(&registrations, &next.registrations));
        source.revoke().unwrap();
        source.close().await.unwrap();
        assert_eq!(
            source
                .broker
                .decision_resource_scope(1, &next.token)
                .unwrap(),
            "terminal-replacement"
        );
        assert!(source
            .broker
            .take_released_registry_events(8)
            .unwrap()
            .is_empty());
        assert!(source
            .capture_request("owned", DecisionOwner::Scope, 1000)
            .is_err());
        replacement.close().await.unwrap();
        assert_eq!(
            source.broker.take_released_registry_events(8).unwrap(),
            vec![(7, Some("terminal-replacement".into()))]
        );
        manager.disconnect_transport().await;
        fixture.server.await.unwrap();
    }
    #[tokio::test]
    async fn terminal_routes_wrong_replacement_authority_never_mutates_hold() {
        let fixture = terminal_fixture().await;
        let source = &fixture.source;
        source.replace_routes(1, vec!["route".into()]).unwrap();
        let terminal = disconnect_terminal(&fixture).await;
        source.close_for_remote_disconnect(&terminal).await.unwrap();
        let operation = source.broker.admit(1, 1, 5000).unwrap();
        let mut routes = source
            .take_disconnected_routes(&fixture.targets, &operation)
            .unwrap();
        let (replacement, targets, verified, manager) =
            reconnected_network(&fixture, &operation).await;
        for wrong in [
            "client",
            "store",
            "broker",
            "generation",
            "scope",
            "context",
        ] {
            let candidate = Arc::new(ClientNetwork::new(
                if wrong == "client" {
                    source.client.clone()
                } else {
                    replacement.client.clone()
                },
                if wrong == "broker" {
                    Arc::new(ClientSession::new())
                } else {
                    source.broker.clone()
                },
                source.future_session_sink.lock().unwrap().clone(),
                BlobScope {
                    generation: if wrong == "generation" { 2 } else { 1 },
                    identity_scope: if wrong == "scope" {
                        source.scope.identity_scope.clone()
                    } else {
                        "candidate".into()
                    },
                },
                if wrong == "store" {
                    Arc::new(
                        BlobStore::new(super::super::client_blobs::BlobLimits::default()).unwrap(),
                    )
                } else {
                    source.blobs.clone()
                },
                Arc::new(super::super::client_ui::UiGate::default()),
                NetworkPolicy::default(),
            ));
            let candidate_targets = super::super::client_targets::ClientTargets::new(
                if wrong == "context" {
                    "foreign-context".into()
                } else {
                    "retained-context".into()
                },
                candidate.scope.identity_scope.clone(),
            );
            assert!(
                routes
                    .bind(&candidate, &candidate_targets, &verified, &operation)
                    .is_err(),
                "{wrong}"
            );
            assert!(!candidate.routes_frozen.load(Ordering::Acquire));
        }
        routes
            .bind(&replacement, &targets, &verified, &operation)
            .unwrap();
        assert_eq!(
            routes.bind(&replacement, &targets, &verified, &operation),
            Err(ProtocolError::StaleScope)
        );
        source.broker.cancel(1, 1).unwrap();
        assert_eq!(
            routes.adopt(&targets, &operation),
            Err(ProtocolError::Cancelled)
        );
        assert!(source
            .broker
            .take_released_registry_events(8)
            .unwrap()
            .is_empty());
        routes.retire().unwrap();
        assert_eq!(
            source.broker.take_released_registry_events(8).unwrap(),
            vec![(1, Some(source.scope.identity_scope.clone()))]
        );
        assert!(routes.adopt(&targets, &operation).is_err());
        source.close().await.unwrap();
        replacement.close().await.unwrap();
        manager.disconnect_transport().await;
        fixture.server.await.unwrap();
    }
    #[tokio::test]
    async fn terminal_close_canceled_waiter_cannot_acknowledge_held_reader_early() {
        let fixture = terminal_fixture().await;
        let source = &fixture.source;
        source.replace_routes(1, vec!["route".into()]).unwrap();
        let (release, blocked) = std::sync::mpsc::channel();
        let (started, entered) = tokio::sync::oneshot::channel();
        source
            .blocking_reads
            .lock()
            .unwrap()
            .spawn_blocking(move || {
                let _ = started.send(());
                blocked.recv().unwrap();
            });
        entered.await.unwrap();
        let terminal = Arc::new(disconnect_terminal(&fixture).await);
        let first_source = source.clone();
        let first_terminal = terminal.clone();
        let first = tokio::spawn(async move {
            first_source
                .close_for_remote_disconnect(&first_terminal)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !source.sealed.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        first.abort();
        let _ = first.await;
        let operation = source.broker.admit(1, 1, 5000).unwrap();
        assert!(matches!(
            source.take_disconnected_routes(&fixture.targets, &operation),
            Err(ProtocolError::RegistryInUse)
        ));
        let second_source = source.clone();
        let second_terminal = terminal.clone();
        let mut second = tokio::spawn(async move {
            second_source
                .close_for_remote_disconnect(&second_terminal)
                .await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut second)
                .await
                .is_err()
        );
        assert!(source
            .broker
            .take_released_registry_events(8)
            .unwrap()
            .is_empty());
        release.send(()).unwrap();
        second.await.unwrap().unwrap();
        // Ordinary close after terminal cleanup must retire, not return cached
        // successful cleanup while silently keeping a dormant route snapshot.
        source.close().await.unwrap();
        assert_eq!(
            source.broker.take_released_registry_events(8).unwrap(),
            vec![(1, Some(source.scope.identity_scope.clone()))]
        );
        assert!(source
            .take_disconnected_routes(&fixture.targets, &operation)
            .is_err());
        assert!(source.close_for_remote_disconnect(&terminal).await.is_err());
        fixture.server.abort();
    }
    #[tokio::test]
    async fn terminal_callback_retirement_precedes_blocking_reader_cleanup_and_fences_late_emit() {
        let mut fixture = terminal_fixture().await;
        let source = fixture.source.clone();
        source.replace_routes(1, vec!["route".into()]).unwrap();
        let pending = source
            .capture_request("owned", DecisionOwner::Scope, 30_000)
            .unwrap();
        source
            .retirement_sink
            .emit(
                "network.request".into(),
                json!({"identityScope":source.scope.identity_scope}),
                Some(DecisionNotice {
                    token: pending.token.clone(),
                    timeout_ms: 30_000,
                }),
            )
            .unwrap();
        struct ProducerEnded(Arc<AtomicBool>);
        impl Drop for ProducerEnded {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let producer_ended = Arc::new(AtomicBool::new(false));
        let ended = producer_ended.clone();
        let (started, entered) = tokio::sync::oneshot::channel();
        source.tasks.lock().unwrap().spawn(async move {
            let _ended = ProducerEnded(ended);
            let _ = started.send(());
            std::future::pending::<()>().await;
            Ok(())
        });
        entered.await.unwrap();
        let (release, blocked) = std::sync::mpsc::channel();
        let (started, entered) = tokio::sync::oneshot::channel();
        source
            .blocking_reads
            .lock()
            .unwrap()
            .spawn_blocking(move || {
                let _ = started.send(());
                let _ = blocked.recv();
            });
        entered.await.unwrap();
        let terminal = disconnect_terminal(&fixture).await;
        let closing = source.clone();
        let close =
            tokio::spawn(async move { closing.close_for_remote_disconnect(&terminal).await });
        let first = tokio::time::timeout(std::time::Duration::from_secs(2), fixture._events.recv())
            .await
            .unwrap()
            .unwrap();
        let ServerMessage::Event {
            sequence: first_sequence,
            event,
            ..
        } = first
        else {
            panic!("missing old callback");
        };
        assert_eq!(event, "network.request");
        let retired =
            tokio::time::timeout(std::time::Duration::from_secs(2), fixture._events.recv())
                .await
                .unwrap()
                .unwrap();
        let ServerMessage::Event {
            sequence,
            event,
            payload,
            decision,
            ..
        } = retired
        else {
            panic!("missing callback retirement proof");
        };
        assert_eq!(event, "scope.callbacks-retired");
        assert_eq!(
            payload,
            json!({"identityScope":source.scope.identity_scope,"throughEventSequence":first_sequence})
        );
        assert_eq!(sequence, first_sequence + 1);
        assert!(decision.is_none());
        assert!(producer_ended.load(Ordering::Acquire));
        assert!(matches!(
            pending.outcome.await.unwrap(),
            DecisionOutcome::Cancelled
        ));
        assert!(
            !close.is_finished(),
            "blocking reader must still be retained"
        );
        assert!(!source.cleanup_drained.load(Ordering::Acquire));
        assert!(source
            .retirement_sink
            .emit(
                "app.log".into(),
                json!({"identityScope":source.scope.identity_scope}),
                None
            )
            .is_err());
        assert!(fixture._events.try_recv().is_err());
        release.send(()).unwrap();
        close.await.unwrap().unwrap();
        fixture.server.abort();
    }

    #[tokio::test]
    async fn terminal_failed_drain_and_abandoned_hold_never_reactivate() {
        for fail_reader in [false, true] {
            let fixture = terminal_fixture().await;
            let source = &fixture.source;
            source.replace_routes(1, vec!["route".into()]).unwrap();
            if fail_reader {
                source
                    .blocking_reads
                    .lock()
                    .unwrap()
                    .spawn_blocking(|| panic!("synthetic terminal reader failure"));
            }
            let terminal = disconnect_terminal(&fixture).await;
            let outcome = source.close_for_remote_disconnect(&terminal).await;
            let operation = source.broker.admit(1, 1, 5000).unwrap();
            if fail_reader {
                assert_eq!(outcome, Err(ProtocolError::CleanupFailed));
                assert!(!source.cleanup_drained.load(Ordering::Acquire));
                assert!(matches!(
                    source.take_disconnected_routes(&fixture.targets, &operation),
                    Err(ProtocolError::RegistryInUse)
                ));
                assert!(source
                    .broker
                    .take_released_registry_events(8)
                    .unwrap()
                    .is_empty());
                // Final retirement is attempted independently of cached drain
                // failure, but must still return that unresolved failure.
                assert_eq!(source.close().await, Err(ProtocolError::CleanupFailed));
            } else {
                outcome.unwrap();
                drop(
                    source
                        .take_disconnected_routes(&fixture.targets, &operation)
                        .unwrap(),
                );
                source.close().await.unwrap();
            }
            assert_eq!(
                source.broker.take_released_registry_events(8).unwrap(),
                vec![(1, Some(source.scope.identity_scope.clone()))]
            );
            assert!(source
                .take_disconnected_routes(&fixture.targets, &operation)
                .is_err());
            fixture.server.abort();
        }
    }
    #[tokio::test]
    async fn route_transfer_adopts_same_version_only_after_exact_source_drain() {
        let (source, _events, _commands, server) = fixture().await;
        let (_cancel, operation) = download_operation();
        source
            .replace_routes(7, vec!["first".into(), "second".into()])
            .unwrap();
        let mut transfer = source.capture_route_transfer(&operation).unwrap();
        assert_eq!(
            source
                .capture_request("owned", DecisionOwner::Scope, 1000)
                .err()
                .unwrap(),
            ProtocolError::StaleScope
        );
        assert_eq!(
            source.replace_routes(8, vec![]),
            Err(ProtocolError::StaleScope)
        );
        let replacement = route_replacement(&source, "replacement");
        transfer.bind_unmanaged(&replacement).unwrap();
        assert_eq!(
            transfer.adopt(&operation),
            Err(ProtocolError::RegistryInUse)
        );
        assert!(source
            .broker
            .take_released_registry_events(8)
            .unwrap()
            .is_empty());
        source.close().await.unwrap();
        assert!(source.cleanup_drained.load(Ordering::Acquire));
        assert!(source
            .broker
            .take_released_registry_events(8)
            .unwrap()
            .is_empty());
        transfer.adopt(&operation).unwrap();
        let request = replacement
            .capture_request("replacement-page", DecisionOwner::Scope, 1000)
            .unwrap();
        assert_eq!(request.registry_version, Some(7));
        assert_eq!(
            request.registrations.as_ref(),
            &["first".to_owned(), "second".to_owned()]
        );
        assert_eq!(
            source
                .broker
                .decision_scoped(
                    1,
                    DecisionOwner::Scope,
                    DecisionKind::Request,
                    1000,
                    Some(7),
                    Some(source.scope.identity_scope.clone())
                )
                .err()
                .unwrap(),
            ProtocolError::StaleScope
        );
        source.revoke().unwrap();
        assert!(source
            .broker
            .take_released_registry_events(8)
            .unwrap()
            .is_empty());
        replacement.replace_routes(8, vec![]).unwrap();
        replacement.broker.revoke_decision(&request.token).unwrap();
        assert_eq!(
            source.broker.take_released_registry_events(8).unwrap(),
            vec![(7, Some("replacement".into()))]
        );
        replacement.close().await.unwrap();
        assert_eq!(
            source.broker.take_released_registry_events(8).unwrap(),
            vec![(8, Some("replacement".into()))]
        );
        server.abort();
    }
    #[tokio::test]
    async fn route_transfer_rejects_foreign_client_store_broker_generation_and_rebinding() {
        let (source, _events, _commands, server) = fixture().await;
        let (foreign, _foreign_events, _foreign_commands, foreign_server) = fixture().await;
        let (_cancel, operation) = download_operation();
        source.replace_routes(1, vec!["route".into()]).unwrap();
        let mut transfer = source.capture_route_transfer(&operation).unwrap();
        assert_eq!(
            transfer.bind_unmanaged(&source),
            Err(ProtocolError::StaleScope)
        );
        for kind in ["client", "broker", "store", "generation", "identity"] {
            let client = if kind == "client" {
                foreign.client.clone()
            } else {
                source.client.clone()
            };
            let broker = if kind == "broker" {
                foreign.broker.clone()
            } else {
                source.broker.clone()
            };
            let blobs = if kind == "store" {
                foreign.blobs.clone()
            } else {
                source.blobs.clone()
            };
            let candidate = Arc::new(ClientNetwork::new(
                client,
                broker,
                source.future_session_sink.lock().unwrap().clone(),
                BlobScope {
                    generation: if kind == "generation" { 2 } else { 1 },
                    identity_scope: if kind == "identity" {
                        source.scope.identity_scope.clone()
                    } else {
                        format!("wrong-{kind}")
                    },
                },
                blobs,
                Arc::new(super::super::client_ui::UiGate::default()),
                NetworkPolicy::default(),
            ));
            assert_eq!(
                transfer.bind_unmanaged(&candidate),
                Err(if kind == "generation" {
                    ProtocolError::StaleGeneration
                } else {
                    ProtocolError::StaleScope
                })
            );
            assert!(!candidate.routes_frozen.load(Ordering::Acquire));
        }
        let replacement = route_replacement(&source, "replacement");
        let other = route_replacement(&source, "other-replacement");
        transfer.bind_unmanaged(&replacement).unwrap();
        assert_eq!(
            transfer.bind_unmanaged(&other),
            Err(ProtocolError::StaleScope)
        );
        assert!(!other.routes_frozen.load(Ordering::Acquire));
        transfer.restore(&operation).unwrap();
        assert!(!source.routes_frozen.load(Ordering::Acquire));
        assert_eq!(*source.registry.lock().unwrap(), Some(1));
        assert!(source
            .broker
            .take_released_registry_events(8)
            .unwrap()
            .is_empty());
        source.close().await.unwrap();
        replacement.close().await.unwrap();
        foreign.close().await.unwrap();
        server.abort();
        foreign_server.abort();
    }
    #[tokio::test]
    async fn canceled_or_abandoned_transfer_never_reactivates_routes() {
        for cancel_after_close in [false, true] {
            let (source, _events, _commands, server) = fixture().await;
            let (cancel, operation) = download_operation();
            source.replace_routes(1, vec!["route".into()]).unwrap();
            let mut transfer = source.capture_route_transfer(&operation).unwrap();
            let replacement = route_replacement(&source, "replacement");
            transfer.bind_unmanaged(&replacement).unwrap();
            if cancel_after_close {
                source.close().await.unwrap();
            }
            cancel.send(CancelSignal::Requested).unwrap();
            assert_eq!(transfer.adopt(&operation), Err(ProtocolError::Cancelled));
            assert_eq!(transfer.restore(&operation), Err(ProtocolError::Cancelled));
            assert!(source
                .broker
                .take_released_registry_events(8)
                .unwrap()
                .is_empty());
            drop(transfer);
            assert_eq!(
                source.broker.take_released_registry_events(8).unwrap(),
                vec![(1, Some(source.scope.identity_scope.clone()))]
            );
            assert!(source.routes_frozen.load(Ordering::Acquire));
            assert!(replacement.routes_frozen.load(Ordering::Acquire));
            assert!(source.replace_routes(2, vec![]).is_err());
            source.close().await.unwrap();
            replacement.close().await.unwrap();
            assert!(source
                .broker
                .take_released_registry_events(8)
                .unwrap()
                .is_empty());
            server.abort();
        }
    }
    #[tokio::test]
    async fn close_seals_and_aborts_owner_tasks_before_first_yield() {
        let (source, mut events, mut commands, server) = fixture().await;
        let ran = Arc::new(AtomicBool::new(false));
        let task_ran = ran.clone();
        source.tasks.lock().unwrap().spawn(async move {
            task_ran.store(true, Ordering::Release);
            Ok(())
        });
        let mut first = Box::pin(source.close());
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(first.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert!(source.sealed.load(Ordering::Acquire));
        assert_eq!(*source.cancellation.borrow(), CancelSignal::SessionClosed);
        assert!(!source.cleanup_drained.load(Ordering::Acquire));
        drop(first);
        source.close().await.unwrap();
        assert!(!ran.load(Ordering::Acquire));
        assert!(source.cleanup_drained.load(Ordering::Acquire));
        assert!(events.try_recv().is_err());
        assert!(commands.try_recv().is_err());
        server.abort();
    }
    #[tokio::test]
    async fn retained_close_survives_canceled_waiter_and_blocks_transfer_until_reader_settles() {
        let (source, _events, _commands, server) = fixture().await;
        let (_cancel, operation) = download_operation();
        source.replace_routes(1, vec!["route".into()]).unwrap();
        let mut transfer = source.capture_route_transfer(&operation).unwrap();
        let replacement = route_replacement(&source, "replacement");
        transfer.bind_unmanaged(&replacement).unwrap();
        let (release, wait) = std::sync::mpsc::channel();
        let (started, entered) = tokio::sync::oneshot::channel();
        source
            .blocking_reads
            .lock()
            .unwrap()
            .spawn_blocking(move || {
                let _ = started.send(());
                wait.recv().unwrap();
            });
        entered.await.unwrap();
        let first_source = source.clone();
        let first = tokio::spawn(async move { first_source.close().await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !source.sealed.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        first.abort();
        let _ = first.await;
        let second_source = source.clone();
        let mut second = tokio::spawn(async move { second_source.close().await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut second)
                .await
                .is_err()
        );
        assert!(!source.cleanup_drained.load(Ordering::Acquire));
        assert_eq!(
            transfer.adopt(&operation),
            Err(ProtocolError::RegistryInUse)
        );
        assert!(source
            .broker
            .take_released_registry_events(8)
            .unwrap()
            .is_empty());
        release.send(()).unwrap();
        second.await.unwrap().unwrap();
        source.close().await.unwrap();
        assert!(source.cleanup_drained.load(Ordering::Acquire));
        transfer.adopt(&operation).unwrap();
        replacement.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn failed_close_is_retained_and_never_becomes_empty_set_success() {
        let (source, _events, _commands, server) = fixture().await;
        let (_cancel, operation) = download_operation();
        source.replace_routes(1, vec!["route".into()]).unwrap();
        let mut transfer = source.capture_route_transfer(&operation).unwrap();
        let replacement = route_replacement(&source, "replacement");
        transfer.bind_unmanaged(&replacement).unwrap();
        source
            .blocking_reads
            .lock()
            .unwrap()
            .spawn_blocking(|| panic!("synthetic retained reader failure"));
        assert_eq!(source.close().await, Err(ProtocolError::CleanupFailed));
        assert_eq!(source.close().await, Err(ProtocolError::CleanupFailed));
        assert!(!source.cleanup_drained.load(Ordering::Acquire));
        assert_eq!(
            transfer.adopt(&operation),
            Err(ProtocolError::RegistryInUse)
        );
        assert_eq!(transfer.restore(&operation), Err(ProtocolError::StaleScope));
        transfer.retire().unwrap();
        replacement.close().await.unwrap();
        server.abort();
    }
    fn download_operation() -> (tokio::sync::watch::Sender<CancelSignal>, OperationLease) {
        let (cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        (
            cancel,
            OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(5),
                cancellation,
            },
        )
    }
    #[tokio::test]
    async fn replacement_session_events_keep_captured_ack_sink_while_old_session_stays_live() {
        let (network, mut events, _commands, server) = fixture().await;
        let (_cancel, operation) = download_operation();
        let source = network.future_session_sink.lock().unwrap().clone();
        let staged = source
            .stage_until_result(&operation, &network.scope.identity_scope)
            .unwrap();
        network
            .set_future_session_sink(staged.clone(), &network.scope.identity_scope, &operation)
            .unwrap();
        network
            .configure_session(
                ApplicationSession {
                    session_id: "replacement".into(),
                    root_page_session: "replacement".into(),
                    active_page: true,
                },
                &operation,
            )
            .await
            .unwrap();
        network.subscribe_responses().unwrap();
        for session in ["replacement", "owned"] {
            network.event(&CdpEvent {method:"Network.responseReceived".into(),session_id:Some(session.into()),
                params:json!({"requestId":session,"response":{"url":format!("https://synthetic.test/{session}"),"status":200,"headers":{}}})}).unwrap();
        }
        let ServerMessage::Event { event, payload, .. } = events.try_recv().unwrap() else {
            panic!("expected old-session response")
        };
        assert_eq!(event, "network.response");
        assert_eq!(payload["url"], "https://synthetic.test/owned");
        assert!(events.try_recv().is_err());
        assert!(network
            .sessions
            .lock()
            .unwrap()
            .get("replacement")
            .unwrap()
            .sink
            .validate_stage(&source, &operation, &network.scope.identity_scope)
            .is_ok());
        assert!(network
            .sessions
            .lock()
            .unwrap()
            .get("owned")
            .unwrap()
            .sink
            .validate_stage(&source, &operation, &network.scope.identity_scope)
            .is_err());
        network.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn unpublished_callback_does_not_block_exclusive_initialization_before_ack() {
        let (network, mut events, _commands, server) = fixture().await;
        let (_cancel, operation) = download_operation();
        let source = network.future_session_sink.lock().unwrap().clone();
        let staged = source
            .stage_until_result(&operation, &network.scope.identity_scope)
            .unwrap();
        network
            .set_future_session_sink(staged, &network.scope.identity_scope, &operation)
            .unwrap();
        network
            .configure_session(
                ApplicationSession {
                    session_id: "replacement".into(),
                    root_page_session: "replacement".into(),
                    active_page: true,
                },
                &operation,
            )
            .await
            .unwrap();
        network
            .configuration_committed("replacement", &operation)
            .unwrap();
        network.replace_routes(1, vec!["route".into()]).unwrap();
        network.event(&CdpEvent {method:"Fetch.requestPaused".into(),session_id:Some("replacement".into()),
            params:json!({"requestId":"first-script","request":{"url":"https://synthetic.test/first","method":"GET","headers":{}}})}).unwrap();
        let exclusive = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            network.ui_gate.enter(
                true,
                false,
                operation.deadline,
                operation.cancellation.clone(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        tokio::task::yield_now().await;
        assert!(events.try_recv().is_err());
        source
            .acknowledge_result_for_test(&ServerMessage::Result {
                retention: None,
                id: "restart".into(),
                generation: 1,
                operation_seq: operation.sequence,
                ok: true,
                data: Some(json!({"identityScope":network.scope.identity_scope})),
                error: None,
                effects: super::super::client_protocol::Effects::Completed,
                scope_state: super::super::client_protocol::ScopeState::Usable,
            })
            .unwrap();
        assert!(events.try_recv().is_err());
        drop(exclusive);
        let ServerMessage::Event {
            event,
            decision: Some(decision),
            ..
        } = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .unwrap()
        else {
            panic!("expected post-ACK request")
        };
        assert_eq!(event, "network.request");
        network
            .broker
            .resolve(
                1,
                &decision.token,
                Decision::Continue {
                    overrides: Default::default(),
                },
            )
            .unwrap();
        let mut tasks = std::mem::take(&mut *network.tasks.lock().unwrap());
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        network.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn future_session_sink_rejects_wrong_scope_and_cancelled_operation() {
        let (network, _events, _commands, server) = fixture().await;
        let (cancel, operation) = download_operation();
        let source = network.future_session_sink.lock().unwrap().clone();
        let staged = source
            .stage_until_result(&operation, &network.scope.identity_scope)
            .unwrap();
        assert_eq!(
            network.set_future_session_sink(staged.clone(), "other", &operation),
            Err(ProtocolError::StaleScope)
        );
        cancel.send_replace(CancelSignal::SessionClosed);
        assert_eq!(
            network.set_future_session_sink(staged, &network.scope.identity_scope, &operation),
            Err(ProtocolError::Cancelled)
        );
        network.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn download_setup_rejects_stale_cancelled_expired_before_journal_or_cdp() {
        for mode in 0..3 {
            let (network, _events, mut commands, server) = fixture().await;
            let (cancel, mut operation) = download_operation();
            let expected = match mode {
                0 => {
                    operation.generation += 1;
                    ProtocolError::StaleGeneration
                }
                1 => {
                    cancel.send_replace(CancelSignal::Requested);
                    ProtocolError::Cancelled
                }
                _ => {
                    operation.deadline = std::time::Instant::now();
                    ProtocolError::DeadlineExceeded
                }
            };
            assert_eq!(
                network
                    .configure_downloads(
                        "owned-context",
                        DownloadSource::Provider("/provider-owned".into()),
                        &operation
                    )
                    .await,
                Err(expected)
            );
            assert!(network.download_source.lock().unwrap().is_none());
            assert!(network.download_context.lock().unwrap().is_none());
            assert!(commands.try_recv().is_err());
            assert_eq!(
                network.broker.health().unwrap().1,
                super::super::client_protocol::ScopeState::Usable
            );
            server.abort();
        }
    }
    #[tokio::test]
    async fn download_setup_acknowledges_once_and_rejects_replacement() {
        let (network, _events, mut commands, server) = fixture().await;
        let (_cancel, operation) = download_operation();
        network
            .configure_downloads(
                "owned-context",
                DownloadSource::Provider("/provider-owned".into()),
                &operation,
            )
            .await
            .unwrap();
        assert!(network.download_ready.load(Ordering::Acquire));
        assert!(network.subscribe_downloads().is_ok());
        let command = commands.recv().await.unwrap();
        assert_eq!(command["method"], "Browser.setDownloadBehavior");
        assert_eq!(command["params"]["browserContextId"], "owned-context");
        assert_eq!(
            network
                .configure_downloads(
                    "other",
                    DownloadSource::Provider("/replacement".into()),
                    &operation
                )
                .await,
            Err(ProtocolError::InvalidArguments)
        );
        assert!(commands.try_recv().is_err());
        assert_eq!(
            network.download_context.lock().unwrap().as_deref(),
            Some("owned-context")
        );
        network.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn local_download_setup_retains_and_drains_directory_validation_worker() {
        let (network, _events, mut commands, server) = fixture().await;
        let (_cancel, operation) = download_operation();
        let directory = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(directory.path()).unwrap();
        network
            .configure_downloads(
                "owned-context",
                DownloadSource::Local(canonical.clone()),
                &operation,
            )
            .await
            .unwrap();
        assert_eq!(
            commands.recv().await.unwrap()["params"]["downloadPath"],
            canonical.to_string_lossy().as_ref()
        );
        network.close().await.unwrap();
        assert!(network.blocking_reads.lock().unwrap().is_empty());
        assert!(
            matches!(&*network.download_source.lock().unwrap(),Some(DownloadSource::Local(path)) if path==&canonical)
        );
        server.abort();
    }
    #[tokio::test]
    async fn lost_download_setup_ack_retains_journal_and_quarantines_timeout_cancel_or_drop() {
        for mode in 0..3 {
            let (network, _events, mut commands, server) = fixture_with_download_delay(true).await;
            let (cancel, mut operation) = download_operation();
            if mode == 0 {
                operation.deadline =
                    std::time::Instant::now() + std::time::Duration::from_millis(100);
            }
            let child = network.clone();
            let task = tokio::spawn(async move {
                child
                    .configure_downloads(
                        "owned-context",
                        DownloadSource::Provider("/provider-owned".into()),
                        &operation,
                    )
                    .await
            });
            tokio::time::timeout(std::time::Duration::from_secs(1), commands.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(!network.download_ready.load(Ordering::Acquire));
            assert_eq!(
                network.subscribe_downloads(),
                Err(ProtocolError::UnsupportedCapability)
            );
            if mode == 2 {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                if mode == 1 {
                    cancel.send_replace(CancelSignal::Requested);
                }
                assert_eq!(
                    task.await.unwrap(),
                    Err(if mode == 0 {
                        ProtocolError::DeadlineExceeded
                    } else {
                        ProtocolError::Cancelled
                    })
                );
            }
            assert!(
                matches!(&*network.download_source.lock().unwrap(),Some(DownloadSource::Provider(path)) if path=="/provider-owned")
            );
            assert_eq!(
                network.download_context.lock().unwrap().as_deref(),
                Some("owned-context")
            );
            assert!(!network.download_ready.load(Ordering::Acquire));
            assert_eq!(
                network.broker.health().unwrap().1,
                super::super::client_protocol::ScopeState::Quarantined
            );
            network.close().await.unwrap();
            assert!(network.download_source.lock().unwrap().is_some());
            server.abort();
        }
    }
    #[tokio::test]
    async fn expired_borrowed_cleanup_budget_never_restarts_per_request() {
        let (network, _events, mut commands, server) = fixture().await;
        {
            let mut pending = network.pending_interceptions.lock().unwrap();
            for index in 0..2048 {
                pending.insert(
                    (
                        "owned".into(),
                        "Fetch.requestPaused".into(),
                        format!("request-{index}"),
                    ),
                    (),
                );
            }
        }
        let started = std::time::Instant::now();
        assert_eq!(
            network
                .release_borrowed_interception(&network.scope.identity_scope, "owned", started)
                .await,
            Err(ProtocolError::CleanupFailed)
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(commands.try_recv().is_err());
        assert_eq!(network.pending_interceptions.lock().unwrap().len(), 2048);
        server.abort();
    }
    #[tokio::test]
    async fn borrowed_retirement_settles_owned_auth_dialog_and_request_only() {
        let (network, _events, mut commands, server) = fixture().await;
        for (method, params) in [
            (
                "Fetch.requestPaused",
                json!({"requestId":"pending-request","request":{"url":"https://synthetic.test/","method":"GET","headers":{}}}),
            ),
            (
                "Fetch.authRequired",
                json!({"requestId":"pending-auth","request":{"url":"https://synthetic.test/"},"authChallenge":{"source":"Server","origin":"https://synthetic.test","scheme":"Basic","realm":"synthetic"}}),
            ),
            (
                "Page.javascriptDialogOpening",
                json!({"type":"confirm","message":"synthetic"}),
            ),
        ] {
            network
                .event(&CdpEvent {
                    method: method.into(),
                    session_id: Some("owned".into()),
                    params,
                })
                .unwrap();
        }
        network.close().await.unwrap();
        assert_eq!(
            network
                .release_borrowed_interception(
                    "wrong-scope",
                    "owned",
                    std::time::Instant::now() + std::time::Duration::from_secs(2)
                )
                .await,
            Err(ProtocolError::StaleScope)
        );
        assert_eq!(
            network
                .release_borrowed_interception(
                    &network.scope.identity_scope,
                    "foreign",
                    std::time::Instant::now() + std::time::Duration::from_secs(2)
                )
                .await,
            Err(ProtocolError::StaleScope)
        );
        network
            .release_borrowed_interception(
                &network.scope.identity_scope,
                "owned",
                std::time::Instant::now() + std::time::Duration::from_secs(2),
            )
            .await
            .unwrap();
        let mut recorded = Vec::new();
        while let Ok(command) = commands.try_recv() {
            recorded.push(command);
        }
        for method in [
            "Fetch.failRequest",
            "Fetch.continueWithAuth",
            "Page.handleJavaScriptDialog",
            "Fetch.disable",
            "Network.disable",
        ] {
            assert!(
                recorded.iter().any(|v| v["method"] == method),
                "missing {method}"
            );
        }
        assert!(recorded.iter().all(|v| v["sessionId"] == "owned"));
        assert!(network.pending_interceptions.lock().unwrap().is_empty());
        server.abort();
    }
    #[tokio::test]
    async fn rejected_resource_release_keeps_maps_body_and_quota_intact() {
        let (mut network, _events, _commands, server) = fixture().await;
        let blobs = Arc::new(
            BlobStore::new(super::super::client_blobs::BlobLimits {
                max_blob_bytes: 3,
                max_total_bytes: 3,
                max_handles: 1,
            })
            .unwrap(),
        );
        blobs.activate_scope(network.scope.clone()).unwrap();
        Arc::get_mut(&mut network).unwrap().blobs = blobs.clone();
        let blob = blobs.insert_sealed(network.scope.clone(), b"abc").unwrap();
        let (handle, resource) = network.new_resource().unwrap();
        network
            .finish_resource(&handle, Ok(blob.handle.clone()))
            .unwrap();
        network.downloads.lock().unwrap().insert(
            "guid".into(),
            DownloadEntry {
                handle: handle.clone(),
                resource,
                completed: true,
                terminal_started: true,
                published: true,
                reservation: None,
            },
        );
        blobs
            .reserve(&network.scope, &blob.handle, "body-owner")
            .unwrap();
        assert_eq!(
            network.release_body(&handle),
            Err(ProtocolError::CleanupFailed)
        );
        assert!(network.resources.lock().unwrap().contains_key(&handle));
        assert!(network.downloads.lock().unwrap().contains_key("guid"));
        assert_eq!(
            blobs.read(&network.scope, &blob.handle, 0, 3).unwrap(),
            b"abc"
        );
        assert!(matches!(
            blobs.create(network.scope.clone(), 1, "0".repeat(64)),
            Err(super::super::client_blobs::BlobError::QuotaExceeded)
        ));
        blobs.rollback("body-owner").unwrap();
        network.release_body(&handle).unwrap();
        assert!(!network.resources.lock().unwrap().contains_key(&handle));
        assert!(network.downloads.lock().unwrap().is_empty());
        assert!(blobs
            .create(network.scope.clone(), 3, "0".repeat(64))
            .is_ok());
        server.abort();
    }
    #[tokio::test]
    async fn uncommitted_session_hold_uses_original_deadline_and_scope_cancellation() {
        let (network, _events, _commands, server) = fixture().await;
        let (ready, receiver) = tokio::sync::watch::channel(false);
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(10);
        assert_eq!(
            network.wait_for_configuration(receiver, deadline).await,
            Err(ProtocolError::DeadlineExceeded)
        );
        let child = network.clone();
        let receiver = ready.subscribe();
        let waiting = tokio::spawn(async move {
            child
                .wait_for_configuration(
                    receiver,
                    std::time::Instant::now() + std::time::Duration::from_secs(30),
                )
                .await
        });
        network.revoke().unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        server.abort();
    }
    #[tokio::test]
    async fn retired_page_callbacks_never_rebind_after_exclusive_ui_wait() {
        for reuse_textual_session in [false, true] {
            let (network, mut events, mut commands, server) = fixture().await;
            assert!(network.uses_ui_gate(&network.ui_gate));
            assert!(!network.uses_ui_gate(&Arc::new(super::super::client_ui::UiGate::default())));
            let (_cancel, operation) = download_operation();
            let exclusive = network
                .ui_gate
                .enter(
                    true,
                    false,
                    operation.deadline,
                    operation.cancellation.clone(),
                )
                .await
                .unwrap();
            for (method, params) in [
                (
                    "Fetch.requestPaused",
                    json!({"requestId":"old-request","request":{"url":"https://synthetic.test/","method":"GET","headers":{}}}),
                ),
                (
                    "Fetch.authRequired",
                    json!({"requestId":"old-auth","request":{"url":"https://synthetic.test/"},"authChallenge":{"source":"Server","origin":"https://synthetic.test","scheme":"basic","realm":"synthetic"}}),
                ),
                (
                    "Page.javascriptDialogOpening",
                    json!({"type":"alert","message":"synthetic old page"}),
                ),
            ] {
                network
                    .event(&CdpEvent {
                        method: method.into(),
                        session_id: Some("owned".into()),
                        params,
                    })
                    .unwrap();
            }
            tokio::task::yield_now().await;
            network.detach_session("owned").unwrap();
            if reuse_textual_session {
                network.sessions.lock().unwrap().insert(
                    "owned".into(),
                    EnrolledSession {
                        sink: network.future_session_sink.lock().unwrap().clone(),
                        application: ApplicationSession {
                            session_id: "owned".into(),
                            root_page_session: "owned".into(),
                            active_page: true,
                        },
                        configuration_ready: tokio::sync::watch::channel(true).0,
                    },
                );
            }
            drop(exclusive);
            let mut tasks = std::mem::take(&mut *network.tasks.lock().unwrap());
            while let Some(result) = tasks.join_next().await {
                result.unwrap().unwrap();
            }
            assert_eq!(network.pending_callbacks().unwrap(), 0);
            assert!(events.try_recv().is_err());
            assert!(commands.try_recv().is_err());
            assert!(network.check().is_ok());
            network.close().await.unwrap();
            server.abort();
        }
    }
    #[tokio::test]
    async fn surviving_worker_callback_keeps_its_original_route_after_page_retirement() {
        let (network, mut events, mut commands, server) = fixture().await;
        network.sessions.lock().unwrap().insert(
            "worker".into(),
            EnrolledSession {
                sink: network.future_session_sink.lock().unwrap().clone(),
                application: ApplicationSession {
                    session_id: "worker".into(),
                    root_page_session: "worker".into(),
                    active_page: false,
                },
                configuration_ready: tokio::sync::watch::channel(true).0,
            },
        );
        network
            .replace_routes(1, vec!["attempt-route".into()])
            .unwrap();
        let (_cancel, operation) = download_operation();
        let exclusive = network
            .ui_gate
            .enter(
                true,
                false,
                operation.deadline,
                operation.cancellation.clone(),
            )
            .await
            .unwrap();
        network.event(&CdpEvent {
            method: "Fetch.requestPaused".into(),
            session_id: Some("worker".into()),
            params: json!({"requestId":"worker-request","request":{"url":"https://synthetic.test/","method":"GET","headers":{}}}),
        }).unwrap();
        tokio::task::yield_now().await;
        network.detach_session("owned").unwrap();
        drop(exclusive);
        let (name, payload, decision) = next_event(&mut events).await;
        assert_eq!(name, "network.request");
        assert_eq!(payload["version"], 1);
        assert_eq!(payload["registrationIds"], json!(["attempt-route"]));
        network
            .broker
            .resolve(1, &decision.unwrap().token, Decision::Abort {})
            .unwrap();
        let mut tasks = std::mem::take(&mut *network.tasks.lock().unwrap());
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        let command = commands.recv().await.unwrap();
        assert_eq!(command["method"], "Fetch.failRequest");
        assert_eq!(command["sessionId"], "worker");
        assert_eq!(network.pending_callbacks().unwrap(), 0);
        assert!(network.check().is_ok());
        network.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn uncommitted_request_backpressure_never_emits_callbacks_or_leaks_tokens() {
        let (network, mut events, mut commands, server) = fixture().await;
        network.sessions.lock().unwrap()["owned"]
            .configuration_ready
            .send_replace(false);
        for index in 0..64 {
            network.event(&CdpEvent{method:"Fetch.requestPaused".into(),session_id:Some("owned".into()),params:json!({"requestId":format!("held-{index}"),"request":{"url":"https://synthetic.test/","method":"GET","headers":{}}})}).unwrap();
        }
        assert_eq!(network.event(&CdpEvent{method:"Fetch.requestPaused".into(),session_id:Some("owned".into()),params:json!({"requestId":"overflow","request":{"url":"https://synthetic.test/","method":"GET","headers":{}}})}),Err(ProtocolError::CapacityExceeded));
        network.close().await.unwrap();
        assert_eq!(network.pending_callbacks().unwrap(), 0);
        assert!(events.try_recv().is_err());
        assert!(commands.try_recv().is_err());
        server.abort();
    }
    async fn next_event(
        events: &mut tokio::sync::mpsc::Receiver<ServerMessage>,
    ) -> (String, Value, Option<DecisionNotice>) {
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
            .await
            .unwrap()
            .unwrap();
        let ServerMessage::Event {
            event,
            payload,
            decision,
            ..
        } = event
        else {
            panic!("expected event")
        };
        (event, payload, decision)
    }
    #[tokio::test]
    async fn cleanup_failure_still_joins_every_retained_blocking_reader() {
        let (network, _, _, server) = fixture().await;
        let completed = Arc::new(AtomicBool::new(false));
        {
            let mut readers = network.blocking_reads.lock().unwrap();
            readers.spawn_blocking(|| panic!("synthetic cleanup panic"));
            let completed = completed.clone();
            readers.spawn_blocking(move || {
                std::thread::sleep(std::time::Duration::from_millis(30));
                completed.store(true, Ordering::Release);
            });
        }
        assert_eq!(network.close().await, Err(ProtocolError::CleanupFailed));
        assert!(completed.load(Ordering::Acquire));
        server.abort();
    }
    #[tokio::test]
    async fn revoke_failure_cannot_skip_owned_reader_drain() {
        let (network, _, _, server) = fixture().await;
        let poison = network.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poison.tokens.lock().unwrap();
            panic!("synthetic poisoned token registry");
        })
        .join();
        let completed = Arc::new(AtomicBool::new(false));
        {
            let completed = completed.clone();
            network
                .blocking_reads
                .lock()
                .unwrap()
                .spawn_blocking(move || {
                    std::thread::sleep(std::time::Duration::from_millis(30));
                    completed.store(true, Ordering::Release);
                });
        }
        assert_eq!(network.close().await, Err(ProtocolError::CleanupFailed));
        assert!(completed.load(Ordering::Acquire));
        server.abort();
    }

    #[tokio::test]
    async fn proxy_challenge_never_receives_application_credentials() {
        let (network, mut events, mut commands, server) = fixture().await;
        network.event(&CdpEvent{method:"Fetch.authRequired".into(),session_id:Some("owned".into()),params:json!({"requestId":"proxy","request":{"url":"https://app.test/"},"authChallenge":{"source":"Proxy","origin":"https://app.test","scheme":"Basic","realm":"synthetic"}})}).unwrap();
        let command = tokio::time::timeout(std::time::Duration::from_secs(2), commands.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(command["method"], "Fetch.continueWithAuth");
        assert_eq!(
            command["params"]["authChallengeResponse"],
            json!({"response":"CancelAuth"})
        );
        assert!(events.try_recv().is_err());
        network.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn owned_download_completes_without_browser_action_mutex() {
        let (network, mut events, _, server) = fixture().await;
        let directory = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(directory.path()).unwrap();
        *network.download_source.lock().unwrap() = Some(DownloadSource::Local(canonical.clone()));
        *network.download_context.lock().unwrap() = Some("owned-context".into());
        network.download_ready.store(true, Ordering::Release);
        network.subscribe_downloads().unwrap();
        std::fs::write(canonical.join("synthetic-guid"), b"downloaded").unwrap();
        network.event(&CdpEvent{method:"Browser.downloadWillBegin".into(),session_id:Some("owned".into()),params:json!({"guid":"synthetic-guid","frameId":"owned-frame","suggestedFilename":"example.txt"})}).unwrap();
        let (_, event, _) = next_event(&mut events).await;
        let handle = event["handle"].as_str().unwrap();
        network
            .event(&CdpEvent {
                method: "Browser.downloadProgress".into(),
                session_id: None,
                params: json!({"guid":"synthetic-guid","state":"completed","receivedBytes":10}),
            })
            .unwrap();
        let operation = network.broker.admit(1, 1, 2000).unwrap();
        assert_eq!(
            network.download_metadata(handle, &operation).await.unwrap()["source"],
            "local"
        );
        let bytes = network
            .read_resource(handle, 0, 32, &operation)
            .await
            .unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(bytes.base64)
                .unwrap(),
            b"downloaded"
        );
        assert!(!canonical.join("synthetic-guid").exists());
        network.release_body(handle).unwrap();
        network.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn canonical_browser_download_ignores_legacy_stream_before_and_after_release() {
        let (network, mut events, _, server) = fixture().await;
        let directory = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(directory.path()).unwrap();
        *network.download_source.lock().unwrap() = Some(DownloadSource::Local(canonical.clone()));
        *network.download_context.lock().unwrap() = Some("owned-context".into());
        network.download_ready.store(true, Ordering::Release);
        network.subscribe_downloads().unwrap();
        let params = json!({"guid":"duplicate-guid","frameId":"owned-frame","url":"https://synthetic.test/file","suggestedFilename":"example.txt"});
        network
            .event(&CdpEvent {
                method: "Page.downloadWillBegin".into(),
                session_id: Some("owned".into()),
                params: params.clone(),
            })
            .unwrap();
        assert!(network.resources.lock().unwrap().is_empty());
        assert!(events.try_recv().is_err());
        for method in ["Browser.downloadWillBegin", "Page.downloadWillBegin"] {
            network
                .event(&CdpEvent {
                    method: method.into(),
                    session_id: Some("owned".into()),
                    params: params.clone(),
                })
                .unwrap();
        }
        let (_, event, _) = next_event(&mut events).await;
        let handle = event["handle"].as_str().unwrap();
        assert!(events.try_recv().is_err());
        assert_eq!(network.downloads.lock().unwrap().len(), 1);
        assert_eq!(network.resources.lock().unwrap().len(), 1);
        // A second maximum producer still fits the default two-producer quota:
        // the duplicate did not reserve another hidden producer.
        drop(
            network
                .blobs
                .reserve_producer(network.scope.clone())
                .unwrap(),
        );
        network
            .event(&CdpEvent {
                method: "Page.downloadProgress".into(),
                session_id: Some("owned".into()),
                params: json!({"guid":"duplicate-guid","state":"canceled"}),
            })
            .unwrap();
        assert!(
            !network
                .downloads
                .lock()
                .unwrap()
                .get("duplicate-guid")
                .unwrap()
                .terminal_started
        );
        std::fs::write(canonical.join("duplicate-guid"), b"downloaded").unwrap();
        network
            .event(&CdpEvent {
                method: "Browser.downloadProgress".into(),
                session_id: None,
                params: json!({"guid":"duplicate-guid","state":"completed","receivedBytes":10}),
            })
            .unwrap();
        let operation = network.broker.admit(1, 1, 2000).unwrap();
        let bytes = network
            .read_resource(handle, 0, 32, &operation)
            .await
            .unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(bytes.base64)
                .unwrap(),
            b"downloaded"
        );
        network.release_body(handle).unwrap();
        for method in ["Page.downloadWillBegin", "Page.downloadProgress"] {
            network
                .event(&CdpEvent {
                    method: method.into(),
                    session_id: Some("owned".into()),
                    params: params.clone(),
                })
                .unwrap();
        }
        assert!(events.try_recv().is_err());
        assert!(network.downloads.lock().unwrap().is_empty());
        assert!(network.resources.lock().unwrap().is_empty());
        let one = network
            .blobs
            .reserve_producer(network.scope.clone())
            .unwrap();
        let two = network
            .blobs
            .reserve_producer(network.scope.clone())
            .unwrap();
        drop((one, two));

        network.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn unobserved_download_is_accepted_but_not_emitted() {
        let (network, mut events, _, server) = fixture().await;
        let directory = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(directory.path()).unwrap();
        *network.download_source.lock().unwrap() = Some(DownloadSource::Local(canonical.clone()));
        *network.download_context.lock().unwrap() = Some("owned-context".into());
        network.download_ready.store(true, Ordering::Release);
        std::fs::write(canonical.join("hidden-guid"), b"hidden").unwrap();
        network.event(&CdpEvent{method:"Browser.downloadWillBegin".into(),session_id:Some("owned".into()),params:json!({"guid":"hidden-guid","frameId":"owned-frame","suggestedFilename":"hidden.txt"})}).unwrap();
        assert!(events.try_recv().is_err());
        network
            .event(&CdpEvent {
                method: "Browser.downloadProgress".into(),
                session_id: None,
                params: json!({"guid":"hidden-guid","state":"completed","receivedBytes":6}),
            })
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while network
                .downloads
                .lock()
                .unwrap()
                .contains_key("hidden-guid")
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!canonical.join("hidden-guid").exists());
        network.close().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn response_body_failures_preserve_closed_native_reasons() {
        let (network, mut events, _, server) = fixture().await;
        network.subscribe_responses().unwrap();
        network.event(&CdpEvent{method:"Network.requestWillBeSent".into(),session_id:Some("owned".into()),params:json!({"requestId":"redirect","redirectResponse":{"url":"https://example.test/old","status":302,"headers":{}}})}).unwrap();
        let (_, event, _) = next_event(&mut events).await;
        let op = network.broker.admit(1, 1, 2000).unwrap();
        assert!(matches!(
            network
                .read_resource(event["handle"].as_str().unwrap(), 0, 32, &op)
                .await,
            Err(ProtocolError::RedirectBodyUnavailable)
        ));
        for (index, raw, expected) in [
            (
                0,
                "net::ERR_CONTENT_LENGTH_MISMATCH",
                ProtocolError::ContentLengthMismatch,
            ),
            (
                1,
                "private unexpected backend text",
                ProtocolError::BrowserFailure,
            ),
        ] {
            let id = format!("response-{index}");
            network.event(&CdpEvent{method:"Network.responseReceived".into(),session_id:Some("owned".into()),params:json!({"requestId":id,"response":{"url":"https://example.test/body","status":200,"headers":{}}})}).unwrap();
            let (_, event, _) = next_event(&mut events).await;
            network
                .event(&CdpEvent {
                    method: "Network.loadingFailed".into(),
                    session_id: Some("owned".into()),
                    params: json!({"requestId":id,"errorText":raw}),
                })
                .unwrap();
            let result = network
                .read_resource(event["handle"].as_str().unwrap(), 0, 32, &op)
                .await;
            assert!(matches!(result,Err(ref actual) if *actual==expected));
        }
        network.close().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn large_original_post_body_is_readable_alias_without_rewriting_request() {
        let (network, mut events, mut commands, server) = fixture().await;
        network.replace_routes(1, vec!["first".into()]).unwrap();
        let original = "p".repeat(1536 * 1024);
        network.event(&CdpEvent {method:"Fetch.requestPaused".into(),session_id:Some("owned".into()),params:json!({"requestId":"original-large","request":{"url":"https://example.test/original","method":"POST","headers":{"Content-Length":original.len().to_string()},"postData":original}})}).unwrap();
        let (_, event, notice) = next_event(&mut events).await;
        assert!(event["request"].get("postData").is_none());
        let alias = event["request"]["postDataHandle"].as_str().unwrap();
        let chunk = network.read_body(alias, 0, 256 * 1024).unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(chunk.base64)
                .unwrap(),
            vec![b'p'; 256 * 1024]
        );
        assert!(!chunk.eof);
        network
            .broker
            .resolve(
                1,
                &notice.unwrap().token,
                Decision::Continue {
                    overrides: RequestOverrides::default(),
                },
            )
            .unwrap();
        let terminal = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let command = commands.recv().await.unwrap();
                if command["method"] == "Fetch.continueRequest" {
                    break command;
                }
            }
        })
        .await
        .unwrap();
        assert!(terminal["params"].get("postData").is_none());
        network.close().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn large_fallback_body_is_read_only_alias_and_terminal_length_is_corrected() {
        let (network, mut events, mut commands, server) = fixture().await;
        network
            .replace_routes(1, vec!["first".into(), "second".into()])
            .unwrap();
        network.event(&CdpEvent{method:"Fetch.requestPaused".into(),session_id:Some("owned".into()),params:json!({"requestId":"request","networkId":"network","request":{"url":"https://example.test/path","method":"POST","headers":{"Content-Length":"8"},"postData":"original"}})}).unwrap();
        let (_, first, notice) = next_event(&mut events).await;
        assert_eq!(first["identityScope"], "synthetic-owned-context");
        let token = notice.unwrap().token;
        let bytes = vec![b'x'; 1536 * 1024];
        let blob = network
            .blobs
            .insert_sealed(network.scope.clone(), &bytes)
            .unwrap();
        network
            .blobs
            .reserve(&network.scope, &blob.handle, &token)
            .unwrap();
        network
            .broker
            .resolve(
                1,
                &token,
                Decision::Fallback {
                    overrides: RequestOverrides {
                        body_handle: Some(blob.handle),
                        ..Default::default()
                    },
                },
            )
            .unwrap();
        let (_, next, notice) = next_event(&mut events).await;
        assert_eq!(next["fallbackOf"], token);
        assert!(next["request"].get("postDataBase64").is_none());
        let alias = next["request"]["postDataHandle"].as_str().unwrap();
        assert_eq!(network.read_body(alias, 0, 32).unwrap().next_offset, 32);
        assert_eq!(
            network.release_body(alias),
            Err(ProtocolError::PolicyDenied)
        );
        network
            .broker
            .resolve(
                1,
                &notice.unwrap().token,
                Decision::Continue {
                    overrides: RequestOverrides::default(),
                },
            )
            .unwrap();
        let command = tokio::time::timeout(std::time::Duration::from_secs(2), commands.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(command["method"], "Fetch.continueRequest");
        assert_eq!(command["params"]["headers"], json!([]));
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(command["params"]["postData"].as_str().unwrap())
                .unwrap(),
            bytes
        );
        network.close().await.unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn response_headers_precede_loading_and_unknown_sessions_are_ignored() {
        let (network, mut events, mut commands, server) = fixture().await;
        network.subscribe_responses().unwrap();
        let mut event = CdpEvent {
            method: "Network.responseReceived".into(),
            session_id: Some("foreign".into()),
            params: json!({"requestId":"r","response":{"url":"https://example.test/","status":200,"headers":{}}}),
        };
        network.event(&event).unwrap();
        assert!(events.try_recv().is_err());
        event.session_id = Some("owned".into());
        network.event(&event).unwrap();
        let (kind, payload, _) = next_event(&mut events).await;
        assert_eq!(kind, "network.response");
        assert!(commands.try_recv().is_err());
        let handle = payload["handle"].as_str().unwrap().to_owned();
        network
            .event(&CdpEvent {
                method: "Network.loadingFinished".into(),
                session_id: Some("owned".into()),
                params: json!({"requestId":"r"}),
            })
            .unwrap();
        let operation = network.broker.admit(1, 1, 2000).unwrap();
        let chunk = network
            .read_resource(&handle, 0, 32, &operation)
            .await
            .unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(chunk.base64)
                .unwrap(),
            b"synthetic-response"
        );
        network.release_body(&handle).unwrap();
        network.close().await.unwrap();
        server.abort();
    }
}

/// Scope policy, not a second engine backend. Ordinary applications retain
/// service-worker behavior; protected injected headers explicitly opt into bypass.
#[derive(Clone, Copy, Default)]
pub struct NetworkPolicy {
    pub bypass_service_worker: bool,
}
