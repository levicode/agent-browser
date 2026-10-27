//! Negotiated browser resource ownership. Browser handles remain native; an
//! execution lease never holds the manager mutex while page work awaits events.
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

use super::cdp::client::CdpClient;
use super::client_protocol::ProtocolError;
use super::client_settlement_trace::{
    self as cleanup_trace, CleanupComponent as CleanupPart, TerminalCleanupStage,
};

#[derive(Default)]
struct GateState {
    epoch: u64,
    readers: usize,
    transitioning: bool,
    closed: bool,
    initialization_nonce: u64,
    initialization_issued: bool,
    initialization_live: bool,
    initialization_published: Option<u64>,
}

/// Separates resource lifetime from the browser action mutex. Existing callback
/// children can finish while a lifecycle transition waits for their parent.
#[derive(Default)]
pub struct ExecutionGate {
    state: Mutex<GateState>,
    changed: Notify,
}

pub struct ScopePermit {
    gate: Arc<ExecutionGate>,
    epoch: u64,
}

/// Private, lifecycle-issued permission to initialize one exact registry while
/// ordinary admission remains closed. This is never constructed from wire data.
struct InitializationBinding {
    gate: Arc<ExecutionGate>,
    targets: Arc<super::client_targets::ClientTargets>,
    epoch: u64,
    nonce: u64,
}
/// Cloneable enrollment access, without authority to revoke or publish a scope.
#[derive(Clone)]
pub struct InitializationAccess {
    binding: Arc<InitializationBinding>,
}
/// The retained lifecycle supervisor alone owns this abandonment guard.
pub struct LifecycleInitialization {
    access: InitializationAccess,
}
impl InitializationAccess {
    /// Only the registry captured at issuance may receive initialization leases.
    pub fn enter(
        &self,
        targets: &Arc<super::client_targets::ClientTargets>,
    ) -> Result<ScopePermit, ProtocolError> {
        if !Arc::ptr_eq(&self.binding.targets, targets) {
            return Err(ProtocolError::StaleScope);
        }
        let mut state = self
            .binding
            .gate
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let initializing =
            state.transitioning && state.initialization_live && state.epoch == self.binding.epoch;
        let published = !state.transitioning
            && self.binding.epoch.checked_add(1) == Some(state.epoch)
            && state.initialization_published == Some(self.binding.nonce);
        if state.closed
            || state.initialization_nonce != self.binding.nonce
            || !(initializing || published)
        {
            return Err(ProtocolError::StaleScope);
        }
        state.readers = state
            .readers
            .checked_add(1)
            .ok_or(ProtocolError::CapacityExceeded)?;
        Ok(ScopePermit {
            gate: self.binding.gate.clone(),
            epoch: state.epoch,
        })
    }
}
impl LifecycleInitialization {
    pub fn access(&self) -> InitializationAccess {
        self.access.clone()
    }
    pub fn enter(
        &self,
        targets: &Arc<super::client_targets::ClientTargets>,
    ) -> Result<ScopePermit, ProtocolError> {
        self.access.enter(targets)
    }
    /// Atomically publish the exact initialized tenure once all children have
    /// settled. The lifecycle owner holds its resource publication lock while
    /// calling this method. A racing child leaves publication unchanged.
    pub fn publish(&self) -> Result<u64, ProtocolError> {
        let mut state = self
            .access
            .binding
            .gate
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.closed
            || !state.transitioning
            || !state.initialization_live
            || state.epoch != self.access.binding.epoch
            || state.initialization_nonce != self.access.binding.nonce
            || state.readers != 0
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let epoch = state
            .epoch
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        state.epoch = epoch;
        state.initialization_published = Some(self.access.binding.nonce);
        state.initialization_live = false;
        state.initialization_issued = false;
        state.transitioning = false;
        drop(state);
        self.access.binding.gate.changed.notify_waiters();
        Ok(epoch)
    }

    /// Stop new children atomically with admission. Already issued leases must
    /// settle and be drained before the lifecycle owner commits the transition.
    pub fn revoke(&self) -> Result<(), ProtocolError> {
        let mut state = self
            .access
            .binding
            .gate
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.closed
            || !state.transitioning
            || state.epoch != self.access.binding.epoch
            || state.initialization_nonce != self.access.binding.nonce
        {
            return Err(ProtocolError::StaleScope);
        }
        state.initialization_live = false;
        drop(state);
        self.access.binding.gate.changed.notify_waiters();
        Ok(())
    }
}
impl Drop for LifecycleInitialization {
    fn drop(&mut self) {
        if let Ok(mut state) = self.access.binding.gate.state.lock() {
            // An abandoned old authority must never close a newer transition.
            if state.epoch == self.access.binding.epoch
                && state.initialization_nonce == self.access.binding.nonce
                && state.initialization_live
            {
                state.initialization_live = false;
                state.closed = true;
            }
        }
        self.access.binding.gate.changed.notify_waiters();
    }
}

impl ExecutionGate {
    pub fn enter(self: &Arc<Self>, callback_child: bool) -> Result<ScopePermit, ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.closed || (state.transitioning && !callback_child) {
            return Err(ProtocolError::ScopeUnavailable);
        }
        // A callback child is admitted only after broker validation of a live
        // parent token. This flag is internal, never a command argument.
        state.readers = state
            .readers
            .checked_add(1)
            .ok_or(ProtocolError::CapacityExceeded)?;
        Ok(ScopePermit {
            gate: self.clone(),
            epoch: state.epoch,
        })
    }

    pub fn begin_transition(&self) -> Result<(), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.closed || state.transitioning {
            return Err(ProtocolError::ScopeUnavailable);
        }
        state.transitioning = true;
        Ok(())
    }

    /// Issue once after old work drains and the retained lifecycle owner has
    /// created the new scope registry. No scope is published by this method.
    pub fn initialization(
        self: &Arc<Self>,
        targets: Arc<super::client_targets::ClientTargets>,
    ) -> Result<LifecycleInitialization, ProtocolError> {
        if targets.context_id.is_empty() || targets.identity_scope.is_empty() {
            return Err(ProtocolError::InvalidArguments);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.closed || !state.transitioning || state.readers != 0 || state.initialization_issued
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let nonce = state
            .initialization_nonce
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        state.initialization_nonce = nonce;
        state.initialization_issued = true;
        state.initialization_live = true;
        Ok(LifecycleInitialization {
            access: InitializationAccess {
                binding: Arc::new(InitializationBinding {
                    gate: self.clone(),
                    targets,
                    epoch: state.epoch,
                    nonce,
                }),
            },
        })
    }

    pub async fn drained(&self) -> Result<(), ProtocolError> {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .state
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                .readers
                == 0
            {
                return Ok(());
            }
            notified.await;
        }
    }

    /// Publish only after replacement initialization AND old resource cleanup.
    pub fn commit_transition(&self) -> Result<u64, ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.closed || !state.transitioning || state.readers != 0 || state.initialization_live {
            return Err(ProtocolError::ScopeUnavailable);
        }
        state.epoch = state
            .epoch
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        state.transitioning = false;
        state.initialization_issued = false;
        state.initialization_published = None;
        Ok(state.epoch)
    }

    pub fn seal(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
        }
        self.changed.notify_waiters();
    }
}

impl ScopePermit {
    pub fn check(&self) -> Result<(), ProtocolError> {
        let state = self
            .gate
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.closed || state.epoch != self.epoch {
            Err(ProtocolError::StaleScope)
        } else {
            Ok(())
        }
    }
}
impl Drop for ScopePermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.gate.state.lock() {
            state.readers = state.readers.saturating_sub(1);
        }
        self.gate.changed.notify_waiters();
    }
}

/// Captured under a short resource lock. Native query/actions use these private
/// handles; no CDP session or target identifier is returned to e2e.
pub struct BrowserExecutionLease {
    pub client: Arc<CdpClient>,
    pub page_session_id: String,
    pub target_id: String,
    pub identity_scope: String,
    pub permit: ScopePermit,
    pub targets: Arc<super::client_targets::ClientTargets>,
}

/// Resource owner retained separately from active execution leases. For remote
/// connections only this context is disposable; the leased browser is not ours.
pub struct OwnedBrowser {
    pub manager: super::browser::BrowserManager,
    pub context_id: String,
    owns_context: bool,
    pub identity_scope: String,
    pub targets: Arc<super::client_targets::ClientTargets>,
    pub page_state: Arc<super::client_page::ClientPageState>,
    pub ui: Arc<super::client_ui::UiGate>,
    runtime: Option<OwnedRuntime>,
    replacement_actions: Option<Arc<super::client_actions::ClientActions>>,
    replacement_routes: Option<super::client_network::RouteTransfer>,
    disconnected_routes: Option<super::client_network::DisconnectedRoutes>,
    reconnect_proof: Option<super::client_reconnect::VerifiedReconnectProof>,
    persistent_probe: super::client_persistent::OwnedProbeJournal,
    borrowed_targets: Option<Vec<String>>,
    browser_tenure: String,
}

/// The lifecycle owner retains this journal before the first enrollment RPC.
/// Teardown contains exact owned resources before releasing attachment barriers.
struct RuntimeInitialization<'a> {
    operation: &'a super::client_session::OperationLease,
    retirement: &'a Arc<Mutex<RetirementJournal>>,
    options: &'a ScopeCreationOptions,
    replacement: Option<ReplacementSeed>,
}

/// One explicit new-scope request, not old application or final-close authority.
/// The old ledger remains retired; the writer barrier installs a distinct owner.
pub(super) struct ReplacementLease {
    debt: Arc<super::client_debt::OwnerDebtLedger>,
    identity_scope: String,
    previous_client: Arc<CdpClient>,
    replacement_client: Arc<CdpClient>,
}
impl ReplacementLease {
    fn begin(
        manager: &mut super::browser::BrowserManager,
        operation: &super::client_session::OperationLease,
    ) -> Result<Self, ProtocolError> {
        check_lifecycle_budget(operation)?;
        if operation.is_callback {
            return Err(ProtocolError::InvalidArguments);
        }
        if manager
            .client
            .debt_ledger()
            .is_some_and(|old| !old.replacement_ready())
        {
            return Err(ProtocolError::CleanupFailed);
        }
        let previous_client = manager.client.clone();
        let identity_scope = uuid::Uuid::new_v4().to_string();
        let debt = super::client_debt::OwnerDebtLedger::unpublished(
            operation,
            identity_scope.clone(),
            true,
        )?;
        manager.bind_native_owner(debt.clone())?;
        Ok(Self {
            debt,
            identity_scope,
            previous_client,
            replacement_client: manager.client.clone(),
        })
    }

    /// Only this manager-issued facade pair may move a drained route registry.
    /// The previous facade remains permanently bound to its retired ledger.
    pub(super) fn check_route_replacement(
        &self,
        previous: &Arc<CdpClient>,
        replacement: &Arc<CdpClient>,
        identity_scope: &str,
        operation: &super::client_session::OperationLease,
    ) -> Result<(), ProtocolError> {
        check_lifecycle_budget(operation)?;
        if !Arc::ptr_eq(previous, &self.previous_client)
            || !Arc::ptr_eq(replacement, &self.replacement_client)
            || identity_scope != self.identity_scope
            || !self
                .debt
                .matches_owner(operation.generation, identity_scope)
            || previous
                .debt_ledger()
                .is_none_or(|old| !old.replacement_ready())
        {
            return Err(ProtocolError::StaleScope);
        }
        self.debt.check_unpublished_operation(operation)?;
        replacement.check_cleanup_owner(&Some(self.debt.clone()))
    }
}

/// Minted only after strict ledger/enrollment checks and local resource release;
/// consumed only after physical close and watcher joins. Never remote ACK proof.
pub(crate) struct TerminalReadOnlyRetirement {
    ledger: Arc<super::client_debt::OwnerDebtLedger>,
    operations: Vec<super::client_debt::OperationKey>,
    targets: Arc<super::client_targets::ClientTargets>,
    bindings: Vec<(String, String, bool)>,
}
impl TerminalReadOnlyRetirement {
    /// Synthetic guard-test input only; never evidence that production minting,
    /// resource release, physical close or watcher joining actually happened.
    #[cfg(test)]
    pub(crate) fn for_commit_guard_test(
        ledger: Arc<super::client_debt::OwnerDebtLedger>,
        operations: Vec<super::client_debt::OperationKey>,
        targets: Arc<super::client_targets::ClientTargets>,
        bindings: Vec<(String, String, bool)>,
    ) -> Self {
        Self {
            ledger,
            operations,
            targets,
            bindings,
        }
    }
    pub(crate) fn commit_with_final_resources<T>(
        &self,
        commit: impl FnOnce() -> Result<T, ProtocolError>,
    ) -> Result<T, ProtocolError> {
        self.targets.require_eval_owner(&self.ledger)?;
        self.targets.with_terminal_read_only(&self.bindings, commit)
    }
    pub(crate) fn operations(&self) -> &[super::client_debt::OperationKey] {
        &self.operations
    }
    pub(crate) fn ledger(&self) -> &Arc<super::client_debt::OwnerDebtLedger> {
        &self.ledger
    }
}

struct ReplacementSeed {
    page_config: super::client_page::PageConfigSnapshot,
    policy: super::client_observation_dispatch::ReadPolicy,
    downloads: DownloadConfiguration,
    actions: Arc<super::client_actions::ClientActions>,
    owner: Option<ReplacementLease>,
}

struct OwnedRuntime {
    // Original attempts allow focused input; reconnect requires fresh evidence.
    observation_after: Option<u64>,
    enrollment: Arc<super::client_enrollment::ClientEnrollment>,
    network: Arc<super::client_network::ClientNetwork>,
    blobs: Arc<super::client_blobs::BlobStore>,
    scope: super::client_blobs::BlobScope,
    configuration: Arc<Mutex<RuntimeConfiguration>>,
    page_active: Arc<std::sync::atomic::AtomicBool>,
    activation: Arc<PageActivation>,
    block_service_workers: bool,
    creation_options: ScopeCreationOptions,
    actions: Arc<super::client_actions::ClientActions>,
    input_gate: Arc<tokio::sync::Mutex<()>>,
    download_cleanup: tokio::sync::Mutex<Option<tokio::task::JoinHandle<std::io::Result<()>>>>,
}
struct PageActivation {
    borrowed: bool,
    active: Arc<std::sync::atomic::AtomicBool>,
    serial: tokio::sync::Mutex<()>,
    page_state: Arc<super::client_page::ClientPageState>,
    network: Arc<super::client_network::ClientNetwork>,
    enrollment: Arc<super::client_enrollment::ClientEnrollment>,
}
impl PageActivation {
    // Original persistent ensurePage performs its initial blank navigation only
    // after callback registration, at first page activation, never before open ACK.
    async fn ensure(
        &self,
        page: &BrowserExecutionLease,
        operation: &super::client_session::OperationLease,
        dispatched: &mut bool,
    ) -> Result<(), ProtocolError> {
        #[cfg(test)]
        page.client
            .activation_diagnostic("ensure-enter", None, "entered", None, None);
        if !self.borrowed || self.active.load(std::sync::atomic::Ordering::SeqCst) {
            #[cfg(test)]
            page.client
                .activation_diagnostic("ensure-bypass", None, "bypass", None, None);
            return Ok(());
        }
        #[cfg(test)]
        page.client
            .activation_diagnostic("ensure-serial", None, "entered", None, None);
        let mut cancellation = operation.cancellation.clone();
        check_lifecycle_budget(operation)?;
        let _serial = tokio::select! {
            biased;
            _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
            result = tokio::time::timeout_at(operation.deadline.into(), self.serial.lock()) => result.map_err(|_| ProtocolError::DeadlineExceeded)?,
        };
        page.permit.check()?;
        check_lifecycle_budget(operation)?;
        if self.active.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        let _navigation = self.network.begin_app_navigation(page, operation)?;
        *dispatched = true;
        #[cfg(test)]
        page.client
            .activation_diagnostic("ensure-navigation", None, "entered", None, None);
        let navigation = self
            .page_state
            .execute(
                page,
                std::slice::from_ref(&page.page_session_id),
                operation,
                "page.navigate",
                &serde_json::json!({"url":"about:blank","waitUntil":"domcontentloaded"}),
            )
            .await;
        #[cfg(test)]
        page.client.activation_diagnostic(
            "ensure-navigation-result",
            None,
            if navigation.is_ok() { "ok" } else { "failed" },
            navigation.as_ref().err(),
            None,
        );
        navigation?;
        #[cfg(test)]
        page.client
            .activation_diagnostic("ensure-flush", None, "entered", None, None);
        let flushed = self.enrollment.flush_app_events(page, operation).await;
        #[cfg(test)]
        page.client.activation_diagnostic(
            "ensure-flush-result",
            None,
            if flushed.is_ok() { "ok" } else { "failed" },
            flushed.as_ref().err(),
            None,
        );
        flushed?;
        page.permit.check()?;
        check_lifecycle_budget(operation)?;
        self.active.store(true, std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        page.client
            .activation_diagnostic("ensure-complete", None, "ok", None, None);
        Ok(())
    }
}
#[derive(Default)]
struct RuntimeConfiguration {
    policy: Option<super::client_observation_dispatch::ReadPolicy>,
    download_directory: Option<tempfile::TempDir>,
    downloads: Option<DownloadConfiguration>,
    configuring: bool,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigureRequest {
    test_id_attribute: String,
    secure_field_selector: String,
    request_policy: RequestPolicy,
    downloads: DownloadConfiguration,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestPolicy {
    site: Option<String>,
    headers: Option<std::collections::HashMap<String, String>>,
    basic_auth: Option<BasicCredentials>,
}
impl RequestPolicy {
    fn observation_frame_policy(&self) -> super::client_observation::ObservationFramePolicy {
        super::client_observation::ObservationFramePolicy::configured(self.site.clone())
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BasicCredentials {
    username: String,
    password: String,
}
#[derive(Clone, serde::Deserialize)]
#[serde(tag = "source", rename_all = "lowercase", deny_unknown_fields)]
enum DownloadConfiguration {
    Local,
    Provider {
        #[serde(rename = "remoteDirectory")]
        remote_directory: String,
    },
}
impl ConfigureRequest {
    fn validate(&self, block_service_workers: bool) -> Result<(), ProtocolError> {
        if self.test_id_attribute.is_empty()
            || self.test_id_attribute.len() > 16 * 1024
            || self.test_id_attribute.contains('\0')
            || self.secure_field_selector != "input[type=\"password\" i]"
            || self.request_policy.headers.is_some() != block_service_workers
            || self
                .request_policy
                .site
                .as_ref()
                // EngineAppInfo.site is siteOf(hostname), not an absolute URL.
                // Request matching remains callback-side; automatic semantic
                // reads freeze this same site into their native-only policy.
                .is_some_and(|site| site.len() > 16 * 1024 || site.chars().any(char::is_control))
            || self.request_policy.headers.as_ref().is_some_and(|headers| {
                headers.iter().any(|(key, value)| {
                    key.is_empty()
                        || key.contains(['\r', '\n', '\0'])
                        || value.contains(['\r', '\n', '\0'])
                })
            })
            || self
                .request_policy
                .basic_auth
                .as_ref()
                .is_some_and(|auth| auth.username.contains('\0') || auth.password.contains('\0'))
        {
            return Err(ProtocolError::InvalidArguments);
        }
        if let DownloadConfiguration::Provider { remote_directory } = &self.downloads {
            if remote_directory.is_empty() || remote_directory.contains('\0') {
                return Err(ProtocolError::InvalidArguments);
            }
        }
        Ok(())
    }
}
impl OwnedRuntime {
    async fn remove_download_directory(&self) -> Result<(), ProtocolError> {
        let mut cleanup = self.download_cleanup.lock().await;
        if cleanup.is_none() {
            let path = self
                .configuration
                .lock()
                .map_err(|_| ProtocolError::CleanupFailed)?
                .download_directory
                .as_ref()
                .map(|directory| directory.path().to_owned());
            let Some(path) = path else {
                return Ok(());
            };
            *cleanup = Some(tokio::task::spawn_blocking(
                move || match std::fs::remove_dir_all(path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    result => result,
                },
            ));
        }
        // The join stays journaled if the lifecycle waiter is canceled. Keep
        // TempDir itself on error; Drop is not our cleanup success evidence.
        let result = cleanup.as_mut().expect("journaled cleanup").await;
        cleanup.take();
        match result {
            Ok(Ok(())) => {
                self.configuration
                    .lock()
                    .map_err(|_| ProtocolError::CleanupFailed)?
                    .download_directory
                    .take();
                Ok(())
            }
            _ => Err(ProtocolError::CleanupFailed),
        }
    }
    async fn release_terminal_connection(
        &self,
        client: &Arc<super::cdp::client::CdpClient>,
        preserve_recording: bool,
    ) -> Result<(), ProtocolError> {
        let proof = match self
            .enrollment
            .terminal_connection_proof()
            .and_then(|proof| {
                proof.check_client(client)?;
                Ok(proof)
            }) {
            Ok(proof) => proof,
            Err(_) => {
                // A missing recovery root cannot revive a page or preserve
                // routes. Final close has a separate, stricter debt-free proof.
                if !preserve_recording {
                    return self.release_final_local_connection(client).await;
                }
                return Err(ProtocolError::CleanupFailed);
            }
        };
        let diagnostics = client.cleanup_observer();
        self.enrollment.seal();
        let drained = self.enrollment.drain().await;
        cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::EnrollmentFallback, &drained);
        let network = self.network.close_for_remote_disconnect(&proof).await;
        cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::OwnerFallback, &network);
        let terminal_recording = self.actions.settle_terminal_recording(client, &proof).await;
        cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::Recording, &terminal_recording);
        let actions = if preserve_recording {
            let recording = self
                .actions
                .recording_page_closing(&self.scope.identity_scope, &self.blobs)
                .await;
            cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::Recording, &recording);
            let uploads = self.actions.cleanup_scope_uploads().await;
            cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::Upload, &uploads);
            if recording.is_err() || uploads.is_err() {
                Err(ProtocolError::CleanupFailed)
            } else {
                Ok(())
            }
        } else {
            self.actions.cleanup_with_diagnostics(&diagnostics).await
        };
        let retired = if preserve_recording {
            Ok(())
        } else {
            self.network.close().await
        };
        let directory = if drained.is_ok() && network.is_ok() {
            let directory = self.remove_download_directory().await;
            cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::Download, &directory);
            directory
        } else {
            Err(ProtocolError::CleanupFailed)
        };
        let blobs = self.blobs.revoke_scope(&self.scope);
        cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::Blob, &blobs);
        if drained.is_err()
            || network.is_err()
            || terminal_recording.is_err()
            || actions.is_err()
            || retired.is_err()
            || directory.is_err()
            || blobs.is_err()
        {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
    async fn release_final_local_connection(
        &self,
        client: &Arc<super::cdp::client::CdpClient>,
    ) -> Result<(), ProtocolError> {
        let diagnostics = client.cleanup_observer();
        self.enrollment.seal();
        let drained = self.enrollment.drain().await;
        cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::EnrollmentFallback, &drained);
        let proof = self
            .enrollment
            .final_local_connection_proof()
            .and_then(|proof| {
                proof.check_client(client)?;
                Ok(proof)
            });
        // Every local obligation is still joined, even when proof is refused.
        // No recording detach/stop failure is reclassified using transport EOF.
        let network = self.network.close().await;
        cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::OwnerFallback, &network);
        let actions = self.actions.cleanup_with_diagnostics(&diagnostics).await;
        let directory = if drained.is_ok() && network.is_ok() {
            let directory = self.remove_download_directory().await;
            cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::Download, &directory);
            directory
        } else {
            Err(ProtocolError::CleanupFailed)
        };
        let blobs = self.blobs.revoke_scope(&self.scope);
        cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::Blob, &blobs);
        let exact = proof.and_then(|proof| {
            proof.check_client(client)?;
            proof.check_network(&self.network)
        });
        if drained.is_err()
            || exact.is_err()
            || network.is_err()
            || actions.is_err()
            || directory.is_err()
            || blobs.is_err()
        {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
    async fn contain_and_release(&self) -> Result<(), ProtocolError> {
        self.contain_and_release_mode(false).await
    }
    async fn contain_and_release_mode(
        &self,
        preserve_recording: bool,
    ) -> Result<(), ProtocolError> {
        let diagnostics = self.network.client.cleanup_observer();
        self.enrollment.seal();
        let drained = self.enrollment.drain().await;
        cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::EnrollmentFallback, &drained);
        let drain_failed = drained.is_err();
        let action_cleanup_failed = if preserve_recording {
            let recording = self
                .actions
                .recording_page_closing(&self.scope.identity_scope, &self.blobs)
                .await;
            cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::Recording, &recording);
            let uploads = self.actions.cleanup_scope_uploads().await;
            cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::Upload, &uploads);
            recording.is_err() || uploads.is_err()
        } else {
            self.actions
                .cleanup_with_diagnostics(&diagnostics)
                .await
                .is_err()
        };
        let contained = self.enrollment.contain_owned_resources().await;
        cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::Containment, &contained);
        let release = match contained {
            Ok(proof) => self.enrollment.release_after_containment(proof).await,
            Err(error) => Err(error),
        };
        cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::Release, &release);
        let directory_failed = if !drain_failed && release.is_ok() {
            let directory = self.remove_download_directory().await;
            cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::Download, &directory);
            directory.is_err()
        } else {
            false
        };
        let revoked = self.blobs.revoke_scope(&self.scope);
        cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::Blob, &revoked);
        if drain_failed
            || action_cleanup_failed
            || release.is_err()
            || directory_failed
            || revoked.is_err()
        {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
}

impl OwnedBrowser {
    /// The retained caller owns this resource before the first acquisition can
    /// yield. Late ACKs bind identities in its exact ledger, even without a waiter.
    async fn isolated_for_scope(
        manager: super::browser::BrowserManager,
        operation: &super::client_session::OperationLease,
        failed: &mut Option<Self>,
    ) -> Result<Self, ProtocolError> {
        let mut resource = Self {
            manager,
            context_id: String::new(),
            identity_scope: String::new(),
            owns_context: true,
            targets: super::client_targets::ClientTargets::new_managed(
                String::new(),
                String::new(),
            ),
            page_state: Arc::new(super::client_page::ClientPageState::new(
                String::new(),
                String::new(),
            )),
            ui: Arc::new(super::client_ui::UiGate::default()),
            runtime: None,
            replacement_actions: None,
            replacement_routes: None,
            disconnected_routes: None,
            reconnect_proof: None,
            persistent_probe: Default::default(),
            borrowed_targets: None,
            browser_tenure: uuid::Uuid::new_v4().to_string(),
        };
        if let Err(error) = resource.bootstrap_context(operation).await {
            *failed = Some(resource);
            return Err(error);
        }
        Ok(resource)
    }

    async fn bootstrap_context(
        &mut self,
        operation: &super::client_session::OperationLease,
    ) -> Result<ReplacementLease, ProtocolError> {
        self.targets.protected_read_residual.replacement_safe()?;
        let lease = ReplacementLease::begin(&mut self.manager, operation)?;
        self.identity_scope = lease.identity_scope.clone();
        self.context_id.clear();
        let response = self
            .manager
            .client
            .send_command(
                "Target.createBrowserContext",
                Some(serde_json::json!({"disposeOnDetach":true})),
                None,
            )
            .await;
        // Reader binding precedes waiter delivery. Never use an old context ID
        // if the new acquisition timed out or returned an invalid identity.
        self.context_id = lease.debt.bound_context().unwrap_or_default();
        response.map_err(|_| ProtocolError::BrowserFailure)?;
        if self.context_id.is_empty() {
            return Err(ProtocolError::InvalidFrame);
        }
        check_lifecycle_budget(operation)?;
        self.targets.protected_read_residual.replacement_safe()?;
        self.targets = super::client_targets::ClientTargets::new_managed(
            self.context_id.clone(),
            self.identity_scope.clone(),
        );
        self.page_state = Arc::new(super::client_page::ClientPageState::new(
            self.identity_scope.clone(),
            self.context_id.clone(),
        ));
        self.ui = Arc::new(super::client_ui::UiGate::default());
        self.manager
            .owned_blank_page(Some(&self.context_id))
            .await
            .map_err(|_| ProtocolError::BrowserFailure)?;
        check_lifecycle_budget(operation)?;
        Ok(lease)
    }
    pub async fn connect(
        endpoint: &str,
        headers: Option<Vec<(String, String)>>,
    ) -> Result<Self, ProtocolError> {
        let manager = super::browser::BrowserManager::connect_owned_browser(endpoint, headers)
            .await
            .map_err(|_| ProtocolError::BrowserFailure)?;
        Self::isolated(manager).await
    }

    /// Initial persistent attachment selects only the verified default-context page.
    /// Unrelated contexts remain untouched; reconnect has a separate restriction.
    async fn connect_persistent(
        endpoint: &str,
        failed: &mut Option<OwnedBrowser>,
    ) -> Result<Self, ProtocolError> {
        let manager = super::browser::BrowserManager::connect_owned_browser(endpoint, None)
            .await
            .map_err(|_| ProtocolError::BrowserFailure)?;
        let identity_scope = uuid::Uuid::new_v4().to_string();
        let mut resource = Self {
            targets: super::client_targets::ClientTargets::new_managed(
                String::new(),
                identity_scope.clone(),
            ),
            page_state: Arc::new(super::client_page::ClientPageState::new(
                identity_scope.clone(),
                String::new(),
            )),
            ui: Arc::new(super::client_ui::UiGate::default()),
            manager,
            context_id: String::new(),
            identity_scope,
            owns_context: false,
            runtime: None,
            replacement_actions: None,
            replacement_routes: None,
            disconnected_routes: None,
            reconnect_proof: None,
            persistent_probe: Default::default(),
            borrowed_targets: None,
            browser_tenure: uuid::Uuid::new_v4().to_string(),
        };
        match super::client_persistent::prepare_persistent(&mut resource.manager).await {
            Ok(prepared) => {
                resource.context_id = prepared.context_id;
                resource.borrowed_targets = Some(vec![prepared.target_id]);
                resource.persistent_probe = prepared.probe;
                resource
                    .targets
                    .protected_read_residual
                    .replacement_safe()?;
                resource.targets = super::client_targets::ClientTargets::new_managed(
                    resource.context_id.clone(),
                    resource.identity_scope.clone(),
                );
                resource.page_state = Arc::new(super::client_page::ClientPageState::new(
                    resource.identity_scope.clone(),
                    resource.context_id.clone(),
                ));
                Ok(resource)
            }
            Err(failure) => {
                resource.persistent_probe = failure.probe;
                *failed = Some(resource);
                Err(failure.error)
            }
        }
    }

    pub async fn launch(
        options: super::cdp::chrome::LaunchOptions,
        engine: Option<&str>,
    ) -> Result<Self, ProtocolError> {
        let manager = super::browser::BrowserManager::launch_owned(options, engine)
            .await
            .map_err(|_| ProtocolError::BrowserFailure)?;
        Self::isolated(manager).await
    }

    async fn isolated(mut manager: super::browser::BrowserManager) -> Result<Self, ProtocolError> {
        let created = manager
            .client
            .send_command(
                "Target.createBrowserContext",
                Some(serde_json::json!({"disposeOnDetach": true})),
                None,
            )
            .await;
        let context_id = match created {
            Ok(value) => value
                .get("browserContextId")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or(ProtocolError::BrowserFailure),
            Err(_) => Err(ProtocolError::BrowserFailure),
        };
        let context_id = match context_id {
            Ok(id) => id,
            Err(error) => {
                // No context identity can be claimed. Closing the connection is
                // containment, not a successful scope creation or cleanup proof.
                let _ = manager.close().await;
                return Err(error);
            }
        };
        if manager.owned_blank_page(Some(&context_id)).await.is_err() {
            let cleaned = manager
                .client
                .send_command(
                    "Target.disposeBrowserContext",
                    Some(serde_json::json!({"browserContextId": context_id})),
                    None,
                )
                .await;
            let closed = manager.close().await;
            return Err(if cleaned.is_err() || closed.is_err() {
                ProtocolError::CleanupFailed
            } else {
                ProtocolError::BrowserFailure
            });
        }
        let identity_scope = uuid::Uuid::new_v4().to_string();
        let targets = super::client_targets::ClientTargets::new_managed(
            context_id.clone(),
            identity_scope.clone(),
        );
        let initialized = async {
            let target_id = manager
                .active_target_id()
                .map_err(|_| ProtocolError::BrowserFailure)?
                .to_owned();
            targets.attached(
                &context_id,
                target_id.clone(),
                manager
                    .active_session_id()
                    .map_err(|_| ProtocolError::BrowserFailure)?
                    .to_owned(),
                "page".into(),
            )?;
            // owned_blank_page has already acknowledged domain initialization and
            // resume on this synthetic initial page. Later targets use enrollment.
            targets.configured(&target_id)?;
            targets.resume_permit(&target_id).await?.complete()?;
            Ok::<(), ProtocolError>(())
        }
        .await;
        if let Err(error) = initialized {
            targets.seal();
            let disposed = manager
                .client
                .send_command(
                    "Target.disposeBrowserContext",
                    Some(serde_json::json!({"browserContextId":context_id})),
                    None,
                )
                .await;
            let closed = manager.close().await;
            return Err(if disposed.is_err() || closed.is_err() {
                ProtocolError::CleanupFailed
            } else {
                error
            });
        }
        let page_state = Arc::new(super::client_page::ClientPageState::new(
            identity_scope.clone(),
            context_id.clone(),
        ));
        Ok(Self {
            manager,
            context_id,
            owns_context: true,
            identity_scope,
            targets,
            page_state,
            ui: Arc::new(super::client_ui::UiGate::default()),
            runtime: None,
            replacement_actions: None,
            replacement_routes: None,
            disconnected_routes: None,
            reconnect_proof: None,
            persistent_probe: Default::default(),
            borrowed_targets: None,
            browser_tenure: uuid::Uuid::new_v4().to_string(),
        })
    }

    async fn replace_cleaned_context(
        &mut self,
        operation: &super::client_session::OperationLease,
    ) -> Result<ReplacementLease, ProtocolError> {
        // Caller has a complete old-context cleanup proof. Keep this object in
        // the lifecycle owner journal while the new context identity is unknown.
        self.targets.protected_read_residual.replacement_safe()?;
        let ids = self
            .manager
            .pages_list()
            .into_iter()
            .map(|page| page.target_id)
            .collect();
        self.manager.forget_disposed_targets(&ids);
        self.replacement_actions = self.runtime.as_ref().map(|runtime| runtime.actions.clone());
        self.runtime = None;
        self.bootstrap_context(operation).await
    }

    /// Enroll only this unpublished context. The supervisor retains both the
    /// authority and this resource journal until publication or cleanup.
    async fn initialize_runtime(
        &mut self,
        gate: Arc<ExecutionGate>,
        broker: Arc<super::client_session::ClientSession>,
        sink: super::client_transport::ClientEventSink,
        blobs: Arc<super::client_blobs::BlobStore>,
        request: RuntimeInitialization<'_>,
    ) -> Result<LifecycleInitialization, ProtocolError> {
        self.targets.protected_read_residual.replacement_safe()?;
        let RuntimeInitialization {
            operation,
            retirement,
            options,
            mut replacement,
        } = request;
        if self.runtime.is_some() || (!self.owns_context && self.borrowed_targets.is_none()) {
            return Err(ProtocolError::PolicyDenied);
        }
        let debt = match self.manager.client.debt_ledger() {
            Some(debt) if debt.matches_owner(operation.generation, &self.identity_scope) => debt,
            Some(_) => return Err(ProtocolError::StaleScope),
            None => super::client_debt::OwnerDebtLedger::unpublished(
                operation,
                self.identity_scope.clone(),
                self.owns_context,
            )?,
        };
        // Borrowed default context still has no destruction authority.
        if !self.context_id.is_empty() {
            debt.bind_context(&self.context_id)?;
        }
        if self.manager.client.debt_ledger().is_none() {
            self.manager.bind_native_owner(debt.clone())?;
        }
        debt.allow_initialization_script(super::client_page::BLOCK_SERVICE_WORKERS)?;
        for source in &options.init_scripts {
            debt.allow_initialization_script(source)?;
        }
        if let Some(seed) = &replacement {
            for source in seed.page_config.initialization_scripts() {
                debt.allow_initialization_script(source)?;
            }
        }
        let seeded = replacement.is_some();
        if let Some(seed) = &replacement {
            self.page_state = Arc::new(super::client_page::ClientPageState::from_config_snapshot(
                self.identity_scope.clone(),
                self.context_id.clone(),
                seed.page_config.clone(),
            )?);
        }
        // The primitive blank-page constructor's provisional registry has never
        // been published. Enrollment alone now proves the complete inventory.
        self.targets.protected_read_residual.replacement_safe()?;
        self.targets = super::client_targets::ClientTargets::new_managed(
            self.context_id.clone(),
            self.identity_scope.clone(),
        );
        self.targets.bind_eval_owner(&debt, operation.generation)?;
        let authority = gate.initialization(self.targets.clone())?;
        let scope = super::client_blobs::BlobScope {
            generation: operation.generation,
            identity_scope: self.identity_scope.clone(),
        };
        blobs
            .activate_scope(scope.clone())
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let sink = sink.stage_until_result(operation, &self.identity_scope)?;
        let network = Arc::new(super::client_network::ClientNetwork::new(
            self.manager.client.clone(),
            broker,
            sink,
            scope.clone(),
            blobs.clone(),
            self.ui.clone(),
            super::client_network::NetworkPolicy {
                bypass_service_worker: options.block_service_workers,
            },
        ));
        let target = self
            .manager
            .active_target_id()
            .map_err(|_| ProtocolError::StaleScope)?
            .to_owned();
        let session = self
            .manager
            .active_session_id()
            .map_err(|_| ProtocolError::StaleScope)?
            .to_owned();
        let enrollment = super::client_enrollment::ClientEnrollment::new(
            self.manager.client.clone(),
            self.targets.clone(),
            self.page_state.clone(),
            network.clone(),
            gate,
            operation.generation,
            session.clone(),
            super::client_enrollment::ScopeConfig {
                viewport: select_scope_viewport(
                    seeded,
                    options.viewport.as_ref().map(|v| (v.width, v.height)),
                    || self.page_state.requested_viewport(),
                )?,
                user_agent: options.user_agent.clone(),
                locale: options.locale.clone(),
                timezone_id: options.timezone_id.clone(),
                block_service_workers: options.block_service_workers,
            },
            match &self.borrowed_targets {
                Some(targets) => {
                    super::client_enrollment::ScopeOwnership::BorrowedTargets(targets.clone())
                }
                None => super::client_enrollment::ScopeOwnership::IsolatedContext,
            },
            Some(authority.access()),
        );
        let page_active = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let activation = Arc::new(PageActivation {
            borrowed: !self.owns_context,
            active: page_active.clone(),
            serial: tokio::sync::Mutex::new(()),
            page_state: self.page_state.clone(),
            network: network.clone(),
            enrollment: enrollment.clone(),
        });
        self.runtime = Some(OwnedRuntime {
            observation_after: None,
            enrollment: enrollment.clone(),
            network,
            blobs,
            scope,
            configuration: Arc::new(Mutex::new(RuntimeConfiguration::default())),
            page_active,
            activation,
            block_service_workers: options.block_service_workers,
            creation_options: options.clone(),
            actions: replacement
                .as_ref()
                .map(|seed| seed.actions.clone())
                .unwrap_or_else(|| Arc::new(super::client_actions::ClientActions::default())),
            input_gate: Arc::new(tokio::sync::Mutex::new(())),
            download_cleanup: tokio::sync::Mutex::new(None),
        });
        retirement
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .register(&enrollment)?;
        if let Some(seed) = replacement.as_mut() {
            let runtime = self
                .runtime
                .as_ref()
                .ok_or(ProtocolError::ScopeUnavailable)?;
            if let Some(routes) = &mut self.disconnected_routes {
                let proof = self
                    .reconnect_proof
                    .as_ref()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                routes.bind(&runtime.network, &self.targets, proof, operation)?;
                routes.adopt(&self.targets, operation)?;
                self.disconnected_routes = None;
            } else {
                let routes = self
                    .replacement_routes
                    .as_mut()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                routes.bind_replacement(
                    &runtime.network,
                    seed.owner.as_ref().ok_or(ProtocolError::ScopeUnavailable)?,
                    operation,
                )?;
                routes.adopt(operation)?;
                self.replacement_routes = None;
            }
            // Fresh local ownership, never a path into the removed old TempDir.
            let source = match &seed.downloads {
                DownloadConfiguration::Local => {
                    let directory = tempfile::Builder::new()
                        .prefix("agent-browser-download-")
                        .tempdir()
                        .map_err(|_| ProtocolError::BrowserFailure)?;
                    let path = std::fs::canonicalize(directory.path())
                        .map_err(|_| ProtocolError::BrowserFailure)?;
                    runtime
                        .configuration
                        .lock()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?
                        .download_directory = Some(directory);
                    super::client_network::DownloadSource::Local(path)
                }
                DownloadConfiguration::Provider { remote_directory } => {
                    super::client_network::DownloadSource::Provider(remote_directory.clone())
                }
            };
            runtime
                .network
                .configure_downloads(&self.context_id, source, operation)
                .await?;
            let mut configuration = runtime
                .configuration
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            configuration.policy = Some(seed.policy.clone());
            configuration.downloads = Some(seed.downloads.clone());
        }
        enrollment
            .enroll_existing(&target, &session, "page", operation)
            .await?;
        if !seeded {
            let page = self.lease(authority.enter(&self.targets)?)?;
            for source in &options.init_scripts {
                self.page_state
                    .execute(
                        &page,
                        std::slice::from_ref(&session),
                        operation,
                        "context.init-script",
                        &serde_json::json!({"source": source}),
                    )
                    .await?;
            }
            let mut media = serde_json::Map::new();
            if let Some(value) = &options.media.color_scheme {
                media.insert("colorScheme".into(), value.clone().into());
            }
            if let Some(value) = &options.media.reduced_motion {
                media.insert("reducedMotion".into(), value.clone().into());
            }
            if !media.is_empty() {
                self.page_state
                    .execute(
                        &page,
                        std::slice::from_ref(&session),
                        operation,
                        "context.media",
                        &serde_json::Value::Object(media),
                    )
                    .await?;
            }
        }
        enrollment.start(operation).await?;
        // The new runtime now owns the same attempt ledger. Before this point
        // partial initialization still retains the independent cleanup journal.
        self.replacement_actions = None;
        Ok(authority)
    }

    fn recovery_identity(&self) -> serde_json::Value {
        use sha2::{Digest, Sha256};
        let opaque = |kind: &str, target: &str| {
            let mut hash = Sha256::new();
            hash.update(b"agent-browser/recovery-identity/1\0");
            hash.update(kind.as_bytes());
            hash.update(b"\0");
            // Browser tenure is private and retained across reset/reconnect.
            // Context/page fingerprints bind actual native object identities;
            // an endpoint alias or connection-local browser agent is not proof.
            if kind == "browser" {
                hash.update(self.browser_tenure.as_bytes());
            }
            hash.update(b"\0");
            if kind != "browser" {
                hash.update(self.context_id.as_bytes());
                hash.update(b"\0");
            }
            hash.update(target.as_bytes());
            format!("{:x}", hash.finalize())
        };
        // These opaque fingerprints identify captured native objects, not
        // standalone authority. Recovery must also prove retained ownership and
        // compare the exact browser context/target before any page adoption.
        serde_json::json!({
            "browser": opaque("browser", ""),
            "context": opaque("context", ""),
            "page": opaque("page", self.manager.active_target_id().unwrap_or_default()),
        })
    }

    pub fn lease(&self, permit: ScopePermit) -> Result<BrowserExecutionLease, ProtocolError> {
        permit.check()?;
        Ok(BrowserExecutionLease {
            client: self.manager.client.clone(),
            page_session_id: self
                .manager
                .active_session_id()
                .map_err(|_| ProtocolError::StaleScope)?
                .to_owned(),
            target_id: self
                .manager
                .active_target_id()
                .map_err(|_| ProtocolError::StaleScope)?
                .to_owned(),
            identity_scope: self.identity_scope.clone(),
            permit,
            targets: self.targets.clone(),
        })
    }

    async fn cleanup_replacement_actions(&mut self) -> Result<(), ProtocolError> {
        let diagnostics = self.manager.client.cleanup_observer();
        let mut failed = false;
        if let Some(routes) = &mut self.disconnected_routes {
            if routes.retire().is_ok() {
                self.disconnected_routes = None;
            } else {
                cleanup_trace::observe_cleanup(
                    &diagnostics,
                    CleanupPart::OwnerFallback,
                    &Err::<(), _>(ProtocolError::CleanupFailed),
                );
                failed = true;
            }
        }
        if let Some(routes) = &mut self.replacement_routes {
            if routes.retire().is_ok() {
                self.replacement_routes = None;
            } else {
                cleanup_trace::observe_cleanup(
                    &diagnostics,
                    CleanupPart::OwnerFallback,
                    &Err::<(), _>(ProtocolError::CleanupFailed),
                );
                failed = true;
            }
        }
        if let Some(actions) = &self.replacement_actions {
            if actions.cleanup_with_diagnostics(&diagnostics).await.is_ok() {
                self.replacement_actions = None;
            } else {
                cleanup_trace::observe_cleanup(
                    &diagnostics,
                    CleanupPart::OwnerFallback,
                    &Err::<(), _>(ProtocolError::CleanupFailed),
                );
                failed = true;
            }
        }
        if failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }

    /// Dispose the owned context while retaining the worker browser. The caller
    /// has drained operations and callback resources before entering this path.
    async fn dispose_context(&mut self) -> Result<(), ProtocolError> {
        if !self.owns_context {
            self.targets.protected_read_residual.replacement_safe()?;
        }
        if !self.owns_context {
            // Ordinary borrowed scope end owns only our sessions and transport.
            // It never acquires context/page destruction authority.
            return self.close().await;
        }
        let retained_cleanup_failed = self.cleanup_replacement_actions().await.is_err();
        let ids = self
            .manager
            .pages_list()
            .into_iter()
            .map(|page| page.target_id)
            .collect();
        if let Some(runtime) = &self.runtime {
            self.ui.seal();
            let contained = runtime.contain_and_release().await;
            runtime
                .enrollment
                .retire_protected_read_after_destroy(&self.targets.protected_read_residual)?;
            contained?;
            self.targets.protected_read_residual.replacement_safe()?;
            self.manager.forget_disposed_targets(&ids);
            return if retained_cleanup_failed {
                Err(ProtocolError::CleanupFailed)
            } else {
                Ok(())
            };
        }
        self.ui.seal();
        self.targets.seal();
        let debt = self.manager.client.debt_ledger();
        self.manager
            .client
            .send_command(
                "Target.disposeBrowserContext",
                Some(serde_json::json!({"browserContextId": self.context_id})),
                None,
            )
            .await
            .map_err(|_| ProtocolError::CleanupFailed)?;
        if let Some(ledger) = debt {
            ledger.retire_after_context_destroy(&self.context_id)?;
            self.targets
                .protected_read_residual
                .record_exact_context_destroyed(&self.manager.client, &ledger, &self.context_id)?;
        }
        self.manager.forget_disposed_targets(&ids);
        if retained_cleanup_failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }

    /// Separate final-close path: retain command/Unknown history and grant no
    /// reusable owner authority. Ordinary close remains unchanged.
    async fn close_terminal_read_only(
        &mut self,
        operations: &[super::client_debt::OperationKey],
    ) -> Result<TerminalReadOnlyRetirement, ProtocolError> {
        let prepared = async {
            if self.owns_context
                || self.replacement_routes.is_some()
                || self.disconnected_routes.is_some()
                || self.reconnect_proof.is_some()
            {
                cleanup_trace::terminal_cleanup_checkpoint(
                    TerminalCleanupStage::OwnerPreconditions,
                    false,
                );
                return Err(ProtocolError::CleanupFailed);
            }
            cleanup_trace::terminal_cleanup_checkpoint(
                TerminalCleanupStage::OwnerPreconditions,
                true,
            );
            self.targets.protected_read_residual.replacement_safe()?;
            self.page_state
                .check_no_active_local_input(&self.identity_scope)?;
            self.cleanup_replacement_actions().await?;
            let runtime = self.runtime.as_ref().ok_or(ProtocolError::CleanupFailed)?;
            self.ui.seal();
            let released = runtime
                .release_terminal_connection(&self.manager.client, false)
                .await;
            cleanup_trace::terminal_cleanup_checkpoint(
                TerminalCleanupStage::RuntimeRelease,
                released.is_ok(),
            );
            released?;
            self.targets.protected_read_residual.replacement_safe()?;
            let probe = self.persistent_probe.cleanup(&self.manager.client).await;
            cleanup_trace::terminal_cleanup_checkpoint(
                TerminalCleanupStage::PersistentProbe,
                probe.is_ok(),
            );
            probe?;
            // Last remote-only check before explicit physical close contaminates
            // transport EOF. This is not an ACK, and nothing is deleted.
            if let Some(ledger) = self.manager.client.debt_ledger() {
                let commands_present = ledger.snapshot().outstanding_commands > 0;
                cleanup_trace::terminal_cleanup_checkpoint(
                    TerminalCleanupStage::LedgerCommandsPresent,
                    commands_present,
                );
            }
            let enrollment = runtime
                .enrollment
                .check_terminal_read_only(operations)
                .await;
            cleanup_trace::terminal_cleanup_checkpoint(
                TerminalCleanupStage::EnrollmentProof,
                enrollment.is_ok(),
            );
            let (ledger, bindings) = enrollment?;
            Ok(TerminalReadOnlyRetirement {
                ledger,
                operations: operations.to_vec(),
                targets: self.targets.clone(),
                bindings,
            })
        }
        .await;
        match prepared {
            Ok(proof) => {
                let closed = self.manager.close().await;
                cleanup_trace::terminal_cleanup_checkpoint(
                    TerminalCleanupStage::PhysicalClose,
                    closed.is_ok(),
                );
                closed.map_err(|_| ProtocolError::CleanupFailed)?;
                Ok(proof)
            }
            Err(_) => {
                // Refused proof never abandons the ordinary cleanup attempts.
                let _ = self.close().await;
                Err(ProtocolError::CleanupFailed)
            }
        }
    }

    /// Caller seals and drains its gate first. A failed dispose is never
    /// rewritten as successful cleanup merely because the connection closes.
    pub async fn close(&mut self) -> Result<(), ProtocolError> {
        if !self.owns_context {
            self.targets.protected_read_residual.replacement_safe()?;
        }
        let retained_cleanup_failed = self.cleanup_replacement_actions().await.is_err();
        if let Some(runtime) = &self.runtime {
            self.ui.seal();
            let contained =
                if !self.owns_context && *self.manager.client.remote_connection_closed().borrow() {
                    runtime
                        .release_terminal_connection(&self.manager.client, false)
                        .await
                } else {
                    runtime.contain_and_release().await
                };
            if self.owns_context {
                runtime
                    .enrollment
                    .retire_protected_read_after_destroy(&self.targets.protected_read_residual)?;
            }
            self.targets.protected_read_residual.replacement_safe()?;
            let probe = self.persistent_probe.cleanup(&self.manager.client).await;
            let closed = self.manager.close().await;
            return if contained.is_ok()
                && probe.is_ok()
                && closed.is_ok()
                && !retained_cleanup_failed
            {
                Ok(())
            } else {
                Err(ProtocolError::CleanupFailed)
            };
        }
        self.targets.seal();
        if !self.owns_context {
            let probe = self.persistent_probe.cleanup(&self.manager.client).await;
            let closed = self.manager.close().await;
            return if probe.is_ok() && closed.is_ok() && !retained_cleanup_failed {
                Ok(())
            } else {
                Err(ProtocolError::CleanupFailed)
            };
        }
        let debt = self.manager.client.debt_ledger();
        if debt.as_ref().is_some_and(|ledger| {
            ledger.replacement_ready()
                && self
                    .manager
                    .client
                    .check_cleanup_owner(&Some(ledger.clone()))
                    .is_ok()
        }) {
            // Replacement can fail before installing any new owner (original
            // cancellation/deadline or writer contention). The exact old ledger
            // still carries disposal plus phase-two ACK proof. Do not attempt
            // ordinary disposal through its permanently retired application gate.
            // A new/unknown acquisition cannot satisfy replacement_ready().
            self.targets.protected_read_residual.replacement_safe()?;
            let closed = self.manager.close().await;
            return if closed.is_ok() && !retained_cleanup_failed {
                Ok(())
            } else {
                Err(ProtocolError::CleanupFailed)
            };
        }
        if let Some(ledger) = &debt {
            if let Some(context) = ledger.bound_context() {
                self.context_id = context;
            }
        }
        if self.context_id.is_empty() {
            self.targets.protected_read_residual.replacement_safe()?;
            // An unknown acquisition is not clean merely because the socket
            // closes. Keep the failed lifecycle resource journaled upstream.
            self.manager
                .close()
                .await
                .map_err(|_| ProtocolError::CleanupFailed)?;
            return Err(ProtocolError::CleanupFailed);
        }
        let disposed = self
            .manager
            .client
            .send_command(
                "Target.disposeBrowserContext",
                Some(serde_json::json!({"browserContextId": self.context_id})),
                None,
            )
            .await;
        let debt_retired = if disposed.is_ok() {
            debt.as_ref()
                .map(|ledger| ledger.retire_after_context_destroy(&self.context_id))
                .transpose()
        } else {
            Ok(None)
        };
        if disposed.is_ok() && debt_retired.is_ok() {
            if let Some(ledger) = &debt {
                self.targets
                    .protected_read_residual
                    .record_exact_context_destroyed(
                        &self.manager.client,
                        ledger,
                        &self.context_id,
                    )?;
            }
        }
        self.targets.protected_read_residual.replacement_safe()?;
        let closed = self.manager.close().await;
        if disposed.is_err() || closed.is_err() || retained_cleanup_failed || debt_retired.is_err()
        {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InitialMedia {
    color_scheme: Option<String>,
    reduced_motion: Option<String>,
}
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialViewport {
    width: u32,
    height: u32,
}
#[derive(Clone, Debug, Default)]
struct ScopeCreationOptions {
    block_service_workers: bool,
    viewport: Option<InitialViewport>,
    user_agent: Option<String>,
    locale: Option<String>,
    timezone_id: Option<String>,
    media: InitialMedia,
    init_scripts: Vec<String>,
}

pub(super) fn select_scope_viewport(
    seeded: bool,
    creation: Option<(u32, u32)>,
    requested: impl FnOnce() -> Result<Option<(u32, u32)>, ProtocolError>,
) -> Result<Option<(u32, u32)>, ProtocolError> {
    if seeded {
        Ok(requested()?.or(creation))
    } else {
        Ok(creation)
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeOpenWire {
    source: String,
    context: Option<String>,
    executable_path: Option<String>,
    headless: Option<bool>,
    endpoint: Option<String>,
    #[serde(default)]
    block_service_workers: bool,
    viewport: Option<InitialViewport>,
    user_agent: Option<String>,
    locale: Option<String>,
    timezone_id: Option<String>,
    #[serde(default)]
    media: InitialMedia,
    #[serde(default)]
    init_scripts: Vec<String>,
}
enum OpenRequest {
    Launch {
        executable_path: Option<String>,
        headless: bool,
        options: ScopeCreationOptions,
    },
    Connect {
        endpoint: String,
        persistent: bool,
        options: ScopeCreationOptions,
    },
    Reuse {
        options: ScopeCreationOptions,
    },
}
impl<'de> serde::Deserialize<'de> for OpenRequest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let value = <serde_json::Value as serde::Deserialize>::deserialize(deserializer)?;
        // viewport:null is the public no-override form; optional scalar fields
        // and media members must not silently turn explicit null into omission.
        if [
            "context",
            "executablePath",
            "headless",
            "endpoint",
            "userAgent",
            "locale",
            "timezoneId",
        ]
        .iter()
        .any(|key| value.get(*key) == Some(&serde_json::Value::Null))
            || ["colorScheme", "reducedMotion"].iter().any(|key| {
                value.get("media").and_then(|media| media.get(*key))
                    == Some(&serde_json::Value::Null)
            })
        {
            return Err(D::Error::custom("invalid null scope option"));
        }
        let wire: ScopeOpenWire = serde_json::from_value(value).map_err(D::Error::custom)?;
        if wire.viewport.as_ref().is_some_and(|v| {
            v.width == 0 || v.height == 0 || v.width > i32::MAX as u32 || v.height > i32::MAX as u32
        }) || wire.init_scripts.len() > 1024
            || wire
                .init_scripts
                .iter()
                .map(String::len)
                .try_fold(0usize, usize::checked_add)
                .is_none_or(|size| size > 8 * 1024 * 1024)
            || wire
                .media
                .color_scheme
                .as_ref()
                .is_some_and(|v| !matches!(v.as_str(), "light" | "dark" | "no-preference"))
            || wire
                .media
                .reduced_motion
                .as_ref()
                .is_some_and(|v| !matches!(v.as_str(), "reduce" | "no-preference"))
        {
            return Err(D::Error::custom("invalid scope creation options"));
        }
        let context = wire.context.as_deref().unwrap_or("isolated");
        let options = ScopeCreationOptions {
            block_service_workers: wire.block_service_workers,
            viewport: wire.viewport,
            user_agent: wire.user_agent,
            locale: wire.locale,
            timezone_id: wire.timezone_id,
            media: wire.media,
            init_scripts: wire.init_scripts,
        };
        match wire.source.as_str() {
            "launch" if context == "isolated" && wire.endpoint.is_none() => Ok(Self::Launch {
                executable_path: wire.executable_path,
                headless: wire.headless.unwrap_or(true),
                options,
            }),
            "connect"
                if matches!(context, "isolated" | "persistent")
                    && wire.executable_path.is_none()
                    && wire.headless.is_none() =>
            {
                let endpoint = wire
                    .endpoint
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| D::Error::custom("missing endpoint"))?;
                Ok(Self::Connect {
                    endpoint,
                    persistent: context == "persistent",
                    options,
                })
            }
            "reuse"
                if context == "isolated"
                    && wire.endpoint.is_none()
                    && wire.executable_path.is_none()
                    && wire.headless.is_none() =>
            {
                Ok(Self::Reuse { options })
            }
            _ => Err(D::Error::custom("invalid scope source")),
        }
    }
}

/// One native client owns one resource scope. Capabilities remain narrow until
/// the corresponding observation, network and protected-capture contracts land.
#[derive(Default)]
struct RetirementJournal {
    shutting_down: bool,
    coordinator: Option<std::sync::Weak<super::client_enrollment::ClientEnrollment>>,
}
/// Constructible only by the lifecycle journal, bound to the exact registry it
/// is retiring. It conveys no remote cleanup or replacement-admission proof.
pub(crate) struct OwnerRetirement {
    targets: Arc<super::client_targets::ClientTargets>,
}
impl OwnerRetirement {
    pub(crate) fn authorizes(&self, targets: &super::client_targets::ClientTargets) -> bool {
        std::ptr::eq(self.targets.as_ref(), targets)
    }
    #[cfg(test)]
    pub(crate) fn for_test(targets: &Arc<super::client_targets::ClientTargets>) -> Self {
        Self {
            targets: targets.clone(),
        }
    }
}
impl RetirementJournal {
    fn register(
        &mut self,
        coordinator: &Arc<super::client_enrollment::ClientEnrollment>,
    ) -> Result<(), ProtocolError> {
        if self.shutting_down {
            coordinator.seal();
            return Err(ProtocolError::Cancelled);
        }
        self.coordinator = Some(Arc::downgrade(coordinator));
        Ok(())
    }
    fn stop(&mut self, permanent: bool) {
        self.shutting_down |= permanent;
        if let Some(coordinator) = self.coordinator.as_ref().and_then(std::sync::Weak::upgrade) {
            if permanent {
                coordinator.seal();
            } else {
                let authority = OwnerRetirement {
                    targets: coordinator.retirement_targets().clone(),
                };
                coordinator.seal_for_owner_retirement(&authority);
            }
        }
    }
}

type ConnectionWatch =
    Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<Result<(), ProtocolError>>>>>;

// This is the retained observation boundary used by ClientBrowser before the
// transport settles the admitted operation in ClientSession.
pub(super) fn settle_observation_dispatch(
    output: Result<
        Result<serde_json::Value, super::client_observation_dispatch::DispatchFailure>,
        tokio::sync::oneshot::error::RecvError,
    >,
    cleanup: Result<
        Result<(), super::client_observation_dispatch::DispatchFailure>,
        tokio::task::JoinError,
    >,
) -> (super::client_transport::NativeOutcome, bool) {
    use super::client_protocol::Effects;
    use super::client_transport::NativeOutcome;
    let cleanup_failed = !matches!(cleanup, Ok(Ok(())))
        || matches!(&output, Ok(Err(failure)) if failure.cleanup_integrity_lost);
    let outcome = match output {
        Ok(Ok(value)) if !cleanup_failed => NativeOutcome {
            retention: None,
            result: Ok(value),
            effects: Effects::Completed,
        },
        Ok(Err(failure)) => {
            let effects = if cleanup_failed || failure.error == ProtocolError::CleanupFailed {
                Effects::Unknown
            } else {
                Effects::NotDispatched
            };
            NativeOutcome {
                retention: None,
                result: Err(failure.error),
                effects,
            }
        }
        _ => NativeOutcome {
            retention: None,
            result: Err(ProtocolError::CleanupFailed),
            effects: Effects::Unknown,
        },
    };
    let cleanup_failed =
        cleanup_failed || matches!(outcome.result, Err(ProtocolError::CleanupFailed));
    (outcome, cleanup_failed)
}

pub(super) fn protected_read_receipt_eligible(
    request: &super::client_observation_dispatch::DispatchRequest,
) -> bool {
    use super::client_observation_dispatch::DispatchRequest;
    matches!(
        request,
        DispatchRequest::Observe(_)
            | DispatchRequest::Screenshot(_)
            | DispatchRequest::TraceSemantic(_)
    )
}

pub(super) fn settle_trace_screenshot(
    mut outcome: super::client_transport::NativeOutcome,
    dirty: bool,
    trace_screenshot: bool,
    expected: &super::client_debt::OperationJournalHandle,
) -> (super::client_transport::NativeOutcome, bool) {
    if trace_screenshot && dirty {
        outcome.result = Err(ProtocolError::CleanupFailed);
        outcome.effects = super::client_protocol::Effects::Unknown;
        outcome.retention = None;
        return (outcome, true);
    }
    settle_protected_read(outcome, dirty, trace_screenshot, expected)
}

/// Joined native protection is not uncertain application input. The exact
/// operation must prove restoration and discharge every owned remote obligation.
pub(super) fn settle_protected_read(
    mut outcome: super::client_transport::NativeOutcome,
    dirty: bool,
    eligible: bool,
    expected: &super::client_debt::OperationJournalHandle,
) -> (super::client_transport::NativeOutcome, bool) {
    // Eligible dispatches use native read/protection commands. A joined producer
    // has restored its temporary changes; those are not uncertain user input.
    // The read still fails and never publishes late pixels or a continuation.
    if eligible
        && !dirty
        && outcome.result.is_err()
        && outcome.effects == super::client_protocol::Effects::NotDispatched
        && super::client_debt::OperationJournalHandle::current().is_some_and(|journal| {
            let state = journal.snapshot();
            journal.same_operation(expected)
                && state.mutation_dispatched
                && !state.integrity_lost
                && journal.clean_protected_read()
        })
    {
        outcome.effects = super::client_protocol::Effects::Completed;
    }
    (outcome, dirty)
}

/// Exact-key test observation only. It cannot grant admission or release a lock.
#[cfg(test)]
struct GenericAdmissionProbe {
    key: super::client_debt::OperationKey,
    reached: tokio::sync::oneshot::Sender<()>,
}

#[cfg(test)]
async fn observe_generic_guard_wait<'a>(
    gate: &'a tokio::sync::Mutex<()>,
    key: super::client_debt::OperationKey,
    probe: &Arc<Mutex<Option<GenericAdmissionProbe>>>,
) -> tokio::sync::MutexGuard<'a, ()> {
    observe_generic_admission_wait(gate.lock(), key, probe).await
}

#[cfg(test)]
async fn observe_generic_admission_wait<F: std::future::Future>(
    wait: F,
    key: super::client_debt::OperationKey,
    probe: &Arc<Mutex<Option<GenericAdmissionProbe>>>,
) -> F::Output {
    tokio::pin!(wait);
    std::future::poll_fn(|cx| {
        let polled = std::future::Future::poll(wait.as_mut(), cx);
        if polled.is_pending() {
            let mut probe = probe.lock().unwrap();
            if probe.as_ref().is_some_and(|probe| probe.key == key) {
                let _ = probe.take().unwrap().reached.send(());
            }
        }
        polled
    })
    .await
}

pub struct ClientBrowser {
    #[cfg(test)]
    generic_admission_probe: Arc<Mutex<Option<GenericAdmissionProbe>>>,
    broker: Arc<super::client_session::ClientSession>,
    event_sink: std::sync::OnceLock<super::client_transport::ClientEventSink>,
    gate: Arc<ExecutionGate>,
    owner: Arc<tokio::sync::Mutex<Option<OwnedBrowser>>>,
    retained_browser: Arc<tokio::sync::Mutex<Option<super::browser::BrowserManager>>>,
    refs: Arc<Mutex<super::element::RefMap>>,
    blobs: Arc<super::client_blobs::BlobStore>,
    retirement: Arc<Mutex<RetirementJournal>>,
    lifecycle: Arc<tokio::sync::Mutex<()>>,
    startup_uncertain: Arc<std::sync::atomic::AtomicBool>,
    terminal_recording: Arc<Mutex<Option<super::client_terminal_artifacts::FrozenRecordingBatch>>>,
    startup_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    connection_watch: ConnectionWatch,
    tasks: Arc<super::client_tasks::RetainedTasks>,
    observation: Arc<super::client_observation_dispatch::ObservationDispatch>,
    #[cfg(feature = "acceptance-faults")]
    faults: Arc<super::client_test_faults::FaultController>,
}
impl ClientBrowser {
    pub fn new(broker: Arc<super::client_session::ClientSession>) -> Self {
        let refs = Arc::new(Mutex::new(super::element::RefMap::new()));
        let observation =
            super::client_observation_dispatch::ObservationDispatch::new(refs.clone());
        Self {
            #[cfg(test)]
            generic_admission_probe: Arc::new(Mutex::new(None)),
            broker,
            event_sink: std::sync::OnceLock::new(),
            gate: Arc::new(ExecutionGate::default()),
            owner: Arc::new(tokio::sync::Mutex::new(None)),
            retained_browser: Arc::new(tokio::sync::Mutex::new(None)),
            refs,
            blobs: Arc::new(
                super::client_blobs::BlobStore::new(Default::default())
                    .expect("fixed valid native blob limits"),
            ),
            retirement: Arc::new(Mutex::new(RetirementJournal::default())),
            lifecycle: Arc::new(tokio::sync::Mutex::new(())),
            startup_uncertain: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            terminal_recording: Arc::new(Mutex::new(None)),
            startup_task: tokio::sync::Mutex::new(None),
            connection_watch: Arc::new(tokio::sync::Mutex::new(None)),
            tasks: Arc::new(super::client_tasks::RetainedTasks::default()),
            observation,
            #[cfg(feature = "acceptance-faults")]
            faults: Arc::new(super::client_test_faults::FaultController::default()),
        }
    }

    async fn open(
        &self,
        request: OpenRequest,
        operation: super::client_session::OperationLease,
    ) -> Result<serde_json::Value, ProtocolError> {
        // Persistent detach-only cleanup needs a proven pause settlement path;
        // do not adopt or navigate a host page before that contract is wired.
        let transition = self.lifecycle.clone().lock_owned().await;
        if self.owner.lock().await.is_some() {
            return Err(ProtocolError::InvalidArguments);
        }
        if !matches!(request, OpenRequest::Reuse { .. })
            && self.retained_browser.lock().await.is_some()
        {
            return Err(ProtocolError::InvalidArguments);
        }
        self.gate.begin_transition()?;
        self.gate.drained().await?;
        let mut task_slot = self.startup_task.lock().await;
        self.startup_uncertain
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let gate = self.gate.clone();
        let owner = self.owner.clone();
        let retained_browser = self.retained_browser.clone();
        let connection_watch = self.connection_watch.clone();
        let event_sink = self
            .event_sink
            .get()
            .cloned()
            .ok_or(ProtocolError::ScopeUnavailable)?;
        let broker = self.broker.clone();
        let retirement = self.retirement.clone();
        let blobs = self.blobs.clone();
        let uncertain = self.startup_uncertain.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        // Retained lifecycle supervisor survives cancellation of the requesting
        // RPC. Shutdown seals first, then joins this task; late startup cleans
        // its resources instead of publishing into an already closed scope.
        *task_slot = Some(tokio::spawn(async move {
            let _transition = transition;
            let options = match &request {
                OpenRequest::Launch { options, .. }
                | OpenRequest::Connect { options, .. }
                | OpenRequest::Reuse { options } => options.clone(),
            };
            let mut failed_persistent = None;
            let created = match request {
                OpenRequest::Reuse { .. } => match retained_browser.lock().await.take() {
                    Some(manager) => {
                        OwnedBrowser::isolated_for_scope(
                            manager,
                            &operation,
                            &mut failed_persistent,
                        )
                        .await
                    }
                    None => Err(ProtocolError::ScopeUnavailable),
                },
                OpenRequest::Connect {
                    endpoint,
                    persistent,
                    ..
                } => {
                    if persistent {
                        OwnedBrowser::connect_persistent(&endpoint, &mut failed_persistent).await
                    } else {
                        match super::browser::BrowserManager::connect_owned_browser(&endpoint, None)
                            .await
                        {
                            Ok(manager) => {
                                OwnedBrowser::isolated_for_scope(
                                    manager,
                                    &operation,
                                    &mut failed_persistent,
                                )
                                .await
                            }
                            Err(_) => Err(ProtocolError::BrowserFailure),
                        }
                    }
                }
                OpenRequest::Launch {
                    executable_path,
                    headless,
                    ..
                } => {
                    match super::browser::BrowserManager::launch_owned(
                        super::cdp::chrome::LaunchOptions {
                            executable_path,
                            headless,
                            ..Default::default()
                        },
                        None,
                    )
                    .await
                    {
                        Ok(manager) => {
                            OwnedBrowser::isolated_for_scope(
                                manager,
                                &operation,
                                &mut failed_persistent,
                            )
                            .await
                        }
                        Err(_) => Err(ProtocolError::BrowserFailure),
                    }
                }
            };
            let result = match created {
                Err(error) => {
                    if let Some(mut resource) = failed_persistent {
                        if resource.close().await.is_err() {
                            *owner.lock().await = Some(resource);
                        } else {
                            uncertain.store(false, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                    Err(error)
                }
                Ok(mut resource) => {
                    let identity = resource.identity_scope.clone();
                    let recovery = resource.recovery_identity();
                    let authority = match resource
                        .initialize_runtime(
                            gate.clone(),
                            broker,
                            event_sink.clone(),
                            blobs,
                            RuntimeInitialization {
                                operation: &operation,
                                retirement: &retirement,
                                options: &options,
                                replacement: None,
                            },
                        )
                        .await
                    {
                        Ok(authority) => authority,
                        Err(error) => {
                            let result = match resource.close().await {
                                Ok(()) => {
                                    uncertain.store(false, std::sync::atomic::Ordering::SeqCst);
                                    Err(error)
                                }
                                Err(_) => {
                                    *owner.lock().await = Some(resource);
                                    Err(ProtocolError::CleanupFailed)
                                }
                            };
                            let _ = send.send(result);
                            return;
                        }
                    };
                    let mut current = owner.lock().await;
                    let published = loop {
                        if *operation.cancellation.borrow()
                            != super::client_session::CancelSignal::None
                        {
                            break Err(ProtocolError::Cancelled);
                        }
                        if std::time::Instant::now() >= operation.deadline {
                            break Err(ProtocolError::DeadlineExceeded);
                        }
                        match resource
                            .runtime
                            .as_ref()
                            .ok_or(ProtocolError::ScopeUnavailable)
                            .and_then(|runtime| runtime.enrollment.publish_initialized(&authority))
                        {
                            Ok(epoch) => break Ok(epoch),
                            Err(error) => {
                                if error != ProtocolError::ScopeUnavailable {
                                    break Err(error);
                                }
                                if std::time::Instant::now() >= operation.deadline
                                    || *operation.cancellation.borrow()
                                        != super::client_session::CancelSignal::None
                                {
                                    break Err(error);
                                }
                                if gate.state.lock().map_or(true, |state| state.closed) {
                                    break Err(error);
                                }
                                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                            }
                        }
                    };
                    match published {
                        Ok(_) => {
                            if let Err(error) = resource
                                .persistent_probe
                                .commit(resource.manager.active_target_id().unwrap_or_default())
                            {
                                *current = Some(resource);
                                let _ = send.send(Err(error));
                                return;
                            }
                            let mut watch_slot = connection_watch.lock().await;
                            // A completed borrowed scope may reopen on a different
                            // connection. Join the old event-only watcher before
                            // installing the exact current connection's watcher.
                            if let Some(previous) = watch_slot.as_mut() {
                                previous.abort();
                                let _ = previous.await;
                            }
                            *watch_slot = None;
                            if watch_slot.is_none() {
                                {
                                    let sink = event_sink;
                                    let watched_client = resource.manager.client.clone();
                                    let watched_targets = resource.targets.clone();
                                    let mut lost = watched_client.remote_connection_closed();
                                    *watch_slot = Some(tokio::spawn(async move {
                                        loop {
                                            if *lost.borrow() {
                                                return sink
                                                    .emit_disconnected(
                                                        &watched_client,
                                                        &watched_targets,
                                                    )
                                                    .map(|_queued| ());
                                            }
                                            if lost.changed().await.is_err() {
                                                return Ok(());
                                            }
                                        }
                                    }));
                                }
                            }
                            drop(watch_slot);
                            *current = Some(resource);
                            uncertain.store(false, std::sync::atomic::Ordering::SeqCst);
                            Ok(
                                serde_json::json!({"identityScope": identity, "recoveryIdentity": recovery}),
                            )
                        }
                        Err(error) => {
                            drop(current);
                            match resource.close().await {
                                Ok(()) => {
                                    uncertain.store(false, std::sync::atomic::Ordering::SeqCst);
                                    Err(error)
                                }
                                Err(_) => {
                                    *owner.lock().await = Some(resource);
                                    Err(ProtocolError::CleanupFailed)
                                }
                            }
                        }
                    }
                }
            };
            let _ = send.send(result);
        }));
        drop(task_slot);
        receive.await.map_err(|_| ProtocolError::BrowserFailure)?
    }

    /// A retained supervisor owns teardown even when the RPC future is dropped.
    /// The same browser process can be reused only after context disposal proof.
    async fn end_scope(
        &self,
        identity_scope: String,
        operation_seq: u64,
    ) -> Result<serde_json::Value, ProtocolError> {
        let transition = self.lifecycle.clone().lock_owned().await;
        let diagnostics = {
            let owner = self.owner.lock().await;
            if owner.as_ref().map(|scope| scope.identity_scope.as_str())
                != Some(identity_scope.as_str())
            {
                return Err(ProtocolError::StaleScope);
            }
            owner
                .as_ref()
                .and_then(|owner| owner.manager.client.cleanup_diagnostics())
        };
        self.stop_enrollment(false)?;
        #[cfg(feature = "acceptance-faults")]
        self.faults.retire_scope(&identity_scope)?;
        self.gate.begin_transition()?;
        self.gate.drained().await?;
        let mut slot = self.startup_task.lock().await;
        self.startup_uncertain
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let gate = self.gate.clone();
        let owner = self.owner.clone();
        let retained = self.retained_browser.clone();
        let refs = self.refs.clone();
        let tasks = self.tasks.clone();
        let uncertain = self.startup_uncertain.clone();
        let diagnostic_attempt = diagnostics
            .as_ref()
            .and_then(|cell| cell.begin(cleanup_trace::CleanupLifecycle::ScopeEnd, operation_seq));
        let diagnostics = diagnostic_attempt
            .as_ref()
            .map(|attempt| attempt.observer());
        let (send, receive) = tokio::sync::oneshot::channel();
        *slot = Some(tokio::spawn(async move {
            let _transition = transition;
            let result = async {
                let task_cleanup = tasks.drain_current().await;
                cleanup_trace::observe_cleanup(
                    &diagnostics,
                    CleanupPart::RetainedTaskFallback,
                    &task_cleanup,
                );
                let task_cleanup_failed = task_cleanup.is_err();
                // Revoke exact authority while the resource is still journaled.
                // A poisoned map must not drop a live browser manager.
                refs.lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .retire_owner_references();
                let mut resource = owner.lock().await.take().ok_or(ProtocolError::StaleScope)?;
                if let Err(error) = resource.dispose_context().await {
                    // Retain the resource for shutdown rather than dropping a
                    // manager whose context cleanup has an unknown outcome.
                    *owner.lock().await = Some(resource);
                    return Err(error);
                }
                if task_cleanup_failed {
                    *owner.lock().await = Some(resource);
                    return Err(ProtocolError::CleanupFailed);
                }
                if let Err(error) = gate.commit_transition() {
                    if resource.manager.close().await.is_err() {
                        *owner.lock().await = Some(resource);
                        return Err(ProtocolError::CleanupFailed);
                    }
                    uncertain.store(false, std::sync::atomic::Ordering::SeqCst);
                    return Err(error);
                }
                if resource.owns_context {
                    *retained.lock().await = Some(resource.manager);
                }
                uncertain.store(false, std::sync::atomic::Ordering::SeqCst);
                Ok(serde_json::Value::Null)
            }
            .await;
            cleanup_trace::observe_cleanup(&diagnostics, CleanupPart::OwnerFallback, &result);
            let _ = send.send(result);
        }));
        drop(slot);
        let result = receive.await.map_err(|_| ProtocolError::CleanupFailed)?;
        if let Some(attempt) = diagnostic_attempt {
            attempt.finish(&result);
        }
        result
    }

    fn stop_enrollment(&self, permanent: bool) -> Result<(), ProtocolError> {
        self.retirement
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .stop(permanent);
        Ok(())
    }

    fn operation_journal(
        page: &BrowserExecutionLease,
        operation: &super::client_session::OperationLease,
    ) -> Result<super::client_debt::OperationJournalHandle, ProtocolError> {
        page.permit.check()?;
        let ledger = page
            .client
            .debt_ledger()
            .ok_or(ProtocolError::ScopeUnavailable)?;
        let journal = ledger.operation(
            super::client_debt::OperationKey {
                generation: operation.generation,
                operation_seq: operation.sequence,
            },
            page.target_id.clone(),
            page.page_session_id.clone(),
        )?;
        journal.bind_operation(operation)?;
        Ok(journal)
    }

    async fn page_lease(
        &self,
        callback_child: bool,
    ) -> Result<BrowserExecutionLease, ProtocolError> {
        let permit = self.gate.enter(callback_child)?;
        self.owner
            .lock()
            .await
            .as_ref()
            .ok_or(ProtocolError::ScopeUnavailable)?
            .lease(permit)
    }
}

impl super::client_transport::ClientExecutor for ClientBrowser {
    fn take_terminal_recording(
        &self,
        key: super::client_debt::OperationKey,
    ) -> Option<super::client_terminal_artifacts::FrozenRecordingBatch> {
        let mut slot = self.terminal_recording.lock().ok()?;
        if slot.as_ref().is_some_and(|batch| batch.key() == key) {
            slot.take()
        } else {
            None
        }
    }
    fn begin_trace_cleanup(
        &self,
        key: super::client_debt::OperationKey,
    ) -> Option<std::time::Instant> {
        self.tasks.begin_protected_cleanup(key)
    }
    fn discard_trace_result(
        &self,
        key: super::client_debt::OperationKey,
        value: &serde_json::Value,
    ) -> Result<(), ProtocolError> {
        self.blobs
            .discard_trace_image(key.generation, value)
            .map_err(|_| ProtocolError::CleanupFailed)
    }
    fn operation_retention_status(
        &self,
        key: super::client_debt::OperationKey,
    ) -> super::client_operation_state::OperationRetentionStatus {
        self.tasks.operation_retention_status(key)
    }
    fn disconnected_recovery_candidate(
        &self,
        key: super::client_debt::OperationKey,
    ) -> Option<super::client_operation_state::DisconnectedRecoveryProof> {
        self.tasks.recovery_candidate(key)
    }
    fn cancel_operation_producer(&self, key: super::client_debt::OperationKey) {
        self.tasks.cancel_operation_producer(key);
    }
    fn fix_operation_result(&self, key: super::client_debt::OperationKey) {
        self.tasks.fix_operation_result(key);
    }
    async fn retire_operation_publication(
        &self,
        _key: super::client_debt::OperationKey,
    ) -> Result<(), ProtocolError> {
        self.observation.retire_interaction().await
    }

    fn set_event_sink(
        &self,
        sink: super::client_transport::ClientEventSink,
    ) -> Result<(), ProtocolError> {
        self.event_sink
            .set(sink)
            .map_err(|_| ProtocolError::InvalidArguments)
    }

    fn prepare_decision(
        &self,
        generation: u64,
        token: &str,
        decision: &super::client_protocol::Decision,
    ) -> Result<(), ProtocolError> {
        let Some(handle) = decision.body_handle() else {
            return Ok(());
        };
        let identity_scope = self.broker.decision_resource_scope(generation, token)?;
        self.blobs
            .reserve(
                &super::client_blobs::BlobScope {
                    generation,
                    identity_scope,
                },
                handle,
                token,
            )
            .map_err(|error| match error {
                super::client_blobs::BlobError::StaleScope => ProtocolError::StaleScope,
                super::client_blobs::BlobError::Closed => ProtocolError::ScopeUnavailable,
                super::client_blobs::BlobError::QuotaExceeded => ProtocolError::CapacityExceeded,
                super::client_blobs::BlobError::Reserved => ProtocolError::PolicyDenied,
                _ => ProtocolError::InvalidArguments,
            })
    }

    fn finish_decision(&self, token: &str, accepted: bool) -> Result<(), ProtocolError> {
        if !accepted {
            self.blobs
                .rollback(token)
                .map_err(|_| ProtocolError::CleanupFailed)?;
        }
        Ok(())
    }

    fn capabilities(&self) -> Vec<String> {
        // Capabilities describe implemented, wired candidate contracts. External
        // acceptance evidence separately determines release readiness.
        let capabilities = [
            super::client_protocol::EXACT_OWNER_CONTINUATION,
            super::client_protocol::DISCONNECTED_RECOVERY,
            super::client_protocol::TERMINAL_RECORDING_ARTIFACTS,
            "browser.scope/1",
            "browser.lifecycle/1",
            super::client_protocol::PERSISTENT_PAGE_REOPEN,
            "browser.evaluate/1",
            "browser.page/1",
            "browser.observe/1",
            "browser.observe-frame-policy/1",
            "browser.trace-semantic/1",
            "browser.query/1",
            "browser.query-union/1",
            "browser.fixture-read-fields/1",
            "browser.actions/1",
            "browser.network/1",
            "browser.dialog/1",
            "browser.download/1",
            "browser.capture/1",
            "browser.state/1",
            "browser.recording/1",
            "browser.blobs/1",
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
        #[cfg(feature = "acceptance-faults")]
        {
            capabilities
                .into_iter()
                .chain(std::iter::once("acceptance.faults/1".into()))
                .collect()
        }
        #[cfg(not(feature = "acceptance-faults"))]
        {
            capabilities
        }
    }

    async fn execute(
        &self,
        command: String,
        mut args: serde_json::Map<String, serde_json::Value>,
        lease: super::client_session::OperationLease,
    ) -> super::client_transport::NativeOutcome {
        use super::client_protocol::Effects;
        use super::client_transport::NativeOutcome;
        // Scope authority is captured by the caller before asynchronous work.
        // Never replace it with the current scope after a reset or reconnect.
        let captured_scope = if command == "scope.open" {
            None
        } else {
            let scope = match args
                .get("identityScope")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
            {
                Some(value) => value.to_owned(),
                None => {
                    return NativeOutcome {
                        retention: None,
                        result: Err(ProtocolError::InvalidArguments),
                        effects: Effects::NotDispatched,
                    }
                }
            };
            if self
                .owner
                .lock()
                .await
                .as_ref()
                .map(|owner| owner.identity_scope.as_str())
                != Some(scope.as_str())
            {
                return NativeOutcome {
                    retention: None,
                    result: Err(ProtocolError::StaleScope),
                    effects: Effects::NotDispatched,
                };
            }
            if command != "scope.end" {
                args.remove("identityScope");
            }
            Some(scope)
        };
        let resource_command = matches!(
            command.as_str(),
            "blob.create"
                | "blob.write"
                | "blob.seal"
                | "blob.release"
                | "blob.read"
                | "network.routes.replace"
                | "network.responses.subscribe"
                | "network.responses.unsubscribe"
                | "network.body.read"
                | "network.body.release"
                | "dialog.register"
                | "download.subscribe"
                | "download.unsubscribe"
                | "download.metadata"
                | "download.read"
                | "download.release"
        );
        let mutating = matches!(
            command.as_str(),
            "scope.open"
                | "scope.end"
                | "page.evaluate"
                | "page.activate"
                | "page.navigate"
                | "page.reload"
                | "page.back"
                | "page.forward"
                | "context.cookies.set"
                | "context.init-script"
                | "context.media"
                | "context.viewport"
                | "input.keyboard"
                | "input.mouse"
        );
        let prepared = match command.as_str() {
            "scope.open" => {
                serde_json::from_value::<OpenRequest>(serde_json::Value::Object(args.clone()))
                    .map(Some)
            }
            "scope.end"
                if args.len() == 1
                    && args
                        .get("identityScope")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|value| !value.is_empty()) =>
            {
                Ok(None)
            }
            "scope.end" => {
                return NativeOutcome {
                    retention: None,
                    result: Err(ProtocolError::InvalidArguments),
                    effects: Effects::NotDispatched,
                }
            }
            _ if resource_command => Ok(None),
            #[cfg(feature = "acceptance-faults")]
            "test.fault.arm" | "test.fault.status" | "test.fault.release" => Ok(None),
            "browser.perform"
            | "browser.pointer"
            | "browser.keyboard.type"
            | "browser.keyboard.press"
            | "recording.start"
            | "recording.stop" => Ok(None),
            "state.restore" => Ok(None),
            "scope.reconnect" => {
                serde_json::from_value::<ReconnectRequest>(serde_json::Value::Object(args.clone()))
                    .map(|_| None)
            }
            "scope.configure"
            | "browser.observe"
            | "browser.trace"
            | "browser.query"
            | "fixture.query"
            | "fixture.read-fields"
            | "fixture.correlate"
            | "capture.screenshot" => Ok(None),
            "page.navigate"
            | "page.reload"
            | "page.back"
            | "page.forward"
            | "context.cookies.get"
            | "context.cookies.set"
            | "context.init-script"
            | "context.media"
            | "context.viewport"
            | "input.keyboard"
            | "input.mouse" => Ok(None),
            "page.activate"
            | "page.title"
            | "page.url"
            | "session.environment"
            | "state.capture"
            | "scope.restart"
            | "scope.reset"
                if args.is_empty() =>
            {
                Ok(None)
            }
            "page.evaluate"
                if args.len() == 2
                    && args.get("source").is_some_and(serde_json::Value::is_string)
                    && args.contains_key("argument") =>
            {
                Ok(None)
            }
            "page.activate"
            | "page.title"
            | "page.url"
            | "page.evaluate"
            | "session.environment"
            | "state.capture"
            | "scope.restart"
            | "scope.reset" => {
                return NativeOutcome {
                    retention: None,
                    result: Err(ProtocolError::InvalidArguments),
                    effects: Effects::NotDispatched,
                }
            }
            _ => {
                return NativeOutcome {
                    retention: None,
                    result: Err(ProtocolError::UnsupportedCommand),
                    effects: Effects::NotDispatched,
                }
            }
        };
        let prepared = match prepared {
            Ok(value) => value,
            Err(_) => {
                return NativeOutcome {
                    retention: None,
                    result: Err(ProtocolError::InvalidArguments),
                    effects: Effects::NotDispatched,
                }
            }
        };
        let recovery = if command == "scope.reconnect" {
            match self.broker.disconnected_recovery(&lease) {
                Ok(proof) => proof,
                Err(error) => {
                    return NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    }
                }
            }
        } else {
            None
        };
        if command != "scope.end" && recovery.is_none() {
            let admission = async {
                self.broker.wait_application_publication(&lease).await?;
                self.tasks.wait_application(&lease).await
            }
            .await;
            if let Err(error) = admission {
                return NativeOutcome {
                    retention: None,
                    result: Err(error),
                    effects: Effects::NotDispatched,
                };
            }
        }
        match self.broker.start(lease.generation, lease.sequence) {
            Ok(true) => {}
            Ok(false) => {
                return NativeOutcome {
                    retention: None,
                    result: Err(ProtocolError::Cancelled),
                    effects: Effects::NotDispatched,
                }
            }
            Err(error) => {
                return NativeOutcome {
                    retention: None,
                    result: Err(error),
                    effects: Effects::NotDispatched,
                }
            }
        }
        if matches!(command.as_str(), "scope.reset" | "state.restore") {
            let identity = captured_scope.unwrap_or_default();
            let restore = if command == "state.restore" {
                args.insert("identityScope".into(), identity.clone().into());
                Some(serde_json::Value::Object(args))
            } else {
                None
            };
            return self.replace_scope(identity, restore, lease).await;
        }
        if command == "scope.reconnect" {
            let request =
                match serde_json::from_value::<ReconnectRequest>(serde_json::Value::Object(args)) {
                    Ok(request) => request,
                    Err(_) => {
                        return NativeOutcome {
                            retention: None,
                            result: Err(ProtocolError::InvalidArguments),
                            effects: Effects::NotDispatched,
                        }
                    }
                };
            return self
                .reconnect_scope(captured_scope.unwrap_or_default(), request, lease, recovery)
                .await;
        }
        if command == "scope.restart" {
            return self
                .restart_pages(captured_scope.unwrap_or_default(), lease)
                .await;
        }
        // Reopen only at the existing explicit page activation boundary. Reads
        // and locators cannot turn an untouched/closed host page into a new tab.
        let reopened = if matches!(
            command.as_str(),
            "page.activate" | "page.navigate" | "recording.start"
        ) {
            let outcome = self
                .ensure_persistent_page(captured_scope.as_deref().unwrap_or_default(), &lease)
                .await;
            match outcome.result {
                Ok(value) => {
                    value.get("reopened").and_then(serde_json::Value::as_bool) == Some(true)
                }
                Err(_) => return outcome,
            }
        } else {
            false
        };
        let finish = |mut outcome: NativeOutcome| {
            // A proven, completed page creation is a completed prefix, not a
            // clean no-effect refusal of the whole public operation.
            if reopened && outcome.effects == Effects::NotDispatched {
                outcome.effects = Effects::Completed;
            }
            outcome
        };
        #[cfg(feature = "acceptance-faults")]
        if matches!(
            command.as_str(),
            "test.fault.arm" | "test.fault.status" | "test.fault.release"
        ) {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Arm {
                phase: super::client_test_faults::Phase,
            }
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Token {
                token: String,
            }
            let result = async {
                let page = self.page_lease(lease.is_callback).await?;
                if captured_scope.as_deref() != Some(page.identity_scope.as_str()) { return Err(ProtocolError::StaleScope); }
                page.permit.check()?;
                // Test controls intentionally bypass UI admission so a held
                // protected transaction can be inspected and released.
                let value = serde_json::Value::Object(args);
                if command == "test.fault.arm" {
                    let arm: Arm = serde_json::from_value(value).map_err(|_| ProtocolError::InvalidArguments)?;
                    Ok(serde_json::json!({"token": self.faults.arm(&page.identity_scope, arm.phase)?}))
                } else {
                    let token: Token = serde_json::from_value(value).map_err(|_| ProtocolError::InvalidArguments)?;
                    if command == "test.fault.status" {
                        serde_json::to_value(self.faults.status(&page.identity_scope, &token.token)?).map_err(|_| ProtocolError::BrowserFailure)
                    } else {
                        self.faults.release(&page.identity_scope, &token.token)?;
                        Ok(serde_json::json!({"released":true}))
                    }
                }
            }.await;
            let effects = if result.is_ok() {
                Effects::Completed
            } else {
                Effects::NotDispatched
            };
            return finish(NativeOutcome {
                retention: None,
                result,
                effects,
            });
        }
        if command == "scope.configure" {
            let request: ConfigureRequest =
                match serde_json::from_value(serde_json::Value::Object(args)) {
                    Ok(request) => request,
                    Err(_) => {
                        return finish(NativeOutcome {
                            retention: None,
                            result: Err(ProtocolError::InvalidArguments),
                            effects: Effects::NotDispatched,
                        })
                    }
                };
            let captured = async {
                let page = self.page_lease(lease.is_callback).await?;
                if captured_scope.as_deref() != Some(page.identity_scope.as_str()) {
                    return Err(ProtocolError::StaleScope);
                }
                let owner = self.owner.lock().await;
                let owner = owner.as_ref().ok_or(ProtocolError::StaleScope)?;
                if owner.identity_scope != page.identity_scope {
                    return Err(ProtocolError::StaleScope);
                }
                let runtime = owner
                    .runtime
                    .as_ref()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                request.validate(runtime.block_service_workers)?;
                Ok((
                    page,
                    runtime.configuration.clone(),
                    runtime.network.clone(),
                    runtime.enrollment.config_gate(),
                    owner.context_id.clone(),
                ))
            }
            .await;
            let (page, configuration, network, config_gate, context_id) = match captured {
                Ok(value) => value,
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let journal = match Self::operation_journal(&page, &lease) {
                Ok(journal) => journal,
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let receive = self.tasks.start_operation(page.identity_scope.clone(), page.targets.clone(), self.broker.clone(), journal.clone(), lease.cancellation.clone(), async move {
                let mut dispatched = false;
                let result = async {
                    page.permit.check()?;
                    let mut cancellation = lease.cancellation.clone();
                    if *cancellation.borrow() != super::client_session::CancelSignal::None { return Err(ProtocolError::Cancelled); }
                    let _configuration = tokio::select! {
                        biased;
                        _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                        guard = tokio::time::timeout_at(lease.deadline.into(), config_gate.lock()) => guard.map_err(|_| ProtocolError::DeadlineExceeded)?,
                    };
                    page.permit.check()?;
                    {
                        let mut state = configuration.lock().map_err(|_| ProtocolError::ScopeUnavailable)?;
                        if state.configuring || state.policy.is_some() { return Err(ProtocolError::InvalidArguments); }
                        state.configuring = true;
                    }
                    let downloads = request.downloads.clone();
                    let source = match request.downloads {
                        DownloadConfiguration::Local => {
                            let directory = tempfile::Builder::new().prefix("agent-browser-download-").tempdir().map_err(|_| ProtocolError::BrowserFailure)?;
                            let path = std::fs::canonicalize(directory.path()).map_err(|_| ProtocolError::BrowserFailure)?;
                            configuration.lock().map_err(|_| ProtocolError::ScopeUnavailable)?.download_directory = Some(directory);
                            super::client_network::DownloadSource::Local(path)
                        },
                        DownloadConfiguration::Provider { remote_directory } => super::client_network::DownloadSource::Provider(remote_directory),
                    };
                    // Journal directory before the first browser effect. The
                    // retained scope owner keeps it even on an unknown ACK.
                    dispatched = true;
                    network.configure_downloads(&context_id, source, &lease).await?;
                    page.permit.check()?;
                    let mut state = configuration.lock().map_err(|_| ProtocolError::ScopeUnavailable)?;
                    state.policy = Some(super::client_observation_dispatch::ReadPolicy { frame_policy: request.request_policy.observation_frame_policy(), test_id_attribute: request.test_id_attribute, secure_field_selector: request.secure_field_selector });
                    state.downloads = Some(downloads);
                    state.configuring = false;
                    Ok(serde_json::Value::Null)
                }.await;
                let failed = result.is_err() && dispatched;
                if failed { page.targets.seal(); }
                let effects = if failed { Effects::Unknown } else if result.is_err() { Effects::NotDispatched } else { Effects::Completed };
                (NativeOutcome { retention: None, result, effects }, failed)
            }).await;
            return finish(await_retained(receive).await);
        }
        if matches!(
            command.as_str(),
            "browser.observe"
                | "browser.trace"
                | "browser.query"
                | "fixture.query"
                | "fixture.read-fields"
                | "fixture.correlate"
                | "capture.screenshot"
        ) {
            use super::client_observation_dispatch::{
                DispatchContext, DispatchRequest, FieldReadRequest, QueryPurpose, QueryRequest,
            };
            let value = serde_json::Value::Object(args);
            let request = match command.as_str() {
                "browser.observe" => serde_json::from_value(value).map(DispatchRequest::Observe),
                "browser.trace" => {
                    serde_json::from_value(value).map(DispatchRequest::TraceSemantic)
                }
                "fixture.correlate" => {
                    serde_json::from_value(value).map(DispatchRequest::Correlate)
                }
                "capture.screenshot" => {
                    serde_json::from_value(value).map(DispatchRequest::Screenshot)
                }
                "fixture.read-fields" => {
                    let mut value = value;
                    let fields = value
                        .as_object_mut()
                        .and_then(|args| args.remove("fields"))
                        .unwrap_or(serde_json::Value::Null);
                    serde_json::from_value(fields).and_then(|fields| {
                        serde_json::from_value(value).map(|options| {
                            DispatchRequest::ReadFields(FieldReadRequest {
                                options,
                                fields,
                                broker: self.broker.clone(),
                            })
                        })
                    })
                }
                _ => serde_json::from_value(value).map(|options| {
                    DispatchRequest::Query(QueryRequest {
                        options,
                        purpose: if command == "fixture.query" {
                            QueryPurpose::Fixture
                        } else {
                            QueryPurpose::Protected
                        },
                    })
                }),
            };
            let request = match request {
                Ok(request) => request,
                Err(_) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(ProtocolError::InvalidArguments),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let captured = async {
                let permit = self.gate.enter(lease.is_callback)?;
                let owner = self.owner.lock().await;
                let owner = owner.as_ref().ok_or(ProtocolError::StaleScope)?;
                let page = owner.lease(permit)?;
                if captured_scope.as_deref() != Some(page.identity_scope.as_str()) {
                    return Err(ProtocolError::StaleScope);
                }
                // Capture attachment tenure before yielding this owner snapshot.
                // A queued context cannot rebind an identical reattachment later.
                let attachment = page.targets.owned_target(&page.target_id)?;
                let runtime = owner
                    .runtime
                    .as_ref()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                if !runtime
                    .page_active
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(ProtocolError::ScopeUnavailable);
                }
                let policy = runtime
                    .configuration
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .policy
                    .clone()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                Ok(DispatchContext {
                    page,
                    attachment,
                    ui: owner.ui.clone(),
                    blobs: runtime.blobs.clone(),
                    scope: runtime.scope.clone(),
                    policy,
                    #[cfg(feature = "acceptance-faults")]
                    faults: self.faults.clone(),
                })
            }
            .await;
            let context = match captured {
                Ok(context) => context,
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let journal = match Self::operation_journal(&context.page, &lease) {
                Ok(journal) => journal,
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let observation = self.observation.clone();
            let receipt_journal = journal.clone();
            let receipt_blobs = context.blobs.clone();
            let receipt_deadline = lease.deadline;
            let receipt_cancellation = lease.cancellation.clone();
            let receipt_generation = lease.generation;
            let (semantic_send, semantic_receive) = tokio::sync::oneshot::channel();
            let receive = self
                .tasks
                .start_operation_prepared(
                    context.scope.identity_scope.clone(),
                    context.page.targets.clone(),
                    self.broker.clone(),
                    journal,
                    lease.cancellation.clone(),
                    move || {
                        // The registry has accepted capacity, but has not spawned
                        // work. Exact-owner/policy validation and Observe ticket
                        // admission are synchronous and precede any task reorder.
                        let trace_screenshot = matches!(&request, DispatchRequest::Screenshot(request)
                            if request.purpose == super::client_observation_dispatch::ScreenshotPurpose::Trace);
                        let semantic_trace = matches!(&request, DispatchRequest::TraceSemantic(_));
                        let protected_receipt = protected_read_receipt_eligible(&request);
                        let prepared = observation.prepare(context, request, lease)?;
                        Ok(async move {
                            let task = observation.start_prepared(prepared);
                            let output = task.result.await;
                            if task.receipt.is_sealed_observation() {
                                if let Ok(Ok(value)) = &output {
                                    // Only the dispatcher can issue this receipt,
                                    // after the tree-only commit. Keep this same
                                    // registered producer alive through its join.
                                    let _ = semantic_send.send((NativeOutcome {
                                        retention: None,
                                        result: Ok(value.clone()),
                                        effects: Effects::Completed,
                                    }, task.receipt.cleanup_failed_before_publication()));
                                }
                            }
                            let cleanup = task.join.await;
                            let (mut outcome, mut dirty) = settle_observation_dispatch(output, cleanup);
                            if (trace_screenshot || semantic_trace) && (std::time::Instant::now() >= receipt_deadline
                                || *receipt_cancellation.borrow() != super::client_session::CancelSignal::None)
                            {
                                if let Ok(value) = &outcome.result {
                                    if trace_screenshot {
                                        dirty |= receipt_blobs.discard_trace_image(receipt_generation, value).is_err();
                                    }
                                    outcome.result = Err(if dirty { ProtocolError::CleanupFailed } else {
                                        (*receipt_cancellation.borrow()).error().unwrap_or(ProtocolError::DeadlineExceeded)
                                    });
                                }
                            }
                            let (outcome, dirty) = settle_trace_screenshot(outcome, dirty, trace_screenshot || semantic_trace, &receipt_journal);
                            settle_protected_read(outcome, dirty, protected_receipt, &receipt_journal)
                        })
                    },
                )
                .await;
            let retained = await_retained(receive);
            tokio::pin!(retained);
            let outcome = tokio::select! {
                biased;
                result = semantic_receive => match result {
                    Ok((outcome, cleanup_failed)) => {
                        if cleanup_failed {
                            // The immutable tree is already committed. Quarantine
                            // before transport snapshots health, not before the
                            // dispatcher's final cancellation/identity checks.
                            let _ = self.broker.quarantine();
                        }
                        outcome
                    },
                    Err(_) => retained.await,
                },
                outcome = &mut retained => outcome,
            };
            return finish(outcome);
        }
        if matches!(
            command.as_str(),
            "browser.perform"
                | "browser.pointer"
                | "browser.keyboard.type"
                | "browser.keyboard.press"
                | "recording.start"
                | "recording.stop"
        ) {
            let captured = async {
                let page = self.page_lease(lease.is_callback).await?;
                if captured_scope.as_deref() != Some(page.identity_scope.as_str()) {
                    return Err(ProtocolError::StaleScope);
                }
                let owner = self.owner.lock().await;
                let owner = owner.as_ref().ok_or(ProtocolError::StaleScope)?;
                if owner.identity_scope != page.identity_scope {
                    return Err(ProtocolError::StaleScope);
                }
                let runtime = owner
                    .runtime
                    .as_ref()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                if !matches!(command.as_str(), "recording.start" | "recording.stop")
                    && !runtime
                        .page_active
                        .load(std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(ProtocolError::ScopeUnavailable);
                }
                Ok((
                    page,
                    owner.page_state.clone(),
                    owner.ui.clone(),
                    runtime.actions.clone(),
                    runtime.input_gate.clone(),
                    runtime.blobs.clone(),
                    runtime.page_active.clone(),
                    runtime.activation.clone(),
                    runtime.enrollment.clone(),
                    runtime.observation_after,
                ))
            }
            .await;
            let (
                page,
                page_state,
                ui,
                actions,
                input_gate,
                blobs,
                page_active,
                activation,
                enrollment,
                observation_after,
            ) = match captured {
                Ok(value) => value,
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            // Direct coordinates carry exact page authority, not DOM/viewport
            // reference authority. Validate them before any renderer preflight.
            args.insert("identityScope".into(), page.identity_scope.clone().into());
            let args = serde_json::Value::Object(args);
            let direct_point = if command == "browser.pointer" {
                match super::client_actions::ClientActions::is_direct_point(&args) {
                    Ok(direct) => direct,
                    Err(error) => {
                        return finish(NativeOutcome {
                            retention: None,
                            result: Err(error),
                            effects: Effects::NotDispatched,
                        })
                    }
                }
            } else {
                false
            };
            let observation = self.observation.clone();
            let publication_fence = match observation.publication_fence() {
                Ok(fence) => fence,
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let attachment = match page.targets.owned_target(&page.target_id) {
                Ok(attachment) => attachment,
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let journal = match Self::operation_journal(&page, &lease) {
                Ok(journal) => journal,
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let action_broker = self.broker.clone();
            let action_tasks = self.tasks.clone();
            #[cfg(test)]
            let admission_probe = self.generic_admission_probe.clone();
            let receive = self.tasks.start_operation(page.identity_scope.clone(), page.targets.clone(), self.broker.clone(), journal.clone(), lease.cancellation.clone(), async move {
                let mut activation_dispatched = false;
                let admission = async {
                  loop {
                    if direct_point {
                        let ledger = page.client.debt_ledger().ok_or(ProtocolError::ScopeUnavailable)?;
                        let check_owner = || {
                            page.permit.check()?;
                            if !ledger.matches_owner(lease.generation, &page.identity_scope)
                                || page.identity_scope != page.targets.identity_scope
                                || journal.key().generation != lease.generation
                                || journal.key().operation_seq != lease.sequence
                                || attachment.session_id != page.page_session_id
                                || !attachment.capture_ready()
                                || !attachment.same_attachment(&page.targets.owned_target(&page.target_id)?)
                            { return Err(ProtocolError::StaleScope); }
                            if !action_broker.check_application_publication(lease.generation)? {
                                return Err(ProtocolError::StaleReference);
                            }
                            Ok(())
                        };
                        // Remote debt remains owned by the older operation. Do
                        // not hold UI/input locks needed by its owner services,
                        // reset this deadline, or infer dispatch from waiting.
                        let waiting = ledger.wait_admission(super::client_debt::AdmissionClass::Input, &lease, &check_owner);
                        #[cfg(test)]
                        let waited = observe_generic_admission_wait(waiting, journal.key(), &admission_probe).await;
                        #[cfg(not(test))]
                        let waited = waiting.await;
                        check_owner()?;
                        waited?;
                    }
                    page.permit.check()?;
                    let ui_permit = ui.enter(false, lease.is_callback, lease.deadline, lease.cancellation.clone()).await?;
                    page.permit.check()?;
                    let mut cancellation = lease.cancellation.clone();
                    if *cancellation.borrow() != super::client_session::CancelSignal::None { return Err(ProtocolError::Cancelled); }
                    #[cfg(test)]
                    let lock = observe_generic_guard_wait(&input_gate, journal.key(), &admission_probe);
                    #[cfg(not(test))]
                    let lock = input_gate.lock();
                    let input_permit = tokio::select! { biased;
                        _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                        guard = tokio::time::timeout_at(lease.deadline.into(), lock) => guard.map_err(|_| ProtocolError::DeadlineExceeded)?,
                    };
                    page.permit.check()?;
                    if !attachment.same_attachment(&page.targets.owned_target(&page.target_id)?) {
                        return Err(ProtocolError::StaleScope);
                    }
                    if !action_broker.check_application_publication(lease.generation)? { return Err(ProtocolError::StaleReference); }
                    action_tasks.check_input_dispatch(journal.key())?;
                    let ledger = page.client.debt_ledger().ok_or(ProtocolError::ScopeUnavailable)?;
                    if let Err(error) = ledger.check_admission(if direct_point { super::client_debt::AdmissionClass::Input } else { super::client_debt::AdmissionClass::Reference }) {
                        if direct_point && error == ProtocolError::ScopeUnavailable {
                            // A new debt may have arrived while acquiring the
                            // guards. Only wait_admission distinguishes pending
                            // debt from retired/poisoned accounting; it rejects
                            // the latter immediately, even after a late ACK.
                            drop(input_permit);
                            drop(ui_permit);
                            continue;
                        }
                        return Err(error);
                    }
                    if !direct_point { observation.check_publication_fence(publication_fence)?; }
                    if command == "recording.start" {
                        super::client_actions::ClientActions::validate_recording_start(&page.identity_scope, &args)?;
                        activation.ensure(&page, &lease, &mut activation_dispatched).await?;
                    }
                    return Ok((ui_permit, input_permit));
                  }
                };
                let admission = if direct_point {
                    // Only pre-dispatch admission is interruptible here. Once
                    // input starts its retained owner still performs cleanup.
                    tokio::select! { biased;
                        _ = enrollment.wait_retired() => Err(ProtocolError::StaleScope),
                        result = admission => result,
                    }
                } else { admission.await };
                let (ui_permit, input_permit) = match admission {
                    Ok(value) => value,
                    Err(error) => { let dirty = error == ProtocolError::CleanupFailed; return (NativeOutcome { retention: None, result: Err(error), effects: if activation_dispatched { Effects::Unknown } else { Effects::NotDispatched } }, dirty); },
                };
                let outcome = if direct_point {
                    // No RefMap, verified_frames, GeometrySnapshot or fabricated
                    // viewport reaches this branch. Guards outlive input cleanup.
                    actions.execute_direct_point(super::client_actions::DirectPointContext {
                        page: &page, operation: &lease, page_state: &page_state, journal: &journal,
                        ui: ui_permit, input: input_permit,
                    }, &args).await
                } else {
                    let _ui = ui_permit;
                    let _input = input_permit;
                    let preflight = async {
                        let super::client_observation_dispatch::VerifiedFrameInventory { frames, iframe_sessions: sessions } = super::client_observation_dispatch::verified_action_frame_inventory(&page, &lease, || {
                            page.permit.check()?;
                            if !attachment.same_attachment(&page.targets.owned_target(&page.target_id)?) { return Err(ProtocolError::StaleScope); }
                            if !action_broker.check_application_publication(lease.generation)? { return Err(ProtocolError::StaleReference); }
                            action_tasks.check_input_dispatch(journal.key())?;
                            observation.check_publication_fence(publication_fence)
                        }).await?;
                        let geometry = super::client_geometry::GeometrySnapshot::capture(&page.client, &page.page_session_id, &frames, &lease).await.map_err(|error| {
                            use super::client_geometry::GeometryError;
                            match error {
                                GeometryError::CleanupFailed { .. } => ProtocolError::CleanupFailed,
                                GeometryError::Cancelled => ProtocolError::Cancelled,
                                GeometryError::DeadlineExceeded => ProtocolError::DeadlineExceeded,
                                GeometryError::StaleIdentity => ProtocolError::StaleScope,
                                _ => ProtocolError::BrowserFailure,
                            }
                        })?;
                        let (revision, refs, observed_revision) = observation.snapshot_with_observation(&lease).await?;
                        observation.check_publication_fence(publication_fence)?;
                        Ok((revision, refs, frames, sessions, geometry, observed_revision))
                    }.await;
                    let (revision, refs, frames, sessions, geometry, observed_revision) = match preflight {
                        Ok(value) => value,
                        Err(error) => { let dirty = error == ProtocolError::CleanupFailed; return (NativeOutcome { retention: None, result: Err(error), effects: if activation_dispatched { Effects::Unknown } else { Effects::NotDispatched } }, dirty); },
                    };
                    actions.execute(super::client_actions::ActionContext { observation_after, observed_revision, page:&page, operation:&lease, page_state:&page_state, refs:&refs, revision, iframe_sessions:&sessions, observation_frames:&frames, blobs:&blobs, geometry:&geometry, realm_authority: super::client_actions::ActionRealmAuthority::Enrolled(&enrollment) }, &command, &args).await
                };
                match outcome {
                    Ok(value) => {
                        if command == "recording.start" { page_active.store(true, std::sync::atomic::Ordering::SeqCst); }
                        (NativeOutcome { retention: None, result: Ok(value), effects: Effects::Completed }, false)
                    },
                    Err(failure) => {
                        if command == "recording.start" && failure.effects != Effects::NotDispatched { page_active.store(true, std::sync::atomic::Ordering::SeqCst); }
                        use super::client_actions::ActionReason;
                        let error = match failure.reason {
                            Some(ActionReason::InterceptedPointer) => ProtocolError::InterceptedPointer,
                            Some(ActionReason::CheckedStateUnchanged) => ProtocolError::CheckedStateUnchanged,
                            Some(ActionReason::ControlReplacedAfterClick) => ProtocolError::CheckedControlReplaced,
                            Some(ActionReason::FillUnsupportedTarget) => ProtocolError::FillUnsupportedTarget,
                            Some(ActionReason::NoEditableFocus) => ProtocolError::NoEditableFocus,
                            _ => failure.error,
                        };
                        (NativeOutcome { retention: None, result: Err(error), effects: if activation_dispatched && failure.effects == Effects::NotDispatched { Effects::Completed } else { failure.effects } }, failure.cleanup_failed)
                    }
                }
            }).await;
            return finish(await_retained(receive).await);
        }
        if command == "state.capture" {
            let captured = async {
                if lease.is_callback {
                    return Err(ProtocolError::InvalidArguments);
                }
                let page = self.page_lease(false).await?;
                if captured_scope.as_deref() != Some(page.identity_scope.as_str()) {
                    return Err(ProtocolError::StaleScope);
                }
                let owner = self.owner.lock().await;
                let owner = owner
                    .as_ref()
                    .filter(|owner| owner.identity_scope == page.identity_scope)
                    .ok_or(ProtocolError::StaleScope)?;
                let runtime = owner
                    .runtime
                    .as_ref()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                Ok((
                    page,
                    owner.page_state.clone(),
                    owner.ui.clone(),
                    runtime.enrollment.clone(),
                    runtime.blobs.clone(),
                    runtime.scope.clone(),
                    if owner.owns_context {
                        super::client_state_dispatch::StateContextKind::Isolated
                    } else {
                        super::client_state_dispatch::StateContextKind::Persistent
                    },
                ))
            }
            .await;
            let (page, page_state, ui, enrollment, blobs, scope, context_kind) = match captured {
                Ok(value) => value,
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let journal = match Self::operation_journal(&page, &lease) {
                Ok(journal) => journal,
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let receive = self
                .tasks
                .start_operation(
                    page.identity_scope.clone(),
                    page.targets.clone(),
                    self.broker.clone(),
                    journal,
                    lease.cancellation.clone(),
                    async move {
                        use super::client_state_dispatch::CapturedStateContext;
                        let admission = async {
                            page.permit.check()?;
                            let permit = ui
                                .enter(true, false, lease.deadline, lease.cancellation.clone())
                                .await?;
                            page.permit.check()?;
                            let attestation = enrollment.attest_capture(&lease).await?;
                            let origins = page_state.visited_origins()?;
                            Ok((permit, attestation, origins))
                        }
                        .await;
                        let (ui_permit, attestation, origins) = match admission {
                            Ok(value) => value,
                            Err(error) => {
                                #[cfg(test)]
                                eprintln!("state.capture phase=pre-attestation error={error:?}");
                                return (
                                    NativeOutcome {
                                        retention: None,
                                        result: Err(error),
                                        effects: Effects::NotDispatched,
                                    },
                                    false,
                                );
                            }
                        };
                        let context = match CapturedStateContext::new(
                            &page,
                            &ui,
                            &ui_permit,
                            super::client_state::NativeStateContext {
                                client: &page.client,
                                context_id: &page.targets.context_id,
                                targets: &page.targets,
                                origins: &origins,
                                origins_complete: true,
                            },
                            context_kind,
                        ) {
                            Ok(context) => context,
                            Err(failure) => {
                                return (
                                    NativeOutcome {
                                        retention: None,
                                        result: Err(failure.error),
                                        effects: Effects::NotDispatched,
                                    },
                                    failure.cleanup_integrity_lost,
                                )
                            }
                        };
                        let exported = super::client_state_dispatch::capture_state(
                            &context, &blobs, &scope, &lease,
                        )
                        .await;
                        #[cfg(test)]
                        if let Err(failure) = &exported {
                            eprintln!("state.capture phase=export error={:?}", failure.error);
                        }
                        match exported {
                            Err(failure) => (
                                NativeOutcome {
                                    retention: None,
                                    result: Err(failure.error),
                                    effects: Effects::NotDispatched,
                                },
                                failure.cleanup_integrity_lost,
                            ),
                            Ok(captured) => {
                                let checked = async {
                                    let verified = enrollment
                                        .verify_capture_attestation(&attestation, &lease)
                                        .await;
                                    #[cfg(test)]
                                    if let Err(error) = &verified {
                                        eprintln!(
                                            "state.capture phase=post-attestation error={error:?}"
                                        );
                                    }
                                    verified?;
                                    if page_state.visited_origins()? != origins {
                                        return Err(ProtocolError::ScopeUnavailable);
                                    }
                                    page.permit.check()?;
                                    serde_json::to_value(&captured)
                                        .map_err(|_| ProtocolError::BrowserFailure)
                                }
                                .await;
                                match checked {
                                    Ok(value) => (
                                        NativeOutcome {
                                            retention: None,
                                            result: Ok(value),
                                            effects: Effects::Completed,
                                        },
                                        false,
                                    ),
                                    Err(error) => {
                                        let cleanup_failed =
                                            blobs.release(&scope, &captured.blob.handle).is_err();
                                        (
                                            NativeOutcome {
                                                retention: None,
                                                result: Err(error),
                                                effects: Effects::NotDispatched,
                                            },
                                            cleanup_failed,
                                        )
                                    }
                                }
                            }
                        }
                    },
                )
                .await;
            return finish(await_retained(receive).await);
        }
        if resource_command {
            // The resource helper owns exact effect classification. In particular,
            // rejected resource validation must not become a fictitious browser
            // mutation, and callback resource reads must not wait on the UI gate.
            let captured = async {
                let page = self.page_lease(lease.is_callback).await?;
                if captured_scope.as_deref() != Some(page.identity_scope.as_str()) {
                    return Err(ProtocolError::StaleScope);
                }
                let owner = self.owner.lock().await;
                let owner = owner.as_ref().ok_or(ProtocolError::StaleScope)?;
                if owner.identity_scope != page.identity_scope {
                    return Err(ProtocolError::StaleScope);
                }
                let runtime = owner
                    .runtime
                    .as_ref()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                Ok((
                    page,
                    runtime.network.clone(),
                    runtime.blobs.clone(),
                    runtime.scope.clone(),
                ))
            }
            .await;
            let (page, network, blobs, scope) = match captured {
                Ok(captured) => captured,
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let broker = self.broker.clone();
            let journal = match Self::operation_journal(&page, &lease) {
                Ok(journal) => journal,
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let receive = self
                .tasks
                .start_operation(
                    page.identity_scope.clone(),
                    page.targets.clone(),
                    self.broker.clone(),
                    journal,
                    lease.cancellation.clone(),
                    async move {
                        if let Err(error) = page.permit.check() {
                            return (
                                NativeOutcome {
                                    retention: None,
                                    result: Err(error),
                                    effects: Effects::NotDispatched,
                                },
                                false,
                            );
                        }
                        let outcome = match super::client_resource_dispatch::execute(
                            super::client_resource_dispatch::ResourceContext {
                                network: &network,
                                blobs: &blobs,
                                scope: &scope,
                                operation: &lease,
                                permit: &page.permit,
                            },
                            &command,
                            &serde_json::Value::Object(args),
                        )
                        .await
                        {
                            Ok(value) => NativeOutcome {
                                retention: None,
                                result: Ok(value),
                                effects: Effects::Completed,
                            },
                            Err(failure) => {
                                if failure.error == ProtocolError::CleanupFailed
                                    || failure.effects == Effects::Unknown
                                {
                                    page.targets.seal();
                                    let _ = broker.quarantine();
                                }
                                NativeOutcome {
                                    retention: None,
                                    result: Err(failure.error),
                                    effects: failure.effects,
                                }
                            }
                        };
                        let cleanup_failed =
                            matches!(outcome.result, Err(ProtocolError::CleanupFailed));
                        (outcome, cleanup_failed)
                    },
                )
                .await;
            return finish(await_retained(receive).await);
        }

        let result = if let Some(request) = prepared {
            self.open(
                request,
                super::client_session::OperationLease {
                    is_callback: lease.is_callback,
                    generation: lease.generation,
                    sequence: lease.sequence,
                    deadline: lease.deadline,
                    cancellation: lease.cancellation.clone(),
                },
            )
            .await
        } else if command == "scope.end" {
            self.end_scope(
                args["identityScope"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                lease.sequence,
            )
            .await
        } else {
            let page = match self.page_lease(lease.is_callback).await {
                Ok(page) if captured_scope.as_deref() == Some(page.identity_scope.as_str()) => page,
                Ok(_) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(ProtocolError::StaleScope),
                        effects: Effects::NotDispatched,
                    })
                }
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let captured = {
                let owner = self.owner.lock().await;
                owner
                    .as_ref()
                    .filter(|owner| owner.identity_scope == page.identity_scope)
                    .and_then(|owner| {
                        owner.runtime.as_ref().map(|runtime| {
                            (
                                owner.page_state.clone(),
                                owner.ui.clone(),
                                runtime.enrollment.config_gate(),
                                runtime.page_active.clone(),
                                runtime.input_gate.clone(),
                                runtime.creation_options.user_agent.clone(),
                                runtime.network.clone(),
                                runtime.enrollment.clone(),
                                runtime.activation.clone(),
                            )
                        })
                    })
            };
            let Some((
                page_state,
                ui,
                config_gate,
                page_active,
                input_gate,
                configured_user_agent,
                network,
                enrollment,
                activation,
            )) = captured
            else {
                return finish(NativeOutcome {
                    retention: None,
                    result: Err(ProtocolError::StaleScope),
                    effects: Effects::NotDispatched,
                });
            };
            let broker = self.broker.clone();
            let dispatch_tasks = self.tasks.clone();
            #[cfg(test)]
            let admission_probe = self.generic_admission_probe.clone();
            let attachment = match page.targets.owned_target(&page.target_id) {
                Ok(attachment) => attachment,
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let journal = match Self::operation_journal(&page, &lease) {
                Ok(journal) => journal,
                Err(error) => {
                    return finish(NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    })
                }
            };
            let receive = self.tasks.start_operation(page.identity_scope.clone(), page.targets.clone(), self.broker.clone(), journal.clone(), lease.cancellation.clone(), async move {
                if let Err(error) = page.permit.check() {
                    return (NativeOutcome { retention: None, result: Err(error), effects: Effects::NotDispatched }, false);
                }
                let mut dispatched = false;
                let mut navigation_interruption = None;
                let result = async {
                        if command != "page.navigate" && command != "page.activate" && command != "session.environment" && !command.starts_with("context.") && !page_active.load(std::sync::atomic::Ordering::SeqCst) {
                            return Err(ProtocolError::ScopeUnavailable);
                        }
                        if command == "page.evaluate" && !lease.is_callback {
                            enrollment.wait_eval_ingress(&page, &lease).await?;
                        }
                        let _ui = ui
                            .enter(
                                false,
                                lease.is_callback,
                                lease.deadline,
                                lease.cancellation.clone(),
                            )
                            .await?;
                        page.permit.check()?;
                        if !broker.check_application_publication(lease.generation)? { return Err(ProtocolError::StaleReference); }
                        // A scope callback is authorized by its exact live native
                        // decision, never by an inferred causal parent or JS purity.
                        let eval_child = if command == "page.evaluate" && lease.is_callback {
                            Some(broker.issue_eval_child(&lease, &page.identity_scope)?)
                        } else { None };
                        let debt = page.client.debt_ledger().ok_or(ProtocolError::ScopeUnavailable)?;
                        let fixed_read = matches!(command.as_str(), "page.title" | "page.url" | "session.environment" | "context.cookies.get");
                        if let Some(permit) = &eval_child {
                            dispatch_tasks.check_eval_dispatch(permit)?;
                            debt.check_eval_input(permit)?;
                        } else if command == "context.media" {
                            // Only an exact same-owner, registered media producer
                            // may justify queuing. Other command mutations retain
                            // the original fast refusal before taking config_gate.
                            if dispatch_tasks.media_dispatch_ready(journal.key())? {
                                debt.check_admission(super::client_debt::AdmissionClass::Input)?;
                            }
                        } else {
                            if !fixed_read { dispatch_tasks.check_input_dispatch(journal.key())?; }
                            debt.check_admission(if fixed_read { super::client_debt::AdmissionClass::FixedRead }
                                else { super::client_debt::AdmissionClass::Input })?;
                        }
                        // Media merges serialize under config_gate. A positively
                        // retained predecessor may still own input until its ACK;
                        // the unchanged admission checks run after this gate.
                        // Enrollment and context changes share only this narrow
                        // configuration boundary; navigation and callback reads
                        // must never hold it while waiting on application work.
                        let _configuration = if matches!(
                            command.as_str(),
                            "context.init-script" | "context.media" | "context.viewport"
                        ) {
                            let mut cancellation = lease.cancellation.clone();
                            if *cancellation.borrow() != super::client_session::CancelSignal::None {
                                return Err(ProtocolError::Cancelled);
                            }
                            #[cfg(not(test))]
                            let guard = config_gate.lock();
                            #[cfg(test)]
                            let guard = observe_generic_guard_wait(&config_gate, journal.key(), &admission_probe);
                            Some(tokio::select! {
                                biased;
                                _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                                result = tokio::time::timeout_at(lease.deadline.into(), guard) =>
                                    result.map_err(|_| ProtocolError::DeadlineExceeded)?,
                            })
                        } else {
                            None
                        };
                        page.permit.check()?;
                        let _input = if matches!(command.as_str(), "input.keyboard" | "input.mouse") {
                            let mut cancellation = lease.cancellation.clone();
                            if *cancellation.borrow() != super::client_session::CancelSignal::None { return Err(ProtocolError::Cancelled); }
                            #[cfg(not(test))]
                            let guard = input_gate.lock();
                            #[cfg(test)]
                            let guard = observe_generic_guard_wait(&input_gate, journal.key(), &admission_probe);
                            Some(tokio::select! {
                                biased;
                                _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                                guard = tokio::time::timeout_at(lease.deadline.into(), guard) => guard.map_err(|_| ProtocolError::DeadlineExceeded)?,
                            })
                        } else { None };
                        // The prior media producer releases config_gate before
                        // its retained supervisor finishes result classification.
                        // Wait only for that positively retained completion, not
                        // an Unknown retirement, and never renew this lease.
                        if command == "context.media" {
                            dispatch_tasks.wait_media_dispatch(&lease).await?;
                        }
                        // Admission before a mutex wait is not dispatch authority.
                        // Cleanup can retain debt or retire publication while this
                        // command waits for the configuration/input guard.
                        page.permit.check()?;
                        if !attachment.same_attachment(&page.targets.owned_target(&page.target_id)?) {
                            return Err(ProtocolError::StaleScope);
                        }
                        if !broker.check_application_publication(lease.generation)? { return Err(ProtocolError::StaleReference); }
                        if let Some(permit) = &eval_child {
                            dispatch_tasks.check_eval_dispatch(permit)?;
                            debt.check_eval_input(permit)?;
                        } else {
                            if !fixed_read { dispatch_tasks.check_input_dispatch(journal.key())?; }
                            debt.check_admission(if fixed_read { super::client_debt::AdmissionClass::FixedRead }
                                else { super::client_debt::AdmissionClass::Input })?;
                        }
                        if command == "context.media" {
                            // Closed native kind proof for this exact registered
                            // journal; only this real serialized path can mint it.
                            dispatch_tasks.mark_media_dispatch(&journal)?;
                        }
                        if command == "session.environment" {
                            return environment_facts(&page, &lease, configured_user_agent.as_deref()).await;
                        }
                        if command == "page.activate" {
                            // Provider recording needs original ensurePage semantics without
                            // starting the native encoder or navigating an already active page.
                            let activated = activation.ensure(&page, &lease, &mut dispatched).await;
                            #[cfg(test)]
                            page.client.activation_diagnostic("ensure-result", None, if activated.is_ok() { "ok" } else { "failed" }, activated.as_ref().err(), None);
                            activated?;
                            page.permit.check()?;
                            check_lifecycle_budget(&lease)?;
                            page_active.store(true, std::sync::atomic::Ordering::SeqCst);
                            dispatched = true;
                            return Ok(serde_json::json!({"activated": true}));
                        }
                        let attachments = page
                            .targets
                            .inventory()?
                            .1
                            .into_iter()
                            .filter(|target| {
                                target.purpose
                                    == Some(super::client_targets::TargetPurpose::Application)
                                    && matches!(target.kind.as_str(), "page" | "iframe")
                            })
                            .collect::<Vec<_>>();
                        let sessions = attachments.iter().map(|target| target.session_id.clone()).collect::<Vec<_>>();
                        if command == "page.navigate" {
                            super::client_page::ClientPageState::validate_navigation(&serde_json::Value::Object(args.clone()))?;
                            activation.ensure(&page, &lease, &mut dispatched).await?;
                        }
                        // The same native primitive implements both direct API
                        // dispatch and callback child execution; no second JS reader.
                        if command == "page.navigate" { page_active.store(true, std::sync::atomic::Ordering::SeqCst); }
                        let navigation = if matches!(command.as_str(), "page.navigate" | "page.back" | "page.forward" | "page.reload") {
                            Some(network.begin_app_navigation(&page, &lease)?)
                        } else { None };
                        // Prepare only after both original gates. The registry
                        // installs a provisional final-submit fence while checking
                        // existing journals; broker binding then revalidates admission.
                        let eval_grant = if command == "page.evaluate" {
                            Some(if let Some(permit) = eval_child {
                                super::client_debt::EvalCommandGrant::Child(permit)
                            } else {
                                let stamp = enrollment.capture_eval_authority(&page, &lease)?;
                                let window = dispatch_tasks.prepare_eval_window(&journal, &lease, stamp)?;
                                if let Err(error) = broker.bind_eval_root(&lease, &window) {
                                    debt.abandon_eval_preparation(&window);
                                    return Err(error);
                                }
                                super::client_debt::EvalCommandGrant::Root(window)
                            })
                        } else { None };
                        dispatched = true;
                        let arguments = serde_json::Value::Object(args);
                        let execution = async {
                            if command == "context.media" {
                                (page_state.execute_media_with_owner(
                                    &page, &lease, &arguments, &enrollment, &attachments,
                                ).await, None)
                            } else {
                                page_state.execute_with_retirement(
                                    &page, &sessions, &lease, &command, &arguments, &dispatch_tasks,
                                ).await
                            }
                        };
                        let (output, interruption) = if let Some(grant) = eval_grant {
                            super::client_debt::eval_command_scope(grant, execution).await
                        } else { execution.await };
                        navigation_interruption = interruption;
                        if navigation.is_some() {
                            let flushed = enrollment.flush_app_events(&page, &lease).await;
                            if output.is_ok() { flushed?; }
                        }
                        drop(navigation);
                        output
                }.await;
                let cleanup_failed = matches!(result, Err(ProtocolError::CleanupFailed));
                if std::time::Instant::now() >= lease.deadline {
                    let _ = broker.expire(lease.generation, lease.sequence);
                }
                let interruption = (*lease.cancellation.borrow()).error();
                let expired = interruption.is_some()
                    || std::time::Instant::now() >= lease.deadline;
                let navigation_settled = command == "page.navigate"
                    && matches!(result, Err(ProtocolError::Cancelled | ProtocolError::DeadlineExceeded))
                    && navigation_interruption.is_some_and(|proof| proof.confirms(&page, &lease, &journal));
                let effects = if !dispatched || matches!(result, Err(ProtocolError::InvalidArguments | ProtocolError::UnsupportedCommand)) {
                    Effects::NotDispatched
                } else if navigation_settled {
                    Effects::Completed
                } else if expired || (result.is_err() && mutating) {
                    Effects::Unknown
                } else { Effects::Completed };
                // Only interruption/success outcomes are normalized. Lost
                // authority and cleanup failures must not become usable timeout
                // results merely because a deadline also elapsed.
                let result = match (&result, interruption) {
                    (Ok(_) | Err(ProtocolError::Cancelled | ProtocolError::DeadlineExceeded), Some(reason))
                        if !navigation_settled => Err(reason),
                    _ => result,
                };
                (NativeOutcome { retention: None, result, effects }, cleanup_failed)
            }).await;
            return finish(await_retained(receive).await);
        };

        if *lease.cancellation.borrow() != super::client_session::CancelSignal::None
            || std::time::Instant::now() >= lease.deadline
        {
            let _ = self.broker.quarantine();
            return finish(NativeOutcome {
                retention: None,
                result: Err(ProtocolError::Cancelled),
                effects: Effects::Unknown,
            });
        }
        let effects = if matches!(
            result,
            Err(ProtocolError::InvalidArguments | ProtocolError::UnsupportedCommand)
        ) {
            Effects::NotDispatched
        } else if result.is_err() && mutating {
            let _ = self.broker.quarantine();
            Effects::Unknown
        } else {
            Effects::Completed
        };
        finish(NativeOutcome {
            retention: None,
            result,
            effects,
        })
    }

    async fn shutdown(&self) -> Result<(), ProtocolError> {
        // Transport takes a negotiated frozen batch before shutdown begins.
        // Any unclaimed batch has no consumer and must release its old charge.
        let mut terminal_recording_failed = match self.terminal_recording.lock() {
            Ok(mut batch) => {
                batch.take();
                false
            }
            Err(_) => true,
        };
        let stop_failed = self.stop_enrollment(true).is_err();
        self.gate.seal();
        let mut startup = self.startup_task.lock().await;
        let supervisor_failed = match startup.as_mut() {
            Some(task) => task.await.is_err(),
            None => false,
        };
        *startup = None;
        drop(startup);
        // Close/EOF may beat a retained failed transition's result. That
        // producer can freeze after the entry clear while shutdown joins it.
        // Once joined, no late batch may outlive a successful cleanup receipt.
        terminal_recording_failed |= match self.terminal_recording.lock() {
            Ok(mut batch) => {
                batch.take();
                false
            }
            Err(_) => true,
        };
        let _lifecycle = self.lifecycle.lock().await;
        let drain_failed = self.gate.drained().await.is_err();
        self.tasks.seal().await;
        let task_cleanup_failed = self.tasks.drain_current().await.is_err();
        // Keep both journals in owner storage across cancellation or failed
        // final cleanup. A local take would drop unresolved retained resources.
        let mut owner = self.owner.lock().await;
        let terminal_operations = if task_cleanup_failed {
            match owner
                .as_ref()
                .and_then(|owner| owner.manager.client.debt_ledger())
            {
                Some(ledger) => {
                    let prepared = self.tasks.prepare_terminal_read_only(&ledger).await;
                    cleanup_trace::terminal_cleanup_checkpoint(
                        TerminalCleanupStage::TaskProof,
                        prepared.is_ok(),
                    );
                    prepared.ok()
                }
                None => None,
            }
        } else {
            None
        };
        let mut terminal = None;
        let cleaned = match (owner.as_mut(), terminal_operations.as_ref()) {
            (Some(owner), Some(operations)) => {
                match owner.close_terminal_read_only(operations).await {
                    Ok(proof) => {
                        terminal = Some(proof);
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            (Some(owner), None) => {
                let closed = owner.close().await;
                cleanup_trace::terminal_cleanup_checkpoint(
                    TerminalCleanupStage::OrdinaryClose,
                    closed.is_ok(),
                );
                closed
            }
            (None, _) => Ok(()),
        };
        if cleaned.is_ok() && terminal.is_none() {
            *owner = None;
        }
        drop(owner);
        let mut retained = self.retained_browser.lock().await;
        let retained_failed = match retained.as_mut() {
            Some(manager) => manager.close().await.is_err(),
            None => false,
        };
        if !retained_failed {
            *retained = None;
        }
        drop(retained);
        // This task only watches native connection evidence and publishes an
        // event. Stopping it never abandons CDP/resource cleanup. Retain the
        // handle until its cancellation has settled.
        let mut connection_watch = self.connection_watch.lock().await;
        let watch_failed = match connection_watch.as_mut() {
            Some(task) => {
                task.abort();
                match task.await {
                    Ok(result) => result.is_err(),
                    Err(error) => !error.is_cancelled(),
                }
            }
            None => false,
        };
        *connection_watch = None;
        if supervisor_failed
            || terminal_recording_failed
            || stop_failed
            || watch_failed
            || drain_failed
            || (task_cleanup_failed && terminal.is_none())
            || retained_failed
            || self
                .startup_uncertain
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            cleanup_trace::terminal_cleanup_checkpoint(TerminalCleanupStage::ShutdownJoins, false);
            return Err(ProtocolError::CleanupFailed);
        }
        cleanup_trace::terminal_cleanup_checkpoint(TerminalCleanupStage::ShutdownJoins, true);
        cleaned?;
        if let Some(proof) = terminal {
            let committed = self.tasks.commit_terminal_read_only(proof);
            cleanup_trace::terminal_cleanup_checkpoint(
                TerminalCleanupStage::FinalCommit,
                committed.is_ok(),
            );
            committed?;
            *self.owner.lock().await = None;
        }
        Ok(())
    }
}

/// Native metadata read on the captured connection, without page source or secrets.
async fn environment_facts(
    page: &BrowserExecutionLease,
    operation: &super::client_session::OperationLease,
    configured_user_agent: Option<&str>,
) -> Result<serde_json::Value, ProtocolError> {
    page.permit.check()?;
    let mut cancellation = operation.cancellation.clone();
    if *cancellation.borrow() != super::client_session::CancelSignal::None {
        return Err(ProtocolError::Cancelled);
    }
    if std::time::Instant::now() >= operation.deadline {
        return Err(ProtocolError::DeadlineExceeded);
    }
    let value = tokio::select! {
        biased;
        _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
        value = tokio::time::timeout_at(operation.deadline.into(), page.client.send_command("Browser.getVersion", None, None)) =>
            value.map_err(|_| ProtocolError::DeadlineExceeded)?.map_err(|_| ProtocolError::BrowserFailure)?,
    };
    page.permit.check()?;
    let browser = value
        .get("product")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 1024)
        .ok_or(ProtocolError::BrowserFailure)?;
    let user_agent = configured_user_agent
        .or_else(|| value.get("userAgent").and_then(serde_json::Value::as_str));
    if user_agent.is_some_and(|value| value.len() > 16 * 1024) {
        return Err(ProtocolError::CapacityExceeded);
    }
    let mut result = serde_json::json!({"identityScope": page.identity_scope, "browser": browser});
    if let Some(user_agent) = user_agent {
        result["userAgent"] = user_agent.into();
    }
    Ok(result)
}

async fn await_retained(
    receiver: Result<
        tokio::sync::oneshot::Receiver<super::client_transport::NativeOutcome>,
        ProtocolError,
    >,
) -> super::client_transport::NativeOutcome {
    use super::client_protocol::Effects;
    use super::client_transport::NativeOutcome;
    match receiver {
        Ok(receiver) => receiver.await.unwrap_or(NativeOutcome {
            retention: None,
            result: Err(ProtocolError::CleanupFailed),
            effects: Effects::Unknown,
        }),
        Err(error) => NativeOutcome {
            retention: None,
            result: Err(error),
            effects: Effects::NotDispatched,
        },
    }
}

impl ClientBrowser {
    /// Reopen only a proven-closed persistent application root. This runs before
    /// dispatch of the caller's command, never as a retry after a command error.
    async fn ensure_persistent_page(
        &self,
        scope: &str,
        operation: &super::client_session::OperationLease,
    ) -> super::client_transport::NativeOutcome {
        use super::client_protocol::Effects;
        use super::client_transport::NativeOutcome;
        let captured = async {
            let (candidate, enrollment) = {
                let owner = self.owner.lock().await;
                let owner = owner.as_ref().ok_or(ProtocolError::StaleScope)?;
                if owner.identity_scope != scope { return Err(ProtocolError::StaleScope); }
                if owner.owns_context || owner.borrowed_targets.is_none() { return Ok(None); }
                let runtime = owner.runtime.as_ref().ok_or(ProtocolError::ScopeUnavailable)?;
                (owner.lease(self.gate.enter(operation.is_callback)?)?, runtime.enrollment.clone())
            };
            if !enrollment.persistent_reopen_candidate(&candidate, operation).await? { return Ok(None); }
            if operation.is_callback { return Err(ProtocolError::StaleReference); }
            if !self.event_sink.get().is_some_and(|sink| sink.persistent_page_reopen_negotiated()) {
                return Err(ProtocolError::UnsupportedCapability);
            }
            drop(candidate);
            let mut cancellation = operation.cancellation.clone();
            check_lifecycle_budget(operation)?;
            let transition = tokio::select! {
                biased;
                _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                result = tokio::time::timeout_at(operation.deadline.into(), self.lifecycle.clone().lock_owned()) => result.map_err(|_| ProtocolError::DeadlineExceeded)?,
            };
            let owner = self.owner.lock().await;
            let owner = owner.as_ref().ok_or(ProtocolError::StaleScope)?;
            if owner.identity_scope != scope || owner.owns_context || owner.borrowed_targets.is_none() { return Err(ProtocolError::StaleScope); }
            let runtime = owner.runtime.as_ref().ok_or(ProtocolError::ScopeUnavailable)?;
            let page = owner.lease(self.gate.enter(false)?)?;
            Ok(Some((transition, page, owner.ui.clone(), owner.page_state.clone(), runtime.enrollment.clone(), runtime.actions.clone(), runtime.input_gate.clone(), runtime.blobs.clone(), runtime.page_active.clone())))
        }.await;
        let (transition, page, ui, page_state, enrollment, actions, input_gate, blobs, active) =
            match captured {
                Ok(Some(value)) => value,
                Ok(None) => {
                    return NativeOutcome {
                        retention: None,
                        result: Ok(serde_json::json!({"reopened":false})),
                        effects: Effects::NotDispatched,
                    }
                }
                Err(error) => {
                    return NativeOutcome {
                        retention: None,
                        result: Err(error),
                        effects: Effects::NotDispatched,
                    }
                }
            };
        let scope = scope.to_owned();
        let operation = super::client_session::OperationLease {
            is_callback: operation.is_callback,
            generation: operation.generation,
            sequence: operation.sequence,
            deadline: operation.deadline,
            cancellation: operation.cancellation.clone(),
        };
        let owner = self.owner.clone();
        let gate = self.gate.clone();
        let refs = self.refs.clone();
        let observation = self.observation.clone();
        let tasks = self.tasks.clone();
        let targets = page.targets.clone();
        let event_sink = match self.event_sink.get().cloned() {
            Some(sink) => sink,
            None => {
                return NativeOutcome {
                    retention: None,
                    result: Err(ProtocolError::ScopeUnavailable),
                    effects: Effects::NotDispatched,
                }
            }
        };
        let receive = self.tasks.start(scope.clone(), targets.clone(), async move {
            let _transition = transition;
            let mut effects = false;
            let result = async {
                let exclusive = ui.enter(true, false, operation.deadline, operation.cancellation.clone()).await?;
                let mut cancellation = operation.cancellation.clone();
                check_lifecycle_budget(&operation)?;
                let _input = tokio::select! {
                    biased;
                    _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                    result = tokio::time::timeout_at(operation.deadline.into(), input_gate.lock()) => result.map_err(|_| ProtocolError::DeadlineExceeded)?,
                };
                page.permit.check()?;
                // The preceding waiter may have shared an already-completed
                // reopen. Do not create a second page for concurrent callers.
                if !enrollment.persistent_page_detached(&page, &operation).await? {
                    return Ok(serde_json::json!({"reopened":false}));
                }
                let key = super::client_debt::OperationKey { generation: operation.generation, operation_seq: operation.sequence };
                tasks.check_input_dispatch(key)?;
                page.client.debt_ledger().ok_or(ProtocolError::ScopeUnavailable)?.check_admission(super::client_debt::AdmissionClass::Input)?;
                let staged = event_sink.stage_until_result(&operation, &scope)?;
                let context = super::client_restart::RestartContext::new_persistent_reopen(&page, &enrollment, &ui, &exclusive, &operation).await?.with_staged_sink(staged.clone());
                // Exact detach has already cleared this session's held input;
                // never send release keys to a detached/replacement session.
                actions.recording_page_closing(&scope, &blobs).await?;
                observation.retire_page_publication(&blobs, &super::client_blobs::BlobScope { generation: operation.generation, identity_scope: scope.clone() }).await?;
                let observation_after = observation.snapshot_for_action(&operation).await?.0;
                refs.lock().map_err(|_| ProtocolError::ScopeUnavailable)?.retire_owner_references();
                let replacement = super::client_restart::reopen_closed_page(&context).await.map_err(|failure| {
                    effects |= failure.effects_started;
                    failure.error
                })?;
                effects = true;
                replacement.validate(&context)?;
                actions.cleanup_scope_uploads().await?;
                let (next, previous_identity, recovery_identity) = {
                    let mut owner = owner.lock().await;
                    let owner = owner.as_mut().ok_or(ProtocolError::StaleScope)?;
                    if owner.identity_scope != scope || !Arc::ptr_eq(&owner.targets, &targets)
                        || owner.manager.active_target_id().ok() != Some(page.target_id.as_str())
                        || owner.manager.active_session_id().ok() != Some(page.page_session_id.as_str()) { return Err(ProtocolError::StaleScope); }
                    replacement.validate(&context)?;
                    let previous_identity = owner.recovery_identity();
                    owner.manager.forget_disposed_targets(&std::iter::once(page.target_id.clone()).collect());
                    owner.manager.register_discovered_page(&replacement.target_id, &replacement.session_id, "about:blank".into(), String::new(), "page".into());
                    if !owner.manager.restore_target_binding(&replacement.target_id, "about:blank") || owner.manager.active_session_id().ok() != Some(replacement.session_id.as_str()) { return Err(ProtocolError::StaleScope); }
                    owner.borrowed_targets = Some(vec![replacement.target_id.clone()]);
                    owner.runtime.as_mut().ok_or(ProtocolError::ScopeUnavailable)?.observation_after = Some(observation_after);
                    (owner.lease(gate.enter(false)?)?, previous_identity, owner.recovery_identity())
                };
                replacement.publish_ready(&context, || next.permit.check()).await?;
                if actions.is_recording_armed().await? {
                    let super::client_observation_dispatch::VerifiedFrameInventory { frames, iframe_sessions: sessions } = super::client_observation_dispatch::verified_frame_inventory(&next, &operation).await?;
                    let geometry = super::client_geometry::GeometrySnapshot::capture(&next.client, &next.page_session_id, &frames, &operation).await.map_err(|_| ProtocolError::BrowserFailure)?;
                    let (revision, references) = observation.snapshot_for_action(&operation).await?;
                    actions.recording_page_opened(super::client_actions::ActionContext { observation_after: None, observed_revision: 0, page: &next, operation: &operation, page_state: &page_state, refs: &references, revision, iframe_sessions: &sessions, observation_frames: &frames, blobs: &blobs, geometry: &geometry, realm_authority: super::client_actions::ActionRealmAuthority::Enrolled(&enrollment) }).await.map_err(|failure| failure.error)?;
                }
                replacement.publish_reopened_ready(&context, |proof| {
                    next.permit.check()?;
                    staged.confirm_reopened_result(&event_sink, &operation, proof)?;
                    // Queue the exact-owner refresh before the operation result,
                    // not behind its result-staged application events.
                    event_sink.emit("scope.page-reopened".into(), serde_json::json!({
                        "version": 1, "identityScope": scope,
                        "previousPageIdentity": previous_identity["page"],
                        "recoveryIdentity": recovery_identity,
                    }), None)?;
                    active.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(serde_json::json!({"reopened":true}))
                }).await
            }.await;
            let dirty = effects && result.is_err() || matches!(result, Err(ProtocolError::CleanupFailed));
            if dirty { targets.seal(); }
            let effect = if result.is_ok() { Effects::Completed } else if effects { Effects::Unknown } else { Effects::NotDispatched };
            (NativeOutcome { retention: None, result, effects: effect }, dirty)
        }).await;
        await_retained(receive).await
    }

    async fn restart_pages(
        &self,
        scope: String,
        operation: super::client_session::OperationLease,
    ) -> super::client_transport::NativeOutcome {
        use super::client_protocol::Effects;
        use super::client_transport::NativeOutcome;
        let captured = async {
            if operation.is_callback { return Err(ProtocolError::InvalidArguments); }
            let mut cancellation = operation.cancellation.clone();
            if *cancellation.borrow() != super::client_session::CancelSignal::None { return Err(ProtocolError::Cancelled); }
            let transition = tokio::select! {
                biased;
                _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                result = tokio::time::timeout_at(operation.deadline.into(), self.lifecycle.clone().lock_owned()) => result.map_err(|_| ProtocolError::DeadlineExceeded)?,
            };
            let page = self.page_lease(false).await?;
            if page.identity_scope != scope { return Err(ProtocolError::StaleScope); }
            let owner = self.owner.lock().await;
            let owner = owner.as_ref().ok_or(ProtocolError::StaleScope)?;
            if owner.identity_scope != scope { return Err(ProtocolError::StaleScope); }
            if !owner.owns_context && owner.borrowed_targets.is_none() { return Err(ProtocolError::UnsupportedCapability); }
            let runtime = owner.runtime.as_ref().ok_or(ProtocolError::ScopeUnavailable)?;
            Ok((transition, page, owner.ui.clone(), owner.page_state.clone(), runtime.enrollment.clone(), runtime.actions.clone(), runtime.input_gate.clone(), runtime.blobs.clone(), runtime.page_active.clone(), !owner.owns_context))
        }.await;
        let (
            transition,
            page,
            ui,
            page_state,
            enrollment,
            actions,
            input_gate,
            blobs,
            active,
            borrowed,
        ) = match captured {
            Ok(value) => value,
            Err(error) => {
                return NativeOutcome {
                    retention: None,
                    result: Err(error),
                    effects: Effects::NotDispatched,
                }
            }
        };
        let owner = self.owner.clone();
        let gate = self.gate.clone();
        let refs = self.refs.clone();
        let observation = self.observation.clone();
        let targets = page.targets.clone();
        let event_sink = match self.event_sink.get().cloned() {
            Some(sink) => sink,
            None => {
                return NativeOutcome {
                    retention: None,
                    result: Err(ProtocolError::ScopeUnavailable),
                    effects: Effects::NotDispatched,
                }
            }
        };
        let diagnostics = page.client.cleanup_diagnostics();
        let diagnostic_attempt = diagnostics.as_ref().and_then(|cell| {
            cell.begin(cleanup_trace::CleanupLifecycle::Restart, operation.sequence)
        });
        let diagnostics = diagnostic_attempt
            .as_ref()
            .map(|attempt| attempt.observer());
        let receive = self.tasks.start(scope.clone(), targets.clone(), async move {
            let _transition = transition;
            let mut effects = false;
            let mut dirty = false;
            let result = async {
                page.permit.check()?;
                let exclusive = ui.enter(true, false, operation.deadline, operation.cancellation.clone()).await?;
                let mut cancellation = operation.cancellation.clone();
                if *cancellation.borrow() != super::client_session::CancelSignal::None { return Err(ProtocolError::Cancelled); }
                let _input = tokio::select! {
                    biased;
                    _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                    result = tokio::time::timeout_at(operation.deadline.into(), input_gate.lock()) => result.map_err(|_| ProtocolError::DeadlineExceeded)?,
                };
                page.permit.check()?;
                let staged = event_sink.stage_until_result(&operation, &scope)?;
                let context = if borrowed {
                    super::client_restart::RestartContext::new_persistent(&page, &enrollment, &ui, &exclusive, &operation)?
                } else {
                    super::client_restart::RestartContext::new(&page, &enrollment, &ui, &exclusive, &operation)?
                }.with_staged_sink(staged);
                // Capture/encoder resources settle before any old page closes.
                effects = true;
                page_state.release_input(&page).await.inspect_err(|_| { dirty = true; if let Some(cell) = &diagnostics { cell.failure(CleanupPart::Input); } })?;
                actions.recording_page_closing(&scope, &blobs).await.inspect_err(|_| { dirty = true; if let Some(cell) = &diagnostics { cell.failure(CleanupPart::Recording); } })?;
                refs.lock().map_err(|_| ProtocolError::ScopeUnavailable)?.retire_owner_references();
                let replacement = super::client_restart::replace_pages(&context).await.map_err(|failure| {
                    if failure.cleanup_integrity_lost {
                        if let Some(cell) = &diagnostics { cell.failure(CleanupPart::OwnerFallback); }
                    }
                    dirty |= failure.cleanup_integrity_lost || failure.effects_started;
                    failure.error
                })?;
                replacement.validate(&context)?;
                actions.cleanup_scope_uploads().await.inspect_err(|_| { dirty = true; if let Some(cell) = &diagnostics { cell.failure(CleanupPart::Upload); } })?;
                let (next, recovery_identity) = {
                    let mut owner = owner.lock().await;
                    let owner = owner.as_mut().ok_or(ProtocolError::StaleScope)?;
                    if owner.identity_scope != scope || !Arc::ptr_eq(&owner.targets, &targets) { return Err(ProtocolError::StaleScope); }
                    replacement.validate(&context)?;
                    owner.manager.forget_disposed_targets(&replacement.closed_targets.iter().cloned().collect());
                    owner.manager.register_discovered_page(&replacement.target_id, &replacement.session_id, "about:blank".into(), String::new(), "page".into());
                    if !owner.manager.restore_target_binding(&replacement.target_id, "about:blank") || owner.manager.active_session_id().ok() != Some(replacement.session_id.as_str()) { return Err(ProtocolError::StaleScope); }
                    if borrowed { owner.borrowed_targets = Some(vec![replacement.target_id.clone()]); }
                    (owner.lease(gate.enter(false)?)?, owner.recovery_identity())
                };
                replacement.publish_ready(&context, || next.permit.check()).await?;
                if cleanup_trace::inventory_enabled() {
                    cleanup_trace::inventory_snapshot(operation.generation, operation.sequence,
                        cleanup_trace::InventoryPoint::RestartReady, next.targets.inventory_diagnostic());
                }
                if actions.is_recording_armed().await? {
                    let super::client_observation_dispatch::VerifiedFrameInventory { frames, iframe_sessions: sessions } = super::client_observation_dispatch::verified_frame_inventory(&next, &operation).await?;
                    let geometry = super::client_geometry::GeometrySnapshot::capture(&next.client, &next.page_session_id, &frames, &operation).await.map_err(|_| ProtocolError::BrowserFailure)?;
                    let (revision, references) = observation.snapshot_for_action(&operation).await?;
                    actions.recording_page_opened(super::client_actions::ActionContext { observation_after: None, observed_revision: 0, page:&next, operation:&operation, page_state:&page_state, refs:&references, revision, iframe_sessions:&sessions, observation_frames:&frames, blobs:&blobs, geometry:&geometry, realm_authority: super::client_actions::ActionRealmAuthority::Enrolled(&enrollment) }).await.map_err(|failure| { dirty |= failure.cleanup_failed; failure.error })?;
                }
                replacement.publish_ready(&context, || {
                    next.permit.check()?;
                    active.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(serde_json::json!({"identityScope":scope,"recoveryIdentity":recovery_identity}))
                }).await
            }.await;
            // Any failed destructive restart cannot be replayed against its new
            // page. Retain the original context for normal lifecycle containment.
            dirty |= effects && result.is_err();
            if dirty { targets.seal(); }
            let effect = if result.is_ok() { Effects::Completed } else if effects { Effects::Unknown } else { Effects::NotDispatched };
            (NativeOutcome { retention: None, result, effects:effect }, dirty)
        }).await;
        let outcome = await_retained(receive).await;
        if let Some(attempt) = diagnostic_attempt {
            attempt.finish(&outcome.result);
        }
        outcome
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReconnectRequest {
    endpoint: String,
    expected_browser_identity: String,
    expected_context_identity: String,
    expected_page_identity: String,
}
fn check_lifecycle_budget(
    operation: &super::client_session::OperationLease,
) -> Result<(), ProtocolError> {
    if *operation.cancellation.borrow() != super::client_session::CancelSignal::None {
        return Err(ProtocolError::Cancelled);
    }
    if std::time::Instant::now() >= operation.deadline {
        return Err(ProtocolError::DeadlineExceeded);
    }
    Ok(())
}
impl ClientBrowser {
    async fn replace_scope(
        &self,
        scope: String,
        restore: Option<serde_json::Value>,
        operation: super::client_session::OperationLease,
    ) -> super::client_transport::NativeOutcome {
        use super::client_protocol::Effects;
        use super::client_transport::NativeOutcome;
        if operation.is_callback {
            return NativeOutcome {
                retention: None,
                result: Err(ProtocolError::InvalidArguments),
                effects: Effects::NotDispatched,
            };
        }
        let mut cancellation = operation.cancellation.clone();
        if let Err(error) = check_lifecycle_budget(&operation) {
            return NativeOutcome {
                retention: None,
                result: Err(error),
                effects: Effects::NotDispatched,
            };
        }
        let transition = tokio::select! {
            biased;
            _ = cancellation.changed() => return NativeOutcome { retention: None, result:Err(ProtocolError::Cancelled), effects:Effects::NotDispatched },
            value = tokio::time::timeout_at(operation.deadline.into(), self.lifecycle.clone().lock_owned()) => match value {
                Ok(value) => value,
                Err(_) => return NativeOutcome { retention: None, result:Err(ProtocolError::DeadlineExceeded), effects:Effects::NotDispatched },
            },
        };
        let mut slot = self.startup_task.lock().await;
        let owner = self.owner.clone();
        let terminal_recording = self.terminal_recording.clone();
        let gate = self.gate.clone();
        let broker = self.broker.clone();
        let retirement = self.retirement.clone();
        let blobs = self.blobs.clone();
        let refs = self.refs.clone();
        let tasks = self.tasks.clone();
        let observation = self.observation.clone();
        let uncertain = self.startup_uncertain.clone();
        let connection_watch = self.connection_watch.clone();
        let Some(sink) = self.event_sink.get().cloned() else {
            return NativeOutcome {
                retention: None,
                result: Err(ProtocolError::ScopeUnavailable),
                effects: Effects::NotDispatched,
            };
        };
        #[cfg(feature = "acceptance-faults")]
        let faults = self.faults.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        *slot = Some(tokio::spawn(async move {
            let _transition = transition;
            let mut accepted = false;
            let mut recording_owner = None;
            let result = async {
                check_lifecycle_budget(&operation)?;
                // The resource never leaves this journal, including partial new
                // context creation and failed initialization/import.
                let mut journal = owner.lock().await;
                let resource = journal.as_mut().ok_or(ProtocolError::StaleScope)?;
                if resource.identity_scope != scope {
                    return Err(ProtocolError::StaleScope);
                }
                if !resource.owns_context {
                    return Err(ProtocolError::UnsupportedCapability);
                }
                let runtime = resource
                    .runtime
                    .as_ref()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                let options = runtime.creation_options.clone();
                let actions = runtime.actions.clone();
                recording_owner = Some(actions.clone());
                let (policy, downloads) = {
                    let configuration = runtime
                        .configuration
                        .lock()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?;
                    (
                        configuration
                            .policy
                            .clone()
                            .ok_or(ProtocolError::ScopeUnavailable)?,
                        configuration
                            .downloads
                            .clone()
                            .ok_or(ProtocolError::ScopeUnavailable)?,
                    )
                };
                let prepared = restore
                    .as_ref()
                    .map(|args| {
                        super::client_state_dispatch::prepare_restore(
                            &blobs,
                            &runtime.scope,
                            args,
                            &operation,
                        )
                    })
                    .transpose()
                    .map_err(|failure| failure.error)?;
                if resource.replacement_routes.is_some() {
                    return Err(ProtocolError::CleanupFailed);
                }
                resource.replacement_routes =
                    Some(runtime.network.capture_route_transfer(&operation)?);
                // Registry capture is acceptance; retain it before stop can
                // independently drain/revoke the old native network owner.
                accepted = true;
                uncertain.store(true, std::sync::atomic::Ordering::SeqCst);
                let state = prepared
                    .map(|prepared| prepared.accept(&operation))
                    .transpose()
                    .map_err(|failure| failure.error)?;
                retirement
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .stop(false);
                #[cfg(feature = "acceptance-faults")]
                faults.retire_scope(&scope)?;
                {
                    let mut watch = connection_watch.lock().await;
                    if let Some(old) = watch.as_mut() {
                        old.abort();
                        if let Err(error) = old.await {
                            if !error.is_cancelled() {
                                return Err(ProtocolError::CleanupFailed);
                            }
                        }
                    }
                    *watch = None;
                }
                gate.begin_transition()?;
                // Owner mutex cannot remain held while admitted operations are
                // finishing their captured ownership checks.
                drop(journal);
                gate.drained().await?;
                tasks.drain_current().await?;
                let mut journal = owner.lock().await;
                let resource = journal.as_mut().ok_or(ProtocolError::StaleScope)?;
                if resource.identity_scope != scope {
                    return Err(ProtocolError::StaleScope);
                }
                let page_config = resource.page_state.snapshot_config(&scope)?;
                let was_recording = actions.is_recording_armed().await?;
                resource.ui.seal();
                let runtime = resource
                    .runtime
                    .as_ref()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                let contained = runtime.contain_and_release_mode(true).await;
                runtime.enrollment.retire_protected_read_after_destroy(
                    &resource.targets.protected_read_residual,
                )?;
                contained?;
                refs.lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .retire_owner_references();
                check_lifecycle_budget(&operation)?;
                let replacement_owner = resource.replace_cleaned_context(&operation).await?;
                let authority = resource
                    .initialize_runtime(
                        gate.clone(),
                        broker,
                        sink.clone(),
                        blobs.clone(),
                        RuntimeInitialization {
                            operation: &operation,
                            retirement: &retirement,
                            options: &options,
                            replacement: Some(ReplacementSeed {
                                page_config,
                                policy,
                                downloads,
                                actions: actions.clone(),
                                owner: Some(replacement_owner),
                            }),
                        },
                    )
                    .await?;
                let expose_page = state.is_none() || was_recording;
                {
                    let page = resource.lease(authority.enter(&resource.targets)?)?;
                    let exclusive = resource
                        .ui
                        .enter(
                            true,
                            false,
                            operation.deadline,
                            operation.cancellation.clone(),
                        )
                        .await?;
                    if let Some(state) = state {
                        let imported_origins =
                            state.origins().map(str::to_owned).collect::<Vec<_>>();
                        let new_runtime = resource
                            .runtime
                            .as_ref()
                            .ok_or(ProtocolError::ScopeUnavailable)?;
                        let attestation = new_runtime.enrollment.attest_capture(&operation).await?;
                        let empty_origins = resource.page_state.visited_origins()?;
                        if !empty_origins.is_empty() {
                            return Err(ProtocolError::ScopeUnavailable);
                        }
                        new_runtime
                            .enrollment
                            .verify_capture_attestation(&attestation, &operation)
                            .await?;
                        let context = super::client_state_dispatch::CapturedStateContext::new(
                            &page,
                            &resource.ui,
                            &exclusive,
                            super::client_state::NativeStateContext {
                                client: &page.client,
                                targets: &page.targets,
                                context_id: &resource.context_id,
                                origins: &empty_origins,
                                origins_complete: true,
                            },
                            super::client_state_dispatch::StateContextKind::Isolated,
                        )
                        .map_err(|failure| failure.error)?;
                        page.client
                            .debt_ledger()
                            .ok_or(ProtocolError::ScopeUnavailable)?
                            .initialization_work(
                                super::client_debt::InitializationWork::StateRestore,
                                &operation,
                                state.import(&context, &operation),
                            )
                            .await?
                            .map_err(|failure| failure.error)?;
                        for origin in imported_origins {
                            resource.page_state.record_origin(&page, &origin)?;
                        }
                    }
                    if was_recording {
                        let debt = page
                            .client
                            .debt_ledger()
                            .ok_or(ProtocolError::ScopeUnavailable)?;
                        debt.initialization_work(
                            super::client_debt::InitializationWork::Recording,
                            &operation,
                            async {
                                let super::client_observation_dispatch::VerifiedFrameInventory {
                                    frames,
                                    iframe_sessions: sessions,
                                } = super::client_observation_dispatch::verified_frame_inventory(
                                    &page, &operation,
                                )
                                .await?;
                                let geometry = super::client_geometry::GeometrySnapshot::capture(
                                    &page.client,
                                    &page.page_session_id,
                                    &frames,
                                    &operation,
                                )
                                .await
                                .map_err(|_| ProtocolError::BrowserFailure)?;
                                let (revision, references) =
                                    observation.snapshot_for_action(&operation).await?;
                                actions
                                    .recording_page_opened(super::client_actions::ActionContext {
                                        observation_after: None,
                                        observed_revision: 0,
                                        page: &page,
                                        operation: &operation,
                                        page_state: &resource.page_state,
                                        refs: &references,
                                        revision,
                                        iframe_sessions: &sessions,
                                        observation_frames: &frames,
                                        blobs: &blobs,
                                        geometry: &geometry,
                                        realm_authority:
                                            super::client_actions::ActionRealmAuthority::Enrolled(
                                                &resource
                                                    .runtime
                                                    .as_ref()
                                                    .ok_or(ProtocolError::ScopeUnavailable)?
                                                    .enrollment,
                                            ),
                                    })
                                    .await
                                    .map_err(|failure| failure.error)?;
                                Ok::<(), ProtocolError>(())
                            },
                        )
                        .await??;
                    }
                }
                loop {
                    check_lifecycle_budget(&operation)?;
                    match resource
                        .runtime
                        .as_ref()
                        .ok_or(ProtocolError::ScopeUnavailable)
                        .and_then(|runtime| runtime.enrollment.publish_initialized(&authority))
                    {
                        Ok(_) => break,
                        Err(ProtocolError::ScopeUnavailable) => {
                            if gate.state.lock().map_or(true, |state| state.closed) {
                                return Err(ProtocolError::ScopeUnavailable);
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                        }
                        Err(error) => return Err(error),
                    }
                }
                resource
                    .runtime
                    .as_ref()
                    .ok_or(ProtocolError::ScopeUnavailable)?
                    .page_active
                    .store(expose_page, std::sync::atomic::Ordering::SeqCst);
                let watched_client = resource.manager.client.clone();
                let watched_targets = resource.targets.clone();
                let mut lost = watched_client.remote_connection_closed();
                let watched_sink = sink.clone();
                *connection_watch.lock().await = Some(tokio::spawn(async move {
                    loop {
                        if *lost.borrow() {
                            return watched_sink
                                .emit_disconnected(&watched_client, &watched_targets)
                                .map(|_queued| ());
                        }
                        if lost.changed().await.is_err() {
                            return Ok(());
                        }
                    }
                }));
                uncertain.store(false, std::sync::atomic::Ordering::SeqCst);
                Ok(serde_json::json!({"identityScope":resource.identity_scope}))
            }
            .await;
            if accepted && result.is_err() {
                gate.seal();
                // The exact failed transition captured this attempt's actions
                // before old-runtime removal. No owner is rediscovered here.
                if let Some(actions) = recording_owner {
                    let key = super::client_debt::OperationKey {
                        generation: operation.generation,
                        operation_seq: operation.sequence,
                    };
                    if let Some(batch) = actions.freeze_finalized_recording(&scope, key, &blobs) {
                        if let Ok(mut slot) = terminal_recording.lock() {
                            if slot.is_none() {
                                *slot = Some(batch);
                            }
                        }
                    }
                }
                if let Some(resource) = owner.lock().await.as_mut() {
                    resource.targets.seal();
                    // Preserve the primary failure; failed retirement remains
                    // journaled for explicit final cleanup, never hidden in Drop.
                    if let Some(routes) = &mut resource.replacement_routes {
                        if routes.retire().is_ok() {
                            resource.replacement_routes = None;
                        }
                    }
                }
            }
            let effects = if result.is_ok() {
                Effects::Completed
            } else if accepted {
                Effects::Unknown
            } else {
                Effects::NotDispatched
            };
            let _ = send.send(NativeOutcome {
                retention: None,
                result,
                effects,
            });
        }));
        drop(slot);
        receive.await.unwrap_or(NativeOutcome {
            retention: None,
            result: Err(ProtocolError::CleanupFailed),
            effects: Effects::Unknown,
        })
    }
}

impl ClientBrowser {
    async fn reconnect_scope(
        &self,
        scope: String,
        request: ReconnectRequest,
        operation: super::client_session::OperationLease,
        recovery: Option<super::client_operation_state::DisconnectedRecoveryProof>,
    ) -> super::client_transport::NativeOutcome {
        use super::client_protocol::Effects;
        use super::client_transport::NativeOutcome;
        if operation.is_callback
            || request.endpoint.trim().is_empty()
            || request.endpoint.len() > 16 * 1024
            || request.endpoint.contains('\0')
            || [
                &request.expected_browser_identity,
                &request.expected_context_identity,
                &request.expected_page_identity,
            ]
            .iter()
            .any(|v| v.is_empty() || v.len() > 1024)
        {
            return NativeOutcome {
                retention: None,
                result: Err(ProtocolError::InvalidArguments),
                effects: Effects::NotDispatched,
            };
        }
        if let Err(error) = check_lifecycle_budget(&operation) {
            return NativeOutcome {
                retention: None,
                result: Err(error),
                effects: Effects::NotDispatched,
            };
        }
        let mut cancellation = operation.cancellation.clone();
        let transition = tokio::select! {
            biased;
            _ = cancellation.changed() => return NativeOutcome { retention: None, result: Err(ProtocolError::Cancelled), effects: Effects::NotDispatched },
            result = tokio::time::timeout_at(operation.deadline.into(), self.lifecycle.clone().lock_owned()) => match result {
                Ok(guard) => guard,
                Err(_) => return NativeOutcome { retention: None, result: Err(ProtocolError::DeadlineExceeded), effects: Effects::NotDispatched },
            },
        };
        let Some(sink) = self.event_sink.get().cloned() else {
            return NativeOutcome {
                retention: None,
                result: Err(ProtocolError::ScopeUnavailable),
                effects: Effects::NotDispatched,
            };
        };
        let mut slot = self.startup_task.lock().await;
        let owner = self.owner.clone();
        let gate = self.gate.clone();
        let broker = self.broker.clone();
        let retirement = self.retirement.clone();
        let blobs = self.blobs.clone();
        let refs = self.refs.clone();
        let tasks = self.tasks.clone();
        let observation = self.observation.clone();
        let uncertain = self.startup_uncertain.clone();
        let connection_watch = self.connection_watch.clone();
        #[cfg(feature = "acceptance-faults")]
        let faults = self.faults.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        *slot = Some(tokio::spawn(async move {
            let _transition = transition;
            let mut accepted = false;
            let mut candidate: Option<super::client_reconnect::VerifiedReconnect> = None;
            let result = async {
                check_lifecycle_budget(&operation)?;
                let mut journal = owner.lock().await;
                let resource = journal.as_mut().ok_or(ProtocolError::StaleScope)?;
                if resource.identity_scope != scope {
                    return Err(ProtocolError::StaleScope);
                }
                if resource.owns_context || resource.borrowed_targets.is_none() {
                    return Err(ProtocolError::UnsupportedCapability);
                }
                let expected = resource.recovery_identity();
                if expected["browser"] != request.expected_browser_identity
                    || expected["context"] != request.expected_context_identity
                    || expected["page"] != request.expected_page_identity
                {
                    return Err(ProtocolError::StaleScope);
                }
                let runtime = resource
                    .runtime
                    .as_ref()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                let terminal = runtime.enrollment.terminal_connection_proof()?;
                terminal.check_client(&resource.manager.client)?;
                if let Some(proof) = &recovery {
                    proof.check()?;
                    let debt = resource
                        .manager
                        .client
                        .debt_ledger()
                        .ok_or(ProtocolError::StaleScope)?;
                    if !Arc::ptr_eq(&debt, proof.ledger())
                        || !debt.matches_owner(operation.generation, &scope)
                    {
                        return Err(ProtocolError::StaleScope);
                    }
                    resource.targets.require_eval_owner(&debt)?;
                    resource.page_state.check_no_active_local_input(&scope)?;
                }
                let retained = super::client_reconnect::RetainedIdentity::capture(
                    &resource.manager,
                    &resource.context_id,
                )?;
                let options = runtime.creation_options.clone();
                let actions = runtime.actions.clone();
                let active = runtime
                    .page_active
                    .load(std::sync::atomic::Ordering::SeqCst);
                let (policy, downloads) = {
                    let configuration = runtime
                        .configuration
                        .lock()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?;
                    (
                        configuration
                            .policy
                            .clone()
                            .ok_or(ProtocolError::ScopeUnavailable)?,
                        configuration
                            .downloads
                            .clone()
                            .ok_or(ProtocolError::ScopeUnavailable)?,
                    )
                };
                if resource.disconnected_routes.is_some() || resource.replacement_routes.is_some() {
                    return Err(ProtocolError::CleanupFailed);
                }
                // Verify the one unpublished candidate before retiring the old
                // runtime. This attaches only the exact retained page; domain
                // setup, parked-route adoption, and publication still follow
                // the old owner's independent terminal cleanup below.
                let identity_scope = uuid::Uuid::new_v4().to_string();
                candidate = Some(
                    super::client_reconnect::reconnect(
                        &request.endpoint,
                        &retained,
                        &operation,
                        &identity_scope,
                    )
                    .await?,
                );
                check_lifecycle_budget(&operation)?;
                resource.replacement_actions = Some(actions.clone());
                accepted = true;
                uncertain.store(true, std::sync::atomic::Ordering::SeqCst);
                retirement
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .stop(false);
                #[cfg(feature = "acceptance-faults")]
                faults.retire_scope(&scope)?;
                gate.begin_transition()?;
                drop(journal);
                gate.drained().await?;
                if let Some(proof) = &recovery {
                    tokio::time::timeout_at(
                        operation.deadline.into(),
                        tasks.drain_disconnected(proof),
                    )
                    .await
                    .map_err(|_| ProtocolError::DeadlineExceeded)??;
                } else {
                    tasks.drain_current().await?;
                }
                let mut journal = owner.lock().await;
                let resource = journal.as_mut().ok_or(ProtocolError::StaleScope)?;
                if resource.identity_scope != scope {
                    return Err(ProtocolError::StaleScope);
                }
                let page_config = resource.page_state.snapshot_config(&scope)?;
                let recording = actions.is_recording_armed().await?;
                // Residual borrowed coordinates must survive old-session release.
                resource
                    .targets
                    .protected_read_residual
                    .replacement_safe()?;
                resource.ui.seal();
                let runtime = resource
                    .runtime
                    .as_ref()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                runtime
                    .release_terminal_connection(&resource.manager.client, true)
                    .await?;
                resource.disconnected_routes = Some(
                    runtime
                        .network
                        .take_disconnected_routes(&resource.targets, &operation)?,
                );
                // Stop the old root event producer before any new scoped
                // authority exists. Abort never stands in for this actual join.
                {
                    let mut watch = connection_watch.lock().await;
                    if let Some(old) = watch.as_mut() {
                        old.abort();
                        if let Err(error) = old.await {
                            if !error.is_cancelled() {
                                return Err(ProtocolError::CleanupFailed);
                            }
                        }
                    }
                    *watch = None;
                }
                if let Some(proof) = &recovery {
                    let verified = candidate.as_ref().ok_or(ProtocolError::ScopeUnavailable)?;
                    broker.bind_recovery_candidate(&operation, verified.proof())?;
                    // This consumes positive local retirement while reader EOF
                    // is still the sole cause, before our explicit socket close.
                    tasks.retire_disconnected_owner(proof)?;
                }
                resource.runtime = None;
                let recovery_observation_baseline =
                    observation.snapshot_with_observation(&operation).await?.2;
                refs.lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .retire_owner_references();
                // Exact terminal local cleanup has settled; this closes only the
                // old socket. Host page/context ownership is never acquired.
                resource.manager.disconnect_transport().await;
                check_lifecycle_budget(&operation)?;
                let verified = candidate.take().ok_or(ProtocolError::ScopeUnavailable)?;
                let (manager, context_id, target_id, proof) = verified.into_parts();
                // Never orphan an earlier owner-local cleanup record.
                resource
                    .targets
                    .protected_read_residual
                    .replacement_safe()?;
                // Journal the new transport before any initialization await.
                resource.manager = manager;
                resource.context_id = context_id;
                resource.identity_scope = identity_scope;
                resource.borrowed_targets = Some(vec![target_id]);
                resource.reconnect_proof = Some(proof);
                resource
                    .targets
                    .protected_read_residual
                    .replacement_safe()?;
                resource.targets = super::client_targets::ClientTargets::new_managed(
                    resource.context_id.clone(),
                    resource.identity_scope.clone(),
                );
                resource.ui = Arc::new(super::client_ui::UiGate::default());
                let authority = resource
                    .initialize_runtime(
                        gate.clone(),
                        broker.clone(),
                        sink.clone(),
                        blobs.clone(),
                        RuntimeInitialization {
                            operation: &operation,
                            retirement: &retirement,
                            options: &options,
                            replacement: Some(ReplacementSeed {
                                page_config,
                                policy,
                                downloads,
                                actions: actions.clone(),
                                owner: None,
                            }),
                        },
                    )
                    .await?;
                resource
                    .runtime
                    .as_mut()
                    .ok_or(ProtocolError::ScopeUnavailable)?
                    .observation_after = Some(recovery_observation_baseline);
                let runtime = resource
                    .runtime
                    .as_ref()
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                runtime
                    .page_active
                    .store(active, std::sync::atomic::Ordering::SeqCst);
                if recording {
                    let page = resource.lease(authority.enter(&resource.targets)?)?;
                    let _exclusive = resource
                        .ui
                        .enter(
                            true,
                            false,
                            operation.deadline,
                            operation.cancellation.clone(),
                        )
                        .await?;
                    let debt = page
                        .client
                        .debt_ledger()
                        .ok_or(ProtocolError::ScopeUnavailable)?;
                    debt.initialization_work(
                        super::client_debt::InitializationWork::Recording,
                        &operation,
                        async {
                            let super::client_observation_dispatch::VerifiedFrameInventory {
                                frames,
                                iframe_sessions: sessions,
                            } = super::client_observation_dispatch::verified_frame_inventory(
                                &page, &operation,
                            )
                            .await?;
                            let geometry = super::client_geometry::GeometrySnapshot::capture(
                                &page.client,
                                &page.page_session_id,
                                &frames,
                                &operation,
                            )
                            .await
                            .map_err(|_| ProtocolError::BrowserFailure)?;
                            let (revision, references) =
                                observation.snapshot_for_action(&operation).await?;
                            actions
                                .recording_page_opened(super::client_actions::ActionContext {
                                    observation_after: None,
                                    observed_revision: 0,
                                    page: &page,
                                    operation: &operation,
                                    page_state: &resource.page_state,
                                    refs: &references,
                                    revision,
                                    iframe_sessions: &sessions,
                                    observation_frames: &frames,
                                    blobs: &blobs,
                                    geometry: &geometry,
                                    realm_authority:
                                        super::client_actions::ActionRealmAuthority::Enrolled(
                                            &runtime.enrollment,
                                        ),
                                })
                                .await
                                .map_err(|failure| failure.error)?;
                            Ok::<(), ProtocolError>(())
                        },
                    )
                    .await??;
                }
                loop {
                    check_lifecycle_budget(&operation)?;
                    match runtime.enrollment.publish_initialized(&authority) {
                        Ok(_) => break,
                        Err(ProtocolError::ScopeUnavailable)
                            if !gate.state.lock().map_or(true, |state| state.closed) =>
                        {
                            tokio::time::sleep(std::time::Duration::from_millis(1)).await
                        }
                        Err(error) => return Err(error),
                    }
                }
                if recovery.is_some() {
                    let debt = resource
                        .manager
                        .client
                        .debt_ledger()
                        .ok_or(ProtocolError::StaleScope)?;
                    broker.publish_recovered_scope(&operation, &debt)?;
                }
                resource.reconnect_proof = None;
                let mut watch = connection_watch.lock().await;
                if let Some(old) = watch.as_mut() {
                    old.abort();
                    let _ = old.await;
                }
                let watched_client = resource.manager.client.clone();
                let watched_targets = resource.targets.clone();
                let mut lost = watched_client.remote_connection_closed();
                *watch = Some(tokio::spawn(async move {
                    loop {
                        if *lost.borrow() {
                            return sink
                                .emit_disconnected(&watched_client, &watched_targets)
                                .map(|_queued| ());
                        }
                        if lost.changed().await.is_err() {
                            return Ok(());
                        }
                    }
                }));
                uncertain.store(false, std::sync::atomic::Ordering::SeqCst);
                Ok(serde_json::json!({"identityScope":resource.identity_scope}))
            }
            .await;
            if accepted && result.is_err() {
                gate.seal();
                if let Some(resource) = owner.lock().await.as_mut() {
                    resource.targets.seal();
                    if let Some(routes) = &mut resource.disconnected_routes {
                        if routes.retire().is_ok() {
                            resource.disconnected_routes = None;
                        }
                    }
                }
            }
            // Until transfer into the owner journal, only this retained task
            // owns the candidate. Settle its transport even after cancellation
            // or old-runtime cleanup failure; Drop is not a cleanup proof.
            if let Some(candidate) = candidate.take() {
                candidate.manager.disconnect_transport().await;
            }
            let _ = send.send(result.map_err(|error| (error, accepted)));
        }));
        drop(slot);
        match receive.await {
            Ok(Ok(value)) => NativeOutcome {
                retention: None,
                result: Ok(value),
                effects: Effects::Completed,
            },
            Ok(Err((error, accepted))) => NativeOutcome {
                retention: None,
                result: Err(error),
                effects: if accepted {
                    Effects::Unknown
                } else {
                    Effects::NotDispatched
                },
            },
            Err(_) => NativeOutcome {
                retention: None,
                result: Err(ProtocolError::CleanupFailed),
                effects: Effects::Unknown,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn trace_native_mutation_without_restore_proof_is_not_completed() {
        use super::super::client_debt::{OperationKey, OwnerDebtLedger};
        use super::super::client_observation_dispatch::DispatchFailure;
        use super::super::client_protocol::{Effects, ScopeState};
        for trace in [false, true] {
            for changed in [false, true] {
                for dirty in [false, true] {
                    let broker = super::super::client_session::ClientSession::new();
                    let lease = broker.admit(1, 1, 5_000).unwrap();
                    assert!(broker.start(1, 1).unwrap());
                    let ledger = OwnerDebtLedger::new(1, "trace-scope".into());
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
                    journal.bind_operation(&lease).unwrap();
                    if changed {
                        journal.mark_mutation_maybe_submitted().unwrap();
                    }
                    let (outcome, lost) = journal
                        .scope(async {
                            let (outcome, lost) = settle_observation_dispatch(
                                Ok(Err(DispatchFailure {
                                    error: ProtocolError::DeadlineExceeded,
                                    identity_scope: "trace-scope".into(),
                                    cleanup_integrity_lost: dirty,
                                })),
                                Ok(Ok(())),
                            );
                            settle_trace_screenshot(outcome, lost, trace, &journal)
                        })
                        .await;
                    assert_eq!(
                        outcome.result,
                        Err(if trace && dirty {
                            ProtocolError::CleanupFailed
                        } else {
                            ProtocolError::DeadlineExceeded
                        })
                    );
                    assert!(outcome.retention.is_none());
                    assert_eq!(lost, dirty);
                    assert_eq!(
                        outcome.effects,
                        if dirty {
                            Effects::Unknown
                        } else {
                            Effects::NotDispatched
                        }
                    );
                    assert_eq!(
                        broker.settle(1, 1, outcome.effects).unwrap(),
                        if dirty {
                            ScopeState::Quarantined
                        } else {
                            ScopeState::Usable
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn observation_cleanup_integrity_settles_quarantined_without_losing_primary() {
        use super::super::client_observation_dispatch::DispatchFailure;
        use super::super::client_protocol::{Effects, ScopeState};
        use super::super::client_session::ClientSession;
        for (error, dirty_dispatch, dirty_join, expected) in [
            (
                ProtocolError::DeadlineExceeded,
                false,
                false,
                Effects::NotDispatched,
            ),
            (
                ProtocolError::Cancelled,
                false,
                false,
                Effects::NotDispatched,
            ),
            (
                ProtocolError::BrowserFailure,
                false,
                false,
                Effects::NotDispatched,
            ),
            (
                ProtocolError::DeadlineExceeded,
                true,
                false,
                Effects::Unknown,
            ),
            (ProtocolError::Cancelled, true, false, Effects::Unknown),
            (ProtocolError::PolicyDenied, true, false, Effects::Unknown),
            (
                ProtocolError::DeadlineExceeded,
                false,
                true,
                Effects::Unknown,
            ),
            (ProtocolError::CleanupFailed, false, false, Effects::Unknown),
        ] {
            let broker = ClientSession::new();
            let _lease = broker.admit(1, 1, 1_000).unwrap();
            assert!(broker.start(1, 1).unwrap());
            let failure = |error, cleanup_integrity_lost| DispatchFailure {
                error,
                identity_scope: "synthetic-scope".into(),
                cleanup_integrity_lost,
            };
            let (outcome, dirty) = settle_observation_dispatch(
                Ok(Err(failure(error.clone(), dirty_dispatch))),
                Ok(if dirty_join {
                    Err(failure(ProtocolError::CleanupFailed, true))
                } else {
                    Ok(())
                }),
            );
            assert_eq!(
                outcome.result,
                Err(error.clone()),
                "primary error must survive"
            );
            assert_eq!(
                outcome.effects, expected,
                "{error:?}, dispatch={dirty_dispatch}, join={dirty_join}"
            );
            let expected_state = if expected == Effects::Unknown {
                ScopeState::Quarantined
            } else {
                ScopeState::Usable
            };
            assert_eq!(dirty, expected == Effects::Unknown);
            assert_eq!(
                broker.settle(1, 1, outcome.effects).unwrap(),
                expected_state
            );
            assert_eq!(broker.health().unwrap(), (1, expected_state));
            if expected_state == ScopeState::Usable {
                let _next = broker.admit(1, 2, 1_000).unwrap();
                assert!(broker.start(1, 2).unwrap());
                assert_eq!(
                    broker.settle(1, 2, Effects::NotDispatched).unwrap(),
                    ScopeState::Usable
                );
            } else {
                assert_eq!(
                    broker.admit(1, 2, 1_000).err(),
                    Some(ProtocolError::ScopeUnavailable)
                );
            }
        }
    }

    #[test]
    fn actual_public_startup_hostname_payload_is_valid_native_configuration() {
        // Exact fixture captured by the real NativeSurface.startAttempt framed-client test.
        let mut value: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/native-startup-hostname.json"
        ))
        .unwrap();
        value.as_object_mut().unwrap().remove("identityScope");
        let request: ConfigureRequest = serde_json::from_value(value.clone()).unwrap();
        request.validate(false).unwrap();
        assert_eq!(request.validate(true), Err(ProtocolError::InvalidArguments));
        for site in ["localhost", "[::1]", "example.com", "example.co.uk"] {
            value["requestPolicy"]["site"] = site.into();
            serde_json::from_value::<ConfigureRequest>(value.clone())
                .unwrap()
                .validate(false)
                .unwrap();
        }
    }

    #[test]
    fn configured_observation_site_is_frozen_without_normalizing_or_allow_all_default() {
        for site in [None, Some(""), Some("app.example"), Some("APP.EXAMPLE")] {
            let mut value = serde_json::json!({
                "testIdAttribute":"data-testid", "secureFieldSelector":"input[type=\"password\" i]",
                "requestPolicy":{}, "downloads":{"source":"local"}
            });
            if let Some(site) = site {
                value["requestPolicy"]["site"] = site.into();
            }
            let mut request: ConfigureRequest = serde_json::from_value(value).unwrap();
            request.validate(false).unwrap();
            let frozen = request.request_policy.observation_frame_policy();
            assert_eq!(
                frozen,
                super::super::client_observation::ObservationFramePolicy::configured(
                    site.map(str::to_owned)
                )
            );
            request.request_policy.site = Some("replacement.example".into());
            assert_ne!(frozen, request.request_policy.observation_frame_policy());
            // Existing restart/reconnect seeds clone this immutable value.
            let seed = super::super::client_observation_dispatch::ReadPolicy {
                frame_policy: frozen.clone(),
                test_id_attribute: request.test_id_attribute,
                secure_field_selector: request.secure_field_selector,
            };
            let replacement = seed.clone();
            assert_eq!(replacement.frame_policy, frozen);
        }
    }
    #[test]
    fn hostname_configuration_rejects_control_data_without_changing_header_authority() {
        for site in ["example.com\nforeign", "example.com\0"] {
            let request: ConfigureRequest = serde_json::from_value(serde_json::json!({
                "testIdAttribute":"data-testid", "secureFieldSelector":"input[type=\"password\" i]",
                "requestPolicy":{"site":site}, "downloads":{"source":"local"}
            }))
            .unwrap();
            assert_eq!(
                request.validate(false),
                Err(ProtocolError::InvalidArguments)
            );
        }
    }

    #[test]
    fn configuration_pins_original_password_policy_and_creation_service_worker_mode() {
        let value = serde_json::json!({
            "testIdAttribute":"data-testid", "secureFieldSelector":"input[type=\"password\" i]",
            "requestPolicy":{}, "downloads":{"source":"local"}
        });
        let request: ConfigureRequest = serde_json::from_value(value.clone()).unwrap();
        request.validate(false).unwrap();
        assert_eq!(request.validate(true), Err(ProtocolError::InvalidArguments));
        let mut weakened = value.clone();
        weakened["secureFieldSelector"] = "input[data-user-selected]".into();
        assert_eq!(
            serde_json::from_value::<ConfigureRequest>(weakened)
                .unwrap()
                .validate(false),
            Err(ProtocolError::InvalidArguments)
        );
        let mut privileged = value.clone();
        privileged["purpose"] = "fixture".into();
        assert!(serde_json::from_value::<ConfigureRequest>(privileged).is_err());
        let mut headers = value;
        headers["requestPolicy"] = serde_json::json!({"headers":{}});
        serde_json::from_value::<ConfigureRequest>(headers)
            .unwrap()
            .validate(true)
            .unwrap();
    }

    #[test]
    fn candidate_advertises_the_complete_wired_public_contract() {
        use super::super::client_transport::ClientExecutor;
        let browser =
            ClientBrowser::new(Arc::new(super::super::client_session::ClientSession::new()));
        let capabilities = browser.capabilities();
        assert!(capabilities
            .iter()
            .any(|value| value == super::super::client_protocol::TERMINAL_RECORDING_ARTIFACTS));
        let families = capabilities
            .iter()
            .filter(|capability| capability.starts_with("browser."))
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        let expected = [
            "scope",
            "lifecycle",
            "persistent-page-reopen",
            "evaluate",
            "page",
            "observe",
            "observe-frame-policy",
            "trace-semantic",
            "query",
            "query-union",
            "fixture-read-fields",
            "actions",
            "network",
            "dialog",
            "download",
            "capture",
            "state",
            "recording",
            "blobs",
        ]
        .into_iter()
        .map(|family| format!("browser.{family}/1"))
        .collect::<std::collections::HashSet<_>>();
        assert_eq!(families, expected);
    }

    #[test]
    fn acceptance_fault_marker_is_compiled_only_in_instrumented_binary() {
        use super::super::client_transport::ClientExecutor;
        let browser =
            ClientBrowser::new(Arc::new(super::super::client_session::ClientSession::new()));
        assert_eq!(
            browser
                .capabilities()
                .iter()
                .any(|value| value == "acceptance.faults/1"),
            cfg!(feature = "acceptance-faults")
        );
    }

    #[test]
    fn decision_upload_reservation_uses_original_token_scope_and_rolls_back_rejection() {
        use super::super::client_blobs::BlobScope;
        use super::super::client_protocol::{Decision, RequestOverrides};
        use super::super::client_session::{ClientSession, DecisionKind, DecisionOwner};
        use super::super::client_transport::ClientExecutor;
        let broker = Arc::new(ClientSession::new());
        let browser = ClientBrowser::new(broker.clone());
        let old = BlobScope {
            generation: 1,
            identity_scope: "old-scope".into(),
        };
        browser.blobs.activate_scope(old.clone()).unwrap();
        let body = browser
            .blobs
            .insert_sealed(old.clone(), b"synthetic")
            .unwrap();
        let token = broker
            .decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                1000,
                None,
                Some(old.identity_scope.clone()),
            )
            .unwrap();
        let decision = Decision::Continue {
            overrides: RequestOverrides {
                body_handle: Some(body.handle.clone()),
                ..Default::default()
            },
        };
        browser
            .prepare_decision(1, &token.token, &decision)
            .unwrap();
        assert!(browser.blobs.borrow_sealed(&old, &body.handle).is_err());
        browser.finish_decision(&token.token, false).unwrap();
        assert!(browser.blobs.borrow_sealed(&old, &body.handle).is_ok());
        browser.blobs.revoke_scope(&old).unwrap();
        let next = BlobScope {
            generation: 1,
            identity_scope: "new-scope".into(),
        };
        browser.blobs.activate_scope(next.clone()).unwrap();
        let replacement = browser
            .blobs
            .insert_sealed(next.clone(), b"replacement")
            .unwrap();
        let stale_decision = Decision::Continue {
            overrides: RequestOverrides {
                body_handle: Some(replacement.handle.clone()),
                ..Default::default()
            },
        };
        assert_eq!(
            browser.prepare_decision(1, &token.token, &stale_decision),
            Err(ProtocolError::StaleScope)
        );
        assert!(browser
            .blobs
            .borrow_sealed(&next, &replacement.handle)
            .is_ok());
        assert_eq!(
            browser.prepare_decision(2, &token.token, &stale_decision),
            Err(ProtocolError::StaleGeneration)
        );
    }

    #[test]
    fn scope_creation_decodes_public_options_and_rejects_cross_source_fields() {
        let request: OpenRequest = serde_json::from_value(serde_json::json!({
            "source":"launch", "context":"isolated", "headless":true,
            "blockServiceWorkers":true, "viewport":{"width":900,"height":700},
            "userAgent":"synthetic-agent", "locale":"en-US", "timezoneId":"UTC",
            "media":{"colorScheme":"dark","reducedMotion":"reduce"},
            "initScripts":["window.synthetic = 1"]
        }))
        .unwrap();
        let OpenRequest::Launch { options, .. } = request else {
            panic!("wrong source")
        };
        assert!(options.block_service_workers);
        assert_eq!(options.viewport.unwrap().width, 900);
        assert_eq!(options.media.color_scheme.as_deref(), Some("dark"));
        assert_eq!(options.init_scripts.len(), 1);
        for invalid in [
            serde_json::json!({"source":"launch","endpoint":"ws://fixture.invalid"}),
            serde_json::json!({"source":"reuse","headless":true}),
            serde_json::json!({"source":"connect","endpoint":"","context":"isolated"}),
            serde_json::json!({"source":"launch","context":"persistent"}),
            serde_json::json!({"source":"launch","viewport":{"width":0,"height":700}}),
            serde_json::json!({"source":"launch","media":{"colorScheme":"invalid"}}),
            serde_json::json!({"source":"launch","unknown":true}),
            serde_json::json!({"source":"reuse","headless":null}),
            serde_json::json!({"source":"launch","locale":null}),
            serde_json::json!({"source":"launch","media":{"colorScheme":null}}),
        ] {
            assert!(serde_json::from_value::<OpenRequest>(invalid).is_err());
        }
        assert!(serde_json::from_value::<OpenRequest>(
            serde_json::json!({"source":"launch","viewport":null})
        )
        .is_ok());
    }

    #[tokio::test]
    async fn retirement_journal_fences_both_registration_orders_and_allows_scope_reuse() {
        use super::super::client_blobs::{BlobScope, BlobStore};
        use super::super::client_enrollment::{ClientEnrollment, ScopeOwnership};
        use super::super::client_network::{ClientNetwork, NetworkPolicy};
        use super::super::client_session::ClientSession;
        use super::super::client_targets::ClientTargets;
        use super::super::client_transport::ClientEventSink;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            std::future::pending::<()>().await;
        });
        let client = Arc::new(
            CdpClient::connect(&format!("ws://{address}"))
                .await
                .unwrap(),
        );
        let create = |identity: &str| {
            let broker = Arc::new(ClientSession::new());
            let (sink, notices) = ClientEventSink::test_channel(broker.clone());
            let blobs = Arc::new(BlobStore::new(Default::default()).unwrap());
            let scope = BlobScope {
                generation: 1,
                identity_scope: identity.into(),
            };
            blobs.activate_scope(scope.clone()).unwrap();
            let targets = ClientTargets::new("context".into(), identity.into());
            let network = Arc::new(ClientNetwork::new(
                client.clone(),
                broker,
                sink,
                scope,
                blobs,
                Arc::new(super::super::client_ui::UiGate::default()),
                NetworkPolicy::default(),
            ));
            let coordinator = ClientEnrollment::new(
                client.clone(),
                targets.clone(),
                Arc::new(super::super::client_page::ClientPageState::new(
                    identity.into(),
                    "context".into(),
                )),
                network,
                Arc::new(ExecutionGate::default()),
                1,
                "session".into(),
                Default::default(),
                ScopeOwnership::IsolatedContext,
                None,
            );
            (coordinator, targets, notices)
        };
        let (first, first_targets, _first_notices) = create("first");
        let mut journal = RetirementJournal::default();
        journal.register(&first).unwrap();
        journal.stop(false);
        assert!(first_targets.inventory().is_err());
        // Exercise the production owner path rather than minting a test
        // capability: admission is permanently closed, but orderly retirement
        // alone must not dirty an otherwise accounted operation settlement.
        assert_eq!(first_targets.check_settlement_integrity(), Ok(()));
        journal.stop(false);
        assert_eq!(first_targets.check_settlement_integrity(), Ok(()));
        assert!(!journal.shutting_down);
        // A later integrity failure cannot be laundered by stopping the same
        // journal again, nor can an earlier failure acquire a clean stamp.
        first_targets.seal();
        journal.stop(false);
        assert!(first_targets.check_settlement_integrity().is_err());
        assert!(first_targets.inventory().is_err());
        let (poisoned, poisoned_targets, _poisoned_notices) = create("poisoned");
        let mut poisoned_journal = RetirementJournal::default();
        poisoned_journal.register(&poisoned).unwrap();
        poisoned_targets.seal();
        poisoned_journal.stop(false);
        assert!(poisoned_targets.check_settlement_integrity().is_err());
        assert!(poisoned_targets.inventory().is_err());
        let (replacement, replacement_targets, _replacement_notices) = create("replacement");
        journal.register(&replacement).unwrap();
        assert!(replacement_targets.inventory().is_ok());
        journal.stop(true);
        assert!(replacement_targets.inventory().is_err());
        assert!(replacement_targets.check_settlement_integrity().is_err());
        let (late, late_targets, _late_notices) = create("late");
        assert_eq!(journal.register(&late), Err(ProtocolError::Cancelled));
        assert!(late_targets.inventory().is_err());
        let mut stopped_first = RetirementJournal::default();
        stopped_first.stop(true);
        let (never_started, never_targets, _never_notices) = create("never-started");
        assert_eq!(
            stopped_first.register(&never_started),
            Err(ProtocolError::Cancelled)
        );
        assert!(never_targets.inventory().is_err());
        client.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn missing_or_retired_dispatch_scope_never_starts_browser_work() {
        use super::super::client_protocol::Effects;
        use super::super::client_session::{CancelSignal, OperationLease};
        use super::super::client_transport::ClientExecutor;
        let browser =
            ClientBrowser::new(Arc::new(super::super::client_session::ClientSession::new()));
        for (args, expected) in [
            (
                serde_json::json!({"source":"()=>1","argument":null}),
                ProtocolError::InvalidArguments,
            ),
            (
                serde_json::json!({"identityScope":"retired-scope","source":"()=>1","argument":null}),
                ProtocolError::StaleScope,
            ),
        ] {
            let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let outcome = browser
                .execute(
                    "page.evaluate".into(),
                    args.as_object().unwrap().clone(),
                    OperationLease {
                        is_callback: false,
                        generation: 1,
                        sequence: 1,
                        deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
                        cancellation,
                    },
                )
                .await;
            assert_eq!(outcome.result.unwrap_err(), expected);
            assert_eq!(outcome.effects, Effects::NotDispatched);
            assert!(browser.owner.lock().await.is_none());
        }
    }

    #[tokio::test]
    async fn provider_activation_requires_current_scope_before_browser_work() {
        use super::super::client_session::{CancelSignal, OperationLease};
        use super::super::client_transport::ClientExecutor;
        let browser =
            ClientBrowser::new(Arc::new(super::super::client_session::ClientSession::new()));
        for (args, expected) in [
            (serde_json::json!({}), ProtocolError::InvalidArguments),
            (
                serde_json::json!({"identityScope":"retired"}),
                ProtocolError::StaleScope,
            ),
        ] {
            let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let outcome = browser
                .execute(
                    "page.activate".into(),
                    args.as_object().unwrap().clone(),
                    OperationLease {
                        is_callback: false,
                        generation: 1,
                        sequence: 1,
                        deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
                        cancellation,
                    },
                )
                .await;
            assert_eq!(outcome.result, Err(expected));
            assert_eq!(
                outcome.effects,
                super::super::client_protocol::Effects::NotDispatched
            );
            assert!(browser.owner.lock().await.is_none());
        }
    }

    fn initialization_registry() -> Arc<super::super::client_targets::ClientTargets> {
        super::super::client_targets::ClientTargets::new("owned-context".into(), "scope".into())
    }

    #[tokio::test]
    async fn initialization_authority_requires_transition_and_old_reader_drain() {
        let gate = Arc::new(ExecutionGate::default());
        let targets = initialization_registry();
        assert!(gate.initialization(targets.clone()).is_err());
        let old = gate.enter(false).unwrap();
        gate.begin_transition().unwrap();
        assert!(gate.initialization(targets.clone()).is_err());
        drop(old);
        gate.drained().await.unwrap();
        let authority = gate.initialization(targets.clone()).unwrap();
        assert!(gate.enter(false).is_err());
        let child = authority.enter(&targets).unwrap();
        child.check().unwrap();
        assert!(gate.commit_transition().is_err());
        authority.revoke().unwrap();
        assert!(authority.enter(&targets).is_err());
        child.check().unwrap();
        assert!(gate.commit_transition().is_err());
        drop(child);
        gate.drained().await.unwrap();
        assert_eq!(gate.commit_transition().unwrap(), 1);
        gate.enter(false).unwrap().check().unwrap();
    }

    #[test]
    fn initialization_exact_registry_not_matching_strings_controls_admission() {
        let gate = Arc::new(ExecutionGate::default());
        gate.begin_transition().unwrap();
        let targets = initialization_registry();
        let authority = gate.initialization(targets.clone()).unwrap();
        assert!(authority.enter(&initialization_registry()).is_err());
        let access = authority.access();
        drop(access.clone());
        access.enter(&targets).unwrap().check().unwrap();
        assert!(gate.initialization(targets.clone()).is_err());
        authority.revoke().unwrap();
        assert!(gate.initialization(targets).is_err());
        gate.commit_transition().unwrap();
    }

    #[test]
    fn initialization_live_authority_blocks_commit_even_without_children() {
        let gate = Arc::new(ExecutionGate::default());
        gate.begin_transition().unwrap();
        let authority = gate.initialization(initialization_registry()).unwrap();
        assert!(gate.commit_transition().is_err());
        authority.revoke().unwrap();
        gate.commit_transition().unwrap();
    }

    #[test]
    fn initialization_abandonment_seals_gate_despite_surviving_access() {
        let gate = Arc::new(ExecutionGate::default());
        gate.begin_transition().unwrap();
        let targets = initialization_registry();
        let authority = gate.initialization(targets.clone()).unwrap();
        let access = authority.access();
        let child = access.enter(&targets).unwrap();
        drop(authority);
        assert!(child.check().is_err());
        assert!(access.enter(&targets).is_err());
        drop(child);
        assert!(gate.commit_transition().is_err());
        assert!(gate.enter(true).is_err());
    }

    #[test]
    fn initialization_retired_authority_cannot_affect_later_transition() {
        let gate = Arc::new(ExecutionGate::default());
        gate.begin_transition().unwrap();
        let targets = initialization_registry();
        let old = gate.initialization(targets.clone()).unwrap();
        let old_access = old.access();
        old.revoke().unwrap();
        gate.commit_transition().unwrap();
        gate.begin_transition().unwrap();
        let current = gate.initialization(targets.clone()).unwrap();
        assert!(old.revoke().is_err());
        assert!(old_access.enter(&targets).is_err());
        drop(old);
        current.enter(&targets).unwrap().check().unwrap();
        current.revoke().unwrap();
        assert_eq!(gate.commit_transition().unwrap(), 2);
    }

    #[test]
    fn initialization_revoke_and_child_admission_share_one_atomic_fence() {
        let gate = Arc::new(ExecutionGate::default());
        gate.begin_transition().unwrap();
        let targets = initialization_registry();
        let authority = gate.initialization(targets.clone()).unwrap();
        let access = authority.access();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let other = barrier.clone();
        let worker = std::thread::spawn(move || {
            other.wait();
            access.enter(&targets)
        });
        barrier.wait();
        authority.revoke().unwrap();
        if let Ok(child) = worker.join().unwrap() {
            assert!(gate.commit_transition().is_err());
            child.check().unwrap();
            drop(child);
        }
        gate.commit_transition().unwrap();
    }

    #[test]
    fn initialization_atomic_publish_preserves_only_exact_tenure_access() {
        let gate = Arc::new(ExecutionGate::default());
        gate.begin_transition().unwrap();
        let targets = initialization_registry();
        let authority = gate.initialization(targets.clone()).unwrap();
        let access = authority.access();
        let child = access.enter(&targets).unwrap();
        assert!(authority.publish().is_err());
        child.check().unwrap();
        drop(child);
        assert_eq!(authority.publish().unwrap(), 1);
        let active = access.enter(&targets).unwrap();
        active.check().unwrap();
        assert!(authority.publish().is_err());
        assert!(authority.revoke().is_err());
        drop(authority);
        active.check().unwrap();
        drop(active);
        gate.begin_transition().unwrap();
        assert!(access.enter(&targets).is_err());
        gate.commit_transition().unwrap();
        assert!(access.enter(&targets).is_err());
    }

    #[test]
    fn initialization_revoked_access_cannot_publish_or_reopen_through_legacy_commit() {
        let gate = Arc::new(ExecutionGate::default());
        gate.begin_transition().unwrap();
        let targets = initialization_registry();
        let authority = gate.initialization(targets.clone()).unwrap();
        let access = authority.access();
        authority.revoke().unwrap();
        assert!(authority.publish().is_err());
        gate.commit_transition().unwrap();
        assert!(access.enter(&targets).is_err());
    }

    #[test]
    fn initialization_nonce_exhaustion_fails_without_issuing_authority() {
        let gate = Arc::new(ExecutionGate::default());
        gate.begin_transition().unwrap();
        gate.state.lock().unwrap().initialization_nonce = u64::MAX;
        assert!(matches!(
            gate.initialization(initialization_registry()),
            Err(ProtocolError::IdentifierExhausted)
        ));
        assert!(!gate.state.lock().unwrap().initialization_live);
    }

    #[tokio::test]
    async fn callback_child_can_finish_while_transition_waits_for_parent() {
        let gate = Arc::new(ExecutionGate::default());
        let parent = gate.enter(false).unwrap();
        gate.begin_transition().unwrap();
        assert!(gate.enter(false).is_err());
        let child = gate.enter(true).unwrap();
        assert!(gate.commit_transition().is_err());
        drop(child);
        drop(parent);
        gate.drained().await.unwrap();
        assert_eq!(gate.commit_transition().unwrap(), 1);
        gate.enter(false).unwrap().check().unwrap();
    }

    #[test]
    fn sealed_scope_rejects_late_results_and_never_reopens() {
        let gate = Arc::new(ExecutionGate::default());
        let permit = gate.enter(false).unwrap();
        gate.seal();
        assert_eq!(permit.check().unwrap_err(), ProtocolError::StaleScope);
        assert!(gate.enter(true).is_err());
        drop(permit);
        assert!(gate.commit_transition().is_err());
    }
    #[tokio::test]
    async fn shutdown_joins_retained_startup_and_rejects_late_publication() {
        use super::super::client_transport::ClientExecutor;
        let browser = Arc::new(ClientBrowser::new(Arc::new(
            super::super::client_session::ClientSession::new(),
        )));
        browser.gate.begin_transition().unwrap();
        browser
            .startup_uncertain
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let gate = browser.gate.clone();
        let uncertain = browser.startup_uncertain.clone();
        let lifecycle = browser.lifecycle.clone().lock_owned().await;
        let (release, released) = tokio::sync::oneshot::channel();
        *browser.startup_task.lock().await = Some(tokio::spawn(async move {
            let _lifecycle = lifecycle;
            released.await.unwrap();
            assert!(gate.commit_transition().is_err());
            // Simulates proven cleanup by the retained lifecycle supervisor;
            // browser process/context cleanup itself is covered by browser CI.
            uncertain.store(false, std::sync::atomic::Ordering::SeqCst);
        }));
        let closing = {
            let browser = browser.clone();
            tokio::spawn(async move { browser.shutdown().await })
        };
        while !browser.gate.state.lock().unwrap().closed {
            tokio::task::yield_now().await;
        }
        assert!(!closing.is_finished());
        assert!(browser.gate.enter(true).is_err());
        release.send(()).unwrap();
        closing.await.unwrap().unwrap();
        assert!(browser.owner.lock().await.is_none());
    }

    #[tokio::test]
    #[ignore = "requires a real installed Chromium; run in browser CI"]
    async fn chromium_owned_scope_isolation_and_cleanup() {
        use super::super::client_transport::ClientExecutor;
        let mut host = super::super::browser::BrowserManager::launch(Default::default(), None)
            .await
            .unwrap();
        host.evaluate("globalThis.syntheticTenant = 17", None)
            .await
            .unwrap();
        let endpoint = host.get_cdp_url().to_owned();
        let browser =
            ClientBrowser::new(Arc::new(super::super::client_session::ClientSession::new()));
        let (sink, _events) =
            super::super::client_transport::ClientEventSink::test_channel(browser.broker.clone());
        browser.set_event_sink(sink).unwrap();
        let (_operation_sender, operation_cancellation) =
            tokio::sync::watch::channel(super::super::client_session::CancelSignal::None);
        let operation = |sequence| super::super::client_session::OperationLease {
            is_callback: false,
            generation: 1,
            sequence,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
            cancellation: operation_cancellation.clone(),
        };
        let opened = browser
            .open(
                OpenRequest::Connect {
                    endpoint,
                    persistent: false,
                    options: Default::default(),
                },
                operation(1),
            )
            .await
            .unwrap();
        assert!(opened["identityScope"]
            .as_str()
            .is_some_and(|scope| !scope.is_empty()));
        {
            let lease = browser.page_lease(false).await.unwrap();
            let value = super::super::browser::evaluate_on(
                &lease.client,
                &lease.page_session_id,
                "globalThis.syntheticTenant = 29; globalThis.syntheticTenant",
            )
            .await
            .unwrap();
            assert_eq!(value, serde_json::json!(29));
            lease.permit.check().unwrap();
        }
        assert_eq!(
            host.evaluate("globalThis.syntheticTenant", None)
                .await
                .unwrap(),
            serde_json::json!(17)
        );
        let first_scope = opened["identityScope"].as_str().unwrap().to_owned();
        let old_context = browser
            .owner
            .lock()
            .await
            .as_ref()
            .unwrap()
            .context_id
            .clone();
        let retained_endpoint = browser
            .owner
            .lock()
            .await
            .as_ref()
            .unwrap()
            .manager
            .get_cdp_url()
            .to_owned();
        browser.end_scope(first_scope.clone(), 0).await.unwrap();
        assert!(browser.owner.lock().await.is_none());
        assert!(browser.page_lease(false).await.is_err());
        let contexts = host
            .client
            .send_command_no_params("Target.getBrowserContexts", None)
            .await
            .unwrap();
        assert!(!contexts["browserContextIds"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(old_context)));
        let reopened = browser
            .open(
                OpenRequest::Reuse {
                    options: Default::default(),
                },
                operation(2),
            )
            .await
            .unwrap();
        assert_ne!(reopened["identityScope"], first_scope);
        assert_eq!(
            browser
                .owner
                .lock()
                .await
                .as_ref()
                .unwrap()
                .manager
                .get_cdp_url(),
            retained_endpoint
        );
        assert_eq!(
            browser.end_scope(first_scope, 0).await.unwrap_err(),
            ProtocolError::StaleScope
        );
        {
            let lease = browser.page_lease(false).await.unwrap();
            let value = super::super::browser::evaluate_on(
                &lease.client,
                &lease.page_session_id,
                "typeof globalThis.syntheticTenant",
            )
            .await
            .unwrap();
            assert_eq!(value, serde_json::json!("undefined"));
        }
        browser.shutdown().await.unwrap();
        assert!(browser.retained_browser.lock().await.is_none());
        assert_eq!(
            host.evaluate("globalThis.syntheticTenant", None)
                .await
                .unwrap(),
            serde_json::json!(17)
        );
        assert!(browser.page_lease(false).await.is_err());
        host.close().await.unwrap();
    }
}

#[cfg(test)]
#[path = "client_browser_reference_tests.rs"]
mod reference_lifetime_tests;

#[cfg(test)]
#[path = "client_browser_state_tests.rs"]
mod state_lifecycle_tests;

#[cfg(test)]
#[path = "client_browser_missing_root_observer_tests.rs"]
mod missing_root_observer_tests;

#[cfg(test)]
#[path = "client_browser_final_local_tests.rs"]
mod final_local_tests;

#[cfg(test)]
#[path = "client_browser_borrowed_cleanup_tests.rs"]
mod borrowed_cleanup_tests;

#[cfg(test)]
#[path = "client_browser_reconnect_tests.rs"]
mod reconnect_tests;

#[cfg(test)]
#[path = "client_browser_recording_attempt_tests.rs"]
mod recording_attempt_tests;
