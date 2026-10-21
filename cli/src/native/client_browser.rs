//! Negotiated browser resource ownership. Browser handles remain native; an
//! execution lease never holds the manager mutex while page work awaits events.
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

use super::cdp::client::CdpClient;
use super::client_protocol::ProtocolError;

#[derive(Default)]
struct GateState {
    epoch: u64,
    readers: usize,
    transitioning: bool,
    closed: bool,
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
        if state.closed || !state.transitioning || state.readers != 0 {
            return Err(ProtocolError::ScopeUnavailable);
        }
        state.epoch = state
            .epoch
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        state.transitioning = false;
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
}

impl OwnedBrowser {
    pub async fn connect(
        endpoint: &str,
        headers: Option<Vec<(String, String)>>,
    ) -> Result<Self, ProtocolError> {
        let manager = super::browser::BrowserManager::connect_owned_browser(endpoint, headers)
            .await
            .map_err(|_| ProtocolError::BrowserFailure)?;
        Self::isolated(manager).await
    }

    /// Persistent attachment is restricted to a dedicated default context.
    /// Validation precedes any page reads, scripts, or navigation.
    pub async fn connect_persistent(endpoint: &str) -> Result<Self, ProtocolError> {
        let mut manager = super::browser::BrowserManager::connect_owned_browser(endpoint, None)
            .await
            .map_err(|_| ProtocolError::BrowserFailure)?;
        let prepared = async {
            let contexts = manager
                .client
                .send_command_no_params("Target.getBrowserContexts", None)
                .await
                .map_err(|_| ProtocolError::BrowserFailure)?;
            let context_id = dedicated_default_context(&contexts)?;
            let targets = manager
                .client
                .send_command_no_params("Target.getTargets", None)
                .await
                .map_err(|_| ProtocolError::BrowserFailure)?;
            if let Some(target_id) = dedicated_default_page(&targets, &context_id)? {
                manager
                    .adopt_verified_page(&target_id, &context_id)
                    .await
                    .map_err(|_| ProtocolError::BrowserFailure)?;
            } else {
                manager
                    .owned_blank_page(None)
                    .await
                    .map_err(|_| ProtocolError::BrowserFailure)?;
            }
            manager
                .navigate("about:blank", super::browser::WaitUntil::DomContentLoaded)
                .await
                .map_err(|_| ProtocolError::BrowserFailure)?;
            Ok::<_, ProtocolError>(context_id)
        }
        .await;
        let context_id = match prepared {
            Ok(id) => id,
            Err(error) => {
                return Err(if manager.close().await.is_err() {
                    ProtocolError::CleanupFailed
                } else {
                    error
                });
            }
        };
        let identity_scope = uuid::Uuid::new_v4().to_string();
        Ok(Self {
            targets: super::client_targets::ClientTargets::new(
                context_id.clone(),
                identity_scope.clone(),
            ),
            page_state: Arc::new(super::client_page::ClientPageState::new(
                identity_scope.clone(),
                context_id.clone(),
            )),
            ui: Arc::new(super::client_ui::UiGate::default()),
            manager,
            context_id,
            identity_scope,
            owns_context: false,
        })
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
        let targets =
            super::client_targets::ClientTargets::new(context_id.clone(), identity_scope.clone());
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

    /// Dispose the owned context while retaining the worker browser. The caller
    /// has drained operations and callback resources before entering this path.
    async fn dispose_context(&mut self) -> Result<(), ProtocolError> {
        if !self.owns_context {
            return Err(ProtocolError::PolicyDenied);
        }
        let (_, inventory) = self.targets.inventory()?;
        let ids = inventory
            .into_iter()
            .map(|target| target.target_id)
            .collect();
        self.ui.seal();
        self.targets.seal();
        self.manager
            .client
            .send_command(
                "Target.disposeBrowserContext",
                Some(serde_json::json!({"browserContextId": self.context_id})),
                None,
            )
            .await
            .map_err(|_| ProtocolError::CleanupFailed)?;
        self.manager.forget_disposed_targets(&ids);
        Ok(())
    }

    /// Caller seals and drains its gate first. A failed dispose is never
    /// rewritten as successful cleanup merely because the connection closes.
    pub async fn close(&mut self) -> Result<(), ProtocolError> {
        self.targets.seal();
        if !self.owns_context {
            return self
                .manager
                .close()
                .await
                .map_err(|_| ProtocolError::CleanupFailed);
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
        let closed = self.manager.close().await;
        if disposed.is_err() || closed.is_err() {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
}

fn dedicated_default_context(value: &serde_json::Value) -> Result<String, ProtocolError> {
    let contexts = value
        .get("browserContextIds")
        .and_then(serde_json::Value::as_array)
        .ok_or(ProtocolError::BrowserFailure)?;
    if !contexts.is_empty() {
        return Err(ProtocolError::PolicyDenied);
    }
    value
        .get("defaultBrowserContextId")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .ok_or(ProtocolError::PolicyDenied)
}

fn dedicated_default_page(
    value: &serde_json::Value,
    context: &str,
) -> Result<Option<String>, ProtocolError> {
    let targets = value
        .get("targetInfos")
        .and_then(serde_json::Value::as_array)
        .ok_or(ProtocolError::BrowserFailure)?;
    match targets.iter().find(|target| {
        target.get("type").and_then(serde_json::Value::as_str) == Some("page")
            && target
                .get("browserContextId")
                .is_none_or(|id| id.as_str() == Some(context))
    }) {
        None => Ok(None),
        Some(target) => target
            .get("targetId")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .map(|id| Some(id.to_owned()))
            .ok_or(ProtocolError::BrowserFailure),
    }
}

#[derive(serde::Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case", deny_unknown_fields)]
enum OpenRequest {
    Launch {
        #[serde(rename = "executablePath")]
        executable_path: Option<String>,
        #[serde(default = "yes")]
        headless: bool,
    },
    Connect {
        endpoint: String,
    },
    Reuse {},
}
fn yes() -> bool {
    true
}

/// One native client owns one resource scope. Capabilities remain narrow until
/// the corresponding observation, network and protected-capture contracts land.
pub struct ClientBrowser {
    broker: Arc<super::client_session::ClientSession>,
    event_sink: std::sync::OnceLock<super::client_transport::ClientEventSink>,
    gate: Arc<ExecutionGate>,
    owner: Arc<tokio::sync::Mutex<Option<OwnedBrowser>>>,
    retained_browser: Arc<tokio::sync::Mutex<Option<super::browser::BrowserManager>>>,
    refs: Arc<Mutex<super::element::RefMap>>,
    lifecycle: Arc<tokio::sync::Mutex<()>>,
    startup_uncertain: Arc<std::sync::atomic::AtomicBool>,
    startup_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl ClientBrowser {
    pub fn new(broker: Arc<super::client_session::ClientSession>) -> Self {
        Self {
            broker,
            event_sink: std::sync::OnceLock::new(),
            gate: Arc::new(ExecutionGate::default()),
            owner: Arc::new(tokio::sync::Mutex::new(None)),
            retained_browser: Arc::new(tokio::sync::Mutex::new(None)),
            refs: Arc::new(Mutex::new(super::element::RefMap::new())),
            lifecycle: Arc::new(tokio::sync::Mutex::new(())),
            startup_uncertain: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            startup_task: tokio::sync::Mutex::new(None),
        }
    }

    async fn open(&self, request: OpenRequest) -> Result<serde_json::Value, ProtocolError> {
        let transition = self.lifecycle.clone().lock_owned().await;
        if self.owner.lock().await.is_some() {
            return Err(ProtocolError::InvalidArguments);
        }
        if !matches!(request, OpenRequest::Reuse {}) && self.retained_browser.lock().await.is_some()
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
        let uncertain = self.startup_uncertain.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        // Retained lifecycle supervisor survives cancellation of the requesting
        // RPC. Shutdown seals first, then joins this task; late startup cleans
        // its resources instead of publishing into an already closed scope.
        *task_slot = Some(tokio::spawn(async move {
            let _transition = transition;
            let created = match request {
                OpenRequest::Reuse {} => match retained_browser.lock().await.take() {
                    Some(manager) => OwnedBrowser::isolated(manager).await,
                    None => Err(ProtocolError::ScopeUnavailable),
                },
                OpenRequest::Connect { endpoint } => OwnedBrowser::connect(&endpoint, None).await,
                OpenRequest::Launch {
                    executable_path,
                    headless,
                } => {
                    OwnedBrowser::launch(
                        super::cdp::chrome::LaunchOptions {
                            executable_path,
                            headless,
                            ..Default::default()
                        },
                        None,
                    )
                    .await
                }
            };
            let result = match created {
                Err(error) => Err(error),
                Ok(mut resource) => {
                    let identity = resource.identity_scope.clone();
                    let mut current = owner.lock().await;
                    match gate.commit_transition() {
                        Ok(_) => {
                            *current = Some(resource);
                            uncertain.store(false, std::sync::atomic::Ordering::SeqCst);
                            Ok(serde_json::json!({"identityScope": identity}))
                        }
                        Err(error) => {
                            drop(current);
                            match resource.close().await {
                                Ok(()) => {
                                    uncertain.store(false, std::sync::atomic::Ordering::SeqCst);
                                    Err(error)
                                }
                                Err(_) => Err(ProtocolError::CleanupFailed),
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
    async fn end_scope(&self, identity_scope: String) -> Result<serde_json::Value, ProtocolError> {
        let transition = self.lifecycle.clone().lock_owned().await;
        if self
            .owner
            .lock()
            .await
            .as_ref()
            .map(|scope| scope.identity_scope.as_str())
            != Some(identity_scope.as_str())
        {
            return Err(ProtocolError::StaleScope);
        }
        self.gate.begin_transition()?;
        self.gate.drained().await?;
        let mut slot = self.startup_task.lock().await;
        self.startup_uncertain
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let gate = self.gate.clone();
        let owner = self.owner.clone();
        let retained = self.retained_browser.clone();
        let refs = self.refs.clone();
        let uncertain = self.startup_uncertain.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        *slot = Some(tokio::spawn(async move {
            let _transition = transition;
            let result = async {
                // Revoke exact authority while the resource is still journaled.
                // A poisoned map must not drop a live browser manager.
                refs.lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .invalidate_all_documents();
                let mut resource = owner.lock().await.take().ok_or(ProtocolError::StaleScope)?;
                if let Err(error) = resource.dispose_context().await {
                    // Retain the resource for shutdown rather than dropping a
                    // manager whose context cleanup has an unknown outcome.
                    *owner.lock().await = Some(resource);
                    return Err(error);
                }
                if let Err(error) = gate.commit_transition() {
                    if resource.manager.close().await.is_err() {
                        *owner.lock().await = Some(resource);
                        return Err(ProtocolError::CleanupFailed);
                    }
                    uncertain.store(false, std::sync::atomic::Ordering::SeqCst);
                    return Err(error);
                }
                *retained.lock().await = Some(resource.manager);
                uncertain.store(false, std::sync::atomic::Ordering::SeqCst);
                Ok(serde_json::Value::Null)
            }
            .await;
            let _ = send.send(result);
        }));
        drop(slot);
        receive.await.map_err(|_| ProtocolError::CleanupFailed)?
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
    fn set_event_sink(
        &self,
        sink: super::client_transport::ClientEventSink,
    ) -> Result<(), ProtocolError> {
        self.event_sink
            .set(sink)
            .map_err(|_| ProtocolError::InvalidArguments)
    }

    fn capabilities(&self) -> Vec<String> {
        // Not wired to the daemon until these operations have real-browser
        // conformance evidence. Never advertise the full e2e contract here.
        vec!["browser.scope/1".into(), "browser.evaluate/1".into()]
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
                    result: Err(ProtocolError::StaleScope),
                    effects: Effects::NotDispatched,
                };
            }
            if command != "scope.end" {
                args.remove("identityScope");
            }
            Some(scope)
        };
        let mutating = matches!(
            command.as_str(),
            "scope.open" | "scope.end" | "page.evaluate"
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
                    result: Err(ProtocolError::InvalidArguments),
                    effects: Effects::NotDispatched,
                }
            }
            "page.title" | "page.url" if args.is_empty() => Ok(None),
            "page.evaluate"
                if args.len() == 2
                    && args.get("source").is_some_and(serde_json::Value::is_string)
                    && args.contains_key("argument") =>
            {
                Ok(None)
            }
            "page.title" | "page.url" | "page.evaluate" => {
                return NativeOutcome {
                    result: Err(ProtocolError::InvalidArguments),
                    effects: Effects::NotDispatched,
                }
            }
            _ => {
                return NativeOutcome {
                    result: Err(ProtocolError::UnsupportedCommand),
                    effects: Effects::NotDispatched,
                }
            }
        };
        let prepared = match prepared {
            Ok(value) => value,
            Err(_) => {
                return NativeOutcome {
                    result: Err(ProtocolError::InvalidArguments),
                    effects: Effects::NotDispatched,
                }
            }
        };
        match self.broker.start(lease.generation, lease.sequence) {
            Ok(true) => {}
            Ok(false) => {
                return NativeOutcome {
                    result: Err(ProtocolError::Cancelled),
                    effects: Effects::NotDispatched,
                }
            }
            Err(error) => {
                return NativeOutcome {
                    result: Err(error),
                    effects: Effects::NotDispatched,
                }
            }
        }
        let result = if let Some(request) = prepared {
            self.open(request).await
        } else if command == "scope.end" {
            self.end_scope(
                args["identityScope"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
            .await
        } else {
            match self.page_lease(lease.is_callback).await {
                Err(error) => Err(error),
                Ok(page) => {
                    if captured_scope.as_deref() != Some(page.identity_scope.as_str()) {
                        return NativeOutcome {
                            result: Err(ProtocolError::StaleScope),
                            effects: Effects::NotDispatched,
                        };
                    }
                    async {
                        let (page_state, ui) = {
                            let owner = self.owner.lock().await;
                            let owner = owner.as_ref().ok_or(ProtocolError::StaleScope)?;
                            if owner.identity_scope != page.identity_scope {
                                return Err(ProtocolError::StaleScope);
                            }
                            (owner.page_state.clone(), owner.ui.clone())
                        };
                        let _ui = ui
                            .enter(
                                false,
                                lease.is_callback,
                                lease.deadline,
                                lease.cancellation.clone(),
                            )
                            .await?;
                        page.permit.check()?;
                        // The same native primitive implements both direct API
                        // dispatch and callback child execution; no second JS reader.
                        page_state
                            .execute(
                                &page,
                                &[],
                                &lease,
                                &command,
                                &serde_json::Value::Object(args),
                            )
                            .await
                    }
                    .await
                }
            }
        };
        if *lease.cancellation.borrow() != super::client_session::CancelSignal::None
            || std::time::Instant::now() >= lease.deadline
        {
            let _ = self.broker.quarantine();
            return NativeOutcome {
                result: Err(ProtocolError::Cancelled),
                effects: Effects::Unknown,
            };
        }
        let effects = if result.is_err() && mutating {
            let _ = self.broker.quarantine();
            Effects::Unknown
        } else {
            Effects::Completed
        };
        NativeOutcome { result, effects }
    }

    async fn shutdown(&self) -> Result<(), ProtocolError> {
        self.gate.seal();
        let mut startup = self.startup_task.lock().await;
        let supervisor_failed = match startup.as_mut() {
            Some(task) => task.await.is_err(),
            None => false,
        };
        *startup = None;
        drop(startup);
        let _lifecycle = self.lifecycle.lock().await;
        let drain_failed = self.gate.drained().await.is_err();
        let mut owner = self.owner.lock().await.take();
        let cleaned = match owner.as_mut() {
            Some(owner) => owner.close().await,
            None => Ok(()),
        };
        let mut retained = self.retained_browser.lock().await.take();
        let retained_failed = match retained.as_mut() {
            Some(manager) => manager.close().await.is_err(),
            None => false,
        };
        if supervisor_failed
            || drain_failed
            || retained_failed
            || self
                .startup_uncertain
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ProtocolError::CleanupFailed);
        }
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn persistent_identity_requires_dedicated_default_context() {
        use serde_json::json;
        assert_eq!(
            dedicated_default_context(
                &json!({"browserContextIds":[],"defaultBrowserContextId":"default-1"})
            )
            .unwrap(),
            "default-1"
        );
        for value in [
            json!({}),
            json!({"browserContextIds":[]}),
            json!({"browserContextIds":[],"defaultBrowserContextId":""}),
            json!({"browserContextIds":["foreign"],"defaultBrowserContextId":"default-1"}),
        ] {
            assert!(dedicated_default_context(&value).is_err());
        }
        let targets = json!({"targetInfos":[
            {"type":"page","targetId":"foreign","browserContextId":"other"},
            {"type":"worker","targetId":"worker"},
            {"type":"page","targetId":"owned","browserContextId":"default-1"}
        ]});
        assert_eq!(
            dedicated_default_page(&targets, "default-1").unwrap(),
            Some("owned".into())
        );
        assert_eq!(dedicated_default_page(&json!({"targetInfos":[{"type":"page","targetId":"foreign","browserContextId":"other"}]}), "default-1").unwrap(), None);
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
        let opened = browser
            .open(OpenRequest::Connect { endpoint })
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
        browser.end_scope(first_scope.clone()).await.unwrap();
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
        let reopened = browser.open(OpenRequest::Reuse {}).await.unwrap();
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
            browser.end_scope(first_scope).await.unwrap_err(),
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
