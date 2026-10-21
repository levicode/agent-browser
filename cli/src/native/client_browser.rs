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
}

/// Resource owner retained separately from active execution leases. For remote
/// connections only this context is disposable; the leased browser is not ours.
pub struct OwnedBrowser {
    pub manager: super::browser::BrowserManager,
    pub context_id: String,
    pub identity_scope: String,
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

    pub async fn launch(
        options: super::cdp::chrome::LaunchOptions,
        engine: Option<&str>,
    ) -> Result<Self, ProtocolError> {
        let manager = super::browser::BrowserManager::launch(options, engine)
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
        Ok(Self {
            manager,
            context_id,
            identity_scope: uuid::Uuid::new_v4().to_string(),
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
        })
    }

    /// Caller seals and drains its gate first. A failed dispose is never
    /// rewritten as successful cleanup merely because the connection closes.
    pub async fn close(&mut self) -> Result<(), ProtocolError> {
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
}
fn yes() -> bool {
    true
}

/// One native client owns one resource scope. Capabilities remain narrow until
/// the corresponding observation, network and protected-capture contracts land.
pub struct ClientBrowser {
    broker: Arc<super::client_session::ClientSession>,
    gate: Arc<ExecutionGate>,
    owner: Arc<tokio::sync::Mutex<Option<OwnedBrowser>>>,
    lifecycle: Arc<tokio::sync::Mutex<()>>,
    startup_uncertain: Arc<std::sync::atomic::AtomicBool>,
    startup_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl ClientBrowser {
    pub fn new(broker: Arc<super::client_session::ClientSession>) -> Self {
        Self {
            broker,
            gate: Arc::new(ExecutionGate::default()),
            owner: Arc::new(tokio::sync::Mutex::new(None)),
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
        self.gate.begin_transition()?;
        self.gate.drained().await?;
        let mut task_slot = self.startup_task.lock().await;
        self.startup_uncertain
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let gate = self.gate.clone();
        let owner = self.owner.clone();
        let uncertain = self.startup_uncertain.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        // Retained lifecycle supervisor survives cancellation of the requesting
        // RPC. Shutdown seals first, then joins this task; late startup cleans
        // its resources instead of publishing into an already closed scope.
        *task_slot = Some(tokio::spawn(async move {
            let _transition = transition;
            let created = match request {
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
    fn capabilities(&self) -> Vec<String> {
        // Not wired to the daemon until these operations have real-browser
        // conformance evidence. Never advertise the full e2e contract here.
        vec!["browser.scope/1".into(), "browser.evaluate/1".into()]
    }

    async fn execute(
        &self,
        command: String,
        args: serde_json::Map<String, serde_json::Value>,
        lease: super::client_session::OperationLease,
    ) -> super::client_transport::NativeOutcome {
        use super::client_protocol::Effects;
        use super::client_transport::NativeOutcome;
        let mutating = command == "scope.open" || command == "page.evaluate";
        let prepared = match command.as_str() {
            "scope.open" => {
                serde_json::from_value::<OpenRequest>(serde_json::Value::Object(args.clone()))
                    .map(Some)
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
        } else {
            match self.page_lease(lease.is_callback).await {
                Err(error) => Err(error),
                Ok(page) => {
                    let expression = match command.as_str() {
                        "page.title" => "document.title".to_owned(),
                        "page.url" => "location.href".to_owned(),
                        _ => format!(
                            "({})({})",
                            args.get("source")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or(""),
                            args["argument"]
                        ),
                    };
                    let value = super::browser::evaluate_on(
                        &page.client,
                        &page.page_session_id,
                        &expression,
                    )
                    .await
                    .map_err(|_| ProtocolError::BrowserFailure)
                    .map(|value| match command.as_str() {
                        "page.title" => serde_json::json!({"title": value}),
                        "page.url" => serde_json::json!({"url": value}),
                        _ => serde_json::json!({"value": value}),
                    });
                    page.permit.check().and(value)
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
        if let Some(task) = startup.as_mut() {
            if task.await.is_err() {
                return Err(ProtocolError::CleanupFailed);
            }
        }
        *startup = None;
        drop(startup);
        let _lifecycle = self.lifecycle.lock().await;
        self.gate.drained().await?;
        let mut owner = self.owner.lock().await.take();
        let cleaned = match owner.as_mut() {
            Some(owner) => owner.close().await,
            None => Ok(()),
        };
        if self
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
        browser.shutdown().await.unwrap();
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
