//! Native request ownership and token dispatch. ECMAScript route matching and
//! callbacks stay in e2e; no JavaScript function or matcher is interpreted here.
use super::cdp::client::CdpClient;
use super::cdp::types::CdpEvent;
use super::client_blobs::{
    BlobChunk, BlobLease, BlobProducer, BlobScope, BlobStore, MAX_CHUNK_BYTES,
};
use super::client_protocol::{Decision, DecisionNotice, ProtocolError, RequestOverrides};
use super::client_session::{
    CancelSignal, ClientSession, DecisionKind, DecisionLease, DecisionOutcome, DecisionOwner,
    OperationLease,
};
use super::client_transport::ClientEventSink;
use base64::Engine;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub struct ClientNetwork {
    pub client: Arc<CdpClient>,
    broker: Arc<ClientSession>,
    sink: ClientEventSink,
    registry: Mutex<Option<u64>>,
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
    response_subscriptions: Mutex<std::collections::HashSet<String>>,
    responses: Mutex<HashMap<(String, String), String>>,
    resources: Mutex<HashMap<String, Arc<BodyResource>>>,
    downloads: Mutex<HashMap<String, DownloadEntry>>,
    download_source: Mutex<Option<DownloadSource>>,
    download_context: Mutex<Option<String>>,
    download_subscriptions: Mutex<std::collections::HashSet<String>>,
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
            sink,
            registry: Mutex::new(None),
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
            response_subscriptions: Mutex::new(std::collections::HashSet::new()),
            responses: Mutex::new(HashMap::new()),
            resources: Mutex::new(HashMap::new()),
            downloads: Mutex::new(HashMap::new()),
            download_source: Mutex::new(None),
            download_context: Mutex::new(None),
            download_subscriptions: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Enrollment is supplied by the scope owner. This module never discovers
    /// targets, changes purposes, adopts bootstrap pages, or resumes execution.
    pub async fn configure_session(
        &self,
        session: ApplicationSession,
        operation: &OperationLease,
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
                    application: session,
                    configuration_ready,
                },
            );
        }
        let result = tokio::time::timeout_at(operation.deadline.into(), async {
            self.client.send_command("Network.enable", Some(json!({"maxTotalBufferSize": self.blobs.producer_limit().saturating_mul(2), "maxResourceBufferSize": self.blobs.producer_limit()})), Some(&id)).await?;
            if policy.bypass_service_worker { self.client.send_command("Network.setBypassServiceWorker",Some(json!({"bypass":true})),Some(&id)).await?; }
            self.client.send_command("Fetch.enable", Some(json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}],"handleAuthRequests":true})), Some(&id)).await?;
            Ok::<(), String>(())
        }).await;
        if !matches!(result, Ok(Ok(()))) {
            self.broker.quarantine()?;
            return Err(ProtocolError::BrowserFailure);
        }
        self.check()
    }

    /// Enrollment calls this only after exact-target settings, recursive
    /// attachment, and resume authorization have all acknowledged completion.
    /// Holding initial requests is failure containment, not a timing delay.
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
        Ok(())
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
    ) -> Result<(), ProtocolError> {
        self.check()?;
        let directory = match &source {
            DownloadSource::Local(directory) => {
                let canonical = std::fs::canonicalize(directory)
                    .map_err(|_| ProtocolError::InvalidArguments)?;
                if &canonical != directory || !canonical.is_dir() {
                    return Err(ProtocolError::InvalidArguments);
                }
                directory.to_string_lossy().into_owned()
            }
            DownloadSource::Provider(directory) => {
                if directory.is_empty() || directory.contains('\0') {
                    return Err(ProtocolError::InvalidArguments);
                }
                directory.clone()
            }
        };
        if self
            .download_source
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .is_some()
        {
            return Err(ProtocolError::InvalidArguments);
        }
        self.client.send_command("Browser.setDownloadBehavior",Some(json!({"behavior":"allowAndName","browserContextId":context_id,"downloadPath":directory,"eventsEnabled":true})),None).await.map_err(|_|ProtocolError::BrowserFailure)?;
        self.check()?;
        *self
            .download_source
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)? = Some(source);
        *self
            .download_context
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)? = Some(context_id.into());
        Ok(())
    }
    pub fn subscribe_downloads(&self) -> Result<String, ProtocolError> {
        self.check()?;
        if self
            .download_source
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .is_none()
        {
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
            .map_err(|_| ProtocolError::CapacityExceeded)?;
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
        self.sink.emit("download.started".into(),json!({"identityScope":self.scope.identity_scope,"activePage":session.active_page,"handle":handle,"suggestedFilename":required_string(params,"suggestedFilename")?}),None)
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
                        .map_err(|_| ProtocolError::CapacityExceeded)
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
        if event.method == "Browser.downloadProgress" || event.method == "Page.downloadProgress" {
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
        let configuration_ready = session.configuration_ready.subscribe();
        let session = session.application;
        if matches!(
            event.method.as_str(),
            "Browser.downloadWillBegin" | "Page.downloadWillBegin"
        ) {
            return self.download_started(&session, &event.params);
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
                    self.sink.emit("network.response".into(),json!({"identityScope":self.scope.identity_scope,"activePage":session.active_page,"handle":handle,"url":required_string(response,"url")?,"status":response.get("status"),"headers":response.get("headers")}),None)?;
                }
            }
            return Ok(());
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
            self.sink.emit("network.response".into(),json!({"identityScope":self.scope.identity_scope,"activePage":session.active_page,"handle":handle,"url":required_string(&response,"url")?,"status":response.get("status"),"headers":response.get("headers")}),None)?;
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
        let callback_reservation = if matches!(
            event.method.as_str(),
            "Fetch.requestPaused" | "Fetch.authRequired" | "Page.javascriptDialogOpening"
        ) {
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
            if callback_reservation.is_some() {
                if let Err(error) = this
                    .wait_for_configuration(configuration_ready, deadline)
                    .await
                {
                    // No callback/default Continue is emitted before commit.
                    // A timed-out admission can only abort the held request.
                    if event.method == "Fetch.requestPaused" {
                        let request_id = required_string(&event.params, "requestId")?;
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(2),
                            this.abort_request(&session.session_id, request_id),
                        )
                        .await;
                    }
                    return Err(error);
                }
            }
            let _callback_permit = if let Some(reservation) = callback_reservation {
                match reservation
                    .enter(deadline, this.cancellation.subscribe())
                    .await
                {
                    Ok(permit) => Some(permit),
                    Err(error) => {
                        if !this.sealed.load(Ordering::Acquire) {
                            let _ = this.broker.quarantine();
                        }
                        return Err(error);
                    }
                }
            } else {
                None
            };
            let result = match event.method.as_str() {
                "Fetch.requestPaused" => {
                    this.paused_request_captured(
                        &session.session_id,
                        event.params,
                        captured.ok_or(ProtocolError::DecisionMissing)?,
                    )
                    .await
                }
                "Fetch.authRequired" => {
                    this.authentication(&session.session_id, event.params).await
                }
                "Page.javascriptDialogOpening" => {
                    this.dialog(&session.session_id, event.params).await
                }
                "Network.loadingFinished" => this.response_finished(&session, event.params).await,
                _ => Ok(()),
            };
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

    pub async fn close(&self) -> Result<(), ProtocolError> {
        let mut failed = self.revoke().is_err();
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
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                if !error.is_cancelled() {
                    failed = true;
                }
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
            Ok(())
        }
    }

    async fn authentication(&self, session: &str, params: Value) -> Result<(), ProtocolError> {
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
        let lease = self.broker.decision_scoped(
            self.scope.generation,
            DecisionOwner::Scope,
            DecisionKind::Authentication,
            30_000,
            None,
            Some(self.scope.identity_scope.clone()),
        )?;
        let _token = self.track_token(session, &lease.token)?;
        self.sink.emit("network.auth".into(),json!({"identityScope":self.scope.identity_scope,"origin":parsed.origin().ascii_serialization(),"source":"Server","scheme":challenge.get("scheme"),"realm":challenge.get("realm")}),Some(DecisionNotice{token:lease.token,timeout_ms:30_000}))?;
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

    async fn dialog(&self, session: &str, params: Value) -> Result<(), ProtocolError> {
        let kind = required_string(&params, "type")?;
        if !matches!(kind, "alert" | "confirm" | "prompt" | "beforeunload") {
            return Err(ProtocolError::InvalidArguments);
        }
        let message = required_string(&params, "message")?;
        let lease = self.broker.decision_scoped(
            self.scope.generation,
            DecisionOwner::Scope,
            DecisionKind::Dialog,
            30_000,
            None,
            Some(self.scope.identity_scope.clone()),
        )?;
        let _token = self.track_token(session, &lease.token)?;
        self.sink.emit(
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
        self.downloads
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .retain(|_, entry| entry.handle != handle);
        let resource = self
            .resources
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .remove(handle);
        if let Some(resource) = resource {
            if let Some(Ok(blob)) = resource
                .completed
                .send_replace(Some(Err(ProtocolError::StaleScope)))
            {
                if blob.starts_with("provider:") {
                    return Ok(());
                }
                self.blobs
                    .release(&self.scope, &blob)
                    .map_err(|_| ProtocolError::CleanupFailed)?;
            }
        }
        Ok(())
    }
    async fn response_finished(
        &self,
        session: &ApplicationSession,
        params: Value,
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
                .blobs
                .reserve_producer(self.scope.clone())
                .map_err(|_| ProtocolError::CapacityExceeded)?;
            let result = self
                .client
                .send_command(
                    "Network.getResponseBody",
                    Some(json!({"requestId":id})),
                    Some(&session.session_id),
                )
                .await
                .map_err(|_| ProtocolError::BrowserFailure)?;
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
            self.blobs
                .finish_producer(producer, bytes)
                .map(|blob| blob.handle)
                .map_err(|_| ProtocolError::CapacityExceeded)
        }
        .await;
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
        Ok(())
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

    /// Replacement affects future captures only. Broker retains retired
    /// snapshots until every paused request/fallback chain releases them.
    pub fn replace_routes(
        &self,
        version: u64,
        registrations: Vec<String>,
    ) -> Result<(), ProtocolError> {
        let mut current = self
            .registry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let (generation, _) = self.broker.health()?;
        self.broker.register_routes_scoped(
            generation,
            version,
            registrations,
            Some(self.scope.identity_scope.clone()),
        )?;
        if let Some(old) = *current {
            self.broker.retire_registry(generation, old)?;
        }
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
        let lease = self.broker.decision_scoped(
            self.scope.generation,
            owner,
            DecisionKind::Request,
            timeout_ms,
            *current,
            Some(self.scope.identity_scope.clone()),
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
            self.sink.emit(
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

#[cfg(test)]
mod tests {
    use super::*;
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
                if socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        json!({"id":command["id"],"result":result}).to_string(),
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
    async fn unobserved_download_is_accepted_but_not_emitted() {
        let (network, mut events, _, server) = fixture().await;
        let directory = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(directory.path()).unwrap();
        *network.download_source.lock().unwrap() = Some(DownloadSource::Local(canonical.clone()));
        *network.download_context.lock().unwrap() = Some("owned-context".into());
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
