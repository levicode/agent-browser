//! Private creation rendezvous. This candidate does not advertise a capability
//! until worker reuse, all lifecycle replacements and real consumer proof land.
use super::super::client_protocol::Effects;
use super::super::client_session::OperationLease;
use super::super::client_transport::NativeOutcome;
use super::*;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdoptWire {
    preparation_id: String,
    context_id: String,
    target_id: String,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AbortWire {
    preparation_id: String,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IdentifyWire {
    identity_scope: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetireWire {
    identity_scope: String,
    context_id: String,
}

impl ClientBrowser {
    pub(super) async fn execute_interop(
        &self,
        command: String,
        mut args: serde_json::Map<String, serde_json::Value>,
        operation: OperationLease,
    ) -> NativeOutcome {
        let refused = |error| NativeOutcome {
            result: Err(error),
            effects: Effects::NotDispatched,
            retention: None,
        };
        if operation.is_callback {
            return refused(ProtocolError::InvalidArguments);
        }
        enum Request {
            Prepare(String, OpenRequest),
            Adopt(AdoptWire),
            Abort(AbortWire),
            Identify(IdentifyWire),
            Retire(RetireWire),
        }
        let request = match command.as_str() {
            "scope.interop.prepare" => {
                let id = match args
                    .remove("preparationId")
                    .and_then(|value| value.as_str().map(str::to_owned))
                {
                    Some(id) if id.len() == 36 && uuid::Uuid::parse_str(&id).is_ok() => id,
                    _ => return refused(ProtocolError::InvalidArguments),
                };
                let request: OpenRequest =
                    match serde_json::from_value(serde_json::Value::Object(args)) {
                        Ok(request) => request,
                        Err(_) => return refused(ProtocolError::InvalidArguments),
                    };
                match &request {
                    OpenRequest::Connect {
                        persistent: true, ..
                    } => return refused(ProtocolError::UnsupportedCapability),
                    OpenRequest::Launch { options, .. }
                    | OpenRequest::Connect { options, .. }
                    | OpenRequest::Reuse { options }
                        if !options.init_scripts.is_empty() =>
                    {
                        return refused(ProtocolError::InvalidArguments)
                    }
                    _ => {}
                }
                Request::Prepare(id, request)
            }
            "scope.interop.adopt" => {
                match serde_json::from_value(serde_json::Value::Object(args)) {
                    Ok(request) => Request::Adopt(request),
                    Err(_) => return refused(ProtocolError::InvalidArguments),
                }
            }
            "scope.interop.abort" => {
                match serde_json::from_value(serde_json::Value::Object(args)) {
                    Ok(request) => Request::Abort(request),
                    Err(_) => return refused(ProtocolError::InvalidArguments),
                }
            }
            "scope.interop.retire" => {
                match serde_json::from_value(serde_json::Value::Object(args)) {
                    Ok(request) => Request::Retire(request),
                    Err(_) => return refused(ProtocolError::InvalidArguments),
                }
            }
            "scope.interop.identify" => {
                match serde_json::from_value(serde_json::Value::Object(args)) {
                    Ok(request) => Request::Identify(request),
                    Err(_) => return refused(ProtocolError::InvalidArguments),
                }
            }
            _ => return refused(ProtocolError::UnsupportedCommand),
        };
        match self.broker.start(operation.generation, operation.sequence) {
            Ok(true) => {}
            Ok(false) => return refused(ProtocolError::Cancelled),
            Err(error) => return refused(error),
        }
        let mutating = !matches!(&request, Request::Identify(_));
        let result = match request {
            Request::Retire(request) => self.begin_interop_retirement(request, operation).await,
            Request::Identify(request) => {
                let owner = self.owner.lock().await;
                match owner
                    .as_ref()
                    .filter(|owner| owner.identity_scope == request.identity_scope)
                {
                    Some(owner) => match owner.manager.active_target_id() {
                        Ok(target) if !target.is_empty() => Ok(
                            serde_json::json!({"contextId":owner.context_id,"targetId":target,"persistent":!owner.owns_context}),
                        ),
                        _ => Err(ProtocolError::StaleScope),
                    },
                    None => Err(ProtocolError::StaleScope),
                }
            }
            Request::Prepare(id, request) => {
                self.prepare_interop_scope(id, request, operation).await
            }
            Request::Adopt(request) => {
                self.interop_preparation
                    .adopt(
                        operation.generation,
                        &request.preparation_id,
                        request.context_id,
                        request.target_id,
                        operation,
                    )
                    .await
            }
            Request::Abort(request) => self
                .interop_preparation
                .abort(operation.generation, &request.preparation_id)
                .await
                .map(|()| serde_json::Value::Null),
        };
        let effects = if result.is_ok() {
            Effects::Completed
        } else if mutating {
            let _ = self.broker.quarantine();
            Effects::Unknown
        } else {
            Effects::NotDispatched
        };
        NativeOutcome {
            result,
            effects,
            retention: None,
        }
    }

    /// Phase one belongs to the same retained lifecycle supervisor as scope.end.
    /// The ACK grants no replacement: owner stays installed and the gate stays
    /// transitioning until exact peer absence and the original phase two settle.
    async fn begin_interop_retirement(
        &self,
        request: RetireWire,
        operation: OperationLease,
    ) -> Result<serde_json::Value, ProtocolError> {
        let transition = self.lifecycle.clone().lock_owned().await;
        check_lifecycle_budget(&operation)?;
        {
            let owner = self.owner.lock().await;
            let owner = owner.as_ref().ok_or(ProtocolError::StaleScope)?;
            if !owner.owns_context
                || owner.identity_scope != request.identity_scope
                || owner.context_id != request.context_id
                || owner.context_id.is_empty()
                || owner.runtime.as_ref().is_none_or(|runtime| {
                    runtime
                        .peer_retirement
                        .load(std::sync::atomic::Ordering::Acquire)
                        != 0
                })
            {
                return Err(ProtocolError::StaleScope);
            }
        }
        let owner = self.owner.clone();
        let gate = self.gate.clone();
        let tasks = self.tasks.clone();
        let refs = self.refs.clone();
        let retirement = self.retirement.clone();
        let (reply, result) = tokio::sync::oneshot::channel();
        let mut slot = self.startup_task.lock().await;
        *slot = Some(tokio::spawn(async move {
            let _transition = transition;
            let result = async {
                check_lifecycle_budget(&operation)?;
                {
                    let owner = owner.lock().await;
                    let runtime = owner
                        .as_ref()
                        .and_then(|owner| owner.runtime.as_ref())
                        .ok_or(ProtocolError::StaleScope)?;
                    gate.begin_transition()?;
                    runtime
                        .peer_retirement
                        .store(1, std::sync::atomic::Ordering::Release);
                }
                retirement
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .stop(false);
                gate.drained().await?;
                tasks.drain_current().await?;
                refs.lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    .retire_owner_references();
                let owner = owner.lock().await;
                let resource = owner.as_ref().ok_or(ProtocolError::StaleScope)?;
                resource.ui.seal();
                resource
                    .runtime
                    .as_ref()
                    .ok_or(ProtocolError::ScopeUnavailable)?
                    .begin_peer_retirement()
                    .await?;
                // A departed caller may not dispatch PW destruction on an expired
                // ACK, but the retained owner remains available to terminal close.
                check_lifecycle_budget(&operation)?;
                Ok(serde_json::Value::Null)
            }
            .await;
            let _ = reply.send(result);
        }));
        drop(slot);
        result.await.map_err(|_| ProtocolError::CleanupFailed)?
    }

    async fn prepare_interop_scope(
        &self,
        id: String,
        request: OpenRequest,
        operation: OperationLease,
    ) -> Result<serde_json::Value, ProtocolError> {
        let transition = self.lifecycle.clone().lock_owned().await;
        check_lifecycle_budget(&operation)?;
        if self.owner.lock().await.is_some()
            || (!matches!(&request, OpenRequest::Reuse { .. })
                && self.retained_browser.lock().await.is_some())
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        self.gate.begin_transition()?;
        self.gate.drained().await?;
        let publisher = ScopeStartup {
            gate: self.gate.clone(),
            owner: self.owner.clone(),
            connection_watch: self.connection_watch.clone(),
            event_sink: self
                .event_sink
                .get()
                .cloned()
                .ok_or(ProtocolError::ScopeUnavailable)?,
            broker: self.broker.clone(),
            retirement: self.retirement.clone(),
            blobs: self.blobs.clone(),
            uncertain: self.startup_uncertain.clone(),
        };
        let custody = self.interop_preparation.clone();
        let failed_manager = self.retained_browser.clone();
        let (reply, result) = tokio::sync::oneshot::channel();
        let mut slot = self.startup_task.lock().await;
        // Connection/launch itself also survives loss of the requesting RPC.
        *slot = Some(tokio::spawn(async move {
            let (created, options) = match request {
                OpenRequest::Reuse { options } => (
                    failed_manager
                        .lock()
                        .await
                        .take()
                        .ok_or_else(|| "No retired worker browser".to_owned()),
                    options,
                ),
                OpenRequest::Launch {
                    executable_path,
                    headless,
                    options,
                } => (
                    super::super::browser::BrowserManager::launch_owned_for_interop(
                        super::super::cdp::chrome::LaunchOptions {
                            executable_path,
                            headless,
                            ..Default::default()
                        },
                    )
                    .await,
                    options,
                ),
                OpenRequest::Connect {
                    endpoint,
                    persistent: false,
                    options,
                } => (
                    super::super::browser::BrowserManager::connect_owned_browser(&endpoint, None)
                        .await,
                    options,
                ),
                _ => {
                    let _ = reply.send(Err(ProtocolError::UnsupportedCapability));
                    return;
                }
            };
            let manager = match created {
                Ok(manager) => manager,
                Err(_) => {
                    let _ = reply.send(Err(ProtocolError::BrowserFailure));
                    return;
                }
            };
            let endpoint = manager.get_cdp_url().to_owned();
            let mut manager = Some(manager);
            let prepared = custody
                .prepare_scope(
                    id.clone(),
                    &mut manager,
                    operation,
                    transition,
                    publisher,
                    options,
                )
                .await;
            if let Some(mut manager) = manager {
                // Custody preflight did not take it. Never forget a late owned
                // launch or turn a borrowed browser into Browser.close authority.
                if manager.close().await.is_err() {
                    *failed_manager.lock().await = Some(manager);
                }
            }
            let _ = reply.send(
                prepared.map(|()| serde_json::json!({"preparationId":id,"endpoint":endpoint})),
            );
        }));
        drop(slot);
        result.await.map_err(|_| ProtocolError::CleanupFailed)?
    }
}
