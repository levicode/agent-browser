//! Same-context page replacement. Context policy, worker sessions, route
//! registries, recording ledger and reference allocators are not replaced.
//! The lifecycle owner must retain this future and its exact execution/UI/input
//! permits until it settles, including after RPC cancellation. Before calling,
//! finish the old recording segment, release input and invalidate document refs
//! without resetting their allocator. Publication and the next recording hook
//! remain owner responsibilities; a successful page proof is not publication.
use super::client_browser::BrowserExecutionLease;
use super::client_enrollment::{BorrowedRestartPermit, ClientEnrollment};
use super::client_protocol::ProtocolError;
use super::client_session::{CancelSignal, OperationLease};
use super::client_targets::{ClientTargets, OwnedTarget, TargetPurpose};
use super::client_transport::ClientEventSink;
use super::client_ui::{UiGate, UiPermit};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use std::time::Instant;

const MAX_INVENTORY: usize = 8192;
const MAX_CLOSED_PAGES: usize = 128;
const MAX_ID_BYTES: usize = 1024;

/// Captured only from the existing native owner, never from wire authority.
/// The coordinator remains live throughout restart, including worker Fetch
/// interception. Do not seal enrollment, close network, disable autoattach or
/// hold a protected target-read barrier while this helper creates the new page.
pub(crate) struct RestartContext<'a> {
    page: &'a BrowserExecutionLease,
    enrollment: &'a Arc<ClientEnrollment>,
    ui_gate: &'a Arc<UiGate>,
    ui: &'a UiPermit,
    operation: &'a OperationLease,
    borrowed: Option<BorrowedRestartPermit>,
    staged_sink: Option<ClientEventSink>,
}
impl<'a> RestartContext<'a> {
    pub(crate) fn new(
        page: &'a BrowserExecutionLease,
        enrollment: &'a Arc<ClientEnrollment>,
        ui_gate: &'a Arc<UiGate>,
        ui: &'a UiPermit,
        operation: &'a OperationLease,
    ) -> Result<Self, ProtocolError> {
        let context = Self {
            page,
            enrollment,
            ui_gate,
            ui,
            operation,
            borrowed: None,
            staged_sink: None,
        };
        context.check()?;
        enrollment.validate_restart_owner(page, ui_gate, operation)?;
        Ok(context)
    }
    /// Explicit restart is narrower than persistent-context lifetime ownership.
    /// This one-operation permit may close verified same-context pages but is
    /// never inherited by ordinary borrowed cleanup or error containment.
    pub(crate) fn new_persistent(
        page: &'a BrowserExecutionLease,
        enrollment: &'a Arc<ClientEnrollment>,
        ui_gate: &'a Arc<UiGate>,
        ui: &'a UiPermit,
        operation: &'a OperationLease,
    ) -> Result<Self, ProtocolError> {
        let mut context = Self {
            page,
            enrollment,
            ui_gate,
            ui,
            operation,
            borrowed: None,
            staged_sink: None,
        };
        context.check()?;
        context.borrowed = Some(enrollment.borrowed_restart_permit(page, ui_gate, operation)?);
        Ok(context)
    }
    /// The lifecycle owner stages this operation's events until its result ACK.
    /// Install only at the old-page-drained boundary, never at construction.
    pub(crate) fn with_staged_sink(mut self, sink: ClientEventSink) -> Self {
        self.staged_sink = Some(sink);
        self
    }
    fn check(&self) -> Result<(), ProtocolError> {
        if self.page.identity_scope.is_empty()
            || self.page.targets.context_id.is_empty()
            || self.page.identity_scope != self.page.targets.identity_scope
        {
            return Err(ProtocolError::StaleScope);
        }
        self.page.permit.check()?;
        self.ui.check_exclusive(self.ui_gate)?;
        if self.operation.is_callback {
            return Err(ProtocolError::InvalidArguments);
        }
        if *self.operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= self.operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        if let Some(permit) = &self.borrowed {
            permit.check(self.operation)?;
        }
        Ok(())
    }
    async fn command(&self, method: &str, params: Value) -> Result<Value, ProtocolError> {
        self.check()?;
        let mut cancellation = self.operation.cancellation.clone();
        tokio::select! {
            biased;
            _ = cancellation.changed() => Err(ProtocolError::Cancelled),
            _ = tokio::time::sleep_until(self.operation.deadline.into()) => Err(ProtocolError::DeadlineExceeded),
            result = self.page.client.send_command(method, Some(params), None) => result.map_err(|_| ProtocolError::BrowserFailure),
        }
    }
}

/// Native journal of effects, not a rollback claim. Any dispatched failure
/// leaves this exact context unavailable for reuse until lifecycle containment.
/// Unknown create outcomes remain journaled even without a returned target ID;
/// they never grant disposal authority over a borrowed host context.
#[derive(Debug)]
pub(crate) struct RestartFailure {
    pub error: ProtocolError,
    pub identity_scope: String,
    pub effects_started: bool,
    pub cleanup_integrity_lost: bool,
    pub closed_targets: Vec<String>,
    pub pending_close_target: Option<String>,
    pub replacement_target: Option<String>,
    pub replacement_session: Option<String>,
    pub create_outcome_unknown: bool,
}
impl RestartFailure {
    fn new(context: &RestartContext<'_>) -> Self {
        Self {
            error: ProtocolError::BrowserFailure,
            identity_scope: context.page.identity_scope.clone(),
            effects_started: false,
            cleanup_integrity_lost: false,
            closed_targets: Vec::new(),
            pending_close_target: None,
            replacement_target: None,
            replacement_session: None,
            create_outcome_unknown: false,
        }
    }
}

/// Exact already-enrolled replacement. The owner must bind this session without
/// issuing another attach, keep the same scope, and never reuse old document IDs.
pub(crate) struct RestartedPage {
    pub target_id: String,
    pub session_id: String,
    pub closed_targets: Vec<String>,
    coordinator: Arc<ClientEnrollment>,
    registry: Arc<ClientTargets>,
    source_target: String,
    source_session: String,
    generation: u64,
    sequence: u64,
    attachment: OwnedTarget,
}
impl RestartedPage {
    /// Validate immediately before owner publication under the retained permits.
    pub(crate) fn validate(&self, context: &RestartContext<'_>) -> Result<(), ProtocolError> {
        context.check()?;
        if !Arc::ptr_eq(&self.coordinator, context.enrollment)
            || !Arc::ptr_eq(&self.registry, &context.page.targets)
            || self.source_target != context.page.target_id
            || self.source_session != context.page.page_session_id
            || self.generation != context.operation.generation
            || self.sequence != context.operation.sequence
            || self.target_id == self.source_target
            || self.session_id == self.source_session
            || self.closed_targets.contains(&self.target_id)
        {
            return Err(ProtocolError::StaleScope);
        }
        let target = self.registry.owned_target(&self.target_id)?;
        if !target.same_attachment(&self.attachment)
            || target.session_id != self.session_id
            || target.kind != "page"
            || target.purpose != Some(TargetPurpose::Application)
            || !target.configured
            || !target.resumed
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    /// Validate retained owner authority before waiting, then publish under the
    /// enrollment/reader/inventory fence. The closure cannot reacquire them.
    pub(crate) async fn publish_ready<T>(
        &self,
        context: &RestartContext<'_>,
        publish: impl FnOnce() -> Result<T, ProtocolError>,
    ) -> Result<T, ProtocolError> {
        self.validate(context)?;
        self.coordinator
            .publish_restart_ready(&self.attachment, context.operation, || {
                context.page.permit.check()?;
                context.ui.check_exclusive(context.ui_gate)?;
                publish()
            })
            .await
    }
}

/// Close exact same-context page roots under isolated ownership or the explicit
/// one-operation persistent restart permit, including pages discovered before
/// the replacement is created. Workers are never closed/detached. Reconciliation is
/// bounded by the original operation deadline and total page count; a page
/// factory cannot turn restart into unbounded work. Once the blank is created,
/// later pages follow ordinary continuous enrollment rather than being mistaken
/// for the new active page. Failure never resurrects an acknowledged closed page.
pub(crate) async fn replace_pages(
    context: &RestartContext<'_>,
) -> Result<RestartedPage, Box<RestartFailure>> {
    let mut journal = RestartFailure::new(context);
    match replace_inner(context, &mut journal).await {
        Ok(page) => Ok(page),
        Err(error) => {
            journal.error = error;
            journal.cleanup_integrity_lost = journal.effects_started;
            if journal.effects_started {
                // The enclosing owner retains containment responsibility. Do
                // not allow a late create ACK to become ordinary application use.
                context.page.targets.seal();
            }
            Err(Box::new(journal))
        }
    }
}
async fn replace_inner(
    context: &RestartContext<'_>,
    journal: &mut RestartFailure,
) -> Result<RestartedPage, ProtocolError> {
    context.check()?;
    if context.borrowed.is_none() {
        context.enrollment.validate_restart_owner(
            context.page,
            context.ui_gate,
            context.operation,
        )?;
    }
    let mut old_sessions = HashSet::new();
    loop {
        let inventory = context.command("Target.getTargets", json!({})).await?;
        let mut pages = owned_page_ids(&inventory, &context.page.targets.context_id)?;
        if pages.is_empty() {
            // Drain exact old-root attribution before taking the final empty
            // inventory. A late popup discovered during that drain is still an
            // old page; it must not inherit the replacement's staged sink.
            context
                .enrollment
                .wait_restart_page_detached(
                    &context.page.target_id,
                    &context.page.page_session_id,
                    context.operation,
                )
                .await?;
            let final_inventory = context.command("Target.getTargets", json!({})).await?;
            pages = owned_page_ids(&final_inventory, &context.page.targets.context_id)?;
            if pages.is_empty() {
                break;
            }
        }
        for target in pages {
            if journal.closed_targets.len() >= MAX_CLOSED_PAGES
                || journal.closed_targets.contains(&target)
            {
                return Err(ProtocolError::CapacityExceeded);
            }
            let enrolled = if context.borrowed.is_some() {
                match context.page.targets.owned_target(&target) {
                    Ok(owned) => Some(owned),
                    Err(ProtocolError::StaleReference) => None,
                    Err(error) => return Err(error),
                }
            } else {
                bounded(context, context.page.targets.wait_attached(&target)).await?;
                Some(context.page.targets.owned_target(&target)?)
            };
            if let Some(owned) = &enrolled {
                if owned.kind != "page" || owned.purpose != Some(TargetPurpose::Application) {
                    return Err(ProtocolError::StaleScope);
                }
                context
                    .enrollment
                    .wait_restart_page_ready(&target, &owned.session_id, context.operation)
                    .await?;
            }
            // Inventory is not dispatch authority: recheck exact browser target
            // identity and context after enrollment waits, before any close.
            let info = verify_page_target(context, &target).await?;
            context.check()?;
            let expected_session = enrolled.as_ref().map(|entry| entry.session_id.clone());
            let session = if let Some(permit) = &context.borrowed {
                // This installs a native retirement fence even before the CDP
                // close. Cancellation/failure after it is not a clean reusable
                // scope, and must not silently revive the fenced host page.
                journal.effects_started = true;
                permit.prepare_page_retirement(&info, context.operation)?
            } else {
                let session = enrolled.ok_or(ProtocolError::StaleReference)?.session_id;
                context.enrollment.expect_restart_page_retirement(
                    &target,
                    &session,
                    context.operation,
                )?;
                Some(session)
            };
            if expected_session.is_some() && expected_session != session {
                return Err(ProtocolError::StaleReference);
            }
            if let Some(session) = &session {
                if context.borrowed.is_some() {
                    context
                        .enrollment
                        .wait_restart_page_ready(&target, session, context.operation)
                        .await?;
                    // The permit can observe enrollment that arrived after the
                    // first lookup. Revalidate after that readiness wait too.
                    verify_page_target(context, &target).await?;
                }
                old_sessions.insert(session.clone());
            }
            context.check()?;
            journal.effects_started = true;
            journal.pending_close_target = Some(target.clone());
            let closed = context
                .command("Target.closeTarget", json!({"targetId":target}))
                .await?;
            if closed.get("success").and_then(Value::as_bool) != Some(true) {
                return Err(ProtocolError::CleanupFailed);
            }
            journal.closed_targets.push(target.clone());
            journal.pending_close_target = None;
            if let Some(session) = &session {
                context
                    .enrollment
                    .wait_restart_page_detached(&target, session, context.operation)
                    .await?;
            }
        }
    }
    // Creation purpose is reserved before the CDP effect, keeping the ordinary
    // enrollment path paused until the exact ACK target becomes the active root.
    context.check()?;
    if let Some(sink) = &context.staged_sink {
        context
            .enrollment
            .install_restart_session_sink(sink, context.operation)?;
    }
    let mut borrowed_admission = context
        .borrowed
        .as_ref()
        .map(|permit| permit.reserve_blank_creation(context.operation))
        .transpose()?;
    let mut reservation = match context
        .page
        .targets
        .reserve_creation(TargetPurpose::Application)
    {
        Ok(reservation) => reservation,
        Err(error) => {
            if let Some(admission) = borrowed_admission.take() {
                admission.cancel_unsubmitted()?;
            }
            return Err(error);
        }
    };
    journal.effects_started = true;
    journal.create_outcome_unknown = true;
    let reply = context
        .command(
            "Target.createTarget",
            json!({
                "browserContextId": context.page.targets.context_id,
                "url": "about:blank",
            }),
        )
        .await?;
    let target = identifier(&reply, "targetId")?.to_owned();
    journal.replacement_target = Some(target.clone());
    journal.create_outcome_unknown = false;
    if target == context.page.target_id || journal.closed_targets.contains(&target) {
        return Err(ProtocolError::StaleScope);
    }
    if let Some(admission) = &mut borrowed_admission {
        let info = verify_page_target(context, &target).await?;
        admission.acknowledge(&info, context.operation)?;
    }
    bounded(context, context.page.targets.wait_attached(&target)).await?;
    let session = context
        .enrollment
        .select_registered_restart_page(&target, context.operation)
        .await?;
    journal.replacement_session = Some(session.clone());
    if session == context.page.page_session_id || old_sessions.contains(&session) {
        return Err(ProtocolError::StaleScope);
    }
    reservation.claim(&target)?;
    drop(reservation);
    context
        .enrollment
        .wait_restart_page_ready(&target, &session, context.operation)
        .await?;
    let attachment = context.page.targets.owned_target(&target)?;
    let page = RestartedPage {
        target_id: target,
        session_id: session,
        closed_targets: journal.closed_targets.clone(),
        coordinator: context.enrollment.clone(),
        registry: context.page.targets.clone(),
        source_target: context.page.target_id.clone(),
        source_session: context.page.page_session_id.clone(),
        generation: context.operation.generation,
        sequence: context.operation.sequence,
        attachment,
    };
    page.validate(context)?;
    if let Some(admission) = borrowed_admission {
        admission.complete(&page.target_id, &page.session_id, context.operation)?;
    }
    Ok(page)
}
async fn verify_page_target(
    context: &RestartContext<'_>,
    target: &str,
) -> Result<Value, ProtocolError> {
    let value = context
        .command("Target.getTargetInfo", json!({"targetId":target}))
        .await?;
    let info = value
        .get("targetInfo")
        .ok_or(ProtocolError::BrowserFailure)?;
    if identifier(info, "targetId")? != target
        || identifier(info, "type")? != "page"
        || identifier(info, "browserContextId")? != context.page.targets.context_id
    {
        return Err(ProtocolError::StaleScope);
    }
    context.check()?;
    Ok(info.clone())
}
async fn bounded<T>(
    context: &RestartContext<'_>,
    future: impl std::future::Future<Output = Result<T, ProtocolError>>,
) -> Result<T, ProtocolError> {
    context.check()?;
    let mut cancellation = context.operation.cancellation.clone();
    tokio::select! {
        biased;
        _ = cancellation.changed() => Err(ProtocolError::Cancelled),
        _ = tokio::time::sleep_until(context.operation.deadline.into()) => Err(ProtocolError::DeadlineExceeded),
        result = future => result,
    }
}
fn identifier<'a>(value: &'a Value, field: &str) -> Result<&'a str, ProtocolError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= MAX_ID_BYTES && !id.contains('\0'))
        .ok_or(ProtocolError::BrowserFailure)
}
fn owned_page_ids(inventory: &Value, context_id: &str) -> Result<Vec<String>, ProtocolError> {
    let infos = inventory
        .get("targetInfos")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::BrowserFailure)?;
    if infos.len() > MAX_INVENTORY {
        return Err(ProtocolError::CapacityExceeded);
    }
    let mut pages = BTreeSet::new();
    let mut owned = HashSet::new();
    for info in infos {
        if info.get("browserContextId").and_then(Value::as_str) != Some(context_id) {
            continue;
        }
        let target = identifier(info, "targetId")?;
        let kind = identifier(info, "type")?;
        if !owned.insert(target.to_owned()) {
            return Err(ProtocolError::BrowserFailure);
        }
        if kind == "page" {
            pages.insert(target.to_owned());
            if pages.len() > MAX_CLOSED_PAGES {
                return Err(ProtocolError::CapacityExceeded);
            }
        }
    }
    Ok(pages.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::super::cdp::client::CdpClient;
    use super::super::client_blobs::{BlobLimits, BlobScope, BlobStore};
    use super::super::client_browser::ExecutionGate;
    use super::super::client_enrollment::{ScopeConfig, ScopeOwnership};
    use super::super::client_network::{ClientNetwork, NetworkPolicy};
    use super::super::client_page::ClientPageState;
    use super::super::client_session::ClientSession;
    use super::super::client_transport::ClientEventSink;
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::Message;

    struct Fixture {
        enrollment: Arc<ClientEnrollment>,
        network: Arc<ClientNetwork>,
        ui: Arc<UiGate>,
        page: BrowserExecutionLease,
        operation: OperationLease,
        cancellation: tokio::sync::watch::Sender<CancelSignal>,
        log: Arc<Mutex<Vec<Value>>>,
        server: tokio::task::JoinHandle<()>,
        persistent: bool,
        _notices: tokio::sync::mpsc::Receiver<super::super::client_protocol::ServerMessage>,
    }
    impl Fixture {
        async fn close(self) {
            let _ = tokio::time::timeout(Duration::from_secs(2), self.enrollment.close()).await;
            let _ = self.network.close().await;
            self.server.abort();
        }
    }
    fn info(target: &str, kind: &str, context: &str) -> Value {
        json!({"targetId":target,"type":kind,"browserContextId":context,"url":"about:blank"})
    }
    fn attached(target: &str, session: &str, kind: &str) -> Value {
        json!({"method":"Target.attachedToTarget","params":{
            "sessionId":session,"targetInfo":info(target,kind,"owned-context"),"waitingForDebugger":true
        }})
    }
    async fn make_fixture(mode: &'static str) -> Fixture {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let recorded = log.clone();
        let persistent = mode.starts_with("persistent");
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            socket.set_nodelay(true).unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut targets = BTreeMap::from([
                (
                    "old-page".to_owned(),
                    info("old-page", "page", "owned-context"),
                ),
                (
                    "worker".to_owned(),
                    info("worker", "service_worker", "owned-context"),
                ),
                (
                    "foreign".to_owned(),
                    info("foreign", "page", "foreign-context"),
                ),
            ]);
            if persistent {
                // Same-context host page has never been adopted or configured.
                targets.insert(
                    "host-page".into(),
                    info("host-page", "page", "owned-context"),
                );
            }
            let mut worker_attached = false;
            let mut popup_added = false;
            while let Some(Ok(Message::Text(text))) = socket.next().await {
                let request: Value = serde_json::from_str(&text).unwrap();
                recorded.lock().unwrap().push(request.clone());
                let method = request["method"].as_str().unwrap();
                let mut before = Vec::new();
                let mut after = Vec::new();
                let result = match method {
                    "Target.setAutoAttach"
                        if request.get("sessionId").is_none()
                            && request["params"]["autoAttach"] == true
                            && !worker_attached =>
                    {
                        worker_attached = true;
                        before.push(attached("worker", "worker-session", "service_worker"));
                        if persistent {
                            before.push(attached("host-page", "host-observer-session", "page"));
                        }
                        json!({})
                    }
                    "Target.getTargets" => {
                        let reply =
                            json!({"targetInfos":targets.values().cloned().collect::<Vec<_>>()});
                        if mode.ends_with("post-empty-popup")
                            && !popup_added
                            && !targets.contains_key("old-page")
                            && !targets.contains_key("replacement")
                        {
                            popup_added = true;
                            targets.insert(
                                "late-popup".into(),
                                info("late-popup", "page", "owned-context"),
                            );
                            let mut popup = attached("late-popup", "popup-session", "page");
                            popup["params"]["targetInfo"]["openerId"] = "old-page".into();
                            after.push(popup);
                        }
                        reply
                    }
                    "Target.getTargetInfo" => {
                        let target = request["params"]["targetId"].as_str().unwrap();
                        let mut found = targets.get(target).cloned().unwrap_or(Value::Null);
                        if mode.ends_with("wrong-context") {
                            found["browserContextId"] = "foreign-context".into();
                        } else if mode.ends_with("replaced-inventory") {
                            found["targetId"] = "replacement-host-target".into();
                        }
                        json!({"targetInfo":found})
                    }
                    "Page.getFrameTree" => json!({"frameTree":{"frame":{
                        "id":request["sessionId"],"loaderId":"synthetic-loader","url":"about:blank","securityOrigin":"null"
                    }}}),
                    "Page.addScriptToEvaluateOnNewDocument" => {
                        json!({"identifier":"synthetic-script"})
                    }
                    "Target.closeTarget" => {
                        let target = request["params"]["targetId"].as_str().unwrap();
                        if mode.ends_with("close-failed") {
                            json!({"success":false})
                        } else {
                            targets.remove(target);
                            let session = match target {
                                "old-page" => "old-session",
                                "host-page" => "host-observer-session",
                                "late-popup" => "popup-session",
                                _ => "replacement-session",
                            };
                            after.push(json!({"method":"Target.detachedFromTarget","params":{"sessionId":session,"targetId":target}}));
                            if mode.ends_with("late-popup") && !popup_added {
                                popup_added = true;
                                targets.insert(
                                    "late-popup".into(),
                                    info("late-popup", "page", "owned-context"),
                                );
                                let mut popup = attached("late-popup", "popup-session", "page");
                                popup["params"]["targetInfo"]["openerId"] = "old-page".into();
                                after.push(popup);
                            }
                            json!({"success":true})
                        }
                    }
                    "Target.createTarget" => {
                        let target = if mode.ends_with("reused-target") {
                            "old-page"
                        } else {
                            "replacement"
                        };
                        let session = if mode.ends_with("reused-session") {
                            "old-session"
                        } else {
                            "replacement-session"
                        };
                        targets.insert(target.into(), info(target, "page", "owned-context"));
                        if mode.ends_with("create-no-ack") {
                            socket
                                .send(Message::Text(attached(target, session, "page").to_string()))
                                .await
                                .unwrap();
                            continue;
                        }
                        if mode.ends_with("ack-before-attach") {
                            after.push(attached(target, session, "page"));
                        } else {
                            before.push(attached(target, session, "page"));
                        }
                        json!({"targetId":target})
                    }
                    _ => json!({}),
                };
                for event in before {
                    if socket.send(Message::Text(event.to_string())).await.is_err() {
                        return;
                    }
                }
                if socket
                    .send(Message::Text(
                        json!({"id":request["id"],"result":result}).to_string(),
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
                for event in after {
                    if socket.send(Message::Text(event.to_string())).await.is_err() {
                        return;
                    }
                }
            }
        });
        let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
        let broker = Arc::new(ClientSession::new());
        let (sink, notices) = ClientEventSink::test_channel(broker.clone());
        let blobs = Arc::new(BlobStore::new(BlobLimits::default()).unwrap());
        blobs
            .activate_scope(BlobScope {
                generation: 1,
                identity_scope: "same-scope".into(),
            })
            .unwrap();
        let ui = Arc::new(UiGate::default());
        let network = Arc::new(ClientNetwork::new(
            client.clone(),
            broker,
            sink,
            BlobScope {
                generation: 1,
                identity_scope: "same-scope".into(),
            },
            blobs,
            ui.clone(),
            NetworkPolicy::default(),
        ));
        network
            .replace_routes(1, vec!["attempt-route".into()])
            .unwrap();
        let targets = ClientTargets::new("owned-context".into(), "same-scope".into());
        let gate = Arc::new(ExecutionGate::default());
        let enrollment = ClientEnrollment::new(
            client.clone(),
            targets.clone(),
            Arc::new(ClientPageState::new(
                "same-scope".into(),
                "owned-context".into(),
            )),
            network.clone(),
            gate.clone(),
            1,
            "old-session".into(),
            ScopeConfig::default(),
            if persistent {
                ScopeOwnership::BorrowedTargets(vec!["old-page".into()])
            } else {
                ScopeOwnership::IsolatedContext
            },
            None,
        );
        let (cancellation, receiver) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline: Instant::now() + Duration::from_secs(5),
            cancellation: receiver,
        };
        enrollment
            .enroll_existing("old-page", "old-session", "page", &operation)
            .await
            .unwrap();
        enrollment.start(&operation).await.unwrap();
        targets.acknowledge_enrollment().unwrap();
        let page = BrowserExecutionLease {
            client,
            targets,
            page_session_id: "old-session".into(),
            target_id: "old-page".into(),
            identity_scope: "same-scope".into(),
            permit: gate.enter(false).unwrap(),
        };
        Fixture {
            enrollment,
            network,
            ui,
            page,
            operation,
            cancellation,
            log,
            server,
            persistent,
            _notices: notices,
        }
    }
    async fn exclusive(fixture: &Fixture) -> UiPermit {
        fixture
            .ui
            .enter(
                true,
                false,
                fixture.operation.deadline,
                fixture.operation.cancellation.clone(),
            )
            .await
            .unwrap()
    }
    fn context<'a>(fixture: &'a Fixture, permit: &'a UiPermit) -> RestartContext<'a> {
        let constructor = if fixture.persistent {
            RestartContext::new_persistent
        } else {
            RestartContext::new
        };
        constructor(
            &fixture.page,
            &fixture.enrollment,
            &fixture.ui,
            permit,
            &fixture.operation,
        )
        .unwrap()
    }
    #[test]
    fn inventory_selects_only_exact_context_pages_and_rejects_ambiguity() {
        let inventory = json!({"targetInfos":[
            info("worker","service_worker","owned"), info("iframe","iframe","owned"),
            info("foreign","page","other"), info("page","page","owned")
        ]});
        assert_eq!(owned_page_ids(&inventory, "owned").unwrap(), vec!["page"]);
        assert!(owned_page_ids(
            &json!({"targetInfos":[info("page","page","owned"),info("page","page","owned")]}),
            "owned"
        )
        .is_err());
        assert!(
            owned_page_ids(&json!({"targetInfos":[info("","page","owned")]}), "owned").is_err()
        );
        assert!(owned_page_ids(
            &json!({"targetInfos":[{"targetId":"page","browserContextId":"owned"}]}),
            "owned"
        )
        .is_err());
        assert!(owned_page_ids(&json!({"targetInfos":[info("same","page","owned"),info("same","service_worker","owned")]}), "owned").is_err());
        let oversized: Vec<_> = (0..=MAX_CLOSED_PAGES)
            .map(|i| info(&format!("page-{i}"), "page", "owned"))
            .collect();
        assert_eq!(
            owned_page_ids(&json!({"targetInfos":oversized}), "owned"),
            Err(ProtocolError::CapacityExceeded)
        );
    }
    #[tokio::test]
    async fn restart_replaces_only_pages_and_keeps_context_worker_and_route_tenure() {
        for mode in [
            "normal",
            "ack-before-attach",
            "late-popup",
            "post-empty-popup",
        ] {
            let fixture = make_fixture(mode).await;
            let permit = exclusive(&fixture).await;
            let context = context(&fixture, &permit);
            let mut page = replace_pages(&context).await.unwrap();
            page.validate(&context).unwrap();
            page.publish_ready(&context, || Ok(())).await.unwrap();
            let replacement_session = page.session_id.clone();
            page.session_id = "old-session".into();
            assert_eq!(page.validate(&context), Err(ProtocolError::StaleScope));
            page.session_id = replacement_session;
            let replacement_target = page.target_id.clone();
            page.target_id = "old-page".into();
            assert_eq!(page.validate(&context), Err(ProtocolError::StaleScope));
            page.target_id = replacement_target;
            page.generation += 1;
            assert_eq!(page.validate(&context), Err(ProtocolError::StaleScope));
            page.generation -= 1;
            page.validate(&context).unwrap();
            assert_eq!(page.target_id, "replacement");
            assert_eq!(page.session_id, "replacement-session");
            assert_eq!(context.page.identity_scope, "same-scope");
            assert!(Arc::ptr_eq(&page.coordinator, &fixture.enrollment));
            assert_eq!(
                page.closed_targets,
                if mode.ends_with("popup") {
                    vec!["old-page", "late-popup"]
                } else {
                    vec!["old-page"]
                }
            );
            let log = fixture.log.lock().unwrap().clone();
            assert!(log.iter().all(|request| !matches!(
                request["method"].as_str(),
                Some(
                    "Target.disposeBrowserContext"
                        | "Target.detachFromTarget"
                        | "Target.attachToTarget"
                        | "Fetch.disable"
                )
            )));
            assert!(log
                .iter()
                .filter(|request| request["method"] == "Target.setAutoAttach")
                .all(|request| request["params"]["autoAttach"] == true));
            assert!(log
                .iter()
                .filter(|request| request["method"] == "Target.closeTarget")
                .all(|request| request["params"]["targetId"] != "worker"
                    && request["params"]["targetId"] != "foreign"));
            assert!(fixture.page.targets.owned_target("worker").unwrap().resumed);
            drop(context);
            drop(permit);
            fixture.close().await;
        }
    }
    #[tokio::test]
    async fn restart_rejects_wrong_owner_ui_and_cancelled_preflight_without_close() {
        let fixture = make_fixture("normal").await;
        let other = make_fixture("normal").await;
        let ordinary = fixture
            .ui
            .enter(
                false,
                false,
                fixture.operation.deadline,
                fixture.operation.cancellation.clone(),
            )
            .await
            .unwrap();
        assert!(RestartContext::new(
            &fixture.page,
            &fixture.enrollment,
            &fixture.ui,
            &ordinary,
            &fixture.operation
        )
        .is_err());
        drop(ordinary);
        let foreign_permit = exclusive(&other).await;
        assert!(RestartContext::new(
            &fixture.page,
            &fixture.enrollment,
            &other.ui,
            &foreign_permit,
            &fixture.operation
        )
        .is_err());
        drop(foreign_permit);
        let permit = exclusive(&fixture).await;
        assert!(RestartContext::new(
            &fixture.page,
            &other.enrollment,
            &fixture.ui,
            &permit,
            &fixture.operation
        )
        .is_err());
        let other_ui = Arc::new(UiGate::default());
        assert!(RestartContext::new(
            &fixture.page,
            &fixture.enrollment,
            &other_ui,
            &permit,
            &fixture.operation
        )
        .is_err());
        fixture.cancellation.send(CancelSignal::Requested).unwrap();
        assert!(matches!(
            RestartContext::new(
                &fixture.page,
                &fixture.enrollment,
                &fixture.ui,
                &permit,
                &fixture.operation
            ),
            Err(ProtocolError::Cancelled)
        ));
        assert!(!fixture
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|request| request["method"] == "Target.closeTarget"));
        drop(permit);
        fixture.close().await;
        other.close().await;
    }
    #[tokio::test]
    async fn explicit_persistent_restart_closes_context_pages_without_adopting_host_pages() {
        for mode in [
            "persistent",
            "persistent-ack-before-attach",
            "persistent-late-popup",
            "persistent-post-empty-popup",
        ] {
            let fixture = make_fixture(mode).await;
            let permit = exclusive(&fixture).await;
            assert!(matches!(
                RestartContext::new(
                    &fixture.page,
                    &fixture.enrollment,
                    &fixture.ui,
                    &permit,
                    &fixture.operation,
                ),
                Err(ProtocolError::UnsupportedCapability)
            ));
            assert!(matches!(
                fixture.page.targets.owned_target("host-page"),
                Err(ProtocolError::StaleReference)
            ));
            let context = context(&fixture, &permit);
            let page = replace_pages(&context).await.unwrap();
            page.validate(&context).unwrap();
            page.publish_ready(&context, || Ok(())).await.unwrap();
            assert_eq!(page.target_id, "replacement");
            assert_eq!(page.session_id, "replacement-session");
            assert!(page.closed_targets.contains(&"old-page".into()));
            assert!(page.closed_targets.contains(&"host-page".into()));
            if mode.ends_with("popup") {
                assert!(page.closed_targets.contains(&"late-popup".into()));
            }
            let log = fixture.log.lock().unwrap().clone();
            for request in log.iter().filter(|r| r["method"] == "Target.closeTarget") {
                assert!(matches!(
                    request["params"]["targetId"].as_str(),
                    Some("old-page" | "host-page" | "late-popup")
                ));
            }
            assert!(log
                .iter()
                .all(|r| r["method"] != "Target.disposeBrowserContext"));
            assert!(log
                .iter()
                .filter(|r| r["method"] == "Target.createTarget")
                .all(|r| r["params"]["browserContextId"] == "owned-context"
                    && r["params"]["url"] == "about:blank"));
            // A one-operation close grant never becomes lifetime ownership of
            // the replacement or unrelated host tabs on ordinary shutdown.
            drop(context);
            drop(permit);
            let boundary = fixture.log.lock().unwrap().len();
            fixture.enrollment.seal();
            fixture.enrollment.drain().await.unwrap();
            let proof = fixture.enrollment.contain_owned_resources().await.unwrap();
            fixture
                .enrollment
                .release_after_containment(proof)
                .await
                .unwrap();
            assert!(fixture.log.lock().unwrap()[boundary..].iter().all(|r| {
                !matches!(
                    r["method"].as_str(),
                    Some("Target.closeTarget" | "Target.disposeBrowserContext")
                )
            }));
            fixture.close().await;
        }
    }
    #[tokio::test]
    async fn ordinary_persistent_close_never_inherits_explicit_restart_authority() {
        let fixture = make_fixture("persistent").await;
        fixture.enrollment.seal();
        fixture.enrollment.drain().await.unwrap();
        let proof = fixture.enrollment.contain_owned_resources().await.unwrap();
        fixture
            .enrollment
            .release_after_containment(proof)
            .await
            .unwrap();
        assert!(fixture.log.lock().unwrap().iter().all(|r| {
            !matches!(
                r["method"].as_str(),
                Some("Target.closeTarget" | "Target.disposeBrowserContext" | "Target.createTarget")
            )
        }));
        fixture.close().await;
    }
    #[tokio::test]
    async fn failed_explicit_persistent_restart_does_not_give_cleanup_host_close_rights() {
        for mode in ["persistent-close-failed", "persistent-create-no-ack"] {
            let mut fixture = make_fixture(mode).await;
            if mode.ends_with("create-no-ack") {
                fixture.operation.deadline = Instant::now() + Duration::from_millis(100);
            }
            let permit = exclusive(&fixture).await;
            let context = context(&fixture, &permit);
            let failure = match replace_pages(&context).await {
                Ok(_) => panic!("failed persistent restart produced proof"),
                Err(failure) => failure,
            };
            assert!(failure.effects_started && failure.cleanup_integrity_lost);
            if mode.ends_with("create-no-ack") {
                assert!(failure.create_outcome_unknown);
            } else {
                assert_eq!(failure.pending_close_target.as_deref(), Some("host-page"));
            }
            drop(context);
            drop(permit);
            let boundary = fixture.log.lock().unwrap().len();
            fixture.enrollment.seal();
            // The original error can remain stored; containment still must use
            // only borrowed-session cleanup, never the expired close permit.
            let _ = fixture.enrollment.drain().await;
            let proof = fixture.enrollment.contain_owned_resources().await.unwrap();
            fixture
                .enrollment
                .release_after_containment(proof)
                .await
                .unwrap();
            assert!(fixture.log.lock().unwrap()[boundary..].iter().all(|r| {
                !matches!(
                    r["method"].as_str(),
                    Some("Target.closeTarget" | "Target.disposeBrowserContext")
                )
            }));
            fixture.close().await;
        }
    }
    #[tokio::test]
    async fn persistent_restart_permit_rejects_wrong_owner_ui_operation_and_expiry() {
        let mut fixture = make_fixture("persistent").await;
        let other = make_fixture("persistent").await;
        let permit = exclusive(&fixture).await;
        let other_permit = exclusive(&other).await;
        assert!(RestartContext::new_persistent(
            &fixture.page,
            &fixture.enrollment,
            &other.ui,
            &other_permit,
            &fixture.operation
        )
        .is_err());
        assert!(RestartContext::new_persistent(
            &fixture.page,
            &other.enrollment,
            &fixture.ui,
            &permit,
            &fixture.operation
        )
        .is_err());
        fixture.page.identity_scope = "wrong-scope".into();
        assert!(RestartContext::new_persistent(
            &fixture.page,
            &fixture.enrollment,
            &fixture.ui,
            &permit,
            &fixture.operation
        )
        .is_err());
        fixture.page.identity_scope = "same-scope".into();
        fixture.page.target_id = "foreign".into();
        assert!(RestartContext::new_persistent(
            &fixture.page,
            &fixture.enrollment,
            &fixture.ui,
            &permit,
            &fixture.operation
        )
        .is_err());
        fixture.page.target_id = "old-page".into();
        let mut context = context(&fixture, &permit);
        let other_operation = OperationLease {
            generation: fixture.operation.generation,
            sequence: fixture.operation.sequence + 1,
            is_callback: false,
            deadline: fixture.operation.deadline,
            cancellation: fixture.operation.cancellation.clone(),
        };
        context.operation = &other_operation;
        assert!(context.check().is_err());
        let expired = OperationLease {
            generation: fixture.operation.generation,
            sequence: fixture.operation.sequence,
            is_callback: false,
            deadline: Instant::now(),
            cancellation: fixture.operation.cancellation.clone(),
        };
        context.operation = &expired;
        assert_eq!(context.check(), Err(ProtocolError::DeadlineExceeded));
        context.operation = &fixture.operation;
        fixture.cancellation.send_replace(CancelSignal::Requested);
        assert_eq!(context.check(), Err(ProtocolError::Cancelled));
        assert!(!fixture.log.lock().unwrap().iter().any(|r| matches!(
            r["method"].as_str(),
            Some("Target.closeTarget" | "Target.createTarget")
        )));
        drop(context);
        drop(permit);
        drop(other_permit);
        fixture.close().await;
        other.close().await;
    }
    #[tokio::test]
    async fn changed_target_inventory_rejects_before_close_dispatch() {
        for mode in [
            "wrong-context",
            "replaced-inventory",
            "persistent-wrong-context",
            "persistent-replaced-inventory",
        ] {
            let fixture = make_fixture(mode).await;
            let permit = exclusive(&fixture).await;
            let failure = match replace_pages(&context(&fixture, &permit)).await {
                Ok(_) => panic!("changed target produced restart proof"),
                Err(failure) => failure,
            };
            assert_eq!(failure.error, ProtocolError::StaleScope);
            assert!(!failure.effects_started);
            assert!(!fixture.log.lock().unwrap().iter().any(|request| {
                matches!(
                    request["method"].as_str(),
                    Some("Target.closeTarget" | "Target.createTarget")
                )
            }));
            drop(permit);
            fixture.close().await;
        }
    }
    #[tokio::test]
    async fn restart_failure_preserves_exact_close_or_create_ownership_without_success_proof() {
        for mode in [
            "close-failed",
            "create-no-ack",
            "reused-target",
            "reused-session",
        ] {
            let mut fixture = make_fixture(mode).await;
            if mode == "create-no-ack" {
                fixture.operation.deadline = Instant::now() + Duration::from_millis(100);
            }
            let permit = exclusive(&fixture).await;
            let context = context(&fixture, &permit);
            let failure = match replace_pages(&context).await {
                Ok(_) => panic!("unexpected restart proof"),
                Err(failure) => failure,
            };
            assert!(failure.effects_started && failure.cleanup_integrity_lost);
            assert_eq!(failure.identity_scope, "same-scope");
            if mode == "close-failed" {
                assert_eq!(failure.pending_close_target.as_deref(), Some("old-page"));
                assert!(failure.closed_targets.is_empty());
            } else {
                assert_eq!(failure.closed_targets, vec!["old-page"]);
            }
            if mode == "create-no-ack" {
                assert!(failure.create_outcome_unknown);
                assert!(failure.replacement_target.is_none());
            }
            assert!(fixture.page.targets.inventory().is_err());
            drop(context);
            drop(permit);
            fixture.close().await;
        }
    }
}
