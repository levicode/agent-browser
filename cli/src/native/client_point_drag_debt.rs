//! Private transaction debt. No Drop task and no independent cleanup budget.
use super::*;
use super::super::cdp::client::{BoundedMethodEvents, CdpClient, DragInterceptionReceipt};
use super::super::client_targets::OwnedTarget;

/// Non-cloneable application capability. State retains the same tenure on cancellation.
pub(crate) struct PointDragToken(pub(super) Arc<Mutex<PointDragDebt>>);
/// Minted only after this transaction's full cleanup and atomic receiver seal.
/// Fields stay private here; a command-status list alone cannot forge this proof.
pub(crate) struct PointDragCleanupProof {
    journal: OperationJournalHandle,
    session: String,
    rejected: Vec<CommandStatusHandle>,
}
impl PointDragCleanupProof {
    #[cfg(test)]
    pub(crate) fn for_test(journal: OperationJournalHandle, session: String, rejected: Vec<CommandStatusHandle>) -> Self {
        Self { journal, session, rejected }
    }
    pub(crate) fn into_parts(self) -> (OperationJournalHandle, String, Vec<CommandStatusHandle>) {
        (self.journal, self.session, self.rejected)
    }
}
struct ObserverCleanup {
    session: String,
    method: &'static str,
    params: Value,
    status: Option<CommandStatusHandle>,
    realm: Option<Arc<super::super::client_enrollment::ExactRealmTicket>>,
    reply_validated: bool,
    terminal_failed: bool,
}
#[derive(Clone, Copy)]
enum ProbeObservation { NoMove, NoDrag, Drag }
impl ProbeObservation {
    fn decode(value: &Value) -> Option<Self> {
        if value.get("exceptionDetails").is_some() { return None; }
        match value["result"]["value"].as_str()? {
            "no-move" => Some(Self::NoMove), "no-drag" => Some(Self::NoDrag),
            "drag" => Some(Self::Drag), _ => None,
        }
    }
}
struct RetainedProbe {
    session: String,
    object: String,
    realm: Arc<super::super::client_enrollment::ExactRealmTicket>,
    cycle: u64,
    arm_status: Option<CommandStatusHandle>,
    arm_value: Option<bool>,
    finish_status: Option<CommandStatusHandle>,
    finish_value: Option<ProbeObservation>,
}
#[derive(Clone)]
struct PendingDragCommand {
    status: CommandStatusHandle,
    dropped: bool,
    disabled: bool,
    may_start_drag: bool,
    observation_was_pending: bool,
    observation_was_finishable: bool,
    application_input: bool,
}
pub(super) struct PointDragDebt {
    key: OperationKey,
    journal: OperationJournalHandle,
    rejected_input: Vec<CommandStatusHandle>,
    realms: Arc<super::super::client_enrollment::PointDragRealms>,
    probe_cycle: u64,
    probes: Vec<RetainedProbe>,
    attachment: OwnedTarget,
    targets: Arc<super::super::client_targets::ClientTargets>,
    session: String,
    receipt: DragInterceptionReceipt,
    _events: Arc<tokio::sync::Mutex<BoundedMethodEvents>>,
    frozen: bool,
    sealed: bool,
    expected_positive: bool,
    observation_pending: bool,
    observation_finishable: bool,
    enable_submitted: bool,
    disabled: bool,
    drop_acknowledged: bool,
    cancel_acknowledged: bool,
    primary_failed: bool,
    cleanup_failed: bool,
    left_release_debt: bool,
    pending: Vec<PendingDragCommand>,
    input_releases: Option<(Vec<ObserverCleanup>, InputState)>,
    cancel_status: Option<CommandStatusHandle>,
    disable_status: Option<CommandStatusHandle>,
    observers: Vec<ObserverCleanup>,
}
fn lock(debt: &Arc<Mutex<PointDragDebt>>) -> Result<MutexGuard<'_, PointDragDebt>, ProtocolError> {
    debt.lock().map_err(|_| ProtocolError::CleanupFailed)
}
impl ClientPageState {
    #[cfg(test)]
    pub(crate) fn point_drag_rejected_statuses_for_test(&self, generation: u64, sequence: u64) -> Result<Vec<client_debt::CommandStatus>, ProtocolError> {
        let debt = self.state()?.point_drag.clone().ok_or(ProtocolError::ScopeUnavailable)?;
        let d = lock(&debt)?;
        if d.key.generation != generation || d.key.operation_seq != sequence || d.journal.key() != d.key {
            return Err(ProtocolError::StaleScope);
        }
        Ok(d.rejected_input.iter().map(CommandStatusHandle::snapshot).collect())
    }
    pub(super) fn point_drag_frozen(&self) -> Result<bool, ProtocolError> {
        let debt = self.state()?.point_drag.clone();
        match debt { Some(debt) => { let frozen = lock(&debt)?.frozen; Ok(frozen) }, None => Ok(false) }
    }
    pub(crate) fn begin_point_drag(
        &self, page: &BrowserExecutionLease, op: &OperationLease,
        receipt: DragInterceptionReceipt,
        events: Arc<tokio::sync::Mutex<BoundedMethodEvents>>,
        realms: Arc<super::super::client_enrollment::PointDragRealms>,
    ) -> Result<PointDragToken, ProtocolError> {
        self.validate(page, op)?;
        let journal = OperationJournalHandle::current().ok_or(ProtocolError::ScopeUnavailable)?;
        let key = journal.key();
        if key.generation != op.generation || key.operation_seq != op.sequence {
            return Err(ProtocolError::StaleScope);
        }
        let attachment = page.targets.owned_target(&page.target_id)?;
        if attachment.session_id != page.page_session_id { return Err(ProtocolError::StaleScope); }
        let mut state = self.state()?;
        if state.point_drag.is_some() || state.input_cleanup.is_some() { return Err(ProtocolError::ScopeUnavailable); }
        bind_input_session(&mut state.input, &page.page_session_id)?;
        let debt = Arc::new(Mutex::new(PointDragDebt {
            key, journal, rejected_input: Vec::new(), realms, probe_cycle: 0, probes: Vec::new(), attachment, targets: page.targets.clone(), session: page.page_session_id.clone(), receipt, _events: events,
            frozen: false, sealed: false, expected_positive: false, observation_pending: false, observation_finishable: false, enable_submitted: false,
            disabled: false, drop_acknowledged: false, cancel_acknowledged: false, primary_failed: false, cleanup_failed: false, left_release_debt: false, pending: Vec::new(),
            cancel_status: None, disable_status: None, observers: Vec::new(), input_releases: None,
        }));
        state.point_drag = Some(debt.clone());
        Ok(PointDragToken(debt))
    }
    fn check_point_drag(&self, page: &BrowserExecutionLease, op: &OperationLease, token: &PointDragToken) -> Result<(), ProtocolError> {
        self.validate(page, op)?;
        if !self.state()?.point_drag.as_ref().is_some_and(|debt| Arc::ptr_eq(debt, &token.0)) { return Err(ProtocolError::StaleScope); }
        let debt = lock(&token.0)?;
        if debt.frozen || debt.key.generation != op.generation || debt.key.operation_seq != op.sequence
            || OperationJournalHandle::current().is_none_or(|j| j.key() != debt.key)
            || debt.session != page.page_session_id
            || !debt.attachment.same_attachment(&page.targets.owned_target(&page.target_id)?) {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    pub(crate) fn point_drag_expected_positive(&self, page: &BrowserExecutionLease, op: &OperationLease, token: &PointDragToken) -> Result<(), ProtocolError> {
        if self.identity_scope != page.identity_scope || !self.state()?.point_drag.as_ref().is_some_and(|d| Arc::ptr_eq(d, &token.0)) { return Err(ProtocolError::StaleScope); }
        let mut debt = lock(&token.0)?;
        if debt.key.generation != op.generation || debt.key.operation_seq != op.sequence { return Err(ProtocolError::StaleScope); }
        debt.expected_positive = true;
        debt.observation_pending = false;
        Ok(())
    }
    /// Only an exact task-completion negative receipt may discharge this uncertainty.
    pub(crate) fn point_drag_observed_negative(&self, page: &BrowserExecutionLease, op: &OperationLease, token: &PointDragToken) -> Result<(), ProtocolError> {
        if self.identity_scope != page.identity_scope || !self.state()?.point_drag.as_ref().is_some_and(|d| Arc::ptr_eq(d, &token.0)) { return Err(ProtocolError::StaleScope); }
        let mut debt = lock(&token.0)?;
        if debt.key.generation != op.generation || debt.key.operation_seq != op.sequence || debt.expected_positive || debt.receipt.observed_on(&debt.session) { return Err(ProtocolError::StaleScope); }
        debt.observation_pending = false;
        Ok(())
    }
    /// Playwright's logical button-up before drop; not physical mouseReleased evidence.
    /// A failed/unacknowledged drop remains transaction debt even after this update.
    pub(crate) fn point_drag_logical_release(&self, page: &BrowserExecutionLease, op: &OperationLease, token: &PointDragToken) -> Result<(), ProtocolError> {
        self.check_point_drag(page, op, token)?;
        if !lock(&token.0)?.receipt.observed_on(&page.page_session_id) { return Err(ProtocolError::ScopeUnavailable); }
        lock(&token.0)?.left_release_debt = true;
        self.state()?.input.mouse.buttons &= !1;
        Ok(())
    }
    /// Register the exact object before arming any listener. Creation itself must
    /// be side-effect free and accounted by the caller's original object group.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_point_drag_observer(&self, page: &BrowserExecutionLease, op: &OperationLease, token: &PointDragToken, session: String, object_id: String, object_group: String, realm: Arc<super::super::client_enrollment::ExactRealmTicket>) -> Result<(), ProtocolError> {
        // Adoption is cleanup bookkeeping, not a new application submission.
        // Accept a cancelled/expired operation's returned object before its caller postchecks.
        if self.identity_scope != page.identity_scope
            || !self.state()?.point_drag.as_ref().is_some_and(|d| Arc::ptr_eq(d, &token.0)) {
            return Err(ProtocolError::StaleScope);
        }
        let mut debt = lock(&token.0)?;
        if debt.key.generation != op.generation || debt.key.operation_seq != op.sequence || debt.frozen {
            return Err(ProtocolError::StaleScope);
        }
        if debt.observers.len() >= 128 || object_id.is_empty() || object_group.is_empty() { return Err(ProtocolError::CapacityExceeded); }
        debt.probes.push(RetainedProbe { session: session.clone(), object: object_id.clone(), realm: realm.clone(), cycle: 0, arm_status: None, arm_value: None, finish_status: None, finish_value: None });
        debt.observers.push(ObserverCleanup { session: session.clone(), method: "Runtime.callFunctionOn", params: json!({"objectId":object_id,"functionDeclaration":"function(){return this.dispose()}","returnByValue":true,"awaitPromise":true}), status: None, reply_validated: false, terminal_failed: false, realm: Some(realm.clone()) });
        debt.observers.push(ObserverCleanup { session, method: "Runtime.releaseObjectGroup", params: json!({"objectGroup":object_group}), status: None, reply_validated: false, terminal_failed: false, realm: Some(realm) });
        Ok(())
    }
    pub(crate) async fn point_drag_observer_command(&self, page: &BrowserExecutionLease, op: &OperationLease, token: &PointDragToken, session: &str, method: &str, params: Value) -> Result<Value, ProtocolError> {
        self.check_point_drag(page, op, token)?;
        let arm = match params["functionDeclaration"].as_str() {
            Some("function(){return this.arm()}") => true,
            Some("function(){return this.finish()}") => false,
            _ => return Err(ProtocolError::InvalidArguments),
        };
        let index = {
            let d = lock(&token.0)?;
            if method != "Runtime.callFunctionOn" { return Err(ProtocolError::InvalidArguments); }
            d.probes.iter().position(|p| p.session == session && params["objectId"].as_str() == Some(p.object.as_str())).ok_or(ProtocolError::StaleScope)?
        };
        let reservation = client_debt::command_scope(CommandCategory::ApplicationRead, false, async {
            page.client.reserve_tracked_command(method, Some(&params), Some(session))
        }).await.map_err(|_| ProtocolError::BrowserFailure)?.ok_or(ProtocolError::ScopeUnavailable)?;
        let status = reservation.status();
        {
            let mut d = lock(&token.0)?;
            if d.frozen || !d.pending.is_empty() { return Err(ProtocolError::ScopeUnavailable); }
            if arm && index == 0 {
                if d.observation_pending || d.expected_positive { return Err(ProtocolError::ScopeUnavailable); }
                d.probe_cycle = d.probe_cycle.checked_add(1).ok_or(ProtocolError::CapacityExceeded)?;
                let cycle = d.probe_cycle;
                for probe in &mut d.probes {
                    probe.cycle = cycle; probe.arm_status = None; probe.arm_value = None;
                    probe.finish_status = None; probe.finish_value = None;
                }
            }
            if d.probe_cycle == 0 || d.probes[index].cycle != d.probe_cycle { return Err(ProtocolError::ScopeUnavailable); }
            let probe = &mut d.probes[index];
            if arm {
                if probe.arm_status.is_some() { return Err(ProtocolError::ScopeUnavailable); }
                probe.arm_status = Some(status.clone());
            } else {
                if probe.arm_value != Some(true) || probe.finish_status.is_some() { return Err(ProtocolError::ScopeUnavailable); }
                probe.finish_status = Some(status.clone());
            }
            d.pending.push(PendingDragCommand { status: status.clone(), dropped: false, disabled: false, may_start_drag: false, observation_was_pending: false, observation_was_finishable: false, application_input: false });
        }
        let value = bounded(page, op, async {
            let value = page.client.send_reserved_command(method, Some(params), Some(session), Some(reservation)).await?;
            // Store decoded evidence BEFORE bounded's postcheck can observe a
            // simultaneous cancellation. Missing Value after submission is never replayable.
            let mut d = lock(&token.0).map_err(|_| "point probe state unavailable".to_owned())?;
            let probe = &mut d.probes[index];
            if arm { probe.arm_value = if value.get("exceptionDetails").is_none() { value["result"]["value"].as_bool() } else { None }; }
            else { probe.finish_value = ProbeObservation::decode(&value); }
            Ok(value)
        }).await?;
        status.wait_successful_ack(op.deadline).await?;
        lock(&token.0)?.pending.clear();
        Ok(value)
    }
    pub(crate) async fn point_drag_command(&self, page: &BrowserExecutionLease, op: &OperationLease, token: &PointDragToken, method: &str, mut params: Value) -> Result<Value, ProtocolError> {
        self.check_point_drag(page, op, token)?;
        if !matches!(method, "Input.setInterceptDrags" | "Input.dispatchDragEvent" | "Input.dispatchMouseEvent") { return Err(ProtocolError::InvalidArguments); }
        if method == "Input.dispatchDragEvent" {
            params.as_object_mut().ok_or(ProtocolError::InvalidArguments)?.insert("modifiers".into(), json!(modifiers(&self.state()?.input)));
        }
        let enable = method == "Input.setInterceptDrags" && params.get("enabled") == Some(&Value::Bool(true));
        let disable = method == "Input.setInterceptDrags" && params.get("enabled") == Some(&Value::Bool(false));
        let drop = method == "Input.dispatchDragEvent" && params.get("type").and_then(Value::as_str) == Some("drop");
        if method == "Input.dispatchDragEvent" && !lock(&token.0)?.receipt.observed_on(&page.page_session_id) { return Err(ProtocolError::ScopeUnavailable); }
        let drag_point = if method == "Input.dispatchDragEvent" {
            let x = params.get("x").and_then(Value::as_f64).filter(|x| x.is_finite()).ok_or(ProtocolError::InvalidArguments)?;
            let y = params.get("y").and_then(Value::as_f64).filter(|y| y.is_finite()).ok_or(ProtocolError::InvalidArguments)?;
            let mut state = self.state()?;
            state.input.mouse.x = x;
            state.input.mouse.y = y;
            state.input.pointer_known = false;
            Some((x, y))
        } else { None };
        let reservation = client_debt::command_scope(CommandCategory::ApplicationInput, method != "Input.setInterceptDrags", async {
            page.client.reserve_tracked_command(method, Some(&params), Some(&page.page_session_id))
        }).await.map_err(|_| ProtocolError::BrowserFailure)?.ok_or(ProtocolError::ScopeUnavailable)?;
        let status = reservation.status();
        let held_left_move = method == "Input.dispatchMouseEvent"
            && params.get("type").and_then(Value::as_str) == Some("mouseMoved")
            && self.state()?.input.mouse.buttons & 1 != 0;
        {
            let mut debt = lock(&token.0)?;
            if debt.frozen { return Err(ProtocolError::ScopeUnavailable); }
            if !debt.pending.is_empty() { return Err(ProtocolError::ScopeUnavailable); }
            // Only a held-left movement can create unresolved native-drag
            // observation. Enabling interception alone cannot start a drag.
            let may_start_drag = held_left_move && debt.enable_submitted && !debt.disabled
                && !debt.receipt.observed_on(&debt.session);
            let observation_was_pending = debt.observation_pending;
            let observation_was_finishable = debt.observation_finishable;
            debt.pending.push(PendingDragCommand { status: status.clone(), dropped: drop, disabled: disable, may_start_drag, observation_was_pending, observation_was_finishable, application_input: true });
            if may_start_drag { debt.observation_pending = true; debt.observation_finishable = false; }
            if enable { debt.enable_submitted = true; debt.disabled = false; }
        }
        let value = bounded(page, op, page.client.send_reserved_command(method, Some(params), Some(&page.page_session_id), Some(reservation))).await?;
        status.wait_successful_ack(op.deadline).await?;
        let mut debt = lock(&token.0)?;
        if debt.pending.iter().any(|p| p.may_start_drag) { debt.observation_finishable = true; }
        debt.pending.clear();
        if disable { debt.disabled = true; }
        if drop { debt.drop_acknowledged = true; }
        std::mem::drop(debt);
        if let Some((x, y)) = drag_point {
            let mut state = self.state()?;
            if state.input.session.as_deref() == Some(page.page_session_id.as_str()) && state.input.mouse.x == x && state.input.mouse.y == y {
                state.input.pointer_known = true;
            }
        }
        Ok(value)
    }
    /// Final application teardown uses the ORIGINAL action deadline, not cleanup's 2s.
    pub(crate) async fn finish_point_drag(&self, page: &BrowserExecutionLease, op: &OperationLease, token: PointDragToken) -> Result<(), ProtocolError> {
        self.check_point_drag(page, op, &token)?;
        {
            let debt = lock(&token.0)?;
            if debt.primary_failed || debt.cleanup_failed || !debt.pending.is_empty() || (debt.enable_submitted && !debt.disabled)
                || (debt.receipt.observed_on(&debt.session) && !debt.drop_acknowledged)
                || ((debt.expected_positive || debt.observation_pending) && !debt.receipt.observed_on(&debt.session)) { return Err(ProtocolError::CleanupFailed); }
        }
        self.teardown_point_drag_observers(&page.client, &token.0, op.deadline).await?;
        self.check_point_drag(page, op, &token)?;
        seal_point_drag(&token.0, op.deadline, false).await?;
        self.check_point_drag(page, op, &token)?;
        self.state()?.point_drag = None;
        Ok(())
    }
    async fn teardown_point_drag_observers(&self, client: &CdpClient, debt: &Arc<Mutex<PointDragDebt>>, deadline: Instant) -> Result<(), ProtocolError> {
        let count = lock(debt)?.observers.len();
        for index in 0..count {
            if lock(debt)?.observers[index].terminal_failed { continue; }
            if lock(debt)?.observers[index].realm.as_ref().is_some_and(|realm| realm.destroyed().is_ok_and(|destroyed| destroyed)) { continue; }
            let (session, method, params, previous) = {
                let d = lock(debt)?; let o = &d.observers[index];
                // A late successful Runtime envelope alone does not prove no
                // JavaScript exception. Without its validated reply, retain debt.
                if o.status.as_ref().is_some_and(|status| !status.has_validated_error_reply()) && !o.reply_validated { return Err(ProtocolError::CleanupFailed); }
                (o.session.clone(), o.method, o.params.clone(), o.status.clone())
            };
            let result = strict_cleanup_command(client, &session, method, params, previous, deadline, |status| {
                lock(debt)?.observers[index].status = Some(status); Ok(())
            }).await;
            match result {
                Ok(()) => lock(debt)?.observers[index].reply_validated = true,
                Err(error) => {
                    let mut d = lock(debt)?;
                    if error.terminal {
                        d.cleanup_failed = true;
                        d.observers[index].terminal_failed = true;
                    } else { return Err(error.error); }
                }
            }
        }
        Ok(())
    }
    /// Freeze and drain before cancel/disable. Never cancel based on renderer evidence alone.
    async fn prepare_point_drag_cleanup(&self, client: &CdpClient, session: &str, deadline: Instant) -> Result<Option<Arc<Mutex<PointDragDebt>>>, ProtocolError> {
        let Some(debt) = self.state()?.point_drag.clone() else { return Ok(None); };
        let pending = {
            let mut d = lock(&debt)?;
            d.frozen = true;
            if d.session != session || !d.attachment.same_attachment(&d.targets.owned_target(&d.attachment.target_id).map_err(|_| ProtocolError::CleanupFailed)?) { return Err(ProtocolError::CleanupFailed); }
            d.pending.clone()
        };
        for pending in pending {
            if let Err(error) = pending.status.wait_successful_ack(deadline).await {
                // Abandoned is minted only by CommandReservation::drop while
                // !submitted (client_debt.rs); Reserved/Destroyed/EOF are NOT
                // equivalent proof. An explicit error ACK is terminal failure,
                // not successful movement, drop, disable, or cleanup.
                let never_submitted = pending.status.snapshot() == client_debt::CommandStatus::Abandoned;
                if pending.status.has_validated_error_reply() || never_submitted {
                    let mut d = lock(&debt)?;
                    d.primary_failed = true;
                    // A generic error ACK does not establish non-injection. Only
                    // exact never-submitted proof can undo movement observation
                    // debt; error ACK is NOT a renderer-negative receipt.
                    if never_submitted && pending.may_start_drag {
                        d.observation_pending = pending.observation_was_pending;
                        d.observation_finishable = pending.observation_was_finishable;
                    }
                    if pending.application_input && pending.status.snapshot() == client_debt::CommandStatus::RetainedRejected { d.rejected_input.push(pending.status.clone()); }
                    continue;
                }
                return Err(error);
            }
            let mut d = lock(&debt)?;
            d.drop_acknowledged |= pending.dropped;
            d.disabled |= pending.disabled;
            if pending.may_start_drag { d.observation_finishable = true; }
        }
        lock(&debt)?.pending.clear();
        // Observation failure must not prevent safe cancel/disable/release. Its
        // unresolved bit stays set and prevents cleanupcomplete at the final fence.
        let _ = self.settle_point_drag_observation(client, session, &debt, deadline).await;
        self.cancel_owned_point_drag(client, session, &debt, deadline).await?;
        let (enabled, disabled, disable_status) = {
            let d = lock(&debt)?;
            (d.enable_submitted, d.disabled, d.disable_status.clone())
        };
        if enabled && !disabled {
            let result = strict_cleanup_command(client, session, "Input.setInterceptDrags", json!({"enabled":false}), disable_status, deadline, |status| { lock(&debt)?.disable_status = Some(status); Ok(()) }).await;
            match result {
                Ok(()) => lock(&debt)?.disabled = true,
                Err(error) => {
                    let mut d = lock(&debt)?;
                    if error.terminal { d.cleanup_failed = true; } else { return Err(error.error); }
                }
            }
        }
        // An own event may first reach the reader while disable is awaiting ACK.
        // Its new authority permits one supplemental cancellation of OUR drag;
        // no earlier unknown/foreign drag was cancelled and no command is replayed.
        self.cancel_owned_point_drag(client, session, &debt, deadline).await?;
        Ok(Some(debt))
    }
    async fn settle_point_drag_observation(&self, client: &CdpClient, session: &str, debt: &Arc<Mutex<PointDragDebt>>, deadline: Instant) -> Result<(), ProtocolError> {
        let (realms, tickets, count, cycle) = {
            let d = lock(debt)?;
            if !d.observation_pending || d.receipt.observed_on(session) { return Ok(()); }
            // Recovery reads are limited to an ACKed original movement. A
            // rejected move without own evidence remains the negative control.
            if !d.observation_finishable { return Err(ProtocolError::CleanupFailed); }
            (d.realms.clone(), d.probes.iter().map(|p| p.realm.clone()).collect::<Vec<_>>(), d.probes.len(), d.probe_cycle)
        };
        if count == 0 || cycle == 0 { return Err(ProtocolError::CleanupFailed); }
        realms.verify_cleanup(client, session, deadline, &tickets).await?;
        let mut complete = true;
        let mut positive = false;
        for index in 0..count {
            let (probe_session, object, arm_status, arm_value, previous, value, probe_cycle) = {
                let d = lock(debt)?; let p = &d.probes[index];
                (p.session.clone(), p.object.clone(), p.arm_status.clone(), p.arm_value, p.finish_status.clone(), p.finish_value, p.cycle)
            };
            if probe_cycle != cycle || arm_value != Some(true) { complete = false; continue; }
            let Some(arm_status) = arm_status else { complete = false; continue; };
            if arm_status.wait_successful_ack(deadline).await.is_err() { complete = false; continue; }
            let observed = if let Some(value) = value {
                let Some(previous) = previous.as_ref() else { complete = false; continue; };
                if previous.wait_successful_ack(deadline).await.is_err() { complete = false; continue; }
                Some(value)
            } else {
                // Only never-submitted finish can be invoked here. A reader ACK
                // without the retained result is not a negative observation.
                if previous.as_ref().is_some_and(|s| s.snapshot() != client_debt::CommandStatus::Abandoned) { complete = false; continue; }
                if Instant::now() >= deadline { complete = false; continue; }
                let params = json!({"objectId":object,"functionDeclaration":"function(){return this.finish()}","returnByValue":true,"awaitPromise":true});
                let reservation = client_debt::command_scope(CommandCategory::CleanupObject, false, async {
                    client.reserve_tracked_command("Runtime.callFunctionOn", Some(&params), Some(&probe_session))
                }).await.map_err(|_| ProtocolError::CleanupFailed)?.ok_or(ProtocolError::CleanupFailed)?;
                let status = reservation.status();
                lock(debt)?.probes[index].finish_status = Some(status.clone());
                let reply = tokio::time::timeout_at(deadline.into(), client.send_reserved_command("Runtime.callFunctionOn", Some(params), Some(&probe_session), Some(reservation))).await;
                match reply {
                    Ok(Ok(value)) => {
                        let decoded = ProbeObservation::decode(&value);
                        lock(debt)?.probes[index].finish_value = decoded;
                        if decoded.is_none() || status.wait_successful_ack(deadline).await.is_err() {
                            lock(debt)?.cleanup_failed = true;
                            complete = false; continue;
                        }
                        decoded
                    }
                    _ => { lock(debt)?.cleanup_failed = true; complete = false; continue; }
                }
            };
            match observed { Some(ProbeObservation::Drag) => positive = true, Some(_) => {}, None => complete = false }
        }
        // Positive native evidence remains a cleanup constraint even if a sibling
        // loses its realm; it never alone authorizes cancellation of a foreign drag.
        if positive { lock(debt)?.expected_positive = true; }
        realms.verify_cleanup(client, session, deadline, &tickets).await?;
        if !complete { return Err(ProtocolError::CleanupFailed); }
        lock(debt)?.observation_pending = false;
        Ok(())
    }
    async fn cancel_owned_point_drag(&self, client: &CdpClient, session: &str, debt: &Arc<Mutex<PointDragDebt>>, deadline: Instant) -> Result<(), ProtocolError> {
        let previous = {
            let d = lock(debt)?;
            if d.session != session { return Err(ProtocolError::CleanupFailed); }
            if !d.receipt.observed_on(session) || d.drop_acknowledged || d.cancel_acknowledged { return Ok(()); }
            if !d.attachment.same_attachment(&d.targets.owned_target(&d.attachment.target_id).map_err(|_| ProtocolError::CleanupFailed)?) { return Err(ProtocolError::CleanupFailed); }
            d.cancel_status.clone()
        };
        let input = self.state()?.input.clone();
        let result = strict_cleanup_command(client, session, "Input.dispatchDragEvent", json!({"type":"dragCancel", "x":input.mouse.x, "y":input.mouse.y, "modifiers":modifiers(&input), "data":{"items":[],"dragOperationsMask":0}}), previous, deadline, |status| { lock(debt)?.cancel_status = Some(status); Ok(()) }).await;
        match result {
            Ok(()) => lock(debt)?.cancel_acknowledged = true,
            Err(error) => {
                let mut d = lock(debt)?;
                if error.terminal { d.cleanup_failed = true; } else { return Err(error.error); }
            }
        }
        Ok(())
    }
    pub(super) async fn cleanup_point_drag(&self, client: &CdpClient, session: &str, deadline: Instant) -> Result<(), ProtocolError> {
        let debt = self.prepare_point_drag_cleanup(client, session, deadline).await?.ok_or(ProtocolError::CleanupFailed)?;
        if lock(&debt)?.input_releases.is_none() {
            let mut input = self.state()?.input.clone();
            {
                let d = lock(&debt)?;
                if d.left_release_debt && !d.drop_acknowledged { input.mouse.buttons |= 1; }
            }
            let mut releases = Vec::new();
            for key in input.keys.clone().into_values() {
                input.keys.remove(&key.code);
                releases.push(ObserverCleanup { session: session.into(), method: "Input.dispatchKeyEvent", params: key_params(&key, false, false, modifiers(&input), false), status: None, reply_validated: false, terminal_failed: false, realm: None });
            }
            for (button, mask) in [("left",1),("right",2),("middle",4),("back",8),("forward",16)] {
                if input.mouse.buttons & mask == 0 { continue; }
                let params = build_mouse_event_params(&mut input.mouse, "mouseReleased", None, None, Some(button), None, Some(1), None, None, Some(0));
                releases.push(ObserverCleanup { session: session.into(), method: "Input.dispatchMouseEvent", params: serde_json::to_value(params).map_err(|_| ProtocolError::CleanupFailed)?, status: None, reply_validated: false, terminal_failed: false, realm: None });
            }
            lock(&debt)?.input_releases = Some((releases, input));
        }
        let count = lock(&debt)?.input_releases.as_ref().unwrap().0.len();
        for index in 0..count {
            let (method, params, status) = {
                let d = lock(&debt)?; let r = &d.input_releases.as_ref().unwrap().0[index];
                (r.method, r.params.clone(), r.status.clone())
            };
            let result = strict_cleanup_command(client, session, method, params, status, deadline, |status| {
                lock(&debt)?.input_releases.as_mut().unwrap().0[index].status = Some(status); Ok(())
            }).await;
            if let Err(error) = result {
                let mut d = lock(&debt)?;
                if error.terminal { d.cleanup_failed = true; } else { return Err(error.error); }
            }
        }
        self.teardown_point_drag_observers(client, &debt, deadline).await?;
        self.cancel_owned_point_drag(client, session, &debt, deadline).await?;
        let (clean, can_complete) = {
            let d = lock(&debt)?;
            let own = d.receipt.observed_on(session);
            let can_complete = !d.cleanup_failed
                && !((d.expected_positive || d.observation_pending) && !own)
                && (!own || d.drop_acknowledged || d.cancel_acknowledged);
            (d.input_releases.as_ref().unwrap().1.clone(), can_complete)
        };
        if !can_complete {
            // Preserve failure, but do not strand an own receipt that arrived
            // between the last cancellation check and the terminal snapshot.
            let _ = self.cancel_owned_point_drag(client, session, &debt, deadline).await;
            return Err(ProtocolError::CleanupFailed);
        }
        if let Err(error) = seal_point_drag(&debt, deadline, true).await {
            // The atomic fence may detect a late first own event. Best-effort
            // cancel it once within the SAME deadline; never retry seal or turn
            // overflow/duplicate/transport failure into cleanup success.
            let _ = self.cancel_owned_point_drag(client, session, &debt, deadline).await;
            return Err(error);
        }
        let proof = {
            let d = lock(&debt)?;
            PointDragCleanupProof { journal: d.journal.clone(), session: d.session.clone(), rejected: d.rejected_input.clone() }
        };
        let ledger = lock(&debt)?.journal.ledger();
        ledger.retire_point_drag_rejections(proof)?;
        let mut state = self.state()?;
        state.input = clean;
        state.point_drag = None;
        Ok(())
    }

}
/// Atomically close the exact healthy subscription at its expected count.
/// The receipt snapshot alone cannot close the late-event publication race.
async fn seal_point_drag(debt: &Arc<Mutex<PointDragDebt>>, deadline: Instant, cleanup: bool) -> Result<(), ProtocolError> {
    let (events, expected) = {
        let d = lock(debt)?;
        if d.sealed { return Ok(()); }
        let own = d.receipt.observed_on(&d.session);
        if d.cleanup_failed || (own && !d.drop_acknowledged && !d.cancel_acknowledged)
            || (!own && (d.expected_positive || d.observation_pending)) { return Err(ProtocolError::CleanupFailed); }
        (d._events.clone(), if own { 1 } else { 0 })
    };
    tokio::time::timeout_at(deadline.into(), async {
        let mut events = events.lock().await;
        let result = if cleanup { events.seal_for_cleanup(expected) } else { events.seal(expected) };
        result.map_err(|_| ProtocolError::CleanupFailed)
    }).await.map_err(|_| ProtocolError::CleanupFailed)??;
    lock(debt)?.sealed = true;
    Ok(())
}
/// A terminal failure permits later independent cleanup, but NEVER mints success.
struct StrictCleanupFailure {
    error: ProtocolError,
    terminal: bool,
}
impl StrictCleanupFailure {
    fn unknown(error: ProtocolError) -> Self { Self { error, terminal: false } }
    fn terminal() -> Self { Self { error: ProtocolError::CleanupFailed, terminal: true } }
}
async fn strict_status(status: &CommandStatusHandle, deadline: Instant) -> Result<(), StrictCleanupFailure> {
    status.wait_successful_ack(deadline).await.map_err(|error| {
        if status.has_validated_error_reply() { StrictCleanupFailure::terminal() } else { StrictCleanupFailure::unknown(error) }
    })
}
/// Persist a reservation before submission; re-entry waits for that exact command,
/// never replays cleanup after an uncertain write. Error ACK is not successful ACK.
async fn strict_cleanup_command(
    client: &CdpClient, session: &str, method: &str, params: Value,
    previous: Option<CommandStatusHandle>, deadline: Instant,
    save: impl FnOnce(CommandStatusHandle) -> Result<(), ProtocolError>,
) -> Result<(), StrictCleanupFailure> {
    if let Some(status) = previous { return strict_status(&status, deadline).await; }
    if Instant::now() >= deadline { return Err(StrictCleanupFailure::unknown(ProtocolError::CleanupFailed)); }
    let category = if method.starts_with("Runtime.") { CommandCategory::CleanupObject } else { CommandCategory::CleanupInput };
    let reservation = client_debt::command_scope(category, false, async {
        client.reserve_tracked_command(method, Some(&params), Some(session))
    }).await.map_err(|_| StrictCleanupFailure::unknown(ProtocolError::CleanupFailed))?.ok_or_else(|| StrictCleanupFailure::unknown(ProtocolError::CleanupFailed))?;
    let status = reservation.status();
    save(status.clone()).map_err(StrictCleanupFailure::unknown)?;
    let result = tokio::time::timeout_at(deadline.into(), client.send_reserved_command(method, Some(params), Some(session), Some(reservation))).await;
    match result {
        // A validated response with exceptionDetails is a known completed JS
        // failure. Retain that semantic result, don't reinterpret its success ACK.
        Ok(Ok(value)) if value.get("exceptionDetails").is_some() => {
            strict_status(&status, deadline).await?;
            return Err(StrictCleanupFailure::terminal());
        }
        Ok(Ok(_)) => {},
        _ if status.has_validated_error_reply() => return Err(StrictCleanupFailure::terminal()),
        _ => return Err(StrictCleanupFailure::unknown(ProtocolError::CleanupFailed)),
    }
    strict_status(&status, deadline).await
}
