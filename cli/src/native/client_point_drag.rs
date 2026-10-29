//! Point-drag passive probe foundation. Not wired into input execution yet.
//! The caller must own exact enrolled realm/object-group cleanup and keep the
//! original point action deadline; this module grants no input authority.

/// Allocate this object in an enrolled isolated realm, with an accounted
/// objectGroup. It deliberately installs no property on window/document and
/// does not inspect a node, selector, geometry, text, or DataTransfer payload.
/// arm/finish are invoked once around each original held mouse move.
pub(super) const CREATE_MOVE_PROBE: &str = r#"function() {
  let armed = false;
  let disposed = false;
  let moved = false;
  let drag = null;
  let timer = null;
  let pending = null;
  let settle = null;
  function onDrag(event) {
    if (event.isTrusted) drag = event;
  }
  function remove() {
    window.removeEventListener('mousemove', onMove, true);
    window.removeEventListener('dragstart', onDrag, true);
    if (timer !== null) { clearTimeout(timer); timer = null; }
  }
  function onMove(event) {
    if (!event.isTrusted) return;
    window.removeEventListener('mousemove', onMove, true);
    moved = true;
    window.addEventListener('dragstart', onDrag, {capture:true, passive:true});
    pending = new Promise(resolve => { settle = resolve; });
    // Native dragstart follows this move. This event-task receipt mirrors the
    // original engine, not a gesture delay or a retry of any input command.
    timer = setTimeout(() => {
      timer = null;
      const resolve = settle;
      settle = null;
      resolve();
    }, 0);
  }
  return {
    arm() {
      if (disposed || armed) throw new Error('point-drag-probe-state');
      armed = true;
      moved = false;
      drag = null;
      pending = null;
      window.addEventListener('mousemove', onMove, {capture:true, passive:true});
      return true;
    },
    async finish() {
      if (disposed || !armed) throw new Error('point-drag-probe-state');
      if (pending) await pending;
      if (disposed) throw new Error('point-drag-probe-disposed');
      const result = !moved ? 'no-move' :
        drag && !drag.defaultPrevented ? 'drag' : 'no-drag';
      remove();
      armed = false;
      drag = null;
      pending = null;
      return result;
    },
    dispose() {
      remove();
      disposed = true;
      armed = false;
      drag = null;
      const resolve = settle;
      settle = null;
      if (resolve) resolve();
      pending = null;
      return true;
    }
  };
}"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MoveObservation {
    NoMove,
    NoDrag,
    Drag,
}
impl MoveObservation {
    pub(super) fn decode(value: &str) -> Option<Self> {
        match value {
            "no-move" => Some(Self::NoMove),
            "no-drag" => Some(Self::NoDrag),
            "drag" => Some(Self::Drag),
            _ => None,
        }
    }
}

/// Only successfully settled exact-realm observations reach this function.
/// Missing/failed/destroyed realms are errors at the caller, never NoMove.
/// Sibling frames normally see no move. Same-point/outside-document movement
/// is not rejected solely because every healthy observer reported NoMove.
pub(super) fn expects_drag(observations: &[MoveObservation]) -> Option<bool> {
    if observations.is_empty() {
        return None;
    }
    Some(observations.contains(&MoveObservation::Drag))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sibling_realms_need_not_receive_the_mouse_move() {
        assert_eq!(expects_drag(&[MoveObservation::NoMove, MoveObservation::Drag]), Some(true));
        assert_eq!(expects_drag(&[MoveObservation::NoMove, MoveObservation::NoDrag]), Some(false));
    }
    #[test]
    fn degenerate_move_remains_pointer_only_but_missing_inventory_is_not_false() {
        assert_eq!(expects_drag(&[MoveObservation::NoMove]), Some(false));
        assert_eq!(expects_drag(&[]), None);
    }
    #[test]
    fn malformed_probe_result_does_not_become_no_drag() {
        for value in ["", "false", "destroyed", "cancelled", "unknown"] {
            assert_eq!(MoveObservation::decode(value), None);
        }
        assert_eq!(MoveObservation::decode("drag"), Some(MoveObservation::Drag));
    }
}

use super::{ActionRealmAuthority, DirectPointRunner, Point};
use super::super::cdp::client::BoundedCdpEvent;
use super::super::client_debt::{self, CommandCategory};
use super::super::client_enrollment::ExactRealmTicket;
use super::super::client_page::PointDragToken;
use super::super::client_protocol::ProtocolError;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Probe {
    session: String,
    object: String,
    realm: Arc<ExactRealmTicket>,
}

// Setup only allocates an inert closure. The observer is registered with the
// page's retained cleanup owner before arm can install any listener.
async fn setup_command(
    runner: &DirectPointRunner<'_, '_>,
    session: &str,
    method: &str,
    params: Value,
) -> Result<Value, ProtocolError> {
    runner.check()?;
    let ctx = runner.context;
    let mut cancelled = ctx.operation.cancellation.clone();
    let command = client_debt::command_scope(CommandCategory::ApplicationObject, false, async {
        ctx.page.client.send_action_command(method, Some(params), Some(session)).await
    });
    tokio::select! {
        result = command => result.map_err(|error| error.into_protocol(ctx.operation)),
        _ = cancelled.changed() => Err(ProtocolError::Cancelled),
        _ = tokio::time::sleep_until(ctx.operation.deadline.into()) => Err(ProtocolError::DeadlineExceeded),
    }
}

async fn probe_call(
    runner: &DirectPointRunner<'_, '_>,
    token: &PointDragToken,
    probe: &Probe,
    function: &str,
) -> Result<Value, ProtocolError> {
    let ctx = runner.context;
    let value = ctx.page_state.point_drag_observer_command(
        ctx.page, ctx.operation, token, &probe.session, "Runtime.callFunctionOn",
        json!({"objectId":probe.object,"functionDeclaration":function,
            "returnByValue":true,"awaitPromise":true}),
    ).await?;
    if value.get("exceptionDetails").is_some() {
        return Err(ProtocolError::BrowserFailure);
    }
    Ok(value["result"]["value"].clone())
}

async fn drag_event(
    runner: &DirectPointRunner<'_, '_>, token: &PointDragToken,
    kind: &str, point: Point, event: &BoundedCdpEvent,
) -> Result<(), ProtocolError> {
    runner.check()?;
    runner.dispatch.mark();
    let ctx = runner.context;
    ctx.page_state.point_drag_command(ctx.page, ctx.operation, token,
        "Input.dispatchDragEvent", json!({"type":kind,"x":point.x,"y":point.y,
            "data":event.params["data"]})).await?;
    runner.check()
}

pub(super) async fn execute(
    runner: &DirectPointRunner<'_, '_>, from: Point, to: Point, pace: Option<Duration>,
) -> Result<(), ProtocolError> {
    runner.check()?;
    let ctx = runner.context;
    let enrollment = match &ctx.realm_authority {
        ActionRealmAuthority::Enrolled(owner) => *owner,
        #[cfg(test)]
        ActionRealmAuthority::UntrackedFixture => return Err(ProtocolError::ScopeUnavailable),
    };
    let realms: super::super::client_enrollment::PointDragRealms = enrollment.capture_point_drag_realms(ctx.page, ctx.operation)?;
    let (events, receipt) = ctx.page.client
        .subscribe_drag_interception(&ctx.page.page_session_id, 1024 * 1024)
        .map_err(|_| ProtocolError::CapacityExceeded)?;
    let events = Arc::new(tokio::sync::Mutex::new(events));
    let token = ctx.page_state.begin_point_drag(ctx.page, ctx.operation, receipt, events.clone())?;
    let mut probes = Vec::new();
    for (index, binding) in realms.bindings().iter().enumerate() {
        let capture = enrollment.reserve_exact_realm(ctx.page, binding, ctx.operation)?;
        let world = setup_command(runner, &binding.session, "Page.createIsolatedWorld",
            json!({"frameId":binding.frame,"worldName":"agent-browser-native-observation"})).await?;
        let context = world["executionContextId"].as_i64().ok_or(ProtocolError::BrowserFailure)?;
        let realm = Arc::new(capture.bind(context, ctx.operation).await?);
        let group = format!("native-point-drag-{}-{}-{index}", ctx.operation.generation, ctx.operation.sequence);
        let value = setup_command(runner, &binding.session, "Runtime.evaluate",
            json!({"expression":format!("({CREATE_MOVE_PROBE})()"),"contextId":context,
                "objectGroup":group,"returnByValue":false})).await?;
        let object = value["result"]["objectId"].as_str().ok_or(ProtocolError::BrowserFailure)?.to_owned();
        // Adoption precedes cancellation/realm checks: cleanup authority may not
        // be discarded because the inert object's creation ACK arrived late.
        ctx.page_state.record_point_drag_observer(ctx.page, ctx.operation, &token,
            binding.session.clone(), object.clone(), group, realm.clone())?;
        if value.get("exceptionDetails").is_some() { return Err(ProtocolError::BrowserFailure); }
        realm.verify_resolution_owner(ctx.operation).await?;
        probes.push(Probe { session: binding.session.clone(), object, realm });
    }
    realms.verify(ctx.page, ctx.operation).await?;
    runner.event("mouseMoved", from, None, None).await?;
    runner.event("mousePressed", from, Some("left"), Some(1)).await?;
    let steps = pace.map(|value| (value.as_millis() / 16).max(2) as usize).unwrap_or(2);
    let start = Instant::now();
    let mut native_drag: Option<BoundedCdpEvent> = None;
    for step in 1..=steps {
        if let Some(pace) = pace {
            let due = start + pace.mul_f64(step as f64 / steps as f64);
            if let Some(wait) = due.checked_duration_since(Instant::now()) { runner.pause(wait).await?; }
        }
        let fraction = step as f64 / steps as f64;
        let point = Point { x:from.x + (to.x-from.x)*fraction, y:from.y+(to.y-from.y)*fraction }.validate()?;
        if let Some(event) = native_drag.as_ref() {
            drag_event(runner, &token, "dragOver", point, event).await?;
            continue;
        }
        for probe in &probes {
            if probe_call(runner, &token, probe, "function(){return this.arm()}").await? != Value::Bool(true) {
                return Err(ProtocolError::BrowserFailure);
            }
        }
        ctx.page_state.point_drag_command(ctx.page, ctx.operation, &token,
            "Input.setInterceptDrags", json!({"enabled":true})).await?;
        runner.event("mouseMoved", point, None, None).await?;
        let mut observations = Vec::new();
        for probe in &probes {
            let value = probe_call(runner, &token, probe, "function(){return this.finish()}").await?;
            observations.push(value.as_str().and_then(MoveObservation::decode).ok_or(ProtocolError::BrowserFailure)?);
        }
        let expected = expects_drag(&observations).ok_or(ProtocolError::BrowserFailure)?;
        if expected { ctx.page_state.point_drag_expected_positive(ctx.page, ctx.operation, &token)?; }
        for probe in &probes { probe.realm.verify_resolution_owner(ctx.operation).await?; }
        realms.verify(ctx.page, ctx.operation).await?;
        if !expected { ctx.page_state.point_drag_observed_negative(ctx.page, ctx.operation, &token)?; }
        ctx.page_state.point_drag_command(ctx.page, ctx.operation, &token,
            "Input.setInterceptDrags", json!({"enabled":false})).await?;
        if !expected {
            if events.lock().await.watermark().received().map_err(|_| ProtocolError::BrowserFailure)? != 0 {
                return Err(ProtocolError::BrowserFailure);
            }
            continue;
        }
        let mut cancelled = ctx.operation.cancellation.clone();
        let mut event_guard = events.lock().await;
        let event = tokio::select! {
            result = event_guard.recv() => result.map_err(|_| ProtocolError::BrowserFailure)?,
            _ = cancelled.changed() => return Err(ProtocolError::Cancelled),
            _ = tokio::time::sleep_until(ctx.operation.deadline.into()) => return Err(ProtocolError::DeadlineExceeded),
        };
        drop(event_guard);
        runner.check()?;
        if event.sequence() != 1 || event.session_id.as_deref() != Some(ctx.page.page_session_id.as_str())
            || !event.params["data"]["items"].is_array()
            || event.params["data"]["dragOperationsMask"].as_i64().is_none() {
            return Err(ProtocolError::BrowserFailure);
        }
        drag_event(runner, &token, "dragEnter", point, &event).await?;
        if step == steps { drag_event(runner, &token, "dragOver", point, &event).await?; }
        // The event owns its bounded payload lease until the final command ACK.
        native_drag = Some(event);
    }
    if let Some(event) = native_drag.as_ref() {
        if events.lock().await.watermark().received().map_err(|_| ProtocolError::BrowserFailure)? != 1 {
            return Err(ProtocolError::BrowserFailure);
        }
        ctx.page_state.point_drag_logical_release(ctx.page, ctx.operation, &token)?;
        drag_event(runner, &token, "drop", to, event).await?;
    } else {
        runner.event("mouseReleased", to, Some("left"), Some(1)).await?;
    }
    ctx.page_state.finish_point_drag(ctx.page, ctx.operation, token).await?;
    runner.check()
}
