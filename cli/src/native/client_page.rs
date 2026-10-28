//! Scope-owned page primitives for the negotiated native client. The caller
//! serializes actions, but callback reads and target enrollment never wait on
//! a lock held across browser I/O. Partial/uncertain mutations require the
//! caller to quarantine this identity scope, not retry them in a new attempt.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

use super::actions::{build_mouse_event_params, MouseState};
use super::browser::{evaluate_on, evaluate_public_on};
use super::cdp::types::CdpEvent;
use super::client_browser::BrowserExecutionLease;
use super::client_debt::{
    self, CleanupDisposition, CommandCategory, CommandStatusHandle, OperationJournalHandle,
    OperationKey, ScopeCleanupCommand,
};
use super::client_protocol::ProtocolError;
use super::client_session::{CancelSignal, ObservedOperationFailure, OperationLease};
use super::interaction::{char_to_key_info, key_text, named_key_info};

#[path = "client_navigation_retirement.rs"]
mod navigation_retirement;

#[derive(Clone, Default)]
struct Config {
    revision: u64,
    scripts: Vec<Arc<str>>,
    color_scheme: Option<String>,
    reduced_motion: Option<String>,
    service_worker_policy: bool,
}
/// Native-private declarative configuration, not a scope or browser authority.
/// Installed registrations and observations are deliberately never transferred.
#[derive(Clone)]
pub(crate) struct PageConfigSnapshot {
    config: Config,
    requested_viewport: Option<(u32, u32)>,
}
impl PageConfigSnapshot {
    pub(crate) fn initialization_scripts(&self) -> impl Iterator<Item = &str> {
        self.config.scripts.iter().map(|script| script.as_ref())
    }
}
pub(crate) const BLOCK_SERVICE_WORKERS: &str = "if (globalThis.ServiceWorkerContainer) ServiceWorkerContainer.prototype.register = async () => { console.warn('Service Worker registration blocked by agent-browser'); };";
#[derive(Clone, Default)]
struct InputState {
    keys: BTreeMap<String, Key>,
    mouse: MouseState,
    pointer_known: bool,
    session: Option<String>,
}
/// A non-cloneable receipt for the exact temporary modifier transaction.
/// The caller serializes input actions and retains cleanup on cancellation.
pub(crate) struct ModifierReceipt {
    identity_scope: String,
    session: String,
    keys: Vec<Key>,
    released: Vec<Key>,
}
#[derive(Clone)]
struct Key {
    key: String,
    code: String,
    vk: i32,
    modifier: i32,
    location: i32,
}
struct NetworkActivity {
    requests: BTreeMap<(String, String), bool>,
    quiet_since: Instant,
    complete: bool,
}
impl Default for NetworkActivity {
    fn default() -> Self {
        Self {
            requests: BTreeMap::new(),
            quiet_since: Instant::now(),
            complete: true,
        }
    }
}
#[derive(Default)]
struct State {
    config: Config,
    installed_scripts: HashMap<String, usize>,
    #[cfg(test)]
    script_registration_acks: HashMap<String, Vec<usize>>,
    script_ids: HashMap<String, Vec<String>>,
    uncertain_scripts: BTreeSet<String>,
    configuration_locks: HashMap<String, Arc<tokio::sync::Mutex<()>>>,
    input: InputState,
    input_cleanup: Option<(Vec<CommandStatusHandle>, InputState)>,
    origins: BTreeSet<String>,
    requested_viewport: Option<(u32, u32)>,
    browser_is_mac: Option<bool>,
    network_roots: HashMap<String, String>,
    network: HashMap<String, NetworkActivity>,
}
/// One instance per owned context/identity scope. Never reuse across reset.
pub struct ClientPageState {
    identity_scope: String,
    context_id: String,
    state: Mutex<State>,
    network_changed: tokio::sync::Notify,
}

/// Native-only terminal receipt for one interrupted Page.navigate. This does
/// not assert that the navigation had no business effects or permit replay.
pub(crate) struct NavigationInterruptionProof {
    key: OperationKey,
    identity_scope: String,
    attachment: super::client_targets::OwnedTarget,
}
impl NavigationInterruptionProof {
    pub(crate) fn confirms(
        self,
        page: &BrowserExecutionLease,
        operation: &OperationLease,
        journal: &OperationJournalHandle,
    ) -> bool {
        let snapshot = journal.snapshot();
        self.key == journal.key()
            && self.key.generation == operation.generation
            && self.key.operation_seq == operation.sequence
            && self.identity_scope == page.identity_scope
            && journal
                .ledger()
                .matches_owner(operation.generation, &page.identity_scope)
            && page.permit.check().is_ok()
            && page
                .targets
                .owned_target(&page.target_id)
                .is_ok_and(|current| {
                    self.attachment.same_attachment(&current)
                        && current.session_id == page.page_session_id
                })
            && snapshot.mutation_dispatched
            && !snapshot.integrity_lost
            && snapshot.input_debt == 0
            && snapshot.object_debt == 0
    }
}

fn append_script(config: &mut Config, source: Arc<str>) -> Result<(), ProtocolError> {
    if config.scripts.len() >= 1024
        || config
            .scripts
            .iter()
            .map(|item| item.len())
            .sum::<usize>()
            .saturating_add(source.len())
            > 8 * 1024 * 1024
    {
        return Err(ProtocolError::CapacityExceeded);
    }
    let revision = config
        .revision
        .checked_add(1)
        .ok_or(ProtocolError::IdentifierExhausted)?;
    config.scripts.push(source);
    config.revision = revision;
    Ok(())
}

fn configuration_incomplete(error: ProtocolError) -> ProtocolError {
    if let Some(journal) = OperationJournalHandle::current() {
        journal.record_cleanup_disposition(CleanupDisposition::IntegrityLost);
    }
    error
}

fn invalid<T>() -> Result<T, ProtocolError> {
    Err(ProtocolError::InvalidArguments)
}
fn decode<T: serde::de::DeserializeOwned>(args: &Value) -> Result<T, ProtocolError> {
    serde_json::from_value(args.clone()).map_err(|_| ProtocolError::InvalidArguments)
}
fn check(page: &BrowserExecutionLease, op: &OperationLease) -> Result<(), ProtocolError> {
    let permitted = page.permit.check();
    #[cfg(test)]
    if let Err(error) = &permitted {
        page.client
            .activation_diagnostic("guard-check", None, "owner-changed", Some(error), None);
    }
    permitted?;
    if let Some(journal) = OperationJournalHandle::current() {
        let admitted = journal.check_application_submission();
        #[cfg(test)]
        if let Err(error) = &admitted {
            page.client.activation_diagnostic(
                "guard-check",
                None,
                "admission-revoked",
                Some(error),
                None,
            );
        }
        admitted?;
    }
    if *op.cancellation.borrow() != CancelSignal::None {
        #[cfg(test)]
        page.client
            .activation_diagnostic("guard-check", None, "cancelled", None, None);
        return Err(ProtocolError::Cancelled);
    }
    if Instant::now() >= op.deadline {
        #[cfg(test)]
        page.client
            .activation_diagnostic("guard-check", None, "deadline", None, None);
        return Err(ProtocolError::DeadlineExceeded);
    }
    Ok(())
}
fn check_initialization(
    page: &BrowserExecutionLease,
    op: &OperationLease,
) -> Result<(), ObservedOperationFailure> {
    let permitted = page.permit.check();
    #[cfg(test)]
    if let Err(error) = &permitted {
        page.client
            .activation_diagnostic("guard-check", None, "owner-changed", Some(error), None);
    }
    permitted?;
    if let Some(journal) = OperationJournalHandle::current() {
        let admitted = journal.check_application_submission();
        #[cfg(test)]
        if let Err(error) = &admitted {
            page.client.activation_diagnostic(
                "guard-check",
                None,
                "admission-revoked",
                Some(error),
                None,
            );
        }
        admitted?;
    }
    if let Err(observed) = ObservedOperationFailure::check_cancelled(op) {
        #[cfg(test)]
        page.client
            .activation_diagnostic("guard-check", None, "cancelled", None, None);
        return Err(observed);
    }
    if Instant::now() >= op.deadline {
        #[cfg(test)]
        page.client
            .activation_diagnostic("guard-check", None, "deadline", None, None);
        return Err(ProtocolError::DeadlineExceeded.into());
    }
    Ok(())
}
// This typed variant is only for retained initializer configuration. A raw
// failed reply uses the original ordinary postcheck/error precedence and can
// never acquire a benign stop receipt from a later owner retirement.
async fn bounded_initialization_component<T>(
    page: &BrowserExecutionLease,
    op: &OperationLease,
    future: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, ObservedOperationFailure> {
    check_initialization(page, op)?;
    let mut cancel = op.cancellation.clone();
    tokio::select! {
        value = future => match value {
            Ok(value) => { check_initialization(page, op)?; Ok(value) },
            Err(_) => { check(page, op)?; Err(ProtocolError::BrowserFailure.into()) },
        },
        _ = cancel.changed() => Err(ObservedOperationFailure::changed(op, &cancel)),
        _ = tokio::time::sleep_until(op.deadline.into()) => Err(ProtocolError::DeadlineExceeded.into()),
    }
}
async fn command_initialization_component(
    page: &BrowserExecutionLease,
    op: &OperationLease,
    session: Option<&str>,
    method: &str,
    args: Value,
) -> Result<Value, ObservedOperationFailure> {
    bounded_initialization_component(
        page,
        op,
        page.client.send_command(method, Some(args), session),
    )
    .await
}
async fn bounded<T>(
    page: &BrowserExecutionLease,
    op: &OperationLease,
    future: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, ProtocolError> {
    check(page, op)?;
    let mut cancel = op.cancellation.clone();
    tokio::select! {
        value = future => { check(page, op)?; value.map_err(|_| ProtocolError::BrowserFailure) },
        _ = cancel.changed() => Err(ProtocolError::Cancelled),
        _ = tokio::time::sleep_until(op.deadline.into()) => Err(ProtocolError::DeadlineExceeded),
    }
}
async fn command(
    page: &BrowserExecutionLease,
    op: &OperationLease,
    session: Option<&str>,
    method: &str,
    args: Value,
) -> Result<Value, ProtocolError> {
    bounded(
        page,
        op,
        page.client.send_command(method, Some(args), session),
    )
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    source: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evaluation {
    source: String,
    argument: Value,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Media {
    color_scheme: Option<String>,
    reduced_motion: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Viewport {
    width: u32,
    height: u32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Navigation {
    url: String,
    wait_until: String,
}
fn navigation_wait(wait: &str) -> Result<&'static str, ProtocolError> {
    match wait {
        "load" => Ok("load"),
        "domcontentloaded" | "networkidle" => Ok("DOMContentLoaded"),
        _ => invalid(),
    }
}
fn decode_navigation(args: &Value) -> Result<Navigation, ProtocolError> {
    let navigation: Navigation = decode(args)?;
    navigation_wait(&navigation.wait_until)?;
    Ok(navigation)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Keyboard {
    action: String,
    value: String,
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
enum Mouse {
    Move {
        x: f64,
        y: f64,
    },
    #[serde(rename_all = "camelCase")]
    Wheel {
        delta_x: f64,
        delta_y: f64,
    },
    Down,
    Up,
}

impl ClientPageState {
    pub fn new(identity_scope: String, context_id: String) -> Self {
        Self {
            identity_scope,
            context_id,
            state: Mutex::new(State::default()),
            network_changed: tokio::sync::Notify::new(),
        }
    }
    /// Caller holds the scope configuration gate after draining prior commands.
    pub(crate) fn snapshot_config(
        &self,
        expected_scope: &str,
    ) -> Result<PageConfigSnapshot, ProtocolError> {
        if expected_scope != self.identity_scope {
            return Err(ProtocolError::StaleScope);
        }
        let state = self.state()?;
        let mut config = state.config.clone();
        // Revisions belong to one registry tenure, not transferable configuration.
        config.revision = 0;
        Ok(PageConfigSnapshot {
            config,
            requested_viewport: state.requested_viewport,
        })
    }
    /// Construct before any new target is enrolled. This cannot overwrite a live
    /// page registry or transfer old session/permit/input/origin ownership.
    pub(crate) fn from_config_snapshot(
        identity_scope: String,
        context_id: String,
        snapshot: PageConfigSnapshot,
    ) -> Result<Self, ProtocolError> {
        if identity_scope.is_empty() || context_id.is_empty() {
            return Err(ProtocolError::InvalidArguments);
        }
        Ok(Self {
            identity_scope,
            context_id,
            state: Mutex::new(State {
                config: snapshot.config,
                requested_viewport: snapshot.requested_viewport,
                ..State::default()
            }),
            network_changed: tokio::sync::Notify::new(),
        })
    }
    /// Add the immutable native policy exactly once to the same ordered script
    /// registry used by application init scripts. Enrollment applies it below.
    pub(crate) fn ensure_service_worker_policy(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.validate(page, op)?;
        let mut state = self.state()?;
        if state.config.service_worker_policy {
            return Ok(());
        }
        append_script(&mut state.config, Arc::from(BLOCK_SERVICE_WORKERS))?;
        state.config.service_worker_policy = true;
        Ok(())
    }
    fn state(&self) -> Result<MutexGuard<'_, State>, ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state
            .input_cleanup
            .as_ref()
            .is_some_and(|(statuses, _)| statuses.iter().all(CommandStatusHandle::settled))
        {
            if let Some((_, input)) = state.input_cleanup.take() {
                state.input = input;
            }
        }
        Ok(state)
    }
    fn validate(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        if self.identity_scope != page.identity_scope || self.context_id.is_empty() {
            return Err(ProtocolError::StaleScope);
        }
        check(page, op)
    }
    fn validate_initialization(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<(), ObservedOperationFailure> {
        if self.identity_scope != page.identity_scope || self.context_id.is_empty() {
            return Err(ProtocolError::StaleScope.into());
        }
        check_initialization(page, op)
    }
    /// Owner registers root pages and descendant OOPIFs BEFORE Network.enable
    /// and before target resume. Popup roots are distinct from the active page.
    pub fn register_network_session(
        &self,
        root_page_session: &str,
        session: &str,
    ) -> Result<(), ProtocolError> {
        if root_page_session.is_empty()
            || session.is_empty()
            || root_page_session.len() > 1024
            || session.len() > 1024
        {
            return invalid();
        }
        let mut state = self.state()?;
        if state.network_roots.len() >= 1024 && !state.network_roots.contains_key(session) {
            return Err(ProtocolError::CapacityExceeded);
        }
        if state
            .network_roots
            .get(session)
            .is_some_and(|old| old != root_page_session)
        {
            return Err(ProtocolError::StaleScope);
        }
        state
            .network_roots
            .insert(session.into(), root_page_session.into());
        state.network.entry(root_page_session.into()).or_default();
        drop(state);
        self.network_changed.notify_waiters();
        Ok(())
    }
    /// Feed only owned sessions from the lossless/bounded native event owner.
    /// Root grouping is proven by the target/frame registry, never inferred
    /// from a URL. Stream overflow must call network_incomplete and quarantine.
    pub fn network_event(
        &self,
        root_page_session: &str,
        event: &CdpEvent,
    ) -> Result<(), ProtocolError> {
        if !matches!(
            event.method.as_str(),
            "Network.requestWillBeSent" | "Network.loadingFinished" | "Network.loadingFailed"
        ) {
            return Ok(());
        }
        let session = event
            .session_id
            .as_deref()
            .ok_or(ProtocolError::BrowserFailure)?;
        let request_id = event
            .params
            .get("requestId")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 1024)
            .ok_or(ProtocolError::BrowserFailure)?;
        let mut state = self.state()?;
        if state.network_roots.get(session).map(String::as_str) != Some(root_page_session) {
            return Err(ProtocolError::StaleScope);
        }
        let activity = state
            .network
            .get_mut(root_page_session)
            .ok_or(ProtocolError::ScopeUnavailable)?;
        if !activity.complete {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let key = (session.to_owned(), request_id.to_owned());
        if event.method == "Network.requestWillBeSent" {
            if activity.requests.len() >= 8192 && !activity.requests.contains_key(&key) {
                activity.complete = false;
                drop(state);
                self.network_changed.notify_waiters();
                return Err(ProtocolError::CapacityExceeded);
            }
            let url = event
                .params
                .pointer("/request/url")
                .and_then(Value::as_str)
                .ok_or(ProtocolError::BrowserFailure)?;
            let excluded = matches!(
                event.params.get("type").and_then(Value::as_str),
                Some("WebSocket" | "EventSource")
            ) || url.ends_with("/favicon.ico");
            // CDP reuses requestId through a redirect. Retain exclusion of the
            // original favicon, and never count a redirect as a second request.
            let previous = activity.requests.get(&key).copied();
            let counted = previous.unwrap_or(!excluded) && !excluded;
            activity.requests.insert(key, counted);
            if counted || previous == Some(true) {
                activity.quiet_since = Instant::now();
            }
        } else if activity.requests.remove(&key) == Some(true) {
            activity.quiet_since = Instant::now();
        }
        drop(state);
        self.network_changed.notify_waiters();
        Ok(())
    }
    pub fn network_incomplete(&self, root_page_session: &str) -> Result<(), ProtocolError> {
        if let Some(activity) = self.state()?.network.get_mut(root_page_session) {
            activity.complete = false;
        }
        self.network_changed.notify_waiters();
        Ok(())
    }
    async fn wait_network_idle(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        loop {
            check(page, op)?;
            let changed = self.network_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let quiet_deadline = {
                let state = self.state()?;
                let activity = state
                    .network
                    .get(&page.page_session_id)
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                if !activity.complete {
                    return Err(ProtocolError::ScopeUnavailable);
                }
                if activity.requests.values().any(|counted| *counted) {
                    None
                } else {
                    Some(activity.quiet_since + Duration::from_millis(500))
                }
            };
            if quiet_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Ok(());
            }
            let mut cancel = op.cancellation.clone();
            tokio::select! {
                _=&mut changed=>{},
                _=tokio::time::sleep_until(quiet_deadline.unwrap_or(op.deadline).into())=>{},
                _=cancel.changed()=>return Err(ProtocolError::Cancelled),
                _=tokio::time::sleep_until(op.deadline.into())=>return Err(ProtocolError::DeadlineExceeded),
            }
        }
    }
    pub fn config_revision(&self) -> Result<u64, ProtocolError> {
        Ok(self.state()?.config.revision)
    }
    pub fn visited_origins(&self) -> Result<Vec<String>, ProtocolError> {
        Ok(self.state()?.origins.iter().cloned().collect())
    }
    pub fn record_origin(
        &self,
        page: &BrowserExecutionLease,
        url: &str,
    ) -> Result<(), ProtocolError> {
        if page.identity_scope != self.identity_scope {
            return Err(ProtocolError::StaleScope);
        }
        page.permit.check()?;
        if let Ok(url) = url::Url::parse(url) {
            let origin = url.origin().ascii_serialization();
            if origin != "null" {
                self.state()?.origins.insert(origin);
            }
        }
        Ok(())
    }
    /// Local held-state only, never proof that an unacknowledged remote
    /// release completed. Recovery must not silently abandon a known drag/key.
    pub(crate) fn check_no_active_local_input(&self, scope: &str) -> Result<(), ProtocolError> {
        if scope != self.identity_scope {
            return Err(ProtocolError::StaleScope);
        }
        let state = self.state()?;
        if !state.input.keys.is_empty()
            || state.input.mouse.buttons != 0
            || state.input_cleanup.is_some()
        {
            return Err(ProtocolError::CleanupFailed);
        }
        Ok(())
    }
    pub fn held_modifiers(&self) -> Result<i32, ProtocolError> {
        Ok(modifiers(&self.state()?.input))
    }
    /// Called only after a successful locator action with known input effects.
    /// Coordinates are projected into the top-level page viewport by the
    /// native observation/interaction layer before they reach this function.
    pub fn record_pointer(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
        x: f64,
        y: f64,
        buttons: i32,
    ) -> Result<(), ProtocolError> {
        self.validate(page, op)?;
        if !x.is_finite() || !y.is_finite() || !(0..=31).contains(&buttons) {
            return invalid();
        }
        let mut state = self.state()?;
        bind_input_session(&mut state.input, &page.page_session_id)?;
        state.input.mouse = MouseState { x, y, buttons };
        state.input.pointer_known = true;
        Ok(())
    }
    pub fn requested_viewport(&self) -> Result<Option<(u32, u32)>, ProtocolError> {
        Ok(self.state()?.requested_viewport)
    }
    pub fn mouse_state(&self) -> Result<MouseState, ProtocolError> {
        Ok(self.state()?.input.mouse)
    }
    /// Only ACKed coordinates on this exact page may guide a node wheel.
    /// Default0,0, another session and pending/failed moves are not evidence.
    pub(crate) fn known_pointer_position(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<Option<(f64, f64)>, ProtocolError> {
        self.validate(page, op)?;
        let state = self.state()?;
        Ok((state.input.pointer_known
            && state.input.session.as_deref() == Some(page.page_session_id.as_str())
            && state.input_cleanup.is_none())
        .then_some((state.input.mouse.x, state.input.mouse.y)))
    }
    /// Target owner must keep a newly attached target paused until the returned
    /// revision equals config_revision(). Scripts install once per session and
    /// run in every new document, including in-process child frames. Out-of-
    /// process frames must be enrolled by the same owner before they resume.
    pub async fn apply_to_new_session(
        &self,
        page: &BrowserExecutionLease,
        session: &str,
        op: &OperationLease,
    ) -> Result<u64, ProtocolError> {
        self.apply_to_new_session_initialization(page, session, op)
            .await
            .map_err(ObservedOperationFailure::into_protocol)
    }
    pub(crate) async fn apply_to_new_session_initialization(
        &self,
        page: &BrowserExecutionLease,
        session: &str,
        op: &OperationLease,
    ) -> Result<u64, ObservedOperationFailure> {
        self.validate_initialization(page, op)?;
        // Serialize only configuration writes for this target. This lock never
        // blocks navigation, callback reads, or another target's enrollment.
        let session_lock = self
            .state()?
            .configuration_locks
            .entry(session.into())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let mut cancel = op.cancellation.clone();
        let _configuration = tokio::select! {
            guard = session_lock.lock() => guard,
            _ = cancel.changed() => return Err(ObservedOperationFailure::changed(op, &cancel)),
            _ = tokio::time::sleep_until(op.deadline.into()) => return Err(ProtocolError::DeadlineExceeded.into()),
        };
        self.validate_initialization(page, op)?;
        let (config, installed) = {
            let s = self.state()?;
            (
                s.config.clone(),
                *s.installed_scripts.get(session).unwrap_or(&0),
            )
        };
        for (index, source) in config.scripts.iter().enumerate().skip(installed) {
            self.state()?.uncertain_scripts.insert(session.into());
            let installed_script = command_initialization_component(
                page,
                op,
                Some(session),
                "Page.addScriptToEvaluateOnNewDocument",
                json!({"source":source.as_ref()}),
            )
            .await?;
            if !installed_script
                .get("identifier")
                .and_then(Value::as_str)
                .is_some_and(|id| !id.is_empty())
            {
                return Err(ProtocolError::BrowserFailure.into());
            }
            {
                let mut state = self.state()?;
                state
                    .script_ids
                    .entry(session.into())
                    .or_default()
                    .push(installed_script["identifier"].as_str().unwrap().to_owned());
                state.uncertain_scripts.remove(session);
                state.installed_scripts.insert(session.into(), index + 1);
                #[cfg(test)]
                state
                    .script_registration_acks
                    .entry(session.into())
                    .or_default()
                    .push(index);
            }
            self.validate_initialization(page, op)?;
        }
        let mut features = Vec::new();
        if let Some(value) = &config.color_scheme {
            features.push(json!({"name":"prefers-color-scheme","value":value}));
        }
        if let Some(value) = &config.reduced_motion {
            features.push(json!({"name":"prefers-reduced-motion","value":value}));
        }
        // Unspecified media must leave the browser's own preferences alone.
        // Explicit no-preference values remain declarations and are applied.
        if !features.is_empty() {
            command_initialization_component(
                page,
                op,
                Some(session),
                "Emulation.setEmulatedMedia",
                json!({"features":features}),
            )
            .await?;
        }
        Ok(config.revision)
    }
    /// Test-only registration evidence: successful ACK ordinals, never source/IDs.
    #[cfg(test)]
    pub(crate) fn script_registration_ack_ordinals(
        &self,
        session: &str,
    ) -> Result<Vec<usize>, ProtocolError> {
        Ok(self
            .state()?
            .script_registration_acks
            .get(session)
            .cloned()
            .unwrap_or_default())
    }
    /// Lifecycle-only cleanup; the caller has drained operations and retains
    /// this future. This removes future registrations, not script side effects
    /// already executed in the borrowed host document.
    pub(crate) async fn remove_session_scripts(
        &self,
        client: &super::cdp::client::CdpClient,
        identity_scope: &str,
        session: &str,
        deadline: Instant,
    ) -> Result<(), ProtocolError> {
        if identity_scope != self.identity_scope {
            return Err(ProtocolError::StaleScope);
        }
        let (ids, mut failed) = {
            let state = self.state()?;
            (
                state.script_ids.get(session).cloned().unwrap_or_default(),
                state.uncertain_scripts.contains(session),
            )
        };
        for id in ids {
            if Instant::now() >= deadline {
                failed = true;
                break;
            }
            match tokio::time::timeout_at(
                deadline.into(),
                client.send_scope_cleanup(
                    ScopeCleanupCommand::RemoveScript {
                        session: session.to_owned(),
                        identifier: id.clone(),
                    },
                    deadline,
                ),
            )
            .await
            {
                Ok(Ok(_)) => {
                    if let Some(ids) = self.state()?.script_ids.get_mut(session) {
                        ids.retain(|value| value != &id);
                    }
                }
                _ => failed = true,
            }
        }
        if failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
    pub fn forget_session(&self, session: &str) -> Result<(), ProtocolError> {
        let mut state = self.state()?;
        state.installed_scripts.remove(session);
        state.script_ids.remove(session);
        state.uncertain_scripts.remove(session);
        state.configuration_locks.remove(session);
        if state.input.session.as_deref() == Some(session) {
            state.input = InputState::default();
        }
        if let Some(root) = state.network_roots.remove(session) {
            if let Some(activity) = state.network.get_mut(&root) {
                activity.requests.retain(|(owner, _), _| owner != session);
                activity.quiet_since = Instant::now();
            }
            if !state.network_roots.values().any(|r| r == &root) {
                state.network.remove(&root);
            }
        }
        drop(state);
        self.network_changed.notify_waiters();
        Ok(())
    }
    async fn apply_existing(
        &self,
        page: &BrowserExecutionLease,
        sessions: &[String],
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        let mut unique = BTreeSet::new();
        for session in sessions
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(page.page_session_id.as_str()))
        {
            if unique.insert(session) {
                self.apply_to_new_session(page, session, op).await?;
            }
        }
        Ok(())
    }
    fn update_media(&self, args: &Value) -> Result<(), ProtocolError> {
        if ["colorScheme", "reducedMotion"]
            .iter()
            .any(|key| args.get(*key) == Some(&Value::Null))
        {
            return invalid();
        }
        let a: Media = decode(args)?;
        if a.color_scheme
            .as_ref()
            .is_some_and(|v| !matches!(v.as_str(), "light" | "dark" | "no-preference"))
            || a.reduced_motion
                .as_ref()
                .is_some_and(|v| !matches!(v.as_str(), "reduce" | "no-preference"))
        {
            return invalid();
        }
        {
            let mut s = self.state()?;
            let revision = s
                .config
                .revision
                .checked_add(1)
                .ok_or(ProtocolError::IdentifierExhausted)?;
            if let Some(journal) = OperationJournalHandle::current() {
                journal.mark_mutation_maybe_submitted()?;
            }
            s.config.revision = revision;
            if a.color_scheme.is_some() {
                s.config.color_scheme = a.color_scheme;
            }
            if a.reduced_motion.is_some() {
                s.config.reduced_motion = a.reduced_motion;
            }
        }
        Ok(())
    }
    /// Production media uses the original attachment tickets, not a later
    /// session lookup, to prove that a failed non-active tab really departed.
    pub(crate) async fn execute_media_with_owner(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
        args: &Value,
        enrollment: &super::client_enrollment::ClientEnrollment,
        attachments: &[super::client_targets::OwnedTarget],
    ) -> Result<Value, ProtocolError> {
        self.validate(page, op)?;
        let active = attachments
            .iter()
            .find(|target| {
                target.target_id == page.target_id && target.session_id == page.page_session_id
            })
            .ok_or(ProtocolError::StaleReference)?;
        enrollment.validate_media_owner(page, op, active)?;
        self.update_media(args)?;
        let result = async {
            let mut unique = BTreeSet::new();
            for target in std::iter::once(active).chain(attachments.iter()) {
                if !unique.insert(target.session_id.as_str()) {
                    continue;
                }
                match self
                    .apply_to_new_session(page, &target.session_id, op)
                    .await
                {
                    Ok(_) => {}
                    Err(ProtocolError::BrowserFailure)
                        if enrollment
                            .media_target_detached(page, op, active, target)
                            .await? => {}
                    Err(error) => return Err(error),
                }
            }
            self.validate(page, op)?;
            enrollment.validate_media_owner(page, op, active)?;
            Ok(Value::Null)
        }
        .await;
        result.map_err(configuration_incomplete)
    }
    /// Production navigation keeps cleanup in the already registered producer.
    /// Other callers retain the existing result-only primitive below.
    pub(crate) async fn execute_with_retirement(
        &self,
        page: &BrowserExecutionLease,
        sessions: &[String],
        op: &OperationLease,
        name: &str,
        args: &Value,
        tasks: &super::client_tasks::RetainedTasks,
    ) -> (
        Result<Value, ProtocolError>,
        Option<NavigationInterruptionProof>,
    ) {
        if name != "page.navigate" {
            return (self.execute(page, sessions, op, name, args).await, None);
        }
        let mut proof = None;
        let result = async {
            self.validate(page, op)?;
            let a = decode_navigation(args)?;
            self.navigate(
                page,
                op,
                "Page.navigate",
                json!({"url":a.url}),
                &a.wait_until,
                Some((tasks, &mut proof)),
            )
            .await?;
            Ok(Value::Null)
        }
        .await;
        (result, proof)
    }
    /// The native dispatcher supplies only sessions proven owned by context_id.
    pub async fn execute(
        &self,
        page: &BrowserExecutionLease,
        sessions: &[String],
        op: &OperationLease,
        name: &str,
        args: &Value,
    ) -> Result<Value, ProtocolError> {
        self.validate(page, op)?;
        let session = Some(page.page_session_id.as_str());
        match name {
            "page.title" | "page.url" => {
                let _: Empty = decode(args)?;
                let expression = if name == "page.title" {
                    "document.title"
                } else {
                    "location.href"
                };
                let value = bounded(
                    page,
                    op,
                    client_debt::command_scope(
                        CommandCategory::ApplicationRead,
                        false,
                        evaluate_on(&page.client, &page.page_session_id, expression),
                    ),
                )
                .await?;
                if !value.is_string() {
                    return Err(ProtocolError::BrowserFailure);
                }
                Ok(if name == "page.title" {
                    json!({"title":value})
                } else {
                    json!({"url":value})
                })
            }
            "page.evaluate" => {
                let a: Evaluation = decode(args)?;
                // Trusted caller source, JSON argument encoded once. The wrapper
                // retains the checked public evaluate envelope as the value; it
                // does not flatten or reinterpret wrapper errors.
                let expression=format!("(async()=>{{const value=await ({} )({}); return {{value:value===undefined?null:value}};}})()",a.source,serde_json::to_string(&a.argument).map_err(|_|ProtocolError::InvalidArguments)?);
                let result = bounded(
                    page,
                    op,
                    evaluate_public_on(&page.client, &page.page_session_id, &expression),
                )
                .await?;
                if !result.is_object() || result.get("value").is_none() {
                    return Err(ProtocolError::BrowserFailure);
                }
                Ok(result)
            }
            "page.navigate" => {
                let a = decode_navigation(args)?;
                self.navigate(
                    page,
                    op,
                    "Page.navigate",
                    json!({"url":a.url}),
                    &a.wait_until,
                    None,
                )
                .await?;
                Ok(Value::Null)
            }
            "page.reload" => {
                let _: Empty = decode(args)?;
                self.navigate(page, op, "Page.reload", json!({}), "load", None)
                    .await?;
                Ok(Value::Null)
            }
            "page.back" | "page.forward" => {
                let _: Empty = decode(args)?;
                let history =
                    command(page, op, session, "Page.getNavigationHistory", json!({})).await?;
                let current = history
                    .get("currentIndex")
                    .and_then(Value::as_i64)
                    .ok_or(ProtocolError::BrowserFailure)?;
                let entries = history
                    .get("entries")
                    .and_then(Value::as_array)
                    .ok_or(ProtocolError::BrowserFailure)?;
                let index = current + if name == "page.back" { -1 } else { 1 };
                if index >= 0 && (index as usize) < entries.len() {
                    let id = entries[index as usize]
                        .get("id")
                        .and_then(Value::as_i64)
                        .ok_or(ProtocolError::BrowserFailure)?;
                    self.navigate(
                        page,
                        op,
                        "Page.navigateToHistoryEntry",
                        json!({"entryId":id}),
                        "load",
                        None,
                    )
                    .await?;
                }
                Ok(Value::Null)
            }
            "context.cookies.get" => {
                let _: Empty = decode(args)?;
                let response = command(
                    page,
                    op,
                    None,
                    "Storage.getCookies",
                    json!({"browserContextId":self.context_id}),
                )
                .await?;
                Ok(json!({"cookies":project_cookies(&response)?}))
            }
            "context.cookies.set" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Cookies {
                    cookies: Vec<Value>,
                }
                let a: Cookies = decode(args)?;
                let cookies = a
                    .cookies
                    .iter()
                    .map(validate_cookie)
                    .collect::<Result<Vec<_>, _>>()?;
                command(
                    page,
                    op,
                    None,
                    "Storage.setCookies",
                    json!({"browserContextId":self.context_id,"cookies":cookies}),
                )
                .await?;
                Ok(Value::Null)
            }
            "context.init-script" => {
                let a: Source = decode(args)?;
                {
                    let mut s = self.state()?;
                    let mut next = s.config.clone();
                    append_script(&mut next, Arc::from(a.source))?;
                    if let Some(journal) = OperationJournalHandle::current() {
                        journal.mark_mutation_maybe_submitted()?;
                    }
                    s.config = next;
                }
                self.apply_existing(page, sessions, op)
                    .await
                    .map_err(configuration_incomplete)?;
                Ok(Value::Null)
            }
            "context.media" => {
                self.update_media(args)?;
                // The ownerless primitive keeps strict failure propagation.
                let ordered = std::iter::once(page.page_session_id.clone())
                    .chain(sessions.iter().cloned())
                    .collect::<Vec<_>>();
                self.apply_existing(page, &ordered, op)
                    .await
                    .map_err(configuration_incomplete)?;
                Ok(Value::Null)
            }
            "context.viewport" => {
                let a: Viewport = decode(args)?;
                if a.width > i32::MAX as u32 || a.height > i32::MAX as u32 {
                    return invalid();
                }
                command(page,op,session,"Emulation.setDeviceMetricsOverride",json!({"width":a.width,"height":a.height,"deviceScaleFactor":0,"mobile":false,"screenWidth":a.width,"screenHeight":a.height})).await?;
                self.state()?.requested_viewport = Some((a.width, a.height));
                Ok(Value::Null)
            }
            "input.keyboard" => {
                let a: Keyboard = decode(args)?;
                let result = self.keyboard(page, op, &a).await;
                if result
                    .as_ref()
                    .is_err_and(|error| *error != ProtocolError::InvalidArguments)
                    && self.release_input(page).await.is_err()
                {
                    return Err(ProtocolError::CleanupFailed);
                }
                result.map(|_| Value::Null)
            }
            "input.mouse" => {
                let a: Mouse = decode(args)?;
                let result = self.mouse(page, op, a).await;
                if result
                    .as_ref()
                    .is_err_and(|error| *error != ProtocolError::InvalidArguments)
                    && self.release_input(page).await.is_err()
                {
                    return Err(ProtocolError::CleanupFailed);
                }
                result.map(|_| Value::Null)
            }
            _ => Err(ProtocolError::UnsupportedCommand),
        }
    }
    async fn navigate(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
        method: &str,
        args: Value,
        wait: &str,
        retirement: Option<(
            &super::client_tasks::RetainedTasks,
            &mut Option<NavigationInterruptionProof>,
        )>,
    ) -> Result<(), ProtocolError> {
        #[cfg(test)]
        page.client
            .activation_diagnostic("nav-enter", None, "entered", None, None);
        let expected = navigation_wait(wait)?;
        if wait == "networkidle" {
            let state = self.state()?;
            if !state
                .network
                .get(&page.page_session_id)
                .is_some_and(|activity| activity.complete)
            {
                return Err(ProtocolError::ScopeUnavailable);
            }
        }
        let session = Some(page.page_session_id.as_str());
        command(
            page,
            op,
            session,
            "Page.setLifecycleEventsEnabled",
            json!({"enabled":true}),
        )
        .await?;
        let tree = command(page, op, session, "Page.getFrameTree", json!({})).await?;
        let frame = tree.pointer("/frameTree/frame/id").and_then(Value::as_str);
        #[cfg(test)]
        page.client.activation_diagnostic(
            "nav-frame",
            None,
            if frame.is_some() {
                "ok"
            } else {
                "malformed-frame"
            },
            None,
            None,
        );
        let frame = frame.ok_or(ProtocolError::BrowserFailure)?.to_owned();
        let previous_loader = tree
            .pointer("/frameTree/frame/loaderId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        // Subscribe after setup history but BEFORE the trigger. Overflow is an
        // explicit unknown browser outcome, never a dropped-event success.
        let methods: &'static [&'static str] = if retirement.is_some() {
            &[
                "Page.lifecycleEvent",
                "Page.frameNavigated",
                "Page.navigatedWithinDocument",
                "Page.frameStartedNavigating",
                "Page.frameStoppedLoading",
                "Page.frameDetached",
                "Inspector.detached",
                "Target.detachedFromTarget",
            ]
        } else {
            &[
                "Page.lifecycleEvent",
                "Page.frameNavigated",
                "Page.navigatedWithinDocument",
                "Inspector.detached",
                "Target.detachedFromTarget",
            ]
        };
        let mut events = page
            .client
            .subscribe_bounded_methods(methods, 256, 65_536)
            .map_err(|_| {
                #[cfg(test)]
                page.client
                    .activation_diagnostic("nav-subscribe", None, "failed", None, None);
                ProtocolError::CapacityExceeded
            })?;
        #[cfg(test)]
        page.client
            .activation_diagnostic("nav-subscribe", None, "ok", None, None);
        if wait == "networkidle" {
            self.state()?
                .network
                .get_mut(&page.page_session_id)
                .ok_or(ProtocolError::ScopeUnavailable)?
                .quiet_since = Instant::now();
        }
        let response = navigation_retirement::trigger(
            page,
            op,
            method,
            args,
            &frame,
            previous_loader.as_deref(),
            &mut events,
            retirement,
        )
        .await;
        #[cfg(test)]
        page.client.activation_diagnostic(
            "nav-trigger-result",
            Some(method),
            if response.is_ok() { "ok" } else { "failed" },
            response.as_ref().err(),
            None,
        );
        let response = response?;
        if response
            .get("errorText")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
            || response.get("isDownload") == Some(&Value::Bool(true))
        {
            #[cfg(test)]
            page.client.activation_diagnostic(
                "nav-trigger-result",
                Some(method),
                if response.get("isDownload") == Some(&Value::Bool(true)) {
                    "download"
                } else {
                    "error-text"
                },
                None,
                None,
            );
            return Err(ProtocolError::BrowserFailure);
        }
        let mut loader = response
            .get("loaderId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        #[cfg(test)]
        page.client.activation_diagnostic(
            "nav-wait",
            None,
            if method != "Page.navigate" || loader.is_some() {
                "entered"
            } else {
                "bypass"
            },
            None,
            None,
        );
        if method != "Page.navigate" || loader.is_some() {
            let mut cancel = op.cancellation.clone();
            let mut reached = BTreeSet::new();
            let mut restored_milestones_requested = false;
            loop {
                check(page, op)?;
                let event = tokio::select! {
                    event=events.recv()=>event.map_err(|_error| {
                        #[cfg(test)]
                        page.client.activation_diagnostic("nav-event", None, if _error == "control event overflow" { "overflow" } else { "channel-closed" }, None, None);
                        ProtocolError::BrowserFailure
                    })?,
                    _=cancel.changed()=> {
                        #[cfg(test)]
                        page.client.activation_diagnostic("nav-wait", None, "cancelled", None, None);
                        return Err(ProtocolError::Cancelled);
                    },
                    _=tokio::time::sleep_until(op.deadline.into())=> {
                        #[cfg(test)]
                        page.client.activation_diagnostic("nav-wait", None, "deadline", None, None);
                        return Err(ProtocolError::DeadlineExceeded);
                    },
                };
                #[cfg(test)]
                page.client.activation_diagnostic(
                    "nav-event",
                    Some(&event.method),
                    "received",
                    None,
                    Some([
                        event.session_id.as_deref() == session,
                        event
                            .params
                            .get("frameId")
                            .or_else(|| event.params.pointer("/frame/id"))
                            .and_then(Value::as_str)
                            == Some(&frame),
                        event
                            .params
                            .get("loaderId")
                            .or_else(|| event.params.pointer("/frame/loaderId"))
                            .and_then(Value::as_str)
                            .is_some_and(|id| Some(id) == loader.as_deref()),
                        event.params.get("name").and_then(Value::as_str) == Some(expected),
                    ]),
                );
                if event.method == "Target.detachedFromTarget"
                    && event.params.get("sessionId").and_then(Value::as_str) == session
                {
                    #[cfg(test)]
                    page.client.activation_diagnostic(
                        "nav-event",
                        Some("Target.detachedFromTarget"),
                        "failed",
                        None,
                        None,
                    );
                    return Err(ProtocolError::BrowserFailure);
                }
                if event.session_id.as_deref() != session {
                    continue;
                }
                if event.method == "Inspector.detached" {
                    #[cfg(test)]
                    page.client.activation_diagnostic(
                        "nav-event",
                        Some("Inspector.detached"),
                        "failed",
                        None,
                        None,
                    );
                    return Err(ProtocolError::BrowserFailure);
                }
                if event.method == "Page.navigatedWithinDocument"
                    && event.params.get("frameId").and_then(Value::as_str) == Some(&frame)
                {
                    break;
                }
                if event.method == "Page.frameNavigated"
                    && event.params.pointer("/frame/id").and_then(Value::as_str) == Some(&frame)
                {
                    let candidate = event
                        .params
                        .pointer("/frame/loaderId")
                        .and_then(Value::as_str);
                    if candidate.is_some() && candidate != previous_loader.as_deref() {
                        loader = candidate.map(str::to_owned);
                        if method == "Page.navigateToHistoryEntry"
                            && event.params.get("type").and_then(Value::as_str)
                                == Some("BackForwardCacheRestore")
                            && candidate.is_some_and(|id| !id.is_empty())
                            && !restored_milestones_requested
                        {
                            // BFCache restores do not dispatch new document load
                            // events. Chromium replays the current document's real
                            // recorded lifecycle milestones when enabled again.
                            // Keep the original lease and exact frame/loader proof;
                            // the restore notification alone is not completion.
                            restored_milestones_requested = true;
                            command(
                                page,
                                op,
                                session,
                                "Page.setLifecycleEventsEnabled",
                                json!({"enabled":true}),
                            )
                            .await?;
                        }
                    }
                }
                if event.method == "Page.lifecycleEvent"
                    && event.params.get("frameId").and_then(Value::as_str) == Some(&frame)
                    && event.params.get("name").and_then(Value::as_str) == Some(expected)
                {
                    if let Some(id) = event.params.get("loaderId").and_then(Value::as_str) {
                        reached.insert(id.to_owned());
                    }
                }
                if loader.as_ref().is_some_and(|id| reached.contains(id)) {
                    break;
                }
            }
        }
        if wait == "networkidle" {
            self.wait_network_idle(page, op).await?;
        }
        #[cfg(test)]
        page.client
            .activation_diagnostic("nav-origin-read", None, "entered", None, None);
        let value = bounded(
            page,
            op,
            client_debt::command_scope(
                CommandCategory::ApplicationRead,
                false,
                evaluate_on(&page.client, &page.page_session_id, "location.href"),
            ),
        )
        .await;
        #[cfg(test)]
        page.client.activation_diagnostic(
            "nav-origin-read",
            None,
            if value.is_ok() { "ok" } else { "failed" },
            value.as_ref().err(),
            None,
        );
        let value = value?;
        // Same-document navigation from an attached profile's initial page
        // does not add a visited origin in the original context contract.
        if let Some(url) = value
            .as_str()
            .filter(|_| loader.is_some())
            .and_then(|s| url::Url::parse(s).ok())
        {
            let origin = url.origin().ascii_serialization();
            if origin != "null" {
                self.state()?.origins.insert(origin);
            }
        }
        #[cfg(test)]
        page.client
            .activation_diagnostic("nav-complete", None, "ok", None, None);
        Ok(())
    }
    async fn browser_is_mac(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<bool, ProtocolError> {
        if let Some(is_mac) = self.state()?.browser_is_mac {
            return Ok(is_mac);
        }
        let version = command(page, op, None, "Browser.getVersion", json!({})).await?;
        let user_agent = version
            .get("userAgent")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::BrowserFailure)?;
        let is_mac = user_agent.contains("Macintosh") || user_agent.contains("Mac OS X");
        self.state()?.browser_is_mac = Some(is_mac);
        Ok(is_mac)
    }
    async fn key_event(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
        key: Key,
        down: bool,
        typed: bool,
    ) -> Result<(), ProtocolError> {
        self.validate(page, op)?;
        let is_mac = if down {
            self.browser_is_mac(page, op).await?
        } else {
            false
        };
        let mut params = {
            let mut s = self.state()?;
            if s.input_cleanup.is_some() {
                return Err(ProtocolError::ScopeUnavailable);
            }
            bind_input_session(&mut s.input, &page.page_session_id)?;
            let repeat = s.input.keys.contains_key(&key.code);
            if down {
                s.input.keys.insert(key.code.clone(), key.clone());
            } else {
                s.input.keys.remove(&key.code);
            }
            key_params(&key, down, repeat, modifiers(&s.input), typed)
        };
        if is_mac {
            params["commands"] = json!(mac_editing_commands(
                &key.code,
                params["modifiers"].as_i64().unwrap_or(0) as i32
            ));
        }
        command(
            page,
            op,
            Some(&page.page_session_id),
            "Input.dispatchKeyEvent",
            params,
        )
        .await?;
        Ok(())
    }
    /// Pure preflight before deferred borrowed-page activation or any CDP work.
    pub(crate) fn validate_navigation(args: &Value) -> Result<(), ProtocolError> {
        decode_navigation(args).map(|_| ())
    }
    /// Pure API preflight, shared with locator actions before focus or selection.
    pub(crate) fn validate_keyboard_command(
        action: &str,
        value: &str,
    ) -> Result<(), ProtocolError> {
        match action {
            "type" => Ok(()),
            "down" | "up" => key_descriptor(value).map(|_| ()),
            "press" => {
                for part in split_chord(value)? {
                    key_descriptor(&part)?;
                }
                Ok(())
            }
            _ => invalid(),
        }
    }
    async fn keyboard(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
        a: &Keyboard,
    ) -> Result<(), ProtocolError> {
        Self::validate_keyboard_command(&a.action, &a.value)?;
        match a.action.as_str() {
            "down" | "up" => {
                self.key_event(
                    page,
                    op,
                    key_descriptor(&a.value)?,
                    a.action == "down",
                    false,
                )
                .await
            }
            "type" => {
                for ch in a.value.chars() {
                    if let Ok(descriptor) = key_descriptor(&ch.to_string()) {
                        self.key_event(page, op, descriptor.clone(), true, false)
                            .await?;
                        self.key_event(page, op, descriptor, false, false).await?;
                    } else {
                        command(
                            page,
                            op,
                            Some(&page.page_session_id),
                            "Input.insertText",
                            json!({"text":ch.to_string()}),
                        )
                        .await?;
                    }
                }
                Ok(())
            }
            "press" => {
                let parts = split_chord(&a.value)?;
                // Validate the entire chord before the first effect.
                let keys = parts
                    .iter()
                    .map(|p| key_descriptor(p))
                    .collect::<Result<Vec<_>, _>>()?;
                let (last, mods) = keys.split_last().ok_or(ProtocolError::InvalidArguments)?;
                for key in mods {
                    self.key_event(page, op, key.clone(), true, false).await?;
                }
                self.key_event(page, op, last.clone(), true, false).await?;
                self.key_event(page, op, last.clone(), false, false).await?;
                for key in mods.iter().rev() {
                    self.key_event(page, op, key.clone(), false, false).await?;
                }
                Ok(())
            }
            _ => invalid(),
        }
    }
    pub(crate) async fn acquire_modifiers(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
        requested: &[String],
    ) -> Result<ModifierReceipt, ProtocolError> {
        self.validate(page, op)?;
        if requested.len() > 8 {
            return invalid();
        }
        // Validate the complete set before changing any held key.
        let keys = requested
            .iter()
            .map(|name| {
                let key = key_descriptor(name)?;
                if key.modifier == 0 {
                    return invalid();
                }
                Ok(key)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut receipt = ModifierReceipt {
            identity_scope: page.identity_scope.clone(),
            session: page.page_session_id.clone(),
            keys: Vec::new(),
            released: Vec::new(),
        };
        let requested_bits = keys.iter().fold(0, |bits, key| bits | key.modifier);
        let previous = {
            let mut state = self.state()?;
            if state.input_cleanup.is_some() {
                return Err(ProtocolError::ScopeUnavailable);
            }
            bind_input_session(&mut state.input, &page.page_session_id)?;
            state
                .input
                .keys
                .values()
                .filter(|key| key.modifier != 0 && requested_bits & key.modifier == 0)
                .cloned()
                .collect::<Vec<_>>()
        };
        for key in previous {
            self.key_event(page, op, key.clone(), false, false).await?;
            receipt.released.push(key);
        }
        for key in keys {
            let held = {
                let mut state = self.state()?;
                if state.input_cleanup.is_some() {
                    return Err(ProtocolError::ScopeUnavailable);
                }
                bind_input_session(&mut state.input, &page.page_session_id)?;
                modifiers(&state.input)
            };
            // A held right-side key already satisfies the corresponding modifier.
            if held & key.modifier != 0 {
                continue;
            }
            self.key_event(page, op, key.clone(), true, false).await?;
            receipt.keys.push(key);
        }
        Ok(receipt)
    }

    pub(crate) async fn restore_modifiers(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
        receipt: ModifierReceipt,
    ) -> Result<(), ProtocolError> {
        self.validate(page, op)?;
        if receipt.identity_scope != page.identity_scope || receipt.session != page.page_session_id
        {
            return Err(ProtocolError::StaleScope);
        }
        for key in receipt.keys.into_iter().rev() {
            self.key_event(page, op, key, false, false).await?;
        }
        for key in receipt.released {
            self.key_event(page, op, key, true, false).await?;
        }
        Ok(())
    }

    /// Shared primitive for locator actions and public mouse commands. Input
    /// state is updated before dispatch so uncertain effects remain cleanable.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn pointer_event(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
        kind: &str,
        point: Option<(f64, f64)>,
        button: Option<&str>,
        click_count: Option<i32>,
        delta: Option<(f64, f64)>,
    ) -> Result<(), ProtocolError> {
        self.validate(page, op)?;
        if point.is_some_and(|(x, y)| !x.is_finite() || !y.is_finite())
            || delta.is_some_and(|(x, y)| !x.is_finite() || !y.is_finite())
        {
            return invalid();
        }
        match kind {
            "mousePressed" | "mouseReleased"
                if matches!(
                    button,
                    Some("left" | "right" | "middle" | "back" | "forward")
                ) && click_count.is_none_or(|n| n > 0)
                    && delta.is_none() => {}
            "mouseMoved" if button.is_none() && click_count.is_none() && delta.is_none() => {}
            "mouseWheel" if button.is_none() && click_count.is_none() && delta.is_some() => {}
            _ => return invalid(),
        }
        let params = {
            let mut state = self.state()?;
            if state.input_cleanup.is_some() {
                return Err(ProtocolError::ScopeUnavailable);
            }
            bind_input_session(&mut state.input, &page.page_session_id)?;
            if point.is_some() {
                state.input.pointer_known = false;
            }
            let mods = modifiers(&state.input);
            build_mouse_event_params(
                &mut state.input.mouse,
                kind,
                point.map(|p| p.0),
                point.map(|p| p.1),
                button,
                None,
                button.map(|_| click_count.unwrap_or(1)),
                delta.map(|p| p.0),
                delta.map(|p| p.1),
                Some(mods),
            )
        };
        let mut params = serde_json::to_value(params).map_err(|_| ProtocolError::BrowserFailure)?;
        if kind == "mouseWheel" {
            for field in ["button", "buttons", "clickCount"] {
                params.as_object_mut().unwrap().remove(field);
            }
        }
        command(
            page,
            op,
            Some(&page.page_session_id),
            "Input.dispatchMouseEvent",
            params,
        )
        .await?;
        if let Some((x, y)) = point {
            let mut state = self.state()?;
            if state.input.session.as_deref() == Some(page.page_session_id.as_str())
                && state.input.mouse.x == x
                && state.input.mouse.y == y
                && state.input_cleanup.is_none()
            {
                state.input.pointer_known = true;
            }
        }
        Ok(())
    }

    async fn mouse(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
        a: Mouse,
    ) -> Result<(), ProtocolError> {
        let (kind, x, y, button, dx, dy) = match a {
            Mouse::Move { x, y } if x.is_finite() && y.is_finite() => {
                ("mouseMoved", Some(x), Some(y), None, None, None)
            }
            Mouse::Wheel { delta_x, delta_y } if delta_x.is_finite() && delta_y.is_finite() => {
                ("mouseWheel", None, None, None, Some(delta_x), Some(delta_y))
            }
            Mouse::Down => ("mousePressed", None, None, Some("left"), None, None),
            Mouse::Up => ("mouseReleased", None, None, Some("left"), None, None),
            _ => return invalid(),
        };
        self.pointer_event(
            page,
            op,
            kind,
            x.zip(y),
            button,
            button.map(|_| 1),
            dx.zip(dy),
        )
        .await
    }
    /// Cleanup runs outside the cancelled operation budget. Caller must retain
    /// this future until it settles and quarantine this scope on any failure.
    /// Do not call after disposing or replacing the owned context.
    pub async fn release_input(&self, page: &BrowserExecutionLease) -> Result<(), ProtocolError> {
        page.permit.check()?;
        let session = self
            .state()?
            .input
            .session
            .clone()
            .unwrap_or_else(|| page.page_session_id.clone());
        self.release_borrowed_input(
            &page.client,
            &page.identity_scope,
            &session,
            Instant::now() + Duration::from_secs(2),
        )
        .await?;
        page.permit.check()
    }
    pub(crate) async fn release_borrowed_input(
        &self,
        client: &super::cdp::client::CdpClient,
        identity_scope: &str,
        session: &str,
        deadline: Instant,
    ) -> Result<(), ProtocolError> {
        if identity_scope != self.identity_scope {
            return Err(ProtocolError::StaleScope);
        }
        if Instant::now() >= deadline {
            return Err(ProtocolError::CleanupFailed);
        }
        let mut input = self.state()?.input.clone();
        if input.session.as_deref().is_some_and(|old| old != session) {
            return Ok(());
        }
        let session = session.to_owned();
        let mut commands = Vec::new();
        for key in input.keys.clone().into_values() {
            input.keys.remove(&key.code);
            commands.push((
                "Input.dispatchKeyEvent",
                key_params(&key, false, false, modifiers(&input), false),
            ));
        }
        for (button, mask) in [
            ("left", 1),
            ("right", 2),
            ("middle", 4),
            ("back", 8),
            ("forward", 16),
        ] {
            if input.mouse.buttons & mask == 0 {
                continue;
            }
            let params = build_mouse_event_params(
                &mut input.mouse,
                "mouseReleased",
                None,
                None,
                Some(button),
                None,
                Some(1),
                None,
                None,
                Some(0),
            );
            commands.push((
                "Input.dispatchMouseEvent",
                serde_json::to_value(params).map_err(|_| ProtocolError::CleanupFailed)?,
            ));
        }
        let clean = InputState {
            mouse: input.mouse,
            pointer_known: input.pointer_known,
            session: Some(session.clone()),
            ..InputState::default()
        };
        if commands.is_empty() {
            return Ok(());
        }
        let mut statuses = Vec::new();
        // Reserve the whole bounded cleanup batch before any send. Failure to
        // reserve even one required key/button is an actual cleanup failure.
        let mut reserved = Vec::new();
        for (method, params) in commands {
            let reservation =
                client_debt::command_scope(CommandCategory::CleanupInput, false, async {
                    client.reserve_tracked_command(method, Some(&params), Some(&session))
                })
                .await
                .map_err(|_| ProtocolError::CleanupFailed)?;
            if let Some(reservation) = &reservation {
                statuses.push(reservation.status());
            }
            reserved.push((method, params, reservation));
        }
        let tracked = statuses.len() == reserved.len();
        let cleanup = futures_util::future::join_all(reserved.into_iter().map(
            |(method, params, reservation)| {
                client.send_reserved_command(method, Some(params), Some(&session), reservation)
            },
        ));
        let result = tokio::time::timeout_at(deadline.into(), cleanup).await;
        let all_acknowledged = matches!(&result, Ok(results) if results.iter().all(Result::is_ok));
        if all_acknowledged {
            self.state()?.input = clean;
            self.state()?.input_cleanup = None;
        } else if tracked
            && statuses
                .iter()
                .all(|status| status.settled() || status.accountably_retained())
            && client
                .debt_ledger()
                .is_some_and(|ledger| !ledger.snapshot().integrity_lost)
        {
            // Unacknowledged releases are remote input debt, not proof the
            // browser is clean. Keep exact statuses so late reader ACKs can
            // reconcile local held state before any later input uses it.
            self.state()?.input_cleanup = Some((statuses, clean));
            if let Some(journal) = OperationJournalHandle::current() {
                journal.record_cleanup_disposition(CleanupDisposition::AccountedRemoteDebt);
            }
        } else {
            return Err(ProtocolError::CleanupFailed);
        }
        Ok(())
    }
}
fn bind_input_session(input: &mut InputState, session: &str) -> Result<(), ProtocolError> {
    if input.session.as_deref().is_some_and(|old| old != session)
        && (!input.keys.is_empty() || input.mouse.buttons != 0)
    {
        return Err(ProtocolError::ScopeUnavailable);
    }
    if input.session.as_deref().is_some_and(|old| old != session) {
        input.mouse = MouseState::default();
        input.pointer_known = false;
    }
    input.session = Some(session.into());
    Ok(())
}
fn modifiers(input: &InputState) -> i32 {
    input.keys.values().fold(0, |bits, key| bits | key.modifier)
}
fn split_chord(value: &str) -> Result<Vec<String>, ProtocolError> {
    let mut parts = Vec::new();
    let mut start = 0;
    for (index, ch) in value.char_indices() {
        if ch == '+' && index > start {
            parts.push(value[start..index].to_owned());
            start = index + 1;
        }
    }
    if start >= value.len() {
        return invalid();
    }
    parts.push(value[start..].to_owned());
    Ok(parts)
}
fn key_descriptor(value: &str) -> Result<Key, ProtocolError> {
    let value = if value == "ControlOrMeta" {
        if cfg!(target_os = "macos") {
            "Meta"
        } else {
            "Control"
        }
    } else {
        value
    };
    let modifier = match value {
        "Alt" | "AltLeft" | "AltRight" => Some(("Alt", 18, 1)),
        "Control" | "ControlLeft" | "ControlRight" => Some(("Control", 17, 2)),
        "Meta" | "MetaLeft" | "MetaRight" => Some(("Meta", 91, 4)),
        "Shift" | "ShiftLeft" | "ShiftRight" => Some(("Shift", 16, 8)),
        _ => None,
    };
    if let Some((key, vk, modifier)) = modifier {
        let right = value.ends_with("Right");
        return Ok(Key {
            key: key.into(),
            code: format!("{}{}", key, if right { "Right" } else { "Left" }),
            vk: if right && key == "Meta" { 92 } else { vk },
            modifier,
            location: if right { 2 } else { 1 },
        });
    }
    if let Some(number) = value
        .strip_prefix('F')
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|v| (1..=24).contains(v))
    {
        if value != format!("F{number}") {
            return invalid();
        }
        return Ok(Key {
            key: value.into(),
            code: value.into(),
            vk: 111 + number,
            modifier: 0,
            location: 0,
        });
    }
    let punctuation = match value {
        "Backquote" => Some('`'),
        "Minus" => Some('-'),
        "Equal" => Some('='),
        "Backslash" => Some('\\'),
        "BracketLeft" => Some('['),
        "BracketRight" => Some(']'),
        "Semicolon" => Some(';'),
        "Quote" => Some('\''),
        "Comma" => Some(','),
        "Period" => Some('.'),
        "Slash" => Some('/'),
        _ => None,
    };
    if let Some(ch) = punctuation {
        let (key, code, vk) = char_to_key_info(ch);
        return Ok(Key {
            key,
            code,
            vk,
            modifier: 0,
            location: 0,
        });
    }
    if let Some(index) = "!@#$%^&*()".chars().position(|c| value == c.to_string()) {
        let digit = "1234567890".chars().nth(index).unwrap();
        let (_, code, vk) = char_to_key_info(digit);
        return Ok(Key {
            key: value.into(),
            code,
            vk,
            modifier: 0,
            location: 0,
        });
    }
    let keypad = match value {
        "Numpad0" => Some(("Insert", 45)),
        "Numpad1" => Some(("End", 35)),
        "Numpad2" => Some(("ArrowDown", 40)),
        "Numpad3" => Some(("PageDown", 34)),
        "Numpad4" => Some(("ArrowLeft", 37)),
        "Numpad5" => Some(("Clear", 12)),
        "Numpad6" => Some(("ArrowRight", 39)),
        "Numpad7" => Some(("Home", 36)),
        "Numpad8" => Some(("ArrowUp", 38)),
        "Numpad9" => Some(("PageUp", 33)),
        "NumpadDecimal" => Some(("Delete", 46)),
        "NumpadEnter" => Some(("Enter", 13)),
        "NumpadDivide" => Some(("/", 111)),
        "NumpadMultiply" => Some(("*", 106)),
        "NumpadSubtract" => Some(("-", 109)),
        "NumpadAdd" => Some(("+", 107)),
        _ => None,
    };
    if let Some((key, vk)) = keypad {
        return Ok(Key {
            key: key.into(),
            code: value.into(),
            vk,
            modifier: 0,
            location: 3,
        });
    }
    let (key, code, vk) = if let Some(letter) = value
        .strip_prefix("Key")
        .filter(|s| s.len() == 1 && s.as_bytes()[0].is_ascii_uppercase())
    {
        char_to_key_info(letter.to_ascii_lowercase().chars().next().unwrap())
    } else if let Some(digit) = value
        .strip_prefix("Digit")
        .filter(|s| s.len() == 1 && s.as_bytes()[0].is_ascii_digit())
    {
        char_to_key_info(digit.chars().next().unwrap())
    } else {
        match value {
            "AltGraph" => ("AltGraph".into(), "AltGraph".into(), 225),
            "AudioVolumeMute" => (value.into(), value.into(), 173),
            "AudioVolumeDown" => (value.into(), value.into(), 174),
            "AudioVolumeUp" => (value.into(), value.into(), 175),
            "MediaTrackNext" => (value.into(), value.into(), 176),
            "MediaTrackPrevious" => (value.into(), value.into(), 177),
            "MediaPlayPause" => (value.into(), value.into(), 179),
            "Insert" => ("Insert".into(), "Insert".into(), 45),
            "CapsLock" => ("CapsLock".into(), "CapsLock".into(), 20),
            "NumLock" => ("NumLock".into(), "NumLock".into(), 144),
            "ScrollLock" => ("ScrollLock".into(), "ScrollLock".into(), 145),
            "Pause" => ("Pause".into(), "Pause".into(), 19),
            "PrintScreen" => ("PrintScreen".into(), "PrintScreen".into(), 44),
            "ContextMenu" => ("ContextMenu".into(), "ContextMenu".into(), 93),
            "Space" => char_to_key_info(' '),
            _ => named_key_info(value),
        }
    };
    if vk == 0 || code.is_empty() {
        return invalid();
    }
    Ok(Key {
        key,
        code,
        vk,
        modifier: 0,
        location: 0,
    })
}
fn shifted(key: &str) -> String {
    let lower = "`1234567890-=[]\\;',./";
    let upper = "~!@#$%^&*()_+{}|:\"<>?";
    if let Some(index) = lower.chars().position(|c| key == c.to_string()) {
        return upper.chars().nth(index).unwrap().to_string();
    }
    key.to_ascii_uppercase()
}
fn key_params(key: &Key, down: bool, repeat: bool, mods: i32, typed: bool) -> Value {
    let mut vk = key.vk;
    let name = if mods & 8 != 0 && key.location == 3 {
        if let Some(digit) = key
            .code
            .strip_prefix("Numpad")
            .filter(|v| v.len() == 1 && v.as_bytes()[0].is_ascii_digit())
        {
            vk = 96 + digit.parse::<i32>().unwrap();
            digit.to_owned()
        } else if key.code == "NumpadDecimal" {
            vk = 110;
            ".".into()
        } else {
            key.key.clone()
        }
    } else if mods & 8 != 0 && key.key.len() == 1 && !typed {
        shifted(&key.key)
    } else {
        key.key.clone()
    };
    let text = if down && name != "Tab" && (typed || mods & !8 == 0) {
        key_text(&name)
    } else {
        None
    };
    let mut params = json!({"type":if down {if text.is_some(){"keyDown"}else{"rawKeyDown"}}else{"keyUp"},"key":name,"code":key.code,"windowsVirtualKeyCode":vk,"modifiers":mods,"autoRepeat":down&&repeat,"location":key.location,"isKeypad":key.location==3});
    if let Some(text) = text {
        params["text"] = json!(text);
        params["unmodifiedText"] = json!(text);
    }
    params
}
// Chromium macOS editing command bindings, cross-checked against the
// Apache-2.0 Playwright macEditingCommands.ts compatibility oracle. Native
// commands only: there is no Playwright runtime or JavaScript input shim.
fn mac_editing_commands(code: &str, modifiers: i32) -> &'static [&'static str] {
    match (modifiers, code) {
        (0, "Backspace") => &["deleteBackward"],
        (0, "Escape") => &["cancelOperation"],
        (0, "ArrowUp") => &["moveUp"],
        (0, "ArrowDown") => &["moveDown"],
        (0, "ArrowLeft") => &["moveLeft"],
        (0, "ArrowRight") => &["moveRight"],
        (0, "F5") => &["complete"],
        (0, "Delete") => &["deleteForward"],
        (0, "Home") => &["scrollToBeginningOfDocument"],
        (0, "End") => &["scrollToEndOfDocument"],
        (0, "PageUp") => &["scrollPageUp"],
        (0, "PageDown") => &["scrollPageDown"],
        (8, "Backspace") => &["deleteBackward"],
        (8, "Escape") => &["cancelOperation"],
        (8, "ArrowUp") => &["moveUpAndModifySelection"],
        (8, "ArrowDown") => &["moveDownAndModifySelection"],
        (8, "ArrowLeft") => &["moveLeftAndModifySelection"],
        (8, "ArrowRight") => &["moveRightAndModifySelection"],
        (8, "F5") => &["complete"],
        (8, "Delete") => &["deleteForward"],
        (8, "Home") => &["moveToBeginningOfDocumentAndModifySelection"],
        (8, "End") => &["moveToEndOfDocumentAndModifySelection"],
        (8, "PageUp") => &["pageUpAndModifySelection"],
        (8, "PageDown") => &["pageDownAndModifySelection"],
        (8, "Numpad5") => &["delete"],
        (2, "Tab") => &["selectNextKeyView"],
        (2, "KeyA") => &["moveToBeginningOfParagraph"],
        (2, "KeyB") => &["moveBackward"],
        (2, "KeyD") => &["deleteForward"],
        (2, "KeyE") => &["moveToEndOfParagraph"],
        (2, "KeyF") => &["moveForward"],
        (2, "KeyH") => &["deleteBackward"],
        (2, "KeyK") => &["deleteToEndOfParagraph"],
        (2, "KeyL") => &["centerSelectionInVisibleArea"],
        (2, "KeyN") => &["moveDown"],
        (2, "KeyO") => &["moveBackward"],
        (2, "KeyP") => &["moveUp"],
        (2, "KeyT") => &["transpose"],
        (2, "KeyV") => &["pageDown"],
        (2, "KeyY") => &["yank"],
        (2, "Backspace") => &["deleteBackwardByDecomposingPreviousCharacter"],
        (2, "ArrowUp") => &["scrollPageUp"],
        (2, "ArrowDown") => &["scrollPageDown"],
        (2, "ArrowLeft") => &["moveToLeftEndOfLine"],
        (2, "ArrowRight") => &["moveToRightEndOfLine"],
        (10, "Tab") => &["selectPreviousKeyView"],
        (10, "KeyA") => &["moveToBeginningOfParagraphAndModifySelection"],
        (10, "KeyB") => &["moveBackwardAndModifySelection"],
        (10, "KeyE") => &["moveToEndOfParagraphAndModifySelection"],
        (10, "KeyF") => &["moveForwardAndModifySelection"],
        (10, "KeyN") => &["moveDownAndModifySelection"],
        (10, "KeyP") => &["moveUpAndModifySelection"],
        (10, "KeyV") => &["pageDownAndModifySelection"],
        (10, "Backspace") => &["deleteBackwardByDecomposingPreviousCharacter"],
        (10, "ArrowUp") => &["scrollPageUp"],
        (10, "ArrowDown") => &["scrollPageDown"],
        (10, "ArrowLeft") => &["moveToLeftEndOfLineAndModifySelection"],
        (10, "ArrowRight") => &["moveToRightEndOfLineAndModifySelection"],
        (1, "Backspace") => &["deleteWordBackward"],
        (1, "Escape") => &["complete"],
        (1, "ArrowUp") => &["moveBackward", "moveToBeginningOfParagraph"],
        (1, "ArrowDown") => &["moveForward", "moveToEndOfParagraph"],
        (1, "ArrowLeft") => &["moveWordLeft"],
        (1, "ArrowRight") => &["moveWordRight"],
        (1, "Delete") => &["deleteWordForward"],
        (1, "PageUp") => &["pageUp"],
        (1, "PageDown") => &["pageDown"],
        (9, "Backspace") => &["deleteWordBackward"],
        (9, "Escape") => &["complete"],
        (9, "ArrowUp") => &["moveParagraphBackwardAndModifySelection"],
        (9, "ArrowDown") => &["moveParagraphForwardAndModifySelection"],
        (9, "ArrowLeft") => &["moveWordLeftAndModifySelection"],
        (9, "ArrowRight") => &["moveWordRightAndModifySelection"],
        (9, "Delete") => &["deleteWordForward"],
        (9, "PageUp") => &["pageUp"],
        (9, "PageDown") => &["pageDown"],
        (3, "KeyB") => &["moveWordBackward"],
        (3, "KeyF") => &["moveWordForward"],
        (3, "Backspace") => &["deleteWordBackward"],
        (11, "KeyB") => &["moveWordBackwardAndModifySelection"],
        (11, "KeyF") => &["moveWordForwardAndModifySelection"],
        (11, "Backspace") => &["deleteWordBackward"],
        (4, "NumpadSubtract") => &["cancel"],
        (4, "Backspace") => &["deleteToBeginningOfLine"],
        (4, "ArrowUp") => &["moveToBeginningOfDocument"],
        (4, "ArrowDown") => &["moveToEndOfDocument"],
        (4, "ArrowLeft") => &["moveToLeftEndOfLine"],
        (4, "ArrowRight") => &["moveToRightEndOfLine"],
        (12, "NumpadSubtract") => &["cancel"],
        (12, "Backspace") => &["deleteToBeginningOfLine"],
        (12, "ArrowUp") => &["moveToBeginningOfDocumentAndModifySelection"],
        (12, "ArrowDown") => &["moveToEndOfDocumentAndModifySelection"],
        (12, "ArrowLeft") => &["moveToLeftEndOfLineAndModifySelection"],
        (12, "ArrowRight") => &["moveToRightEndOfLineAndModifySelection"],
        (4, "KeyA") => &["selectAll"],
        (4, "KeyC") => &["copy"],
        (4, "KeyX") => &["cut"],
        (4, "KeyV") => &["paste"],
        (4, "KeyZ") => &["undo"],
        (12, "KeyZ") => &["redo"],
        _ => &[],
    }
}
fn validate_cookie(value: &Value) -> Result<Value, ProtocolError> {
    let obj = value.as_object().ok_or(ProtocolError::InvalidArguments)?;
    if obj.keys().any(|key| {
        !matches!(
            key.as_str(),
            "name"
                | "value"
                | "url"
                | "domain"
                | "path"
                | "expires"
                | "httpOnly"
                | "secure"
                | "sameSite"
        )
    }) {
        return invalid();
    }
    if !value.get("name").is_some_and(Value::is_string)
        || !value.get("value").is_some_and(Value::is_string)
    {
        return invalid();
    }
    match (value.get("url"), value.get("domain")) {
        (Some(Value::String(url)), None) if !obj.contains_key("path") => {
            let parsed = url::Url::parse(url).map_err(|_| ProtocolError::InvalidArguments)?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return invalid();
            }
        }
        (None, Some(Value::String(domain))) if !domain.is_empty() => {}
        _ => return invalid(),
    }
    if value
        .get("path")
        .is_some_and(|p| !p.as_str().is_some_and(|s| s.starts_with('/')))
    {
        return invalid();
    }
    if value.get("expires").is_some_and(|v| {
        !v.as_f64()
            .is_some_and(|n| n.is_finite() && (n == -1.0 || n >= 0.0))
    }) {
        return invalid();
    }
    for field in ["httpOnly", "secure"] {
        if value.get(field).is_some_and(|v| !v.is_boolean()) {
            return invalid();
        }
    }
    if value
        .get("sameSite")
        .is_some_and(|v| !matches!(v.as_str(), Some("Strict" | "Lax" | "None")))
    {
        return invalid();
    }
    let mut result = value.clone();
    if result.get("domain").is_some() && result.get("path").is_none() {
        result["path"] = json!("/");
    }
    if result.get("expires").and_then(Value::as_f64) == Some(-1.0) {
        result.as_object_mut().unwrap().remove("expires");
    }
    Ok(result)
}
fn project_cookies(response: &Value) -> Result<Vec<Value>, ProtocolError> {
    response
        .get("cookies")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::BrowserFailure)?
        .iter()
        .map(|cookie| {
            let mut result = json!({});
            for field in ["name", "value", "domain", "path"] {
                result[field] = json!(cookie
                    .get(field)
                    .and_then(Value::as_str)
                    .ok_or(ProtocolError::BrowserFailure)?);
            }
            for field in ["httpOnly", "secure"] {
                result[field] = json!(cookie
                    .get(field)
                    .and_then(Value::as_bool)
                    .ok_or(ProtocolError::BrowserFailure)?);
            }
            let expires = cookie
                .get("expires")
                .and_then(Value::as_f64)
                .ok_or(ProtocolError::BrowserFailure)?;
            let session = cookie
                .get("session")
                .and_then(Value::as_bool)
                .ok_or(ProtocolError::BrowserFailure)?;
            result["expires"] = json!(if session { -1.0 } else { expires });
            result["sameSite"] = json!("Lax");
            if let Some(site) = cookie.get("sameSite") {
                if !matches!(site.as_str(), Some("Strict" | "Lax" | "None")) {
                    return Err(ProtocolError::BrowserFailure);
                }
                result["sameSite"] = site.clone();
            }
            Ok(result)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn fixed_page_reads_and_public_evaluate_have_distinct_real_dispatch_journals() {
        for (name, args, mutating) in [
            ("page.title", json!({}), false),
            ("page.url", json!({}), false),
            (
                "page.evaluate",
                json!({"source":"()=>1","argument":null}),
                true,
            ),
        ] {
            let (page, log, server) = mock("hold-evaluate").await;
            let state = ClientPageState::new("scope".into(), "context".into());
            let ledger = client_debt::OwnerDebtLedger::new(1, "scope".into());
            page.client.install_debt_ledger(ledger.clone()).unwrap();
            let (mut op, _sender) = operation();
            op.deadline = Instant::now() + Duration::from_millis(30);
            let journal = ledger
                .operation(
                    client_debt::OperationKey {
                        generation: 1,
                        operation_seq: 1,
                    },
                    "target".into(),
                    "page".into(),
                )
                .unwrap();
            journal.bind_operation(&op).unwrap();
            assert_eq!(
                journal
                    .scope(state.execute(&page, &[], &op, name, &args))
                    .await,
                Err(ProtocolError::DeadlineExceeded)
            );
            assert_eq!(journal.snapshot().mutation_dispatched, mutating);
            assert_eq!(ledger.snapshot().input_debt, u32::from(mutating));
            let log = log.lock().unwrap();
            assert_eq!(log.len(), 1);
            assert_eq!(log[0]["method"], "Runtime.evaluate");
            assert_eq!(log[0]["sessionId"], "page");
            assert_eq!(log[0]["params"].get("userGesture").is_some(), mutating);
            drop(log);
            server.abort();
        }
    }
    #[tokio::test]
    async fn repeated_evaluation_exceptions_release_handles_and_lost_release_retains_debt() {
        for hold in [false, true] {
            let (page, log, server) = mock(if hold {
                "exception-handle-hold"
            } else {
                "exception-handle"
            })
            .await;
            let state = ClientPageState::new("scope".into(), "context".into());
            let ledger = client_debt::OwnerDebtLedger::new(1, "scope".into());
            page.client.install_debt_ledger(ledger.clone()).unwrap();
            let (op, _sender) = operation();
            let journal = ledger
                .operation(
                    client_debt::OperationKey {
                        generation: 1,
                        operation_seq: 1,
                    },
                    "target".into(),
                    "page".into(),
                )
                .unwrap();
            journal.bind_operation(&op).unwrap();
            for _ in 0..if hold { 1 } else { 40 } {
                assert_eq!(
                    journal
                        .scope(state.execute(
                            &page,
                            &[],
                            &op,
                            "page.evaluate",
                            &json!({"source":"()=>{throw 1}","argument":null})
                        ))
                        .await,
                    Err(ProtocolError::BrowserFailure)
                );
                assert_eq!(ledger.snapshot().object_debt, u32::from(hold));
                assert!(!ledger.snapshot().integrity_lost);
            }
            assert_eq!(
                log.lock()
                    .unwrap()
                    .iter()
                    .filter(|r| r["method"] == "Runtime.releaseObject")
                    .count(),
                if hold { 1 } else { 40 }
            );
            assert_eq!(ledger.snapshot().input_debt, 0);
            server.abort();
        }
    }

    use super::super::cdp::client::CdpClient;
    use super::super::client_browser::{ExecutionGate, OwnedBrowser};
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use std::sync::Arc;
    use tokio::sync::watch;
    use tokio_tungstenite::tungstenite::Message;

    #[test]
    fn config_snapshot_transfers_declarations_not_scope_authority() {
        let old = ClientPageState::new("old".into(), "context-old".into());
        {
            let mut state = old.state().unwrap();
            append_script(&mut state.config, Arc::from("globalThis.first = 1")).unwrap();
            append_script(&mut state.config, Arc::from("globalThis.second = 2")).unwrap();
            state.config.color_scheme = Some("dark".into());
            state.config.reduced_motion = Some("reduce".into());
            state.requested_viewport = Some((0, 720));
            state.origins.insert("https://old.example".into());
            state.installed_scripts.insert("old-session".into(), 2);
            state.input.session = Some("old-session".into());
            state.browser_is_mac = Some(true);
            state
                .network_roots
                .insert("old-session".into(), "old-session".into());
        }
        assert!(matches!(
            old.snapshot_config("new"),
            Err(ProtocolError::StaleScope)
        ));
        let snapshot = old.snapshot_config("old").unwrap();
        let fresh = ClientPageState::from_config_snapshot(
            "new".into(),
            "context-new".into(),
            snapshot.clone(),
        )
        .unwrap();
        assert!(ClientPageState::from_config_snapshot("".into(), "ctx".into(), snapshot).is_err());
        let state = fresh.state().unwrap();
        assert_eq!(
            state
                .config
                .scripts
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<&str>>(),
            vec!["globalThis.first = 1", "globalThis.second = 2"]
        );
        assert_eq!(state.config.color_scheme.as_deref(), Some("dark"));
        assert_eq!(state.config.reduced_motion.as_deref(), Some("reduce"));
        assert_eq!(state.requested_viewport, Some((0, 720)));
        assert_eq!(state.config.revision, 0);
        assert!(state.origins.is_empty() && state.installed_scripts.is_empty());
        assert!(state.input.session.is_none() && state.browser_is_mac.is_none());
        assert!(state.network_roots.is_empty() && state.network.is_empty());
        assert!(state.configuration_locks.is_empty());
    }
    #[tokio::test]
    async fn seeded_native_policy_is_not_duplicated_and_scripts_reinstall_per_new_session() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let old = ClientPageState::new("scope".into(), "context".into());
        old.ensure_service_worker_policy(&page, &op).unwrap();
        old.ensure_service_worker_policy(&page, &op).unwrap();
        let fresh = ClientPageState::from_config_snapshot(
            "scope".into(),
            "replacement-context".into(),
            old.snapshot_config("scope").unwrap(),
        )
        .unwrap();
        fresh.ensure_service_worker_policy(&page, &op).unwrap();
        assert_eq!(fresh.state().unwrap().config.scripts.len(), 1);
        fresh
            .apply_to_new_session(&page, "new-session", &op)
            .await
            .unwrap();
        fresh
            .apply_to_new_session(&page, "new-session", &op)
            .await
            .unwrap();
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|event| event["method"] == "Page.addScriptToEvaluateOnNewDocument")
                .count(),
            1
        );
        task.abort();
    }

    #[tokio::test]
    async fn component_page_lock_wait_observes_exact_stop_without_releasing_lock() {
        use std::future::Future;
        for signal in [CancelSignal::OwnerRetirement, CancelSignal::Requested] {
            let (page, log, server) = mock("normal").await;
            let state = ClientPageState::new("scope".into(), "context".into());
            let lock = Arc::new(tokio::sync::Mutex::new(()));
            state
                .state()
                .unwrap()
                .configuration_locks
                .insert("held-session".into(), lock.clone());
            let held = lock.lock().await;
            let (op, sender) = operation();
            let future = state.apply_to_new_session_initialization(&page, "held-session", &op);
            tokio::pin!(future);
            let pending = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(future.as_mut().poll(cx).is_pending())
            })
            .await;
            assert!(
                pending,
                "must reach actual retained configuration lock wait"
            );
            sender.send_replace(signal);
            let result = future.await;
            let Err(ObservedOperationFailure::Stopped(observed)) = result else {
                panic!("missing actual selected stop observation")
            };
            let (captured, observed_signal) = observed.into_parts();
            assert_eq!(observed_signal, signal);
            assert!(captured.cancellation.same_channel(&op.cancellation));
            assert_eq!(captured.sequence, op.sequence);
            assert!(log.lock().unwrap().is_empty());
            drop(held);
            server.abort();
            let _ = server.await;
        }
    }
    #[tokio::test]
    async fn component_page_failed_reply_cannot_borrow_later_owner_stop() {
        let (page, _log, server) = mock("normal").await;
        let (op, sender) = operation();
        let result = bounded_initialization_component(&page, &op, async {
            sender.send_replace(CancelSignal::OwnerRetirement);
            Err::<(), String>("controlled failure".into())
        })
        .await;
        // Original ordinary postcheck precedes raw error mapping. It may retain
        // Cancelled, but must NEVER mint a successful owner-retirement receipt.
        assert!(matches!(
            result,
            Err(ObservedOperationFailure::Operation(
                ProtocolError::Cancelled
            ))
        ));
        let (op, _sender) = operation();
        let result = bounded_initialization_component(&page, &op, async {
            Err::<(), String>("controlled failure".into())
        })
        .await;
        assert!(matches!(
            result,
            Err(ObservedOperationFailure::Operation(
                ProtocolError::BrowserFailure
            ))
        ));
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn component_page_success_postcheck_keeps_stop_and_failure_precedence() {
        let (page, _log, server) = mock("normal").await;
        let (op, sender) = operation();
        let result = bounded_initialization_component(&page, &op, async {
            sender.send_replace(CancelSignal::OwnerRetirement);
            Ok::<(), String>(())
        })
        .await;
        assert!(matches!(result, Err(ObservedOperationFailure::Stopped(_))));
        let wrong = ClientPageState::new("wrong-scope".into(), "context".into());
        assert!(matches!(
            wrong
                .apply_to_new_session_initialization(&page, "session", &op)
                .await,
            Err(ObservedOperationFailure::Operation(
                ProtocolError::StaleScope
            ))
        ));
        let (mut expired, _sender) = operation();
        expired.deadline = Instant::now();
        assert!(matches!(
            bounded_initialization_component(
                &page,
                &expired,
                std::future::pending::<Result<(), String>>()
            )
            .await,
            Err(ObservedOperationFailure::Operation(
                ProtocolError::DeadlineExceeded
            ))
        ));
        server.abort();
        let _ = server.await;
    }
    fn operation() -> (OperationLease, watch::Sender<CancelSignal>) {
        let (sender, cancellation) = watch::channel(CancelSignal::None);
        (
            OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline: Instant::now() + Duration::from_secs(5),
                cancellation,
            },
            sender,
        )
    }
    type Log = Arc<Mutex<Vec<Value>>>;
    async fn mock(mode: &'static str) -> (BrowserExecutionLease, Log, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let log: Log = Arc::default();
        let captured = log.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut history_restored = false;
            while let Some(Ok(message)) = ws.next().await {
                let Ok(text) = message.to_text() else {
                    continue;
                };
                let request: Value = serde_json::from_str(text).unwrap();
                captured.lock().unwrap().push(request.clone());
                let method = request["method"].as_str().unwrap();
                if mode == "cancel-down"
                    && method == "Input.dispatchKeyEvent"
                    && request["params"]["type"] != "keyUp"
                {
                    continue;
                }
                if mode == "hold-navigation" && method == "Page.navigate" {
                    continue;
                }
                if mode == "hold-evaluate" && method == "Runtime.evaluate" {
                    continue;
                }
                if mode == "exception-handle-hold" && method == "Runtime.releaseObject" {
                    continue;
                }
                let result = match method {
                    "Browser.getVersion" => json!({"userAgent":"Synthetic Chromium Linux"}),
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"main","loaderId":"old"}}})
                    }
                    "Page.setLifecycleEventsEnabled"
                        if mode.starts_with("restore-") && history_restored =>
                    {
                        // Chromium 156 replays the current document's recorded
                        // lifecycle timestamps when this command enables events.
                        // A BFCache restore itself emits frameNavigated only.
                        if mode == "restore-held-replay" {
                            continue;
                        }
                        if mode != "restore-missing-milestone" {
                            let session = if mode == "restore-milestone-wrong-session" {
                                "other"
                            } else {
                                "page"
                            };
                            let frame = if mode == "restore-milestone-wrong-frame" {
                                "child"
                            } else {
                                "main"
                            };
                            let loader = if mode == "restore-milestone-wrong-loader" {
                                "old"
                            } else {
                                "restored"
                            };
                            ws.send(Message::Text(json!({"method":"Page.lifecycleEvent","sessionId":session,"params":{"frameId":frame,"loaderId":loader,"name":"load"}}).to_string())).await.unwrap();
                        }
                        json!({})
                    }
                    "Page.navigate" | "Page.reload" | "Page.navigateToHistoryEntry" => {
                        if mode.starts_with("restore-") {
                            history_restored = true;
                            if mode == "restore-same-document" {
                                ws.send(Message::Text(json!({"method":"Page.navigatedWithinDocument","sessionId":"page","params":{"frameId":"main","url":"https://fixture.invalid/#restored"}}).to_string())).await.unwrap();
                            } else {
                                let session = if mode == "restore-wrong-session" {
                                    "other"
                                } else {
                                    "page"
                                };
                                let frame = if mode == "restore-wrong-frame" {
                                    "child"
                                } else {
                                    "main"
                                };
                                let loader = if mode == "restore-old-loader" {
                                    "old"
                                } else if mode == "restore-empty-loader" {
                                    ""
                                } else {
                                    "restored"
                                };
                                let kind = if mode == "restore-normal-navigation" {
                                    "Navigation"
                                } else {
                                    "BackForwardCacheRestore"
                                };
                                ws.send(Message::Text(json!({"method":"Page.frameNavigated","sessionId":session,"params":{"frame":{"id":frame,"loaderId":loader},"type":kind}}).to_string())).await.unwrap();
                            }
                        } else if mode != "same-document" {
                            for (session, loader, name) in [
                                ("other", "new", "load"),
                                ("page", "old", "load"),
                                ("page", "new", "DOMContentLoaded"),
                                ("page", "new", "networkIdle"),
                                ("page", "new", "load"),
                            ] {
                                if name == "DOMContentLoaded" {
                                    ws.send(Message::Text(json!({"method":"Page.frameNavigated","sessionId":"page","params":{"frame":{"id":"main","loaderId":"new"}}}).to_string())).await.unwrap();
                                }
                                ws.send(Message::Text(json!({"method":"Page.lifecycleEvent","sessionId":session,"params":{"frameId":"main","loaderId":loader,"name":name}}).to_string())).await.unwrap();
                            }
                        } else if method != "Page.navigate" {
                            ws.send(Message::Text(json!({"method":"Page.navigatedWithinDocument","sessionId":"page","params":{"frameId":"main","url":"https://fixture.invalid/#two"}}).to_string())).await.unwrap();
                        }
                        if method == "Page.navigate" && mode.starts_with("restore-") {
                            json!({"frameId":"main","loaderId":"restored"})
                        } else if method == "Page.navigate" && mode != "same-document" {
                            json!({"frameId":"main","loaderId":"new"})
                        } else {
                            json!({})
                        }
                    }
                    "Page.getNavigationHistory" => {
                        json!({"currentIndex":if mode == "restore-back" { 1 } else { 0 },"entries":[{"id":1},{"id":2}]})
                    }
                    "Runtime.evaluate" if mode == "malformed-evaluate" => {
                        json!({"result":{"type":"object","value":{}}})
                    }
                    "Runtime.evaluate" if mode.starts_with("exception-handle") => {
                        json!({"result":{"type":"undefined"},"exceptionDetails":{"text":"synthetic exception","exception":{"type":"object","description":"synthetic exception","objectId":"exception-handle"}}})
                    }
                    "Runtime.evaluate" if mode == "exception-evaluate" => {
                        json!({"result":{"type":"undefined"},"exceptionDetails":{"text":"synthetic exception","exception":{"type":"object","description":"synthetic exception"}}})
                    }
                    "Runtime.evaluate"
                        if request["params"]["expression"]
                            .as_str()
                            .is_some_and(|s| s.starts_with("(async()=>")) =>
                    {
                        json!({"result":{"type":"object","value":{"value":{"ok":true,"value":null}}}})
                    }
                    "Runtime.evaluate" => {
                        json!({"result":{"type":"string","value":"https://fixture.invalid/path"}})
                    }
                    "Storage.getCookies" => {
                        json!({"cookies":[{"name":"sid","value":"synthetic","domain":"fixture.invalid","path":"/","expires":0,"session":true,"httpOnly":true,"secure":false,"sameSite":"Lax"}]})
                    }
                    "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":"script"}),
                    _ => json!({}),
                };
                if ws
                    .send(Message::Text(
                        json!({"id":request["id"],"sessionId":request["sessionId"],"result":result}).to_string(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        let gate = Arc::new(ExecutionGate::default());
        (
            BrowserExecutionLease {
                client,
                page_session_id: "page".into(),
                target_id: "target".into(),
                identity_scope: "scope".into(),
                permit: gate.enter(false).unwrap(),
                targets: super::super::client_targets::ClientTargets::new(
                    "context".into(),
                    "scope".into(),
                ),
            },
            log,
            task,
        )
    }
    // Controlled transport evidence, deliberately not a recovery policy. The
    // peer accepts every command but can withhold one reply while still serving
    // cleanup and a later drain barrier on the same WebSocket.
    async fn command_debt_peer(
        cancel: watch::Sender<CancelSignal>,
        hold_release: bool,
    ) -> (BrowserExecutionLease, Log, Log, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let requests: Log = Arc::default();
        let replies: Log = Arc::default();
        let received = requests.clone();
        let acknowledged = replies.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut held: Option<Value> = None;
            while let Some(Ok(Message::Text(text))) = socket.next().await {
                let request: Value = serde_json::from_str(&text).unwrap();
                received.lock().unwrap().push(request.clone());
                if (hold_release && request["params"]["type"] == "mouseReleased")
                    || (!hold_release && request["method"] == "Runtime.evaluate")
                {
                    assert!(held.replace(request).is_none());
                    if hold_release {
                        cancel.send_replace(CancelSignal::Requested);
                    }
                    continue;
                }
                if request["method"] == "Browser.getVersion" {
                    if let Some(late) = held.take() {
                        socket
                            .send(Message::Text(
                                json!({"id":late["id"],"result":{}}).to_string(),
                            ))
                            .await
                            .unwrap();
                        acknowledged.lock().unwrap().push(late);
                    }
                }
                socket
                    .send(Message::Text(
                        json!({"id":request["id"],"result":{}}).to_string(),
                    ))
                    .await
                    .unwrap();
                acknowledged.lock().unwrap().push(request);
            }
        });
        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        let gate = Arc::new(ExecutionGate::default());
        let page = BrowserExecutionLease {
            client,
            page_session_id: "page".into(),
            target_id: "target".into(),
            identity_scope: "scope".into(),
            permit: gate.enter(false).unwrap(),
            targets: super::super::client_targets::ClientTargets::new(
                "context".into(),
                "scope".into(),
            ),
        };
        (page, requests, replies, server)
    }

    #[tokio::test]
    async fn accepted_unacked_release_is_not_proved_clean_by_zero_local_buttons() {
        let (op, cancel) = operation();
        let (page, requests, replies, server) = command_debt_peer(cancel, true).await;
        let state = ClientPageState::new("scope".into(), "context".into());
        state
            .pointer_event(&page, &op, "mouseMoved", Some((12., 20.)), None, None, None)
            .await
            .unwrap();
        state
            .pointer_event(
                &page,
                &op,
                "mousePressed",
                None,
                Some("left"),
                Some(1),
                None,
            )
            .await
            .unwrap();
        assert_eq!(state.mouse_state().unwrap().buttons, 1);
        // A compound continuation must not run after the release wait cancels,
        // even if its successful reply arrives later on this same connection.
        let compound = async {
            state
                .pointer_event(
                    &page,
                    &op,
                    "mouseReleased",
                    None,
                    Some("left"),
                    Some(1),
                    None,
                )
                .await?;
            state
                .pointer_event(
                    &page,
                    &op,
                    "mousePressed",
                    None,
                    Some("left"),
                    Some(2),
                    None,
                )
                .await
        }
        .await;
        assert_eq!(compound, Err(ProtocolError::Cancelled));
        assert_eq!(state.mouse_state().unwrap().buttons, 0);
        assert_eq!(requests.lock().unwrap().len(), 3);
        assert_eq!(replies.lock().unwrap().len(), 2);
        assert_eq!(
            requests.lock().unwrap()[2]["params"]["type"],
            "mouseReleased"
        );
        // Current blind spot: no cleanup command is sent, yet this reports OK.
        state.release_input(&page).await.unwrap();
        assert_eq!(requests.lock().unwrap().len(), 3);
        page.client
            .send_command("Browser.getVersion", None, None)
            .await
            .unwrap();
        assert_eq!(requests.lock().unwrap().len(), 4);
        assert_eq!(replies.lock().unwrap().len(), 4);
        assert_eq!(compound, Err(ProtocolError::Cancelled));
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r["params"]["type"] == "mousePressed")
                .count(),
            1
        );
        assert_eq!(
            state
                .pointer_event(
                    &page,
                    &op,
                    "mousePressed",
                    None,
                    Some("left"),
                    Some(2),
                    None
                )
                .await,
            Err(ProtocolError::Cancelled)
        );
        assert_eq!(requests.lock().unwrap().len(), 4);
        server.abort();
    }

    #[tokio::test]
    async fn all_input_acked_then_read_timeout_is_a_different_transport_fact() {
        let (mut op, cancel) = operation();
        let (page, requests, replies, server) = command_debt_peer(cancel, false).await;
        let state = ClientPageState::new("scope".into(), "context".into());
        for (kind, button) in [
            ("mouseMoved", None),
            ("mousePressed", Some("left")),
            ("mouseReleased", Some("left")),
        ] {
            state
                .pointer_event(
                    &page,
                    &op,
                    kind,
                    Some((12., 20.)),
                    button,
                    button.map(|_| 1),
                    None,
                )
                .await
                .unwrap();
        }
        op.deadline = Instant::now() + Duration::from_millis(50);
        let postcondition = command(
            &page,
            &op,
            Some("page"),
            "Runtime.evaluate",
            json!({"expression":"document.readyState","returnByValue":true}),
        )
        .await;
        assert_eq!(postcondition, Err(ProtocolError::DeadlineExceeded));
        assert_eq!(state.mouse_state().unwrap().buttons, 0);
        assert_eq!(requests.lock().unwrap().len(), 4);
        assert_eq!(replies.lock().unwrap().len(), 3);
        assert!(replies
            .lock()
            .unwrap()
            .iter()
            .all(|r| r["method"] == "Input.dispatchMouseEvent"));
        state.release_input(&page).await.unwrap();
        assert_eq!(requests.lock().unwrap().len(), 4);
        page.client
            .send_command("Browser.getVersion", None, None)
            .await
            .unwrap();
        assert_eq!(requests.lock().unwrap().len(), 5);
        assert_eq!(postcondition, Err(ProtocolError::DeadlineExceeded));
        server.abort();
    }

    #[tokio::test]
    async fn shared_pointer_secondary_double_click_and_cleanup_preserve_state() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        state
            .pointer_event(
                &page,
                &op,
                "mouseMoved",
                Some((12.5, 20.0)),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        state
            .pointer_event(
                &page,
                &op,
                "mousePressed",
                None,
                Some("right"),
                Some(2),
                None,
            )
            .await
            .unwrap();
        state
            .pointer_event(
                &page,
                &op,
                "mousePressed",
                None,
                Some("left"),
                Some(1),
                None,
            )
            .await
            .unwrap();
        assert_eq!(state.mouse_state().unwrap().buttons, 3);
        state.release_input(&page).await.unwrap();
        assert_eq!(state.mouse_state().unwrap().buttons, 0);
        let requests = log.lock().unwrap();
        let events = requests
            .iter()
            .filter(|r| r["method"] == "Input.dispatchMouseEvent")
            .map(|r| &r["params"])
            .collect::<Vec<_>>();
        assert_eq!(events[1]["button"], "right");
        assert_eq!(events[1]["clickCount"], 2);
        assert_eq!(events[1]["x"], 12.5);
        assert_eq!(events[3]["button"], "left");
        assert_eq!(events[3]["buttons"], 2);
        assert_eq!(events[4]["button"], "right");
        assert_eq!(events[4]["buttons"], 0);
        task.abort();
    }
    #[tokio::test]
    async fn shared_pointer_invalid_and_cancelled_commands_have_no_effects() {
        let (page, log, task) = mock("normal").await;
        let (op, sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        for (kind, point, button, count, delta) in [
            ("bogus", None, None, None, None),
            ("mousePressed", None, Some("bogus"), Some(1), None),
            ("mousePressed", None, Some("left"), Some(0), None),
            ("mouseMoved", Some((f64::NAN, 0.0)), None, None, None),
            ("mouseWheel", None, None, None, Some((f64::INFINITY, 0.0))),
            ("mouseMoved", None, Some("left"), None, None),
        ] {
            assert_eq!(
                state
                    .pointer_event(&page, &op, kind, point, button, count, delta)
                    .await,
                Err(ProtocolError::InvalidArguments)
            );
        }
        sender.send(CancelSignal::Requested).unwrap();
        assert!(state
            .pointer_event(
                &page,
                &op,
                "mousePressed",
                None,
                Some("right"),
                Some(2),
                None
            )
            .await
            .is_err());
        assert_eq!(state.mouse_state().unwrap().buttons, 0);
        assert!(log.lock().unwrap().is_empty());
        task.abort();
    }
    #[tokio::test]
    async fn temporary_modifier_exact_set_restores_preheld_right_key() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        state
            .keyboard(
                &page,
                &op,
                &Keyboard {
                    action: "down".into(),
                    value: "ShiftRight".into(),
                },
            )
            .await
            .unwrap();
        let receipt = state
            .acquire_modifiers(&page, &op, &["Control".into()])
            .await
            .unwrap();
        assert_eq!(state.held_modifiers().unwrap(), 2);
        state.restore_modifiers(&page, &op, receipt).await.unwrap();
        assert_eq!(state.held_modifiers().unwrap(), 8);
        assert!(state.state().unwrap().input.keys.contains_key("ShiftRight"));
        let receipt = state.acquire_modifiers(&page, &op, &[]).await.unwrap();
        assert_eq!(state.held_modifiers().unwrap(), 0);
        state.restore_modifiers(&page, &op, receipt).await.unwrap();
        assert_eq!(state.held_modifiers().unwrap(), 8);
        let requests = log.lock().unwrap().clone();
        let events = requests
            .iter()
            .filter(|r| r["method"] == "Input.dispatchKeyEvent")
            .collect::<Vec<_>>();
        assert_eq!(events[1]["params"]["type"], "keyUp");
        assert_eq!(events[1]["params"]["code"], "ShiftRight");
        assert_eq!(events[4]["params"]["code"], "ShiftRight");
        drop(requests);
        state.release_input(&page).await.unwrap();
        task.abort();
    }
    #[tokio::test]
    async fn temporary_modifiers_preserve_preheld_right_keys_and_reject_invalid_sets() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        state
            .keyboard(
                &page,
                &op,
                &Keyboard {
                    action: "down".into(),
                    value: "ShiftRight".into(),
                },
            )
            .await
            .unwrap();
        let count = log.lock().unwrap().len();
        assert!(state
            .acquire_modifiers(&page, &op, &["Control".into(), "a".into()])
            .await
            .is_err());
        assert_eq!(log.lock().unwrap().len(), count);
        let receipt = state
            .acquire_modifiers(
                &page,
                &op,
                &["Shift".into(), "Control".into(), "Control".into()],
            )
            .await
            .unwrap();
        assert_eq!(state.held_modifiers().unwrap(), 10);
        state.restore_modifiers(&page, &op, receipt).await.unwrap();
        assert_eq!(state.held_modifiers().unwrap(), 8);
        assert!(state.state().unwrap().input.keys.contains_key("ShiftRight"));
        let requests = log.lock().unwrap().clone();
        let events = requests
            .iter()
            .filter(|r| r["method"] == "Input.dispatchKeyEvent")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 3);
        assert_eq!(events[1]["params"]["code"], "ControlLeft");
        assert_eq!(events[2]["params"]["type"], "keyUp");
        drop(requests);
        state.release_input(&page).await.unwrap();
        task.abort();
    }
    #[test]
    fn pure_keyboard_preflight_reuses_full_key_grammar_without_effects() {
        for (action, value) in [
            ("press", "Control++"),
            ("press", "Shift+ArrowLeft"),
            ("down", "ShiftRight"),
            ("up", "ControlOrMeta"),
            ("type", "中+literal"),
        ] {
            ClientPageState::validate_keyboard_command(action, value).unwrap();
        }
        for (action, value) in [
            ("unknown", "a"),
            ("press", "Shift+NotAKey"),
            ("down", "Control+a"),
            ("press", ""),
        ] {
            assert_eq!(
                ClientPageState::validate_keyboard_command(action, value),
                Err(ProtocolError::InvalidArguments)
            );
        }
    }
    #[test]
    fn pure_chord_literal_plus_and_modifier_aliases() {
        assert_eq!(split_chord("Control++").unwrap(), vec!["Control", "+"]);
        assert_eq!(split_chord("+").unwrap(), vec!["+"]);
        assert_eq!(key_descriptor("Shift").unwrap().code, "ShiftLeft");
        assert_eq!(key_descriptor("ShiftRight").unwrap().location, 2);
        assert_eq!(
            key_descriptor("ControlOrMeta").unwrap().modifier,
            if cfg!(target_os = "macos") { 4 } else { 2 }
        );
        assert_eq!(key_descriptor("\n").unwrap().code, "Enter");
        assert!(key_descriptor("NotAKey").is_err());
    }
    #[test]
    fn pure_printable_keyboard_events_use_official_us_key_mapping() {
        for (key, code, vk) in [
            ("a", "KeyA", 65),
            ("A", "KeyA", 65),
            ("!", "Digit1", 49),
            ("+", "Equal", 187),
            (".", "Period", 190),
            ("KeyA", "KeyA", 65),
            ("Slash", "Slash", 191),
        ] {
            let key = key_descriptor(key).unwrap();
            assert_eq!(key.code, code);
            assert_eq!(key.vk, vk);
            let params = key_params(&key, true, false, 0, false);
            assert_eq!(params["type"], "keyDown");
            assert!(params.get("text").is_some());
            assert_eq!(key_params(&key, false, false, 0, false)["type"], "keyUp");
        }
        let a = key_descriptor("a").unwrap();
        assert_eq!(key_params(&a, true, true, 8, false)["text"], "A");
        assert_eq!(key_params(&a, true, true, 8, false)["autoRepeat"], true);
        assert!(key_params(&a, true, false, 2, false).get("text").is_none());
        assert_eq!(
            key_params(&key_descriptor("Numpad1").unwrap(), true, false, 8, false)["text"],
            "1"
        );
    }
    #[test]
    fn pure_mac_editing_commands_preserve_chromium_shortcuts_without_js_input() {
        assert_eq!(mac_editing_commands("KeyA", 4), &["selectAll"]);
        assert_eq!(
            mac_editing_commands("ArrowLeft", 12),
            &["moveToLeftEndOfLineAndModifySelection"]
        );
        assert_eq!(mac_editing_commands("KeyO", 2), &["moveBackward"]);
        assert!(mac_editing_commands("Enter", 0).is_empty());
    }
    #[test]
    fn pure_replacement_page_never_inherits_pointer_or_held_modifiers() {
        let mut input = InputState {
            session: Some("old".into()),
            mouse: MouseState {
                x: 20.0,
                y: 30.0,
                buttons: 0,
            },
            pointer_known: true,
            ..Default::default()
        };
        input
            .keys
            .insert("ShiftLeft".into(), key_descriptor("Shift").unwrap());
        assert!(bind_input_session(&mut input, "new").is_err());
        input.keys.clear();
        bind_input_session(&mut input, "new").unwrap();
        assert_eq!(input.mouse.x, 0.0);
        assert_eq!(input.mouse.y, 0.0);
        assert!(!input.pointer_known);
        assert_eq!(modifiers(&input), 0);
    }

    #[tokio::test]
    async fn known_pointer_requires_an_ack_on_the_current_session() {
        let (op, cancel) = operation();
        let (mut page, _requests, _replies, server) = command_debt_peer(cancel, false).await;
        let state = ClientPageState::new("scope".into(), "context".into());
        assert_eq!(state.known_pointer_position(&page, &op).unwrap(), None);
        state
            .pointer_event(&page, &op, "mouseMoved", Some((0., 0.)), None, None, None)
            .await
            .unwrap();
        assert_eq!(
            state.known_pointer_position(&page, &op).unwrap(),
            Some((0., 0.))
        );
        page.page_session_id = "replacement".into();
        assert_eq!(state.known_pointer_position(&page, &op).unwrap(), None);
        state
            .pointer_event(&page, &op, "mouseMoved", Some((80., 70.)), None, None, None)
            .await
            .unwrap();
        assert_eq!(
            state.known_pointer_position(&page, &op).unwrap(),
            Some((80., 70.))
        );
        server.abort();
    }

    #[tokio::test]
    async fn failed_move_never_publishes_a_known_pointer() {
        let (op, cancel) = operation();
        let (page, _requests, _replies, server) = command_debt_peer(cancel, false).await;
        let state = ClientPageState::new("scope".into(), "context".into());
        state
            .pointer_event(&page, &op, "mouseMoved", Some((80., 70.)), None, None, None)
            .await
            .unwrap();
        assert_eq!(
            state.known_pointer_position(&page, &op).unwrap(),
            Some((80., 70.))
        );
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        assert!(state
            .pointer_event(
                &page,
                &op,
                "mouseMoved",
                Some((120., 90.)),
                None,
                None,
                None
            )
            .await
            .is_err());
        assert_eq!(state.known_pointer_position(&page, &op).unwrap(), None);
    }
    #[test]
    fn pure_cookie_validation_never_converts_invalid_data_to_empty_success() {
        assert!(project_cookies(&json!({})).is_err());
        assert!(project_cookies(&json!({"cookies":[{}]})).is_err());
        assert!(validate_cookie(&json!({"name":"x","value":"v","url":"https://fixture.invalid","domain":"fixture.invalid"})).is_err());
        assert!(validate_cookie(
            &json!({"name":"x","value":"v","domain":"fixture.invalid","partitionKey":"other"})
        )
        .is_err());
        let cookie = validate_cookie(
            &json!({"name":"x","value":"v","domain":"fixture.invalid","expires":-1}),
        )
        .unwrap();
        assert_eq!(cookie["path"], "/");
        assert!(cookie.get("expires").is_none());
    }
    #[tokio::test]
    async fn keyboard_type_held_shift_repeat_and_unicode_use_native_dispatch() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        for (action, value) in [
            ("type", "ab!中"),
            ("down", "Shift"),
            ("down", "Shift"),
            ("press", "ArrowLeft"),
            ("up", "Shift"),
        ] {
            state
                .execute(
                    &page,
                    &[],
                    &op,
                    "input.keyboard",
                    &json!({"action":action,"value":value}),
                )
                .await
                .unwrap();
        }
        let requests = log.lock().unwrap();
        let events: Vec<_> = requests
            .iter()
            .filter(|v| v["method"] == "Input.dispatchKeyEvent")
            .map(|v| &v["params"])
            .collect();
        assert_eq!(events[0]["key"], "a");
        assert_eq!(events[1]["type"], "keyUp");
        assert_eq!(events[4]["key"], "!");
        assert_eq!(events[4]["code"], "Digit1");
        assert_eq!(events[7]["autoRepeat"], true);
        assert_eq!(events[8]["key"], "ArrowLeft");
        assert_eq!(events[8]["modifiers"], 8);
        assert_eq!(events.last().unwrap()["modifiers"], 0);
        assert_eq!(
            requests
                .iter()
                .filter(|v| v["method"] == "Input.insertText")
                .count(),
            1
        );
        assert!(state.state().unwrap().input.keys.is_empty());
        task.abort();
    }
    #[tokio::test]
    async fn cancellation_drains_held_key_without_using_cancelled_budget() {
        let (page, log, task) = mock("cancel-down").await;
        let (mut op, _sender) = operation();
        op.deadline = Instant::now() + Duration::from_millis(30);
        let state = ClientPageState::new("scope".into(), "context".into());
        let error = state
            .execute(
                &page,
                &[],
                &op,
                "input.keyboard",
                &json!({"action":"down","value":"Shift"}),
            )
            .await
            .unwrap_err();
        assert_eq!(error, ProtocolError::DeadlineExceeded);
        let requests = log.lock().unwrap();
        assert_eq!(requests.last().unwrap()["params"]["type"], "keyUp");
        assert_eq!(requests.last().unwrap()["params"]["modifiers"], 0);
        assert!(state.state().unwrap().input.keys.is_empty());
        task.abort();
    }
    #[tokio::test]
    async fn pointer_state_survives_move_down_drag_wheel_up() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        for args in [
            json!({"action":"move","x":12,"y":34}),
            json!({"action":"down"}),
            json!({"action":"move","x":20,"y":40}),
            json!({"action":"wheel","deltaX":3,"deltaY":9}),
            json!({"action":"up"}),
        ] {
            state
                .execute(&page, &[], &op, "input.mouse", &args)
                .await
                .unwrap();
        }
        let requests = log.lock().unwrap();
        assert_eq!(requests[1]["params"]["x"], 12.0);
        assert_eq!(requests[1]["params"]["buttons"], 1);
        assert_eq!(requests[2]["params"]["button"], "left");
        assert_eq!(requests[3]["params"]["deltaY"], 9.0);
        assert_eq!(requests[4]["params"]["buttons"], 0);
        assert_eq!(requests[4]["params"]["y"], 40.0);
        task.abort();
    }
    #[tokio::test]
    async fn context_configuration_without_media_never_emulates_initial_or_child_sessions() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        for session in ["page", "popup"] {
            assert_eq!(
                state
                    .apply_to_new_session(&page, session, &op)
                    .await
                    .unwrap(),
                0
            );
        }
        // This is an absence assertion on the production CDP client, not a
        // renderer-default assertion that could hide an empty-features reset.
        assert!(log.lock().unwrap().is_empty());
        state
            .execute(
                &page,
                &["page".into(), "popup".into()],
                &op,
                "context.init-script",
                &json!({"source":"globalThis.syntheticInit=1"}),
            )
            .await
            .unwrap();
        assert_eq!(state.config_revision().unwrap(), 1);
        state
            .execute(
                &page,
                &["page".into(), "popup".into()],
                &op,
                "context.media",
                &json!({}),
            )
            .await
            .unwrap();
        assert_eq!(state.config_revision().unwrap(), 2);
        for _ in 0..2 {
            assert_eq!(
                state
                    .apply_to_new_session(&page, "child", &op)
                    .await
                    .unwrap(),
                2
            );
        }
        let fresh = ClientPageState::from_config_snapshot(
            "scope".into(),
            "replacement-context".into(),
            state.snapshot_config("scope").unwrap(),
        )
        .unwrap();
        assert_eq!(
            fresh
                .apply_to_new_session(&page, "replacement-child", &op)
                .await
                .unwrap(),
            0
        );
        let requests = log.lock().unwrap();
        assert_eq!(requests.len(), 4);
        assert!(requests.iter().all(|request| {
            request["method"] == "Page.addScriptToEvaluateOnNewDocument"
                && request["params"]["source"] == "globalThis.syntheticInit=1"
        }));
        assert_eq!(
            requests
                .iter()
                .map(|request| request["sessionId"].clone())
                .collect::<Vec<_>>(),
            vec![
                json!("page"),
                json!("popup"),
                json!("child"),
                json!("replacement-child")
            ]
        );
        task.abort();
    }
    #[tokio::test]
    async fn context_media_explicit_values_survive_empty_updates_and_snapshot_child_enrollment() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        for (index, (update, color_scheme, reduced_motion)) in [
            (
                json!({"colorScheme":"dark","reducedMotion":"reduce"}),
                "dark",
                "reduce",
            ),
            (
                json!({"colorScheme":"no-preference"}),
                "no-preference",
                "reduce",
            ),
            (
                json!({"reducedMotion":"no-preference"}),
                "no-preference",
                "no-preference",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            log.lock().unwrap().clear();
            state
                .execute(
                    &page,
                    &["page".into(), "popup".into()],
                    &op,
                    "context.media",
                    &update,
                )
                .await
                .unwrap();
            state
                .execute(
                    &page,
                    &["page".into(), "popup".into()],
                    &op,
                    "context.media",
                    &json!({}),
                )
                .await
                .unwrap();
            assert_eq!(state.config_revision().unwrap(), 2 * (index as u64 + 1));
            let fresh = ClientPageState::from_config_snapshot(
                "scope".into(),
                "replacement-context".into(),
                state.snapshot_config("scope").unwrap(),
            )
            .unwrap();
            assert_eq!(
                fresh
                    .apply_to_new_session(&page, "child", &op)
                    .await
                    .unwrap(),
                0
            );
            let requests = log.lock().unwrap();
            assert_eq!(requests.len(), 5);
            assert!(requests.iter().all(|request| {
                request["method"] == "Emulation.setEmulatedMedia"
                    && request["params"]["features"]
                        == json!([
                            {"name":"prefers-color-scheme","value":color_scheme},
                            {"name":"prefers-reduced-motion","value":reduced_motion},
                        ])
            }));
            assert_eq!(
                requests
                    .iter()
                    .map(|request| request["sessionId"].clone())
                    .collect::<Vec<_>>(),
                vec![
                    json!("page"),
                    json!("popup"),
                    json!("page"),
                    json!("popup"),
                    json!("child")
                ]
            );
        }
        task.abort();
    }
    #[tokio::test]
    async fn context_media_updates_active_page_before_popup_with_reversed_inventory() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        state
            .execute(
                &page,
                &[],
                &op,
                "context.media",
                &json!({"colorScheme":"dark"}),
            )
            .await
            .unwrap();
        assert_eq!(
            state
                .apply_to_new_session(&page, "popup", &op)
                .await
                .unwrap(),
            1
        );
        // The native dispatcher forwards HashMap-backed target inventory.
        // Its arbitrary order must not reverse the original active-then-popup
        // media update contract. No order is required between sibling popups.
        state
            .execute(
                &page,
                &["popup".into(), "page".into()],
                &op,
                "context.media",
                &json!({"reducedMotion":"reduce"}),
            )
            .await
            .unwrap();
        assert_eq!(state.config_revision().unwrap(), 2);
        let requests = log.lock().unwrap();
        assert_eq!(requests.len(), 4);
        for (request, session) in requests.iter().zip(["page", "popup", "page", "popup"]) {
            assert_eq!(request["method"], "Emulation.setEmulatedMedia");
            assert_eq!(request["sessionId"], session);
        }
        let initial = json!([{"name":"prefers-color-scheme","value":"dark"}]);
        let merged = json!([
            {"name":"prefers-color-scheme","value":"dark"},
            {"name":"prefers-reduced-motion","value":"reduce"},
        ]);
        assert_eq!(requests[0]["params"]["features"], initial);
        assert_eq!(requests[1]["params"]["features"], initial);
        assert_eq!(requests[2]["params"]["features"], merged);
        assert_eq!(requests[3]["params"]["features"], merged);
        task.abort();
    }
    #[tokio::test]
    async fn context_media_updates_duplicate_active_session_only_once() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        state
            .execute(
                &page,
                &["page".into(), "popup".into(), "page".into()],
                &op,
                "context.media",
                &json!({"colorScheme":"dark"}),
            )
            .await
            .unwrap();
        let requests = log.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for (request, session) in requests.iter().zip(["page", "popup"]) {
            assert_eq!(request["method"], "Emulation.setEmulatedMedia");
            assert_eq!(request["sessionId"], session);
            assert_eq!(
                request["params"]["features"],
                json!([{"name":"prefers-color-scheme","value":"dark"}])
            );
        }
        task.abort();
    }
    #[tokio::test]
    async fn context_configuration_merges_and_enrolls_without_reinstalling_scripts() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        state
            .execute(
                &page,
                &["page".into()],
                &op,
                "context.init-script",
                &json!({"source":"globalThis.syntheticInit=1"}),
            )
            .await
            .unwrap();
        state
            .execute(
                &page,
                &[],
                &op,
                "context.media",
                &json!({"colorScheme":"dark","reducedMotion":"reduce"}),
            )
            .await
            .unwrap();
        state
            .execute(
                &page,
                &[],
                &op,
                "context.media",
                &json!({"colorScheme":"light"}),
            )
            .await
            .unwrap();
        assert_eq!(
            state
                .apply_to_new_session(&page, "popup", &op)
                .await
                .unwrap(),
            state.config_revision().unwrap()
        );
        state
            .apply_to_new_session(&page, "popup", &op)
            .await
            .unwrap();
        let requests = log.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|v| v["method"] == "Page.addScriptToEvaluateOnNewDocument")
                .count(),
            2
        );
        let features = &requests.last().unwrap()["params"]["features"];
        assert_eq!(features[0]["value"], "light");
        assert_eq!(features[1]["value"], "reduce");
        task.abort();
    }
    #[tokio::test]
    async fn evaluate_preserves_whole_checked_envelope_and_encodes_argument_once() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        let argument = json!([null,"世界\"\n",{"nested":true}]);
        let result = state
            .execute(
                &page,
                &[],
                &op,
                "page.evaluate",
                &json!({"source":"async arg=>({ok:true,value:arg})","argument":argument}),
            )
            .await
            .unwrap();
        assert_eq!(result, json!({"value":{"ok":true,"value":null}}));
        {
            let requests = log.lock().unwrap();
            let expression = requests[0]["params"]["expression"].as_str().unwrap();
            assert!(expression.contains(&serde_json::to_string(&argument).unwrap()));
            assert_eq!(requests[0]["params"]["awaitPromise"], true);
            assert_eq!(requests[0]["params"]["returnByValue"], true);
            assert_eq!(requests[0]["params"]["userGesture"], true);
            assert_eq!(requests[0]["sessionId"], "page");
            assert_eq!(requests.len(), 1);
        }
        // Public gesture authority never leaks into fixed title/url probes or
        // the generic primitive, even on the same already-used connection.
        state
            .execute(
                &page,
                &["other-owned-session".into()],
                &op,
                "page.title",
                &json!({}),
            )
            .await
            .unwrap();
        state
            .execute(&page, &[], &op, "page.url", &json!({}))
            .await
            .unwrap();
        evaluate_on(&page.client, &page.page_session_id, "location.href")
            .await
            .unwrap();
        let requests = log.lock().unwrap();
        assert_eq!(requests.len(), 4);
        for request in requests.iter().skip(1) {
            assert!(request["params"].get("userGesture").is_none());
            assert_eq!(request["sessionId"], "page");
        }
        task.abort();
    }
    #[tokio::test]
    async fn public_evaluate_invalid_cancelled_expired_or_stale_never_dispatches() {
        let (page, log, task) = mock("normal").await;
        let state = ClientPageState::new("scope".into(), "context".into());
        let args = json!({"source":"value=>value","argument":null});
        let (op, _sender) = operation();
        assert_eq!(
            state
                .execute(
                    &page,
                    &[],
                    &op,
                    "page.evaluate",
                    &json!({"source":"()=>1","argument":null,"extra":true})
                )
                .await,
            Err(ProtocolError::InvalidArguments)
        );
        let (cancelled, sender) = operation();
        sender.send_replace(CancelSignal::Requested);
        assert_eq!(
            state
                .execute(&page, &[], &cancelled, "page.evaluate", &args)
                .await,
            Err(ProtocolError::Cancelled)
        );
        let (mut expired, _sender) = operation();
        expired.deadline = Instant::now() - Duration::from_millis(1);
        assert_eq!(
            state
                .execute(&page, &[], &expired, "page.evaluate", &args)
                .await,
            Err(ProtocolError::DeadlineExceeded)
        );
        let foreign = ClientPageState::new("foreign".into(), "context".into());
        assert_eq!(
            foreign
                .execute(&page, &[], &op, "page.evaluate", &args)
                .await,
            Err(ProtocolError::StaleScope)
        );
        assert!(log.lock().unwrap().is_empty());
        task.abort();
    }
    #[tokio::test]
    async fn public_evaluate_held_reply_cancel_and_deadline_do_not_replay() {
        for cancel in [false, true] {
            let (page, log, server) = mock("hold-evaluate").await;
            let state = ClientPageState::new("scope".into(), "context".into());
            let (mut op, sender) = operation();
            op.deadline = Instant::now() + Duration::from_millis(100);
            let seen = log.clone();
            let cancellation = tokio::spawn(async move {
                if cancel {
                    while seen.lock().unwrap().is_empty() {
                        tokio::task::yield_now().await;
                    }
                    sender.send_replace(CancelSignal::Requested);
                } else {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            });
            let result = state
                .execute(
                    &page,
                    &["other".into()],
                    &op,
                    "page.evaluate",
                    &json!({"source":"async()=>1","argument":null}),
                )
                .await;
            assert_eq!(
                result,
                Err(if cancel {
                    ProtocolError::Cancelled
                } else {
                    ProtocolError::DeadlineExceeded
                })
            );
            cancellation.await.unwrap();
            let requests = log.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0]["sessionId"], "page");
            assert_eq!(requests[0]["params"]["userGesture"], true);
            server.abort();
        }
    }
    #[tokio::test]
    async fn public_evaluate_keeps_malformed_and_exception_failures() {
        for mode in ["malformed-evaluate", "exception-evaluate"] {
            let (page, log, server) = mock(mode).await;
            let state = ClientPageState::new("scope".into(), "context".into());
            let (op, _sender) = operation();
            assert_eq!(
                state
                    .execute(
                        &page,
                        &[],
                        &op,
                        "page.evaluate",
                        &json!({"source":"()=>1","argument":null})
                    )
                    .await,
                Err(ProtocolError::BrowserFailure)
            );
            assert_eq!(log.lock().unwrap().len(), 1);
            server.abort();
        }
    }
    #[tokio::test]
    async fn cookies_are_context_scoped_and_session_expiry_is_normalized() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "owned-context".into());
        let result = state
            .execute(&page, &[], &op, "context.cookies.get", &json!({}))
            .await
            .unwrap();
        assert_eq!(result["cookies"][0]["expires"], -1.0);
        state.execute(&page,&[],&op,"context.cookies.set",&json!({"cookies":[{"name":"x","value":"v","domain":"fixture.invalid","expires":-1}]})).await.unwrap();
        let requests = log.lock().unwrap();
        for request in requests.iter() {
            assert_eq!(request["params"]["browserContextId"], "owned-context");
            assert!(request.get("sessionId").is_none());
        }
        task.abort();
    }
    #[tokio::test]
    async fn navigation_correlates_frame_loader_and_records_origin() {
        let (page, _, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        state.register_network_session("page", "page").unwrap();
        for wait in ["load", "domcontentloaded", "networkidle"] {
            state
                .execute(
                    &page,
                    &[],
                    &op,
                    "page.navigate",
                    &json!({"url":"https://fixture.invalid/path","waitUntil":wait}),
                )
                .await
                .unwrap();
        }
        state
            .execute(&page, &[], &op, "page.reload", &json!({}))
            .await
            .unwrap();
        state
            .execute(&page, &[], &op, "page.forward", &json!({}))
            .await
            .unwrap();
        assert_eq!(
            state.visited_origins().unwrap(),
            vec!["https://fixture.invalid"]
        );
        task.abort();
    }
    // Pinned Chromium 156.0.8078.47: InspectorPageAgent::
    // DidRestoreFromBackForwardCache emits frameNavigated, while
    // setLifecycleEventsEnabled replays stored milestones for the live loader.
    // https://raw.githubusercontent.com/chromium/chromium/1d17a2e2ee147bb7d6ae2ab6abdb3a2510c17775/third_party/blink/renderer/core/inspector/inspector_page_agent.cc
    #[tokio::test]
    async fn history_restore_uses_current_native_lifecycle_milestones() {
        for (mode, name) in [
            ("restore-back", "page.back"),
            ("restore-forward", "page.forward"),
        ] {
            let (page, log, task) = mock(mode).await;
            let (mut op, _sender) = operation();
            op.deadline = Instant::now() + Duration::from_millis(250);
            let state = ClientPageState::new("scope".into(), "context".into());
            let result = state.execute(&page, &[], &op, name, &json!({})).await;
            task.abort();
            assert_eq!(
                result,
                Ok(Value::Null),
                "{mode}: restore must prove its recorded load"
            );
            let requests = log.lock().unwrap();
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| request["method"] == "Page.setLifecycleEventsEnabled")
                    .count(),
                2
            );
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| request["method"] == "Page.navigateToHistoryEntry")
                    .count(),
                1
            );
        }
    }

    #[tokio::test]
    async fn history_restore_does_not_invent_or_borrow_completion() {
        for (mode, replays) in [
            ("restore-wrong-session", 0),
            ("restore-wrong-frame", 0),
            ("restore-old-loader", 0),
            ("restore-empty-loader", 0),
            ("restore-normal-navigation", 0),
            ("restore-missing-milestone", 1),
            ("restore-milestone-wrong-session", 1),
            ("restore-milestone-wrong-frame", 1),
            ("restore-milestone-wrong-loader", 1),
        ] {
            let (page, log, task) = mock(mode).await;
            let (mut op, _sender) = operation();
            op.deadline = Instant::now() + Duration::from_millis(100);
            let state = ClientPageState::new("scope".into(), "context".into());
            let result = state
                .execute(&page, &[], &op, "page.forward", &json!({}))
                .await;
            task.abort();
            assert_eq!(result, Err(ProtocolError::DeadlineExceeded), "{mode}");
            assert_eq!(
                log.lock()
                    .unwrap()
                    .iter()
                    .filter(|request| request["method"] == "Page.setLifecycleEventsEnabled")
                    .count(),
                1 + replays,
                "{mode}"
            );
        }
    }

    #[tokio::test]
    async fn history_restore_replay_is_not_a_navigation_or_same_document_fallback() {
        for (mode, name, args, success) in [
            (
                "restore-forward",
                "page.navigate",
                json!({"url":"https://fixture.invalid/", "waitUntil":"load"}),
                false,
            ),
            ("restore-forward", "page.reload", json!({}), false),
            ("restore-same-document", "page.forward", json!({}), true),
        ] {
            let (page, log, task) = mock(mode).await;
            let (mut op, _sender) = operation();
            op.deadline = Instant::now() + Duration::from_millis(100);
            let state = ClientPageState::new("scope".into(), "context".into());
            let result = state.execute(&page, &[], &op, name, &args).await;
            task.abort();
            if success {
                assert_eq!(result, Ok(Value::Null));
            } else {
                assert_eq!(result, Err(ProtocolError::DeadlineExceeded));
            }
            assert_eq!(
                log.lock()
                    .unwrap()
                    .iter()
                    .filter(|request| request["method"] == "Page.setLifecycleEventsEnabled")
                    .count(),
                1
            );
        }
    }

    #[tokio::test]
    async fn history_restore_replay_preserves_the_original_cancellation_budget() {
        let (page, log, task) = mock("restore-held-replay").await;
        let (op, sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        let cancel = async {
            tokio::time::timeout(Duration::from_secs(1), async {
                while log
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|request| request["method"] == "Page.setLifecycleEventsEnabled")
                    .count()
                    < 2
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("history restore should request recorded milestones");
            sender.send_replace(CancelSignal::Requested);
        };
        let args = json!({});
        let navigation = state.execute(&page, &[], &op, "page.forward", &args);
        let (result, ()) = tokio::join!(navigation, cancel);
        task.abort();
        assert_eq!(result, Err(ProtocolError::Cancelled));
    }

    #[tokio::test]
    async fn same_document_and_history_boundary_do_not_wait_for_nonexistent_load() {
        let (page, log, task) = mock("same-document").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        state
            .execute(
                &page,
                &[],
                &op,
                "page.navigate",
                &json!({"url":"https://fixture.invalid/#two","waitUntil":"load"}),
            )
            .await
            .unwrap();
        state
            .execute(&page, &[], &op, "page.back", &json!({}))
            .await
            .unwrap();
        state
            .execute(&page, &[], &op, "page.forward", &json!({}))
            .await
            .unwrap();
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|v| v["method"] == "Page.navigateToHistoryEntry")
                .count(),
            1
        );
        task.abort();
    }
    #[tokio::test]
    async fn stale_scope_is_rejected_before_any_browser_effect() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("different".into(), "context".into());
        assert_eq!(
            state
                .execute(&page, &[], &op, "page.title", &json!({}))
                .await
                .unwrap_err(),
            ProtocolError::StaleScope
        );
        assert!(log.lock().unwrap().is_empty());
        task.abort();
    }
    #[tokio::test]
    async fn callback_read_is_not_blocked_by_parent_navigation() {
        let (page, log, server) = mock("hold-navigation").await;
        let page = Arc::new(page);
        let state = Arc::new(ClientPageState::new("scope".into(), "context".into()));
        let (op, cancel) = operation();
        let task_state = state.clone();
        let task_page = page.clone();
        let navigation = tokio::spawn(async move {
            task_state
                .execute(
                    &task_page,
                    &[],
                    &op,
                    "page.navigate",
                    &json!({"url":"https://fixture.invalid","waitUntil":"load"}),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if log
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|v| v["method"] == "Page.navigate")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let (mut child, _sender) = operation();
        child.is_callback = true;
        let title = tokio::time::timeout(
            Duration::from_secs(1),
            state.execute(&page, &[], &child, "page.title", &json!({})),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(title["title"].is_string());
        cancel.send(CancelSignal::Requested).unwrap();
        assert_eq!(
            navigation.await.unwrap().unwrap_err(),
            ProtocolError::Cancelled
        );
        server.abort();
    }
    #[tokio::test]
    async fn concurrent_enrollment_installs_each_script_once_per_session() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        state
            .execute(
                &page,
                &[],
                &op,
                "context.init-script",
                &json!({"source":"globalThis.once=1"}),
            )
            .await
            .unwrap();
        let (a, b) = tokio::join!(
            state.apply_to_new_session(&page, "popup", &op),
            state.apply_to_new_session(&page, "popup", &op)
        );
        a.unwrap();
        b.unwrap();
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|v| v["method"] == "Page.addScriptToEvaluateOnNewDocument"
                    && v["sessionId"] == "popup")
                .count(),
            1
        );
        task.abort();
    }
    #[tokio::test]
    async fn invalid_input_does_not_release_existing_held_modifiers() {
        let (page, log, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        state
            .execute(
                &page,
                &[],
                &op,
                "input.keyboard",
                &json!({"action":"down","value":"Shift"}),
            )
            .await
            .unwrap();
        let before = log.lock().unwrap().len();
        assert_eq!(
            state
                .execute(
                    &page,
                    &[],
                    &op,
                    "input.keyboard",
                    &json!({"action":"press","value":"Control+UnknownKey"})
                )
                .await
                .unwrap_err(),
            ProtocolError::InvalidArguments
        );
        assert_eq!(log.lock().unwrap().len(), before);
        assert_eq!(modifiers(&state.state().unwrap().input), 8);
        state.release_input(&page).await.unwrap();
        task.abort();
    }
    fn network_event(
        session: &str,
        method: &str,
        id: &str,
        resource_type: &str,
        url: &str,
    ) -> CdpEvent {
        CdpEvent {
            session_id: Some(session.into()),
            method: method.into(),
            params: json!({"requestId":id,"type":resource_type,"request":{"url":url}}),
        }
    }
    #[tokio::test]
    async fn same_document_networkidle_waits_existing_frame_request_but_not_popup() {
        let (page, _, task) = mock("same-document").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        state.register_network_session("page", "page").unwrap();
        state.register_network_session("page", "child").unwrap();
        state.register_network_session("popup", "popup").unwrap();
        state
            .network_event(
                "page",
                &network_event(
                    "child",
                    "Network.requestWillBeSent",
                    "fetch",
                    "Fetch",
                    "https://fixture.invalid/pending",
                ),
            )
            .unwrap();
        state
            .network_event(
                "page",
                &network_event(
                    "child",
                    "Network.requestWillBeSent",
                    "fetch",
                    "Fetch",
                    "https://fixture.invalid/redirect",
                ),
            )
            .unwrap();
        state
            .network_event(
                "popup",
                &network_event(
                    "popup",
                    "Network.requestWillBeSent",
                    "background",
                    "Fetch",
                    "https://fixture.invalid/other",
                ),
            )
            .unwrap();
        assert_eq!(state.state().unwrap().network["page"].requests.len(), 1);
        let started = Instant::now();
        let finish = async {
            tokio::time::sleep(Duration::from_millis(75)).await;
            state
                .network_event(
                    "page",
                    &network_event("child", "Network.loadingFinished", "fetch", "Fetch", ""),
                )
                .unwrap();
        };
        let args = json!({"url":"https://fixture.invalid/#hash","waitUntil":"networkidle"});
        let navigate = state.execute(&page, &[], &op, "page.navigate", &args);
        let (result, ()) = tokio::join!(navigate, finish);
        result.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(570));
        task.abort();
    }
    #[tokio::test]
    async fn networkidle_excludes_persistent_streams_and_fails_closed_on_lost_events() {
        let (page, _, task) = mock("normal").await;
        let (op, _sender) = operation();
        let state = ClientPageState::new("scope".into(), "context".into());
        state.register_network_session("page", "page").unwrap();
        for (kind, id, url) in [
            ("WebSocket", "ws", "wss://fixture.invalid/socket"),
            ("EventSource", "sse", "https://fixture.invalid/events"),
            ("Other", "icon", "https://fixture.invalid/favicon.ico"),
        ] {
            state
                .network_event(
                    "page",
                    &network_event("page", "Network.requestWillBeSent", id, kind, url),
                )
                .unwrap();
        }
        assert!(!state.state().unwrap().network["page"]
            .requests
            .values()
            .any(|v| *v));
        state.network_incomplete("page").unwrap();
        assert_eq!(
            state.wait_network_idle(&page, &op).await.unwrap_err(),
            ProtocolError::ScopeUnavailable
        );
        task.abort();
    }
    /// Explicit CI/browser test. Skipping this test is not browser conformance.
    #[tokio::test]
    #[ignore = "requires installed Chromium and local process/socket permissions"]
    async fn e2e_client_page_input_context_and_evaluate() {
        let options = super::super::cdp::chrome::LaunchOptions {
            headless: true,
            ..Default::default()
        };
        let mut browser = OwnedBrowser::launch(options, None)
            .await
            .expect("Chromium must launch");
        let gate = Arc::new(ExecutionGate::default());
        let page = browser.lease(gate.enter(false).unwrap()).unwrap();
        let state = ClientPageState::new(page.identity_scope.clone(), browser.context_id.clone());
        let (mut op, _sender) = operation();
        op.deadline = Instant::now() + Duration::from_secs(30);
        state
            .execute(
                &page,
                &[],
                &op,
                "context.init-script",
                &json!({"source":"window.syntheticInit=42"}),
            )
            .await
            .unwrap();
        state
            .execute(
                &page,
                &[],
                &op,
                "context.media",
                &json!({"colorScheme":"dark","reducedMotion":"reduce"}),
            )
            .await
            .unwrap();
        state
            .execute(
                &page,
                &[],
                &op,
                "context.media",
                &json!({"colorScheme":"light"}),
            )
            .await
            .unwrap();
        state.execute(&page,&[],&op,"page.navigate",&json!({"url":"data:text/html,<input id=i autofocus><script>window.events=[];for(const type of ['keydown','keyup'])document.addEventListener(type,e=>events.push([e.type,e.key,e.shiftKey]));</script>","waitUntil":"load"})).await.unwrap();
        state
            .execute(
                &page,
                &[],
                &op,
                "page.evaluate",
                &json!({"source":"()=>document.querySelector('input').focus()","argument":null}),
            )
            .await
            .unwrap();
        for (action, value) in [
            ("type", "ab"),
            ("down", "Shift"),
            ("press", "ArrowLeft"),
            ("up", "Shift"),
        ] {
            state
                .execute(
                    &page,
                    &[],
                    &op,
                    "input.keyboard",
                    &json!({"action":action,"value":value}),
                )
                .await
                .unwrap();
        }
        let result=state.execute(&page,&[],&op,"page.evaluate",&json!({"source":"()=>({text:i.value,start:i.selectionStart,end:i.selectionEnd,events,init:syntheticInit,dark:matchMedia('(prefers-color-scheme:dark)').matches,reduce:matchMedia('(prefers-reduced-motion:reduce)').matches})","argument":null})).await.unwrap();
        assert_eq!(result["value"]["text"], "ab");
        assert_eq!(result["value"]["start"], 1);
        assert_eq!(result["value"]["end"], 2);
        assert_eq!(result["value"]["events"][0][0], "keydown");
        assert_eq!(result["value"]["events"][1][0], "keyup");
        assert_eq!(result["value"]["init"], 42);
        assert_eq!(result["value"]["dark"], false);
        assert_eq!(result["value"]["reduce"], true);
        state
            .execute(
                &page,
                &[],
                &op,
                "context.viewport",
                &json!({"width":640,"height":480}),
            )
            .await
            .unwrap();
        let viewport = state
            .execute(
                &page,
                &[],
                &op,
                "page.evaluate",
                &json!({"source":"()=>[innerWidth,innerHeight]","argument":null}),
            )
            .await
            .unwrap();
        assert_eq!(viewport["value"], json!([640, 480]));
        let echo=state.execute(&page,&[],&op,"page.evaluate",&json!({"source":"async value=>({ok:true,value})","argument":[null,"synthetic Unicode 世界",{"count":3}]})).await.unwrap();
        assert_eq!(
            echo["value"],
            json!({"ok":true,"value":[null,"synthetic Unicode 世界",{"count":3}]})
        );
        state.execute(&page,&[],&op,"context.cookies.set",&json!({"cookies":[{"name":"owned","value":"synthetic","domain":"fixture.invalid","httpOnly":true,"expires":-1}]})).await.unwrap();
        let other = page
            .client
            .send_command(
                "Target.createBrowserContext",
                Some(json!({"disposeOnDetach":true})),
                None,
            )
            .await
            .unwrap();
        let other_id = other["browserContextId"].as_str().unwrap();
        page.client.send_command("Storage.setCookies",Some(json!({"browserContextId":other_id,"cookies":[{"name":"unrelated","value":"must-not-leak","domain":"fixture.invalid","path":"/"}]})),None).await.unwrap();
        let cookies = state
            .execute(&page, &[], &op, "context.cookies.get", &json!({}))
            .await
            .unwrap();
        assert!(cookies["cookies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "owned" && c["httpOnly"] == true));
        assert!(!cookies["cookies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "unrelated"));
        page.client
            .send_command(
                "Target.disposeBrowserContext",
                Some(json!({"browserContextId":other_id})),
                None,
            )
            .await
            .unwrap();
        state.release_input(&page).await.unwrap();
        drop(page);
        browser.close().await.unwrap();
    }
    #[test]
    fn navigation_preflight_reuses_strict_public_schema_without_browser_effects() {
        for wait in ["load", "domcontentloaded", "networkidle"] {
            assert!(ClientPageState::validate_navigation(
                &json!({"url":"https://synthetic.test/","waitUntil":wait})
            )
            .is_ok());
        }
        for args in [
            json!({"url":"https://synthetic.test/"}),
            json!({"url":false,"waitUntil":"load"}),
            json!({"url":"https://synthetic.test/","waitUntil":"commit"}),
            json!({"url":"https://synthetic.test/","waitUntil":"load","extra":true}),
        ] {
            assert_eq!(
                ClientPageState::validate_navigation(&args),
                Err(ProtocolError::InvalidArguments)
            );
        }
    }
}
