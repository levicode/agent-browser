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
use super::browser::evaluate_on;
use super::cdp::types::CdpEvent;
use super::client_browser::BrowserExecutionLease;
use super::client_protocol::ProtocolError;
use super::client_session::{CancelSignal, OperationLease};
use super::interaction::{char_to_key_info, key_text, named_key_info};

#[derive(Clone, Default)]
struct Config {
    revision: u64,
    scripts: Vec<Arc<str>>,
    color_scheme: Option<String>,
    reduced_motion: Option<String>,
}
#[derive(Clone, Default)]
struct InputState {
    keys: BTreeMap<String, Key>,
    mouse: MouseState,
    session: Option<String>,
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
    configuration_locks: HashMap<String, Arc<tokio::sync::Mutex<()>>>,
    input: InputState,
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

fn invalid<T>() -> Result<T, ProtocolError> {
    Err(ProtocolError::InvalidArguments)
}
fn decode<T: serde::de::DeserializeOwned>(args: &Value) -> Result<T, ProtocolError> {
    serde_json::from_value(args.clone()).map_err(|_| ProtocolError::InvalidArguments)
}
fn check(page: &BrowserExecutionLease, op: &OperationLease) -> Result<(), ProtocolError> {
    page.permit.check()?;
    if *op.cancellation.borrow() != CancelSignal::None {
        return Err(ProtocolError::Cancelled);
    }
    if Instant::now() >= op.deadline {
        return Err(ProtocolError::DeadlineExceeded);
    }
    Ok(())
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
    fn state(&self) -> Result<MutexGuard<'_, State>, ProtocolError> {
        self.state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)
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
        Ok(())
    }
    pub fn requested_viewport(&self) -> Result<Option<(u32, u32)>, ProtocolError> {
        Ok(self.state()?.requested_viewport)
    }
    pub fn mouse_state(&self) -> Result<MouseState, ProtocolError> {
        Ok(self.state()?.input.mouse)
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
        self.validate(page, op)?;
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
            _ = cancel.changed() => return Err(ProtocolError::Cancelled),
            _ = tokio::time::sleep_until(op.deadline.into()) => return Err(ProtocolError::DeadlineExceeded),
        };
        self.validate(page, op)?;
        let (config, installed) = {
            let s = self.state()?;
            (
                s.config.clone(),
                *s.installed_scripts.get(session).unwrap_or(&0),
            )
        };
        for (index, source) in config.scripts.iter().enumerate().skip(installed) {
            let installed_script = command(
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
                return Err(ProtocolError::BrowserFailure);
            }
            self.validate(page, op)?;
            self.state()?
                .installed_scripts
                .insert(session.into(), index + 1);
        }
        let mut features = Vec::new();
        if let Some(value) = &config.color_scheme {
            features.push(json!({"name":"prefers-color-scheme","value":value}));
        }
        if let Some(value) = &config.reduced_motion {
            features.push(json!({"name":"prefers-reduced-motion","value":value}));
        }
        command(
            page,
            op,
            Some(session),
            "Emulation.setEmulatedMedia",
            json!({"features":features}),
        )
        .await?;
        Ok(config.revision)
    }
    pub fn forget_session(&self, session: &str) -> Result<(), ProtocolError> {
        let mut state = self.state()?;
        state.installed_scripts.remove(session);
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
                    evaluate_on(&page.client, &page.page_session_id, expression),
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
                    evaluate_on(&page.client, &page.page_session_id, &expression),
                )
                .await?;
                if !result.is_object() || result.get("value").is_none() {
                    return Err(ProtocolError::BrowserFailure);
                }
                Ok(result)
            }
            "page.navigate" => {
                let a: Navigation = decode(args)?;
                self.navigate(
                    page,
                    op,
                    "Page.navigate",
                    json!({"url":a.url}),
                    &a.wait_until,
                )
                .await?;
                Ok(Value::Null)
            }
            "page.reload" => {
                let _: Empty = decode(args)?;
                self.navigate(page, op, "Page.reload", json!({}), "load")
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
                    if s.config.scripts.len() >= 1024
                        || s.config
                            .scripts
                            .iter()
                            .map(|source| source.len())
                            .sum::<usize>()
                            .saturating_add(a.source.len())
                            > 8 * 1024 * 1024
                    {
                        return Err(ProtocolError::CapacityExceeded);
                    }
                    s.config.revision = s
                        .config
                        .revision
                        .checked_add(1)
                        .ok_or(ProtocolError::IdentifierExhausted)?;
                    s.config.scripts.push(Arc::from(a.source));
                }
                self.apply_existing(page, sessions, op).await?;
                Ok(Value::Null)
            }
            "context.media" => {
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
                    s.config.revision = s
                        .config
                        .revision
                        .checked_add(1)
                        .ok_or(ProtocolError::IdentifierExhausted)?;
                    if a.color_scheme.is_some() {
                        s.config.color_scheme = a.color_scheme;
                    }
                    if a.reduced_motion.is_some() {
                        s.config.reduced_motion = a.reduced_motion;
                    }
                }
                self.apply_existing(page, sessions, op).await?;
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
    ) -> Result<(), ProtocolError> {
        let expected = match wait {
            "load" => "load",
            "domcontentloaded" => "DOMContentLoaded",
            "networkidle" => "DOMContentLoaded",
            _ => return invalid(),
        };
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
        let frame = tree
            .pointer("/frameTree/frame/id")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::BrowserFailure)?
            .to_owned();
        let previous_loader = tree
            .pointer("/frameTree/frame/loaderId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        // Subscribe after setup history but BEFORE the trigger. Overflow is an
        // explicit unknown browser outcome, never a dropped-event success.
        let mut events = page
            .client
            .subscribe_bounded_methods(
                &[
                    "Page.lifecycleEvent",
                    "Page.frameNavigated",
                    "Page.navigatedWithinDocument",
                    "Inspector.detached",
                    "Target.detachedFromTarget",
                ],
                256,
                65_536,
            )
            .map_err(|_| ProtocolError::CapacityExceeded)?;
        if wait == "networkidle" {
            self.state()?
                .network
                .get_mut(&page.page_session_id)
                .ok_or(ProtocolError::ScopeUnavailable)?
                .quiet_since = Instant::now();
        }
        let response = command(page, op, session, method, args).await?;
        if response
            .get("errorText")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
            || response.get("isDownload") == Some(&Value::Bool(true))
        {
            return Err(ProtocolError::BrowserFailure);
        }
        let mut loader = response
            .get("loaderId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if method != "Page.navigate" || loader.is_some() {
            let mut cancel = op.cancellation.clone();
            let mut reached = BTreeSet::new();
            loop {
                check(page, op)?;
                let event = tokio::select! {
                    event=events.recv()=>event.map_err(|_|ProtocolError::BrowserFailure)?,
                    _=cancel.changed()=>return Err(ProtocolError::Cancelled),
                    _=tokio::time::sleep_until(op.deadline.into())=>return Err(ProtocolError::DeadlineExceeded),
                };
                if event.method == "Target.detachedFromTarget"
                    && event.params.get("sessionId").and_then(Value::as_str) == session
                {
                    return Err(ProtocolError::BrowserFailure);
                }
                if event.session_id.as_deref() != session {
                    continue;
                }
                if event.method == "Inspector.detached" {
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
        let value = bounded(
            page,
            op,
            evaluate_on(&page.client, &page.page_session_id, "location.href"),
        )
        .await?;
        if let Some(url) = value.as_str().and_then(|s| url::Url::parse(s).ok()) {
            let origin = url.origin().ascii_serialization();
            if origin != "null" {
                self.state()?.origins.insert(origin);
            }
        }
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
    async fn keyboard(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
        a: &Keyboard,
    ) -> Result<(), ProtocolError> {
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
        let params = {
            let mut s = self.state()?;
            bind_input_session(&mut s.input, &page.page_session_id)?;
            let mods = modifiers(&s.input);
            build_mouse_event_params(
                &mut s.input.mouse,
                kind,
                x,
                y,
                button,
                None,
                button.map(|_| 1),
                dx,
                dy,
                Some(mods),
            )
        };
        let mut params = serde_json::to_value(params).map_err(|_| ProtocolError::BrowserFailure)?;
        // Chromium's public wheel primitive carries deltas and modifiers, not
        // a new button transition. Keep held buttons in native state only.
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
        Ok(())
    }
    /// Cleanup runs outside the cancelled operation budget. Caller must retain
    /// this future until it settles and quarantine this scope on any failure.
    /// Do not call after disposing or replacing the owned context.
    pub async fn release_input(&self, page: &BrowserExecutionLease) -> Result<(), ProtocolError> {
        if page.identity_scope != self.identity_scope {
            return Err(ProtocolError::StaleScope);
        }
        page.permit.check()?;
        let mut input = self.state()?.input.clone();
        let session = input
            .session
            .as_deref()
            .unwrap_or(&page.page_session_id)
            .to_owned();
        let cleanup = async {
            for key in input.keys.clone().into_values() {
                input.keys.remove(&key.code);
                page.client
                    .send_command(
                        "Input.dispatchKeyEvent",
                        Some(key_params(&key, false, false, modifiers(&input), false)),
                        Some(&session),
                    )
                    .await?;
            }
            if input.mouse.buttons != 0 {
                let params = build_mouse_event_params(
                    &mut input.mouse,
                    "mouseReleased",
                    None,
                    None,
                    Some("left"),
                    Some(0),
                    Some(1),
                    None,
                    None,
                    Some(0),
                );
                page.client
                    .send_command(
                        "Input.dispatchMouseEvent",
                        Some(
                            serde_json::to_value(params)
                                .map_err(|_| "cleanup serialization".to_string())?,
                        ),
                        Some(&session),
                    )
                    .await?;
            }
            Ok::<(), String>(())
        };
        tokio::time::timeout(Duration::from_secs(2), cleanup)
            .await
            .map_err(|_| ProtocolError::CleanupFailed)?
            .map_err(|_| ProtocolError::CleanupFailed)?;
        page.permit.check()?;
        self.state()?.input = InputState {
            mouse: input.mouse,
            session: Some(session),
            ..InputState::default()
        };
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
    use super::super::cdp::client::CdpClient;
    use super::super::client_browser::{ExecutionGate, OwnedBrowser};
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use std::sync::Arc;
    use tokio::sync::watch;
    use tokio_tungstenite::tungstenite::Message;

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
                let result = match method {
                    "Browser.getVersion" => json!({"userAgent":"Synthetic Chromium Linux"}),
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"main","loaderId":"old"}}})
                    }
                    "Page.navigate" | "Page.reload" | "Page.navigateToHistoryEntry" => {
                        if mode != "same-document" {
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
                        if method == "Page.navigate" && mode != "same-document" {
                            json!({"frameId":"main","loaderId":"new"})
                        } else {
                            json!({})
                        }
                    }
                    "Page.getNavigationHistory" => {
                        json!({"currentIndex":0,"entries":[{"id":1},{"id":2}]})
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
                        json!({"id":request["id"],"result":result}).to_string(),
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
        assert_eq!(modifiers(&input), 0);
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
        let requests = log.lock().unwrap();
        let expression = requests[0]["params"]["expression"].as_str().unwrap();
        assert!(expression.contains(&serde_json::to_string(&argument).unwrap()));
        assert_eq!(requests[0]["params"]["awaitPromise"], true);
        assert_eq!(requests[0]["params"]["returnByValue"], true);
        task.abort();
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
}
