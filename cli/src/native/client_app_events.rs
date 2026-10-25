//! Projects already-attributed application events onto the public app channels.
//!
//! This module owns neither a CDP subscription nor session/lifecycle authority.
//! The enrollment owner must admit only exact Application sessions, retain its
//! scope permit through publication, and forget retired sessions before reuse.
//! Backend failures are typed errors, never application log messages. Only the
//! selected application text fields below can cross this wire boundary.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use serde_json::{json, Value};

use super::cdp::types::CdpEvent;
use super::client_protocol::ProtocolError;
use super::client_settlement_trace::network_probe::Outcome as ProbeOutcome;

const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_URL_BYTES: usize = 64 * 1024;
const MAX_FRAME_NAME_BYTES: usize = 8 * 1024;
const MAX_REQUESTS: usize = 2048;
const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_NAVIGATIONS: usize = 256;
const MAX_PREVIEW_ITEMS: usize = 1024;
const TRUNCATED: &str = " [truncated]";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppNavigationKind {
    Main,
    Popup,
    PopupNavigation,
    Frame,
}
impl AppNavigationKind {
    fn wire(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Popup => "popup",
            Self::PopupNavigation => "popup-navigation",
            Self::Frame => "frame",
        }
    }
}

/// Enrollment supplies frame attribution, not a guess based on URL or timing.
/// Popup means one confirmed opening, not every navigation of a popup page.
/// PopupNavigation includes later same-document navigation, matching the
/// original frame-navigation signal. Enrollment owns the opening transition;
/// an initial about:blank attachment must not consume its real destination.
#[derive(Clone, Copy)]
pub struct AppNavigationContext<'a> {
    pub kind: AppNavigationKind,
    pub frame_name: Option<&'a str>,
    pub initiated_by_operation: bool,
}

/// This is projection context, not a credential. The caller must prove that
/// this exact session belongs to the current Application tenure before use.
#[derive(Clone, Copy)]
pub struct AppEventContext<'a> {
    pub session_id: &'a str,
    pub navigation: Option<AppNavigationContext<'a>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppLogSource {
    Console,
    Error,
    Network,
}
impl AppLogSource {
    fn wire(self) -> &'static str {
        match self {
            Self::Console => "console",
            Self::Error => "error",
            Self::Network => "network",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppLogLevel {
    Error,
    Warning,
    Info,
}
impl AppLogLevel {
    fn wire(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProjectedAppEvent {
    Log {
        source: AppLogSource,
        level: AppLogLevel,
        text: String,
    },
    Navigation {
        kind: AppNavigationKind,
        url: String,
        frame_name: Option<String>,
        initiated_by_operation: bool,
    },
}
impl ProjectedAppEvent {
    /// Construct only the public allowlisted payload. No remote IDs, raw CDP
    /// values, exception metadata, request headers, or diagnostics are copied.
    pub fn into_wire(self, identity_scope: &str) -> Result<(&'static str, Value), ProtocolError> {
        identifier(identity_scope)?;
        Ok(match self {
            Self::Log {
                source,
                level,
                text,
            } => {
                limited(&text, MAX_TEXT_BYTES)?;
                (
                    "app.log",
                    json!({"identityScope":identity_scope,"source":source.wire(),"level":level.wire(),"text":text}),
                )
            }
            Self::Navigation {
                kind,
                url,
                frame_name,
                initiated_by_operation,
            } => {
                limited(&url, MAX_URL_BYTES)?;
                if let Some(name) = &frame_name {
                    limited(name, MAX_FRAME_NAME_BYTES)?;
                }
                let mut payload = json!({"identityScope":identity_scope,"kind":kind.wire(),"url":url,"initiatedByOperation":initiated_by_operation});
                if let Some(name) = frame_name {
                    payload["frameName"] = Value::String(name);
                }
                ("app.navigation", payload)
            }
        })
    }
}

struct RequestLine {
    method: String,
    url: String,
    response_reported: bool,
}
impl RequestLine {
    fn bytes(&self) -> usize {
        self.method.len() + self.url.len()
    }
}
#[derive(Default)]
struct ProjectionState {
    requests: HashMap<(String, String), RequestLine>,
    request_bytes: usize,
    navigations: HashMap<String, HashSet<u64>>,
    next_navigation: u64,
}

/// One projector per scope. Its bounded state is correlation only; enrollment
/// remains the sole authority for Application/StateBootstrap/foreign sessions.
#[derive(Default)]
pub struct AppEventProjector {
    state: Arc<Mutex<ProjectionState>>,
}

/// Suppresses only explicit engine navigations of this exact session. Retain
/// through command completion and the owner's event-watermark drain. Dropping
/// on success, failure, cancellation, or task abort releases this marker only.
pub struct OwnNavigationGuard {
    state: Weak<Mutex<ProjectionState>>,
    session_id: String,
    token: u64,
}
impl Drop for OwnNavigationGuard {
    fn drop(&mut self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        let Ok(mut state) = state.lock() else { return };
        if let Some(tokens) = state.navigations.get_mut(&self.session_id) {
            tokens.remove(&self.token);
            if tokens.is_empty() {
                state.navigations.remove(&self.session_id);
            }
        }
    }
}
impl AppEventProjector {
    pub fn new() -> Self {
        Self::default()
    }
    fn state(&self) -> Result<MutexGuard<'_, ProjectionState>, ProtocolError> {
        self.state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)
    }
    pub fn begin_navigation(&self, session_id: &str) -> Result<OwnNavigationGuard, ProtocolError> {
        identifier(session_id)?;
        let mut state = self.state()?;
        if state.navigations.values().map(HashSet::len).sum::<usize>() >= MAX_NAVIGATIONS {
            return Err(ProtocolError::CapacityExceeded);
        }
        let token = state
            .next_navigation
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        state.next_navigation = token;
        state
            .navigations
            .entry(session_id.into())
            .or_default()
            .insert(token);
        Ok(OwnNavigationGuard {
            state: Arc::downgrade(&self.state),
            session_id: session_id.into(),
            token,
        })
    }
    /// Forget before retiring a session. An old guard cannot clear a marker
    /// from any later session tenure, even if a backend reuses its identifier.
    pub fn forget_session(&self, session_id: &str) -> Result<(), ProtocolError> {
        let mut state = self.state()?;
        state
            .requests
            .retain(|(session, _), _| session != session_id);
        state.request_bytes = state.requests.values().map(RequestLine::bytes).sum();
        state.navigations.remove(session_id);
        Ok(())
    }
    pub fn clear(&self) -> Result<(), ProtocolError> {
        let mut state = self.state()?;
        state.requests.clear();
        state.request_bytes = 0;
        state.navigations.clear();
        // Do not reuse navigation tokens while an old guard may still exist.
        Ok(())
    }
    /// Synchronous projection on enrollment's existing ordered event pump.
    /// Unsupported methods and mismatched/unscoped sessions produce no event.
    /// The caller checks cancellation/retirement again before sink publication.
    pub fn project(
        &self,
        event: &CdpEvent,
        context: AppEventContext<'_>,
    ) -> Result<Option<ProjectedAppEvent>, ProtocolError> {
        self.project_observed(event, context, &mut ProbeOutcome::Unreached)
    }
    pub(crate) fn project_observed(
        &self,
        event: &CdpEvent,
        context: AppEventContext<'_>,
        outcome: &mut ProbeOutcome,
    ) -> Result<Option<ProjectedAppEvent>, ProtocolError> {
        *outcome = ProbeOutcome::Invalid;
        if event.session_id.as_deref() != Some(context.session_id) {
            *outcome = ProbeOutcome::WrongSession;
            return Ok(None);
        }
        identifier(context.session_id)?;
        match event.method.as_str() {
            "Runtime.consoleAPICalled" => console(&event.params),
            "Runtime.exceptionThrown" => exception(&event.params),
            "Network.requestWillBeSent"
            | "Network.responseReceived"
            | "Network.loadingFailed"
            | "Network.loadingFinished" => self.network(event, context.session_id, outcome),
            "Page.frameNavigated" | "Page.navigatedWithinDocument" => {
                let Some(navigation) = context.navigation else {
                    return Ok(None);
                };
                let frame = if event.method == "Page.frameNavigated" {
                    event
                        .params
                        .get("frame")
                        .ok_or(ProtocolError::InvalidFrame)?
                } else {
                    &event.params
                };
                let url = string(frame, "url")?;
                let url = diagnostic_text(url, MAX_URL_BYTES);
                let frame_name = navigation.frame_name.map(diagnostic_frame_name);
                let marked = navigation.kind == AppNavigationKind::Main
                    && self
                        .state()?
                        .navigations
                        .get(context.session_id)
                        .is_some_and(|tokens| !tokens.is_empty());
                Ok(Some(ProjectedAppEvent::Navigation {
                    kind: navigation.kind,
                    url,
                    frame_name,
                    initiated_by_operation: navigation.kind == AppNavigationKind::Main
                        && (navigation.initiated_by_operation || marked),
                }))
            }
            _ => {
                *outcome = ProbeOutcome::Unsupported;
                Ok(None)
            }
        }
    }
    fn network(
        &self,
        event: &CdpEvent,
        session: &str,
        outcome: &mut ProbeOutcome,
    ) -> Result<Option<ProjectedAppEvent>, ProtocolError> {
        let id = string(&event.params, "requestId")?;
        identifier(id)?;
        let key = (session.to_owned(), id.to_owned());
        let mut state = self.state()?;
        if event.method == "Network.requestWillBeSent" {
            let request = event
                .params
                .get("request")
                .ok_or(ProtocolError::InvalidFrame)?;
            let method = string(request, "method")?;
            let url = string(request, "url")?;
            // Correlation is diagnostic only. Large valid URLs or request
            // volume must not become a browser/network capability restriction.
            let method = diagnostic_text(method, 64);
            let url = diagnostic_text(url, MAX_URL_BYTES);
            if let Some(previous) = state.requests.remove(&key) {
                state.request_bytes -= previous.bytes();
            }
            let bytes = method.len() + url.len();
            while state.requests.len() >= MAX_REQUESTS
                || state.request_bytes.saturating_add(bytes) > MAX_REQUEST_BYTES
            {
                let Some(victim) = state.requests.keys().next().cloned() else {
                    break;
                };
                if let Some(previous) = state.requests.remove(&victim) {
                    state.request_bytes -= previous.bytes();
                }
            }
            state.request_bytes += bytes;
            state.requests.insert(
                key,
                RequestLine {
                    method,
                    url,
                    response_reported: false,
                },
            );
            *outcome = ProbeOutcome::Stored;
            return Ok(None);
        }
        if event.method == "Network.loadingFinished" || event.method == "Network.loadingFailed" {
            let Some(request) = state.requests.remove(&key) else {
                return Ok(None);
            };
            state.request_bytes -= request.bytes();
            if event.method == "Network.loadingFinished" {
                return Ok(None);
            }
            let failure = string(&event.params, "errorText")?;
            if event.params.get("canceled") == Some(&Value::Bool(true))
                || failure == "net::ERR_ABORTED"
                || failure == "NS_BINDING_ABORTED"
                || failure.contains("cancelled")
            {
                return Ok(None);
            }
            let mut text = Text::default();
            text.push(&request.method);
            text.push(" ");
            text.push(&request.url);
            text.push(" ");
            text.push(failure);
            return Ok(Some(log(
                AppLogSource::Network,
                AppLogLevel::Error,
                text.finish(),
            )));
        }
        let Some(request) = state.requests.get_mut(&key) else {
            *outcome = ProbeOutcome::MissingRequest;
            return Ok(None);
        };
        if request.response_reported {
            *outcome = ProbeOutcome::Duplicate;
            return Ok(None);
        }
        let response = event
            .params
            .get("response")
            .ok_or(ProtocolError::InvalidFrame)?;
        let status = response
            .get("status")
            .and_then(Value::as_f64)
            .filter(|n| n.is_finite() && n.fract() == 0.0 && *n >= 0.0 && *n <= 999.0)
            .ok_or(ProtocolError::InvalidFrame)? as u16;
        request.response_reported = true;
        if status < 400
            || (status == 404
                && url::Url::parse(&request.url)
                    .ok()
                    .is_some_and(|url| url.path() == "/favicon.ico"))
        {
            *outcome = ProbeOutcome::Ignored;
            return Ok(None);
        }
        let status_text = string(response, "statusText")?;
        let mut text = Text::default();
        text.push(&request.method);
        text.push(" ");
        text.push(&request.url);
        text.push(" ");
        text.push(&status.to_string());
        if !status_text.is_empty() {
            text.push(" ");
            text.push(status_text);
        }
        *outcome = ProbeOutcome::Projected;
        Ok(Some(log(
            AppLogSource::Network,
            if status >= 500 {
                AppLogLevel::Error
            } else {
                AppLogLevel::Warning
            },
            text.finish(),
        )))
    }
}

fn console(params: &Value) -> Result<Option<ProjectedAppEvent>, ProtocolError> {
    if params.get("executionContextId").and_then(Value::as_u64) == Some(0) {
        return Ok(None);
    }
    let level = match string(params, "type")? {
        "error" | "assert" => AppLogLevel::Error,
        "warning" => AppLogLevel::Warning,
        "log" | "info" => AppLogLevel::Info,
        _ => return Ok(None),
    };
    let args = params
        .get("args")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidFrame)?;
    let mut text = Text::default();
    for (i, arg) in args.iter().take(MAX_PREVIEW_ITEMS).enumerate() {
        if i != 0 {
            text.push(" ");
        }
        remote_preview(arg, &mut text)?;
    }
    if args.len() > MAX_PREVIEW_ITEMS {
        text.push(TRUNCATED);
    }
    if text.value.starts_with("Failed to load resource:") {
        return Ok(None);
    }
    if let Some(frame) = params.pointer("/stackTrace/callFrames/0") {
        let url = string(frame, "url")?;
        if !url.is_empty() {
            let line = frame
                .get("lineNumber")
                .and_then(Value::as_i64)
                .and_then(|line| line.checked_add(1))
                .ok_or(ProtocolError::InvalidFrame)?;
            text.push(" (at ");
            text.push(url);
            text.push(":");
            text.push(&line.to_string());
            text.push(")");
        }
    }
    Ok(Some(log(AppLogSource::Console, level, text.finish())))
}

fn exception(params: &Value) -> Result<Option<ProjectedAppEvent>, ProtocolError> {
    let details = params
        .get("exceptionDetails")
        .ok_or(ProtocolError::InvalidFrame)?;
    let mut message = Text::default();
    if let Some(exception) = details.get("exception") {
        if let Some(description) = exception
            .get("description")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
        {
            message.push(description);
        } else if let Some(value) = exception.get("value") {
            primitive(value, &mut message)?;
        } else {
            message.push("undefined");
        }
    } else {
        message.push(string(details, "text")?);
    }
    let full = message.finish();
    let stack_start = full.find("\n    at");
    let headline = stack_start.map_or(full.as_str(), |position| &full[..position]);
    let (name, error_message) = headline
        .split_once(':')
        .map_or(("", headline), |(name, rest)| {
            (name, rest.strip_prefix(' ').unwrap_or(rest))
        });
    let override_name = details
        .pointer("/exception/preview/properties")
        .and_then(Value::as_array)
        .and_then(|properties| {
            properties
                .iter()
                .take(MAX_PREVIEW_ITEMS)
                .find(|property| property.get("name").and_then(Value::as_str) == Some("name"))
        })
        .map(|property| {
            property
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or("Error")
        });
    let mut text = Text::default();
    text.push(override_name.unwrap_or(name));
    text.push(": ");
    text.push(error_message);
    if let Some(top) = full.lines().find(|line| line.trim().starts_with("at ")) {
        text.push(" ");
        text.push(top.trim());
    } else if details.get("exception").is_none() {
        if let Some(frame) = details.pointer("/stackTrace/callFrames/0") {
            // Match the browser's exception fallback, not a backend failure.
            let function = string(frame, "functionName")?;
            text.push(" at ");
            text.push(if function.is_empty() {
                "<anonymous>"
            } else {
                function
            });
            text.push(" (");
            text.push(string(frame, "url")?);
            text.push(":");
            text.push(
                &frame
                    .get("lineNumber")
                    .and_then(Value::as_i64)
                    .ok_or(ProtocolError::InvalidFrame)?
                    .to_string(),
            );
            text.push(":");
            text.push(
                &frame
                    .get("columnNumber")
                    .and_then(Value::as_i64)
                    .ok_or(ProtocolError::InvalidFrame)?
                    .to_string(),
            );
            text.push(")");
        }
    }
    Ok(Some(log(
        AppLogSource::Error,
        AppLogLevel::Error,
        text.finish(),
    )))
}

fn remote_preview(remote: &Value, text: &mut Text) -> Result<(), ProtocolError> {
    let kind = string(remote, "type")?;
    if kind == "undefined" {
        text.push("undefined");
        return Ok(());
    }
    if let Some(value) = remote.get("value") {
        return primitive(value, text);
    }
    if let Some(value) = remote.get("unserializableValue").and_then(Value::as_str) {
        text.push(value);
        return Ok(());
    }
    let description = remote
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("");
    let properties = remote
        .pointer("/preview/properties")
        .and_then(Value::as_array);
    if let Some(properties) = properties.filter(|_| {
        description == "Object" || remote.get("subtype").and_then(Value::as_str) == Some("array")
    }) {
        if description == "Object" {
            text.push("{");
            for (i, property) in properties.iter().take(MAX_PREVIEW_ITEMS).enumerate() {
                if i != 0 {
                    text.push(", ");
                }
                text.push(string(property, "name")?);
                text.push(": ");
                text.push(
                    property
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or("undefined"),
                );
            }
            if properties.len() > MAX_PREVIEW_ITEMS {
                text.push(TRUNCATED);
            }
            text.push("}");
        } else {
            let mut indexed = properties
                .iter()
                .take(MAX_PREVIEW_ITEMS)
                .filter_map(|property| {
                    property
                        .get("name")
                        .and_then(Value::as_str)?
                        .parse::<u32>()
                        .ok()
                        .map(|index| (index, property))
                })
                .collect::<Vec<_>>();
            indexed.sort_by_key(|(index, _)| *index);
            text.push("[");
            let mut previous = None;
            for (i, (index, property)) in indexed.iter().enumerate() {
                if i != 0 {
                    text.push(", ");
                }
                let gap = previous.map_or(*index as u64, |previous: u32| {
                    index.saturating_sub(previous).saturating_sub(1) as u64
                });
                if gap == 1 {
                    text.push("empty, ");
                } else if gap > 1 {
                    text.push("empty x ");
                    text.push(&gap.to_string());
                    text.push(", ");
                }
                text.push(
                    property
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or("undefined"),
                );
                previous = Some(*index);
            }
            if properties.len() > MAX_PREVIEW_ITEMS {
                text.push(TRUNCATED);
            }
            text.push("]");
        }
    } else {
        text.push(description);
    }
    Ok(())
}
fn primitive(value: &Value, text: &mut Text) -> Result<(), ProtocolError> {
    match value {
        Value::Null => text.push("null"),
        Value::Bool(value) => text.push(if *value { "true" } else { "false" }),
        Value::Number(value) => text.push(&value.to_string()),
        Value::String(value) => text.push(value),
        // Never serialize an arbitrary protocol object or recursively copy it.
        _ => return Err(ProtocolError::InvalidFrame),
    }
    Ok(())
}
fn log(source: AppLogSource, level: AppLogLevel, text: String) -> ProjectedAppEvent {
    ProjectedAppEvent::Log {
        source,
        level,
        text,
    }
}
fn string<'a>(value: &'a Value, name: &str) -> Result<&'a str, ProtocolError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or(ProtocolError::InvalidFrame)
}
fn identifier(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > 1024 {
        Err(ProtocolError::InvalidFrame)
    } else {
        Ok(())
    }
}
/// Display metadata only; never use this value to navigate or match a route.
pub(crate) fn diagnostic_frame_name(value: &str) -> String {
    diagnostic_text(value, MAX_FRAME_NAME_BYTES)
}
fn diagnostic_text(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max.saturating_sub(TRUNCATED.len());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{}", &value[..end], TRUNCATED)
}
fn limited(value: &str, max: usize) -> Result<(), ProtocolError> {
    if value.len() > max {
        Err(ProtocolError::CapacityExceeded)
    } else {
        Ok(())
    }
}
#[derive(Default)]
struct Text {
    value: String,
    truncated: bool,
}
impl Text {
    fn push(&mut self, value: &str) {
        if self.truncated {
            return;
        }
        if self.value.len().saturating_add(value.len()) <= MAX_TEXT_BYTES {
            self.value.push_str(value);
            return;
        }
        let available = (MAX_TEXT_BYTES - TRUNCATED.len()).saturating_sub(self.value.len());
        let mut end = available.min(value.len());
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        self.value.push_str(&value[..end]);
        while self.value.len() > MAX_TEXT_BYTES - TRUNCATED.len() {
            self.value.pop();
        }
        self.value.push_str(TRUNCATED);
        self.truncated = true;
    }
    fn finish(self) -> String {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::super::client_protocol::{ServerMessage, MAX_FRAME_BYTES};
    use super::*;

    fn event(session: &str, method: &str, params: Value) -> CdpEvent {
        CdpEvent {
            method: method.into(),
            params,
            session_id: Some(session.into()),
        }
    }
    fn context(session: &str) -> AppEventContext<'_> {
        AppEventContext {
            session_id: session,
            navigation: None,
        }
    }
    fn navigation(session: &str, kind: AppNavigationKind) -> AppEventContext<'_> {
        AppEventContext {
            session_id: session,
            navigation: Some(AppNavigationContext {
                kind,
                frame_name: Some("pay"),
                initiated_by_operation: false,
            }),
        }
    }
    fn request(projector: &AppEventProjector, session: &str, id: &str, method: &str, url: &str) {
        assert_eq!(projector.project(&event(session, "Network.requestWillBeSent", json!({"requestId":id,"request":{"method":method,"url":url,"headers":{"Authorization":"private-header"}}})), context(session)).unwrap(), None);
    }
    fn wire(projected: Option<ProjectedAppEvent>) -> (&'static str, Value) {
        projected.unwrap().into_wire("scope").unwrap()
    }

    #[test]
    fn console_levels_locations_and_load_echo_filter_match_original() {
        let projector = AppEventProjector::new();
        for (kind, expected) in [
            ("log", "info"),
            ("info", "info"),
            ("warning", "warning"),
            ("error", "error"),
            ("assert", "error"),
        ] {
            let (name, value) = wire(projector.project(&event("page", "Runtime.consoleAPICalled", json!({"type":kind,"executionContextId":4,"args":[{"type":"string","value":"ready"}],"stackTrace":{"callFrames":[{"url":"https://app.test/app.js","lineNumber":11,"columnNumber":4}]}})), context("page")).unwrap());
            assert_eq!(name, "app.log");
            assert_eq!(
                value,
                json!({"identityScope":"scope","source":"console","level":expected,"text":"ready (at https://app.test/app.js:12)"})
            );
        }
        for params in [
            json!({"type":"debug","args":[]}),
            json!({"type":"log","executionContextId":0,"args":[]}),
            json!({"type":"error","args":[{"type":"string","value":"Failed to load resource: net::ERR_FAILED"}]}),
        ] {
            assert_eq!(
                projector
                    .project(
                        &event("page", "Runtime.consoleAPICalled", params),
                        context("page")
                    )
                    .unwrap(),
                None
            );
        }
    }
    #[test]
    fn console_previews_are_allowlisted_application_text_not_remote_objects() {
        let params = json!({"type":"log","args":[{"type":"object","objectId":"secret-remote-id","description":"Object","preview":{"properties":[{"name":"answer","value":"42"}]}},{"type":"object","subtype":"array","description":"Array(3)","preview":{"properties":[{"name":"2","value":"tail"},{"name":"length","value":"3"}]}},{"type":"number","unserializableValue":"NaN"},{"type":"undefined"},{"type":"object","value":null}],"diagnostic":"private backend diagnostic","sessionId":"remote-session"});
        let (_, value) = wire(
            AppEventProjector::new()
                .project(
                    &event("page", "Runtime.consoleAPICalled", params),
                    context("page"),
                )
                .unwrap(),
        );
        assert_eq!(
            value["text"],
            "{answer: 42} [empty x 2, tail] NaN undefined null"
        );
        let bytes = value.to_string();
        assert!(!bytes.contains("secret-remote-id"));
        assert!(!bytes.contains("diagnostic"));
        assert!(!bytes.contains("remote-session"));
    }
    #[test]
    fn exceptions_preserve_message_and_first_application_stack_only() {
        let params = json!({"exceptionDetails":{"text":"Uncaught","exceptionId":42,"scriptId":"secret-script","exception":{"type":"object","objectId":"secret-object","description":"RangeError: render loop exceeded\n    at render (https://app.test/:9:3)\n    at second (https://app.test/:3:2)","preview":{"properties":[]}}}});
        let (_, value) = wire(
            AppEventProjector::new()
                .project(
                    &event("page", "Runtime.exceptionThrown", params),
                    context("page"),
                )
                .unwrap(),
        );
        assert_eq!(
            value,
            json!({"identityScope":"scope","source":"error","level":"error","text":"RangeError: render loop exceeded at render (https://app.test/:9:3)"})
        );
    }
    #[test]
    fn thrown_primitives_and_custom_error_name_match_browser_reporting() {
        let projector = AppEventProjector::new();
        let (_, value) = wire(projector.project(&event("page", "Runtime.exceptionThrown", json!({"exceptionDetails":{"text":"Uncaught","exception":{"type":"string","value":"bad"}}})), context("page")).unwrap());
        assert_eq!(value["text"], ": bad");
        let (_, value) = wire(projector.project(&event("page", "Runtime.exceptionThrown", json!({"exceptionDetails":{"exception":{"type":"object","description":"Error: custom","preview":{"properties":[{"name":"name","value":"ApplicationError"}]}}}})), context("page")).unwrap());
        assert_eq!(value["text"], "ApplicationError: custom");
    }
    #[test]
    fn network_status_failure_filters_and_terminal_cleanup_match_original() {
        let projector = AppEventProjector::new();
        for (id, path, status, status_text, expected) in [
            (
                "1",
                "/api/todos",
                500,
                "Internal Server Error",
                Some("error"),
            ),
            ("2", "/api/missing", 404, "Not Found", Some("warning")),
            ("3", "/favicon.ico?fresh=1", 404, "Not Found", None),
            ("4", "/fine", 200, "OK", None),
        ] {
            request(
                &projector,
                "page",
                id,
                "GET",
                &format!("https://app.test{path}"),
            );
            let response = event(
                "page",
                "Network.responseReceived",
                json!({"requestId":id,"response":{"status":status,"statusText":status_text,"headers":{"cookie":"private"}}}),
            );
            let projected = projector.project(&response, context("page")).unwrap();
            match expected {
                Some(level) => {
                    let (_, value) = wire(projected);
                    assert_eq!(value["level"], level);
                    assert_eq!(
                        value["text"],
                        format!("GET https://app.test{path} {status} {status_text}")
                    );
                }
                None => assert_eq!(projected, None),
            }
            assert_eq!(projector.project(&response, context("page")).unwrap(), None);
            assert_eq!(
                projector
                    .project(
                        &event("page", "Network.loadingFinished", json!({"requestId":id})),
                        context("page")
                    )
                    .unwrap(),
                None
            );
        }
        for (id, reason, canceled, emitted) in [
            ("5", "net::ERR_CONNECTION_RESET", false, true),
            ("6", "net::ERR_ABORTED", false, false),
            ("7", "NS_BINDING_ABORTED", false, false),
            ("8", "request cancelled", false, false),
            ("9", "net::ERR_FAILED", true, false),
        ] {
            request(&projector, "page", id, "POST", "https://app.test/api/reset");
            let failure = event(
                "page",
                "Network.loadingFailed",
                json!({"requestId":id,"errorText":reason,"canceled":canceled}),
            );
            let projected = projector.project(&failure, context("page")).unwrap();
            assert_eq!(projected.is_some(), emitted);
            if emitted {
                assert_eq!(
                    wire(projected).1["text"],
                    "POST https://app.test/api/reset net::ERR_CONNECTION_RESET"
                );
            }
            assert_eq!(projector.project(&failure, context("page")).unwrap(), None);
        }
        assert!(projector.state().unwrap().requests.is_empty());
        assert_eq!(projector.state().unwrap().request_bytes, 0);
    }
    #[test]
    fn redirect_replaces_request_line_and_sessions_cannot_cross_correlate() {
        let projector = AppEventProjector::new();
        request(&projector, "page", "same", "POST", "https://app.test/first");
        request(
            &projector,
            "page",
            "same",
            "GET",
            "https://app.test/redirected",
        );
        request(&projector, "child", "same", "PUT", "https://app.test/frame");
        let response =
            json!({"requestId":"same","response":{"status":404,"statusText":"Not Found"}});
        assert_eq!(
            wire(
                projector
                    .project(
                        &event("page", "Network.responseReceived", response.clone()),
                        context("page")
                    )
                    .unwrap()
            )
            .1["text"],
            "GET https://app.test/redirected 404 Not Found"
        );
        assert_eq!(
            wire(
                projector
                    .project(
                        &event("child", "Network.responseReceived", response),
                        context("child")
                    )
                    .unwrap()
            )
            .1["text"],
            "PUT https://app.test/frame 404 Not Found"
        );
    }
    #[test]
    fn attribution_is_required_and_unknown_protocol_diagnostics_are_never_logs() {
        let projector = AppEventProjector::new();
        for method in [
            "Runtime.consoleAPICalled",
            "Runtime.exceptionThrown",
            "Network.loadingFailed",
            "Page.frameNavigated",
        ] {
            assert_eq!(
                projector
                    .project(
                        &event("foreign", method, json!({"private":"backend diagnostics"})),
                        context("owned")
                    )
                    .unwrap(),
                None
            );
            assert_eq!(
                projector
                    .project(
                        &CdpEvent {
                            method: method.into(),
                            params: json!({}),
                            session_id: None
                        },
                        context("owned")
                    )
                    .unwrap(),
                None
            );
        }
        assert_eq!(
            projector
                .project(
                    &event(
                        "owned",
                        "Inspector.detached",
                        json!({"reason":"private backend failure"})
                    ),
                    context("owned")
                )
                .unwrap(),
            None
        );
        assert_eq!(
            projector
                .project(
                    &event("owned", "Page.frameNavigated", json!({})),
                    context("owned")
                )
                .unwrap(),
            None
        );
        assert_eq!(projector.project(&event("owned", "Runtime.consoleAPICalled", json!({"type":"log","args":[{"type":"object","value":{"objectId":"private"}}]})), context("owned")).unwrap_err(), ProtocolError::InvalidFrame);
    }
    #[test]
    fn navigation_wire_never_contains_backend_identity() {
        let projector = AppEventProjector::new();
        let frame = event(
            "page",
            "Page.frameNavigated",
            json!({"frame":{"id":"remote-frame","parentId":"remote-parent","loaderId":"remote-loader","url":"https://app.test/embed","name":"ignored-untrusted-name"}}),
        );
        let (_, value) = wire(
            projector
                .project(&frame, navigation("page", AppNavigationKind::Frame))
                .unwrap(),
        );
        assert_eq!(
            value,
            json!({"identityScope":"scope","kind":"frame","url":"https://app.test/embed","frameName":"pay","initiatedByOperation":false})
        );
        let within = event(
            "page",
            "Page.navigatedWithinDocument",
            json!({"frameId":"remote-frame","url":"https://app.test/#next"}),
        );
        assert_eq!(
            wire(
                projector
                    .project(&within, navigation("page", AppNavigationKind::Main))
                    .unwrap()
            )
            .1["url"],
            "https://app.test/#next"
        );
    }
    #[test]
    fn navigation_markers_are_exact_session_main_frame_and_raii_bound() {
        let projector = AppEventProjector::new();
        let event_for = |session| {
            event(
                session,
                "Page.frameNavigated",
                json!({"frame":{"url":"https://app.test/next"}}),
            )
        };
        let marked = |session, kind| {
            wire(
                projector
                    .project(&event_for(session), navigation(session, kind))
                    .unwrap(),
            )
            .1["initiatedByOperation"]
                .as_bool()
                .unwrap()
        };
        let first = projector.begin_navigation("page").unwrap();
        let second = projector.begin_navigation("page").unwrap();
        assert!(marked("page", AppNavigationKind::Main));
        assert!(!marked("child", AppNavigationKind::Main));
        assert!(!marked("page", AppNavigationKind::Frame));
        assert!(!marked("page", AppNavigationKind::Popup));
        assert!(!marked("page", AppNavigationKind::PopupNavigation));
        drop(first);
        assert!(marked("page", AppNavigationKind::Main));
        drop(second);
        assert!(!marked("page", AppNavigationKind::Main));
    }
    #[test]
    fn later_popup_and_frame_same_document_navigation_retain_their_kind() {
        let projector = AppEventProjector::new();
        let marker = projector.begin_navigation("popup").unwrap();
        for (kind, expected) in [
            (AppNavigationKind::Popup, "popup"),
            (AppNavigationKind::PopupNavigation, "popup-navigation"),
            (AppNavigationKind::Frame, "frame"),
        ] {
            let (_, payload) = wire(
                projector
                    .project(
                        &event(
                            "popup",
                            "Page.navigatedWithinDocument",
                            json!({"frameId":"remote-frame","url":"https://app.test/#next"}),
                        ),
                        navigation("popup", kind),
                    )
                    .unwrap(),
            );
            assert_eq!(payload["kind"], expected);
            assert_eq!(payload["url"], "https://app.test/#next");
            assert_eq!(payload["initiatedByOperation"], false);
        }
        drop(marker);
    }
    #[test]
    fn late_guard_drop_cannot_clear_new_tenure_and_retirement_drops_request_data() {
        let projector = AppEventProjector::new();
        request(
            &projector,
            "page",
            "request",
            "GET",
            "https://app.test/private",
        );
        let retired = projector.begin_navigation("page").unwrap();
        projector.forget_session("page").unwrap();
        let current = projector.begin_navigation("page").unwrap();
        drop(retired);
        assert_eq!(projector.state().unwrap().navigations["page"].len(), 1);
        assert_eq!(
            projector
                .project(
                    &event(
                        "page",
                        "Network.loadingFailed",
                        json!({"requestId":"request","errorText":"net::ERR_FAILED"})
                    ),
                    context("page")
                )
                .unwrap(),
            None
        );
        projector.clear().unwrap();
        let newest = projector.begin_navigation("page").unwrap();
        drop(current);
        assert_eq!(projector.state().unwrap().navigations["page"].len(), 1);
        drop(newest);
        assert!(projector.state().unwrap().navigations.is_empty());
    }
    #[tokio::test]
    async fn cancelling_a_navigation_task_releases_its_marker() {
        let projector = Arc::new(AppEventProjector::new());
        let marker = projector.begin_navigation("page").unwrap();
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _marker = marker;
            started.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(projector.state().unwrap().navigations.is_empty());
    }
    #[test]
    fn text_and_serialized_wire_are_bounded_even_with_escaping_and_unicode() {
        let text = "\u{0000}😀".repeat(MAX_TEXT_BYTES);
        let projected = AppEventProjector::new().project(&event("page", "Runtime.consoleAPICalled", json!({"type":"log","args":[{"type":"string","value":text}],"stackTrace":{"callFrames":[{"url":"https://app.test/","lineNumber":0}]}})), context("page")).unwrap();
        let (event, payload) = wire(projected);
        let text = payload["text"].as_str().unwrap();
        assert!(text.len() <= MAX_TEXT_BYTES);
        assert!(text.ends_with(TRUNCATED));
        let message = ServerMessage::Event {
            generation: 1,
            sequence: 1,
            event: event.into(),
            payload,
            decision: None,
        };
        assert!(serde_json::to_vec(&message).unwrap().len() < MAX_FRAME_BYTES);
    }
    #[test]
    fn correlation_and_navigation_capacity_are_bounded_and_reclaimed() {
        let projector = AppEventProjector::new();
        for id in 0..MAX_REQUESTS {
            request(
                &projector,
                "page",
                &id.to_string(),
                "GET",
                "https://app.test/",
            );
        }
        assert!(projector.project(&event("page", "Network.requestWillBeSent", json!({"requestId":"overflow","request":{"method":"GET","url":"https://app.test/"}})), context("page")).unwrap().is_none());
        assert!(projector.state().unwrap().requests.len() <= MAX_REQUESTS);
        projector.forget_session("page").unwrap();
        assert_eq!(projector.state().unwrap().request_bytes, 0);
        let guards = (0..MAX_NAVIGATIONS)
            .map(|_| projector.begin_navigation("page").unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            projector.begin_navigation("page"),
            Err(ProtocolError::CapacityExceeded)
        ));
        drop(guards);
        assert!(projector.begin_navigation("page").is_ok());
    }
    #[test]
    fn large_valid_diagnostic_urls_are_truncated_without_rejecting_requests() {
        let projector = AppEventProjector::new();
        let url = format!("data:image/svg+xml,{}", "界".repeat(100_000));
        projector
            .project(
                &event(
                    "page",
                    "Network.requestWillBeSent",
                    json!({"requestId":"large","request":{"method":"GET","url":url}}),
                ),
                context("page"),
            )
            .unwrap();
        let state = projector.state().unwrap();
        let saved = &state
            .requests
            .get(&("page".into(), "large".into()))
            .unwrap()
            .url;
        assert!(saved.len() <= MAX_URL_BYTES && saved.ends_with(TRUNCATED));
        drop(state);
        let projected = projector
            .project(
                &event("page", "Page.frameNavigated", json!({"frame":{"url":url}})),
                navigation("page", AppNavigationKind::Main),
            )
            .unwrap()
            .unwrap();
        let (_, wire) = projected.into_wire("scope").unwrap();
        assert!(wire["url"].as_str().unwrap().ends_with(TRUNCATED));
        assert!(diagnostic_frame_name(&"名".repeat(10_000)).len() <= MAX_FRAME_NAME_BYTES);
    }
    #[test]
    fn valid_large_console_argument_and_preview_counts_truncate_display_only() {
        let projector = AppEventProjector::new();
        let args = vec![json!({"type":"string","value":"x"}); MAX_PREVIEW_ITEMS + 1];
        let projected = projector
            .project(
                &event(
                    "page",
                    "Runtime.consoleAPICalled",
                    json!({"type":"log","args":args}),
                ),
                context("page"),
            )
            .unwrap()
            .unwrap();
        let (_, wire) = projected.into_wire("scope").unwrap();
        assert!(wire["text"].as_str().unwrap().ends_with(TRUNCATED));
        for subtype in ["object", "array"] {
            let properties = (0..MAX_PREVIEW_ITEMS + 1)
                .map(|i| json!({"name":i.to_string(),"value":"x"}))
                .collect::<Vec<_>>();
            let projected=projector.project(&event("page","Runtime.consoleAPICalled",json!({"type":"log","args":[{"type":"object","subtype":subtype,"description":if subtype=="array" {"Array"} else {"Object"},"preview":{"properties":properties}}]})),context("page")).unwrap().unwrap();
            let (_, wire) = projected.into_wire("scope").unwrap();
            assert!(wire["text"].as_str().unwrap().contains(TRUNCATED));
        }
    }
    #[test]
    fn diagnostic_real_projector_and_capture_emit_keep_retirement_outcomes() {
        use super::super::client_settlement_trace::network_probe::{self as probe, Outcome, Stage};
        const URL: &str = "http://127.0.0.1:12345/bad-sw.js";
        let make = |method: &str, id: &str| CdpEvent {
            method: method.into(),
            session_id: Some("worker".into()),
            params: json!({
                "requestId": id, "request": {"url": URL, "method": "GET"},
                "response": {"url": URL, "status": 500, "statusText": "Internal Server Error"}
            }),
        };
        let projector = AppEventProjector::new();
        let request = make("Network.requestWillBeSent", "one");
        let response = make("Network.responseReceived", "one");
        let saved = probe::test_capture(URL, |record| {
            let mut outcome = Outcome::Unreached;
            let mut apply = |event: &CdpEvent, session: &str, expected: Outcome| {
                record(
                    &event.method,
                    event.session_id.as_deref(),
                    &event.params,
                    Stage::Receive,
                    None,
                );
                let result = projector
                    .project_observed(
                        event,
                        AppEventContext {
                            session_id: session,
                            navigation: None,
                        },
                        &mut outcome,
                    )
                    .unwrap();
                assert_eq!(outcome, expected);
                record(
                    &event.method,
                    event.session_id.as_deref(),
                    &event.params,
                    Stage::Project,
                    Some(outcome),
                );
                result
            };
            assert!(apply(&response, "worker", Outcome::MissingRequest).is_none());
            assert!(apply(&request, "wrong", Outcome::WrongSession).is_none());
            assert!(apply(&request, "worker", Outcome::Stored).is_none());
            assert!(apply(
                &make("Network.responseReceived", "other"),
                "worker",
                Outcome::MissingRequest
            )
            .is_none());
            let projected = apply(&response, "worker", Outcome::Projected).unwrap();
            let (name, payload) = projected.into_wire("scope").unwrap();
            assert_eq!(name, "app.log");
            assert_eq!(
                payload["text"],
                format!("GET {URL} 500 Internal Server Error")
            );
            assert!(apply(&response, "worker", Outcome::Duplicate).is_none());
            projector.forget_session("worker").unwrap();
            assert!(apply(&response, "worker", Outcome::MissingRequest).is_none());
        });
        assert_eq!(saved.len(), 14);
        assert!(saved.iter().all(|row| row["droppedBefore"] == 0));
        assert_eq!(saved.last().unwrap()["probe"]["outcome"], "missing-request");
        // Diagnostic I/O and the real projector, not browser/adapter acceptance.
    }
}
