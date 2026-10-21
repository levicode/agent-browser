//! Exact-reference action execution for one negotiated scope. No selector
//! fallback, second identity registry, or renderer handles cross the wire.
//! The owner retains execution and cleanup through cancellation, and quarantines
//! Unknown effects before disposing the original context.
use super::client_blobs::{BlobLease, BlobProducer, BlobScope, BlobStore};
use super::client_browser::BrowserExecutionLease;
use super::client_observation::NodeReference;
use super::client_page::ClientPageState;
use super::client_protocol::{Effects, ProtocolError};
use super::client_session::{CancelSignal, OperationLease};
use super::element::{self, ExactBinding, RefMap};
use super::recording::{self, CaptureOptions, RecordingOptions, RecordingState};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionReason {
    InterceptedPointer,
}
#[derive(Debug)]
pub struct ActionFailure {
    pub error: ProtocolError,
    pub effects: Effects,
    pub cleanup_failed: bool,
    pub reason: Option<ActionReason>,
}
#[derive(Default)]
struct Dispatch {
    sent: AtomicBool,
    cleanup: AtomicBool,
    intercepted: AtomicBool,
}
impl Dispatch {
    fn mark(&self) {
        self.sent.store(true, Ordering::SeqCst);
    }
    fn failure(&self, error: ProtocolError) -> ActionFailure {
        ActionFailure {
            error,
            cleanup_failed: self.cleanup.load(Ordering::SeqCst),
            reason: self
                .intercepted
                .load(Ordering::SeqCst)
                .then_some(ActionReason::InterceptedPointer),
            effects: if self.sent.load(Ordering::SeqCst) {
                Effects::Unknown
            } else {
                Effects::NotDispatched
            },
        }
    }
}
pub struct ActionContext<'a> {
    pub page: &'a BrowserExecutionLease,
    pub operation: &'a OperationLease,
    pub page_state: &'a ClientPageState,
    pub refs: &'a RefMap,
    pub revision: u64,
    pub iframe_sessions: &'a HashMap<String, String>,
    pub blobs: &'a BlobStore,
}
impl ActionContext<'_> {
    fn check(&self) -> Result<(), ProtocolError> {
        self.page.permit.check()?;
        if *self.operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= self.operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(())
    }
    fn blob_scope(&self) -> BlobScope {
        BlobScope {
            generation: self.operation.generation,
            identity_scope: self.page.identity_scope.clone(),
        }
    }
    async fn bounded<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, String>>,
    ) -> Result<T, ProtocolError> {
        self.check()?;
        let mut cancel = self.operation.cancellation.clone();
        tokio::select! {
            value=future=>{self.check()?;value.map_err(|_|ProtocolError::BrowserFailure)},
            _=cancel.changed()=>Err(ProtocolError::Cancelled),
            _=tokio::time::sleep_until(self.operation.deadline.into())=>Err(ProtocolError::DeadlineExceeded),
        }
    }
    async fn command(
        &self,
        dispatch: &Dispatch,
        mutation: bool,
        session: &str,
        method: &str,
        args: Value,
    ) -> Result<Value, ProtocolError> {
        self.check()?;
        if mutation {
            dispatch.mark();
        }
        self.bounded(
            self.page
                .client
                .send_command(method, Some(args), Some(session)),
        )
        .await
    }
    async fn pause(&self, duration: Duration) -> Result<(), ProtocolError> {
        self.check()?;
        let mut cancel = self.operation.cancellation.clone();
        tokio::select! {
            _=tokio::time::sleep(duration)=>self.check(),
            _=cancel.changed()=>Err(ProtocolError::Cancelled),
            _=tokio::time::sleep_until(self.operation.deadline.into())=>Err(ProtocolError::DeadlineExceeded),
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Point {
    x: f64,
    y: f64,
}
impl Point {
    fn validate(self) -> Result<Self, ProtocolError> {
        if self.x.is_finite() && self.y.is_finite() {
            Ok(Self {
                x: self.x.round(),
                y: self.y.round(),
            })
        } else {
            Err(ProtocolError::InvalidArguments)
        }
    }
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Direction {
    Up,
    Down,
    Left,
    Right,
}
#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Momentum {
    #[default]
    None,
    Slow,
    Fast,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Selection {
    LabelString(String),
    Exact(SelectionObject),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionObject {
    label: Option<String>,
    value: Option<String>,
    index: Option<usize>,
}
impl Selection {
    fn wire(&self) -> Result<Value, ProtocolError> {
        match self {
            Self::LabelString(label) => Ok(json!({"label":label})),
            Self::Exact(s) => {
                if usize::from(s.label.is_some())
                    + usize::from(s.value.is_some())
                    + usize::from(s.index.is_some())
                    != 1
                {
                    return Err(ProtocolError::InvalidArguments);
                }
                Ok(if let Some(label) = &s.label {
                    json!({"label":label})
                } else if let Some(value) = &s.value {
                    json!({"value":value})
                } else {
                    json!({"index":s.index})
                })
            }
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UploadFile {
    name: String,
    mime_type: String,
    body_handle: String,
    relative_path: Option<String>,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum LocatorAction {
    Tap {
        modifiers: Option<Vec<String>>,
    },
    DoubleTap {
        modifiers: Option<Vec<String>>,
    },
    SecondaryTap {
        modifiers: Option<Vec<String>>,
    },
    Check,
    Uncheck,
    Clear,
    Focus,
    Hover,
    ScrollIntoView,
    LongPress {
        #[serde(rename = "durationMs")]
        duration_ms: Option<u64>,
    },
    Fill {
        value: String,
        sensitive: bool,
    },
    Press {
        key: String,
    },
    SelectOption {
        value: Selection,
    },
    SetInputFiles {
        #[serde(rename = "directoryName")]
        directory_name: Option<String>,
        files: Vec<UploadFile>,
    },
    DragTo {
        target: NodeReference,
    },
    Swipe {
        direction: Direction,
        #[serde(default)]
        momentum: Momentum,
    },
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum PointerAction {
    Tap,
    DoubleTap,
    SecondaryTap,
    Hover,
    LongPress {
        #[serde(rename = "durationMs")]
        duration_ms: Option<u64>,
    },
    DragTo {
        target: Point,
    },
    Swipe {
        direction: Direction,
        #[serde(default)]
        momentum: Momentum,
    },
    SwipeTo {
        target: Point,
        #[serde(rename = "durationMs")]
        duration_ms: Option<u64>,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Perform {
    identity_scope: String,
    #[serde(rename = "ref")]
    reference: NodeReference,
    action: LocatorAction,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pointer {
    identity_scope: String,
    point: Point,
    action: PointerAction,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyboardType {
    identity_scope: String,
    text: String,
    replace: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyboardPress {
    identity_scope: String,
    key: String,
}
fn decode<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, ProtocolError> {
    serde_json::from_value(v.clone()).map_err(|_| ProtocolError::InvalidArguments)
}
fn scope(ctx: &ActionContext<'_>, identity: &str) -> Result<(), ProtocolError> {
    ctx.check()?;
    if ctx.page.identity_scope != identity {
        Err(ProtocolError::StaleScope)
    } else {
        Ok(())
    }
}
fn reference<'a>(
    ctx: &'a ActionContext<'_>,
    r: &NodeReference,
) -> Result<(&'a element::RefEntry, ExactBinding), ProtocolError> {
    if r.revision != ctx.revision.to_string() {
        return Err(ProtocolError::StaleReference);
    }
    let id = element::parse_ref(&r.id).ok_or(ProtocolError::InvalidArguments)?;
    let entry = ctx.refs.get(&id).ok_or(ProtocolError::StaleReference)?;
    if entry.kind == element::NativeReferenceKind::ReadOnlyCssPseudo {
        return Err(ProtocolError::NotActionable);
    }
    let binding = entry
        .exact_binding
        .clone()
        .ok_or(ProtocolError::StaleReference)?;
    if binding.page_session != ctx.page.page_session_id {
        return Err(ProtocolError::StaleReference);
    }
    Ok((entry, binding))
}
struct Resolved {
    object: String,
    session: String,
    binding: ExactBinding,
}
impl Resolved {
    async fn release(&self, ctx: &ActionContext<'_>) -> Result<(), ProtocolError> {
        tokio::time::timeout(
            Duration::from_millis(250),
            ctx.page.client.send_command(
                "Runtime.releaseObject",
                Some(json!({"objectId":self.object})),
                Some(&self.session),
            ),
        )
        .await
        .map_err(|_| ProtocolError::CleanupFailed)?
        .map_err(|_| ProtocolError::CleanupFailed)?;
        Ok(())
    }
    async fn call(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        mutation: bool,
        source: &str,
        args: Vec<Value>,
    ) -> Result<Value, ProtocolError> {
        let result=ctx.command(d,mutation,&self.session,"Runtime.callFunctionOn",json!({"objectId":self.object,"functionDeclaration":source,"arguments":args.into_iter().map(|value|json!({"value":value})).collect::<Vec<_>>(),"returnByValue":true,"awaitPromise":true})).await?;
        let released =
            release_call_handles(ctx, d, &self.session, &result, Some(&self.object)).await;
        if result.get("exceptionDetails").is_some() {
            return Err(ProtocolError::BrowserFailure);
        }
        released?;
        let value = result["result"]["value"].clone();
        match value["status"].as_str() {
            Some("stale") => Err(ProtocolError::StaleReference),
            Some("intercepted-pointer") => {
                d.intercepted.store(true, Ordering::SeqCst);
                Err(ProtocolError::NotActionable)
            }
            Some("not-actionable") => Err(ProtocolError::NotActionable),
            Some("invalid") => Err(ProtocolError::InvalidArguments),
            _ => Ok(value),
        }
    }
}
async fn release_call_handles(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    session: &str,
    result: &Value,
    retained: Option<&str>,
) -> Result<(), ProtocolError> {
    let mut seen = HashSet::new();
    let mut failed = false;
    for object in [
        result["result"]["objectId"].as_str(),
        result["exceptionDetails"]["exception"]["objectId"].as_str(),
    ]
    .into_iter()
    .flatten()
    {
        if Some(object) == retained || !seen.insert(object) {
            continue;
        }
        failed |= !matches!(
            tokio::time::timeout(
                Duration::from_millis(250),
                ctx.page.client.send_command(
                    "Runtime.releaseObject",
                    Some(json!({"objectId":object})),
                    Some(session)
                )
            )
            .await,
            Ok(Ok(_))
        );
    }
    if failed {
        d.cleanup.store(true, Ordering::SeqCst);
        Err(ProtocolError::CleanupFailed)
    } else {
        Ok(())
    }
}
async fn resolve(ctx: &ActionContext<'_>, r: &NodeReference) -> Result<Resolved, ProtocolError> {
    let (entry, binding) = reference(ctx, r)?;
    let backend = entry.backend_node_id.ok_or(ProtocolError::StaleReference)?;
    ctx.bounded(element::validate_exact_binding(
        &ctx.page.client,
        &ctx.page.page_session_id,
        &binding,
    ))
    .await?;
    let object = ctx
        .bounded(element::resolve_exact_object(
            &ctx.page.client,
            &binding,
            backend,
        ))
        .await?;
    Ok(Resolved {
        object,
        session: binding.session.clone(),
        binding,
    })
}

/// Upload directories and recording tasks remain owned beyond an interrupted
/// RPC. The scope owner must await cleanup before disposing its context.
pub struct ClientActions {
    uploads: tokio::sync::Mutex<Vec<UploadResource>>,
    recording: tokio::sync::Mutex<Option<OwnedRecording>>,
}
impl Default for ClientActions {
    fn default() -> Self {
        Self {
            uploads: tokio::sync::Mutex::new(Vec::new()),
            recording: tokio::sync::Mutex::new(None),
        }
    }
}
impl ClientActions {
    pub async fn execute(
        &self,
        ctx: ActionContext<'_>,
        name: &str,
        args: &Value,
    ) -> Result<Value, ActionFailure> {
        let d = Dispatch::default();
        let result = self.execute_inner(&ctx, &d, name, args).await;
        result.map_err(|error| d.failure(error))
    }
    async fn execute_inner(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        name: &str,
        args: &Value,
    ) -> Result<Value, ProtocolError> {
        ctx.check()?;
        match name {
            "browser.perform" => {
                let request: Perform = decode(args)?;
                scope(ctx, &request.identity_scope)?;
                self.perform(ctx, d, request).await?;
            }
            "browser.pointer" => {
                let request: Pointer = decode(args)?;
                scope(ctx, &request.identity_scope)?;
                self.pointer(ctx, d, request.point.validate()?, request.action)
                    .await?;
            }
            "browser.keyboard.type" => {
                let request: KeyboardType = decode(args)?;
                scope(ctx, &request.identity_scope)?;
                require_editable_focus(ctx, d).await?;
                ctx.check()?;
                if request.replace {
                    keyboard(ctx, d, "press", "ControlOrMeta+A").await?;
                    ctx.check()?;
                    keyboard(ctx, d, "press", "Delete").await?;
                    ctx.check()?;
                }
                keyboard(ctx, d, "type", &request.text).await?;
            }
            "browser.keyboard.press" => {
                let request: KeyboardPress = decode(args)?;
                scope(ctx, &request.identity_scope)?;
                keyboard(ctx, d, "press", &request.key).await?;
            }
            "recording.start" => {
                self.record_start(ctx, d, decode(args)?).await?;
            }
            "recording.stop" => return self.record_stop(ctx, d, decode(args)?).await,
            _ => return Err(ProtocolError::UnsupportedCommand),
        }
        ctx.check()?;
        Ok(Value::Null)
    }
}

struct StagedUpload {
    directory: OwnedDirectory,
    paths: Vec<String>,
    _leases: Vec<BlobLease>,
    error: Option<ProtocolError>,
}
struct UploadResource {
    job: Option<tokio::task::JoinHandle<Result<StagedUpload, ProtocolError>>>,
    staged: Option<StagedUpload>,
}
impl UploadResource {
    async fn settle(&mut self) -> Result<(), ProtocolError> {
        if let Some(job) = self.job.as_mut() {
            let result = job.await.map_err(|_| ProtocolError::CleanupFailed);
            self.job.take();
            self.staged = Some(result??);
        }
        match self.staged.as_ref().and_then(|value| value.error.clone()) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

struct OwnedDirectory {
    path: PathBuf,
}
impl OwnedDirectory {
    fn create() -> Result<Self, ProtocolError> {
        let path =
            std::env::temp_dir().join(format!("agent-browser-action-{}", uuid::Uuid::new_v4()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&path)
            .map_err(|_| ProtocolError::BrowserFailure)?;
        Ok(Self { path })
    }
    fn close(self) -> Result<(), ProtocolError> {
        std::fs::remove_dir_all(&self.path).map_err(|_| ProtocolError::CleanupFailed)
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
fn component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0', ':'])
        && name.len() <= 255
}
fn upload_path(name: &str) -> Result<PathBuf, ProtocolError> {
    if name.is_empty() || name.len() > 4096 || name.contains(['\\', '\0', ':']) {
        return Err(ProtocolError::InvalidArguments);
    }
    let path = Path::new(name);
    if path.is_absolute()
        || path
            .components()
            .any(|p| !matches!(p, Component::Normal(_)))
        || name.split('/').any(|p| !component(p))
    {
        return Err(ProtocolError::InvalidArguments);
    }
    Ok(path.into())
}
fn duration(value: Option<u64>, default: u64) -> Result<Duration, ProtocolError> {
    let ms = value.unwrap_or(default);
    if ms > 60_000 {
        Err(ProtocolError::InvalidArguments)
    } else {
        Ok(Duration::from_millis(ms))
    }
}
fn wheel(
    direction: Direction,
    momentum: Momentum,
    width: f64,
    height: f64,
) -> Result<(f64, f64), ProtocolError> {
    if !width.is_finite() || !height.is_finite() || width <= 0.0 || height <= 0.0 {
        return Err(ProtocolError::NotActionable);
    }
    let extent = if matches!(direction, Direction::Up | Direction::Down) {
        height
    } else {
        width
    };
    let distance = (extent
        * match momentum {
            Momentum::None => 0.5,
            Momentum::Slow => 0.75,
            Momentum::Fast => 1.5,
        })
    .round();
    Ok(match direction {
        Direction::Up => (0.0, -distance),
        Direction::Down => (0.0, distance),
        Direction::Left => (-distance, 0.0),
        Direction::Right => (distance, 0.0),
    })
}
async fn keyboard(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    action: &str,
    value: &str,
) -> Result<(), ProtocolError> {
    ctx.check()?;
    ClientPageState::validate_keyboard_command(action, value)?;
    d.mark();
    ctx.page_state
        .execute(
            ctx.page,
            &[],
            ctx.operation,
            "input.keyboard",
            &json!({"action":action,"value":value}),
        )
        .await?;
    Ok(())
}
async fn pointer_event(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    kind: &str,
    point: Option<Point>,
    button: Option<&str>,
    count: Option<i32>,
    delta: Option<(f64, f64)>,
) -> Result<(), ProtocolError> {
    ctx.check()?;
    d.mark();
    // Shared page input state is the single owner of held keys/buttons.
    ctx.page_state
        .pointer_event(
            ctx.page,
            ctx.operation,
            kind,
            point.map(|p| (p.x, p.y)),
            button,
            count,
            delta,
        )
        .await
}
async fn viewport(ctx: &ActionContext<'_>, d: &Dispatch) -> Result<(f64, f64), ProtocolError> {
    let result = ctx
        .command(
            d,
            false,
            &ctx.page.page_session_id,
            "Page.getLayoutMetrics",
            json!({}),
        )
        .await?;
    let size = result
        .get("cssLayoutViewport")
        .or_else(|| result.get("layoutViewport"))
        .ok_or(ProtocolError::BrowserFailure)?;
    Ok((
        size["clientWidth"]
            .as_f64()
            .ok_or(ProtocolError::BrowserFailure)?,
        size["clientHeight"]
            .as_f64()
            .ok_or(ProtocolError::BrowserFailure)?,
    ))
}
async fn rendered(ctx: &ActionContext<'_>, d: &Dispatch) -> Result<(), ProtocolError> {
    let result=ctx.command(d,false,&ctx.page.page_session_id,"Runtime.evaluate",json!({"expression":"document.hidden?true:new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>resolve(true))))","awaitPromise":true,"returnByValue":true})).await?;
    if result.get("exceptionDetails").is_some() {
        return Err(ProtocolError::BrowserFailure);
    }
    Ok(())
}
async fn scroll(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    point: Option<Point>,
    direction: Direction,
    momentum: Momentum,
    extent: (f64, f64),
) -> Result<(), ProtocolError> {
    let delta = wheel(direction, momentum, extent.0, extent.1)?;
    if let Some(point) = point {
        pointer_event(ctx, d, "mouseMoved", Some(point), None, None, None).await?;
    }
    pointer_event(ctx, d, "mouseWheel", None, None, None, Some(delta)).await?;
    rendered(ctx, d).await
}
async fn click(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    point: Point,
    button: &str,
    count: i32,
    hold: Duration,
) -> Result<(), ProtocolError> {
    pointer_event(ctx, d, "mouseMoved", Some(point), None, None, None).await?;
    for click_count in 1..=count {
        pointer_event(
            ctx,
            d,
            "mousePressed",
            Some(point),
            Some(button),
            Some(click_count),
            None,
        )
        .await?;
        if !hold.is_zero() {
            ctx.pause(hold).await?;
        }
        pointer_event(
            ctx,
            d,
            "mouseReleased",
            Some(point),
            Some(button),
            Some(click_count),
            None,
        )
        .await?;
    }
    Ok(())
}
async fn drag(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    from: Point,
    to: Point,
    pace: Option<Duration>,
) -> Result<(), ProtocolError> {
    pointer_event(ctx, d, "mouseMoved", Some(from), None, None, None).await?;
    pointer_event(
        ctx,
        d,
        "mousePressed",
        Some(from),
        Some("left"),
        Some(1),
        None,
    )
    .await?;
    let steps = pace
        .map(|p| (p.as_millis() / 16).max(2) as usize)
        .unwrap_or(2);
    let start = Instant::now();
    for step in 1..=steps {
        if let Some(pace) = pace {
            let due = start + pace.mul_f64(step as f64 / steps as f64);
            if let Some(wait) = due.checked_duration_since(Instant::now()) {
                ctx.pause(wait).await?;
            }
        }
        let t = step as f64 / steps as f64;
        let point = Point {
            x: from.x + (to.x - from.x) * t,
            y: from.y + (to.y - from.y) * t,
        }
        .validate()?;
        pointer_event(ctx, d, "mouseMoved", Some(point), None, None, None).await?;
    }
    pointer_event(
        ctx,
        d,
        "mouseReleased",
        Some(to),
        Some("left"),
        Some(1),
        None,
    )
    .await
}
async fn action_target(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    r: &NodeReference,
) -> Result<Resolved, ProtocolError> {
    let resolved = resolve(ctx, r).await?;
    let (_, binding) = reference(ctx, r)?;
    if binding.actionable {
        return Ok(resolved);
    }
    let result=ctx.command(d,false,&resolved.session,"Runtime.callFunctionOn",json!({"objectId":resolved.object,"functionDeclaration":"function(){if(this!==document||!this.isConnected)return null;return this.documentElement;}","returnByValue":false})).await;
    let released = resolved.release(ctx).await;
    if released.is_err() {
        d.cleanup.store(true, Ordering::SeqCst);
    }
    let value = result?;
    let candidate = value["result"]["objectId"].as_str();
    if released.is_err() || value.get("exceptionDetails").is_some() || candidate.is_none() {
        let _ =
            release_call_handles(ctx, d, &resolved.session, &value, Some(&resolved.object)).await;
        return Err(if value.get("exceptionDetails").is_some() {
            ProtocolError::BrowserFailure
        } else if released.is_err() {
            ProtocolError::CleanupFailed
        } else {
            ProtocolError::NotActionable
        });
    }
    let object = candidate.unwrap().to_owned();
    release_call_handles(ctx, d, &resolved.session, &value, Some(&object)).await?;
    Ok(Resolved {
        object,
        session: resolved.session,
        binding: resolved.binding,
    })
}
async fn center(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    node: &Resolved,
    enabled: bool,
) -> Result<(Point, (f64, f64)), ProtocolError> {
    let mut previous: Option<(Point, (f64, f64))> = None;
    loop {
        match center_once(ctx, d, node, enabled).await {
            Ok(current) => {
                if previous.as_ref().is_some_and(|old| {
                    (old.0.x - current.0.x).abs() < 0.5
                        && (old.0.y - current.0.y).abs() < 0.5
                        && (old.1 .0 - current.1 .0).abs() < 0.5
                        && (old.1 .1 - current.1 .1).abs() < 0.5
                }) {
                    return Ok(current);
                }
                previous = Some(current);
            }
            Err(ProtocolError::NotActionable) => previous = None,
            Err(ProtocolError::DeadlineExceeded) => return Err(ProtocolError::NotActionable),
            Err(error) => return Err(error),
        }
        match ctx.pause(Duration::from_millis(16)).await {
            Ok(()) => (),
            Err(ProtocolError::DeadlineExceeded) => return Err(ProtocolError::NotActionable),
            Err(error) => return Err(error),
        }
    }
}
async fn center_once(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    node: &Resolved,
    enabled: bool,
) -> Result<(Point, (f64, f64)), ProtocolError> {
    node.call(ctx,d,false,r#"function(){if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};const rect=this.getBoundingClientRect();const style=getComputedStyle(this);if(rect.width<=0||rect.height<=0||style.visibility==='hidden'||style.visibility==='collapse')return {status:'not-actionable'};return true;}"#,vec![]).await?;
    ctx.command(
        d,
        true,
        &node.session,
        "DOM.scrollIntoViewIfNeeded",
        json!({"objectId":node.object}),
    )
    .await?;
    let bounds = ctx
        .command(
            d,
            false,
            &node.session,
            "DOM.getBoxModel",
            json!({"objectId":node.object}),
        )
        .await?;
    let quad = bounds["model"]["border"]
        .as_array()
        .ok_or(ProtocolError::NotActionable)?;
    if quad.len() != 8 {
        return Err(ProtocolError::BrowserFailure);
    }
    let values = quad
        .iter()
        .map(|v| {
            v.as_f64()
                .filter(|v| v.is_finite())
                .ok_or(ProtocolError::BrowserFailure)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let local = Point {
        x: (values[0] + values[2] + values[4] + values[6]) / 4.0,
        y: (values[1] + values[3] + values[5] + values[7]) / 4.0,
    }
    .validate()?;
    let function = format!(
        r#"function(x,y,enabled){{
      if(!this.isConnected||this.ownerDocument!==document)return {{status:'stale'}};
      const rect=this.getBoundingClientRect();const style=this.ownerDocument.defaultView.getComputedStyle(this);
      if(rect.width<=0||rect.height<=0||style.visibility==='hidden'||style.visibility==='collapse')return {{status:'not-actionable'}};
      let doc=this.ownerDocument;while(doc.defaultView&&doc.defaultView.frameElement)doc=doc.defaultView.frameElement.ownerDocument;
      if(typeof doc.elementFromPoint!=='function'||typeof this.matches!=='function')return {{status:'not-actionable'}};
      const blocker={};const actionable={};
      if(blocker(doc,this,x,y)!==null)return {{status:'intercepted-pointer'}};
      if(enabled&&actionable(doc,this,x,y)!==null)return {{status:'not-actionable'}};
      return {{width:rect.width,height:rect.height}};
    }}"#,
        element::BLOCKER_AT_JS,
        element::ACTIONABILITY_JS
    );
    let size = node
        .call(
            ctx,
            d,
            false,
            &function,
            vec![json!(local.x), json!(local.y), json!(enabled)],
        )
        .await?;
    let offset = ctx
        .bounded(element::session_viewport_offset(
            &ctx.page.client,
            &ctx.page.page_session_id,
            &node.session,
            ctx.iframe_sessions,
        ))
        .await?;
    Ok((
        Point {
            x: local.x + offset.0,
            y: local.y + offset.1,
        }
        .validate()?,
        (
            size["width"]
                .as_f64()
                .ok_or(ProtocolError::BrowserFailure)?,
            size["height"]
                .as_f64()
                .ok_or(ProtocolError::BrowserFailure)?,
        ),
    ))
}
impl ClientActions {
    async fn pointer(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        point: Point,
        action: PointerAction,
    ) -> Result<(), ProtocolError> {
        match action {
            PointerAction::Tap => click(ctx, d, point, "left", 1, Duration::ZERO).await,
            PointerAction::DoubleTap => click(ctx, d, point, "left", 2, Duration::ZERO).await,
            PointerAction::SecondaryTap => click(ctx, d, point, "right", 1, Duration::ZERO).await,
            PointerAction::Hover => {
                pointer_event(ctx, d, "mouseMoved", Some(point), None, None, None).await
            }
            PointerAction::LongPress { duration_ms } => {
                click(ctx, d, point, "left", 1, duration(duration_ms, 500)?).await
            }
            PointerAction::DragTo { target } => drag(ctx, d, point, target.validate()?, None).await,
            PointerAction::SwipeTo {
                target,
                duration_ms,
            } => {
                drag(
                    ctx,
                    d,
                    point,
                    target.validate()?,
                    duration_ms.map(|v| duration(Some(v), 0)).transpose()?,
                )
                .await
            }
            PointerAction::Swipe {
                direction,
                momentum,
            } => {
                scroll(
                    ctx,
                    d,
                    Some(point),
                    direction,
                    momentum,
                    viewport(ctx, d).await?,
                )
                .await
            }
        }
    }
    async fn perform(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        request: Perform,
    ) -> Result<(), ProtocolError> {
        // Scope admission precedes the client-lifetime viewport exception.
        if ctx.refs.is_viewport_ref(&request.reference.id) {
            if let LocatorAction::Swipe {
                direction,
                momentum,
            } = request.action
            {
                return scroll(ctx, d, None, direction, momentum, viewport(ctx, d).await?).await;
            }
            return Err(ProtocolError::NotActionable);
        }
        if let LocatorAction::DragTo { target } = &request.action {
            reference(ctx, target)?;
        }
        if let LocatorAction::SelectOption { value } = &request.action {
            value.wire()?;
        }
        if let LocatorAction::LongPress { duration_ms } = &request.action {
            duration(*duration_ms, 500)?;
        }
        let node = action_target(ctx, d, &request.reference).await?;
        let result = self.perform_node(ctx, d, &node, request.action).await;
        let released = node.release(ctx).await;
        if released.is_err() {
            d.cleanup.store(true, Ordering::SeqCst);
            return result.and(Err(ProtocolError::CleanupFailed));
        }
        result
    }
    async fn perform_node(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        node: &Resolved,
        action: LocatorAction,
    ) -> Result<(), ProtocolError> {
        match action {
            LocatorAction::Tap { modifiers } => self.tap(ctx, d, node, "left", 1, modifiers).await,
            LocatorAction::DoubleTap { modifiers } => {
                self.tap(ctx, d, node, "left", 2, modifiers).await
            }
            LocatorAction::SecondaryTap { modifiers } => {
                self.tap(ctx, d, node, "right", 1, modifiers).await
            }
            LocatorAction::LongPress { duration_ms } => {
                let (point, _) = center(ctx, d, node, true).await?;
                click(ctx, d, point, "left", 1, duration(duration_ms, 500)?).await
            }
            LocatorAction::Hover => {
                let (point, _) = center(ctx, d, node, false).await?;
                pointer_event(ctx, d, "mouseMoved", Some(point), None, None, None).await
            }
            LocatorAction::Swipe {
                direction,
                momentum,
            } => {
                let (point, size) = center(ctx, d, node, false).await?;
                scroll(ctx, d, Some(point), direction, momentum, size).await
            }
            LocatorAction::ScrollIntoView => {
                ctx.command(
                    d,
                    true,
                    &node.session,
                    "DOM.scrollIntoViewIfNeeded",
                    json!({"objectId":node.object}),
                )
                .await?;
                Ok(())
            }
            LocatorAction::Focus => focus(ctx, d, node).await,
            LocatorAction::Press { key } => {
                ClientPageState::validate_keyboard_command("press", &key)?;
                focus(ctx, d, node).await?;
                keyboard(ctx, d, "press", &key).await
            }
            LocatorAction::Fill { value, sensitive } => {
                // Sensitive and ordinary fills both return only fixed error
                // categories. No submitted value or raw renderer cause escapes.
                fill(ctx, d, node, &value, sensitive).await
            }
            LocatorAction::Clear => fill(ctx, d, node, "", false).await,
            LocatorAction::SelectOption { value } => {
                node.call(ctx, d, true, SELECT_OPTION, vec![value.wire()?])
                    .await?;
                Ok(())
            }
            LocatorAction::Check => set_checked(ctx, d, node, true).await,
            LocatorAction::Uncheck => set_checked(ctx, d, node, false).await,
            LocatorAction::DragTo { target } => {
                let other = action_target(ctx, d, &target).await?;
                let result = async {
                    let (from, _) = center(ctx, d, node, true).await?;
                    let (to, _) = center(ctx, d, &other, true).await?;
                    drag(ctx, d, from, to, None).await
                }
                .await;
                let release = other.release(ctx).await;
                if release.is_err() {
                    d.cleanup.store(true, Ordering::SeqCst);
                    return result.and(Err(ProtocolError::CleanupFailed));
                }
                result
            }
            LocatorAction::SetInputFiles {
                directory_name,
                files,
            } => self.upload(ctx, d, node, directory_name, files).await,
        }
    }
    async fn tap(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        node: &Resolved,
        button: &str,
        count: i32,
        modifiers: Option<Vec<String>>,
    ) -> Result<(), ProtocolError> {
        let (point, _) = center(ctx, d, node, true).await?;
        let receipt = if let Some(modifiers) = modifiers {
            ctx.check()?;
            d.mark();
            Some(
                ctx.page_state
                    .acquire_modifiers(ctx.page, ctx.operation, &modifiers)
                    .await?,
            )
        } else {
            None
        };
        let result = click(ctx, d, point, button, count, Duration::ZERO).await;
        if let Some(receipt) = receipt {
            let restored = ctx
                .page_state
                .restore_modifiers(ctx.page, ctx.operation, receipt)
                .await;
            if restored.is_err() {
                d.cleanup.store(true, Ordering::SeqCst);
            }
            if let Err(error) = restored {
                return Err(result.err().unwrap_or(error));
            }
        }
        result
    }
    async fn upload(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        node: &Resolved,
        directory_name: Option<String>,
        files: Vec<UploadFile>,
    ) -> Result<(), ProtocolError> {
        if files.len() > 10000 || directory_name.as_ref().is_some_and(|n| !component(n)) {
            return Err(ProtocolError::InvalidArguments);
        }
        let mut seen = HashSet::new();
        let mut staged = Vec::<(PathBuf, BlobLease)>::new();
        for file in files {
            if !component(&file.name)
                || file.mime_type.len() > 255
                || file.mime_type.contains(['\r', '\n', '\0'])
            {
                return Err(ProtocolError::InvalidArguments);
            }
            let relative = match (&directory_name, file.relative_path) {
                (Some(_), Some(path)) => {
                    let path = upload_path(&path)?;
                    if path.file_name().and_then(|n| n.to_str()) != Some(&file.name) {
                        return Err(ProtocolError::InvalidArguments);
                    }
                    path
                }
                (None, None) => PathBuf::from(&file.name),
                _ => return Err(ProtocolError::InvalidArguments),
            };
            if !seen.insert(relative.clone()) {
                return Err(ProtocolError::InvalidArguments);
            }
            let lease = ctx
                .blobs
                .borrow_sealed(&ctx.blob_scope(), &file.body_handle)
                .map_err(|_| ProtocolError::InvalidArguments)?;
            staged.push((relative, lease));
        }
        // Validate file-input and cardinality before creating files or dispatch.
        node.call(ctx,d,false,r#"function(directory,count){if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};if(!(this instanceof HTMLInputElement)||this.type!=='file'||this.disabled||this.webkitdirectory!==directory||(!directory&&!this.multiple&&count>1))return {status:'not-actionable'};return true;}"#,vec![json!(directory_name.is_some()),json!(staged.len())]).await?;
        let deadline = ctx.operation.deadline;
        let cancellation = ctx.operation.cancellation.clone();
        let mut resources = self.uploads.lock().await;
        ctx.check()?;
        let job = tokio::task::spawn_blocking(move || {
            stage_upload(directory_name, staged, deadline, cancellation)
        });
        resources.push(UploadResource {
            job: Some(job),
            staged: None,
        });
        let resource = resources.last_mut().ok_or(ProtocolError::BrowserFailure)?;
        // Await without detaching. On a dropped outer future, the stored handle
        // is still joined by cleanup and owns the directory plus quota leases.
        resource.settle().await?;
        let paths = resource
            .staged
            .as_ref()
            .ok_or(ProtocolError::BrowserFailure)?
            .paths
            .clone();
        drop(resources);
        ctx.check()?;
        ctx.command(
            d,
            true,
            &node.session,
            "DOM.setFileInputFiles",
            json!({"objectId":node.object,"files":paths}),
        )
        .await?;
        Ok(())
    }
    pub async fn cleanup(&self) -> Result<(), ProtocolError> {
        let mut recording = self.recording.lock().await;
        let stopped = if let Some(owned) = recording.as_mut() {
            recording::stop_recording_task(&mut owned.state)
                .await
                .map_err(|_| ProtocolError::CleanupFailed)
        } else {
            Ok(())
        };
        let mut recording_failed = stopped.is_err();
        if let Some(owned) = recording.as_mut() {
            if let Some(job) = owned.read_job.as_mut() {
                recording_failed |= job.await.is_err();
            }
            owned.read_job.take();
        }
        if let Some(owned) = recording.take() {
            recording_failed |= owned.directory.close().is_err();
        }
        drop(recording);
        let mut uploads = self.uploads.lock().await;
        let mut failed = recording_failed;
        for upload in uploads.iter_mut() {
            failed |= upload.settle().await.is_err();
        }
        let resources = std::mem::take(&mut *uploads);
        drop(uploads);
        for mut upload in resources {
            if let Some(staged) = upload.staged.take() {
                failed |= staged.directory.close().is_err();
            }
        }
        if failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
}
async fn focus(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    node: &Resolved,
) -> Result<(), ProtocolError> {
    node.call(ctx,d,true,"function(){if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};if(typeof this.focus!=='function')return {status:'not-actionable'};this.focus();return true;}",vec![]).await?;
    Ok(())
}
const PREPARE_FILL: &str = r#"function(value){
 if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};
 if(this.matches(':disabled')||this.readOnly)return {status:'not-actionable'};
 if(this instanceof HTMLInputElement){
  const type=this.type;
  if(['button','checkbox','file','hidden','image','radio','range','reset','submit','color'].includes(type))return {status:'not-actionable'};
  if(type==='number'&&value!==''&&!Number.isFinite(Number(value)))return {status:'invalid'};
  this.focus();
  if(['date','datetime-local','month','time','week'].includes(type)){this.value=value;if(this.value!==value)return {status:'invalid'};this.dispatchEvent(new Event('input',{bubbles:true,composed:true}));this.dispatchEvent(new Event('change',{bubbles:true}));return {complete:true};}
  this.select();return {complete:false};
 }
 if(this instanceof HTMLTextAreaElement){this.focus();this.select();return {complete:false};}
 if(this.isContentEditable){this.focus();const range=document.createRange();range.selectNodeContents(this);const selection=document.getSelection();selection.removeAllRanges();selection.addRange(range);return {complete:false};}
 return {status:'not-actionable'};
}"#;
async fn fill(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    node: &Resolved,
    value: &str,
    _sensitive: bool,
) -> Result<(), ProtocolError> {
    let result = node
        .call(ctx, d, true, PREPARE_FILL, vec![json!(value)])
        .await?;
    if result["complete"] == true {
        return Ok(());
    }
    if value.is_empty() {
        keyboard(ctx, d, "press", "Delete").await?;
    } else {
        ctx.command(
            d,
            true,
            &ctx.page.page_session_id,
            "Input.insertText",
            json!({"text":value}),
        )
        .await?;
    }
    Ok(())
}
const SELECT_OPTION: &str = r#"function(wanted){
 if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};
 if(!(this instanceof HTMLSelectElement)||this.matches(':disabled'))return {status:'not-actionable'};
 const options=Array.from(this.options);const selected=options.find((option,index)=>wanted.index!==undefined?index===wanted.index:wanted.value!==undefined?option.value===wanted.value:option.label===wanted.label);
 if(!selected||selected.disabled)return {status:'not-actionable'};
 for(const option of options)option.selected=option===selected;
 this.dispatchEvent(new Event('input',{bubbles:true,composed:true}));this.dispatchEvent(new Event('change',{bubbles:true}));return true;
}"#;
const CHECKED_STATE: &str = r#"function(){
 if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};
 if(this instanceof HTMLInputElement&&['checkbox','radio'].includes(this.type))return {checked:this.checked,radio:this.type==='radio'};
 const role=this.getAttribute('role');if(['checkbox','radio','switch'].includes(role)){const value=this.getAttribute('aria-checked');if(value==='true'||value==='false')return {checked:value==='true',radio:role==='radio'};}
 return {status:'not-actionable'};
}"#;
async fn set_checked(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    node: &Resolved,
    wanted: bool,
) -> Result<(), ProtocolError> {
    let before = node.call(ctx, d, false, CHECKED_STATE, vec![]).await?;
    if before["checked"] == wanted {
        return Ok(());
    }
    if !wanted && before["radio"] == true {
        return Err(ProtocolError::NotActionable);
    }
    let (point, _) = center(ctx, d, node, true).await?;
    click(ctx, d, point, "left", 1, Duration::ZERO).await?;
    let mut first = true;
    loop {
        match node.call(ctx, d, false, CHECKED_STATE, vec![]).await {
            Ok(value) if value["checked"] == wanted => return Ok(()),
            Err(ProtocolError::StaleReference) if first => return Ok(()),
            Err(error) => return Err(error),
            _ => {}
        }
        first = false;
        if Instant::now() + Duration::from_millis(20) >= ctx.operation.deadline {
            return Err(ProtocolError::NotActionable);
        }
        ctx.pause(Duration::from_millis(20)).await?;
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordingSize {
    width: u32,
    height: u32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordingStart {
    identity_scope: String,
    size: Option<RecordingSize>,
    quality: Option<u8>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordingStop {
    identity_scope: String,
}
struct OwnedRecording {
    state: RecordingState,
    directory: OwnedDirectory,
    producer: Option<BlobProducer>,
    scope: BlobScope,
    started_at: String,
    read_job: Option<tokio::task::JoinHandle<Result<Vec<u8>, ProtocolError>>>,
}
impl ClientActions {
    async fn record_start(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        request: RecordingStart,
    ) -> Result<(), ProtocolError> {
        scope(ctx, &request.identity_scope)?;
        let options = CaptureOptions {
            size: request.size.map(|s| (s.width, s.height)),
            jpeg: true,
            quality: request.quality,
        }
        .validate()
        .map_err(|_| ProtocolError::InvalidArguments)?;
        let mut slot = self.recording.lock().await;
        if slot.is_some() {
            return Err(ProtocolError::NotActionable);
        }
        ctx.bounded(recording::check_ffmpeg_available()).await?;
        let producer = ctx
            .blobs
            .reserve_producer(ctx.blob_scope())
            .map_err(|_| ProtocolError::CapacityExceeded)?;
        let directory = OwnedDirectory::create()?;
        let path = directory
            .path
            .join("recording.webm")
            .to_str()
            .ok_or(ProtocolError::BrowserFailure)?
            .to_owned();
        let mut state = RecordingState::new();
        recording::recording_start(&mut state, &path, RecordingOptions::default())
            .map_err(|_| ProtocolError::BrowserFailure)?;
        // Publish ownership, never user-visible success, before the first await
        // that can allocate a remote capture resource.
        *slot = Some(OwnedRecording {
            state,
            directory,
            producer: Some(producer),
            scope: ctx.blob_scope(),
            read_job: None,
            started_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });
        let owned = slot.as_mut().ok_or(ProtocolError::BrowserFailure)?;
        let initial = ctx
            .bounded(recording::capture_initial_image_with_options(
                &ctx.page.client,
                &ctx.page.page_session_id,
                options,
            ))
            .await?;
        d.mark();
        let capture = ctx
            .bounded(recording::attach_capture_session(
                &ctx.page.client,
                &ctx.page.page_session_id,
                &owned.state.capture_session,
            ))
            .await?;
        let frames = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let captured = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let sheets = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        owned.state.capture_task = Some(recording::spawn_recording_task_with_options(
            ctx.page.client.clone(),
            capture,
            initial,
            path,
            owned.state.fps,
            frames.clone(),
            captured.clone(),
            false,
            owned.state.shared_cursor.clone(),
            owned.state.cursor_overlays.clone(),
            Vec::new(),
            None,
            owned.state.contact_sheet_threshold,
            sheets.clone(),
            cancel_rx,
            options,
            Some(ready_tx),
        ));
        owned.state.cancel_tx = Some(cancel_tx);
        owned.state.shared_frame_count = Some(frames);
        owned.state.shared_captured_count = Some(captured);
        owned.state.shared_contact_sheet_count = Some(sheets);
        ctx.bounded(async {
            ready_rx
                .await
                .map_err(|_| "Native recording startup unavailable".to_string())?
        })
        .await?;
        ctx.check()
    }
    async fn record_stop(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        request: RecordingStop,
    ) -> Result<Value, ProtocolError> {
        scope(ctx, &request.identity_scope)?;
        let mut slot = self.recording.lock().await;
        let Some(owned) = slot.as_mut() else {
            return Ok(json!({"identityScope":ctx.page.identity_scope,"segments":[]}));
        };
        if owned.scope != ctx.blob_scope() {
            return Err(ProtocolError::StaleScope);
        }
        // Retain the recorder join across RPC cancellation. Its existing native
        // teardown owns screencast ACKs, encoder completion, and session detach.
        d.mark();
        recording::stop_recording_task(&mut owned.state)
            .await
            .map_err(|_| ProtocolError::CleanupFailed)?;
        recording::recording_stop(&mut owned.state).map_err(|_| ProtocolError::BrowserFailure)?;
        ctx.check()?;
        let limit = ctx.blobs.producer_limit();
        let path = owned.state.output_path.clone();
        let deadline = ctx.operation.deadline;
        let cancellation = ctx.operation.cancellation.clone();
        owned.read_job = Some(tokio::task::spawn_blocking(move || {
            read_recording(path, limit, deadline, cancellation)
        }));
        let read = owned
            .read_job
            .as_mut()
            .ok_or(ProtocolError::BrowserFailure)?
            .await;
        owned.read_job.take();
        let bytes = read.map_err(|_| ProtocolError::BrowserFailure)??;
        ctx.check()?;
        let producer = owned.producer.take().ok_or(ProtocolError::BrowserFailure)?;
        let info = ctx
            .blobs
            .finish_producer(producer, bytes)
            .map_err(|_| ProtocolError::BrowserFailure)?;
        let started_at = owned.started_at.clone();
        let owned = slot.take().ok_or(ProtocolError::BrowserFailure)?;
        if owned.directory.close().is_err() {
            let _ = ctx.blobs.release(&ctx.blob_scope(), &info.handle);
            return Err(ProtocolError::CleanupFailed);
        }
        Ok(
            json!({"identityScope":ctx.page.identity_scope,"segments":[{"identityScope":ctx.page.identity_scope,"handle":info.handle,"size":info.size,"sha256":info.sha256,"mediaType":"video/webm","startedAt":started_at}]}),
        )
    }
}

/// Focus is discovered by the native AX tree, including closed shadow roots.
/// No synthetic locator/ref or injected shadow-root registry is introduced.
async fn require_editable_focus(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
) -> Result<(), ProtocolError> {
    if ctx.revision == 0 {
        return Err(ProtocolError::StaleReference);
    }
    let frames = super::client_observation::enumerate_frames(
        &ctx.page.client,
        &ctx.page.page_session_id,
        ctx.iframe_sessions,
        ctx.operation,
    )
    .await
    .map_err(|error| match error {
        super::client_observation::ObservationError::Cancelled => ProtocolError::Cancelled,
        super::client_observation::ObservationError::DeadlineExceeded => {
            ProtocolError::DeadlineExceeded
        }
        super::client_observation::ObservationError::StaleReference => {
            ProtocolError::StaleReference
        }
        _ => ProtocolError::BrowserFailure,
    })?;
    ctx.check()?;
    for frame in frames {
        let tree = ctx
            .command(
                d,
                false,
                &frame.binding.session,
                "Accessibility.getFullAXTree",
                json!({"frameId":frame.binding.frame}),
            )
            .await?;
        let nodes = tree["nodes"]
            .as_array()
            .ok_or(ProtocolError::BrowserFailure)?;
        for node in nodes {
            if !node["properties"].as_array().is_some_and(|properties| {
                properties.iter().any(|property| {
                    property["name"] == "focused" && property["value"]["value"] == true
                })
            }) {
                continue;
            }
            let backend = node["backendDOMNodeId"]
                .as_i64()
                .ok_or(ProtocolError::BrowserFailure)?;
            let object = ctx
                .bounded(element::resolve_exact_object(
                    &ctx.page.client,
                    &frame.binding,
                    backend,
                ))
                .await?;
            let resolved = Resolved {
                object,
                session: frame.binding.session.clone(),
                binding: frame.binding.clone(),
            };
            let result=resolved.call(ctx,d,false,r#"function(){
              if(!this.isConnected||this.ownerDocument!==document)return {status:'stale'};
              if(this===document.body||this===document.documentElement)return false;
              if(this instanceof HTMLInputElement)return !this.disabled&&!this.readOnly&&!['button','submit','reset','checkbox','radio','file','image','range','color'].includes(this.type);
              if(this instanceof HTMLTextAreaElement)return !this.disabled&&!this.readOnly;
              if(this instanceof HTMLSelectElement||this instanceof HTMLButtonElement||this instanceof HTMLAnchorElement||this instanceof HTMLIFrameElement||this instanceof HTMLFrameElement)return false;
              return this.nodeType===1;
            }"#,vec![]).await;
            let released = resolved.release(ctx).await;
            if released.is_err() {
                d.cleanup.store(true, Ordering::SeqCst);
                return result.map(|_| ()).and(Err(ProtocolError::CleanupFailed));
            }
            ctx.check()?;
            if result? == true {
                return Ok(());
            }
        }
    }
    Err(ProtocolError::NotActionable)
}

fn stage_upload(
    directory_name: Option<String>,
    staged: Vec<(PathBuf, BlobLease)>,
    deadline: Instant,
    cancellation: tokio::sync::watch::Receiver<CancelSignal>,
) -> Result<StagedUpload, ProtocolError> {
    let check = || {
        if *cancellation.borrow() != CancelSignal::None {
            Err(ProtocolError::Cancelled)
        } else if Instant::now() >= deadline {
            Err(ProtocolError::DeadlineExceeded)
        } else {
            Ok(())
        }
    };
    check()?;
    let directory = OwnedDirectory::create()?;
    let result = (|| -> Result<Vec<String>, ProtocolError> {
        let root = if let Some(name) = &directory_name {
            let root = directory.path.join(name);
            std::fs::create_dir(&root).map_err(|_| ProtocolError::BrowserFailure)?;
            root
        } else {
            directory.path.clone()
        };
        let mut paths = Vec::new();
        for (relative, lease) in &staged {
            check()?;
            let path = root.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|_| ProtocolError::BrowserFailure)?;
            }
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&path)
                .map_err(|_| ProtocolError::BrowserFailure)?;
            for chunk in lease.bytes().chunks(256 * 1024) {
                check()?;
                std::io::Write::write_all(&mut file, chunk)
                    .map_err(|_| ProtocolError::BrowserFailure)?;
            }
            paths.push(
                path.to_str()
                    .ok_or(ProtocolError::BrowserFailure)?
                    .to_owned(),
            );
        }
        if directory_name.is_some() {
            paths = vec![root
                .to_str()
                .ok_or(ProtocolError::BrowserFailure)?
                .to_owned()];
        }
        check()?;
        Ok(paths)
    })();
    let (paths, error) = match result {
        Ok(paths) => (paths, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    Ok(StagedUpload {
        directory,
        paths,
        _leases: staged.into_iter().map(|(_, lease)| lease).collect(),
        error,
    })
}

fn read_recording(
    path: String,
    limit: usize,
    deadline: Instant,
    cancellation: tokio::sync::watch::Receiver<CancelSignal>,
) -> Result<Vec<u8>, ProtocolError> {
    let metadata = std::fs::metadata(&path).map_err(|_| ProtocolError::BrowserFailure)?;
    if metadata.len() == 0 || metadata.len() > limit as u64 {
        return Err(ProtocolError::CapacityExceeded);
    }
    let mut file = std::fs::File::open(path).map_err(|_| ProtocolError::BrowserFailure)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut buffer = [0u8; 256 * 1024];
    loop {
        if *cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        let count = std::io::Read::read(&mut file, &mut buffer)
            .map_err(|_| ProtocolError::BrowserFailure)?;
        if count == 0 {
            break;
        }
        if bytes.len() + count > limit {
            return Err(ProtocolError::CapacityExceeded);
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    if !bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]) {
        return Err(ProtocolError::BrowserFailure);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::{
        cdp::client::CdpClient, client_blobs::BlobLimits, client_browser::ExecutionGate,
        client_targets::ClientTargets,
    };
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    type Log = Arc<std::sync::Mutex<Vec<Value>>>;
    struct Fixture {
        page: BrowserExecutionLease,
        op: OperationLease,
        _cancel: tokio::sync::watch::Sender<CancelSignal>,
        state: ClientPageState,
        refs: RefMap,
        blobs: BlobStore,
        frames: HashMap<String, String>,
        log: Log,
        server: tokio::task::JoinHandle<()>,
    }
    impl Fixture {
        fn context(&self) -> ActionContext<'_> {
            ActionContext {
                page: &self.page,
                operation: &self.op,
                page_state: &self.state,
                refs: &self.refs,
                revision: 1,
                iframe_sessions: &self.frames,
                blobs: &self.blobs,
            }
        }
        fn inputs(&self) -> Vec<Value> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .filter(|r| {
                    r["method"]
                        .as_str()
                        .is_some_and(|m| m.starts_with("Input."))
                })
                .cloned()
                .collect()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }
    async fn fixture(mode: &'static str) -> Fixture {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let log: Log = Arc::default();
        let captured = log.clone();
        let gate = Arc::new(ExecutionGate::default());
        let server_gate = gate.clone();
        let (cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let server_cancel = cancel.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                let Ok(text) = message.to_text() else {
                    continue;
                };
                let request: Value = serde_json::from_str(text).unwrap();
                captured.lock().unwrap().push(request.clone());
                let method = request["method"].as_str().unwrap();
                let source = request["params"]["functionDeclaration"]
                    .as_str()
                    .unwrap_or("");
                if source.contains("return this.nodeType===1") {
                    if mode == "focus-cancel" {
                        server_cancel.send_replace(CancelSignal::Requested);
                    }
                    if mode == "focus-reset" {
                        server_gate.seal();
                    }
                }
                if method == "Input.dispatchKeyEvent"
                    && request["params"]["type"] == "keyUp"
                    && ((mode == "select-cancel" && request["params"]["code"] == "KeyA")
                        || (mode == "delete-cancel" && request["params"]["code"] == "Delete"))
                {
                    server_cancel.send_replace(CancelSignal::Requested);
                }
                let result = match method {
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"main","loaderId":"doc","url":"about:blank"}}})
                    }
                    "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                    "DOM.resolveNode" => {
                        json!({"object":{"objectId":"exact-node","subtype":"node"}})
                    }
                    "DOM.getBoxModel" => json!({"model":{"border":[0,0,100,0,100,50,0,50]}}),
                    "Page.getLayoutMetrics" => {
                        json!({"cssLayoutViewport":{"clientWidth":100,"clientHeight":200}})
                    }
                    "Browser.getVersion" => json!({"userAgent":"Synthetic Linux"}),
                    "Accessibility.getFullAXTree" => {
                        json!({"nodes":[{"backendDOMNodeId":42,"properties":[{"name":"focused","value":{"value":true}}]}]})
                    }
                    "Runtime.callFunctionOn" => {
                        if source.contains("const blocker=") {
                            if mode == "intercepted" {
                                json!({"result":{"value":{"status":"intercepted-pointer"}}})
                            } else {
                                json!({"result":{"value":{"width":100,"height":50}}})
                            }
                        } else if source == PREPARE_FILL {
                            json!({"result":{"value":{"complete":false}}})
                        } else {
                            json!({"result":{"value":true}})
                        }
                    }
                    "Runtime.evaluate" => json!({"result":{"value":true}}),
                    _ => json!({}),
                };
                if socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
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
        let page = BrowserExecutionLease {
            client,
            page_session_id: "page".into(),
            target_id: "target".into(),
            identity_scope: "scope".into(),
            permit: gate.enter(false).unwrap(),
            targets: ClientTargets::new("context".into(), "scope".into()),
        };
        let op = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline: Instant::now() + Duration::from_secs(5),
            cancellation,
        };
        let mut refs = RefMap::new();
        refs.bind_exact(
            42,
            "textbox",
            "",
            ExactBinding {
                page_session: "page".into(),
                session: "page".into(),
                frame: "main".into(),
                loader: "doc".into(),
                actionable: true,
            },
        );
        let blobs = BlobStore::new(BlobLimits::default()).unwrap();
        blobs
            .activate_scope(BlobScope {
                generation: 1,
                identity_scope: "scope".into(),
            })
            .unwrap();
        Fixture {
            page,
            op,
            _cancel: cancel,
            state: ClientPageState::new("scope".into(), "context".into()),
            refs,
            blobs,
            frames: HashMap::new(),
            log,
            server,
        }
    }
    #[test]
    fn upload_paths_refuse_escapes_and_preserve_nested_directory_paths() {
        for path in [
            "", "../a", "a/../b", "/tmp/a", "a\\b", "C:a", "a//b", "a/./b", "a\0b",
        ] {
            assert!(upload_path(path).is_err(), "{path:?}");
        }
        assert_eq!(
            upload_path("nested/data.txt").unwrap(),
            PathBuf::from("nested/data.txt")
        );
    }
    #[test]
    fn select_modes_are_unambiguous_and_string_means_label() {
        assert_eq!(
            decode::<Selection>(&json!("value-looking-label"))
                .unwrap()
                .wire()
                .unwrap(),
            json!({"label":"value-looking-label"})
        );
        assert!(decode::<Selection>(&json!({"label":"a","value":"b"}))
            .unwrap()
            .wire()
            .is_err());
        assert!(decode::<Selection>(&json!({"index":-1})).is_err());
    }
    #[test]
    fn pointer_and_swipe_preserve_public_geometry_contract() {
        assert_eq!(Point { x: 3.7, y: 8.1 }.validate().unwrap().x, 4.0);
        assert!(Point {
            x: f64::NAN,
            y: 0.0
        }
        .validate()
        .is_err());
        assert_eq!(
            wheel(Direction::Down, Momentum::None, 100.0, 200.0).unwrap(),
            (0.0, 100.0)
        );
        assert_eq!(
            wheel(Direction::Left, Momentum::Fast, 100.0, 200.0).unwrap(),
            (-150.0, 0.0)
        );
        assert!(duration(Some(60001), 500).is_err());
    }
    #[tokio::test]
    async fn viewport_capability_still_rejects_old_scope_and_dom_actions() {
        let f = fixture("normal").await;
        let viewport = f.refs.try_viewport_ref().unwrap();
        let actions = ClientActions::default();
        for (scope, kind) in [("old-scope", "swipe"), ("scope", "tap")] {
            let action = if kind == "swipe" {
                json!({"kind":kind,"direction":"down"})
            } else {
                json!({"kind":kind})
            };
            let error=actions.execute(f.context(),"browser.perform",&json!({"identityScope":scope,"ref":{"id":format!("@{viewport}"),"revision":"0"},"action":action})).await.unwrap_err();
            assert_eq!(error.effects, Effects::NotDispatched);
        }
        assert!(f.inputs().is_empty());
    }
    #[tokio::test]
    async fn stale_exact_ref_revision_never_dispatches_or_uses_role_fallback() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        let error=actions.execute(f.context(),"browser.perform",&json!({"identityScope":"scope","ref":{"id":"@e1","revision":"0"},"action":{"kind":"tap"}})).await.unwrap_err();
        assert_eq!(error.error, ProtocolError::StaleReference);
        assert_eq!(error.effects, Effects::NotDispatched);
        assert!(f.log.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn typing_sequence_fences_focus_select_delete_and_scope_reset() {
        for mode in [
            "focus-cancel",
            "select-cancel",
            "delete-cancel",
            "focus-reset",
        ] {
            let f = fixture(mode).await;
            let actions = ClientActions::default();
            let error = actions
                .execute(
                    f.context(),
                    "browser.keyboard.type",
                    &json!({"identityScope":"scope","replace":true,"text":"Z"}),
                )
                .await
                .unwrap_err();
            let inputs = f.inputs();
            if mode.starts_with("focus-") {
                assert!(inputs.is_empty(), "{mode}");
                assert_eq!(error.effects, Effects::NotDispatched);
            }
            if mode == "select-cancel" {
                assert!(!inputs.iter().any(|r| r["params"]["code"] == "Delete"));
            }
            assert!(
                !inputs
                    .iter()
                    .any(|r| r["params"]["code"] == "KeyZ" || r["method"] == "Input.insertText"),
                "{mode}"
            );
            if mode == "focus-reset" {
                assert_eq!(error.error, ProtocolError::StaleScope);
            } else {
                assert_eq!(error.error, ProtocolError::Cancelled);
            }
        }
    }
    #[tokio::test]
    async fn replacement_typing_dispatches_select_delete_then_literal_type() {
        let f = fixture("normal").await;
        ClientActions::default()
            .execute(
                f.context(),
                "browser.keyboard.type",
                &json!({"identityScope":"scope","replace":true,"text":"Z"}),
            )
            .await
            .unwrap();
        let input = f.inputs();
        let a = input
            .iter()
            .position(|r| r["params"]["code"] == "KeyA")
            .unwrap();
        let delete = input
            .iter()
            .position(|r| r["params"]["code"] == "Delete")
            .unwrap();
        let text = input
            .iter()
            .position(|r| r["params"]["code"] == "KeyZ")
            .unwrap();
        assert!(a < delete && delete < text);
    }
    #[tokio::test]
    async fn pointer_secondary_and_double_click_have_native_button_counts() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        for kind in ["secondaryTap", "doubleTap"] {
            actions.execute(f.context(),"browser.pointer",&json!({"identityScope":"scope","point":{"x":10,"y":20},"action":{"kind":kind}})).await.unwrap();
        }
        let input = f.inputs();
        let pressed: Vec<_> = input
            .iter()
            .filter(|r| r["params"]["type"] == "mousePressed")
            .collect();
        assert_eq!(pressed.len(), 3);
        assert_eq!(pressed[0]["params"]["button"], "right");
        assert_eq!(pressed[2]["params"]["clickCount"], 2);
    }
    #[tokio::test]
    async fn sensitive_fill_failure_has_only_static_categories() {
        let f = fixture("focus-cancel").await;
        f._cancel.send_replace(CancelSignal::Requested);
        let actions = ClientActions::default();
        let error=actions.execute(f.context(),"browser.perform",&json!({"identityScope":"scope","ref":{"id":"@e1","revision":"1"},"action":{"kind":"fill","value":"synthetic-secret-value","sensitive":true}})).await.unwrap_err();
        assert!(!format!("{error:?}").contains("synthetic-secret-value"));
        assert_eq!(error.error, ProtocolError::Cancelled);
    }

    #[tokio::test]
    async fn obscured_action_exposes_only_closed_interception_reason() {
        let mut f = fixture("intercepted").await;
        f.op.deadline = Instant::now() + Duration::from_millis(80);
        let error = ClientActions::default().execute(f.context(),"browser.perform",&json!({"identityScope":"scope","ref":{"id":"@e1","revision":"1"},"action":{"kind":"tap"}})).await.unwrap_err();
        assert_eq!(error.error, ProtocolError::NotActionable);
        assert_eq!(error.reason, Some(ActionReason::InterceptedPointer));
        assert!(f.inputs().is_empty());
    }
    #[tokio::test]
    async fn readonly_pseudo_action_never_resolves_or_retargets_origin() {
        let mut f = fixture("normal").await;
        let id = f
            .refs
            .try_bind_readonly_pseudo(
                99,
                "ListMarker",
                ExactBinding {
                    page_session: "page".into(),
                    session: "page".into(),
                    frame: "main".into(),
                    loader: "doc".into(),
                    actionable: false,
                },
            )
            .unwrap();
        let error=ClientActions::default().execute(f.context(),"browser.perform",&json!({"identityScope":"scope","ref":{"id":format!("@{id}"),"revision":"1"},"action":{"kind":"tap"}})).await.unwrap_err();
        assert_eq!(error.error, ProtocolError::NotActionable);
        assert_eq!(error.effects, Effects::NotDispatched);
        assert!(f.log.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn invalid_keyboard_chord_is_not_dispatched() {
        let f = fixture("normal").await;
        let error = ClientActions::default()
            .execute(
                f.context(),
                "browser.keyboard.press",
                &json!({"identityScope":"scope","key":"NotARealModifier+Enter"}),
            )
            .await
            .unwrap_err();
        assert_eq!(error.error, ProtocolError::InvalidArguments);
        assert_eq!(error.effects, Effects::NotDispatched);
        assert!(f.inputs().is_empty());
    }
    #[tokio::test]
    async fn cancelled_upload_wait_retains_writer_and_cleanup_drains_error_directory() {
        let directory = OwnedDirectory::create().unwrap();
        let path = directory.path.clone();
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let actions = ClientActions::default();
        actions.uploads.lock().await.push(UploadResource {
            job: Some(tokio::task::spawn_blocking(move || {
                let _ = wait.blocking_recv();
                Ok(StagedUpload {
                    directory,
                    paths: Vec::new(),
                    _leases: Vec::new(),
                    error: Some(ProtocolError::Cancelled),
                })
            })),
            staged: None,
        });
        {
            let mut resources = actions.uploads.lock().await;
            assert!(
                tokio::time::timeout(Duration::from_millis(10), resources[0].settle())
                    .await
                    .is_err()
            );
            assert!(resources[0].job.is_some());
        }
        assert!(path.exists());
        release.send(()).unwrap();
        assert_eq!(
            actions.cleanup().await.unwrap_err(),
            ProtocolError::CleanupFailed
        );
        assert!(!path.exists());
        assert!(actions.uploads.lock().await.is_empty());
    }
    #[tokio::test]
    #[ignore = "requires real Chromium in hosted CI; native actions, not protocol mocks"]
    async fn chromium_exact_actions_fill_select_check_document_and_stale_ref() {
        use super::super::browser::{evaluate_on, BrowserManager};
        let mut browser = BrowserManager::launch(Default::default(), None)
            .await
            .unwrap();
        let result = async {
            let session = browser.active_session_id()?.to_owned();
            evaluate_on(&browser.client, &session, r#"document.body.innerHTML='<input id="text"><select id="pick"><option value="a">Alpha</option><option value="b">Beta</option></select><input id="check" type="checkbox"><button id="button" onclick="this.dataset.clicked=Number(this.dataset.clicked||0)+1">Click</button>'; true"#).await?;
            let gate = Arc::new(ExecutionGate::default());
            let page = BrowserExecutionLease { client: browser.client.clone(), page_session_id: session.clone(), target_id: browser.active_target_id()?.into(), identity_scope: "fixture-actions".into(), permit: gate.enter(false).unwrap(), targets: ClientTargets::new("fixture-context".into(), "fixture-actions".into()) };
            let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let operation = OperationLease { is_callback: false, generation: 1, sequence: 1, deadline: Instant::now()+Duration::from_secs(30), cancellation };
            let frames = HashMap::new();
            let tree = browser.client.send_command_no_params("Page.getFrameTree",Some(&session)).await?;
            let frame = &tree["frameTree"]["frame"];
            let binding = ExactBinding { page_session: session.clone(), session: session.clone(), frame: frame["id"].as_str().ok_or("missing frame")?.into(), loader: frame["loaderId"].as_str().ok_or("missing loader")?.into(), actionable: true };
            let document = browser.client.send_command("DOM.getDocument",Some(json!({})),Some(&session)).await?;
            let root = document["root"]["nodeId"].as_i64().ok_or("missing document")?;
            let mut refs = RefMap::new();
            let mut ids = HashMap::new();
            for selector in ["#text", "#pick", "#check", "#button"] {
                let node = browser.client.send_command("DOM.querySelector",Some(json!({"nodeId":root,"selector":selector})),Some(&session)).await?;
                let described = browser.client.send_command("DOM.describeNode",Some(json!({"nodeId":node["nodeId"]})),Some(&session)).await?;
                let backend = described["node"]["backendNodeId"].as_i64().ok_or("missing backend")?;
                ids.insert(selector, format!("@{}", refs.bind_exact(backend,"generic","",binding.clone())));
            }
            let document_backend = document["root"]["backendNodeId"].as_i64().ok_or("missing document backend")?;
            let mut document_binding = binding.clone(); document_binding.actionable = false;
            let document_ref = format!("@{}",refs.bind_exact(document_backend,"document","",document_binding));
            let blobs = BlobStore::new(BlobLimits::default()).unwrap();
            blobs.activate_scope(BlobScope {generation:1, identity_scope:page.identity_scope.clone()}).unwrap();
            let state = ClientPageState::new(page.identity_scope.clone(), "fixture-context".into());
            let actions = ClientActions::default();
            for (selector, action) in [
                ("#text", json!({"kind":"fill","value":"native synthetic","sensitive":false})),
                ("#pick", json!({"kind":"selectOption","value":{"label":"Beta"}})),
                ("#check", json!({"kind":"check"})),
                ("#button", json!({"kind":"doubleTap"})),
            ] {
                actions.execute(ActionContext {page:&page,operation:&operation,page_state:&state,refs:&refs,revision:1,iframe_sessions:&frames,blobs:&blobs},"browser.perform",&json!({"identityScope":page.identity_scope,"ref":{"id":ids[selector],"revision":"1"},"action":action})).await.map_err(|error|format!("action failed: {:?}",error.error))?;
            }
            let value = evaluate_on(&browser.client,&session,"[document.querySelector('#text').value,document.querySelector('#pick').value,document.querySelector('#check').checked,document.querySelector('#button').dataset.clicked]").await?;
            assert_eq!(value,json!(["native synthetic","b",true,"2"]));
            actions.execute(ActionContext {page:&page,operation:&operation,page_state:&state,refs:&refs,revision:1,iframe_sessions:&frames,blobs:&blobs},"browser.perform",&json!({"identityScope":page.identity_scope,"ref":{"id":document_ref,"revision":"1"},"action":{"kind":"scrollIntoView"}})).await.map_err(|error|format!("document action failed: {:?}",error.error))?;
            evaluate_on(&browser.client,&session,"document.querySelector('#button').remove(); true").await?;
            assert!(actions.execute(ActionContext {page:&page,operation:&operation,page_state:&state,refs:&refs,revision:1,iframe_sessions:&frames,blobs:&blobs},"browser.perform",&json!({"identityScope":page.identity_scope,"ref":{"id":ids["#button"],"revision":"1"},"action":{"kind":"tap"}})).await.is_err());
            actions.cleanup().await.map_err(|_|"cleanup failed")?;
            Ok::<(),String>(())
        }.await;
        browser.close().await.unwrap();
        result.unwrap();
    }
}
