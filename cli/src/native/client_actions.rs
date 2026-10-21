//! Exact-reference action execution for one negotiated scope. No selector
//! fallback, second identity registry, or renderer handles cross the wire.
//! The owner retains execution and cleanup through cancellation, and quarantines
//! Unknown effects before disposing the original context.
use super::client_blobs::{ArtifactReservation, AttemptArtifacts, BlobLease, BlobScope, BlobStore};
use super::client_browser::BrowserExecutionLease;
use super::client_geometry::{GeometryError, GeometrySnapshot, Point as GeometryPoint};
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
    CheckedStateUnchanged,
    ControlReplacedAfterClick,
    RecordingSegmentMissing { ordinal: u64 },
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
    checked_unchanged: AtomicBool,
    checked_replaced: AtomicBool,
    recording_missing: std::sync::atomic::AtomicU64,
    acknowledged_postcondition: AtomicBool,
}
impl Dispatch {
    fn mark(&self) {
        self.sent.store(true, Ordering::SeqCst);
    }
    fn failure(&self, error: ProtocolError) -> ActionFailure {
        ActionFailure {
            error,
            cleanup_failed: self.cleanup.load(Ordering::SeqCst),
            reason: if self.intercepted.load(Ordering::SeqCst) {
                Some(ActionReason::InterceptedPointer)
            } else if self.checked_replaced.load(Ordering::SeqCst) {
                Some(ActionReason::ControlReplacedAfterClick)
            } else if self.checked_unchanged.load(Ordering::SeqCst) {
                Some(ActionReason::CheckedStateUnchanged)
            } else if self.recording_missing.load(Ordering::SeqCst) > 0 {
                Some(ActionReason::RecordingSegmentMissing {
                    ordinal: self.recording_missing.load(Ordering::SeqCst),
                })
            } else {
                None
            },
            effects: if self.acknowledged_postcondition.load(Ordering::SeqCst)
                && !self.cleanup.load(Ordering::SeqCst)
            {
                Effects::Completed
            } else if self.sent.load(Ordering::SeqCst) {
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
    pub geometry: &'a GeometrySnapshot,
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
async fn resolve_action_object(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    binding: &ExactBinding,
    backend: i64,
) -> Result<String, ProtocolError> {
    ctx.check()?;
    let future = element::resolve_exact_object(&ctx.page.client, binding, backend);
    tokio::pin!(future);
    let mut cancellation = ctx.operation.cancellation.clone();
    let outcome = tokio::select! {
        result=&mut future => Ok(result),
        _=cancellation.changed()=>Err(ProtocolError::Cancelled),
        _=tokio::time::sleep_until(ctx.operation.deadline.into())=>Err(ProtocolError::DeadlineExceeded),
    };
    let (result, interrupted) = match outcome {
        Ok(result) => (result, None),
        Err(primary) => match tokio::time::timeout(Duration::from_millis(250), &mut future).await {
            Ok(result) => (result, Some(primary)),
            Err(_) => {
                d.cleanup.store(true, Ordering::SeqCst);
                return Err(primary);
            }
        },
    };
    let object = match result {
        Ok(object) => object,
        Err(_) => {
            if interrupted.is_some() {
                d.cleanup.store(true, Ordering::SeqCst);
            }
            return Err(interrupted.unwrap_or(ProtocolError::BrowserFailure));
        }
    };
    if let Some(primary) = interrupted.or_else(|| ctx.check().err()) {
        let released = tokio::time::timeout(
            Duration::from_millis(250),
            ctx.page.client.send_command(
                "Runtime.releaseObject",
                Some(json!({"objectId":object})),
                Some(&binding.session),
            ),
        )
        .await;
        if !matches!(released, Ok(Ok(_))) {
            d.cleanup.store(true, Ordering::SeqCst);
        }
        return Err(primary);
    }
    Ok(object)
}
async fn resolve(
    ctx: &ActionContext<'_>,
    d: &Dispatch,
    r: &NodeReference,
) -> Result<Resolved, ProtocolError> {
    let (entry, binding) = reference(ctx, r)?;
    let backend = entry.backend_node_id.ok_or(ProtocolError::StaleReference)?;
    ctx.bounded(element::validate_exact_binding(
        &ctx.page.client,
        &ctx.page.page_session_id,
        &binding,
    ))
    .await?;
    let object = resolve_action_object(ctx, d, &binding, backend).await?;
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
    recording: tokio::sync::Mutex<RecordingLedger>,
}
impl Default for ClientActions {
    fn default() -> Self {
        Self {
            uploads: tokio::sync::Mutex::new(Vec::new()),
            recording: tokio::sync::Mutex::new(RecordingLedger::default()),
        }
    }
}
impl ClientActions {
    /// Validate without activating a borrowed page or mutating attempt state.
    pub(crate) fn validate_recording_start(
        identity_scope: &str,
        args: &Value,
    ) -> Result<(), ProtocolError> {
        let request: RecordingStart = decode(args)?;
        if request.identity_scope != identity_scope {
            return Err(ProtocolError::StaleScope);
        }
        request.capture_options(None).map(|_| ())
    }
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
    let resolved = resolve(ctx, d, r).await?;
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
fn geometry_failure(d: &Dispatch, error: GeometryError) -> ProtocolError {
    match error {
        GeometryError::Cancelled => ProtocolError::Cancelled,
        GeometryError::DeadlineExceeded => ProtocolError::DeadlineExceeded,
        GeometryError::StaleIdentity => ProtocolError::StaleReference,
        GeometryError::CleanupFailed { primary } => {
            d.cleanup.store(true, Ordering::SeqCst);
            primary
                .map(|e| geometry_failure(d, *e))
                .unwrap_or(ProtocolError::CleanupFailed)
        }
        GeometryError::InvalidGeometry | GeometryError::IncompleteInventory => {
            ProtocolError::UnsupportedCapability
        }
        GeometryError::BackendFailure => ProtocolError::BrowserFailure,
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
    let geometry = ctx
        .geometry
        .refresh_after_scroll(&ctx.page.client, ctx.operation)
        .await
        .map_err(|e| geometry_failure(d, e))?;
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
    let local = GeometryPoint {
        x: (values[0] + values[2] + values[4] + values[6]) / 4.0,
        y: (values[1] + values[3] + values[5] + values[7]) / 4.0,
    };
    let root = geometry
        .project_native_point(
            &node.binding.frame,
            GeometryPoint {
                x: local.x,
                y: local.y,
            },
        )
        .map_err(|e| geometry_failure(d, e))?;
    // Public Input rounds once in root space. Hit-test precisely that eventual
    // dispatch point, not a separately rounded renderer-local coordinate.
    let rounded = Point {
        x: root.x,
        y: root.y,
    }
    .validate()?;
    let root = GeometryPoint {
        x: rounded.x,
        y: rounded.y,
    };
    let local = geometry
        .root_to_frame_point(&node.binding.frame, root)
        .map_err(|e| geometry_failure(d, e))?;
    let function = format!(
        r#"function(x,y,enabled){{
      if(!this.isConnected||this.ownerDocument!==document)return {{status:'stale'}};
      const rect=this.getBoundingClientRect();const style=this.ownerDocument.defaultView.getComputedStyle(this);
      if(rect.width<=0||rect.height<=0||style.visibility==='hidden'||style.visibility==='collapse')return {{status:'not-actionable'}};
      const doc=this.ownerDocument;
      if(typeof doc.elementFromPoint!=='function'||typeof this.matches!=='function'||!doc.elementFromPoint(x,y))return {{status:'not-actionable'}};
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
    // A child-frame local hit can be unobscured while its iframe is covered in
    // an ancestor. Prove each exact native owner in its own parent realm.
    for (binding, backend) in geometry
        .owner_chain(&node.binding.frame)
        .map_err(|e| geometry_failure(d, e))?
    {
        let local = geometry
            .root_to_frame_point(&binding.frame, root)
            .map_err(|e| geometry_failure(d, e))?;
        let object = resolve_action_object(ctx, d, &binding, backend).await?;
        let owner = Resolved {
            object,
            session: binding.session.clone(),
            binding,
        };
        let result = owner
            .call(
                ctx,
                d,
                false,
                &function,
                vec![json!(local.x), json!(local.y), json!(false)],
            )
            .await;
        let cleanup = owner.release(ctx).await;
        if cleanup.is_err() {
            d.cleanup.store(true, Ordering::SeqCst);
        }
        result?;
        cleanup?;
    }
    geometry
        .revalidate(&ctx.page.client, ctx.operation)
        .await
        .map_err(|e| geometry_failure(d, e))?;
    ctx.check()?;
    Ok((
        Point {
            x: root.x,
            y: root.y,
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
    /// Scope teardown drains only scope-local uploads. Recording is owned by
    /// the attempt and survives a properly sequenced page replacement.
    pub async fn cleanup_scope_uploads(&self) -> Result<(), ProtocolError> {
        let mut uploads = self.uploads.lock().await;
        let mut failed = false;
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
    pub async fn cleanup(&self) -> Result<(), ProtocolError> {
        let recording = self.abandon_recording().await;
        let uploads = self.cleanup_scope_uploads().await;
        if recording.is_err() || uploads.is_err() {
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
    let mut largest_read = Duration::ZERO;
    loop {
        // A completed unchanged read is evidence; a timed-out in-flight read is
        // not. Do not dispatch another poll after its measured round-trip budget
        // has gone, and never reinterpret a transport timeout as unchanged.
        if !first {
            ctx.page.permit.check()?;
            if *ctx.operation.cancellation.borrow() != CancelSignal::None {
                return Err(ProtocolError::Cancelled);
            }
            if !checked_poll_fits(
                Instant::now(),
                ctx.operation.deadline,
                Duration::ZERO,
                largest_read,
            ) {
                return checked_unchanged(d);
            }
        }
        let read_started = Instant::now();
        match node.call(ctx, d, false, CHECKED_STATE, vec![]).await {
            Ok(value) if value["checked"] == wanted => return Ok(()),
            Err(ProtocolError::StaleReference) if first => return Ok(()),
            Err(ProtocolError::StaleReference) => {
                d.checked_replaced.store(true, Ordering::SeqCst);
                d.acknowledged_postcondition.store(true, Ordering::SeqCst);
                return Err(ProtocolError::NotActionable);
            }
            Err(error) => return Err(error),
            _ => {}
        }
        largest_read = largest_read.max(read_started.elapsed());
        first = false;
        let interval = Duration::from_millis(20);
        if !checked_poll_fits(
            Instant::now(),
            ctx.operation.deadline,
            interval,
            largest_read,
        ) {
            return checked_unchanged(d);
        }
        match ctx.pause(interval).await {
            Ok(()) => (),
            Err(ProtocolError::DeadlineExceeded) => {
                ctx.page.permit.check()?;
                if *ctx.operation.cancellation.borrow() != CancelSignal::None {
                    return Err(ProtocolError::Cancelled);
                }
                return checked_unchanged(d);
            }
            Err(error) => return Err(error),
        }
    }
}
fn checked_poll_fits(
    now: Instant,
    deadline: Instant,
    pause: Duration,
    last_read: Duration,
) -> bool {
    pause
        .checked_add(last_read)
        .and_then(|budget| now.checked_add(budget))
        .is_some_and(|due| due < deadline)
}
fn checked_unchanged(d: &Dispatch) -> Result<(), ProtocolError> {
    d.checked_unchanged.store(true, Ordering::SeqCst);
    d.acknowledged_postcondition.store(true, Ordering::SeqCst);
    Err(ProtocolError::NotActionable)
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
impl RecordingStart {
    fn capture_options(
        &self,
        output_limit: Option<usize>,
    ) -> Result<CaptureOptions, ProtocolError> {
        CaptureOptions {
            size: self.size.as_ref().map(|s| (s.width, s.height)),
            jpeg: true,
            quality: self.quality,
            output_limit,
        }
        .validate()
        .map_err(|_| ProtocolError::InvalidArguments)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordingStop {
    identity_scope: String,
}
struct RecordingAttachment {
    client: Arc<super::cdp::client::CdpClient>,
    reservation: super::client_targets::AuxiliaryAttachmentReservation,
    startup: Option<tokio::task::JoinHandle<Result<String, String>>>,
    session: Option<String>,
    detached: Arc<AtomicBool>,
    acknowledged_cleanup: HashSet<String>,
    terminal_complete: bool,
    cleanup_failed: bool,
}
impl RecordingAttachment {
    async fn settle_terminal(
        &mut self,
        client: &Arc<super::cdp::client::CdpClient>,
        proof: &super::client_enrollment::NativeTerminalProof,
    ) -> Result<(), ProtocolError> {
        proof.check_client(client)?;
        if !Arc::ptr_eq(client, &self.client) || !*self.client.remote_connection_closed().borrow() {
            return Err(ProtocolError::CleanupFailed);
        }
        if let Some(job) = self.startup.as_mut() {
            // Retain the handle until its await completes, including when this
            // cleanup call is cancelled. A lost attach ACK is not replayed.
            let result = job.await;
            self.startup.take();
            if let Ok(Ok(session)) = result {
                self.session = Some(session.clone());
                let _ = self.reservation.claim(&session);
            }
        }
        self.reservation.settle_terminal_connection(proof)?;
        self.terminal_complete = true;
        self.cleanup_failed = false;
        Ok(())
    }
    async fn settle(&mut self) -> bool {
        if self.terminal_complete {
            return true;
        }
        if let Some(job) = self.startup.as_mut() {
            let result = job.await;
            self.startup.take();
            match result {
                Ok(Ok(session)) => {
                    self.session = Some(session.clone());
                    let _ = self.reservation.claim(&session);
                }
                _ => self.reservation.quarantine(),
            }
        }
        if self.detached.load(Ordering::SeqCst) {
            if let Some(session) = &self.session {
                self.acknowledged_cleanup.insert(session.clone());
            }
        }
        let Ok(sessions) = self.reservation.cleanup_sessions() else {
            self.cleanup_failed = true;
            return false;
        };
        if self.session.is_none()
            || sessions
                .iter()
                .any(|s| !self.acknowledged_cleanup.contains(s))
        {
            self.reservation.quarantine();
        }
        for session in sessions {
            if !self.acknowledged_cleanup.contains(&session) {
                if recording::detach_capture_session_checked(&self.client, &session).await {
                    self.acknowledged_cleanup.insert(session.clone());
                } else {
                    self.cleanup_failed = true;
                    continue;
                }
            }
            if self.session.as_deref() != Some(session.as_str()) {
                self.cleanup_failed |= self.reservation.candidate_detached(&session).is_err();
            }
        }
        let complete = self.session.as_ref().is_some_and(|session| {
            self.acknowledged_cleanup.contains(session)
                && self.reservation.detached(session).is_ok()
        });
        complete && !self.cleanup_failed
    }
}
struct OwnedRecording {
    state: RecordingState,
    directory: OwnedDirectory,
    reservation: Option<ArtifactReservation>,
    scope: BlobScope,
    started_at: String,
    ordinal: u64,
    read_job: Option<tokio::task::JoinHandle<Result<Vec<u8>, ProtocolError>>>,
    bytes: Option<Vec<u8>>,
    cleanup_complete: Arc<AtomicBool>,
    attachment: Option<RecordingAttachment>,
}
#[derive(Default)]
struct RecordingLedger {
    authority: Option<AttemptArtifacts>,
    options: Option<CaptureOptions>,
    current: Option<OwnedRecording>,
    finished: Vec<OwnedRecording>,
    armed: bool,
    abandoned: bool,
    ordinal: u64,
    lost: Option<u64>,
    cleanup_failed: bool,
    filesystem_cleanup_failed: bool,
}
impl RecordingLedger {
    async fn finish_current(&mut self, blobs: &BlobStore) -> Result<(), ProtocolError> {
        let Some(owned) = self.current.as_mut() else {
            return Ok(());
        };
        // A failed native stop can still leave a valid finalized WebM. Retain
        // that artifact rather than discarding it because of the stop status.
        let had_capture = owned.state.capture_task.is_some();
        let _stop = recording::stop_recording_task(&mut owned.state).await;
        if let Some(attachment) = owned.attachment.as_mut() {
            let clean = attachment.settle().await;
            self.cleanup_failed |= !clean;
            if !had_capture
                && clean
                && owned.state.encoder_complete.load(Ordering::SeqCst)
                && !owned.state.cleanup_task_failed
            {
                owned.cleanup_complete.store(true, Ordering::SeqCst);
            }
        }
        self.cleanup_failed |= !owned.cleanup_complete.load(Ordering::SeqCst);
        let _ = recording::recording_stop(&mut owned.state);
        if owned.read_job.is_none() && owned.bytes.is_none() {
            let path = owned.state.output_path.clone();
            let limit = blobs.producer_limit();
            let (sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            owned.read_job = Some(tokio::task::spawn_blocking(move || {
                let _sender = sender;
                read_recording(
                    path,
                    limit,
                    Instant::now() + Duration::from_secs(30),
                    cancellation,
                )
            }));
        }
        let result = if let Some(job) = owned.read_job.as_mut() {
            let result = job.await;
            owned.read_job.take();
            result
                .map_err(|_| ProtocolError::BrowserFailure)
                .and_then(|v| v)
        } else {
            Ok(owned.bytes.take().ok_or(ProtocolError::BrowserFailure)?)
        };
        match result {
            Ok(bytes) => {
                blobs
                    .shrink_artifact(
                        owned
                            .reservation
                            .as_mut()
                            .ok_or(ProtocolError::BrowserFailure)?,
                        bytes.len(),
                    )
                    .map_err(|_| ProtocolError::CapacityExceeded)?;
                owned.bytes = Some(bytes);
                self.finished
                    .push(self.current.take().ok_or(ProtocolError::BrowserFailure)?);
            }
            Err(_) => {
                self.lost.get_or_insert(owned.ordinal);
                if !owned.cleanup_complete.load(Ordering::SeqCst) {
                    return Err(ProtocolError::CleanupFailed);
                }
                let owned = self.current.take().ok_or(ProtocolError::BrowserFailure)?;
                if owned.directory.close().is_err() {
                    self.cleanup_failed = true;
                    self.filesystem_cleanup_failed = true;
                    return Err(ProtocolError::CleanupFailed);
                }
            }
        }
        Ok(())
    }
    async fn settle_start(
        &mut self,
        d: &Dispatch,
        result: Result<(), ProtocolError>,
    ) -> Result<(), ProtocolError> {
        self.armed = result.is_ok();
        if result.is_err() && self.discard_current().await.is_err() {
            d.cleanup.store(true, Ordering::SeqCst);
        }
        result
    }
    async fn discard_current(&mut self) -> Result<(), ProtocolError> {
        let mut failed = false;
        if let Some(owned) = self.current.as_mut() {
            let had_capture = owned.state.capture_task.is_some();
            let _ = recording::stop_recording_task(&mut owned.state).await;
            if let Some(attachment) = owned.attachment.as_mut() {
                let clean = attachment.settle().await;
                failed |= !clean;
                if !had_capture
                    && clean
                    && owned.state.encoder_complete.load(Ordering::SeqCst)
                    && !owned.state.cleanup_task_failed
                {
                    owned.cleanup_complete.store(true, Ordering::SeqCst);
                }
            }
            failed |= !owned.cleanup_complete.load(Ordering::SeqCst);
            if let Some(job) = owned.read_job.as_mut() {
                failed |= job.await.is_err();
            }
            owned.read_job.take();
        }
        // A failed startup/stop still owns its exact attachment and private
        // reservation. Keep it available for proven terminal settlement.
        if failed {
            return Err(ProtocolError::CleanupFailed);
        }
        if let Some(owned) = self.current.take() {
            failed |= owned.directory.close().is_err();
        }
        if failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
}
impl ClientActions {
    /// Settle only resources belonging to the exact terminal native connection.
    /// This does not prove host target, process, or evaluate termination, and
    /// leaves private files, quota reservations, and attempt authority intact.
    pub(crate) async fn settle_terminal_recording(
        &self,
        client: &Arc<super::cdp::client::CdpClient>,
        proof: &super::client_enrollment::NativeTerminalProof,
    ) -> Result<(), ProtocolError> {
        proof.check_client(client)?;
        if !*client.remote_connection_closed().borrow() {
            return Err(ProtocolError::CleanupFailed);
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut ledger = self.recording.lock().await;
            let mut failed = false;
            let RecordingLedger {
                current, finished, ..
            } = &mut *ledger;
            for owned in current.iter_mut().chain(finished.iter_mut()) {
                let Some(attachment) = owned.attachment.as_mut() else {
                    // No connection-specific ownership means no authority to
                    // clear an existing unrelated cleanup failure.
                    failed |= !owned.cleanup_complete.load(Ordering::SeqCst);
                    continue;
                };
                if !Arc::ptr_eq(&attachment.client, client) {
                    // Earlier, already settled segments may belong to a previous
                    // connection; their artifacts remain in the same attempt.
                    failed |= !owned.cleanup_complete.load(Ordering::SeqCst);
                    continue;
                }
                let _ = recording::stop_recording_task(&mut owned.state).await;
                let remote = attachment.settle_terminal(client, proof).await.is_ok();
                if let Some(job) = owned.read_job.as_mut() {
                    let result = job.await;
                    owned.read_job.take();
                    match result {
                        Ok(Ok(bytes)) => owned.bytes = Some(bytes),
                        Ok(Err(_)) => {} // Artifact validity is independent.
                        Err(_) => owned.state.cleanup_task_failed = true,
                    }
                }
                let complete = remote
                    && owned.state.encoder_complete.load(Ordering::SeqCst)
                    && !owned.state.cleanup_task_failed;
                owned.cleanup_complete.store(complete, Ordering::SeqCst);
                failed |= !complete;
            }
            // Do not clear historical filesystem failures with connection proof.
            if !failed && (ledger.current.is_some() || !ledger.finished.is_empty()) {
                ledger.cleanup_failed = ledger.filesystem_cleanup_failed;
            }
            if failed || ledger.cleanup_failed {
                Err(ProtocolError::CleanupFailed)
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|_| ProtocolError::CleanupFailed)?
    }
    /// Read the one attempt ledger, bounded independently of a caller RPC.
    pub async fn is_recording_armed(&self) -> Result<bool, ProtocolError> {
        let ledger = tokio::time::timeout(Duration::from_secs(5), self.recording.lock())
            .await
            .map_err(|_| ProtocolError::DeadlineExceeded)?;
        Ok(ledger.armed && !ledger.abandoned)
    }
    /// Lifecycle-only: call before disposing/revoking the recorded page scope.
    /// The owner retains this future until capture and file reads have joined.
    pub async fn recording_page_closing(
        &self,
        expected_scope: &str,
        blobs: &BlobStore,
    ) -> Result<(), ProtocolError> {
        let mut ledger = self.recording.lock().await;
        if ledger
            .current
            .as_ref()
            .is_some_and(|v| v.scope.identity_scope != expected_scope)
        {
            return Err(ProtocolError::StaleScope);
        }
        ledger.finish_current(blobs).await?;
        if ledger.cleanup_failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
    /// Lifecycle-only: new scope is already initialized and admitted. This
    /// never observes target events or creates a second page registry.
    pub async fn recording_page_opened(&self, ctx: ActionContext<'_>) -> Result<(), ActionFailure> {
        let d = Dispatch::default();
        let mut ledger = self.recording.lock().await;
        if !ledger.armed || ledger.abandoned {
            return Ok(());
        }
        if ledger.current.is_some() {
            return Err(d.failure(ProtocolError::NotActionable));
        }
        let result = Self::begin_segment(&ctx, &d, &mut ledger).await;
        ledger
            .settle_start(&d, result)
            .await
            .map_err(|error| d.failure(error))
    }
    /// Final attempt teardown. Disarm before awaiting so queued page-open
    /// hooks cannot create another segment; retire publication authority first.
    pub async fn abandon_recording(&self) -> Result<(), ProtocolError> {
        let mut ledger = self.recording.lock().await;
        ledger.abandoned = true;
        ledger.armed = false;
        let mut failed = ledger.cleanup_failed;
        failed |= ledger
            .authority
            .as_ref()
            .is_some_and(|a| a.retire().is_err());
        failed |= ledger.discard_current().await.is_err();
        for owned in ledger.finished.drain(..) {
            failed |= owned.directory.close().is_err();
        }
        ledger.lost = None;
        ledger.authority.take();
        if failed {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
    async fn record_start(
        &self,
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        request: RecordingStart,
    ) -> Result<(), ProtocolError> {
        scope(ctx, &request.identity_scope)?;
        let options = request.capture_options(Some(ctx.blobs.producer_limit()))?;
        let mut ledger = self.recording.lock().await;
        if ledger.abandoned {
            return Err(ProtocolError::StaleScope);
        }
        if ledger.current.is_some() {
            ledger.armed = true;
            return Ok(());
        }
        if ledger.authority.is_none() {
            ledger.authority = Some(
                ctx.blobs
                    .begin_artifact_attempt(&ctx.blob_scope())
                    .map_err(|_| ProtocolError::StaleScope)?,
            );
        }
        ledger.options = Some(options);
        let result = Self::begin_segment(ctx, d, &mut ledger).await;
        ledger.settle_start(d, result).await
    }
    async fn begin_segment(
        ctx: &ActionContext<'_>,
        d: &Dispatch,
        ledger: &mut RecordingLedger,
    ) -> Result<(), ProtocolError> {
        ctx.check()?;
        let mut options = ledger.options.ok_or(ProtocolError::BrowserFailure)?;
        if options.size.is_none() {
            let metrics = ctx
                .command(
                    d,
                    false,
                    &ctx.page.page_session_id,
                    "Page.getLayoutMetrics",
                    json!({}),
                )
                .await?;
            let viewport = &metrics["cssLayoutViewport"];
            let width = viewport["clientWidth"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(ProtocolError::BrowserFailure)?;
            let height = viewport["clientHeight"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(ProtocolError::BrowserFailure)?;
            options.size = Some((width, height));
            options = options
                .validate()
                .map_err(|_| ProtocolError::InvalidArguments)?;
        }
        ctx.bounded(recording::check_ffmpeg_available()).await?;
        let reservation = ctx
            .blobs
            .reserve_artifact(
                ledger
                    .authority
                    .as_ref()
                    .ok_or(ProtocolError::BrowserFailure)?,
                &ctx.blob_scope(),
            )
            .map_err(|_| ProtocolError::CapacityExceeded)?;
        let directory = OwnedDirectory::create()?;
        ledger.ordinal = ledger
            .ordinal
            .checked_add(1)
            .filter(|v| *v <= 1_000_000)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        let name = if ledger.ordinal == 1 {
            "video.webm".into()
        } else {
            format!("video-part{}.webm", ledger.ordinal)
        };
        let path = directory
            .path
            .join(name)
            .to_str()
            .ok_or(ProtocolError::BrowserFailure)?
            .to_owned();
        let mut state = RecordingState::new();
        recording::recording_start(&mut state, &path, RecordingOptions::default())
            .map_err(|_| ProtocolError::BrowserFailure)?;
        ledger.current = Some(OwnedRecording {
            state,
            directory,
            reservation: Some(reservation),
            scope: ctx.blob_scope(),
            started_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            ordinal: ledger.ordinal,
            read_job: None,
            bytes: None,
            cleanup_complete: Arc::new(AtomicBool::new(true)),
            attachment: None,
        });
        let owned = ledger
            .current
            .as_mut()
            .ok_or(ProtocolError::BrowserFailure)?;
        let initial = ctx
            .bounded(recording::capture_initial_image_with_options(
                &ctx.page.client,
                &ctx.page.page_session_id,
                options,
            ))
            .await?;
        ctx.check()?;
        let reservation = ctx.page.targets.reserve_auxiliary_attachment(
            &ctx.page.identity_scope,
            &ctx.page.target_id,
            &ctx.page.page_session_id,
        )?;
        let client = ctx.page.client.clone();
        let target = ctx.page.target_id.clone();
        let shared = owned.state.capture_session.clone();
        // Register retained ownership synchronously with spawn, before any
        // cancellation-sensitive await. The bounded job still owns an unknown
        // attachment outcome when the caller stops waiting.
        d.mark();
        owned.cleanup_complete.store(false, Ordering::SeqCst);
        owned.attachment = Some(RecordingAttachment {
            client: client.clone(),
            reservation,
            session: None,
            detached: Arc::new(AtomicBool::new(false)),
            acknowledged_cleanup: HashSet::new(),
            terminal_complete: false,
            cleanup_failed: false,
            startup: Some(tokio::spawn(async move {
                tokio::time::timeout(
                    Duration::from_secs(5),
                    recording::attach_capture_session_to_target(&client, &target, &shared),
                )
                .await
                .map_err(|_| "Native recorder attach outcome unknown".to_owned())?
            })),
        });
        let attachment = owned
            .attachment
            .as_mut()
            .ok_or(ProtocolError::BrowserFailure)?;
        let job = attachment
            .startup
            .as_mut()
            .ok_or(ProtocolError::BrowserFailure)?;
        let mut cancellation = ctx.operation.cancellation.clone();
        let result = tokio::select! {
            result = job => result,
            _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
            _ = tokio::time::sleep_until(ctx.operation.deadline.into()) => return Err(ProtocolError::DeadlineExceeded),
        };
        // Clear a terminal JoinHandle before propagating any failure. A pending
        // handle remains owned above when cancellation wins the select.
        attachment.startup.take();
        let capture = match result {
            Ok(Ok(session)) => session,
            _ => {
                attachment.reservation.quarantine();
                return Err(ProtocolError::BrowserFailure);
            }
        };
        attachment.session = Some(capture.clone());
        attachment.reservation.claim(&capture)?;
        ctx.check()?;
        let frames = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let captured = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let sheets = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        owned.state.encoder_complete.store(false, Ordering::SeqCst);
        owned.state.capture_task = Some(recording::spawn_recording_task_with_session_proof(
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
            Some(owned.cleanup_complete.clone()),
            Some(attachment.detached.clone()),
            Some(owned.state.encoder_complete.clone()),
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
        let mut ledger = self.recording.lock().await;
        ledger.armed = false;
        if ledger.current.is_some() {
            d.mark();
        }
        let finalized = ledger.finish_current(ctx.blobs).await;
        d.cleanup.store(ledger.cleanup_failed, Ordering::SeqCst);
        finalized?;
        ctx.check()?;
        if ledger.cleanup_failed {
            return Err(ProtocolError::CleanupFailed);
        }
        if let Some(ordinal) = ledger.lost.take() {
            d.recording_missing.store(ordinal, Ordering::SeqCst);
            return Err(ProtocolError::BrowserFailure);
        }
        if ledger
            .finished
            .iter()
            .any(|v| v.reservation.is_none() || v.bytes.is_none())
        {
            return Err(ProtocolError::BrowserFailure);
        }
        let mut items = Vec::with_capacity(ledger.finished.len());
        for owned in &mut ledger.finished {
            items.push((
                owned
                    .reservation
                    .take()
                    .ok_or(ProtocolError::BrowserFailure)?,
                owned.bytes.take().ok_or(ProtocolError::BrowserFailure)?,
            ));
        }
        let infos = match ctx.blobs.finish_artifact_batch(items, ctx.blob_scope()) {
            Ok(infos) => infos,
            Err((_, items)) => {
                for (owned, (reservation, bytes)) in ledger.finished.iter_mut().zip(items) {
                    owned.reservation = Some(reservation);
                    owned.bytes = Some(bytes);
                }
                return Err(ProtocolError::StaleScope);
            }
        };
        let mut segments: Vec<Value> = Vec::with_capacity(infos.len());
        let mut cleanup_failed = false;
        for (owned, info) in ledger.finished.drain(..).zip(&infos) {
            let started_at = owned.started_at;
            cleanup_failed |= owned.directory.close().is_err();
            segments.push(json!({"identityScope":ctx.page.identity_scope,"handle":info.handle,"size":info.size,"sha256":info.sha256,"mediaType":"video/webm","startedAt":started_at}));
        }
        let check = ctx.check();
        if cleanup_failed || check.is_err() {
            for info in infos {
                cleanup_failed |= ctx.blobs.release(&ctx.blob_scope(), &info.handle).is_err();
            }
            d.cleanup.store(cleanup_failed, Ordering::SeqCst);
            return Err(check.err().unwrap_or(ProtocolError::CleanupFailed));
        }

        Ok(json!({"identityScope":ctx.page.identity_scope,"segments":segments}))
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
    if metadata.len() == 0 || metadata.len() >= limit as u64 {
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
        geometry: GeometrySnapshot,
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
                geometry: &self.geometry,
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
            let mut checked_reads = 0;
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
                        if mode == "resolve-cancel" {
                            server_cancel.send_replace(CancelSignal::Requested);
                            tokio::time::sleep(Duration::from_millis(30)).await;
                        }
                        json!({"object":{"objectId":"exact-node","subtype":"node"}})
                    }
                    "DOM.getBoxModel" => json!({"model":{"border":[0,0,100,0,100,50,0,50]}}),
                    "Page.getLayoutMetrics" => {
                        json!({"cssVisualViewport":{"clientWidth":100.,"clientHeight":200.,"offsetX":0.,"offsetY":0.,"scale":1.},"cssLayoutViewport":{"clientWidth":100.,"clientHeight":200.}})
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
                        } else if source == CHECKED_STATE {
                            checked_reads += 1;
                            if mode == "check-read-stalled" && checked_reads == 2 {
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            }
                            if (mode == "check-replaced" && checked_reads > 2)
                                || (mode == "check-immediate-replacement" && checked_reads > 1)
                            {
                                json!({"result":{"value":{"status":"stale"}}})
                            } else {
                                json!({"result":{"value":{"checked":false,"radio":false}}})
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
        let geometry = GeometrySnapshot::capture(
            &page.client,
            "page",
            &[super::super::client_observation::ObservationFrame {
                parent_frame_id: None,
                owner_backend_id: None,
                url: "about:blank".into(),
                binding: refs.get("e1").unwrap().exact_binding.clone().unwrap(),
                offset_x: 0.,
                offset_y: 0.,
                frame_path: vec![],
            }],
            &op,
        )
        .await
        .unwrap();
        log.lock().unwrap().clear();
        Fixture {
            geometry,
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
    #[tokio::test]
    async fn cancelled_exact_resolution_drains_and_releases_late_remote_handle() {
        let f = fixture("resolve-cancel").await;
        let d = Dispatch::default();
        let binding = f.refs.get("e1").unwrap().exact_binding.clone().unwrap();
        let result = resolve_action_object(&f.context(), &d, &binding, 42).await;
        assert_eq!(result, Err(ProtocolError::Cancelled));
        assert!(!d.cleanup.load(Ordering::SeqCst));
        assert!(f.inputs().is_empty());
        assert!(f
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|v| v["method"] == "Runtime.releaseObject"
                && v["params"]["objectId"] == "exact-node"));
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

    async fn seed_recording(
        actions: &ClientActions,
        f: &Fixture,
        ordinal: u64,
        bytes: Option<&[u8]>,
        stop_error: bool,
    ) {
        let mut ledger = actions.recording.lock().await;
        if ledger.authority.is_none() {
            ledger.authority = Some(
                f.blobs
                    .begin_artifact_attempt(&f.context().blob_scope())
                    .unwrap(),
            );
        }
        let reservation = f
            .blobs
            .reserve_artifact(
                ledger.authority.as_ref().unwrap(),
                &f.context().blob_scope(),
            )
            .unwrap();
        let directory = OwnedDirectory::create().unwrap();
        let path = directory.path.join(format!("video-part{ordinal}.webm"));
        if let Some(bytes) = bytes {
            std::fs::write(&path, bytes).unwrap();
        }
        let mut state = RecordingState::new();
        state.output_path = path.to_string_lossy().into_owned();
        state.active = true;
        state.frame_count = 1;
        state.capture_task = Some(tokio::spawn(async move {
            if stop_error {
                Err("Synthetic stop failure".into())
            } else {
                Ok(())
            }
        }));
        ledger.armed = true;
        ledger.ordinal = ordinal;
        ledger.current = Some(OwnedRecording {
            state,
            directory,
            reservation: Some(reservation),
            scope: f.context().blob_scope(),
            started_at: format!("2026-10-21T00:00:0{ordinal}.000Z"),
            ordinal,
            read_job: None,
            bytes: None,
            cleanup_complete: Arc::new(AtomicBool::new(true)),
            attachment: None,
        });
    }
    async fn collect_recording(
        actions: &ClientActions,
        f: &Fixture,
    ) -> Result<Value, ActionFailure> {
        actions
            .execute(
                f.context(),
                "recording.stop",
                &json!({"identityScope":f.page.identity_scope}),
            )
            .await
    }
    #[tokio::test]
    async fn recording_ledger_preserves_order_start_instants_and_rotated_scope() {
        let mut f = fixture("normal").await;
        let actions = ClientActions::default();
        let bytes = [0x1a, 0x45, 0xdf, 0xa3, 1];
        seed_recording(&actions, &f, 1, Some(&bytes), false).await;
        actions
            .recording_page_closing("scope", &f.blobs)
            .await
            .unwrap();
        assert!(actions.recording.lock().await.armed);
        f.blobs.revoke_scope(&f.context().blob_scope()).unwrap();
        f.page.identity_scope = "replacement".into();
        f.blobs.activate_scope(f.context().blob_scope()).unwrap();
        seed_recording(&actions, &f, 2, Some(&bytes), false).await;
        let result = collect_recording(&actions, &f).await.unwrap();
        let segments = result["segments"].as_array().unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0]["startedAt"], "2026-10-21T00:00:01.000Z");
        assert_eq!(segments[1]["startedAt"], "2026-10-21T00:00:02.000Z");
        for segment in segments {
            assert_eq!(segment["identityScope"], "replacement");
            let handle = segment["handle"].as_str().unwrap();
            assert_eq!(
                f.blobs
                    .read(&f.context().blob_scope(), handle, 0, 5)
                    .unwrap(),
                bytes
            );
            f.blobs.release(&f.context().blob_scope(), handle).unwrap();
        }
        assert!(!actions.recording.lock().await.armed);
        assert_eq!(
            collect_recording(&actions, &f).await.unwrap()["segments"],
            json!([])
        );
    }
    #[tokio::test]
    async fn recording_batch_rejection_preserves_two_private_segments_for_current_scope() {
        let mut f = fixture("normal").await;
        let actions = ClientActions::default();
        let bytes = [0x1a, 0x45, 0xdf, 0xa3, 1];
        for ordinal in [1, 2] {
            seed_recording(&actions, &f, ordinal, Some(&bytes), false).await;
            actions
                .recording_page_closing("scope", &f.blobs)
                .await
                .unwrap();
        }
        f.blobs.revoke_scope(&f.context().blob_scope()).unwrap();
        assert_eq!(
            collect_recording(&actions, &f).await.unwrap_err().error,
            ProtocolError::StaleScope
        );
        {
            let ledger = actions.recording.lock().await;
            assert_eq!(ledger.finished.len(), 2);
            assert!(ledger
                .finished
                .iter()
                .all(|v| v.reservation.is_some() && v.bytes.as_deref() == Some(&bytes)));
        }
        f.page.identity_scope = "replacement".into();
        f.blobs.activate_scope(f.context().blob_scope()).unwrap();
        let result = collect_recording(&actions, &f).await.unwrap();
        assert_eq!(result["segments"].as_array().unwrap().len(), 2);
        assert_eq!(
            collect_recording(&actions, &f).await.unwrap()["segments"],
            json!([])
        );
    }
    #[tokio::test]
    async fn recording_valid_file_does_not_hide_unproved_capture_cleanup() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        seed_recording(&actions, &f, 1, Some(&[0x1a, 0x45, 0xdf, 0xa3]), true).await;
        actions
            .recording
            .lock()
            .await
            .current
            .as_ref()
            .unwrap()
            .cleanup_complete
            .store(false, Ordering::SeqCst);
        let failure = collect_recording(&actions, &f).await.unwrap_err();
        assert_eq!(failure.error, ProtocolError::CleanupFailed);
        assert!(failure.cleanup_failed);
        assert_eq!(actions.recording.lock().await.finished.len(), 1);
        assert_eq!(
            actions.abandon_recording().await,
            Err(ProtocolError::CleanupFailed)
        );
    }
    #[tokio::test]
    async fn recording_failed_stop_keeps_valid_file_and_reports_missing_once() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        let bytes = [0x1a, 0x45, 0xdf, 0xa3, 1];
        seed_recording(&actions, &f, 1, Some(&bytes), true).await;
        actions
            .recording_page_closing("scope", &f.blobs)
            .await
            .unwrap();
        seed_recording(&actions, &f, 2, None, true).await;
        assert_eq!(
            collect_recording(&actions, &f).await.unwrap_err().error,
            ProtocolError::BrowserFailure
        );
        assert!(!actions.recording.lock().await.armed);
        let result = collect_recording(&actions, &f).await.unwrap();
        assert_eq!(result["segments"].as_array().unwrap().len(), 1);
        assert_eq!(
            result["segments"][0]["startedAt"],
            "2026-10-21T00:00:01.000Z"
        );
        assert_eq!(
            collect_recording(&actions, &f).await.unwrap()["segments"],
            json!([])
        );
    }
    #[tokio::test]
    async fn recording_abandon_joins_and_prevents_late_page_segments() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        seed_recording(&actions, &f, 1, Some(&[0x1a, 0x45, 0xdf, 0xa3]), false).await;
        let path = actions
            .recording
            .lock()
            .await
            .current
            .as_ref()
            .unwrap()
            .directory
            .path
            .clone();
        actions.abandon_recording().await.unwrap();
        assert!(!path.exists());
        actions.recording_page_opened(f.context()).await.unwrap();
        assert!(actions.recording.lock().await.current.is_none());
        assert!(f.log.lock().unwrap().is_empty());
        assert_eq!(
            collect_recording(&actions, &f).await.unwrap()["segments"],
            json!([])
        );
    }
    #[tokio::test]
    async fn recording_failed_first_start_disarms_and_joins_owned_resources() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        seed_recording(&actions, &f, 1, Some(&[0x1a, 0x45, 0xdf, 0xa3]), false).await;
        let path = actions
            .recording
            .lock()
            .await
            .current
            .as_ref()
            .unwrap()
            .directory
            .path
            .clone();
        let d = Dispatch::default();
        let result = actions
            .recording
            .lock()
            .await
            .settle_start(&d, Err(ProtocolError::BrowserFailure))
            .await;
        assert_eq!(result, Err(ProtocolError::BrowserFailure));
        assert!(!actions.recording.lock().await.armed);
        assert!(actions.recording.lock().await.current.is_none());
        assert!(!path.exists());
        actions.recording_page_opened(f.context()).await.unwrap();
        assert_eq!(
            collect_recording(&actions, &f).await.unwrap()["segments"],
            json!([])
        );
        assert!(f.log.lock().unwrap().is_empty());
    }
    async fn enroll_recording_fixture(page: &BrowserExecutionLease) {
        page.targets
            .attached(
                &page.targets.context_id,
                page.target_id.clone(),
                page.page_session_id.clone(),
                "page".into(),
            )
            .unwrap();
        page.targets.configured(&page.target_id).unwrap();
        page.targets
            .resume_permit(&page.target_id)
            .await
            .unwrap()
            .complete()
            .unwrap();
        page.targets.acknowledge_enrollment().unwrap();
    }
    #[test]
    fn recording_start_preflight_reuses_strict_shape_scope_size_quality_validation() {
        for args in [
            json!({"identityScope":"scope"}),
            json!({"identityScope":"scope", "size":{"width":320,"height":200},"quality":70}),
            json!({"identityScope":"scope", "quality":0}),
            json!({"identityScope":"scope", "quality":100}),
        ] {
            assert_eq!(
                ClientActions::validate_recording_start("scope", &args),
                Ok(())
            );
        }
        assert_eq!(
            ClientActions::validate_recording_start("scope", &json!({"identityScope":"other"})),
            Err(ProtocolError::StaleScope)
        );
        for args in [
            Value::Null,
            json!([]),
            json!({}),
            json!({"identityScope":3}),
            json!({"identityScope":"scope","unknown":true}),
            json!({"identityScope":"scope","size":{"width":320}}),
            json!({"identityScope":"scope","size":{"width":320,"height":200,"unknown":0}}),
            json!({"identityScope":"scope","size":{"width":0,"height":200}}),
            json!({"identityScope":"scope","size":{"width":16385,"height":1}}),
            json!({"identityScope":"scope","size":{"width":10000,"height":10000}}),
            json!({"identityScope":"scope","size":{"width":-1,"height":200}}),
            json!({"identityScope":"scope","quality":101}),
            json!({"identityScope":"scope","quality":256}),
            json!({"identityScope":"scope","quality":-1}),
            json!({"identityScope":"scope","quality":70.5}),
            json!({"identityScope":"scope","quality":"70"}),
        ] {
            assert_eq!(
                ClientActions::validate_recording_start("scope", &args),
                Err(ProtocolError::InvalidArguments),
                "{args}"
            );
        }
    }
    fn terminal_recording_proof(
        f: &Fixture,
    ) -> Result<
        (
            super::super::client_enrollment::NativeTerminalProof,
            Arc<super::super::client_network::ClientNetwork>,
        ),
        ProtocolError,
    > {
        use super::super::{
            client_enrollment::NativeTerminalProof,
            client_network::{ClientNetwork, NetworkPolicy},
            client_session::ClientSession,
            client_transport::ClientEventSink,
            client_ui::UiGate,
        };
        let broker = Arc::new(ClientSession::new());
        let (sink, _notices) = ClientEventSink::test_channel(broker.clone());
        let blobs = Arc::new(BlobStore::new(BlobLimits::default()).unwrap());
        let network = Arc::new(ClientNetwork::new(
            f.page.client.clone(),
            broker,
            sink,
            f.context().blob_scope(),
            blobs,
            Arc::new(UiGate::default()),
            NetworkPolicy::default(),
        ));
        let proof = NativeTerminalProof::for_test(
            f.page.client.clone(),
            f.page.targets.clone(),
            &network,
            1,
            "target".into(),
        )?;
        Ok((proof, network))
    }
    async fn seed_terminal_recording(actions: &ClientActions, f: &Fixture) {
        enroll_recording_fixture(&f.page).await;
        seed_recording(actions, f, 1, Some(&[0x1a, 0x45, 0xdf, 0xa3]), false).await;
        let mut reservation = f
            .page
            .targets
            .reserve_auxiliary_attachment("scope", "target", "page")
            .unwrap();
        reservation.claim("recorder").unwrap();
        let mut ledger = actions.recording.lock().await;
        let owned = ledger.current.as_mut().unwrap();
        owned.cleanup_complete.store(false, Ordering::SeqCst);
        owned.attachment = Some(RecordingAttachment {
            client: f.page.client.clone(),
            reservation,
            startup: None,
            session: Some("recorder".into()),
            detached: Arc::new(AtomicBool::new(false)),
            acknowledged_cleanup: HashSet::new(),
            terminal_complete: false,
            cleanup_failed: false,
        });
    }
    async fn disconnect_recording_fixture(f: &Fixture) {
        let mut closed = f.page.client.remote_connection_closed();
        f.server.abort();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !*closed.borrow_and_update() {
                closed.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn terminal_recording_missing_file_retains_attempt_and_failed_start_ownership() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        seed_terminal_recording(&actions, &f).await;
        disconnect_recording_fixture(&f).await;
        {
            let mut ledger = actions.recording.lock().await;
            let owned = ledger.current.as_mut().unwrap();
            std::fs::remove_file(&owned.state.output_path).unwrap();
            owned.state.encoder_complete.store(false, Ordering::SeqCst);
            assert_eq!(
                ledger.finish_current(&f.blobs).await,
                Err(ProtocolError::CleanupFailed)
            );
            assert_eq!(
                ledger.discard_current().await,
                Err(ProtocolError::CleanupFailed)
            );
            assert!(ledger.current.as_ref().unwrap().reservation.is_some());
            assert!(ledger.current.as_ref().unwrap().directory.path.exists());
        }
        assert_eq!(
            actions
                .settle_terminal_recording(&f.page.client, &terminal_recording_proof(&f).unwrap().0)
                .await,
            Err(ProtocolError::CleanupFailed)
        );
        assert!(actions.recording.lock().await.current.is_some());
    }
    #[tokio::test]
    async fn terminal_recording_refuses_live_or_different_native_connection() {
        let f = fixture("normal").await;
        let other = fixture("normal").await;
        let actions = ClientActions::default();
        seed_terminal_recording(&actions, &f).await;
        assert!(matches!(
            terminal_recording_proof(&f),
            Err(ProtocolError::StaleScope)
        ));
        disconnect_recording_fixture(&other).await;
        // Foreign proof is rejected by the scope-authority layer before any
        // recording cleanup. A valid proof for another attachment below is
        // instead a recording cleanup ownership failure.
        assert_eq!(
            actions
                .settle_terminal_recording(
                    &f.page.client,
                    &terminal_recording_proof(&other).unwrap().0
                )
                .await,
            Err(ProtocolError::StaleScope)
        );
        assert_eq!(
            actions
                .settle_terminal_recording(
                    &other.page.client,
                    &terminal_recording_proof(&other).unwrap().0
                )
                .await,
            Err(ProtocolError::CleanupFailed)
        );
        let ledger = actions.recording.lock().await;
        assert!(ledger
            .current
            .as_ref()
            .unwrap()
            .state
            .capture_task
            .is_some());
        assert!(f.log.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn terminal_before_and_after_stop_retains_file_and_does_not_forge_detach_ack() {
        for after_stop in [false, true] {
            let f = fixture("normal").await;
            let actions = ClientActions::default();
            seed_terminal_recording(&actions, &f).await;
            disconnect_recording_fixture(&f).await;
            if after_stop {
                let mut ledger = actions.recording.lock().await;
                ledger.finish_current(&f.blobs).await.unwrap();
                assert!(ledger.cleanup_failed);
                assert_eq!(ledger.finished.len(), 1);
            }
            actions
                .settle_terminal_recording(&f.page.client, &terminal_recording_proof(&f).unwrap().0)
                .await
                .unwrap();
            let ledger = actions.recording.lock().await;
            let owned = ledger
                .current
                .as_ref()
                .unwrap_or_else(|| &ledger.finished[0]);
            assert!(owned.directory.path.exists());
            assert!(owned.reservation.is_some());
            assert!(owned.state.capture_task.is_none());
            assert!(owned.cleanup_complete.load(Ordering::SeqCst));
            let attachment = owned.attachment.as_ref().unwrap();
            assert!(!attachment.detached.load(Ordering::SeqCst));
            assert!(attachment.acknowledged_cleanup.is_empty());
            assert!(f.log.lock().unwrap().is_empty());
        }
    }
    #[tokio::test]
    async fn terminal_recording_cancel_retains_capture_attach_read_and_encoder_proof() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        seed_terminal_recording(&actions, &f).await;
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let (attach_release, attach_wait) = tokio::sync::oneshot::channel::<()>();
        let (read_release, read_wait) = tokio::sync::oneshot::channel::<()>();
        {
            let mut ledger = actions.recording.lock().await;
            let owned = ledger.current.as_mut().unwrap();
            recording::stop_recording_task(&mut owned.state)
                .await
                .unwrap();
            owned.state.encoder_complete.store(false, Ordering::SeqCst);
            owned.state.capture_task = Some(tokio::spawn(async move {
                let _ = wait.await;
                Ok(())
            }));
            owned.attachment.as_mut().unwrap().startup = Some(tokio::spawn(async move {
                let _ = attach_wait.await;
                Err("terminal attach".into())
            }));
            owned.read_job = Some(tokio::spawn(async move {
                let _ = read_wait.await;
                Ok(vec![0x1a, 0x45, 0xdf, 0xa3])
            }));
        }
        disconnect_recording_fixture(&f).await;
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            actions.settle_terminal_recording(
                &f.page.client,
                &terminal_recording_proof(&f).unwrap().0
            )
        )
        .await
        .is_err());
        {
            let ledger = actions.recording.lock().await;
            let owned = ledger.current.as_ref().unwrap();
            assert!(owned.state.capture_task.is_some());
            assert!(owned.attachment.as_ref().unwrap().startup.is_some());
            assert!(owned.read_job.is_some());
            assert!(owned.directory.path.exists());
        }
        release.send(()).unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            actions.settle_terminal_recording(
                &f.page.client,
                &terminal_recording_proof(&f).unwrap().0
            )
        )
        .await
        .is_err());
        attach_release.send(()).unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            actions.settle_terminal_recording(
                &f.page.client,
                &terminal_recording_proof(&f).unwrap().0
            )
        )
        .await
        .is_err());
        assert!(actions
            .recording
            .lock()
            .await
            .current
            .as_ref()
            .unwrap()
            .read_job
            .is_some());
        read_release.send(()).unwrap();
        // A valid file and joined synthetic task cannot substitute for child wait.
        assert_eq!(
            actions
                .settle_terminal_recording(&f.page.client, &terminal_recording_proof(&f).unwrap().0)
                .await,
            Err(ProtocolError::CleanupFailed)
        );
        let ledger = actions.recording.lock().await;
        let owned = ledger.current.as_ref().unwrap();
        assert!(owned.bytes.is_some());
        assert!(!owned.cleanup_complete.load(Ordering::SeqCst));
        assert!(owned.reservation.is_some());
    }
    #[tokio::test]
    async fn recorder_cancelled_attach_retains_ack_and_detaches_exact_session() {
        let f = fixture("normal").await;
        enroll_recording_fixture(&f.page).await;
        let reservation = f
            .page
            .targets
            .reserve_auxiliary_attachment("scope", "target", "page")
            .unwrap();
        let (release, wait) = tokio::sync::oneshot::channel();
        let mut attachment = RecordingAttachment {
            client: f.page.client.clone(),
            reservation,
            startup: Some(tokio::spawn(async move {
                let _ = wait.await;
                Ok("recorder".to_owned())
            })),
            session: None,
            detached: Arc::new(AtomicBool::new(false)),
            acknowledged_cleanup: HashSet::new(),
            terminal_complete: false,
            cleanup_failed: false,
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(10), attachment.settle())
                .await
                .is_err()
        );
        assert!(attachment.startup.is_some());
        release.send(()).unwrap();
        assert!(attachment.settle().await);
        assert!(attachment.startup.is_none());
        let calls = f.log.lock().unwrap().clone();
        let detaches = calls
            .iter()
            .filter(|v| v["method"] == "Target.detachFromTarget")
            .collect::<Vec<_>>();
        assert_eq!(detaches.len(), 1);
        assert_eq!(detaches[0]["params"]["sessionId"], "recorder");
        assert!(f.page.targets.protected_read_barrier().is_err()); // quarantine remains
    }
    #[tokio::test]
    async fn recorder_unknown_attach_is_not_cleaned_by_empty_candidate_list() {
        let f = fixture("normal").await;
        enroll_recording_fixture(&f.page).await;
        let reservation = f
            .page
            .targets
            .reserve_auxiliary_attachment("scope", "target", "page")
            .unwrap();
        let mut attachment = RecordingAttachment {
            client: f.page.client.clone(),
            reservation,
            startup: Some(tokio::spawn(async {
                Err("synthetic unknown ACK".to_owned())
            })),
            session: None,
            detached: Arc::new(AtomicBool::new(false)),
            acknowledged_cleanup: HashSet::new(),
            terminal_complete: false,
            cleanup_failed: false,
        };
        assert!(!attachment.settle().await);
        assert!(attachment.startup.is_none());
        assert!(!attachment.settle().await); // terminal handle was consumed, not polled twice
        assert!(f.log.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn recorder_settlement_drains_owned_candidates_before_completing_exact_ack() {
        let f = fixture("normal").await;
        enroll_recording_fixture(&f.page).await;
        let mut reservation = f
            .page
            .targets
            .reserve_auxiliary_attachment("scope", "target", "page")
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            f.page
                .targets
                .classify_auxiliary_attachment("target", "uncertain")
        )
        .await
        .is_err());
        reservation.quarantine();
        assert!(reservation.claim("recorder").is_err());
        let mut attachment = RecordingAttachment {
            client: f.page.client.clone(),
            reservation,
            startup: None,
            session: Some("recorder".into()),
            detached: Arc::new(AtomicBool::new(true)),
            acknowledged_cleanup: HashSet::new(),
            terminal_complete: false,
            cleanup_failed: false,
        };
        assert!(attachment.settle().await);
        assert!(attachment.settle().await);
        let calls = f.log.lock().unwrap().clone();
        let detaches = calls
            .iter()
            .filter(|v| v["method"] == "Target.detachFromTarget")
            .collect::<Vec<_>>();
        assert_eq!(detaches.len(), 1);
        assert_eq!(detaches[0]["params"]["sessionId"], "uncertain");
        assert!(f.page.targets.protected_read_barrier().is_err());
    }
    #[tokio::test]
    async fn recorder_detach_ack_settles_reservation_without_touching_primary() {
        let f = fixture("normal").await;
        enroll_recording_fixture(&f.page).await;
        let mut reservation = f
            .page
            .targets
            .reserve_auxiliary_attachment("scope", "target", "page")
            .unwrap();
        reservation.claim("recorder").unwrap();
        let mut attachment = RecordingAttachment {
            client: f.page.client.clone(),
            reservation,
            startup: None,
            session: Some("recorder".into()),
            detached: Arc::new(AtomicBool::new(true)),
            acknowledged_cleanup: HashSet::new(),
            terminal_complete: false,
            cleanup_failed: false,
        };
        assert!(attachment.settle().await);
        assert!(f.log.lock().unwrap().is_empty());
        assert!(f.page.targets.protected_read_barrier().is_ok());
    }
    #[tokio::test]
    async fn recording_cancelled_close_retains_join_and_artifact_ownership() {
        let f = fixture("normal").await;
        let actions = ClientActions::default();
        seed_recording(&actions, &f, 1, Some(&[0x1a, 0x45, 0xdf, 0xa3]), false).await;
        let (release, wait) = tokio::sync::oneshot::channel();
        actions
            .recording
            .lock()
            .await
            .current
            .as_mut()
            .unwrap()
            .state
            .capture_task = Some(tokio::spawn(async move {
            let _ = wait.await;
            Ok(())
        }));
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            actions.recording_page_closing("scope", &f.blobs)
        )
        .await
        .is_err());
        assert!(actions
            .recording
            .lock()
            .await
            .current
            .as_ref()
            .unwrap()
            .state
            .capture_task
            .is_some());
        release.send(()).unwrap();
        actions
            .recording_page_closing("scope", &f.blobs)
            .await
            .unwrap();
        assert_eq!(actions.recording.lock().await.finished.len(), 1);
        actions.abandon_recording().await.unwrap();
    }
    #[tokio::test]
    async fn immediate_click_replacement_preserves_original_success_semantics() {
        let f = fixture("check-immediate-replacement").await;
        let node = Resolved {
            object: "exact-node".into(),
            session: "page".into(),
            binding: f.refs.get("e1").unwrap().exact_binding.clone().unwrap(),
        };
        let d = Dispatch::default();
        set_checked(&f.context(), &d, &node, true).await.unwrap();
        assert!(d.sent.load(Ordering::SeqCst));
        assert!(!d.checked_replaced.load(Ordering::SeqCst));
    }
    #[test]
    fn checked_poll_admission_reserves_completed_read_latency_without_extending_deadline() {
        let now = Instant::now();
        let deadline = now + Duration::from_millis(35);
        assert!(!checked_poll_fits(
            now,
            deadline,
            Duration::from_millis(20),
            Duration::from_millis(25)
        ));
        assert!(checked_poll_fits(
            now,
            deadline,
            Duration::from_millis(20),
            Duration::from_millis(10)
        ));
        assert!(!checked_poll_fits(
            deadline,
            deadline,
            Duration::ZERO,
            Duration::ZERO
        ));
        let d = Dispatch::default();
        d.mark();
        let failure = d.failure(ProtocolError::DeadlineExceeded);
        assert_eq!(failure.effects, Effects::Unknown);
        assert_eq!(failure.reason, None);
        assert_eq!(checked_unchanged(&d), Err(ProtocolError::NotActionable));
        assert_eq!(
            d.failure(ProtocolError::NotActionable).effects,
            Effects::Completed
        );
    }
    #[tokio::test]
    async fn checked_postconditions_distinguish_replacement_from_unchanged() {
        for (mode, reason) in [
            ("check-replaced", ActionReason::ControlReplacedAfterClick),
            ("check-unchanged", ActionReason::CheckedStateUnchanged),
        ] {
            let mut f = fixture(mode).await;
            f.op.deadline = Instant::now() + Duration::from_millis(350);
            let node = Resolved {
                object: "exact-node".into(),
                session: "page".into(),
                binding: f.refs.get("e1").unwrap().exact_binding.clone().unwrap(),
            };
            let d = Dispatch::default();
            let error = set_checked(&f.context(), &d, &node, true)
                .await
                .unwrap_err();
            let failure = d.failure(error);
            assert_eq!(failure.error, ProtocolError::NotActionable);
            assert_eq!(failure.reason, Some(reason));
            assert_eq!(failure.effects, Effects::Completed);
            d.cleanup.store(true, Ordering::SeqCst);
            assert_eq!(
                d.failure(ProtocolError::NotActionable).effects,
                Effects::Unknown
            );
            assert_eq!(
                f.inputs()
                    .iter()
                    .filter(|v| v["params"]["type"] == "mouseReleased")
                    .count(),
                1
            );
        }
    }
    #[tokio::test]
    async fn checked_inflight_postcondition_timeout_keeps_unknown_outcome() {
        let mut f = fixture("check-read-stalled").await;
        f.op.deadline = Instant::now() + Duration::from_millis(350);
        let node = Resolved {
            object: "exact-node".into(),
            session: "page".into(),
            binding: f.refs.get("e1").unwrap().exact_binding.clone().unwrap(),
        };
        let d = Dispatch::default();
        let error = set_checked(&f.context(), &d, &node, true)
            .await
            .unwrap_err();
        assert_eq!(error, ProtocolError::DeadlineExceeded);
        let failure = d.failure(error);
        assert_eq!(failure.effects, Effects::Unknown);
        assert_eq!(failure.reason, None);
        assert_eq!(
            f.inputs()
                .iter()
                .filter(|request| request["params"]["type"] == "mouseReleased")
                .count(),
            1
        );
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
            let geometry = action_fixture_geometry(&page,&operation).await?;
            for (selector, action) in [
                ("#text", json!({"kind":"fill","value":"native synthetic","sensitive":false})),
                ("#pick", json!({"kind":"selectOption","value":{"label":"Beta"}})),
                ("#check", json!({"kind":"check"})),
                ("#button", json!({"kind":"doubleTap"})),
            ] {
                actions.execute(ActionContext {page:&page,operation:&operation,page_state:&state,refs:&refs,revision:1,iframe_sessions:&frames,blobs:&blobs,geometry:&geometry},"browser.perform",&json!({"identityScope":page.identity_scope,"ref":{"id":ids[selector],"revision":"1"},"action":action})).await.map_err(|error|format!("action failed: {:?}",error.error))?;
            }
            let value = evaluate_on(&browser.client,&session,"[document.querySelector('#text').value,document.querySelector('#pick').value,document.querySelector('#check').checked,document.querySelector('#button').dataset.clicked]").await?;
            assert_eq!(value,json!(["native synthetic","b",true,"2"]));
            actions.execute(ActionContext {page:&page,operation:&operation,page_state:&state,refs:&refs,revision:1,iframe_sessions:&frames,blobs:&blobs,geometry:&geometry},"browser.perform",&json!({"identityScope":page.identity_scope,"ref":{"id":document_ref,"revision":"1"},"action":{"kind":"scrollIntoView"}})).await.map_err(|error|format!("document action failed: {:?}",error.error))?;
            evaluate_on(&browser.client,&session,"document.querySelector('#button').remove(); true").await?;
            assert!(actions.execute(ActionContext {page:&page,operation:&operation,page_state:&state,refs:&refs,revision:1,iframe_sessions:&frames,blobs:&blobs,geometry:&geometry},"browser.perform",&json!({"identityScope":page.identity_scope,"ref":{"id":ids["#button"],"revision":"1"},"action":{"kind":"tap"}})).await.is_err());
            actions.cleanup().await.map_err(|_|"cleanup failed")?;
            Ok::<(),String>(())
        }.await;
        browser.close().await.unwrap();
        result.unwrap();
    }
    #[tokio::test]
    #[ignore = "requires hosted Chromium; transformed nested-frame input and ancestor occlusion"]
    async fn chromium_nested_frame_action_projects_input_and_checks_exact_ancestor_occlusion() {
        use super::super::browser::{evaluate_on, BrowserManager};
        let mut browser = BrowserManager::launch(Default::default(), None)
            .await
            .unwrap();
        let result=async {
            let session=browser.active_session_id()?.to_owned();
            evaluate_on(&browser.client,&session,r#"(async()=>{
              document.body.style.margin='0';const outer=document.createElement('iframe');
              outer.id='outer';outer.style.cssText='position:absolute;left:100px;top:80px;width:300px;height:200px;border:5px solid black;padding:3px;transform:scale(1.25);transform-origin:0 0';
              const loaded=new Promise(r=>outer.onload=r);outer.srcdoc='<body style="margin:0"></body>';document.body.append(outer);await loaded;
              const inner=outer.contentDocument.createElement('iframe');inner.id='inner';inner.style.cssText='position:absolute;left:20px;top:30px;width:160px;height:100px;border:4px solid black;transform:scale(.75);transform-origin:0 0';
              const ready=new Promise(r=>inner.onload=r);inner.srcdoc='<body style="margin:0"><button style="position:absolute;left:12px;top:15px;width:80px;height:30px" onclick="this.dataset.clicks=Number(this.dataset.clicks||0)+1">Nested</button></body>';
              outer.contentDocument.body.append(inner);await ready;return true;
            })()"#).await?;
            let gate=Arc::new(ExecutionGate::default());
            let page=BrowserExecutionLease{client:browser.client.clone(),page_session_id:session.clone(),target_id:browser.active_target_id()?.into(),identity_scope:"nested-actions".into(),permit:gate.enter(false).unwrap(),targets:ClientTargets::new("fixture".into(),"nested-actions".into())};
            let (_cancel,cancellation)=tokio::sync::watch::channel(CancelSignal::None);
            let mut operation=OperationLease{is_callback:false,generation:1,sequence:1,deadline:Instant::now()+Duration::from_secs(20),cancellation};
            let inventory=super::super::client_observation::enumerate_frames(&page.client,&session,&HashMap::new(),&operation).await.map_err(|_|"Frame inventory failed")?;
            assert_eq!(inventory.len(),3);
            let frame=inventory.iter().find(|f|f.parent_frame_id.as_ref().is_some_and(|parent|inventory.iter().any(|p|p.binding.frame==*parent && p.parent_frame_id.is_some()))).ok_or("Nested frame missing")?;
            let world=page.client.send_command("Page.createIsolatedWorld",Some(json!({"frameId":frame.binding.frame,"worldName":"native-action-fixture"})),Some(&frame.binding.session)).await?;
            let object=page.client.send_command("Runtime.evaluate",Some(json!({"contextId":world["executionContextId"],"expression":"document.querySelector('button')"})),Some(&frame.binding.session)).await?;
            let object_id=object["result"]["objectId"].as_str().ok_or("Button handle missing")?;
            let described=page.client.send_command("DOM.describeNode",Some(json!({"objectId":object_id})),Some(&frame.binding.session)).await?;
            page.client.send_command("Runtime.releaseObject",Some(json!({"objectId":object_id})),Some(&frame.binding.session)).await?;
            let backend=described["node"]["backendNodeId"].as_i64().ok_or("Button backend missing")?;
            let mut refs=RefMap::new();let mut binding=frame.binding.clone();binding.actionable=true;
            let id=format!("@{}",refs.bind_exact(backend,"button","Nested",binding));
            let geometry=GeometrySnapshot::capture(&page.client,&session,&inventory,&operation).await.map_err(|_|"Geometry proof failed")?;
            let state=ClientPageState::new(page.identity_scope.clone(),"fixture".into());let blobs=BlobStore::new(BlobLimits::default()).unwrap();
            blobs.activate_scope(BlobScope{generation:1,identity_scope:page.identity_scope.clone()}).unwrap();
            let sessions=HashMap::new();let actions=ClientActions::default();
            let args=json!({"identityScope":page.identity_scope,"ref":{"id":id,"revision":"1"},"action":{"kind":"tap"}});
            actions.execute(ActionContext{page:&page,operation:&operation,page_state:&state,refs:&refs,revision:1,iframe_sessions:&sessions,blobs:&blobs,geometry:&geometry},"browser.perform",&args).await.map_err(|e|format!("Nested action failed: {:?}",e.error))?;
            assert_eq!(evaluate_on(&page.client,&session,"document.querySelector('#outer').contentDocument.querySelector('#inner').contentDocument.querySelector('button').dataset.clicks").await?,json!("1"));
            evaluate_on(&page.client,&session,"const cover=document.createElement('div');cover.style.cssText='position:fixed;inset:0;z-index:999;background:red';document.body.append(cover);true").await?;
            operation.deadline=Instant::now()+Duration::from_secs(2);
            let error=actions.execute(ActionContext{page:&page,operation:&operation,page_state:&state,refs:&refs,revision:1,iframe_sessions:&sessions,blobs:&blobs,geometry:&geometry},"browser.perform",&args).await.unwrap_err();
            assert_eq!(error.error,ProtocolError::NotActionable);assert_eq!(error.reason,Some(ActionReason::InterceptedPointer));
            assert_eq!(evaluate_on(&page.client,&session,"document.querySelector('#outer').contentDocument.querySelector('#inner').contentDocument.querySelector('button').dataset.clicks").await?,json!("1"));
            actions.cleanup().await.map_err(|_|"Action cleanup failed")?;Ok::<(),String>(())
        }.await;
        browser.close().await.unwrap();
        result.unwrap();
    }
    async fn action_fixture_geometry(
        page: &BrowserExecutionLease,
        operation: &OperationLease,
    ) -> Result<GeometrySnapshot, String> {
        let frames = super::super::client_observation::enumerate_frames(
            &page.client,
            &page.page_session_id,
            &HashMap::new(),
            operation,
        )
        .await
        .map_err(|_| "Fixture frame inventory failed")?;
        GeometrySnapshot::capture(&page.client, &page.page_session_id, &frames, operation)
            .await
            .map_err(|_| "Fixture geometry failed".to_owned())
    }
    #[tokio::test]
    #[ignore = "requires real Chromium and ffmpeg/ffprobe in hosted CI; no mock encoding"]
    async fn chromium_recording_attempt_segments_first_frame_size_and_scope_rotation() {
        use super::super::browser::{evaluate_on, BrowserManager};
        async fn page_lease(browser: &BrowserManager, identity: &str) -> BrowserExecutionLease {
            let gate = Arc::new(ExecutionGate::default());
            let page = BrowserExecutionLease {
                client: browser.client.clone(),
                page_session_id: browser.active_session_id().unwrap().into(),
                target_id: browser.active_target_id().unwrap().into(),
                identity_scope: identity.into(),
                permit: gate.enter(false).unwrap(),
                targets: ClientTargets::new(format!("context-{identity}"), identity.into()),
            };
            enroll_recording_fixture(&page).await;
            page
        }
        let mut first = BrowserManager::launch(Default::default(), None)
            .await
            .unwrap();
        let mut second = BrowserManager::launch(Default::default(), None)
            .await
            .unwrap();
        let actions = ClientActions::default();
        let result = async {
            let first_page = page_lease(&first, "record-first").await;
            let second_page = page_lease(&second, "record-second").await;
            for page in [&first_page, &second_page] {
                evaluate_on(&page.client, &page.page_session_id, "document.documentElement.style.background='rgb(20,40,80)'; document.body.style.margin='0'; document.body.innerHTML='<div style=\"width:100vw;height:100vh;background:rgb(20,40,80)\"></div>'; true").await?;
            }
            let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let operation = OperationLease { is_callback:false, generation:1, sequence:1, deadline:Instant::now()+Duration::from_secs(45), cancellation };
            let refs = RefMap::new(); let frames = HashMap::new();
            let blobs = BlobStore::new(BlobLimits::default()).unwrap();
            let first_state = ClientPageState::new(first_page.identity_scope.clone(), "context-first".into());
            let second_state = ClientPageState::new(second_page.identity_scope.clone(), "context-second".into());
            let first_scope = BlobScope {generation:1,identity_scope:first_page.identity_scope.clone()};
            let second_scope = BlobScope {generation:1,identity_scope:second_page.identity_scope.clone()};
            blobs.activate_scope(first_scope.clone()).unwrap();
            let first_geometry=action_fixture_geometry(&first_page,&operation).await?;
            let second_geometry=action_fixture_geometry(&second_page,&operation).await?;
            let first_context = || ActionContext {page:&first_page,operation:&operation,page_state:&first_state,refs:&refs,revision:1,iframe_sessions:&frames,blobs:&blobs,geometry:&first_geometry};
            actions.execute(first_context(), "recording.start", &json!({"identityScope":first_page.identity_scope,"size":{"width":320,"height":200},"quality":70})).await.map_err(|e|format!("record start {:?}",e.error))?;
            actions.recording_page_closing(&first_page.identity_scope, &blobs).await.map_err(|e|format!("record close {e:?}"))?;
            blobs.revoke_scope(&first_scope).unwrap();
            blobs.activate_scope(second_scope.clone()).unwrap();
            let second_context = || ActionContext {page:&second_page,operation:&operation,page_state:&second_state,refs:&refs,revision:1,iframe_sessions:&frames,blobs:&blobs,geometry:&second_geometry};
            actions.recording_page_opened(second_context()).await.map_err(|e|format!("record reopen {:?}",e.error))?;
            let output = actions.execute(second_context(), "recording.stop", &json!({"identityScope":second_page.identity_scope})).await.map_err(|e|format!("record stop {:?}",e.error))?;
            let segments = output["segments"].as_array().ok_or("missing segments")?;
            assert_eq!(segments.len(), 2);
            let first_instant = chrono::DateTime::parse_from_rfc3339(segments[0]["startedAt"].as_str().unwrap()).unwrap();
            let second_instant = chrono::DateTime::parse_from_rfc3339(segments[1]["startedAt"].as_str().unwrap()).unwrap();
            assert!(first_instant <= second_instant);
            let directory = OwnedDirectory::create().map_err(|_|"test directory")?;
            for (index, segment) in segments.iter().enumerate() {
                assert_eq!(segment["identityScope"], second_page.identity_scope);
                let handle = segment["handle"].as_str().unwrap();
                let size = segment["size"].as_u64().unwrap() as usize;
                let mut bytes = Vec::new();
                while bytes.len() < size { bytes.extend(blobs.read(&second_scope, handle, bytes.len(), (size-bytes.len()).min(super::super::client_blobs::MAX_CHUNK_BYTES)).unwrap()); }
                blobs.release(&second_scope, handle).unwrap();
                let video = directory.path.join(format!("segment-{index}.webm"));
                let image_path = directory.path.join(format!("segment-{index}.png"));
                tokio::fs::write(&video, bytes).await.map_err(|_|"test video write")?;
                let probe = tokio::process::Command::new("ffprobe").args(["-v","error","-select_streams","v:0","-show_entries","stream=codec_name,width,height","-of","json"]).arg(&video).output().await.map_err(|_|"ffprobe required")?;
                assert!(probe.status.success());
                let metadata: Value = serde_json::from_slice(&probe.stdout).unwrap();
                assert_eq!(metadata["streams"][0]["codec_name"], "vp8");
                assert_eq!(metadata["streams"][0]["width"], 320);
                assert_eq!(metadata["streams"][0]["height"], 200);
                let decoded = tokio::process::Command::new("ffmpeg").args(["-v","error","-i"]).arg(&video).args(["-frames:v","1"]).arg(&image_path).output().await.map_err(|_|"ffmpeg required")?;
                assert!(decoded.status.success());
                let image = image::open(&image_path).unwrap().to_rgb8();
                let pixel = image.get_pixel(160,100).0;
                for (actual, expected) in pixel.into_iter().zip([20u8,40,80]) { assert!(actual.abs_diff(expected)<20, "first frame must not be blank"); }
            }
            directory.close().map_err(|_|"test artifact cleanup")?;
            assert_eq!(actions.execute(second_context(), "recording.stop", &json!({"identityScope":second_page.identity_scope})).await.map_err(|_|"second collection")?["segments"], json!([]));
            Ok::<(),String>(())
        }.await;
        let cleanup = actions.cleanup().await;
        let first_closed = first.close().await;
        let second_closed = second.close().await;
        cleanup.unwrap();
        first_closed.unwrap();
        second_closed.unwrap();
        result.unwrap();
    }
}
