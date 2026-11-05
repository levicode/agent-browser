//! Native-only protected pixel transaction. Raw pixels stay inside this module;
//! cleanup integrity is part of the outcome, even for optional screenshots.
use super::client_browser::BrowserExecutionLease;
use super::client_debt::{self, CommandCategory};
use super::client_geometry::{Bounds, GeometryError, GeometrySnapshot, Polygon, Viewport};
use super::client_observation::ObservationFrame;
use super::client_protected_read::{ProtectedReadJournal, ProtectedReadReason};
use super::client_session::{CancelSignal, OperationLease};
use base64::Engine;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[cfg(test)]
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Cursor;

const MAX_PIXELS: u64 = 16_777_216;
// Encoded PNG payload ceiling, not a total working-memory budget. Raster and
// transport allocations retain their independent existing limits.
pub(super) const MAX_PNG_BYTES: usize = 32 * 1024 * 1024;
const MAX_DOM_NODES: usize = 100_000;
// Published metadata is bounded independently of the DOM budget. A page may
// mount a plugin region per element, and the protocol result must stay inside
// the existing frame budget, so the exact count is reported while only the
// first regions keep their bounds.
const MAX_UNINSPECTED_REGIONS: usize = 256;

#[path = "client_capture_metadata.rs"]
mod metadata;
pub use metadata::CaptureReason;
pub(crate) use metadata::{CaptureAttemptFailure, CapturePhase};

impl CapturePhase {
    fn failure(self, reason: CaptureReason, operation: &OperationLease) -> CaptureAttemptFailure {
        let failure = CaptureAttemptFailure {
            phase: self,
            reason,
        };
        // Record the original refusal before optional observation maps or
        // suppresses it. Closed facts only; diagnostics never affect authority.
        super::client_settlement_trace::protected_capture_failure(operation, failure);
        failure
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureFailure {
    pub reason: CaptureReason,
    pub identity_scope: String,
    /// True means the captured OLD scope needs quarantine, never whichever
    /// scope happens to be current when this asynchronous result arrives.
    pub cleanup_integrity_lost: bool,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureRequest {
    pub secure_field_selector: String,
}
/// Built by the native owner after a complete frame inventory. The caller must
/// retain the returned task until cleanup, including when its RPC is cancelled.
pub struct CaptureContext {
    pub page: BrowserExecutionLease,
    pub frames: Vec<ObservationFrame>,
    /// `<object>`/`<embed>` plugin subtree roots from the same verified
    /// inventory. They are opaque author content: not projected, not masked,
    /// and not evidence of a missing frame.
    pub opaque_frames: HashSet<String>,
    pub inventory_complete: bool,
}
/// One unmasked capture region. Its plugin document is opaque author content:
/// the pixels are published as the browser painted them, and no secure-field
/// proof covers them. A caller that requires a fully inspected capture must
/// treat the presence of these regions as a limitation.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct UninspectedRegion {
    /// Closed region class. Only plugin regions are published today.
    pub kind: &'static str,
    /// CSS pixels relative to the captured viewport origin, clipped to it.
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}
impl UninspectedRegion {
    fn plugin(bounds: Bounds) -> Self {
        Self {
            kind: "plugin",
            x: bounds.x,
            y: bounds.y,
            width: bounds.width,
            height: bounds.height,
        }
    }
}
pub struct MaskedCapture {
    pub png: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub scale: f64,
    pub masked_region_count: usize,
    /// Exact number of visible plugin regions in the captured viewport. It may
    /// exceed `uninspected.len()` when the published bounds are bounded.
    pub uninspected_region_count: usize,
    /// The published regions, in capture order, at most
    /// `MAX_UNINSPECTED_REGIONS`.
    pub uninspected: Vec<UninspectedRegion>,
    pub identity_scope: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FrameMasks {
    count: usize,
    secure: Vec<usize>,
    masks: Vec<usize>,
    /// A visible plugin region whose pixels cannot be bounded: it sits inside
    /// protected content, or an ancestor filter paints outside its border box.
    /// The capture stays refused instead of publishing unbounded pixels.
    unprovable_plugin: bool,
    /// Indices of visible plugin regions whose exact owner border quad the
    /// capture publishes as uninspected.
    uninspected: Vec<usize>,
    unsafe_geometry: bool,
}
#[derive(Clone, PartialEq)]
struct MaskProof {
    count: usize,
    secure_nodes: Vec<(String, i64)>,
    masks: Vec<Polygon>,
    /// Visible plugin regions that still paint inside the capture viewport, in
    /// viewport CSS pixels. They are never masked and never enter the raster
    /// mask pass; they are published as uninspected metadata.
    uninspected: Vec<Bounds>,
    uninspected_total: usize,
}

fn check(context: &CaptureContext, operation: &OperationLease) -> Result<(), CaptureReason> {
    context
        .page
        .permit
        .check()
        .map_err(|_| CaptureReason::StaleScope)?;
    if *operation.cancellation.borrow() != CancelSignal::None {
        return Err(CaptureReason::Cancelled);
    }
    if std::time::Instant::now() >= operation.deadline {
        return Err(CaptureReason::Deadline);
    }
    if super::client_observation::capture_superseded() {
        return Err(CaptureReason::Superseded);
    }
    Ok(())
}
async fn command(
    context: &CaptureContext,
    operation: &OperationLease,
    session: &str,
    method: &str,
    args: Value,
) -> Result<Value, CaptureReason> {
    let group = args["objectGroup"]
        .as_str()
        .filter(|group| {
            ["capture-source", "capture-owner", "capture"]
                .iter()
                .any(|prefix| group.starts_with(&format!("{prefix}-{}-", operation.sequence)))
        })
        .map(str::to_owned);
    let mutation = method == "Animation.setPlaybackRate"
        || args["expression"].as_str() == Some(SOURCE_MASK_HOLDER)
        || args["functionDeclaration"].as_str()
            == Some("function(selector,...nodes){return this.install(selector,nodes)}");
    let category = if super::client_observation::produces_remote_objects(method) {
        CommandCategory::ApplicationObject
    } else {
        CommandCategory::ApplicationRead
    };
    client_debt::command_scope(category, mutation, async {
        if let Some(group) = group {
            client_debt::native_object_group(
                &group,
                command_inner(context, operation, session, method, args),
            )
            .await
        } else {
            command_inner(context, operation, session, method, args).await
        }
    })
    .await
}
async fn command_inner(
    context: &CaptureContext,
    operation: &OperationLease,
    session: &str,
    method: &str,
    args: Value,
) -> Result<Value, CaptureReason> {
    check(context, operation)?;
    if !super::client_observation::capture_retirement_active() {
        let mut cancellation = operation.cancellation.clone();
        return tokio::select! {
            result = context.page.client.send_command(method, Some(args), Some(session)) => {
                if !super::client_observation::produces_remote_objects(method) { check(context, operation)?; }
                result.map_err(|_| CaptureReason::BrowserFailure)
            }
            _ = cancellation.changed() => Err(CaptureReason::Cancelled),
            _ = tokio::time::sleep_until(operation.deadline.into()) => Err(CaptureReason::Deadline),
        };
    }
    let result = super::client_observation::retained_read_command(
        &context.page.client,
        session,
        method,
        args,
        operation,
    )
    .await
    .map_err(|error| match error {
        super::client_observation::ObservationError::Cancelled => CaptureReason::Cancelled,
        super::client_observation::ObservationError::DeadlineExceeded => CaptureReason::Deadline,
        super::client_observation::ObservationError::Superseded => CaptureReason::Superseded,
        super::client_observation::ObservationError::CleanupFailed { .. } => {
            CaptureReason::CleanupFailed
        }
        _ => CaptureReason::BrowserFailure,
    });
    if result.is_ok() && !super::client_observation::produces_remote_objects(method) {
        check(context, operation)?;
    }
    result
}
/// Spawn supervision before the first page mutation. Dropping the RPC receiver
/// does not drop this task; the owner joins it before releasing its scope.
pub fn start_capture(
    context: CaptureContext,
    request: CaptureRequest,
    operation: OperationLease,
) -> tokio::task::JoinHandle<Result<MaskedCapture, CaptureFailure>> {
    let operation_journal = client_debt::OperationJournalHandle::current();
    tokio::spawn(async move {
        if let Some(journal) = operation_journal {
            journal
                .scope(capture_transaction(context, request, operation))
                .await
        } else {
            capture_transaction(context, request, operation).await
        }
    })
}

async fn capture_transaction(
    context: CaptureContext,
    request: CaptureRequest,
    operation: OperationLease,
) -> Result<MaskedCapture, CaptureFailure> {
    let mut journal =
        ProtectedReadJournal::begin(&context.page, &operation).map_err(|failure| {
            CaptureFailure {
                reason: protected_reason(failure.reason),
                identity_scope: failure.identity_scope,
                cleanup_integrity_lost: failure.cleanup_integrity_lost,
            }
        })?;
    let mut geometry = None;
    let result = async {
        journal
            .stabilize_animations()
            .await
            .map_err(protected_reason)?;
        geometry = Some(
            GeometrySnapshot::capture_excluding_opaque(
                &context.page.client,
                &context.page.page_session_id,
                &context.frames,
                &context.opaque_frames,
                &operation,
            )
            .await
            .map_err(geometry_reason)?,
        );
        capture_under_journal(
            &context,
            &request,
            &operation,
            &mut journal,
            geometry.as_ref().ok_or(CaptureReason::UnsafeGeometry)?,
        )
        .await
        .map_err(|failure| failure.reason)
    }
    .await;
    let integrity = journal.check().map_err(protected_reason);
    if let Err(failure) = journal.restore().await {
        return Err(CaptureFailure {
            reason: result
                .as_ref()
                .err()
                .copied()
                .unwrap_or_else(|| protected_reason(failure.reason)),
            identity_scope: failure.identity_scope,
            cleanup_integrity_lost: failure.cleanup_integrity_lost,
        });
    }
    let geometry_integrity = match &geometry {
        Some(proof) => proof
            .revalidate(&context.page.client, &operation)
            .await
            .map_err(geometry_reason),
        None => Ok(()),
    };
    let cleanup_integrity_lost = result.as_ref().err() == Some(&CaptureReason::CleanupFailed)
        || geometry_integrity.as_ref().err() == Some(&CaptureReason::CleanupFailed);
    if cleanup_integrity_lost {
        context.page.targets.seal();
    }
    result
        .and_then(|pixels| {
            integrity?;
            geometry_integrity?;
            journal.check().map_err(protected_reason)?;
            Ok(pixels)
        })
        .map_err(|reason| CaptureFailure {
            reason,
            identity_scope: context.page.identity_scope.clone(),
            cleanup_integrity_lost,
        })
}
/// Capture within the caller's animation-stabilized protected transaction. The caller must
/// retain the journal, restore it, and revalidate before publishing these bytes.
/// This helper owns source masks through the same journal; no lifecycle mutation.
pub(crate) async fn capture_under_journal(
    context: &CaptureContext,
    request: &CaptureRequest,
    operation: &OperationLease,
    journal: &mut ProtectedReadJournal<'_>,
    geometry: &GeometrySnapshot,
) -> Result<MaskedCapture, CaptureAttemptFailure> {
    let viewport_size = async {
        journal.require_stabilized().map_err(protected_reason)?;

        if !context.inventory_complete || context.frames.is_empty() {
            return Err(CaptureReason::IncompleteFrames);
        }
        if request.secure_field_selector.is_empty() || request.secure_field_selector.len() > 8192 {
            return Err(CaptureReason::MaskingUnproven);
        }
        for frame in &context.frames {
            if frame.binding.page_session != context.page.page_session_id
                || !journal.contains_session(&frame.binding.session)
            {
                return Err(CaptureReason::IncompleteFrames);
            }
        }
        validate_frames(context, operation).await?;
        viewport(context, operation).await
    }
    .await
    .map_err(|reason| CapturePhase::Admission.failure(reason, operation))?;
    let before = masks(context, request, operation, geometry)
        .await
        .map_err(|reason| CapturePhase::IndependentCoverage.failure(reason, operation))?;
    async {
        install_source_masks(context, request, operation, journal).await?;
        journal
            .verify_source_masks()
            .await
            .map_err(source_mask_reason)
    }
    .await
    .map_err(|reason| CapturePhase::SourceProtection.failure(reason, operation))?;
    let bytes = async {
        // Reuse canonical native screenshot capture, without annotations or IO.
        check(context, operation)?;
        journal.raw_capture_started().map_err(protected_reason)?;
        let receipt = super::screenshot::ProtectedScreenshotReceipt::default();
        let capture = super::screenshot::take_protected_screenshot(
            &context.page.client, &context.page.page_session_id, &receipt,
        );
        tokio::pin!(capture);
        let mut cancellation = operation.cancellation.clone();
        let (raw, interrupted) = tokio::select! {
            result = &mut capture => (Some(result), None),
            _ = cancellation.changed() => (None, Some(CaptureReason::Cancelled)),
            _ = tokio::time::sleep_until(operation.deadline.into()) => (None, Some(CaptureReason::Deadline)),
        };
        if let Some(reason) = interrupted {
            // Source-mask custody is required even without an Observe admission.
            // Retirement governs publication/continuation proofs, not supervision
            // of an already-submitted protected raw capture. Never publish its
            // late pixels or manufacture an admission while finishing cleanup.
            let cleanup_deadline = journal.begin_cleanup();
            #[cfg(all(test, feature = "acceptance-faults"))]
            if super::client_observation::capture_retirement_active() {
                retained_capture_test::entered(context, operation, reason);
            }
            let settled = tokio::time::timeout_at(cleanup_deadline.into(), &mut capture).await;
            if !matches!(&settled, Ok(Ok(_))) && !(matches!(&settled, Ok(Err(_))) && receipt.acknowledged()) {
                return Err(CaptureReason::CleanupFailed);
            }
            journal.raw_capture_completed().map_err(protected_reason)?;
            return Err(reason);
        }
        let raw = match raw.ok_or(CaptureReason::BrowserFailure)? {
            Ok(raw) => raw,
            Err(_) => {
                // A correlated error ACK has no pixels but ends raw custody.
                // EOF, malformed/wrong-session replies and abandoned waiters
                // cannot supply this reader-owned reservation receipt.
                if receipt.acknowledged() {
                    journal.raw_capture_completed().map_err(protected_reason)?;
                }
                return Err(CaptureReason::BrowserFailure);
            }
        };
        journal.raw_capture_completed().map_err(protected_reason)?;
        check(context, operation)?;
        if raw.base64.len() > MAX_PNG_BYTES * 4 / 3 + 4 {
            return Err(CaptureReason::BoundsExceeded);
        }
        base64::engine::general_purpose::STANDARD
            .decode(raw.base64)
            .map_err(|_| CaptureReason::BrowserFailure)
    }
    .await
    .map_err(|reason| CapturePhase::RawCapture.failure(reason, operation))?;
    async {
        #[cfg(test)]
        equivalence_tests::after_raw_capture(context, operation).await?;
        validate_frames(context, operation).await?;
        journal
            .verify_source_masks()
            .await
            .map_err(source_mask_reason)?;
        // Compare ordinary visible geometry only after our source rules are gone.
        // Errors above still leave ownership in the outer retained cleanup journal.
        journal
            .remove_source_masks()
            .await
            .map_err(|_| CaptureReason::CleanupFailed)?;
        validate_frames(context, operation).await?;
        if viewport(context, operation).await? != viewport_size
            || masks(context, request, operation, geometry).await? != before
        {
            return Err(CaptureReason::MaskingUnproven);
        }
        check(context, operation)?;
        geometry
            .revalidate(&context.page.client, operation)
            .await
            .map_err(geometry_reason)?;
        raster_mask(
            &bytes,
            geometry.viewport,
            &before,
            &context.page.identity_scope,
        )
    }
    .await
    .map_err(|reason| CapturePhase::PostCaptureValidation.failure(reason, operation))
}
/// Source masks track the controls rather than an earlier raster rectangle.
/// The retained holder is created and journaled before installing any rule.
/// Native snapshot enumeration supplies elements in closed shadow roots too.
async fn install_source_masks(
    context: &CaptureContext,
    request: &CaptureRequest,
    operation: &OperationLease,
    journal: &mut ProtectedReadJournal<'_>,
) -> Result<(), CaptureReason> {
    let mut sessions = HashSet::new();
    let mut seen = HashSet::new();
    let mut total = 0usize;
    for frame in &context.frames {
        if !sessions.insert(frame.binding.session.clone()) {
            continue;
        }
        let snapshot = command(
            context,
            operation,
            &frame.binding.session,
            "DOMSnapshot.captureSnapshot",
            json!({"computedStyles":[]}),
        )
        .await?;
        let strings = snapshot["strings"]
            .as_array()
            .ok_or(CaptureReason::MaskingUnproven)?;
        for document in snapshot["documents"]
            .as_array()
            .ok_or(CaptureReason::IncompleteFrames)?
        {
            let index = document["frameId"]
                .as_u64()
                .ok_or(CaptureReason::IncompleteFrames)? as usize;
            let id = strings
                .get(index)
                .and_then(Value::as_str)
                .ok_or(CaptureReason::IncompleteFrames)?;
            // A plugin document is opaque author content: the verified frame
            // inventory proved it and deliberately omitted it. It is never
            // inspected, so it contributes no mask proof and no secure node.
            if context.opaque_frames.contains(id) {
                continue;
            }
            let owned = context
                .frames
                .iter()
                .find(|f| f.binding.frame == id && f.binding.session == frame.binding.session)
                .ok_or(CaptureReason::IncompleteFrames)?;
            if !seen.insert(id.to_owned()) {
                return Err(CaptureReason::IncompleteFrames);
            }
            let types = document["nodes"]["nodeType"]
                .as_array()
                .ok_or(CaptureReason::MaskingUnproven)?;
            let backends = document["nodes"]["backendNodeId"]
                .as_array()
                .ok_or(CaptureReason::MaskingUnproven)?;
            if types.len() != backends.len() {
                return Err(CaptureReason::MaskingUnproven);
            }
            total = total
                .checked_add(types.len())
                .ok_or(CaptureReason::BoundsExceeded)?;
            if total > MAX_DOM_NODES {
                return Err(CaptureReason::BoundsExceeded);
            }
            let world = command(
                context,
                operation,
                &owned.binding.session,
                "Page.createIsolatedWorld",
                json!({"frameId":id,"worldName":"agent-browser-protected-capture"}),
            )
            .await?;
            let realm = world["executionContextId"]
                .as_i64()
                .ok_or(CaptureReason::MaskingUnproven)?;
            let group = format!("capture-source-{}-{}", operation.sequence, id);
            journal
                .reserve_source_group(owned.binding.session.clone(), group.clone())
                .map_err(protected_reason)?;
            let response = command(
                context,
                operation,
                &owned.binding.session,
                "Runtime.evaluate",
                json!({"contextId":realm,"expression":SOURCE_MASK_HOLDER,"objectGroup":group}),
            )
            .await?;
            if response.get("exceptionDetails").is_some() {
                return Err(CaptureReason::MaskingUnproven);
            }
            let object = response["result"]["objectId"]
                .as_str()
                .ok_or(CaptureReason::MaskingUnproven)?
                .to_owned();
            journal
                .bind_source_holder(&owned.binding.session, &group, object.clone())
                .map_err(protected_reason)?;
            let ids = source_mask_backend_ids(document, strings)?;
            for batch in ids.chunks(64) {
                let mut args = vec![json!({"value":request.secure_field_selector})];
                let resolved:Vec<Result<Value,CaptureReason>>=futures_util::stream::iter(batch.iter().copied().map(|backend|{let group=&group;async move {
                    let value=command(context,operation,&owned.binding.session,"DOM.resolveNode",json!({"backendNodeId":backend,"executionContextId":realm,"objectGroup":group})).await?;
                    let handle=value["object"]["objectId"].as_str().ok_or(CaptureReason::MaskingUnproven)?;
                    Ok(json!({"objectId":handle}))
                }})).buffered(16).collect().await;
                if resolved
                    .iter()
                    .any(|result| result.as_ref().err() == Some(&CaptureReason::CleanupFailed))
                {
                    return Err(CaptureReason::CleanupFailed);
                }
                for value in resolved {
                    args.push(value?);
                }
                let installed=command(context,operation,&owned.binding.session,"Runtime.callFunctionOn",json!({"objectId":object,"functionDeclaration":"function(selector,...nodes){return this.install(selector,nodes)}","arguments":args,"returnByValue":true,"objectGroup":group})).await?;
                if installed.get("exceptionDetails").is_some()
                    || installed["result"]["value"] != true
                {
                    return Err(CaptureReason::MaskingUnproven);
                }
            }
        }
    }
    if seen.len() != context.frames.len() {
        return Err(CaptureReason::IncompleteFrames);
    }
    Ok(())
}

/// DOMSnapshot reports CSS pseudo-elements as nodeType 1, but resolveNode may
/// expose CSSPseudoElement rather than a Node. Separate only native-proven
/// generated nodes; never turn an arbitrary failed Element receiver into a skip.
#[derive(Debug, Default, PartialEq, Eq)]
struct CapturePseudoNodes {
    indices: HashSet<usize>,
    origins: Vec<i64>,
}
fn capture_pseudo_nodes(
    document: &Value,
    strings: &[Value],
) -> Result<CapturePseudoNodes, CaptureReason> {
    let nodes = &document["nodes"];
    let types = nodes["nodeType"]
        .as_array()
        .ok_or(CaptureReason::MaskingUnproven)?;
    let backends = nodes["backendNodeId"]
        .as_array()
        .ok_or(CaptureReason::MaskingUnproven)?;
    if types.len() != backends.len() {
        return Err(CaptureReason::MaskingUnproven);
    }
    if types.len() > MAX_DOM_NODES {
        return Err(CaptureReason::BoundsExceeded);
    }
    let mut proof = CapturePseudoNodes::default();
    let Some(rare) = nodes.get("pseudoType") else {
        return Ok(proof);
    };
    let indices = rare["index"]
        .as_array()
        .ok_or(CaptureReason::MaskingUnproven)?;
    let values = rare["value"]
        .as_array()
        .ok_or(CaptureReason::MaskingUnproven)?;
    if indices.len() != values.len() {
        return Err(CaptureReason::MaskingUnproven);
    }
    for (index, value) in indices.iter().zip(values) {
        let index = index
            .as_u64()
            .filter(|i| *i < types.len() as u64)
            .ok_or(CaptureReason::MaskingUnproven)? as usize;
        let kind = value
            .as_u64()
            .and_then(|i| strings.get(i as usize))
            .and_then(Value::as_str)
            .ok_or(CaptureReason::MaskingUnproven)?;
        // These generated boxes belong to their originating element's subtree.
        // Other pseudo kinds (e.g. view-transition image copies) need a separate
        // paint proof and must not inherit this bounded exclusion.
        if types[index].as_u64() != Some(1)
            || !matches!(kind, "before" | "after" | "marker")
            || !proof.indices.insert(index)
        {
            return Err(CaptureReason::MaskingUnproven);
        }
        backends[index]
            .as_i64()
            .filter(|id| *id > 0)
            .ok_or(CaptureReason::MaskingUnproven)?;
    }
    if proof.indices.is_empty() {
        return Ok(proof);
    }
    let parents = nodes["parentIndex"]
        .as_array()
        .filter(|parents| parents.len() == types.len())
        .ok_or(CaptureReason::MaskingUnproven)?;
    let mut origins = HashSet::new();
    for index in indices {
        let mut cursor = index.as_u64().ok_or(CaptureReason::MaskingUnproven)? as usize;
        let mut depth = 0;
        loop {
            depth += 1;
            if depth > 256 {
                return Err(CaptureReason::BoundsExceeded);
            }
            // Snapshot order is parent before child. This also rejects cycles,
            // cross-document roots and missing or fabricated origin indices.
            cursor = parents[cursor]
                .as_u64()
                .filter(|parent| *parent < cursor as u64)
                .ok_or(CaptureReason::MaskingUnproven)? as usize;
            if types[cursor].as_u64() != Some(1) {
                return Err(CaptureReason::MaskingUnproven);
            }
            if !proof.indices.contains(&cursor) {
                let backend = backends[cursor]
                    .as_i64()
                    .filter(|id| *id > 0)
                    .ok_or(CaptureReason::MaskingUnproven)?;
                if origins.insert(backend) {
                    proof.origins.push(backend);
                }
                break;
            }
        }
    }
    Ok(proof)
}

fn source_mask_backend_ids(document: &Value, strings: &[Value]) -> Result<Vec<i64>, CaptureReason> {
    let nodes = &document["nodes"];
    let types = nodes["nodeType"]
        .as_array()
        .ok_or(CaptureReason::MaskingUnproven)?;
    let backends = nodes["backendNodeId"]
        .as_array()
        .ok_or(CaptureReason::MaskingUnproven)?;
    if types.len() != backends.len() {
        return Err(CaptureReason::MaskingUnproven);
    }
    let pseudo = capture_pseudo_nodes(document, strings)?;
    let mut internal = HashSet::new();
    if let Some(rare) = nodes.get("shadowRootType") {
        let indices = rare["index"]
            .as_array()
            .ok_or(CaptureReason::MaskingUnproven)?;
        let values = rare["value"]
            .as_array()
            .ok_or(CaptureReason::MaskingUnproven)?;
        if indices.len() != values.len() {
            return Err(CaptureReason::MaskingUnproven);
        }
        let mut seen = HashSet::new();
        for (index, value) in indices.iter().zip(values) {
            let index = index
                .as_u64()
                .filter(|i| *i < types.len() as u64)
                .ok_or(CaptureReason::MaskingUnproven)? as usize;
            if !seen.insert(index) {
                return Err(CaptureReason::MaskingUnproven);
            }
            let kind = value
                .as_u64()
                .and_then(|i| strings.get(i as usize))
                .and_then(Value::as_str)
                .ok_or(CaptureReason::MaskingUnproven)?;
            match kind {
                "user-agent" => {
                    internal.insert(index);
                }
                "open" | "closed" => {}
                _ => return Err(CaptureReason::MaskingUnproven),
            }
        }
    }
    types
        .iter()
        .zip(backends)
        .enumerate()
        .filter(|(i, (kind, _))| {
            !internal.contains(i)
                && !pseudo.indices.contains(i)
                && matches!(kind.as_u64(), Some(1 | 9 | 11))
        })
        .map(|(_, (_, id))| {
            id.as_i64()
                .filter(|id| *id > 0)
                .ok_or(CaptureReason::MaskingUnproven)
        })
        .collect()
}

// These are temporary owned stylesheet nodes, not author inline-style edits.
// Opacity preserves layout and suppresses the entire control's composited
// subtree. The raster pass still returns the original black mask rectangles.
// This is bounded source-mask parity, not a promise against hostile transient
// tampering that leaves no observable evidence between checks.
const SOURCE_MASK_HOLDER: &str = r#"(()=>{
 const connected=Object.getOwnPropertyDescriptor(Node.prototype,'isConnected').get;
 const owner=Object.getOwnPropertyDescriptor(Node.prototype,'ownerDocument').get;
 const getRoot=Node.prototype.getRootNode,append=Node.prototype.appendChild,remove=Node.prototype.removeChild;
 const matches=Element.prototype.matches,queryDocument=Document.prototype.querySelectorAll,queryShadow=DocumentFragment.prototype.querySelectorAll;
 const create=Document.prototype.createElement,text=Object.getOwnPropertyDescriptor(Node.prototype,'textContent').set;
 const roots=new Map(),tracked=new Set();let selector=null,removed=false;
 const rootOf=node=>getRoot.call(node);
 const ours=node=>node===document||owner.call(node)===document;
 const selected=node=>node.nodeType===1&&matches.call(node,'input[type="password" i],'+selector);
 return {
 install(request,nodes){
  if(removed||typeof request!=='string'||!request.length||request.length>8192)return false;
  if(selector!==null&&selector!==request)return false;selector=request;
  // Parse the exact selector before adding a stylesheet.
  queryDocument.call(document,'input[type="password" i],'+selector);
  for(const node of nodes){
   if(!connected.call(node)||!ours(node))return false;
   const root=rootOf(node);if(root!==document&&!(root instanceof ShadowRoot))return false;
   if(!roots.has(root)){
    const style=create.call(document,'style');
    const rule='input[type="password" i],'+selector+'{opacity:0!important}';
    text.call(style,rule);
    // Journal ownership before append; insertion failure is still removable.
    roots.set(root,{style,rule,parent:root===document?document.documentElement:root});
    append.call(roots.get(root).parent,style);
    const sheet=style.sheet;if(!sheet||sheet.cssRules.length!==1)return false;roots.get(root).cssText=sheet.cssRules[0].cssText;
   }
   if(node.nodeType===1)tracked.add(node);
  }
  return true;
 },
 verify(){
  if(removed||selector===null||!roots.has(document))return false;
  for(const [root,entry]of roots){
   if(!connected.call(root)||!connected.call(entry.style)||entry.style.parentNode!==entry.parent||rootOf(entry.style)!==root||entry.style.textContent!==entry.rule)return false;
   const sheet=entry.style.sheet;if(!sheet||sheet.disabled||sheet.cssRules.length!==1)return false;
   const rule=sheet.cssRules[0];if(rule.cssText!==entry.cssText)return false;if(rule.style.getPropertyValue('opacity')!=='0'||rule.style.getPropertyPriority('opacity')!=='important')return false;
   const nodes=root===document?queryDocument.call(root,'input[type="password" i],'+selector):queryShadow.call(root,'input[type="password" i],'+selector);
   for(const node of nodes)if(Number(getComputedStyle(node).opacity)!==0)return false;
  }
  for(const node of tracked)if(connected.call(node)&&selected(node)&&(!roots.has(rootOf(node))||Number(getComputedStyle(node).opacity)!==0))return false;
  return true;
 },
 remove(){
  let complete=true;
  for(const {style}of roots.values()){try{if(style.parentNode)remove.call(style.parentNode,style);}catch{complete=false;}}
  if(complete){removed=true;roots.clear();tracked.clear();}return complete;
 }
 };
})()"#;

fn source_mask_reason(reason: ProtectedReadReason) -> CaptureReason {
    match reason {
        ProtectedReadReason::BrowserFailure => CaptureReason::MaskingUnproven,
        other => protected_reason(other),
    }
}
pub(crate) fn geometry_reason(reason: GeometryError) -> CaptureReason {
    match reason {
        GeometryError::InvalidGeometry => CaptureReason::UnsafeGeometry,
        GeometryError::IncompleteInventory => CaptureReason::IncompleteFrames,
        GeometryError::StaleIdentity => CaptureReason::StaleScope,
        GeometryError::Cancelled => CaptureReason::Cancelled,
        GeometryError::Superseded => CaptureReason::Superseded,
        GeometryError::DeadlineExceeded => CaptureReason::Deadline,
        // A geometry command that failed proves nothing about a mask or about
        // policy: the node, frame or layout it addressed was moving with the
        // page. Source masks are proven separately while pixels are captured,
        // so a failed read here is a capture race the caller resolves with a
        // fresh capture, never a policy refusal. Reporting it as
        // MaskingUnproven made a transient layout change look like a denial.
        GeometryError::BackendFailure => CaptureReason::IncompleteFrames,
        GeometryError::CleanupFailed { .. } => CaptureReason::CleanupFailed,
    }
}
fn protected_reason(reason: ProtectedReadReason) -> CaptureReason {
    match reason {
        ProtectedReadReason::Cancelled => CaptureReason::Cancelled,
        ProtectedReadReason::Superseded => CaptureReason::Superseded,
        ProtectedReadReason::CleanupFailed => CaptureReason::CleanupFailed,
        ProtectedReadReason::Deadline => CaptureReason::Deadline,
        ProtectedReadReason::StaleScope => CaptureReason::StaleScope,
        ProtectedReadReason::IncompleteInventory => CaptureReason::IncompleteFrames,
        ProtectedReadReason::BrowserFailure => CaptureReason::BrowserFailure,
    }
}

async fn viewport(
    context: &CaptureContext,
    operation: &OperationLease,
) -> Result<(f64, f64), CaptureReason> {
    let value = command(
        context,
        operation,
        &context.page.page_session_id,
        "Page.getLayoutMetrics",
        json!({}),
    )
    .await?;
    let viewport = value
        .get("cssVisualViewport")
        .ok_or(CaptureReason::UnsafeGeometry)?;
    let width = viewport["clientWidth"]
        .as_f64()
        .ok_or(CaptureReason::UnsafeGeometry)?;
    let height = viewport["clientHeight"]
        .as_f64()
        .ok_or(CaptureReason::UnsafeGeometry)?;
    if !width.is_finite()
        || !height.is_finite()
        || width <= 0.0
        || height <= 0.0
        || viewport["scale"].as_f64() != Some(1.0)
        || viewport["offsetX"].as_f64() != Some(0.0)
        || viewport["offsetY"].as_f64() != Some(0.0)
    {
        return Err(CaptureReason::UnsafeGeometry);
    }
    Ok((width, height))
}
async fn validate_frames(
    context: &CaptureContext,
    operation: &OperationLease,
) -> Result<(), CaptureReason> {
    for frame in &context.frames {
        let tree = command(
            context,
            operation,
            &frame.binding.session,
            "Page.getFrameTree",
            json!({}),
        )
        .await?;
        fn find<'a>(tree: &'a Value, id: &str) -> Option<&'a str> {
            if tree["frame"]["id"].as_str() == Some(id) {
                return tree["frame"]["loaderId"].as_str();
            }
            tree["childFrames"]
                .as_array()?
                .iter()
                .find_map(|child| find(child, id))
        }
        if find(&tree["frameTree"], &frame.binding.frame) != Some(frame.binding.loader.as_str()) {
            return Err(CaptureReason::StaleScope);
        }
    }
    Ok(())
}

// Snapshot enumerates closed shadow trees as well as ordinary DOM. Discovery
// publishes no form values, text content, or serialized HTML. Snapshot payloads
// stay native and are never included in diagnostics or returned to the adapter.
async fn masks(
    context: &CaptureContext,
    request: &CaptureRequest,
    operation: &OperationLease,
    geometry: &GeometrySnapshot,
) -> Result<MaskProof, CaptureReason> {
    let mut proof = MaskProof {
        count: 0,
        secure_nodes: Vec::new(),
        masks: Vec::new(),
        uninspected: Vec::new(),
        uninspected_total: 0,
    };
    let mut sessions = HashSet::new();
    let mut seen = HashSet::new();
    let mut total = 0usize;
    for frame in &context.frames {
        if !sessions.insert(frame.binding.session.clone()) {
            continue;
        }
        let snapshot = command(
            context,
            operation,
            &frame.binding.session,
            "DOMSnapshot.captureSnapshot",
            json!({"computedStyles":[]}),
        )
        .await?;
        let strings = snapshot["strings"]
            .as_array()
            .ok_or(CaptureReason::MaskingUnproven)?;
        for document in snapshot["documents"]
            .as_array()
            .ok_or(CaptureReason::MaskingUnproven)?
        {
            let index = document["frameId"]
                .as_u64()
                .ok_or(CaptureReason::IncompleteFrames)? as usize;
            let id = strings
                .get(index)
                .and_then(Value::as_str)
                .ok_or(CaptureReason::IncompleteFrames)?;
            // A plugin document is opaque author content: the verified frame
            // inventory proved it and deliberately omitted it. It is never
            // inspected, so it contributes no mask proof and no secure node.
            if context.opaque_frames.contains(id) {
                continue;
            }
            let owned = context
                .frames
                .iter()
                .find(|f| f.binding.frame == id && f.binding.session == frame.binding.session)
                .ok_or(CaptureReason::IncompleteFrames)?;
            if !seen.insert(id.to_owned()) {
                return Err(CaptureReason::IncompleteFrames);
            }
            // Additive offsets cannot prove transformed frame geometry.
            // Secure child-frame pixels remain refused below until the shared
            // native projection proves their exact paint bounds.
            let world = command(
                context,
                operation,
                &owned.binding.session,
                "Page.createIsolatedWorld",
                json!({"frameId":id,"worldName":"agent-browser-protected-capture"}),
            )
            .await?;
            let realm = world["executionContextId"]
                .as_i64()
                .ok_or(CaptureReason::MaskingUnproven)?;
            let types = document["nodes"]["nodeType"]
                .as_array()
                .ok_or(CaptureReason::MaskingUnproven)?;
            let backends = document["nodes"]["backendNodeId"]
                .as_array()
                .ok_or(CaptureReason::MaskingUnproven)?;
            if types.len() != backends.len() {
                return Err(CaptureReason::MaskingUnproven);
            }
            total = total
                .checked_add(types.len())
                .ok_or(CaptureReason::BoundsExceeded)?;
            if total > MAX_DOM_NODES {
                return Err(CaptureReason::BoundsExceeded);
            }
            let group = format!("capture-{}-{}", operation.sequence, id);
            let gathered = async {
                let pseudo = capture_pseudo_nodes(document, strings)?;
                // Generated content on any protected origin/ancestor remains
                // refused, including attr(value), overflow and closed roots.
                // Only real originating Elements enter this separate reader.
                for batch in pseudo.origins.chunks(64) {
                    let mut args = vec![json!({"value":request.secure_field_selector})];
                    let handles: Vec<Result<Value,CaptureReason>> = futures_util::stream::iter(batch.iter().copied().map(|backend| { let group = &group; async move {
                        let resolved = command(context, operation, &owned.binding.session, "DOM.resolveNode", json!({"backendNodeId":backend,"executionContextId":realm,"objectGroup":group})).await?;
                        let object = resolved["object"]["objectId"].as_str().ok_or(CaptureReason::MaskingUnproven)?;
                        Ok::<Value, CaptureReason>(json!({"objectId":object}))
                    }})).buffered(16).collect().await;
                    if handles.iter().any(|result| result.as_ref().err() == Some(&CaptureReason::CleanupFailed)) { return Err(CaptureReason::CleanupFailed); }
                    args.extend(handles.into_iter().collect::<Result<Vec<_>,_>>()?);
                    let response = command(context, operation, &owned.binding.session, "Runtime.callFunctionOn", json!({"executionContextId":realm,"functionDeclaration":PSEUDO_ORIGIN_READER,"arguments":args,"returnByValue":true,"objectGroup":group})).await?;
                    if response.get("exceptionDetails").is_some() { return Err(CaptureReason::MaskingUnproven); }
                    match response["result"]["value"].as_bool() {
                        Some(true) => {},
                        Some(false) => return Err(CaptureReason::UnsafeGeometry),
                        None => return Err(CaptureReason::MaskingUnproven),
                    }
                }
                let ids: Vec<_> = types.iter().zip(backends).enumerate().filter(|(index,(kind,_))| kind.as_u64()==Some(1) && !pseudo.indices.contains(index)).map(|(_,(_,id))|id.as_i64().ok_or(CaptureReason::MaskingUnproven)).collect::<Result<Vec<i64>,_>>()?;
                let mut owner_paint_checked = false;
                for batch in ids.chunks(64) {
                    let mut args = vec![json!({"value":request.secure_field_selector})];
                    let handles: Vec<Result<Value,CaptureReason>> = futures_util::stream::iter(batch.iter().copied().map(|backend: i64| { let group = &group; async move {
                        let resolved = command(context, operation, &owned.binding.session, "DOM.resolveNode", json!({"backendNodeId":backend,"executionContextId":realm,"objectGroup":group})).await?;
                        let object = resolved["object"]["objectId"].as_str().ok_or(CaptureReason::MaskingUnproven)?;
                        Ok::<Value, CaptureReason>(json!({"objectId":object}))
                    }})).buffered(16).collect().await;
                    if handles.iter().any(|result| result.as_ref().err() == Some(&CaptureReason::CleanupFailed)) { return Err(CaptureReason::CleanupFailed); }
                    args.extend(handles.into_iter().collect::<Result<Vec<_>,_>>()?);
                    let response = command(context, operation, &owned.binding.session, "Runtime.callFunctionOn", json!({"executionContextId":realm,"functionDeclaration":MASK_READER,"arguments":args,"returnByValue":true,"objectGroup":group})).await?;
                    if response.get("exceptionDetails").is_some() { return Err(CaptureReason::MaskingUnproven); }
                    let result: FrameMasks = serde_json::from_value(response["result"]["value"].clone()).map_err(|_|CaptureReason::MaskingUnproven)?;
                    // An unprovable plugin region stays refused: its document is
                    // never inspected, so it could contain secure glyphs, and a
                    // filtered ancestor can paint them outside the measured box.
                    // Every other visible plugin region is published unmasked.
                    if result.unprovable_plugin { return Err(CaptureReason::UninspectableContent); }
                    if result.unsafe_geometry { return Err(CaptureReason::UnsafeGeometry); }
                    proof.count += result.count;
                    if result.secure.len()!=result.count {return Err(CaptureReason::MaskingUnproven);}
                    for index in result.secure {proof.secure_nodes.push((id.to_owned(),*batch.get(index).ok_or(CaptureReason::MaskingUnproven)?));}
                    if !result.masks.is_empty() && !owner_paint_checked { verify_owner_paint(context, operation, geometry, id).await?; owner_paint_checked = true; }
                    let secure_backends = result.masks.into_iter().map(|index| batch.get(index).copied().ok_or(CaptureReason::MaskingUnproven)).collect::<Result<Vec<_>, _>>()?;
                    let polygons: Vec<Result<Vec<Polygon>, CaptureReason>> = futures_util::stream::iter(secure_backends.into_iter().map(|backend| async move {
                        geometry.node_border_polygons(&context.page.client, owned, backend, operation).await.map_err(geometry_reason)
                    })).buffered(16).collect().await;
                    // Drain every geometry future through its handle cleanup before propagating an error.
                    if polygons.iter().any(|result| result.as_ref().err() == Some(&CaptureReason::CleanupFailed)) { return Err(CaptureReason::CleanupFailed); }
                    for result in polygons {
                        for polygon in result? { proof.masks.push(geometry.clip_for_capture(id, &polygon).map_err(geometry_reason)?); }
                    }
                    // Plugin regions are published, never masked. Their exact
                    // owner border quad goes through the same shared proof as a
                    // secure mask, so any frame transform and clip is applied
                    // before the viewport intersection is reported. A region
                    // entirely outside the captured pixels is not claimed as
                    // uninspected; the count stays exact past the published cut.
                    for index in result.uninspected {
                        let backend = *batch.get(index).ok_or(CaptureReason::MaskingUnproven)?;
                        let polygons = geometry
                            .node_border_polygons(&context.page.client, owned, backend, operation)
                            .await
                            .map_err(geometry_reason)?;
                        for polygon in polygons {
                            let clipped =
                                geometry.clip_for_capture(id, &polygon).map_err(geometry_reason)?;
                            let Some(bounds) =
                                clipped.bounds().filter(|bounds| bounds.width > 0.0 && bounds.height > 0.0)
                            else {
                                continue;
                            };
                            proof.uninspected_total = proof
                                .uninspected_total
                                .checked_add(1)
                                .ok_or(CaptureReason::BoundsExceeded)?;
                            if proof.uninspected.len() < MAX_UNINSPECTED_REGIONS {
                                proof.uninspected.push(bounds);
                            }
                        }
                    }
                }
                Ok(())
            }.await;
            // This group owns read-only handles, not installed source masks.
            // Exact submitted release debt may remain on the stable owner.
            let released = super::client_actions::release_group_accounted(
                &context.page.client,
                &owned.binding.session,
                &group,
            )
            .await;
            if super::client_observation::capture_retirement_active() && !released {
                return Err(CaptureReason::CleanupFailed);
            }
            gathered?;
        }
    }
    if seen.len() != context.frames.len() {
        return Err(CaptureReason::IncompleteFrames);
    }
    Ok(proof)
}
// Frame transforms belong to shared geometry; this check is only the capture
// paint policy. An outer CSS filter can paint protected child glyphs outside
// the verified iframe content polygon even when the child's own styles are safe.
async fn verify_owner_paint(
    context: &CaptureContext,
    operation: &OperationLease,
    geometry: &GeometrySnapshot,
    frame_id: &str,
) -> Result<(), CaptureReason> {
    for (binding, backend) in geometry.owner_chain(frame_id).map_err(geometry_reason)? {
        let group = format!("capture-owner-{}-{}", operation.sequence, backend);
        let result = async {
            let world = command(context, operation, &binding.session, "Page.createIsolatedWorld", json!({"frameId":binding.frame,"worldName":"agent-browser-protected-capture"})).await?;
            let realm = world["executionContextId"].as_i64().ok_or(CaptureReason::MaskingUnproven)?;
            let resolved = command(context, operation, &binding.session, "DOM.resolveNode", json!({"backendNodeId":backend,"executionContextId":realm,"objectGroup":group})).await?;
            let object = resolved["object"]["objectId"].as_str().ok_or(CaptureReason::MaskingUnproven)?;
            let response = command(context, operation, &binding.session, "Runtime.callFunctionOn", json!({"objectId":object,"functionDeclaration":OWNER_PAINT_READER,"returnByValue":true,"objectGroup":group})).await?;
            if response.get("exceptionDetails").is_some() || response["result"]["value"] != true { return Err(CaptureReason::UnsafeGeometry); }
            Ok(())
        }.await;
        if !super::client_actions::release_group_accounted(
            &context.page.client,
            &binding.session,
            &group,
        )
        .await
        {
            return Err(CaptureReason::CleanupFailed);
        }
        result?;
    }
    Ok(())
}
const OWNER_PAINT_READER: &str = r#"function(){
 const connected=Object.getOwnPropertyDescriptor(Node.prototype,'isConnected').get;
 const owner=Object.getOwnPropertyDescriptor(Node.prototype,'ownerDocument').get;
 if(!connected.call(this)||owner.call(this)!==document)return false;
 for(let p=this;p;){if(getComputedStyle(p).filter!=='none')return false;p=p.parentElement||(p.getRootNode().host||null);}
 return true;
}"#;

// A pseudo is not an Element receiver. Its native snapshot origin must be a
// live ordinary Element outside every protected subtree; generated secret paint
// is deliberately refused rather than assumed to fit the host border polygon.
const PSEUDO_ORIGIN_READER: &str = r#"function(selector,...nodes){
 const connected=Object.getOwnPropertyDescriptor(Node.prototype,'isConnected').get;
 const owner=Object.getOwnPropertyDescriptor(Node.prototype,'ownerDocument').get;
 const parent=Object.getOwnPropertyDescriptor(Node.prototype,'parentElement').get;
 const root=Node.prototype.getRootNode,matches=Element.prototype.matches;
 for(const node of nodes){
  if(!connected.call(node)||owner.call(node)!==document)throw Error('stale');
  let depth=0;for(let p=node;p;){
   if(++depth>256)throw Error('depth');
   if(matches.call(p,'input[type="password" i]')||matches.call(p,selector))return false;
   p=parent.call(p)||(root.call(p).host||null);
  }
 }
 return true;
}"#;

const MASK_READER: &str = r#"function(selector,...nodes){
 const connected=Object.getOwnPropertyDescriptor(Node.prototype,'isConnected').get;
 const owner=Object.getOwnPropertyDescriptor(Node.prototype,'ownerDocument').get;
 let count=0,masks=[],secureIds=[],unprovablePlugin=false,uninspected=[],unsafeGeometry=false;
 for(const [index,node] of nodes.entries()){
  if(!connected.call(node)||owner.call(node)!==document)throw Error('stale');
  const rect=node.getBoundingClientRect(),style=getComputedStyle(node);
  const visible=rect.width>0&&rect.height>0&&style.visibility!=='hidden'&&style.display!=='none'&&Number(style.opacity)!==0;
  let secure=false;for(let p=node;p;){if(p.matches('input[type="password" i]')||p.matches(selector)){secure=true;break;}p=p.parentElement||(p.getRootNode().host||null);}
  if(visible&&(node.localName==='object'||node.localName==='embed')){
   // A plugin document is opaque author content and is never inspected for
   // secure fields. Inside protected content its glyphs still cannot be proven
   // safe, and an ancestor filter can paint those glyphs outside the measured
   // border box, so both captures stay refused. Every other visible plugin
   // region is published unchanged and reported as uninspected: degraded,
   // never silent.
   if(secure){unprovablePlugin=true;continue;}
   let filtered=false;for(let p=node;p;){if(getComputedStyle(p).filter!=='none'){filtered=true;break;}p=p.parentElement||(p.getRootNode().host||null);}
   if(filtered){unprovablePlugin=true;continue;}
   uninspected.push(index);
   continue;
  }
  if(!secure)continue;
  count++;secureIds.push(index);
  if(!visible){if(style.display==='contents')unsafeGeometry=true;continue;}
  if(![rect.x,rect.y,rect.width,rect.height].every(Number.isFinite))throw Error('geometry');
  // A clean refusal is not an all-black success. Required password-input
  // geometry is distinct from optional arbitrary secure-container policies.
  // Decorative box shadows do not carry the input's protected glyph pixels.
  let bleed=!(node.localName==='input'||node.localName==='textarea')||style.textShadow!=='none';
  for(let p=node;p;){const s=getComputedStyle(p);if(s.filter!=='none')bleed=true;p=p.parentElement||(p.getRootNode().host||null);}
  if(bleed){unsafeGeometry=true;continue;}
  masks.push(index);
 }
 return {count,masks,secure:secureIds,unprovablePlugin,uninspected,unsafeGeometry};
}"#;

fn raster_mask(
    bytes: &[u8],
    viewport: Viewport,
    proof: &MaskProof,
    scope: &str,
) -> Result<MaskedCapture, CaptureReason> {
    // Validate PNG IHDR before allocating a decoded pixel buffer.
    if bytes.len() < 24
        || bytes.len() > MAX_PNG_BYTES
        || &bytes[..8] != b"\x89PNG\r\n\x1a\n"
        || &bytes[12..16] != b"IHDR"
    {
        return Err(CaptureReason::BoundsExceeded);
    }
    let width = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
    let height = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
    if width == 0 || height == 0 || u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(CaptureReason::BoundsExceeded);
    }
    if !viewport.width.is_finite()
        || !viewport.height.is_finite()
        || viewport.width <= 0.0
        || viewport.height <= 0.0
    {
        return Err(CaptureReason::UnsafeGeometry);
    }
    let sx = f64::from(width) / viewport.width;
    let sy = f64::from(height) / viewport.height;
    if (sx - sy).abs() > 1.0 / viewport.width.min(viewport.height) {
        return Err(CaptureReason::UnsafeGeometry);
    }
    let mut image = image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
        .map_err(|_| CaptureReason::BrowserFailure)?
        .to_rgba8();
    if image.dimensions() != (width, height) {
        return Err(CaptureReason::BoundsExceeded);
    }
    for polygon in &proof.masks {
        let Some(bounds) = polygon
            .raster_bounds(viewport, width, height)
            .map_err(geometry_reason)?
        else {
            continue;
        };
        let (left, top, right, bottom) = (bounds.left, bounds.top, bounds.right, bounds.bottom);
        for y in top..bottom {
            for x in left..right {
                image.put_pixel(x, y, image::Rgba([0, 0, 0, 255]));
            }
        }
    }
    let mut output = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image)
        .write_to(&mut output, image::ImageFormat::Png)
        .map_err(|_| CaptureReason::BrowserFailure)?;
    let png = output.into_inner();
    if png.len() > MAX_PNG_BYTES {
        return Err(CaptureReason::BoundsExceeded);
    }
    Ok(MaskedCapture {
        png,
        width,
        height,
        scale: sx,
        masked_region_count: proof.count,
        uninspected_region_count: proof.uninspected_total,
        uninspected: proof
            .uninspected
            .iter()
            .take(MAX_UNINSPECTED_REGIONS)
            .copied()
            .map(UninspectedRegion::plugin)
            .collect(),
        identity_scope: scope.to_owned(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn test_viewport(width: f64, height: f64) -> Viewport {
        Viewport {
            width,
            height,
            offset_x: 0.,
            offset_y: 0.,
            scale: 1.,
            layout_width: width,
            layout_height: height,
        }
    }
    #[test]
    fn source_mask_native_roots_exclude_user_agent_and_retain_closed_author_nodes() {
        let strings = vec![json!("user-agent"), json!("closed")];
        let mut doc = json!({"nodes":{"nodeType":[9,1,11,1,11,1],"backendNodeId":[1,2,3,4,5,6],"shadowRootType":{"index":[2,3,4,5],"value":[0,0,1,1]}}});
        assert_eq!(
            source_mask_backend_ids(&doc, &strings).unwrap(),
            vec![1, 2, 5, 6]
        );
        doc["nodes"]["shadowRootType"]["value"][0] = json!(99);
        assert_eq!(
            source_mask_backend_ids(&doc, &strings),
            Err(CaptureReason::MaskingUnproven)
        );
    }
    #[test]
    fn source_mask_rejections_preserve_deadline_cancel_and_scope() {
        assert_eq!(
            source_mask_reason(ProtectedReadReason::Cancelled),
            CaptureReason::Cancelled
        );
        assert_eq!(
            source_mask_reason(ProtectedReadReason::Deadline),
            CaptureReason::Deadline
        );
        assert_eq!(
            source_mask_reason(ProtectedReadReason::StaleScope),
            CaptureReason::StaleScope
        );
        let a = MaskProof {
            count: 1,
            secure_nodes: vec![("frame".into(), 1)],
            masks: vec![],
            uninspected: vec![],
            uninspected_total: 0,
        };
        let b = MaskProof {
            count: 1,
            secure_nodes: vec![("frame".into(), 2)],
            masks: vec![],
            uninspected: vec![],
            uninspected_total: 0,
        };
        assert!(
            a != b,
            "replacement secure node cannot reuse the earlier coverage proof"
        );
    }
    #[test]
    fn geometry_read_failures_are_retryable_capture_races_not_denials() {
        // A geometry command that failed while the page moved proves nothing
        // about a mask: the caller takes a fresh capture. Masking proof
        // failures themselves stay policy refusals.
        assert_eq!(
            geometry_reason(GeometryError::BackendFailure),
            CaptureReason::IncompleteFrames
        );
        assert_eq!(
            geometry_reason(GeometryError::InvalidGeometry),
            CaptureReason::UnsafeGeometry
        );
        assert_eq!(
            source_mask_reason(ProtectedReadReason::BrowserFailure),
            CaptureReason::MaskingUnproven
        );
        assert_eq!(
            geometry_reason(GeometryError::CleanupFailed {
                primary: Some(Box::new(GeometryError::Cancelled))
            }),
            CaptureReason::CleanupFailed
        );
        assert_eq!(
            geometry_reason(GeometryError::StaleIdentity),
            CaptureReason::StaleScope
        );
    }
    #[test]
    fn fractional_masks_round_outward() {
        let image = image::RgbaImage::from_pixel(8, 8, image::Rgba([255, 120, 80, 255]));
        let mut bytes = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image)
            .write_to(&mut bytes, image::ImageFormat::Png)
            .unwrap();
        let result = raster_mask(
            bytes.get_ref(),
            test_viewport(4.0, 4.0),
            &MaskProof {
                secure_nodes: Vec::new(),
                count: 1,
                masks: vec![Polygon::rectangle_for_test(0.75, 0.75, 0.5, 0.5)],
                uninspected: vec![],
                uninspected_total: 0,
            },
            "scope",
        )
        .unwrap();
        let pixels = image::load_from_memory(&result.png).unwrap().to_rgba8();
        assert_eq!(pixels.get_pixel(1, 1).0, [0, 0, 0, 255]);
        assert_eq!(pixels.get_pixel(2, 2).0, [0, 0, 0, 255]);
        assert_eq!(pixels.get_pixel(0, 0).0, [255, 120, 80, 255]);
    }
    #[test]
    fn invalid_png_is_not_released() {
        assert!(raster_mask(
            b"not png",
            test_viewport(10.0, 10.0),
            &MaskProof {
                secure_nodes: Vec::new(),
                count: 0,
                masks: vec![],
                uninspected: vec![],
                uninspected_total: 0,
            },
            "old"
        )
        .is_err());
    }
    #[test]
    fn uninspected_plugin_regions_are_published_unmasked() {
        let image = image::RgbaImage::from_pixel(4, 4, image::Rgba([255, 120, 80, 255]));
        let mut bytes = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image)
            .write_to(&mut bytes, image::ImageFormat::Png)
            .unwrap();
        let result = raster_mask(
            bytes.get_ref(),
            test_viewport(4.0, 4.0),
            &MaskProof {
                secure_nodes: Vec::new(),
                count: 1,
                masks: vec![Polygon::rectangle_for_test(0.0, 0.0, 1.0, 1.0)],
                uninspected: vec![Bounds {
                    x: 1.0,
                    y: 2.0,
                    width: 2.0,
                    height: 2.0,
                }],
                uninspected_total: 1,
            },
            "scope",
        )
        .unwrap();
        assert_eq!(result.masked_region_count, 1);
        assert_eq!(result.uninspected_region_count, 1);
        assert_eq!(
            result.uninspected,
            vec![UninspectedRegion {
                kind: "plugin",
                x: 1.0,
                y: 2.0,
                width: 2.0,
                height: 2.0,
            }]
        );
        // The secure mask is painted; the plugin region keeps the browser
        // pixels and only the metadata warns about it.
        let pixels = image::load_from_memory(&result.png).unwrap().to_rgba8();
        assert_eq!(pixels.get_pixel(0, 0).0, [0, 0, 0, 255]);
        assert_eq!(pixels.get_pixel(2, 3).0, [255, 120, 80, 255]);
    }
    #[test]
    fn uninspected_metadata_is_bounded_but_the_count_is_exact() {
        let regions = (0..MAX_UNINSPECTED_REGIONS + 2)
            .map(|_| Bounds {
                x: 0.0,
                y: 0.0,
                width: 1.0,
                height: 1.0,
            })
            .collect::<Vec<_>>();
        let image = image::RgbaImage::from_pixel(2, 2, image::Rgba([10, 20, 30, 255]));
        let mut bytes = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image)
            .write_to(&mut bytes, image::ImageFormat::Png)
            .unwrap();
        let result = raster_mask(
            bytes.get_ref(),
            test_viewport(2.0, 2.0),
            &MaskProof {
                secure_nodes: Vec::new(),
                count: 0,
                masks: vec![],
                uninspected: regions,
                uninspected_total: MAX_UNINSPECTED_REGIONS + 2,
            },
            "scope",
        )
        .unwrap();
        assert_eq!(result.uninspected_region_count, MAX_UNINSPECTED_REGIONS + 2);
        assert_eq!(result.uninspected.len(), MAX_UNINSPECTED_REGIONS);
    }
    // Only closed diagnostic values leave this helper; equality stays on raw JSON.
    fn background_page_state_diagnostic(before: &Value, after: &Value) -> Value {
        let state = |value: &Value| {
            let visibility = match value.get("visibility").and_then(Value::as_str) {
                Some("visible") => "Visible",
                Some("hidden") => "Hidden",
                _ => "Unknown",
            };
            let focus = match value.get("focus").and_then(Value::as_bool) {
                Some(focus) => json!(focus),
                None => json!("Unknown"),
            };
            json!({"visibility": visibility, "focus": focus})
        };
        json!({
            "before": state(before),
            "after": state(after),
            "visibility_changed": before.get("visibility") != after.get("visibility"),
            "focus_changed": before.get("focus") != after.get("focus"),
            "record_changed": before != after,
        })
    }
    #[test]
    fn background_page_diagnostic_is_closed_and_preserves_exact_change_detection() {
        let sentinel = "secret-looking-sentinel://private.example/token?value=never-log";
        let cases = [
            Value::Null,
            json!(true),
            json!(7),
            json!(sentinel),
            json!([sentinel]),
            json!({}),
            json!({"visibility": null, "focus": null}),
            json!({"visibility": sentinel, "focus": sentinel}),
            json!({"visibility": [sentinel], "focus": {"secret": sentinel}}),
            json!({"visibility": "visible", "focus": true}),
            json!({"visibility": "hidden", "focus": false}),
            json!({"visibility": "visible", "focus": true, "extra": sentinel}),
        ];
        for before in &cases {
            for after in &cases {
                let diagnostic = background_page_state_diagnostic(before, after);
                assert!(!diagnostic.to_string().contains(sentinel));
                for state in [&diagnostic["before"], &diagnostic["after"]] {
                    assert!(matches!(
                        state["visibility"].as_str(),
                        Some("Visible" | "Hidden" | "Unknown")
                    ));
                    assert!(state["focus"].is_boolean() || state["focus"] == "Unknown");
                }
                assert_eq!(diagnostic["record_changed"], json!(before != after));
                assert_eq!(
                    diagnostic["visibility_changed"],
                    json!(before.get("visibility") != after.get("visibility"))
                );
                assert_eq!(
                    diagnostic["focus_changed"],
                    json!(before.get("focus") != after.get("focus"))
                );
            }
        }
        for malformed in &cases[..9] {
            let diagnostic = background_page_state_diagnostic(malformed, malformed);
            assert_eq!(
                diagnostic["before"],
                json!({"visibility": "Unknown", "focus": "Unknown"})
            );
        }
        assert_eq!(
            background_page_state_diagnostic(&cases[9], &cases[10]),
            json!({
                "before": {"visibility": "Visible", "focus": true},
                "after": {"visibility": "Hidden", "focus": false},
                "visibility_changed": true,
                "focus_changed": true,
                "record_changed": true,
            })
        );
    }
    /// Static one-page masking and cleanup proof only. This does not establish
    /// recursive target enrollment, OOPIF projection, or dynamic paint fidelity.
    #[tokio::test]
    #[ignore = "hosted Chromium: exact source-mask cleanup, dynamic closed roots and background visibility"]
    async fn chromium_source_masks_cover_dynamic_fields_without_activating_background_page() {
        use super::super::client_browser::{ExecutionGate, OwnedBrowser};
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        let mut owner = OwnedBrowser::launch(Default::default(), None)
            .await
            .unwrap();
        let gate = Arc::new(ExecutionGate::default());
        let mut page = owner.lease(gate.enter(false).unwrap()).unwrap();
        let client = page.client.clone();
        let session = page.page_session_id.clone();
        let target = page.target_id.clone();
        let (_tx, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 3100001,
            deadline: Instant::now() + Duration::from_secs(30),
            cancellation,
        };
        let result:Result<(),String>=async {
            client.send_command("Runtime.evaluate",Some(json!({"expression":r#"(()=>{document.body.style.cssText='margin:0;background:white';const h=document.createElement('div');document.body.append(h);const root=h.attachShadow({mode:'closed'});const input=document.createElement('input');input.type='password';input.value='synthetic-only';input.style.cssText='position:absolute;left:10px;top:10px;width:80px;height:25px;background:red';root.append(input);window.__sourceMaskFixture={root,input,style:input.getAttribute('style')};return true})()"#,"returnByValue":true})),Some(&session)).await?;
            // Independently activate another exact host page BEFORE the capture.
            // The capture must preserve this state, never activate its own page.
            let peer=client.send_command("Target.createTarget",Some(json!({"url":"about:blank","browserContextId":owner.context_id,"background":false})),None).await?["targetId"].as_str().ok_or("Missing peer target")?.to_owned();
            let peer_session=client.send_command("Target.attachToTarget",Some(json!({"targetId":peer,"flatten":true})),None).await?["sessionId"].as_str().ok_or("Missing peer session")?.to_owned();
            client.send_command("Target.activateTarget",Some(json!({"targetId":peer})),None).await?;
            // Fixture readiness, not a capture repair: activation ACK can precede
            // the renderer's focus event. Wait under the ORIGINAL operation deadline,
            // without another activation, sleep, focus override, or lifecycle command.
            let ready_budget = operation.deadline.saturating_duration_since(Instant::now()).as_millis();
            if ready_budget == 0 { return Err("Background fixture readiness budget expired".into()); }
            let readiness_script = format!(r#"new Promise(resolve=>{{
                const ready=()=>document.visibilityState==='visible'&&document.hasFocus();
                const initiallyReady=ready();let settled=false;let timer;
                const finish=value=>{{if(settled)return;settled=true;clearTimeout(timer);
                    window.removeEventListener('focus',check);document.removeEventListener('visibilitychange',check);
                    resolve({{initiallyReady,ready:value,listenersRemoved:true}});}};
                const check=()=>{{if(ready())finish(true);}};
                window.addEventListener('focus',check);document.addEventListener('visibilitychange',check);
                timer=setTimeout(()=>finish(false),{ready_budget});check();
            }})"#);
            let readiness=tokio::time::timeout_at(tokio::time::Instant::from_std(operation.deadline),
                client.send_command("Runtime.evaluate",Some(json!({"expression":readiness_script,"awaitPromise":true,"returnByValue":true})),Some(&peer_session)))
                .await.map_err(|_|"Background fixture readiness deadline")??;
            let ready=&readiness["result"]["value"];
            let initially_ready=ready["initiallyReady"].as_bool().ok_or("Invalid background fixture readiness proof")?;
            let ready_now=ready["ready"].as_bool().ok_or("Invalid background fixture readiness proof")?;
            let listeners_removed=ready["listenersRemoved"].as_bool().ok_or("Invalid background fixture readiness proof")?;
            eprintln!("BackgroundFixtureReadiness initially_ready={initially_ready} ready={ready_now} listeners_removed={listeners_removed}");
            if !ready_now||!listeners_removed{return Err("Fixture did not establish renderer foreground readiness".into());}
            let read=json!({"expression":"({visibility:document.visibilityState,focus:document.hasFocus()})","returnByValue":true});
            let before=client.send_command("Runtime.evaluate",Some(read.clone()),Some(&session)).await?["result"]["value"].clone();
            let peer_before=client.send_command("Runtime.evaluate",Some(read.clone()),Some(&peer_session)).await?["result"]["value"].clone();
            if before["visibility"]!="hidden"||peer_before["visibility"]!="visible"||peer_before["focus"]!=true{return Err("Fixture did not establish exact background and foreground pages".into());}
            let frames=super::super::client_observation::enumerate_frames(&client,&session,&HashMap::new(),&operation).await.map_err(|e|format!("Frame inventory: {e:?}"))?;
            page.targets.acknowledge_enrollment().map_err(|e|format!("Primitive fixture inventory: {e:?}"))?;
            let operation_journal = owned_capture_journal(&mut owner, &mut page, &operation);
            let client = page.client.clone();
            let context=CaptureContext{page,frames,opaque_frames:HashSet::new(),inventory_complete:true};
            let mut journal=operation_journal.scope(async { ProtectedReadJournal::begin(&context.page,&operation) }).await.map_err(|e|format!("Journal: {e:?}"))?;
            let masked:Result<(),String>=async {
                operation_journal.scope(journal.stabilize_animations()).await.map_err(|e|format!("Stabilization: {e:?}"))?;
                operation_journal.scope(install_source_masks(&context,&CaptureRequest{secure_field_selector:"input[type=\"password\" i]".into()},&operation,&mut journal)).await.map_err(|e|format!("Install: {e:?}"))?;
                let changed=client.send_command("Runtime.evaluate",Some(json!({"expression":r#"(()=>{const f=window.__sourceMaskFixture;f.input.style.left='100px';const n=document.createElement('input');n.type='password';n.value='new-synthetic-only';n.style.cssText='position:absolute;left:10px;top:10px;width:80px;height:25px;background:red';f.root.append(n);f.newInput=n;return getComputedStyle(f.input).opacity==='0'&&getComputedStyle(n).opacity==='0'})()"#,"returnByValue":true})),Some(&session)).await?;
                if changed["result"]["value"]!=true{return Err("Moved or new matching closed-root field was not masked at source".into());}
                operation_journal.scope(journal.verify_source_masks()).await.map_err(|e|format!("Source proof: {e:?}"))?;
                // Raw source screenshot must already suppress the red controls;
                // the production raster pass adds the required black regions.
                let shot=client.send_command("Page.captureScreenshot",Some(json!({"format":"png","fromSurface":true})),Some(&session)).await?;
                let bytes=base64::engine::general_purpose::STANDARD.decode(shot["data"].as_str().ok_or("No source pixels")?).map_err(|_|"Invalid source pixels")?;
                let image=image::load_from_memory(&bytes).map_err(|_|"Invalid source PNG")?.to_rgba8();
                if image.width()<185||image.height()<40{return Err("Unexpected source viewport".into());}
                for x in [20,110]{if image.get_pixel(x,20).0!=[255,255,255,255]{return Err("Source mask did not suppress control pixels".into());}}
                Ok(())
            }.await;
            let restore=operation_journal.scope(journal.restore()).await;
            drop(journal);
            restore.map_err(|e|format!("Source cleanup: {e:?}"))?;masked?;
            let after=client.send_command("Runtime.evaluate",Some(read.clone()),Some(&session)).await?["result"]["value"].clone();
            let peer_after=client.send_command("Runtime.evaluate",Some(read),Some(&peer_session)).await?["result"]["value"].clone();
            if after!=before||peer_after!=peer_before{
                eprintln!("CapturedPage {}", background_page_state_diagnostic(&before, &after));
                eprintln!("PeerPage {}", background_page_state_diagnostic(&peer_before, &peer_after));
                return Err("Source capture changed host visibility/focus".into());
            }
            let clean=client.send_command("Runtime.evaluate",Some(json!({"expression":"(()=>{const f=window.__sourceMaskFixture;return f.root.querySelectorAll('style').length===0&&document.querySelectorAll('style').length===0&&getComputedStyle(f.input).opacity==='1'&&getComputedStyle(f.newInput).opacity==='1'&&f.input.style.left==='100px'&&f.input.value==='synthetic-only'})()","returnByValue":true})),Some(&session)).await?;
            if clean["result"]["value"]!=true{return Err("Source cleanup left a rule or overwrote concurrent author state".into());}
            for id in [&target,&peer]{let info=client.send_command("Target.getTargetInfo",Some(json!({"targetId":id})),None).await?;if info["targetInfo"]["targetId"]!=*id{return Err("Capture closed a host page".into());}}
            client.send_command("Target.detachFromTarget",Some(json!({"sessionId":peer_session})),None).await?;
            Ok(())
        }.await;
        let cleanup = owner.close().await;
        assert!(
            cleanup.is_ok(),
            "Owned test context cleanup failed: {cleanup:?}"
        );
        assert!(result.is_ok(), "Source mask/background gate: {result:?}");
    }
    #[tokio::test]
    #[ignore = "requires real Chromium; required static masked-pixel fidelity gate"]
    async fn chromium_static_mask_preserves_public_pixels_and_restores_state() {
        static_mask_fixture(false).await;
    }
    #[tokio::test]
    #[ignore = "requires real Chromium: masked same-process transformed iframe pixels"]
    async fn chromium_shared_geometry_masks_transformed_frame_passwords() {
        static_mask_fixture(true).await;
    }
    /// Real-browser acceptance for visible plugin content. Three visible
    /// `<object>` plugin documents no longer refuse the capture; their owner
    /// regions are published as unmasked `uninspected` bounds while a password
    /// input in the same document keeps its black mask.
    #[tokio::test]
    #[ignore = "requires real Chromium: three visible <object> plugin regions"]
    async fn chromium_visible_plugin_regions_are_published_uninspected() {
        use super::super::client_browser::{ExecutionGate, OwnedBrowser};
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        let mut owner = OwnedBrowser::launch(Default::default(), None)
            .await
            .unwrap();
        let gate = Arc::new(ExecutionGate::default());
        let mut page = owner.lease(gate.enter(false).unwrap()).unwrap();
        let client = page.client.clone();
        let session = page.page_session_id.clone();
        let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 3_200_001,
            deadline: Instant::now() + Duration::from_secs(30),
            cancellation,
        };
        let result: Result<(), String> = async {
            client.send_command("Emulation.setDeviceMetricsOverride", Some(json!({"width":400,"height":300,"deviceScaleFactor":1,"mobile":false})), Some(&session)).await?;
            let setup = client.send_command("Runtime.evaluate", Some(json!({"expression":r#"(()=>{
                document.body.style.cssText='margin:0;background:rgb(25,75,125)';
                const box='position:absolute;width:100px;height:50px;border:0;padding:0';
                const plugin=(left,top)=>{const node=document.createElement('object');node.type='text/html';node.data='about:blank';node.style.cssText=box+';left:'+left+'px;top:'+top+'px';document.body.appendChild(node);return node;};
                window.__pluginFixture={first:plugin(10,10),second:plugin(150,10),third:plugin(10,100)};
                const input=document.createElement('input');input.type='password';input.value='synthetic-plugin-secret';
                input.style.cssText=box+';left:150px;top:100px;background:red';
                document.body.appendChild(input);window.__pluginFixture.input=input;
                return document.querySelectorAll('object').length===3;
            })()"#,"returnByValue":true})), Some(&session)).await?;
            if setup["result"]["value"] != true {
                return Err("Visible plugin fixture setup failed".into());
            }
            // The plugin documents are real renderer targets; wait for the three
            // native child frames so the inventory proves the same page shape.
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    let tree = client.send_command("Page.getFrameTree", Some(json!({})), Some(&session)).await.unwrap();
                    let children = tree["frameTree"]["childFrames"].as_array().map(Vec::len).unwrap_or(0);
                    if children >= 3 { return; }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }).await.map_err(|_| "visible plugin frames did not appear")?;
            page.targets.acknowledge_enrollment().map_err(|_| "Visible plugin inventory acknowledgement failed")?;
            let super::super::client_observation_dispatch::VerifiedFrameInventory { frames, opaque_frames, .. } =
                super::super::client_observation_dispatch::verified_frame_inventory(&page, &operation).await.map_err(|error| format!("Visible plugin inventory: {error:?}"))?;
            if opaque_frames.len() != 3 { return Err(format!("Expected three proven plugin frames, got {opaque_frames:?}")); }
            let journal = owned_capture_journal(&mut owner, &mut page, &operation);
            // Accounting replaces the ambient transport handle with its exact
            // owner-bound view; post-capture reads must use that same view.
            let client = page.client.clone();
            let captured = journal.scope(async {
                start_capture(CaptureContext { page, frames, opaque_frames, inventory_complete: true },
                    CaptureRequest { secure_field_selector: "input[type=\"password\" i]".into() }, operation).await
            }).await.map_err(|_| "Visible plugin capture task failed")?
                .map_err(|error| format!("Visible plugin capture was refused: {error:?}"))?;
            if captured.uninspected_region_count != 3 || captured.uninspected.len() != 3 {
                return Err(format!("Unexpected uninspected metadata: {:?}", captured.uninspected));
            }
            for (region, expected) in captured.uninspected.iter().zip([(10.0, 10.0), (150.0, 10.0), (10.0, 100.0)]) {
                let (x, y) = expected;
                if region.kind != "plugin" || (region.x - x).abs() > 0.5 || (region.y - y).abs() > 0.5
                    || (region.width - 100.0).abs() > 0.5 || (region.height - 50.0).abs() > 0.5 {
                    return Err(format!("Unexpected plugin bounds {region:?} for {expected:?}"));
                }
            }
            if captured.masked_region_count < 1 { return Err("Password input mask proof was lost".into()); }
            let pixels = image::load_from_memory(&captured.png).map_err(|_| "Visible plugin PNG invalid")?.to_rgba8();
            if pixels.dimensions() != (400, 300) { return Err("Unexpected visible plugin screenshot dimensions".into()); }
            if pixels.get_pixel(200, 120).0 != [0, 0, 0, 255] { return Err("Password pixels were not black".into()); }
            if pixels.get_pixel(60, 35).0 == [0, 0, 0, 255] { return Err("Plugin pixels were masked instead of published".into()); }
            let controls = client.send_command("Runtime.evaluate", Some(json!({"expression":"window.__pluginFixture.input.value==='synthetic-plugin-secret'&&document.querySelectorAll('object').length===3","returnByValue":true})), Some(&session)).await?;
            if controls["result"]["value"] != true { return Err("Capture changed the visible plugin fixture".into()); }
            Ok(())
        }.await;
        let cleanup = owner.close().await;
        assert!(
            cleanup.is_ok(),
            "Owned test context cleanup failed: {cleanup:?}"
        );
        assert!(result.is_ok(), "Visible plugin capture gate: {result:?}");
    }
    /// A plugin region whose pixels cannot be bounded keeps the original
    /// refusal: its document is never inspected, so it could hold secure
    /// glyphs, and a filtered ancestor can paint them outside the owner border
    /// box. Degrading to a marker is allowed only when the bounds are truthful.
    #[tokio::test]
    #[ignore = "requires real Chromium: unprovable <object> plugin region"]
    async fn chromium_unprovable_plugin_regions_stay_refused() {
        for filtered in [false, true] {
            unprovable_plugin_fixture(filtered).await;
        }
    }
    async fn unprovable_plugin_fixture(filtered: bool) {
        use super::super::client_browser::{ExecutionGate, OwnedBrowser};
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        let mut owner = OwnedBrowser::launch(Default::default(), None)
            .await
            .unwrap();
        let gate = Arc::new(ExecutionGate::default());
        let mut page = owner.lease(gate.enter(false).unwrap()).unwrap();
        let client = page.client.clone();
        let session = page.page_session_id.clone();
        let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 3_200_002 + u64::from(filtered),
            deadline: Instant::now() + Duration::from_secs(30),
            cancellation,
        };
        let (setup, selector) = if filtered {
            (
                r#"(()=>{
                document.body.style.cssText='margin:0;background:rgb(25,75,125)';
                const node=document.createElement('object');node.type='text/html';node.data='about:blank';
                node.style.cssText='position:absolute;left:10px;top:10px;width:100px;height:50px;border:0;padding:0;filter:blur(4px)';
                document.body.appendChild(node);
                return document.querySelectorAll('object').length===1;
            })()"#,
                "input[type=\"password\" i]",
            )
        } else {
            (
                r#"(()=>{
                document.body.style.cssText='margin:0;background:rgb(25,75,125)';
                const host=document.createElement('div');host.setAttribute('data-protected','');
                host.style.cssText='position:absolute;left:0;top:0;width:200px;height:150px';
                const node=document.createElement('object');node.type='text/html';node.data='about:blank';
                node.style.cssText='position:absolute;left:10px;top:10px;width:100px;height:50px;border:0;padding:0';
                host.appendChild(node);document.body.appendChild(host);
                return document.querySelectorAll('object').length===1;
            })()"#,
                "[data-protected],input[type=\"password\" i]",
            )
        };
        let result: Result<(), String> = async {
            client
                .send_command(
                    "Emulation.setDeviceMetricsOverride",
                    Some(json!({"width":400,"height":300,"deviceScaleFactor":1,"mobile":false})),
                    Some(&session),
                )
                .await?;
            let setup = client
                .send_command(
                    "Runtime.evaluate",
                    Some(json!({"expression":setup,"returnByValue":true})),
                    Some(&session),
                )
                .await?;
            if setup["result"]["value"] != true {
                return Err("Unprovable plugin fixture setup failed".into());
            }
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    let tree = client
                        .send_command("Page.getFrameTree", Some(json!({})), Some(&session))
                        .await
                        .unwrap();
                    let children = tree["frameTree"]["childFrames"]
                        .as_array()
                        .map(Vec::len)
                        .unwrap_or(0);
                    if children >= 1 {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .map_err(|_| "unprovable plugin frame did not appear")?;
            page.targets
                .acknowledge_enrollment()
                .map_err(|_| "Unprovable plugin inventory acknowledgement failed")?;
            let super::super::client_observation_dispatch::VerifiedFrameInventory {
                frames,
                opaque_frames,
                ..
            } = super::super::client_observation_dispatch::verified_frame_inventory(
                &page, &operation,
            )
            .await
            .map_err(|error| format!("Unprovable plugin inventory: {error:?}"))?;
            let journal = owned_capture_journal(&mut owner, &mut page, &operation);
            let captured = journal
                .scope(async {
                    start_capture(
                        CaptureContext {
                            page,
                            frames,
                            opaque_frames,
                            inventory_complete: true,
                        },
                        CaptureRequest {
                            secure_field_selector: selector.into(),
                        },
                        operation,
                    )
                    .await
                })
                .await
                .map_err(|_| "Unprovable plugin capture task failed")?;
            match captured {
                Err(failure)
                    if failure.reason == CaptureReason::UninspectableContent
                        && !failure.cleanup_integrity_lost =>
                {
                    Ok(())
                }
                Err(failure) => Err(format!("Unexpected unprovable plugin refusal: {failure:?}")),
                Ok(_) => Err("Unprovable plugin pixels were published".into()),
            }
        }
        .await;
        let cleanup = owner.close().await;
        assert!(
            cleanup.is_ok(),
            "Owned test context cleanup failed: {cleanup:?}"
        );
        assert!(
            result.is_ok(),
            "Unprovable plugin capture gate (filtered={filtered}): {result:?}"
        );
    }
    /// Primitive Chromium fixtures launch a real managed owner without the
    /// ClientBrowser dispatcher. Install its exact accounting before capture;
    /// never downgrade managed targets or manufacture restoration evidence.
    pub(super) fn owned_capture_journal(
        owner: &mut super::super::client_browser::OwnedBrowser,
        page: &mut super::super::client_browser::BrowserExecutionLease,
        operation: &OperationLease,
    ) -> super::super::client_debt::OperationJournalHandle {
        use super::super::client_debt::{OperationKey, OwnerDebtLedger};
        assert!(page.client.debt_ledger().is_none());
        assert!(
            matches!(
                ProtectedReadJournal::begin(page, operation),
                Err(failure) if failure.reason == ProtectedReadReason::CleanupFailed
                    && !failure.cleanup_integrity_lost
            ),
            "a managed owner without accounting must still refuse capture"
        );
        let ledger = OwnerDebtLedger::new(operation.generation, page.identity_scope.clone());
        ledger.bind_context(&page.targets.context_id).unwrap();
        ledger
            .bind_session(
                &page.targets.context_id,
                &page.target_id,
                &page.page_session_id,
            )
            .unwrap();
        assert!(std::sync::Arc::ptr_eq(&owner.manager.client, &page.client));
        page.client.install_debt_ledger(ledger.clone()).unwrap();
        let view = page.client.owner_view(ledger.clone()).unwrap();
        owner.manager.client = view.clone();
        page.client = view;
        assert!(std::sync::Arc::ptr_eq(&owner.manager.client, &page.client));
        let journal = ledger
            .operation(
                OperationKey {
                    generation: operation.generation,
                    operation_seq: operation.sequence,
                },
                page.target_id.clone(),
                page.page_session_id.clone(),
            )
            .unwrap();
        journal.bind_operation(operation).unwrap();
        assert!(ledger.matches_owner(operation.generation, &page.identity_scope));
        assert_eq!(
            ledger.bound_context().as_deref(),
            Some(page.targets.context_id.as_str())
        );
        journal
    }
    async fn static_mask_fixture(framed: bool) {
        use super::super::client_browser::{ExecutionGate, OwnedBrowser};
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        for closed_shadow in [false, true] {
            let mut owner = OwnedBrowser::launch(Default::default(), None)
                .await
                .unwrap();
            let gate = Arc::new(ExecutionGate::default());
            let mut page = owner.lease(gate.enter(false).unwrap()).unwrap();
            let client = page.client.clone();
            let session = page.page_session_id.clone();
            let (sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let operation = OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline: Instant::now() + Duration::from_secs(30),
                cancellation,
            };
            let result:Result<(),String>=async {
                client.send_command("Emulation.setDeviceMetricsOverride",Some(json!({"width":400,"height":300,"deviceScaleFactor":1,"mobile":false})),Some(&session)).await?;
                let fixture=format!(r#"(()=>{{document.body.style.cssText='margin:0;background:rgb(25,75,125)';const host=document.createElement('div');host.style.cssText='position:absolute;left:20px;top:20px;width:120px;height:40px;background:red;box-shadow:0 0 4px white';document.body.appendChild(host);const root={closed_shadow}?host.attachShadow({{mode:'closed'}}):host;const input=document.createElement('input');input.type='password';input.value='synthetic-mask-only';input.style.cssText='position:absolute;left:0;top:0;width:100px;height:30px;border:0;padding:0;box-shadow:none;text-shadow:none;background:red';root.appendChild(input);window.__maskFixture={{host,input,style:input.getAttribute('style')}};document.body.dataset.tick='0';setInterval(()=>document.body.dataset.tick=String(Number(document.body.dataset.tick)+1),10);return true}})()"#);
                let setup=client.send_command("Runtime.evaluate",Some(json!({"expression":fixture,"returnByValue":true})),Some(&session)).await?;
                if setup["result"]["value"]!=true{return Err("Static masking fixture setup failed".into());}
                if framed {
                    let child = client.send_command("Runtime.evaluate", Some(json!({"expression":r#"new Promise(resolve=>{const frame=document.createElement('iframe');frame.style.cssText='position:absolute;left:150px;top:20px;width:120px;height:80px;border:4px solid green;padding:5px;transform:scale(1.2);transform-origin:top left';frame.onload=()=>resolve(true);frame.srcdoc='<body style="margin:0;background:yellow"><input type="password" value="synthetic-child-secret" style="position:absolute;left:10px;top:10px;width:60px;height:20px;border:0;padding:0;background:red;text-shadow:none">';document.body.appendChild(frame);window.__maskFixture.frame=frame;})"#,"awaitPromise":true,"returnByValue":true})), Some(&session)).await?;
                    if child["result"]["value"] != true { return Err("Child masking fixture setup failed".into()); }
                }
                client.send_command("Animation.enable",Some(json!({})),Some(&session)).await?;
                client.send_command("Animation.setPlaybackRate",Some(json!({"playbackRate":0.75})),Some(&session)).await?;
                let frames=super::super::client_observation::enumerate_frames(&client,&session,&HashMap::new(),&operation).await.map_err(|_|"Static frame enumeration failed")?;
                if frames.len() != if framed { 2 } else { 1 } { return Err("Unexpected static frame inventory".into()); }
                // Only this synthetic fixture is a known one-renderer inventory.
                // Production callers cannot use this acknowledgement as a substitute
                // for the native owner's recursive enrollment barrier.
                page.targets.acknowledge_enrollment().map_err(|_|"Static inventory acknowledgement failed")?;
                let journal = owned_capture_journal(&mut owner, &mut page, &operation);
                let client = page.client.clone();
                let captured=journal.scope(async { start_capture(CaptureContext{page,frames,opaque_frames:HashSet::new(),inventory_complete:true},CaptureRequest{secure_field_selector:"input[type=\"password\" i]".into()},operation).await }).await.map_err(|_|"Capture task failed")?.map_err(|error|format!("Static protected capture failed: {error:?}"))?;
                let rate=client.send_command("Animation.getPlaybackRate",Some(json!({})),Some(&session)).await?;
                if rate["playbackRate"].as_f64()!=Some(0.75){return Err("Animation playback was not restored".into());}
                let controls=client.send_command("Runtime.evaluate",Some(json!({"expression":"window.__maskFixture.input.value==='synthetic-mask-only' && window.__maskFixture.input.getAttribute('style')===window.__maskFixture.style","returnByValue":true})),Some(&session)).await?;
                if controls["result"]["value"]!=true{return Err("Capture changed the synthetic control".into());}
                let before=client.send_command("Runtime.evaluate",Some(json!({"expression":"Number(document.body.dataset.tick)","returnByValue":true})),Some(&session)).await?["result"]["value"].as_u64().ok_or("Missing synthetic timer")?;
                tokio::time::timeout(Duration::from_secs(3),async {
                    loop {
                        let value=client.send_command("Runtime.evaluate",Some(json!({"expression":"Number(document.body.dataset.tick)","returnByValue":true})),Some(&session)).await?;
                        if value["result"]["value"].as_u64().is_some_and(|tick|tick>before){return Ok::<(),String>(());}
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }).await.map_err(|_|"Synthetic timer did not resume")??;
                let pixels=image::load_from_memory(&captured.png).map_err(|_|"Masked PNG invalid")?.to_rgba8();
                if pixels.dimensions()!=(400,300){return Err("Unexpected static screenshot dimensions".into());}
                if pixels.get_pixel(25,25).0 != [0,0,0,255]{return Err("Protected pixels were not black".into());}
                if framed && pixels.get_pixel(190,55).0 != [0,0,0,255] { return Err("Transformed child password pixels were not black".into()); }
                if framed {
                    let child=client.send_command("Runtime.evaluate",Some(json!({"expression":"window.__maskFixture.frame.contentDocument.querySelector('input').value==='synthetic-child-secret'","returnByValue":true})),Some(&session)).await?;
                    if child["result"]["value"] != true { return Err("Capture changed child control".into()); }
                }
                if pixels.get_pixel(300,200).0 != [25,75,125,255]{return Err(if closed_shadow {"Closed-shadow masking erased public background"}else{"Password masking erased public background"}.into());}
                Ok(())
            }.await;
            drop(sender);
            let cleanup = owner.close().await;
            assert!(cleanup.is_ok(), "Static fixture context cleanup failed");
            result.unwrap();
        }
    }
}

// Exact-client/operation notification only: tests decide when the fake peer
// acknowledges the retained screenshot, without changing its drain deadline.
#[cfg(all(test, feature = "acceptance-faults"))]
pub(super) mod retained_capture_test {
    use super::super::cdp::client::CdpClient;
    use super::*;
    use std::sync::{Arc, Mutex, OnceLock};
    use tokio::sync::oneshot;

    type Key = (usize, u64);
    static HOOKS: OnceLock<Mutex<HashMap<Key, oneshot::Sender<CaptureReason>>>> = OnceLock::new();

    pub struct Registration {
        client: Arc<CdpClient>,
        sequence: u64,
    }
    impl Registration {
        fn key(&self) -> Key {
            (Arc::as_ptr(&self.client) as usize, self.sequence)
        }
    }
    impl Drop for Registration {
        fn drop(&mut self) {
            HOOKS.get().unwrap().lock().unwrap().remove(&self.key());
        }
    }
    pub fn register(
        client: &Arc<CdpClient>,
        sequence: u64,
    ) -> (Registration, oneshot::Receiver<CaptureReason>) {
        let registration = Registration {
            client: client.clone(),
            sequence,
        };
        let (send, receipt) = oneshot::channel();
        assert!(HOOKS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .insert(registration.key(), send)
            .is_none());
        (registration, receipt)
    }
    pub(super) fn entered(
        context: &CaptureContext,
        operation: &OperationLease,
        reason: CaptureReason,
    ) {
        let key = (
            Arc::as_ptr(&context.page.client) as usize,
            operation.sequence,
        );
        let send = HOOKS
            .get()
            .and_then(|hooks| hooks.lock().unwrap().remove(&key));
        if let Some(send) = send {
            let _ = send.send(reason);
        }
    }
}

#[cfg(test)]
#[path = "client_capture_equivalence_tests.rs"]
mod equivalence_tests;

#[cfg(test)]
#[path = "client_capture_pseudo_tests.rs"]
mod pseudo_tests;
