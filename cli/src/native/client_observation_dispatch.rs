//! Scoped orchestration of the existing native matcher and protected capture.
//! The executor retains every task through restoration; capabilities are gated
//! separately by browser conformance, not by this module's existence.
use super::client_blobs::{BlobError, BlobScope, BlobStore};
use super::client_browser::BrowserExecutionLease;
use super::client_capture::{self, CaptureContext, CaptureReason, CaptureRequest};
use super::client_geometry::GeometrySnapshot;
use super::client_observation::{
    self as observation, ObservationError, ObservationFrame, ObservationOptions, QueryOptions,
    SemanticNode,
};
use super::client_protected_read::{ProtectedReadJournal, ProtectedReadReason};
use super::client_protocol::ProtocolError;
use super::client_session::{CancelSignal, OperationLease};
use super::client_targets::TargetPurpose;
use super::client_ui::UiGate;
use super::element::{parse_ref, RefMap};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
#[path = "client_reference_correlation.rs"]
mod reference_correlation;
pub use reference_correlation::CorrelateRequest;

#[derive(Debug)]
pub struct DispatchFailure {
    pub error: ProtocolError,
    pub identity_scope: String,
    pub cleanup_integrity_lost: bool,
}
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObserveFlags {
    #[serde(default)]
    pub pixels: bool,
    #[serde(default)]
    pub pixel_fallback: bool,
    #[serde(default)]
    pub comparable: bool,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObserveRequest {
    pub options: ObserveFlags,
    pub test_id_attribute: String,
    pub secure_field_selector: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryPurpose {
    Fixture,
    Protected,
}
pub struct QueryRequest {
    pub options: QueryOptions,
    pub purpose: QueryPurpose,
}
pub enum DispatchRequest {
    Correlate(CorrelateRequest),
    Observe(ObserveRequest),
    Query(QueryRequest),
    Screenshot(CaptureRequest),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadPolicy {
    pub test_id_attribute: String,
    pub secure_field_selector: String,
}
pub struct DispatchContext {
    #[cfg(feature = "acceptance-faults")]
    pub faults: Arc<super::client_test_faults::FaultController>,
    pub page: BrowserExecutionLease,
    pub ui: Arc<UiGate>,
    pub blobs: Arc<BlobStore>,
    pub scope: BlobScope,
    pub policy: ReadPolicy,
}
pub struct DispatchTask {
    /// Must be retained and joined by lifecycle shutdown, never aborted merely
    /// because the RPC receiver or its deadline has gone away.
    pub join: tokio::task::JoinHandle<Result<(), DispatchFailure>>,
    pub result: oneshot::Receiver<Result<Value, DispatchFailure>>,
}
struct Publication {
    revision: u64,
    published_revision: u64,
    observed_revision: u64,
}
#[derive(Clone, Copy)]
enum PublicationKind {
    Snapshot,
    AdditiveQuery,
    PixelsOnly,
}
impl Publication {
    fn stage_revision(&mut self, kind: PublicationKind) -> Result<u64, ProtocolError> {
        if matches!(kind, PublicationKind::PixelsOnly)
            || matches!(kind, PublicationKind::AdditiveQuery) && self.published_revision != 0
        {
            return Ok(self.published_revision);
        }
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        Ok(self.revision)
    }
    fn commit_refs(
        &mut self,
        kind: PublicationKind,
        revision: u64,
        destination: &mut RefMap,
        staged: RefMap,
    ) {
        if !matches!(kind, PublicationKind::PixelsOnly) {
            *destination = staged;
            self.published_revision = revision;
            if matches!(kind, PublicationKind::Snapshot) {
                self.observed_revision = revision;
            }
        }
    }
}
pub struct ObservationDispatch {
    refs: Arc<Mutex<RefMap>>,
    publication: tokio::sync::Mutex<Publication>,
}
struct Output {
    value: Value,
    handles: Vec<String>,
}
impl ObservationDispatch {
    pub fn new(refs: Arc<Mutex<RefMap>>) -> Arc<Self> {
        Arc::new(Self {
            refs,
            publication: tokio::sync::Mutex::new(Publication {
                revision: 0,
                published_revision: 0,
                observed_revision: 0,
            }),
        })
    }
    /// Caller holds the ordinary UI permit and exact scope lease. This is the
    /// sole current revision authority; a request's revision is never authority.
    pub async fn snapshot_for_action(
        &self,
        operation: &OperationLease,
    ) -> Result<(u64, RefMap), ProtocolError> {
        let (revision, refs, _) = self.snapshot_with_observation(operation).await?;
        Ok((revision, refs))
    }
    pub async fn snapshot_with_observation(
        &self,
        operation: &OperationLease,
    ) -> Result<(u64, RefMap, u64), ProtocolError> {
        let mut cancellation = operation.cancellation.clone();
        if *cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        let publication = tokio::select! {
            biased;
            _=cancellation.changed()=>return Err(ProtocolError::Cancelled),
            _=tokio::time::sleep_until(operation.deadline.into())=>return Err(ProtocolError::DeadlineExceeded),
            publication=self.publication.lock()=>publication,
        };
        let refs = self
            .refs
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .clone();
        if *cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok((
            publication.published_revision,
            refs,
            publication.observed_revision,
        ))
    }
    pub fn start(
        self: Arc<Self>,
        context: DispatchContext,
        request: DispatchRequest,
        operation: OperationLease,
    ) -> DispatchTask {
        let (send, result) = oneshot::channel();
        let join = tokio::spawn(async move {
            let scope = context.scope.clone();
            let blobs = context.blobs.clone();
            let targets = context.page.targets.clone();
            let output = self.run(context, request, operation).await;
            match output {
                Ok(output) => {
                    if send.send(Ok(output.value)).is_err()
                        && !release_handles(&blobs, &scope, &output.handles)
                    {
                        targets.seal();
                        return Err(DispatchFailure {
                            error: ProtocolError::CleanupFailed,
                            identity_scope: scope.identity_scope,
                            cleanup_integrity_lost: true,
                        });
                    }
                }
                Err(error) => {
                    if error.cleanup_integrity_lost {
                        targets.seal();
                    }
                    if let Err(Err(error)) = send.send(Err(error)) {
                        if error.cleanup_integrity_lost {
                            return Err(error);
                        }
                    }
                }
            }
            Ok(())
        });
        DispatchTask { join, result }
    }
    async fn run(
        &self,
        context: DispatchContext,
        request: DispatchRequest,
        operation: OperationLease,
    ) -> Result<Output, DispatchFailure> {
        let identity = context.page.identity_scope.clone();
        let observation_cleanup = AtomicBool::new(false);
        let map_observation = |error| observation_error_with_cleanup(error, &observation_cleanup);
        let map_geometry = |error| geometry_error_with_cleanup(error, &observation_cleanup);
        let failure = |error: ProtocolError| DispatchFailure {
            error: error.clone(),
            identity_scope: identity.clone(),
            cleanup_integrity_lost: error == ProtocolError::CleanupFailed
                || observation_cleanup.load(Ordering::SeqCst),
        };
        if context.scope.identity_scope != identity
            || context.scope.generation != operation.generation
        {
            return Err(failure(ProtocolError::StaleScope));
        }
        check(&context.page, &operation).map_err(failure)?;
        validate_policy(&context.policy, &request).map_err(failure)?;
        let protected =
            !matches!(&request, DispatchRequest::Query(q) if q.purpose == QueryPurpose::Fixture);
        // Semantic-only reads need exclusive admission and exact target/frame
        // fences, not a browser lifecycle mutation. Chromium's frozen state
        // also hides the page; setting active does not undo that visibility.
        let stabilize_pixels = matches!(&request, DispatchRequest::Screenshot(_))
            || matches!(&request, DispatchRequest::Observe(r) if r.options.pixels);
        let _ui = context
            .ui
            .enter(
                protected,
                operation.is_callback,
                operation.deadline,
                operation.cancellation.clone(),
            )
            .await
            .map_err(failure)?;
        // Acquire UI first: a queued protected writer must not hold this mutex
        // while a valid callback query needs it to finish the active parent.
        let mut cancellation = operation.cancellation.clone();
        let mut publication = tokio::select! {
            lock = self.publication.lock() => lock,
            _ = cancellation.changed() => return Err(failure(ProtocolError::Cancelled)),
            _ = tokio::time::sleep_until(operation.deadline.into()) => return Err(failure(ProtocolError::DeadlineExceeded)),
        };
        check(&context.page, &operation).map_err(failure)?;
        // Correlation reads committed authority only. It must return before any
        // revision staging, clone publication, pixel reservation or journal.
        if let DispatchRequest::Correlate(request) = &request {
            let value = reference_correlation::run(
                self,
                &context,
                request,
                &operation,
                publication.observed_revision,
                &observation_cleanup,
            )
            .await
            .map_err(failure)?;
            return Ok(Output {
                value,
                handles: vec![],
            });
        }
        let publication_kind = match &request {
            DispatchRequest::Correlate(_) => return Err(failure(ProtocolError::InvalidArguments)),
            DispatchRequest::Observe(_) => PublicationKind::Snapshot,
            DispatchRequest::Query(_) => PublicationKind::AdditiveQuery,
            DispatchRequest::Screenshot(_) => PublicationKind::PixelsOnly,
        };
        let revision = publication
            .stage_revision(publication_kind)
            .map_err(failure)?;
        let mut staged = self
            .refs
            .lock()
            .map_err(|_| failure(ProtocolError::ScopeUnavailable))?
            .clone();
        let wants_pixels = matches!(&request, DispatchRequest::Screenshot(_))
            || matches!(&request, DispatchRequest::Observe(r) if r.options.pixels);
        // Charge the native producer before screenshot collection starts.
        let mut producer = if wants_pixels {
            Some(
                context
                    .blobs
                    .reserve_producer(context.scope.clone())
                    .map_err(|error| failure(blob_error(error)))?,
            )
        } else {
            None
        };
        let frames =
            verified_frames_with_cleanup(&context.page, &operation, Some(&observation_cleanup))
                .await
                .map_err(failure)?;
        let fallback_selector = match &request {
            DispatchRequest::Observe(request) if request.options.pixel_fallback => {
                Some(request.secure_field_selector.clone())
            }
            _ => None,
        };
        let mut capture_context = CaptureContext {
            page: context.page,
            frames,
            inventory_complete: true,
        };
        let is_observe = matches!(&request, DispatchRequest::Observe(_));
        let outcome = async {
        let mut journal = if protected {
            Some(
                ProtectedReadJournal::begin(
                    &capture_context.page,
                    &operation,
                )
                .map_err(|e| DispatchFailure {
                    error: protected_error(e.reason),
                    identity_scope: e.identity_scope,
                    cleanup_integrity_lost: e.cleanup_integrity_lost,
                })?,
            )
        } else {
            None
        };
        let mut geometry = None;
        let result = async {
            if stabilize_pixels { journal.as_mut().ok_or(ProtocolError::PolicyDenied)?.stabilize_animations().await.map_err(protected_error)?; }
            let frozen = verified_frames_with_cleanup(&capture_context.page, &operation, Some(&observation_cleanup)).await?;
            same_frames(&capture_context.frames, &frozen)?;
            // A semantic tree may prove an iframe owner non-rendering. Acquire
            // that exact proof before spatial validation, never infer it from
            // omitted/truncated output. Pixel and query paths remain strict.
            if !matches!(&request, DispatchRequest::Observe(request) if !request.options.pixels) {
                geometry = Some(GeometrySnapshot::capture(&capture_context.page.client, &capture_context.page.page_session_id, &frozen, &operation).await.map_err(map_geometry)?);
            }
            match request {
                DispatchRequest::Correlate(_) => Err(ProtocolError::InvalidArguments),
                DispatchRequest::Query(query) => {
                    let geometry = geometry.as_ref().ok_or(ProtocolError::PolicyDenied)?;
                    let mut output = observation::query(&capture_context.page.client, &frozen, &mut staged, &identity, revision, &query.options, &operation).await.map_err(map_observation)?;
                    observation::project_geometry(&capture_context.page.client, &frozen, &staged, geometry, &mut output.nodes, &operation).await.map_err(map_geometry)?;
                    Ok((serde_json::to_value(output).map_err(|_| ProtocolError::BrowserFailure)?, None, false))
                }
                DispatchRequest::Screenshot(request) => {
                    let geometry = geometry.as_ref().ok_or(ProtocolError::PolicyDenied)?;
                    let pixels = client_capture::capture_under_journal(&capture_context, &request, &operation, journal.as_mut().ok_or(ProtocolError::PolicyDenied)?, geometry).await.map_err(capture_error)?;
                    Ok((Value::Null, Some(pixels), false))
                }
                DispatchRequest::Observe(request) => {
                    let options = ObservationOptions { test_id_attribute: request.test_id_attribute, secure_field_selector: request.secure_field_selector.clone(), ..ObservationOptions::default() };
                    let observed_viewport = viewport(&capture_context.page, &operation).await?;
                    let semantic = semantic_lease(&operation, request.options.pixel_fallback);
                    let tree = async {
                        #[cfg(feature = "acceptance-faults")]
                        context.faults.checkpoint(&identity, super::client_test_faults::Phase::SemanticAcquire, vec![], &semantic).await.map_err(fault_observation_error)?;
                        #[cfg(feature = "acceptance-faults")]
                        let prior_next_ref = staged.next_ref_num();
                        let tree = observation::observe(&capture_context.page.client, &frozen, &mut staged, &identity, revision, &options, &semantic).await?;
                        #[cfg(feature = "acceptance-faults")]
                        {
                            let mut allocated = staged.ref_ids().into_iter().filter(|id| id.strip_prefix('e').and_then(|number| number.parse::<usize>().ok()).is_some_and(|number| number >= prior_next_ref)).map(|id| format!("@{id}")).collect::<Vec<_>>();
                            allocated.sort();
                            context.faults.checkpoint(&identity, super::client_test_faults::Phase::SemanticPublish, allocated, &semantic).await.map_err(fault_observation_error)?;
                        }
                        Ok::<_, ObservationError>(tree)
                    }.await;
                    let (mut value, fallback) = match tree {
                        Ok(mut tree) => {
                            if geometry.is_none() {
                                geometry = Some(GeometrySnapshot::capture_semantic(&capture_context.page.client, &capture_context.page.page_session_id, &frozen, &tree.hidden_frame_proof, &operation).await.map_err(map_geometry)?);
                            }
                            let geometry = geometry.as_ref().ok_or(ProtocolError::PolicyDenied)?;
                            observation::project_geometry(&capture_context.page.client, &frozen, &staged, geometry, &mut tree.roots, &operation).await.map_err(map_geometry)?;
                            let root = exact_root(tree.roots, &staged, &frozen)?;
                            verify_document_root(&capture_context.page, &root, &staged, &operation).await?;
                            (json!({"identityScope":identity,"revision":revision.to_string(),"root":root,"viewportRef":tree.viewport_ref,"truncated":tree.truncated}), false)
                        }
                        Err(ObservationError::DeadlineExceeded) if request.options.pixel_fallback => {
                            check(&capture_context.page, &operation)?;
                            // Any previous pixel stabilization must restore before fresh
                            // fallback pixels can observe current application state.
                            return Ok((Value::Null, None, true));
                        }
                        Err(error) => return Err(map_observation(error)),
                    };
                    if viewport(&capture_context.page, &operation).await? != observed_viewport { return Err(ProtocolError::StaleScope); }
                    value["viewport"] = observed_viewport;
                    let main = main_frame(&frozen)?;
                    value["location"] = Value::String(main.url.clone());
                    let pixels = if request.options.pixels || fallback {
                        let geometry = geometry.as_ref().ok_or(ProtocolError::PolicyDenied)?;
                        let pixel_operation = pixel_lease(&operation);
                        let result = client_capture::capture_under_journal(&capture_context, &CaptureRequest { secure_field_selector: request.secure_field_selector }, &pixel_operation, journal.as_mut().ok_or(ProtocolError::PolicyDenied)?, geometry).await;
                        match result {
                            Ok(pixels) => {
                                if viewport(&capture_context.page, &operation).await? != value["viewport"] { return Err(ProtocolError::StaleScope); }
                                Some(pixels)
                            },
                            // Only an ordinary backend capture failure can omit
                            // optional enrichment. Masking/scope/cleanup proof is
                            // never downgraded to fixture reads or raw pixels.
                            Err(CaptureReason::BrowserFailure | CaptureReason::Deadline) if !fallback => { check(&capture_context.page, &operation)?; None },
                            Err(reason) => return Err(capture_error(reason)),
                        }
                    } else { None };
                    Ok((value, pixels, false))
                }
            }
        }.await;
        let restoration = match &mut journal {
            Some(journal) => journal.restore().await,
            None => Ok(()),
        };
        if let Err(error) = restoration {
            return Err(DispatchFailure {
                error: result
                    .as_ref()
                    .err()
                    .cloned()
                    .unwrap_or_else(|| protected_error(error.reason)),
                identity_scope: identity.clone(),
                cleanup_integrity_lost: error.cleanup_integrity_lost
                    || observation_cleanup.load(Ordering::SeqCst),
            });
        }
        // A clean restore must not turn a policy failure into a timeout and
        // thereby accidentally authorize fallback at a higher layer.
        let (mut value, mut pixels, needs_fresh_fallback) = result.map_err(failure)?;
        if !needs_fresh_fallback {
            if let Some(geometry) = &geometry {
                geometry
                    .revalidate(&capture_context.page.client, &operation)
                    .await
                    .map_err(map_geometry)
                    .map_err(failure)?;
            }
        }
        if needs_fresh_fallback {
            if let Some(journal) = &journal {
                journal.check().map_err(|e| failure(protected_error(e)))?;
            }
            // Release the old target barrier only after acknowledged restoration.
            // The UI owner and original operation budget remain unchanged.
            drop(journal);
            check(&capture_context.page, &operation).map_err(failure)?;
            capture_context.frames = verified_frames_with_cleanup(&capture_context.page, &operation, Some(&observation_cleanup))
                .await
                .map_err(failure)?;
            staged = self
                .refs
                .lock()
                .map_err(|_| failure(ProtocolError::ScopeUnavailable))?
                .clone();
            // A tree-unavailable semantic fallback retires located authority too.
            // Standalone pixels-only publication does not take this branch.
            staged.retire_all_references();
            staged.begin_observation(&capture_context.page.identity_scope, operation.generation, revision);
            let selector = fallback_selector
                .as_deref()
                .ok_or_else(|| failure(ProtocolError::PolicyDenied))?;
            // Permission to fall back does not itself request pixels. Admit
            // fresh fallback only after the semantic deadline and restoration,
            // under the same exact scope and unchanged operation budget.
            check(&capture_context.page, &operation).map_err(failure)?;
            if producer.is_none() {
                producer = Some(context.blobs.reserve_producer(context.scope.clone())
                    .map_err(|error| failure(blob_error(error)))?);
            }
            let (fresh_value, fresh_pixels, fresh_journal) = fresh_fallback(
                &capture_context,
                selector,
                &mut staged,
                revision,
                &operation,
            )
            .await?;
            value = fresh_value;
            pixels = Some(fresh_pixels);
            journal = Some(fresh_journal);
        }
        if let Some(journal) = &journal {
            journal.check().map_err(|e| failure(protected_error(e)))?;
        }
        check(&capture_context.page, &operation).map_err(failure)?;
        let final_frames = verified_frames_with_cleanup(&capture_context.page, &operation, Some(&observation_cleanup))
            .await
            .map_err(failure)?;
        same_frames(&capture_context.frames, &final_frames).map_err(failure)?;
        if value.get("viewport").is_some()
            && viewport(&capture_context.page, &operation)
                .await
                .map_err(failure)?
                != value["viewport"]
        {
            return Err(failure(ProtocolError::StaleScope));
        }
        let mut handles = Vec::new();
        if let Some(pixels) = pixels {
            let producer = producer
                .take()
                .ok_or_else(|| failure(ProtocolError::ScopeUnavailable))?;
            let image = context
                .blobs
                .finish_producer(producer, pixels.png)
                .map_err(|error| failure(blob_error(error)))?;
            handles.push(image.handle.clone());
            let image = json!({"identityScope":identity,"handle":image.handle,"size":image.size,"sha256":image.sha256,"mediaType":"image/png","width":pixels.width,"height":pixels.height,"scale":pixels.scale,"maskedRegionCount":pixels.masked_region_count});
            if value.is_null() {
                value = image;
            } else {
                value["maskedRegionCount"] = image["maskedRegionCount"].clone();
                value["pixels"] = image;
            }
        }
        let publish = (|| {
            bounded_result(&value)?;
            check(&capture_context.page, &operation)?;
            if let Some(journal) = &journal {
                journal.check().map_err(protected_error)?;
            }
            let mut refs = self
                .refs
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            check(&capture_context.page, &operation)?;
            publication.commit_refs(publication_kind, revision, &mut refs, staged);
            Ok::<(), ProtocolError>(())
        })();
        if let Err(error) = publish {
            let clean = release_handles(&context.blobs, &context.scope, &handles);
            if !clean {
                capture_context.page.targets.seal();
            }
            return Err(DispatchFailure {
                error,
                identity_scope: identity.clone(),
                cleanup_integrity_lost: !clean,
            });
        }
        Ok(Output { value, handles })
        }.await;
        match outcome {
            Err(mut failure)
                if is_observe
                    && !failure.cleanup_integrity_lost
                    && failure.error == ProtocolError::StaleScope =>
            {
                match document_retirement_proven(&capture_context, &operation).await {
                    Ok(true) => failure.error = ProtocolError::StaleReference,
                    Err(ProtocolError::CleanupFailed) => failure.cleanup_integrity_lost = true,
                    _ => {}
                }
                Err(failure)
            }
            outcome => outcome,
        }
    }
}

/// Classify only an observe failure after its cleanup has finished. A stale
/// capture can also mean layout movement, a retired attempt, or lost inventory
/// authority; none of those is evidence of document replacement.
async fn document_retirement_proven(
    context: &CaptureContext,
    operation: &OperationLease,
) -> Result<bool, ProtocolError> {
    if check(&context.page, operation).is_err() {
        return Ok(false);
    }
    let Ok((revision, targets)) = context.page.targets.inventory() else {
        return Ok(false);
    };
    let page_present = targets.iter().any(|target| {
        target.target_id == context.page.target_id
            && target.session_id == context.page.page_session_id
            && target.kind == "page"
            && target.purpose == Some(TargetPurpose::Application)
    });
    let replaced = if !page_present {
        true
    } else {
        // This recheck consumes only the original operation's remaining budget.
        // Failure to obtain a complete owned inventory is inconclusive, not a
        // reason to convert cancellation or a backend error into NODE_STALE.
        match verified_frames(&context.page, operation).await {
            Ok(current) => retired_document(&context.frames, &current),
            Err(ProtocolError::CleanupFailed) => return Err(ProtocolError::CleanupFailed),
            Err(_) => false,
        }
    };
    Ok(replaced
        && context.page.targets.check_revision(revision).is_ok()
        && check(&context.page, operation).is_ok())
}
fn retired_document(before: &[ObservationFrame], after: &[ObservationFrame]) -> bool {
    before.iter().any(|old| {
        !after.iter().any(|new| {
            old.binding.page_session == new.binding.page_session
                && old.binding.session == new.binding.session
                && old.binding.frame == new.binding.frame
                && old.binding.loader == new.binding.loader
        })
    })
}

#[cfg(feature = "acceptance-faults")]
fn fault_observation_error(error: ProtocolError) -> ObservationError {
    match error {
        ProtocolError::DeadlineExceeded => ObservationError::DeadlineExceeded,
        ProtocolError::Cancelled => ObservationError::Cancelled,
        ProtocolError::StaleScope => ObservationError::StaleReference,
        _ => ObservationError::BackendFailure,
    }
}
/// A timed-out semantic transaction is already restored before entering here.
/// Returned journal retains the new target barrier until the final publication.
async fn fresh_fallback<'a>(
    context: &'a CaptureContext,
    selector: &str,
    refs: &mut RefMap,
    revision: u64,
    operation: &'a OperationLease,
) -> Result<
    (
        Value,
        super::client_capture::MaskedCapture,
        ProtectedReadJournal<'a>,
    ),
    DispatchFailure,
> {
    let observation_cleanup = AtomicBool::new(false);
    let failure = |error: ProtocolError| DispatchFailure {
        cleanup_integrity_lost: error == ProtocolError::CleanupFailed
            || observation_cleanup.load(Ordering::SeqCst),
        error,
        identity_scope: context.page.identity_scope.clone(),
    };
    let mut journal =
        ProtectedReadJournal::begin(&context.page, operation).map_err(|error| DispatchFailure {
            error: protected_error(error.reason),
            identity_scope: error.identity_scope,
            cleanup_integrity_lost: error.cleanup_integrity_lost,
        })?;
    let mut geometry = None;
    let result = async {
        journal.stabilize_animations().await.map_err(protected_error)?;
        let frozen = verified_frames_with_cleanup(&context.page, operation, Some(&observation_cleanup)).await?;
        same_frames(&context.frames, &frozen)?;
        geometry = Some(GeometrySnapshot::capture(&context.page.client, &context.page.page_session_id, &frozen, operation).await.map_err(geometry_error)?);
        let geometry = geometry.as_ref().ok_or(ProtocolError::PolicyDenied)?;
        let root = minimal_document(&context.page, &frozen, refs, operation).await?;
        let viewport_ref = {
            let viewport = refs.try_viewport_ref(&context.page.identity_scope, operation.generation,
                &context.page.page_session_id, revision).map_err(|_| ProtocolError::IdentifierExhausted)?;
            observation::NodeReference { id: format!("@{}", viewport.id), revision: viewport.issuance.revision.to_string() }
        };
        let viewport = viewport(&context.page, operation).await?;
        let pixels = client_capture::capture_under_journal(context, &CaptureRequest { secure_field_selector: selector.to_owned() }, &pixel_lease(operation), &mut journal, geometry).await.map_err(capture_error)?;
        let value = json!({"identityScope":context.page.identity_scope,"revision":revision.to_string(),"root":{"ref":root},
            "viewportRef":viewport_ref,"truncated":true,"treeUnavailable":true,
            "viewport":viewport,"location":main_frame(&frozen)?.url});
        Ok::<_, ProtocolError>((value, pixels))
    }.await;
    if let Err(error) = journal.restore().await {
        return Err(DispatchFailure {
            error: result
                .as_ref()
                .err()
                .cloned()
                .unwrap_or_else(|| protected_error(error.reason)),
            identity_scope: error.identity_scope,
            cleanup_integrity_lost: error.cleanup_integrity_lost
                || observation_cleanup.load(Ordering::SeqCst),
        });
    }
    let (value, pixels) = result.map_err(failure)?;
    if let Some(geometry) = &geometry {
        geometry
            .revalidate(&context.page.client, operation)
            .await
            .map_err(geometry_error)
            .map_err(failure)?;
    }
    journal
        .check()
        .map_err(|error| failure(protected_error(error)))?;
    check(&context.page, operation).map_err(failure)?;
    same_frames(
        &context.frames,
        &verified_frames_with_cleanup(&context.page, operation, Some(&observation_cleanup))
            .await
            .map_err(failure)?,
    )
    .map_err(failure)?;
    if viewport(&context.page, operation).await.map_err(failure)? != value["viewport"] {
        return Err(failure(ProtocolError::StaleScope));
    }
    Ok((value, pixels, journal))
}

fn validate_policy(policy: &ReadPolicy, request: &DispatchRequest) -> Result<(), ProtocolError> {
    if policy.test_id_attribute.is_empty()
        || policy.test_id_attribute.len() > 256
        || policy.secure_field_selector.is_empty()
        || policy.secure_field_selector.len() > 8192
    {
        return Err(ProtocolError::PolicyDenied);
    }
    let matches = match request {
        DispatchRequest::Correlate(_) => true,
        DispatchRequest::Observe(request) => {
            policy.test_id_attribute == request.test_id_attribute
                && policy.secure_field_selector == request.secure_field_selector
        }
        DispatchRequest::Query(request) => {
            policy.test_id_attribute == request.options.test_id_attribute
                && policy.secure_field_selector == request.options.secure_field_selector
        }
        DispatchRequest::Screenshot(request) => {
            policy.secure_field_selector == request.secure_field_selector
        }
    };
    if !matches {
        return Err(ProtocolError::PolicyDenied);
    }
    Ok(())
}
/// Leave room for correlation/outcome metadata without allocating a second
/// unbounded serialized copy. Query matches are never silently discarded.
fn bounded_result(value: &Value) -> Result<(), ProtocolError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.0 {
                return Err(std::io::Error::other("native result bound exceeded"));
            }
            self.0 -= bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(
        Counter(super::client_protocol::MAX_FRAME_BYTES - 16 * 1024),
        value,
    )
    .map_err(|_| ProtocolError::CapacityExceeded)
}
fn release_handles(blobs: &BlobStore, scope: &BlobScope, handles: &[String]) -> bool {
    let mut clean = true;
    for handle in handles {
        clean &= blobs.release(scope, handle).is_ok();
    }
    clean
}
fn blob_error(error: BlobError) -> ProtocolError {
    match error {
        BlobError::QuotaExceeded => ProtocolError::CapacityExceeded,
        BlobError::StaleScope | BlobError::Closed => ProtocolError::StaleScope,
        _ => ProtocolError::BrowserFailure,
    }
}
fn check(page: &BrowserExecutionLease, operation: &OperationLease) -> Result<(), ProtocolError> {
    page.permit.check()?;
    if *operation.cancellation.borrow() != CancelSignal::None {
        return Err(ProtocolError::Cancelled);
    }
    if Instant::now() >= operation.deadline {
        return Err(ProtocolError::DeadlineExceeded);
    }
    Ok(())
}
async fn command(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    session: &str,
    method: &str,
    args: Value,
) -> Result<Value, ProtocolError> {
    check(page, operation)?;
    let mut cancellation = operation.cancellation.clone();
    tokio::select! {
        result = page.client.send_command(method, Some(args), Some(session)) => { check(page, operation)?; result.map_err(|_| ProtocolError::BrowserFailure) },
        _ = cancellation.changed() => Err(ProtocolError::Cancelled),
        _ = tokio::time::sleep_until(operation.deadline.into()) => Err(ProtocolError::DeadlineExceeded),
    }
}
/// Derive frame/session ownership from native session evidence, never from the
/// commonly equal but non-contractual target ID and frame ID strings.
pub async fn verified_frames(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
) -> Result<Vec<ObservationFrame>, ProtocolError> {
    verified_frames_with_cleanup(page, operation, None).await
}
async fn verified_frames_with_cleanup(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    cleanup: Option<&AtomicBool>,
) -> Result<Vec<ObservationFrame>, ProtocolError> {
    check(page, operation)?;
    let (revision, targets) = page.targets.inventory()?;
    let main = targets
        .iter()
        .find(|target| {
            target.target_id == page.target_id
                && target.session_id == page.page_session_id
                && target.kind == "page"
                && target.purpose == Some(TargetPurpose::Application)
        })
        .ok_or(ProtocolError::StaleScope)?;
    if !main.resumed {
        return Err(ProtocolError::ScopeUnavailable);
    }
    let mut sessions = HashSet::new();
    let mut trees = Vec::new();
    for target in &targets {
        if target.purpose != Some(TargetPurpose::Application) {
            // State-bootstrap targets have independent ownership and cannot
            // establish application frame ancestry.
            continue;
        }
        if !target.configured || !target.resumed {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if !sessions.insert(target.session_id.clone()) {
            return Err(ProtocolError::StaleScope);
        }
        if !matches!(target.kind.as_str(), "page" | "iframe") {
            continue;
        }
        let tree = command(
            page,
            operation,
            &target.session_id,
            "Page.getFrameTree",
            json!({}),
        )
        .await?;
        trees.push((target.session_id.clone(), target.kind == "page", tree));
    }
    let lineage = page_lineage(&trees, &page.page_session_id)?;
    let mapping = lineage.iframe_sessions;
    let frames =
        observation::enumerate_frames(&page.client, &page.page_session_id, &mapping, operation)
            .await
            .map_err(|error| match cleanup {
                Some(cleanup) => observation_error_with_cleanup(error, cleanup),
                None => observation_error(error),
            })?;
    let root = main_frame(&frames)?;
    if root.binding.session != page.page_session_id {
        return Err(ProtocolError::StaleScope);
    }
    let mut ids = HashSet::new();
    for frame in &frames {
        if frame.binding.page_session != page.page_session_id
            || frame.binding.loader.is_empty()
            || !sessions.contains(&frame.binding.session)
            || !ids.insert(frame.binding.frame.clone())
        {
            return Err(ProtocolError::StaleScope);
        }
        if let Some(parent) = &frame.parent_frame_id {
            if !frames
                .iter()
                .any(|candidate| &candidate.binding.frame == parent)
            {
                return Err(ProtocolError::StaleScope);
            }
        }
    }
    if frames.len() != lineage.parents.len()
        || frames
            .iter()
            .any(|frame| lineage.parents.get(&frame.binding.frame) != Some(&frame.parent_frame_id))
    {
        return Err(ProtocolError::StaleScope);
    }
    for (frame, session) in mapping {
        if !frames.iter().any(|candidate| {
            candidate.binding.frame == frame
                && candidate.binding.session == session
                && candidate.parent_frame_id.is_some()
        }) {
            return Err(ProtocolError::UnsupportedCapability);
        }
    }
    page.targets.check_revision(revision)?;
    check(page, operation)?;
    Ok(frames)
}
/// Page roots and renderer roots are different identities. Merge exact native
/// parent edges first, then attribute every renderer root to one owned page.
struct PageLineage {
    iframe_sessions: HashMap<String, String>,
    parents: HashMap<String, Option<String>>,
}
fn page_lineage(
    trees: &[(String, bool, Value)],
    active_session: &str,
) -> Result<PageLineage, ProtocolError> {
    let mut parents: HashMap<String, String> = HashMap::new();
    let mut nodes = HashSet::new();
    let mut pages = HashMap::new();
    let mut renderers = HashMap::new();
    let mut active_root = None;
    let mut visits = 0usize;
    for (session, is_page, tree) in trees {
        let root = tree.get("frameTree").ok_or(ProtocolError::BrowserFailure)?;
        let root_id = root["frame"]["id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or(ProtocolError::BrowserFailure)?;
        if *is_page {
            if pages.insert(root_id.to_owned(), session.clone()).is_some() {
                return Err(ProtocolError::StaleScope);
            }
            if session == active_session {
                active_root = Some(root_id.to_owned());
            }
        } else if renderers
            .insert(root_id.to_owned(), session.clone())
            .is_some()
        {
            return Err(ProtocolError::StaleScope);
        }
        let mut pending = vec![(root, None::<&str>, 0usize)];
        let mut seen = HashSet::new();
        while let Some((node, nested_parent, depth)) = pending.pop() {
            visits += 1;
            if visits > 100_000 || depth > 256 {
                return Err(ProtocolError::UnsupportedCapability);
            }
            let id = node["frame"]["id"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or(ProtocolError::BrowserFailure)?;
            if !seen.insert(id) {
                return Err(ProtocolError::StaleScope);
            }
            nodes.insert(id.to_owned());
            let explicit = match node["frame"].get("parentId") {
                None => None,
                Some(v) => Some(
                    v.as_str()
                        .filter(|s| !s.is_empty())
                        .ok_or(ProtocolError::BrowserFailure)?,
                ),
            };
            if nested_parent.is_some() && explicit.is_some() && nested_parent != explicit {
                return Err(ProtocolError::StaleScope);
            }
            if let Some(parent) = nested_parent.or(explicit) {
                if parent == id
                    || parents
                        .insert(id.to_owned(), parent.to_owned())
                        .is_some_and(|old| old != parent)
                {
                    return Err(ProtocolError::StaleScope);
                }
            }
            if let Some(children) = node.get("childFrames") {
                for child in children.as_array().ok_or(ProtocolError::BrowserFailure)? {
                    pending.push((child, Some(id), depth + 1));
                }
            }
        }
    }
    let active_root = active_root.ok_or(ProtocolError::StaleScope)?;
    if pages
        .keys()
        .any(|id| parents.contains_key(id) || renderers.contains_key(id))
    {
        return Err(ProtocolError::StaleScope);
    }
    let mut owners = HashMap::new();
    for id in &nodes {
        let mut current = id;
        let mut seen = HashSet::new();
        loop {
            if !seen.insert(current) || seen.len() > 256 {
                return Err(ProtocolError::StaleScope);
            }
            if pages.contains_key(current) {
                owners.insert(id.clone(), current.clone());
                break;
            }
            current = parents
                .get(current)
                .filter(|parent| nodes.contains(*parent))
                .ok_or(ProtocolError::StaleScope)?;
        }
    }
    Ok(PageLineage {
        iframe_sessions: renderers
            .into_iter()
            .filter(|(id, _)| owners.get(id) == Some(&active_root))
            .collect(),
        parents: nodes
            .into_iter()
            .filter(|id| owners.get(id) == Some(&active_root))
            .map(|id| {
                let parent = parents.get(&id).cloned();
                (id, parent)
            })
            .collect(),
    })
}
fn main_frame(frames: &[ObservationFrame]) -> Result<&ObservationFrame, ProtocolError> {
    let mut roots = frames
        .iter()
        .filter(|frame| frame.parent_frame_id.is_none());
    let root = roots.next().ok_or(ProtocolError::BrowserFailure)?;
    if roots.next().is_some() {
        return Err(ProtocolError::BrowserFailure);
    }
    Ok(root)
}
fn same_frames(
    before: &[ObservationFrame],
    after: &[ObservationFrame],
) -> Result<(), ProtocolError> {
    if before.len() != after.len()
        || before.iter().any(|a| {
            !after.iter().any(|b| {
                a.binding.page_session == b.binding.page_session
                    && a.binding.session == b.binding.session
                    && a.binding.frame == b.binding.frame
                    && a.binding.loader == b.binding.loader
                    && a.parent_frame_id == b.parent_frame_id
                    && a.owner_backend_id == b.owner_backend_id
                    // Location is projected from this transaction too. A
                    // same-document navigation need not change its loader.
                    && a.url == b.url
            })
        })
    {
        return Err(ProtocolError::StaleScope);
    }
    Ok(())
}
fn exact_root(
    mut roots: Vec<SemanticNode>,
    refs: &RefMap,
    frames: &[ObservationFrame],
) -> Result<SemanticNode, ProtocolError> {
    if roots.len() != 1 {
        return Err(ProtocolError::BrowserFailure);
    }
    let root = roots.remove(0);
    let main = main_frame(frames)?;
    let entry = parse_ref(&root.reference.id)
        .and_then(|id| refs.get(&id))
        .ok_or(ProtocolError::StaleReference)?;
    let binding = entry
        .exact_binding
        .as_ref()
        .ok_or(ProtocolError::StaleReference)?;
    if root.role.as_deref() != Some("document")
        || entry.backend_node_id.is_none()
        || binding.page_session != main.binding.page_session
        || binding.session != main.binding.session
        || binding.frame != main.binding.frame
        || binding.loader != main.binding.loader
    {
        return Err(ProtocolError::StaleReference);
    }
    Ok(root)
}
async fn verify_document_root(
    page: &BrowserExecutionLease,
    root: &SemanticNode,
    refs: &RefMap,
    operation: &OperationLease,
) -> Result<(), ProtocolError> {
    let backend = parse_ref(&root.reference.id)
        .and_then(|id| refs.get(&id))
        .and_then(|entry| entry.backend_node_id)
        .ok_or(ProtocolError::StaleReference)?;
    let value = command(
        page,
        operation,
        &page.page_session_id,
        "DOM.getDocument",
        json!({"depth":0,"pierce":false}),
    )
    .await?;
    if value["root"]["nodeType"].as_i64() != Some(9)
        || value["root"]["backendNodeId"].as_i64() != Some(backend)
    {
        return Err(ProtocolError::StaleReference);
    }
    Ok(())
}
async fn minimal_document(
    page: &BrowserExecutionLease,
    frames: &[ObservationFrame],
    refs: &mut RefMap,
    operation: &OperationLease,
) -> Result<observation::NodeReference, ProtocolError> {
    let main = main_frame(frames)?;
    let value = command(
        page,
        operation,
        &main.binding.session,
        "DOM.getDocument",
        json!({"depth":0,"pierce":false}),
    )
    .await?;
    let document = &value["root"];
    if document["nodeType"].as_i64() != Some(9) {
        return Err(ProtocolError::BrowserFailure);
    }
    let backend = document["backendNodeId"]
        .as_i64()
        .filter(|id| *id > 0)
        .ok_or(ProtocolError::BrowserFailure)?;
    let reference = refs
        .try_bind_exact(backend, "document", "", main.binding.clone())
        .map_err(|_| ProtocolError::IdentifierExhausted)?;
    Ok(observation::NodeReference {
        id: format!("@{reference}"),
        revision: refs
            .get(&reference)
            .and_then(|entry| entry.issued_revision())
            .ok_or(ProtocolError::StaleReference)?
            .to_string(),
    })
}
async fn viewport(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
) -> Result<Value, ProtocolError> {
    let metrics = command(
        page,
        operation,
        &page.page_session_id,
        "Page.getLayoutMetrics",
        json!({}),
    )
    .await?;
    let viewport = &metrics["cssVisualViewport"];
    let width = viewport["clientWidth"]
        .as_f64()
        .filter(|n| n.is_finite() && *n > 0.0)
        .ok_or(ProtocolError::BrowserFailure)?;
    let height = viewport["clientHeight"]
        .as_f64()
        .filter(|n| n.is_finite() && *n > 0.0)
        .ok_or(ProtocolError::BrowserFailure)?;
    Ok(json!({"width":width,"height":height}))
}
fn pixel_lease(operation: &OperationLease) -> OperationLease {
    let remaining = operation.deadline.saturating_duration_since(Instant::now());
    let reserve = (remaining / 5).min(Duration::from_millis(500));
    OperationLease {
        is_callback: operation.is_callback,
        generation: operation.generation,
        sequence: operation.sequence,
        deadline: operation.deadline - reserve,
        cancellation: operation.cancellation.clone(),
    }
}
fn semantic_lease(operation: &OperationLease, fallback: bool) -> OperationLease {
    semantic_lease_at(operation, fallback, Instant::now())
}
fn semantic_lease_at(operation: &OperationLease, fallback: bool, now: Instant) -> OperationLease {
    let remaining = operation.deadline.saturating_duration_since(now);
    let reserve = if fallback {
        // Preserve the original reader budget: reserve one quarter, capped at
        // two seconds, for a fresh masked capture after semantic timeout.
        (remaining / 4).min(Duration::from_secs(2))
    } else {
        Duration::ZERO
    };
    OperationLease {
        is_callback: operation.is_callback,
        generation: operation.generation,
        sequence: operation.sequence,
        deadline: operation.deadline - reserve,
        cancellation: operation.cancellation.clone(),
    }
}
fn observation_error_with_cleanup(error: ObservationError, cleanup: &AtomicBool) -> ProtocolError {
    match error {
        ObservationError::CleanupFailed { primary } => {
            cleanup.store(true, Ordering::SeqCst);
            primary
                .map(|error| observation_error_with_cleanup(*error, cleanup))
                .unwrap_or(ProtocolError::CleanupFailed)
        }
        error => observation_error(error),
    }
}
fn observation_error(error: ObservationError) -> ProtocolError {
    match error {
        ObservationError::ResourceLimit => ProtocolError::CapacityExceeded,
        ObservationError::CleanupFailed { .. } => ProtocolError::CleanupFailed,
        ObservationError::InvalidArguments => ProtocolError::InvalidArguments,
        ObservationError::StaleReference => ProtocolError::StaleReference,
        ObservationError::Cancelled => ProtocolError::Cancelled,
        ObservationError::DeadlineExceeded => ProtocolError::DeadlineExceeded,
        ObservationError::BackendFailure => ProtocolError::BrowserFailure,
        ObservationError::PolicyDenied => ProtocolError::PolicyDenied,
    }
}
fn protected_error(error: ProtectedReadReason) -> ProtocolError {
    match error {
        ProtectedReadReason::Cancelled => ProtocolError::Cancelled,
        ProtectedReadReason::Deadline => ProtocolError::DeadlineExceeded,
        ProtectedReadReason::StaleScope => ProtocolError::StaleScope,
        ProtectedReadReason::IncompleteInventory => ProtocolError::ScopeUnavailable,
        ProtectedReadReason::BrowserFailure => ProtocolError::BrowserFailure,
    }
}
fn geometry_error_with_cleanup(
    error: super::client_geometry::GeometryError,
    cleanup: &AtomicBool,
) -> ProtocolError {
    match error {
        super::client_geometry::GeometryError::CleanupFailed { primary } => {
            cleanup.store(true, Ordering::SeqCst);
            primary
                .map(|error| geometry_error_with_cleanup(*error, cleanup))
                .unwrap_or(ProtocolError::CleanupFailed)
        }
        error => geometry_error(error),
    }
}
fn geometry_error(error: super::client_geometry::GeometryError) -> ProtocolError {
    capture_error(client_capture::geometry_reason(error))
}
fn capture_error(error: CaptureReason) -> ProtocolError {
    match error {
        CaptureReason::CleanupFailed => ProtocolError::CleanupFailed,
        CaptureReason::Cancelled => ProtocolError::Cancelled,
        CaptureReason::Deadline => ProtocolError::DeadlineExceeded,
        CaptureReason::StaleScope => ProtocolError::StaleScope,
        CaptureReason::BrowserFailure => ProtocolError::BrowserFailure,
        CaptureReason::BoundsExceeded => ProtocolError::CapacityExceeded,
        CaptureReason::IncompleteFrames
        | CaptureReason::UnsafeGeometry
        | CaptureReason::UninspectableContent
        | CaptureReason::MaskingUnproven => ProtocolError::PolicyDenied,
    }
}

#[cfg(test)]
mod tests {
    use super::super::element::ExactBinding;
    use super::*;
    #[test]
    fn observation_cleanup_preserves_primary_without_authorizing_fallback() {
        let cleanup = AtomicBool::new(false);
        let error = observation_error_with_cleanup(
            ObservationError::CleanupFailed {
                primary: Some(Box::new(ObservationError::DeadlineExceeded)),
            },
            &cleanup,
        );
        assert_eq!(error, ProtocolError::DeadlineExceeded);
        assert!(cleanup.load(Ordering::SeqCst));
        // Fallback matches the original observation variant, never this mapped error.
        assert_eq!(
            observation_error(ObservationError::ResourceLimit),
            ProtocolError::CapacityExceeded
        );
        assert_eq!(
            observation_error(ObservationError::CleanupFailed { primary: None }),
            ProtocolError::CleanupFailed
        );
    }
    fn lineage_tree(id: &str, parent: Option<&str>, children: Vec<Value>) -> Value {
        let mut frame = json!({"id":id});
        if let Some(parent) = parent {
            frame["parentId"] = json!(parent);
        }
        json!({"frameTree":{"frame":frame,"childFrames":children}})
    }
    #[test]
    fn page_lineage_excludes_only_proven_other_tab_renderers() {
        let child = |id| json!({"frame":{"id":id}});
        let trees = vec![
            (
                "page-a".into(),
                true,
                lineage_tree("a", None, vec![child("remote-a")]),
            ),
            (
                "page-b".into(),
                true,
                lineage_tree("b", None, vec![child("remote-b")]),
            ),
            (
                "session-a".into(),
                false,
                lineage_tree(
                    "remote-a",
                    Some("a"),
                    vec![child("local-a"), child("nested-a")],
                ),
            ),
            (
                "session-nested".into(),
                false,
                lineage_tree("nested-a", Some("remote-a"), vec![]),
            ),
            (
                "session-b".into(),
                false,
                lineage_tree("remote-b", Some("b"), vec![]),
            ),
        ];
        let result = page_lineage(&trees, "page-a").unwrap();
        assert_eq!(result.iframe_sessions.len(), 2);
        assert_eq!(result.iframe_sessions.get("remote-a").unwrap(), "session-a");
        assert_eq!(
            result.iframe_sessions.get("nested-a").unwrap(),
            "session-nested"
        );
        assert_eq!(result.parents.len(), 4);
        assert_eq!(
            result.parents.get("local-a"),
            Some(&Some("remote-a".into()))
        );
        assert!(!result.parents.contains_key("b"));
    }
    #[test]
    fn page_lineage_rejects_ambiguous_foreign_and_incomplete_edges() {
        let page = ("page".into(), true, lineage_tree("root", None, vec![]));
        for bad in [
            lineage_tree("child", None, vec![]),
            lineage_tree("child", Some("foreign"), vec![]),
            lineage_tree("child", Some("child"), vec![]),
            lineage_tree("root", None, vec![]),
        ] {
            assert!(page_lineage(&[page.clone(), ("remote".into(), false, bad)], "page").is_err());
        }
        let conflicting = vec![
            (
                "page".into(),
                true,
                lineage_tree("root", None, vec![json!({"frame":{"id":"child"}})]),
            ),
            (
                "other".into(),
                true,
                lineage_tree("other-root", None, vec![]),
            ),
            (
                "remote".into(),
                false,
                lineage_tree("child", Some("other-root"), vec![]),
            ),
        ];
        assert!(page_lineage(&conflicting, "page").is_err());
    }
    #[test]
    fn page_lineage_requires_unique_root_sessions_and_valid_tree_shape() {
        let duplicate = vec![
            ("page".into(), true, lineage_tree("root", None, vec![])),
            ("other".into(), true, lineage_tree("root", None, vec![])),
        ];
        assert!(page_lineage(&duplicate, "page").is_err());
        let malformed = vec![(
            "page".into(),
            true,
            json!({"frameTree":{"frame":{"id":"root"},"childFrames":null}}),
        )];
        assert!(page_lineage(&malformed, "page").is_err());
    }
    fn frame(id: &str, parent: Option<&str>) -> ObservationFrame {
        ObservationFrame {
            parent_frame_id: parent.map(str::to_owned),
            owner_backend_id: parent.map(|_| 2),
            url: "https://fixture.invalid/".into(),
            binding: ExactBinding {
                page_session: "page-session".into(),
                session: "page-session".into(),
                frame: id.into(),
                loader: "loader".into(),
                actionable: false,
            },
            offset_x: 0.0,
            offset_y: 0.0,
            frame_path: Vec::new(),
        }
    }
    #[test]
    fn retirement_proof_requires_loss_of_an_existing_exact_document() {
        let old = vec![frame("main", None), frame("child", Some("main"))];
        let mut current = old.clone();
        current[0].offset_x = 100.0;
        current[0].url.push_str("#same-document");
        assert!(!retired_document(&old, &current));
        current.push(frame("new-child", Some("main")));
        assert!(!retired_document(&old, &current));
        current[1].binding.loader = "replacement-loader".into();
        assert!(retired_document(&old, &current));
        assert!(retired_document(&old, &old[..1]));
        let mut replacement = old.clone();
        replacement[0].binding.session = "replacement-session".into();
        assert!(retired_document(&old, &replacement));
        assert!(!retired_document(&[], &old));
    }
    fn operation() -> OperationLease {
        let (_send, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 7,
            deadline: Instant::now() + Duration::from_secs(8),
            cancellation,
        }
    }
    #[tokio::test]
    async fn abandoned_rpc_keeps_ui_exclusive_until_restore_and_reports_dirty_cleanup() {
        use super::super::cdp::client::CdpClient;
        use super::super::client_browser::ExecutionGate;
        use super::super::client_targets::ClientTargets;
        use futures_util::{SinkExt, StreamExt};
        for fail_restore in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let (restoring_send, restoring_receive) = oneshot::channel();
            let (release_send, release_receive) = oneshot::channel();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut restoring_send = Some(restoring_send);
                let mut release_receive = Some(release_receive);
                while let Some(Ok(message)) = socket.next().await {
                    let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                    let result = match request["method"].as_str().unwrap() {
                        "Page.getFrameTree" => {
                            json!({"frameTree":{"frame":{"id":"frame","loaderId":"loader","url":"https://fixture.invalid/"}}})
                        }
                        "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                        "Animation.getPlaybackRate" => json!({"playbackRate":1}),
                        _ => json!({}),
                    };
                    let mut response = json!({"id":request["id"],"sessionId":request["sessionId"],"result":result});
                    assert_ne!(request["method"], "Page.setWebLifecycleState");
                    // Hold the exact saved-rate restoration ACK, not the removed
                    // lifecycle activation command. JSON encodes this f64 as 1.0.
                    if request["method"] == "Animation.setPlaybackRate"
                        && request["params"]["playbackRate"].as_f64() == Some(1.0)
                    {
                        if let Some(send) = restoring_send.take() {
                            let _ = send.send(());
                        }
                        if let Some(release) = release_receive.take() {
                            let _ = release.await;
                        }
                        if fail_restore {
                            response.as_object_mut().unwrap().remove("result");
                            response["error"] =
                                json!({"code":-32000,"message":"synthetic restore failure"});
                        }
                    }
                    if socket
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            response.to_string(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let client = Arc::new(CdpClient::connect(&url).await.unwrap());
            let targets = ClientTargets::new("context".into(), "scope".into());
            targets
                .attached("context", "target".into(), "session".into(), "page".into())
                .unwrap();
            targets.configured("target").unwrap();
            targets
                .resume_permit("target")
                .await
                .unwrap()
                .complete()
                .unwrap();
            targets.acknowledge_enrollment().unwrap(); // Exact synthetic single-page fixture only.
            let gate = Arc::new(ExecutionGate::default());
            let page = BrowserExecutionLease {
                client,
                page_session_id: "session".into(),
                target_id: "target".into(),
                identity_scope: "scope".into(),
                permit: gate.enter(false).unwrap(),
                targets: targets.clone(),
            };
            let ui = Arc::new(UiGate::default());
            let blobs = Arc::new(BlobStore::new(Default::default()).unwrap());
            let scope = BlobScope {
                generation: 1,
                identity_scope: "scope".into(),
            };
            blobs.activate_scope(scope.clone()).unwrap();
            let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let operation = OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline: Instant::now() + Duration::from_secs(5),
                cancellation: cancellation.clone(),
            };
            let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
            let task = dispatch.start(
                DispatchContext {
                    #[cfg(feature = "acceptance-faults")]
                    faults: Arc::new(super::super::client_test_faults::FaultController::default()),
                    page,
                    ui: ui.clone(),
                    blobs,
                    scope,
                    policy: ReadPolicy {
                        test_id_attribute: "data-testid".into(),
                        secure_field_selector: "input[type=password]".into(),
                    },
                },
                DispatchRequest::Screenshot(CaptureRequest {
                    secure_field_selector: "input[type=password]".into(),
                }),
                operation,
            );
            drop(task.result);
            tokio::time::timeout(Duration::from_secs(2), restoring_receive)
                .await
                .unwrap()
                .unwrap();
            assert!(!task.join.is_finished());
            assert!(tokio::time::timeout(
                Duration::from_millis(10),
                ui.enter(
                    false,
                    false,
                    Instant::now() + Duration::from_secs(1),
                    cancellation.clone()
                )
            )
            .await
            .is_err());
            release_send.send(()).unwrap();
            let settled = task.join.await.unwrap();
            if fail_restore {
                assert!(settled.unwrap_err().cleanup_integrity_lost);
                assert!(targets.inventory().is_err());
            } else {
                settled.unwrap();
                assert!(targets.inventory().is_ok());
            }
            ui.enter(
                false,
                false,
                Instant::now() + Duration::from_secs(1),
                cancellation,
            )
            .await
            .unwrap();
            server.abort();
        }
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn semantic_only_timeout_never_mutates_lifecycle_and_fallback_stabilizes_separately() {
        for (pixels, fallback) in [(false, false), (false, true), (true, true)] {
            semantic_timeout_fallback_admission(pixels, fallback, "available").await;
        }
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn actual_semantic_timeout_requires_admission_before_fallback_capture() {
        semantic_timeout_fallback_admission(false, true, "occupied").await;
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn fallback_capture_refusal_releases_admitted_producer_after_restore() {
        semantic_timeout_fallback_admission(false, true, "capture-refused").await;
    }
    #[cfg(feature = "acceptance-faults")]
    #[tokio::test]
    async fn fallback_dirty_restore_releases_admitted_producer_without_publishing() {
        semantic_timeout_fallback_admission(false, true, "dirty-restore").await;
    }
    #[cfg(feature = "acceptance-faults")]
    async fn semantic_timeout_fallback_admission(pixels: bool, fallback: bool, mode: &'static str) {
        use super::super::cdp::client::CdpClient;
        use super::super::client_blobs::BlobLimits;
        use super::super::client_browser::ExecutionGate;
        use super::super::client_targets::ClientTargets;
        use super::super::client_test_faults::{FaultController, Phase, State};
        use base64::Engine;
        use futures_util::{SinkExt, StreamExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let lifecycle = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = lifecycle.clone();
        let animation_commands = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let animation_log = animation_commands.clone();
        let source_commands = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let source_log = source_commands.clone();
        let captures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let capture_log = captures.clone();
        let blobs = Arc::new(
            BlobStore::new(BlobLimits {
                max_blob_bytes: 4096,
                max_total_bytes: 8192,
                max_handles: 8,
            })
            .unwrap(),
        );
        let scope = BlobScope {
            generation: 1,
            identity_scope: "scope".into(),
        };
        blobs.activate_scope(scope.clone()).unwrap();
        let retained = blobs.insert_sealed(scope.clone(), b"r").unwrap();
        let live_producer = if mode == "occupied" {
            Some(blobs.reserve_producer(scope.clone()).unwrap())
        } else {
            None
        };
        if live_producer.is_some() {
            assert!(matches!(
                blobs.reserve_producer(scope.clone()),
                Err(BlobError::QuotaExceeded)
            ));
        }
        let budget_changes = blobs.budget_changes().unwrap();
        let capture_blobs = blobs.clone();
        let capture_scope = scope.clone();
        let mut bytes = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgba8(10, 10)
            .write_to(&mut bytes, image::ImageFormat::Png)
            .unwrap();
        let png = base64::engine::general_purpose::STANDARD.encode(bytes.into_inner());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                if request["method"]
                    .as_str()
                    .is_some_and(|method| method.starts_with("Animation."))
                {
                    animation_log.fetch_add(1, Ordering::SeqCst);
                }
                if request["method"] == "Page.setWebLifecycleState" {
                    log.lock()
                        .unwrap()
                        .push(request["params"]["state"].as_str().unwrap().into());
                }
                if matches!(
                    request["method"].as_str(),
                    Some(
                        "Animation.enable"
                            | "DOMSnapshot.captureSnapshot"
                            | "Page.captureScreenshot"
                    )
                ) {
                    assert!(
                        matches!(
                            capture_blobs.reserve_producer(capture_scope.clone()),
                            Err(BlobError::QuotaExceeded)
                        ),
                        "pixel stabilization and capture must follow producer admission"
                    );
                }
                let result = match request["method"].as_str().unwrap() {
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"frame","loaderId":"loader","url":"https://fixture.invalid/"}}})
                    }
                    "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                    "Animation.getPlaybackRate" => json!({"playbackRate":1}),
                    "Page.getLayoutMetrics" => {
                        json!({"cssVisualViewport":{"clientWidth":10,"clientHeight":10,"scale":1,"offsetX":0,"offsetY":0},"cssLayoutViewport":{"clientWidth":10,"clientHeight":10}})
                    }
                    "DOM.getDocument" => json!({"root":{"nodeType":9,"backendNodeId":1}}),
                    "DOMSnapshot.captureSnapshot" => {
                        json!({"strings":["frame"],"documents":[{"frameId":0,"nodes":{"nodeType":[],"backendNodeId":[]}}]})
                    }
                    "Runtime.evaluate" => {
                        // This peer has an empty DOM inventory. Its only evaluate is
                        // the source-mask holder factory, never an arbitrary script.
                        assert_eq!(request["params"]["contextId"], 1);
                        assert!(request["params"]["objectGroup"]
                            .as_str()
                            .unwrap()
                            .starts_with("capture-source-"));
                        source_log.lock().unwrap().push("holder");
                        json!({"result":{"type":"object","objectId":"source-holder"}})
                    }
                    "Runtime.callFunctionOn" => {
                        assert_eq!(request["params"]["objectId"], "source-holder");
                        let phase = match request["params"]["functionDeclaration"].as_str().unwrap()
                        {
                            "function(){return this.verify()}" => "verify",
                            "function(){return this.remove()}" => "remove",
                            other => panic!("unexpected source holder method: {other}"),
                        };
                        assert_eq!(request["params"]["returnByValue"], true);
                        assert!(request["params"]["objectGroup"]
                            .as_str()
                            .unwrap()
                            .starts_with("capture-source-"));
                        source_log.lock().unwrap().push(phase);
                        json!({"result":{"type":"boolean","value":true}})
                    }
                    "Runtime.releaseObjectGroup"
                        if request["params"]["objectGroup"]
                            .as_str()
                            .is_some_and(|group| group.starts_with("capture-source-")) =>
                    {
                        source_log.lock().unwrap().push("release");
                        json!({})
                    }
                    "Page.captureScreenshot" => {
                        capture_log.fetch_add(1, Ordering::SeqCst);
                        json!({"data":png})
                    }
                    _ => json!({}),
                };
                let refused = mode == "capture-refused"
                    && request["method"] == "Page.captureScreenshot"
                    || mode == "dirty-restore"
                        && request["method"] == "Animation.setPlaybackRate"
                        && request["params"]["playbackRate"].as_f64() == Some(1.0);
                let response = if refused {
                    json!({"id":request["id"],"sessionId":request["sessionId"],"error":{"code":-32000,"message":"synthetic capture or restore refusal"}})
                } else {
                    json!({"id":request["id"],"sessionId":request["sessionId"],"result":result})
                };
                if socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        response.to_string(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        let targets = ClientTargets::new("context".into(), "scope".into());
        targets
            .attached("context", "target".into(), "session".into(), "page".into())
            .unwrap();
        targets.configured("target").unwrap();
        targets
            .resume_permit("target")
            .await
            .unwrap()
            .complete()
            .unwrap();
        // The boundary under test is Dispatch.start, not enrollment startup.
        targets.acknowledge_enrollment().unwrap();
        let gate = Arc::new(ExecutionGate::default());
        let page = BrowserExecutionLease {
            client,
            page_session_id: "session".into(),
            target_id: "target".into(),
            identity_scope: "scope".into(),
            permit: gate.enter(false).unwrap(),
            targets: targets.clone(),
        };
        let faults = Arc::new(FaultController::default());
        let token = faults.arm("scope", Phase::SemanticAcquire).unwrap();
        let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline: Instant::now() + Duration::from_millis(2000),
            cancellation,
        };
        let refs = Arc::new(Mutex::new(RefMap::new()));
        let dispatch = ObservationDispatch::new(refs.clone());
        let task = dispatch.clone().start(
            DispatchContext {
                faults: faults.clone(),
                page,
                ui: Arc::new(UiGate::default()),
                blobs: blobs.clone(),
                scope: scope.clone(),
                policy: ReadPolicy {
                    test_id_attribute: "data-testid".into(),
                    secure_field_selector: "input[type=password]".into(),
                },
            },
            DispatchRequest::Observe(ObserveRequest {
                options: ObserveFlags {
                    pixels,
                    pixel_fallback: fallback,
                    comparable: false,
                },
                test_id_attribute: "data-testid".into(),
                secure_field_selector: "input[type=password]".into(),
            }),
            operation,
        );
        let output = task.result.await.unwrap();
        task.join.await.unwrap().unwrap();
        assert_eq!(
            faults.status("scope", &token).unwrap().state,
            State::Expired,
            "the actual semantic deadline must expire before fallback admission"
        );
        assert_eq!(blobs.read(&scope, &retained.handle, 0, 1).unwrap(), b"r");
        if mode == "occupied" {
            let error = output.unwrap_err();
            assert_eq!(error.error, ProtocolError::CapacityExceeded);
            assert!(!error.cleanup_integrity_lost);
            assert!(refs.lock().unwrap().ref_ids().is_empty());
            assert_eq!(dispatch.publication.lock().await.published_revision, 0);
            assert_eq!(animation_commands.load(Ordering::SeqCst), 0);
            assert!(source_commands.lock().unwrap().is_empty());
            assert_eq!(captures.load(Ordering::SeqCst), 0);
            assert!(lifecycle.lock().unwrap().is_empty());
            assert!(!budget_changes.has_changed().unwrap());
            assert!(matches!(
                blobs.reserve_producer(scope.clone()),
                Err(BlobError::QuotaExceeded)
            ));
            drop(live_producer);
            let released = blobs.reserve_producer(scope.clone()).unwrap();
            drop(released);
            blobs.release(&scope, &retained.handle).unwrap();
            blobs.check_budget_integrity().unwrap();
            assert!(targets.inventory().is_ok());
            server.abort();
            let _ = server.await;
            return;
        }
        if matches!(mode, "capture-refused" | "dirty-restore") {
            let error = output.unwrap_err();
            assert_eq!(error.error, ProtocolError::BrowserFailure);
            assert_eq!(error.cleanup_integrity_lost, mode == "dirty-restore");
            assert!(refs.lock().unwrap().ref_ids().is_empty());
            assert_eq!(dispatch.publication.lock().await.published_revision, 0);
            assert_eq!(captures.load(Ordering::SeqCst), 1);
            assert_eq!(animation_commands.load(Ordering::SeqCst), 4);
            assert!(lifecycle.lock().unwrap().is_empty());
            let expected = if mode == "capture-refused" {
                vec!["holder", "verify", "remove", "release"]
            } else {
                vec!["holder", "verify", "verify", "remove", "release"]
            };
            assert_eq!(*source_commands.lock().unwrap(), expected);
            assert_eq!(targets.inventory().is_err(), mode == "dirty-restore");
            // Exact maximum reservations prove no unpublished pixel charge
            // remains after clean refusal or dirty cleanup.
            let released = blobs.reserve_producer(scope.clone()).unwrap();
            drop(released);
            blobs.release(&scope, &retained.handle).unwrap();
            let first = blobs.reserve_producer(scope.clone()).unwrap();
            let second = blobs.reserve_producer(scope.clone()).unwrap();
            drop((first, second));
            blobs.check_budget_integrity().unwrap();
            server.abort();
            let _ = server.await;
            return;
        }
        if !fallback {
            assert_eq!(output.unwrap_err().error, ProtocolError::DeadlineExceeded);
            assert!(lifecycle.lock().unwrap().is_empty());
            assert_eq!(animation_commands.load(Ordering::SeqCst), 0);
            assert!(source_commands.lock().unwrap().is_empty());
            assert!(!budget_changes.has_changed().unwrap());
            server.abort();
            let _ = server.await;
            return;
        }
        let output = output.unwrap();
        assert_eq!(output["treeUnavailable"], true);
        let root = output["root"].as_object().expect("fallback root object");
        assert_eq!(
            root.len(),
            1,
            "unavailable tree must serialize only the exact root reference"
        );
        assert!(root.contains_key("ref"));
        assert!(root["ref"]["id"].as_str().unwrap().starts_with("@e"));
        assert_eq!(output["truncated"], true);
        assert_eq!(
            faults.status("scope", &token).unwrap().state,
            State::Expired
        );
        assert!(lifecycle.lock().unwrap().is_empty());
        assert_eq!(
            animation_commands.load(Ordering::SeqCst),
            if pixels { 8 } else { 4 }
        );
        let expected_source_cycle = ["holder", "verify", "verify", "remove", "release"];
        assert_eq!(
                *source_commands.lock().unwrap(),
                expected_source_cycle,
                "the timed-out semantic phase never captures; fresh fallback owns one settled source holder"
            );
        assert_eq!(captures.load(Ordering::SeqCst), 1);
        assert_eq!(output["viewport"], json!({"width":10.0,"height":10.0}));
        assert_eq!(output["pixels"]["width"], 10);
        assert_eq!(output["pixels"]["height"], 10);
        assert_eq!(output["pixels"]["maskedRegionCount"], 0);
        assert_eq!(dispatch.publication.lock().await.published_revision, 1);
        let root_id = root["ref"]["id"].as_str().unwrap();
        assert_eq!(
            refs.lock()
                .unwrap()
                .get(root_id.trim_start_matches('@'))
                .unwrap()
                .backend_node_id,
            Some(1)
        );
        blobs
            .release(&scope, output["pixels"]["handle"].as_str().unwrap())
            .unwrap();
        blobs.release(&scope, &retained.handle).unwrap();
        let first = blobs.reserve_producer(scope.clone()).unwrap();
        let second = blobs.reserve_producer(scope.clone()).unwrap();
        drop((first, second));
        blobs.check_budget_integrity().unwrap();
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn action_snapshot_uses_committed_revision_not_failed_staging_counter() {
        let refs = Arc::new(Mutex::new(RefMap::new()));
        let dispatch = ObservationDispatch::new(refs);
        {
            let mut publication = dispatch.publication.lock().await;
            publication.revision = 9;
            publication.published_revision = 4;
        }
        let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let mut operation = operation();
        operation.cancellation = cancellation;
        assert_eq!(dispatch.snapshot_for_action(&operation).await.unwrap().0, 4);
        let locked = dispatch.publication.lock().await;
        operation.deadline = Instant::now() + Duration::from_millis(5);
        assert!(matches!(
            dispatch.snapshot_for_action(&operation).await,
            Err(ProtocolError::DeadlineExceeded)
        ));
        drop(locked);
    }
    #[tokio::test]
    async fn screenshot_and_additive_query_preserve_action_snapshot_but_observe_replaces_it() {
        let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            cancellation,
            ..operation()
        };
        let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
        let binding = frame("root", None).binding;
        let mut initial = RefMap::new();
        let id = initial
            .try_bind_exact(10, "button", "Public", binding.clone())
            .unwrap();
        let mut publication = dispatch.publication.lock().await;
        let original = publication
            .stage_revision(PublicationKind::Snapshot)
            .unwrap();
        publication.commit_refs(
            PublicationKind::Snapshot,
            original,
            &mut dispatch.refs.lock().unwrap(),
            initial.clone(),
        );
        let pixel_revision = publication
            .stage_revision(PublicationKind::PixelsOnly)
            .unwrap();
        // Even an accidental mutation of the screenshot's private clone must
        // not alter actionable identity or its committed revision.
        let mut pixels = initial.clone();
        pixels.begin_snapshot();
        publication.commit_refs(
            PublicationKind::PixelsOnly,
            pixel_revision,
            &mut dispatch.refs.lock().unwrap(),
            pixels,
        );
        drop(publication);
        let (current, refs) = dispatch.snapshot_for_action(&operation).await.unwrap();
        assert_eq!(current, original);
        assert!(refs.get(&id).is_some());
        let mut publication = dispatch.publication.lock().await;
        let queried = publication
            .stage_revision(PublicationKind::AdditiveQuery)
            .unwrap();
        let mut additive = refs;
        let added = additive
            .try_bind_exact(11, "button", "Second", binding)
            .unwrap();
        publication.commit_refs(
            PublicationKind::AdditiveQuery,
            queried,
            &mut dispatch.refs.lock().unwrap(),
            additive,
        );
        drop(publication);
        let (current, refs) = dispatch.snapshot_for_action(&operation).await.unwrap();
        assert_eq!(current, original);
        assert!(refs.get(&id).is_some() && refs.get(&added).is_some());
        let mut publication = dispatch.publication.lock().await;
        let replacement = publication
            .stage_revision(PublicationKind::Snapshot)
            .unwrap();
        publication.commit_refs(
            PublicationKind::Snapshot,
            replacement,
            &mut dispatch.refs.lock().unwrap(),
            RefMap::new(),
        );
        drop(publication);
        let (current, _) = dispatch.snapshot_for_action(&operation).await.unwrap();
        assert_ne!(current, original); // Strict action revision equality rejects the old ref.
    }
    #[test]
    fn only_committed_observation_advances_reconnect_evidence() {
        let mut publication = Publication {
            revision: 0,
            published_revision: 0,
            observed_revision: 0,
        };
        let mut refs = RefMap::new();
        for kind in [PublicationKind::AdditiveQuery, PublicationKind::PixelsOnly] {
            let revision = publication.stage_revision(kind).unwrap();
            publication.commit_refs(kind, revision, &mut refs, RefMap::new());
            assert_eq!(publication.observed_revision, 0);
        }
        let abandoned = publication
            .stage_revision(PublicationKind::Snapshot)
            .unwrap();
        assert_eq!(publication.observed_revision, 0);
        let committed = publication
            .stage_revision(PublicationKind::Snapshot)
            .unwrap();
        assert!(committed > abandoned);
        publication.commit_refs(
            PublicationKind::Snapshot,
            committed,
            &mut refs,
            RefMap::new(),
        );
        assert_eq!(publication.observed_revision, committed);
        for kind in [PublicationKind::AdditiveQuery, PublicationKind::PixelsOnly] {
            let revision = publication.stage_revision(kind).unwrap();
            publication.commit_refs(kind, revision, &mut refs, RefMap::new());
            assert_eq!(publication.observed_revision, committed);
        }
    }
    #[test]
    fn initial_query_allocates_epoch_and_pixels_do_not_allocate_one() {
        let mut publication = Publication {
            revision: 0,
            published_revision: 0,
            observed_revision: 0,
        };
        assert_eq!(
            publication
                .stage_revision(PublicationKind::PixelsOnly)
                .unwrap(),
            0
        );
        assert_eq!(publication.revision, 0);
        assert_eq!(
            publication
                .stage_revision(PublicationKind::AdditiveQuery)
                .unwrap(),
            1
        );
        // Abandoned first-query epoch is not published or reused.
        assert_eq!(
            publication
                .stage_revision(PublicationKind::AdditiveQuery)
                .unwrap(),
            2
        );
        assert_eq!(publication.published_revision, 0);
    }
    #[test]
    fn semantic_geometry_cleanup_preserves_nested_primary_and_integrity() {
        use super::super::client_geometry::GeometryError;
        let cleanup = AtomicBool::new(false);
        assert_eq!(
            geometry_error_with_cleanup(
                GeometryError::CleanupFailed {
                    primary: Some(Box::new(GeometryError::CleanupFailed {
                        primary: Some(Box::new(GeometryError::Cancelled))
                    }))
                },
                &cleanup
            ),
            ProtocolError::Cancelled
        );
        assert!(cleanup.load(Ordering::SeqCst));
    }
    #[tokio::test]
    async fn fixture_query_publishes_zero_area_semantics_through_dispatch() {
        use super::super::cdp::client::CdpClient;
        use super::super::client_browser::ExecutionGate;
        use super::super::client_targets::ClientTargets;
        use futures_util::{SinkExt, StreamExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = ws.next().await {
                let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                let result = match request["method"].as_str().unwrap() {
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"frame","loaderId":"loader","url":"https://fixture.invalid/"}}})
                    }
                    "Page.getLayoutMetrics" => {
                        json!({"cssVisualViewport":{"clientWidth":100,"clientHeight":80,"offsetX":0,"offsetY":0,"scale":1},"cssLayoutViewport":{"clientWidth":100,"clientHeight":80}})
                    }
                    "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                    "DOM.getDocument" => {
                        json!({"root":{"nodeType":9,"backendNodeId":1,"children":[{"nodeType":1,"backendNodeId":7}]}})
                    }
                    "Accessibility.getFullAXTree" => {
                        json!({"nodes":[{"nodeId":"zero","backendDOMNodeId":7,"role":{"type":"role","value":"generic"}}]})
                    }
                    "DOM.resolveNode" => json!({"object":{"objectId":"owner","subtype":"node"}}),
                    "DOM.getBoxModel" => json!({"model":{"border":[10,20,10,20,10,20,10,20]}}),
                    "Runtime.getProperties" => json!({"result":[]}),
                    "Runtime.callFunctionOn" => {
                        let declaration =
                            request["params"]["functionDeclaration"].as_str().unwrap();
                        if declaration.contains("Array.from(result)") {
                            json!({"result":{"objectId":"security"}})
                        } else if declaration.starts_with("function(expression") {
                            json!({"result":{"value":{"indices":[0],"redacted":[]}}})
                        } else if declaration.contains("const read=") {
                            json!({"result":{"value":[{"attributes":{},"labels":[],"states":{"secure":false,"hidden":true},"text":"","rect":{"x":999,"y":999,"width":0,"height":0}}]}})
                        } else if declaration.contains("frameOwner") {
                            json!({"result":{"value":{"connected":true,"frameOwner":false}}})
                        } else {
                            json!({"result":{"value":true}})
                        }
                    }
                    "Runtime.releaseObject" | "Runtime.releaseObjectGroup" => json!({}),
                    method => panic!("unexpected zero-area dispatch command: {method}"),
                };
                if ws
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
        let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
        let targets = ClientTargets::new("context".into(), "scope".into());
        targets
            .attached("context", "target".into(), "session".into(), "page".into())
            .unwrap();
        targets.configured("target").unwrap();
        targets
            .resume_permit("target")
            .await
            .unwrap()
            .complete()
            .unwrap();
        targets.acknowledge_enrollment().unwrap(); // Synthetic complete inventory only.
        let gate = Arc::new(ExecutionGate::default());
        let page = BrowserExecutionLease {
            client,
            page_session_id: "session".into(),
            target_id: "target".into(),
            identity_scope: "scope".into(),
            permit: gate.enter(false).unwrap(),
            targets,
        };
        let blobs = Arc::new(BlobStore::new(Default::default()).unwrap());
        let scope = BlobScope {
            generation: 1,
            identity_scope: "scope".into(),
        };
        blobs.activate_scope(scope.clone()).unwrap();
        let refs = Arc::new(Mutex::new(RefMap::new()));
        let dispatch = ObservationDispatch::new(refs.clone());
        let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            generation: 1,
            sequence: 1,
            is_callback: false,
            deadline: Instant::now() + Duration::from_secs(5),
            cancellation,
        };
        let task = dispatch.start(DispatchContext {
            #[cfg(feature="acceptance-faults")]
            faults:Arc::new(super::super::client_test_faults::FaultController::default()),
            page, ui:Arc::new(UiGate::default()), blobs, scope,
            policy:ReadPolicy { test_id_attribute:"data-testid".into(), secure_field_selector:"input[type=password]".into() },
        }, DispatchRequest::Query(QueryRequest {
            purpose:QueryPurpose::Fixture,
            options:serde_json::from_value(json!({"expression":{"kind":"selector","selector":"#zero"},"secureFieldSelector":"input[type=password]"})).unwrap(),
        }), operation);
        let result = task.result.await.unwrap().unwrap();
        task.join.await.unwrap().unwrap();
        assert_eq!(
            result["nodes"][0]["rect"],
            json!({"x":10.0,"y":20.0,"width":0.0,"height":0.0})
        );
        assert_eq!(result["nodes"][0]["states"]["hidden"], true);
        let id = result["nodes"][0]["ref"]["id"].as_str().unwrap();
        assert_eq!(
            refs.lock()
                .unwrap()
                .get(id.trim_start_matches('@'))
                .unwrap()
                .backend_node_id,
            Some(7)
        );
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn tree_observe_skips_positive_hidden_iframe_before_spatial_proof() {
        tree_observe_with_hidden_iframe(false).await;
    }
    #[tokio::test]
    async fn tree_only_fallback_does_not_reserve_unused_pixels_under_live_blob_pressure() {
        tree_observe_with_hidden_iframe(true).await;
    }
    async fn tree_observe_with_hidden_iframe(pixel_fallback: bool) {
        use super::super::cdp::client::CdpClient;
        use super::super::client_blobs::BlobLimits;
        use super::super::client_browser::ExecutionGate;
        use super::super::client_targets::ClientTargets;
        use futures_util::{SinkExt, StreamExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = ws.next().await {
                let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                let result = match request["method"].as_str().unwrap() {
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"frame","loaderId":"loader","url":"https://fixture.invalid/"},"childFrames":[{"frame":{"id":"child","parentId":"frame","loaderId":"child-loader","url":"about:blank"}}]}})
                    }
                    "Page.getLayoutMetrics" => {
                        json!({"cssVisualViewport":{"clientWidth":100,"clientHeight":80,"offsetX":0,"offsetY":0,"scale":1},"cssLayoutViewport":{"clientWidth":100,"clientHeight":80}})
                    }
                    "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                    "DOM.getDocument" => {
                        json!({"root":{"nodeType":9,"backendNodeId":1,"children":[{"nodeType":1,"nodeName":"IFRAME","localName":"iframe","backendNodeId":7}]}})
                    }
                    "Accessibility.getFullAXTree" => {
                        assert_eq!(
                            request["params"]["frameId"], "frame",
                            "hidden child AX must not be acquired"
                        );
                        json!({"nodes":[{"nodeId":"document","backendDOMNodeId":1,"role":{"type":"role","value":"RootWebArea"}},{"nodeId":"owner","backendDOMNodeId":7,"role":{"type":"role","value":"Iframe"}}]})
                    }
                    "DOM.resolveNode" => {
                        json!({"object":{"objectId":format!("node-{}", request["params"]["backendNodeId"]),"subtype":"node"}})
                    }
                    "DOM.getFrameOwner" => json!({"backendNodeId":7}),
                    "DOM.getBoxModel" => panic!("hidden frame spatial proof must not run"),
                    "Runtime.getProperties" => json!({"result":[]}),
                    "Runtime.callFunctionOn" => {
                        let declaration =
                            request["params"]["functionDeclaration"].as_str().unwrap();
                        if declaration.contains("Array.from(result)") {
                            json!({"result":{"objectId":"security"}})
                        } else if declaration.contains("selector:parts.join") {
                            json!({"result":{"value":{"x":0,"y":0,"selector":"iframe"}}})
                        } else if declaration.starts_with("function(expression") {
                            json!({"result":{"value":{"indices":[0],"redacted":[]}}})
                        } else if declaration.contains("return {status:data.__nativeStatus") {
                            json!({"result":{"value":{"nodeType":1,"tag":"iframe","hidden":true}}})
                        } else if declaration.contains("const read=") {
                            let values = request["params"]["arguments"].as_array().unwrap().iter().skip(2).map(|argument| {
                                match argument["objectId"].as_str().unwrap() {
                                    "node-1" => json!({"attributes":{},"labels":[],"states":{},"rect":null,"author":{"nodeType":9,"visible":true}}),
                                    "node-7" => json!({"attributes":{},"labels":[],"states":{"hidden":true},"rect":null,"author":{"nodeType":1,"tag":"iframe","visible":false}}),
                                    _ => panic!("unknown exact metadata receiver"),
                                }
                            }).collect::<Vec<_>>();
                            json!({"result":{"value":values}})
                        } else if declaration
                            .starts_with("function(testId,secureSelector,boundedObservation")
                        {
                            json!({"result":{"value":{"attributes":{},"labels":[],"states":{"hidden":true},"rect":null,"author":{"nodeType":1,"tag":"iframe","visible":false}}}})
                        } else if declaration.contains("frameOwner") {
                            json!({"result":{"value":{"connected":true,"frameOwner":false}}})
                        } else {
                            json!({"result":{"value":true}})
                        }
                    }
                    "Runtime.releaseObject" | "Runtime.releaseObjectGroup" => json!({}),
                    method => panic!("unexpected zero-area dispatch command: {method}"),
                };
                if ws
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
        let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
        let targets = ClientTargets::new("context".into(), "scope".into());
        targets
            .attached("context", "target".into(), "session".into(), "page".into())
            .unwrap();
        targets.configured("target").unwrap();
        targets
            .resume_permit("target")
            .await
            .unwrap()
            .complete()
            .unwrap();
        // This synthetic peer tests production Dispatch.start admission, not
        // browser startup or enrollment readiness.
        targets.acknowledge_enrollment().unwrap();
        let gate = Arc::new(ExecutionGate::default());
        let page = BrowserExecutionLease {
            client,
            page_session_id: "session".into(),
            target_id: "target".into(),
            identity_scope: "scope".into(),
            permit: gate.enter(false).unwrap(),
            targets,
        };
        let blobs = Arc::new(
            BlobStore::new(BlobLimits {
                max_blob_bytes: 4096,
                max_total_bytes: 8192,
                max_handles: 8,
            })
            .unwrap(),
        );
        let scope = BlobScope {
            generation: 1,
            identity_scope: "scope".into(),
        };
        blobs.activate_scope(scope.clone()).unwrap();
        let retained = blobs.insert_sealed(scope.clone(), b"r").unwrap();
        let live_producer = blobs.reserve_producer(scope.clone()).unwrap();
        assert!(matches!(
            blobs.reserve_producer(scope.clone()),
            Err(BlobError::QuotaExceeded)
        ));
        let budget_changes = blobs.budget_changes().unwrap();
        let refs = Arc::new(Mutex::new(RefMap::new()));
        let dispatch = ObservationDispatch::new(refs.clone());
        let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            generation: 1,
            sequence: 1,
            is_callback: false,
            deadline: Instant::now() + Duration::from_secs(5),
            cancellation,
        };
        let task = dispatch.clone().start(
            DispatchContext {
                #[cfg(feature = "acceptance-faults")]
                faults: Arc::new(super::super::client_test_faults::FaultController::default()),
                page,
                ui: Arc::new(UiGate::default()),
                blobs: blobs.clone(),
                scope: scope.clone(),
                policy: ReadPolicy {
                    test_id_attribute: "data-testid".into(),
                    secure_field_selector: "input[type=password]".into(),
                },
            },
            DispatchRequest::Observe(ObserveRequest {
                options: ObserveFlags {
                    pixels: false,
                    pixel_fallback,
                    comparable: false,
                },
                test_id_attribute: "data-testid".into(),
                secure_field_selector: "input[type=password]".into(),
            }),
            operation,
        );
        let result = task.result.await.unwrap().unwrap();
        task.join.await.unwrap().unwrap();
        assert_eq!(result["root"]["role"], "document");
        assert!(result["root"]["children"]
            .as_array()
            .is_none_or(Vec::is_empty));
        assert!(result.get("hidden_frame_proof").is_none());
        assert!(result.get("hiddenFrameProof").is_none());
        assert!(result.get("pixels").is_none());
        assert!(result.get("treeUnavailable").is_none());
        assert_eq!(result["viewport"], json!({"width":100.0,"height":80.0}));
        assert_eq!(result["location"], "https://fixture.invalid/");
        // The strict peer rejects screenshots, source-mask commands, animation
        // changes, and spatial reads of the positively hidden iframe.
        assert!(!budget_changes.has_changed().unwrap());
        assert_eq!(blobs.read(&scope, &retained.handle, 0, 1).unwrap(), b"r");
        assert!(matches!(
            blobs.reserve_producer(scope.clone()),
            Err(BlobError::QuotaExceeded)
        ));
        assert_eq!(
            dispatch
                .snapshot_for_action(&OperationLease {
                    generation: 1,
                    sequence: 2,
                    is_callback: false,
                    deadline: Instant::now() + Duration::from_secs(1),
                    cancellation: _sender.subscribe(),
                })
                .await
                .unwrap()
                .0,
            1
        );
        let root = result["root"]["ref"]["id"].as_str().unwrap();
        assert_eq!(
            refs.lock()
                .unwrap()
                .get(root.trim_start_matches('@'))
                .unwrap()
                .backend_node_id,
            Some(1)
        );
        drop(live_producer);
        blobs.release(&scope, &retained.handle).unwrap();
        blobs.check_budget_integrity().unwrap();
        server.abort();
        let _ = server.await;
    }
    #[test]
    fn fallback_reserves_bounded_time_without_resetting_parent_deadline() {
        let parent = operation();
        let now = parent.deadline - Duration::from_secs(8);
        let semantic = semantic_lease_at(&parent, true, now);
        assert_eq!(parent.deadline - semantic.deadline, Duration::from_secs(2));
        assert_eq!(semantic.sequence, parent.sequence);
        assert_eq!(semantic_lease(&parent, false).deadline, parent.deadline);
        let pixels = pixel_lease(&parent);
        assert_eq!(
            parent.deadline - pixels.deadline,
            Duration::from_millis(500)
        );
    }
    #[test]
    fn fallback_semantic_budget_matches_quarter_reserve_and_cap_boundaries() {
        let now = Instant::now();
        for (remaining, reserve) in [
            (Duration::ZERO, Duration::ZERO),
            (Duration::from_millis(4), Duration::from_millis(1)),
            (Duration::from_secs(2), Duration::from_millis(500)),
            (Duration::from_secs(8), Duration::from_secs(2)),
            (Duration::from_secs(12), Duration::from_secs(2)),
        ] {
            let mut parent = operation();
            parent.deadline = now + remaining;
            let semantic = semantic_lease_at(&parent, true, now);
            assert_eq!(semantic.deadline, parent.deadline - reserve);
            assert_eq!(
                semantic_lease_at(&parent, false, now).deadline,
                parent.deadline
            );
            assert_eq!(semantic.sequence, parent.sequence);
            assert_eq!(semantic.generation, parent.generation);
            assert_eq!(semantic.is_callback, parent.is_callback);
        }
        // A two-second stalled reader expires at 1500ms, not the former
        // 1000ms half-budget cut that violated the original >1250ms fixture.
        let mut parent = operation();
        parent.deadline = now + Duration::from_secs(2);
        assert_eq!(
            semantic_lease_at(&parent, true, now).deadline - now,
            Duration::from_millis(1500)
        );
        // Setup already spent from the same parent deadline, not a fresh budget.
        assert_eq!(
            semantic_lease_at(&parent, true, now + Duration::from_secs(1)).deadline,
            parent.deadline - Duration::from_millis(250)
        );
        assert_eq!(
            semantic_lease_at(&parent, true, now + Duration::from_secs(3)).deadline,
            parent.deadline
        );
    }
    #[test]
    fn frames_are_order_independent_but_never_rebind_documents_or_sessions() {
        let a = vec![frame("root", None), frame("child", Some("root"))];
        let mut b = vec![a[1].clone(), a[0].clone()];
        same_frames(&a, &b).unwrap();
        b[0].binding.loader = "replacement".into();
        assert_eq!(same_frames(&a, &b), Err(ProtocolError::StaleScope));
        b[0] = a[1].clone();
        b[0].binding.session = "foreign".into();
        assert_eq!(same_frames(&a, &b), Err(ProtocolError::StaleScope));
        b[0] = a[1].clone();
        b[1].url.push_str("#same-document-navigation");
        assert_eq!(same_frames(&a, &b), Err(ProtocolError::StaleScope));
        assert!(main_frame(&[frame("one", None), frame("two", None)]).is_err());
    }
    #[test]
    fn document_root_is_exact_and_viewport_is_not_a_document_wrapper() {
        let frames = vec![frame("root", None)];
        let mut refs = RefMap::new();
        let id = refs
            .try_bind_exact(10, "document", "", frames[0].binding.clone())
            .unwrap();
        let mut root = SemanticNode::default();
        root.reference.id = format!("@{id}");
        root.reference.revision = "1".into();
        root.role = Some("document".into());
        assert!(exact_root(vec![root.clone()], &refs, &frames).is_ok());
        assert!(exact_root(vec![root.clone(), root.clone()], &refs, &frames).is_err());
        let mut foreign = frames.clone();
        foreign[0].binding.loader = "new".into();
        assert!(exact_root(vec![root.clone()], &refs, &foreign).is_err());
        let viewport = refs
            .try_viewport_ref("scope", 1, &frames[0].binding.page_session, 1)
            .unwrap();
        let mut fake = root;
        fake.reference.id = format!("@{}", viewport.id);
        assert!(exact_root(vec![fake], &refs, &frames).is_err());
    }
    #[test]
    fn abandoned_staging_consumes_native_ids_without_publishing_entries() {
        let mut refs = RefMap::new();
        let mut abandoned = refs.clone();
        let binding = frame("root", None).binding;
        let lost = abandoned
            .try_bind_exact(1, "button", "", binding.clone())
            .unwrap();
        assert!(refs.get(&lost).is_none());
        let next = refs.try_bind_exact(2, "button", "", binding).unwrap();
        assert_ne!(lost, next);
    }
    #[test]
    fn masking_failures_are_never_reclassified_as_optional_backend_errors() {
        assert_eq!(
            capture_error(CaptureReason::MaskingUnproven),
            ProtocolError::PolicyDenied
        );
        assert_eq!(
            capture_error(CaptureReason::UnsafeGeometry),
            ProtocolError::PolicyDenied
        );
        assert_eq!(
            capture_error(CaptureReason::Cancelled),
            ProtocolError::Cancelled
        );
        assert_eq!(
            observation_error(ObservationError::PolicyDenied),
            ProtocolError::PolicyDenied
        );
    }
    #[test]
    fn oversized_semantics_fail_before_publication_not_transport_poison() {
        bounded_result(&json!({"nodes":[]})).unwrap();
        assert_eq!(
            bounded_result(
                &json!({"text":"x".repeat(super::super::client_protocol::MAX_FRAME_BYTES)})
            ),
            Err(ProtocolError::CapacityExceeded)
        );
    }
    #[test]
    fn repeated_request_policy_cannot_weaken_captured_scope_policy() {
        let policy = ReadPolicy {
            test_id_attribute: "data-testid".into(),
            secure_field_selector: "input[type=password],.private".into(),
        };
        let weaker = DispatchRequest::Screenshot(CaptureRequest {
            secure_field_selector: "input[type=password]".into(),
        });
        assert_eq!(
            validate_policy(&policy, &weaker),
            Err(ProtocolError::PolicyDenied)
        );
        let exact = DispatchRequest::Screenshot(CaptureRequest {
            secure_field_selector: policy.secure_field_selector.clone(),
        });
        validate_policy(&policy, &exact).unwrap();
    }
    #[test]
    fn wire_observe_flags_do_not_grant_fixture_read_authority() {
        assert!(serde_json::from_value::<ObserveFlags>(json!({"purpose":"fixture"})).is_err());
        let flags: ObserveFlags = serde_json::from_value(json!({"pixelFallback":true})).unwrap();
        assert!(flags.pixel_fallback);
        assert!(!flags.pixels);
    }
}
