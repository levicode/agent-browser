//! Admission/commit branch proof plus a separately ignored real Chromium race.
//! The in-memory commit cases are not evidence of renderer cleanup/actionability.
use super::*;
use crate::native::cdp::client::CdpClient;
use crate::native::client_browser::ExecutionGate;
use crate::native::client_targets::ClientTargets;
use crate::native::element::{ExactBinding, LocatedIssuance};
use futures_util::StreamExt;

#[path = "client_capture_metadata_deadline_tests.rs"]
mod metadata_deadline_tests;

#[path = "client_capture_acquisition_deadline_tests.rs"]
mod acquisition_deadline_tests;

#[path = "client_capture_frame_owner_deadline_tests.rs"]
mod frame_owner_deadline_tests;

struct Owner {
    client: Arc<CdpClient>,
    targets: Arc<ClientTargets>,
    gate: Arc<ExecutionGate>,
    ui: Arc<UiGate>,
    blobs: Arc<BlobStore>,
    scope: BlobScope,
    session: String,
    target: String,
}
impl Owner {
    async fn new(client: Arc<CdpClient>, session: &str, target: &str, scope: &str) -> Self {
        let targets = ClientTargets::new("context".into(), scope.into());
        targets
            .attached("context", target.into(), session.into(), "page".into())
            .unwrap();
        targets.configured(target).unwrap();
        targets
            .resume_permit(target)
            .await
            .unwrap()
            .complete()
            .unwrap();
        targets.acknowledge_enrollment().unwrap();
        let blobs = Arc::new(BlobStore::new(Default::default()).unwrap());
        let scope = BlobScope {
            generation: 1,
            identity_scope: scope.into(),
        };
        blobs.activate_scope(scope.clone()).unwrap();
        Self {
            client,
            targets,
            gate: Arc::new(ExecutionGate::default()),
            ui: Arc::new(UiGate::default()),
            blobs,
            scope,
            session: session.into(),
            target: target.into(),
        }
    }
    fn context(&self) -> DispatchContext {
        DispatchContext {
            #[cfg(feature = "acceptance-faults")]
            faults: Arc::new(super::super::client_test_faults::FaultController::default()),
            attachment: self.targets.owned_target(&self.target).unwrap(),
            page: BrowserExecutionLease {
                client: self.client.clone(),
                page_session_id: self.session.clone(),
                target_id: self.target.clone(),
                identity_scope: self.scope.identity_scope.clone(),
                permit: self.gate.enter(false).unwrap(),
                targets: self.targets.clone(),
            },
            ui: self.ui.clone(),
            blobs: self.blobs.clone(),
            scope: self.scope.clone(),
            policy: ReadPolicy {
                test_id_attribute: "data-testid".into(),
                secure_field_selector: "input[type=password]".into(),
            },
        }
    }
    fn binding(&self) -> ExactBinding {
        ExactBinding {
            page_session: self.session.clone(),
            session: self.session.clone(),
            frame: "frame".into(),
            loader: "loader".into(),
            actionable: true,
        }
    }
}
fn operation(sequence: u64) -> (OperationLease, tokio::sync::watch::Sender<CancelSignal>) {
    let (sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
    (
        OperationLease {
            is_callback: false,
            generation: 1,
            sequence,
            deadline: Instant::now() + Duration::from_secs(30),
            cancellation,
        },
        sender,
    )
}
fn observe() -> DispatchRequest {
    DispatchRequest::Observe(ObserveRequest {
        options: ObserveFlags::default(),
        test_id_attribute: "data-testid".into(),
        secure_field_selector: "input[type=password]".into(),
    })
}
async fn peer() -> (Owner, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(Ok(message)) = socket.next().await {
            assert!(
                !message.is_text(),
                "admission/commit proof must not send CDP"
            );
        }
    });
    let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
    (
        Owner::new(client, "session", "target", "scope").await,
        server,
    )
}
fn staged(owner: &Owner, refs: &RefMap, revision: u64, backend: i64) -> (RefMap, String) {
    let mut staged = refs.clone();
    staged.begin_observation(
        &owner.scope.identity_scope,
        owner.scope.generation,
        revision,
    );
    let id = staged
        .try_bind_exact(backend, "button", "public", owner.binding())
        .unwrap();
    (staged, id)
}
fn commit(
    dispatch: &ObservationDispatch,
    prepared: &PreparedDispatch,
    publication: &mut Publication,
    revision: u64,
    refs: RefMap,
) -> Result<(), ProtocolError> {
    dispatch.commit_staged(
        &prepared.context.page,
        &prepared.operation,
        prepared.capture.as_ref(),
        prepared.trace.as_ref(),
        prepared.retirement_fence,
        publication,
        PublicationKind::Snapshot,
        revision,
        refs,
    )
}

#[tokio::test]
async fn admitted_b_rejects_actual_a_commit_without_retiring_committed_authorities() {
    let (owner, server) = peer().await;
    let refs = Arc::new(Mutex::new(RefMap::new()));
    let dispatch = ObservationDispatch::new(refs.clone());
    let (op, _s0_cancel) = operation(1);
    let s0 = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let mut publication = dispatch.publication.lock().await;
    let revision = publication
        .stage_revision(PublicationKind::Snapshot)
        .unwrap();
    let (mut initial, observed) = staged(&owner, &refs.lock().unwrap(), revision, 10);
    let located = initial
        .try_bind_located(
            11,
            "button",
            owner.binding(),
            LocatedIssuance {
                identity_scope: "scope".into(),
                generation: 1,
                revision,
            },
            None,
        )
        .unwrap();
    let viewport = initial
        .try_viewport_ref("scope", 1, "session", revision)
        .unwrap()
        .id
        .clone();
    commit(&dispatch, &s0, &mut publication, revision, initial).unwrap();
    let (op, _a_cancel) = operation(2);
    let a = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let attempted_revision = publication
        .stage_revision(PublicationKind::Snapshot)
        .unwrap();
    let (attempted, burned) = staged(&owner, &refs.lock().unwrap(), attempted_revision, 12);
    let before_admission = refs.lock().unwrap().ref_ids();
    // A has reached the actual final commit seam while holding publication.
    // B's admission must neither wait for that lock nor mutate committed refs.
    let (op, b_cancel) = operation(3);
    let b = dispatch.prepare(owner.context(), observe(), op).unwrap();
    assert!(*a.capture.as_ref().unwrap().retired.borrow());
    assert!(!*b.capture.as_ref().unwrap().retired.borrow());
    assert_eq!(refs.lock().unwrap().ref_ids(), before_admission);
    assert_eq!(publication.observed_revision, revision);
    // A later failure/cancellation/dropped retained B never revives A.
    b_cancel.send_replace(CancelSignal::Requested);
    drop(b);
    assert_eq!(
        commit(
            &dispatch,
            &a,
            &mut publication,
            attempted_revision,
            attempted
        ),
        Err(ProtocolError::StaleReference)
    );
    assert_eq!(publication.published_revision, revision);
    assert_eq!(publication.observed_revision, revision);
    let current = refs.lock().unwrap();
    assert!(current
        .get(&observed)
        .unwrap()
        .is_current_observed(revision));
    assert!(current.get(&located).unwrap().matches_reference(
        "scope",
        1,
        "session",
        &revision.to_string()
    ));
    assert!(current.matches_viewport_reference(
        "scope",
        1,
        "session",
        &viewport,
        &revision.to_string()
    ));
    assert!(current.get(&burned).is_none());
    let next = current.try_allocate_ref().unwrap();
    assert_ne!(next, burned, "discarded staged identity stays burned");
    drop(current);
    drop(publication);
    server.abort();
}

#[tokio::test]
async fn commit_before_new_admission_is_legal_and_old_sequence_cannot_retake_authority() {
    let (owner, server) = peer().await;
    let refs = Arc::new(Mutex::new(RefMap::new()));
    let dispatch = ObservationDispatch::new(refs.clone());
    let (op, _a_cancel) = operation(10);
    let a = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let mut publication = dispatch.publication.lock().await;
    let revision = publication
        .stage_revision(PublicationKind::Snapshot)
        .unwrap();
    let (first, id) = staged(&owner, &refs.lock().unwrap(), revision, 10);
    commit(&dispatch, &a, &mut publication, revision, first).unwrap();
    let (op, _b_cancel) = operation(12);
    let b = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let (op, _late_cancel) = operation(11);
    assert!(matches!(
        dispatch.prepare(owner.context(), observe(), op),
        Err(ProtocolError::StaleReference)
    ));
    assert!(!*b.capture.as_ref().unwrap().retired.borrow());
    assert!(refs.lock().unwrap().get(&id).is_some());
    assert_eq!(publication.observed_revision, revision);
    drop(publication);
    server.abort();
}

#[tokio::test]
async fn rejected_and_non_observe_requests_cannot_acquire_capture_authority() {
    let (owner, server) = peer().await;
    let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
    let (op, _a_cancel) = operation(1);
    let a = dispatch.prepare(owner.context(), observe(), op).unwrap();
    for kind in [
        "policy",
        "scope",
        "generation",
        "session",
        "callback",
        "cancel",
        "deadline",
    ] {
        let mut context = owner.context();
        let (mut op, sender) = operation(2);
        let mut request = observe();
        match kind {
            "policy" => {
                if let DispatchRequest::Observe(ref mut value) = request {
                    value.secure_field_selector = "*".into();
                }
            }
            "scope" => context.scope.identity_scope = "other".into(),
            "generation" => context.scope.generation += 1,
            "session" => context.page.page_session_id = "wrong".into(),
            "callback" => op.is_callback = true,
            "cancel" => {
                sender.send_replace(CancelSignal::Requested);
            }
            "deadline" => op.deadline = Instant::now(),
            _ => unreachable!(),
        }
        assert!(dispatch.prepare(context, request, op).is_err(), "{kind}");
        assert!(!*a.capture.as_ref().unwrap().retired.borrow(), "{kind}");
    }
    let query = |purpose| {
        DispatchRequest::Query(QueryRequest {
            purpose,
            options: serde_json::from_value(
                json!({"expression":{"kind":"selector","selector":"button"},
            "testIdAttribute":"data-testid","secureFieldSelector":"input[type=password]"}),
            )
            .unwrap(),
        })
    };
    for request in [
        DispatchRequest::Screenshot(ScreenshotRequest {
            purpose: ScreenshotPurpose::PixelsOnly,
            secure_field_selector: "input[type=password]".into(),
        }),
        query(QueryPurpose::Fixture),
        query(QueryPurpose::Protected),
        DispatchRequest::Correlate(CorrelateRequest {
            located: vec![],
            observed: vec![],
        }),
    ] {
        let (op, _sender) = operation(3);
        let prepared = dispatch.prepare(owner.context(), request, op).unwrap();
        assert!(prepared.capture.is_none());
        assert!(!*a.capture.as_ref().unwrap().retired.borrow());
    }
    assert_eq!(dispatch.captures.lock().unwrap().latest.len(), 1);
    assert_eq!(dispatch.publication.lock().await.observed_revision, 0);
    server.abort();
}

#[tokio::test]
async fn retained_capacity_and_closing_reject_before_capture_admission() {
    use crate::native::client_protocol::Effects;
    use crate::native::client_tasks::RetainedTasks;
    use crate::native::client_transport::NativeOutcome;
    let (owner, server) = peer().await;
    let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
    let (op, _a_cancel) = operation(1);
    let a = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let tasks = RetainedTasks::default();
    let mut releases = Vec::new();
    for _ in 0..64 {
        let (release, wait) = oneshot::channel();
        releases.push(release);
        let receiver = tasks
            .start("scope".into(), owner.targets.clone(), async move {
                wait.await.unwrap();
                (
                    NativeOutcome {
                        retention: None,
                        result: Ok(Value::Null),
                        effects: Effects::Completed,
                    },
                    false,
                )
            })
            .await
            .unwrap();
        drop(receiver);
    }
    let (op, _b_cancel) = operation(2);
    let context = owner.context();
    let refused = tasks
        .start_prepared("scope".into(), owner.targets.clone(), || {
            let _b = dispatch.prepare(context, observe(), op)?;
            Ok(async {
                (
                    NativeOutcome {
                        retention: None,
                        result: Ok(Value::Null),
                        effects: Effects::Completed,
                    },
                    false,
                )
            })
        })
        .await;
    assert!(matches!(refused, Err(ProtocolError::CapacityExceeded)));
    assert!(!*a.capture.as_ref().unwrap().retired.borrow());
    for release in releases {
        release.send(()).unwrap();
    }
    tasks.drain().await.unwrap();
    tasks.seal().await;
    let (op, _c_cancel) = operation(3);
    let context = owner.context();
    let refused = tasks
        .start_prepared("scope".into(), owner.targets.clone(), || {
            let _c = dispatch.prepare(context, observe(), op)?;
            Ok(async {
                (
                    NativeOutcome {
                        retention: None,
                        result: Ok(Value::Null),
                        effects: Effects::Completed,
                    },
                    false,
                )
            })
        })
        .await;
    assert!(matches!(refused, Err(ProtocolError::ScopeUnavailable)));
    assert!(!*a.capture.as_ref().unwrap().retired.borrow());
    server.abort();
}

#[tokio::test]
async fn exact_owner_tenures_isolate_admission_and_retired_owner_cannot_retarget() {
    let (owner, server) = peer().await;
    let other = Owner::new(
        owner.client.clone(),
        "other-session",
        "other-target",
        "other-scope",
    )
    .await;
    let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
    let (op, _a_cancel) = operation(20);
    let a = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let (op, _b_cancel) = operation(21);
    let b = dispatch.prepare(other.context(), observe(), op).unwrap();
    assert!(!*a.capture.as_ref().unwrap().retired.borrow());
    assert!(!*b.capture.as_ref().unwrap().retired.borrow());
    let old_context = owner.context();
    owner.gate.seal();
    let (op, _old_cancel) = operation(100);
    assert!(matches!(
        dispatch.prepare(old_context, observe(), op),
        Err(ProtocolError::StaleScope)
    ));
    assert!(!*b.capture.as_ref().unwrap().retired.borrow());
    // Exact strings cannot alias a detached/re-attached native tenure.
    let before = other.context();
    other.targets.detach("other-target").unwrap();
    other
        .targets
        .attached(
            "context",
            "other-target".into(),
            "other-session".into(),
            "page".into(),
        )
        .unwrap();
    other.targets.configured("other-target").unwrap();
    other
        .targets
        .resume_permit("other-target")
        .await
        .unwrap()
        .complete()
        .unwrap();
    assert!(!b.capture.as_ref().unwrap().owner.matches(&before.page, 1));
    let (op, _old_context_cancel) = operation(100);
    assert!(
        matches!(
            dispatch.prepare(before, observe(), op),
            Err(ProtocolError::StaleScope)
        ),
        "an old captured context must not acquire an identical replacement tenure"
    );
    let (op, _new_cancel) = operation(22);
    let fresh = dispatch.prepare(other.context(), observe(), op).unwrap();
    assert!(!Arc::ptr_eq(
        b.capture.as_ref().unwrap(),
        fresh.capture.as_ref().unwrap()
    ));
    let mut publication = dispatch.publication.lock().await;
    assert_eq!(
        commit(&dispatch, &b, &mut publication, 1, RefMap::new()),
        Err(ProtocolError::StaleReference)
    );
    drop(publication);
    server.abort();
}

#[tokio::test]
async fn cancellation_observed_at_final_commit_precedes_supersession() {
    let (owner, server) = peer().await;
    let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
    let (op, cancel) = operation(1);
    let a = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let (op, _b_cancel) = operation(2);
    let _b = dispatch.prepare(owner.context(), observe(), op).unwrap();
    cancel.send_replace(CancelSignal::Requested);
    let mut publication = dispatch.publication.lock().await;
    assert_eq!(
        commit(&dispatch, &a, &mut publication, 1, RefMap::new()),
        Err(ProtocolError::Cancelled)
    );
    drop(publication);
    server.abort();
}

#[tokio::test]
async fn already_settled_stale_result_is_not_rewritten_by_later_user_cancel() {
    let (owner, server) = peer().await;
    let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
    let (op, cancel) = operation(1);
    let a = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let (op, _b_cancel) = operation(2);
    let _b = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let task = dispatch.start_prepared(a);
    let settled = task.result.await.unwrap().unwrap_err();
    task.join.await.unwrap().unwrap();
    assert_eq!(settled.error, ProtocolError::StaleReference);
    cancel.send_replace(CancelSignal::Requested);
    assert_eq!(settled.error, ProtocolError::StaleReference);
    assert!(!settled.cleanup_integrity_lost);
    server.abort();
}

#[tokio::test]
async fn superseded_first_staging_cannot_install_viewport_or_observed_revision() {
    let (owner, server) = peer().await;
    let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
    let (op, _a_cancel) = operation(1);
    let a = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let mut publication = dispatch.publication.lock().await;
    let revision = publication
        .stage_revision(PublicationKind::Snapshot)
        .unwrap();
    let (mut private, id) = staged(&owner, &dispatch.refs.lock().unwrap(), revision, 1);
    let viewport = private
        .try_viewport_ref("scope", 1, "session", revision)
        .unwrap()
        .id
        .clone();
    let (op, _b_cancel) = operation(2);
    let b = dispatch.prepare(owner.context(), observe(), op).unwrap();
    drop(b);
    assert_eq!(
        commit(&dispatch, &a, &mut publication, revision, private),
        Err(ProtocolError::StaleReference)
    );
    assert_eq!(publication.observed_revision, 0);
    assert_eq!(publication.published_revision, 0);
    let refs = dispatch.refs.lock().unwrap();
    assert!(refs.ref_ids().is_empty());
    assert!(!refs.is_viewport_ref(&viewport));
    assert!(refs.get(&id).is_none());
    assert_ne!(refs.try_allocate_ref().unwrap(), viewport);
    drop(refs);
    drop(publication);
    server.abort();
}

#[tokio::test]
async fn exact_resolution_stops_between_commands_but_releases_started_objects() {
    use crate::native::client_observation::{with_capture_retirement, CaptureRetirement};
    use crate::native::element::{resolve_exact_object_typed, ExactResolutionError};
    use futures_util::SinkExt;
    for (phase, dirty) in [
        ("realm", false),
        ("resolve", false),
        ("proof", false),
        ("resolve", true),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let (reached, wait_reached) = oneshot::channel();
        let (reply, wait_reply) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut reached = Some(reached);
            let mut wait_reply = Some(wait_reply);
            let mut methods = Vec::new();
            while let Some(Ok(message)) = socket.next().await {
                if !message.is_text() {
                    continue;
                }
                let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                let method = request["method"].as_str().unwrap();
                methods.push(method.to_owned());
                let boundary = match method {
                    "Page.createIsolatedWorld" => "realm",
                    "DOM.resolveNode" => "resolve",
                    "Runtime.callFunctionOn" => "proof",
                    "Runtime.releaseObject" => "cleanup",
                    other => panic!("retired exact resolution dispatched {other}"),
                };
                if boundary == phase {
                    reached.take().unwrap().send(()).unwrap();
                    wait_reply.take().unwrap().await.unwrap();
                }
                let result = match boundary {
                    "realm" => json!({"executionContextId":1}),
                    "resolve" => json!({"object":{"objectId":"exact-owned"}}),
                    "proof" => json!({"result":{"value":true}}),
                    "cleanup" => {
                        assert_eq!(request["params"]["objectId"], "exact-owned");
                        json!({})
                    }
                    _ => unreachable!(),
                };
                let response = if dirty && boundary == "cleanup" {
                    json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic release refusal"}})
                } else {
                    json!({"id":request["id"],"result":result})
                };
                socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        response.to_string(),
                    ))
                    .await
                    .unwrap();
                if phase == "realm" || boundary == "cleanup" {
                    break;
                }
            }
            methods
        });
        let client = CdpClient::connect(&endpoint).await.unwrap();
        let binding = ExactBinding {
            page_session: "session".into(),
            session: "session".into(),
            frame: "frame".into(),
            loader: "loader".into(),
            actionable: true,
        };
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let resolve = with_capture_retirement(
            Some(CaptureRetirement::new(receiver)),
            resolve_exact_object_typed(&client, &binding, 1),
        );
        let supersede = async {
            wait_reached.await.unwrap();
            stop.send_replace(true);
            reply.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(resolve, supersede);
        if dirty {
            assert!(matches!(
                result,
                Err(ExactResolutionError::CleanupFailed { .. })
            ));
        } else {
            assert_eq!(result, Err(ExactResolutionError::Superseded));
        }
        let methods = server.await.unwrap();
        assert_eq!(
            methods
                .iter()
                .filter(|m| m.as_str() == "DOM.resolveNode")
                .count(),
            usize::from(phase != "realm")
        );
        assert_eq!(
            methods
                .iter()
                .filter(|m| m.as_str() == "Runtime.callFunctionOn")
                .count(),
            usize::from(phase == "proof")
        );
        assert_eq!(
            methods
                .iter()
                .filter(|m| m.as_str() == "Runtime.releaseObject")
                .count(),
            usize::from(phase != "realm")
        );
    }
}

#[tokio::test]
#[ignore = "hosted Chromium: post-reply metadata hold, acknowledged cleanup, newer exact actionability"]
async fn chromium_newer_capture_finishes_before_old_metadata_hold_is_manually_released() {
    use crate::native::browser::{evaluate_on, BrowserManager};
    use crate::native::client_observation::equivalence_tests::hold_metadata;
    let mut browser = BrowserManager::launch(Default::default(), None)
        .await
        .unwrap();
    let result = async {
        let session = browser.active_session_id()?.to_owned();
        let target = browser.active_target_id()?.to_owned();
        evaluate_on(&browser.client, &session,
            r#"document.body.innerHTML='<button onclick="this.textContent=\'Clicked\'">Click</button>';true"#).await?;
        let owner = Owner::new(browser.client.clone(), &session, &target, "hosted-supersession").await;
        let refs = Arc::new(Mutex::new(RefMap::new()));
        let dispatch = ObservationDispatch::new(refs.clone());
        let (op, _a_cancel) = operation(1001);
        let (_guard, held) = hold_metadata(&op);
        let a = dispatch.clone().start(owner.context(), observe(), op);
        tokio::time::timeout(Duration::from_secs(8), held.reached()).await.map_err(|_| "A never acquired metadata")?;
        assert!(!held.handles().is_empty());
        assert_eq!(held.releases(), 0);
        let (op, _b_cancel) = operation(1002);
        let (_b_guard, b_held) = hold_metadata(&op);
        b_held.release(); // Track B's ownership without holding its reader.
        let prepared = dispatch.prepare(owner.context(), observe(), op).map_err(|e| format!("B admission: {e:?}"))?;
        let b = dispatch.clone().start_prepared(prepared);
        let current = tokio::time::timeout(Duration::from_secs(8), b.result).await.map_err(|_| "B waited for obsolete hold")?
            .map_err(|_| "B result owner lost")?.map_err(|e| format!("B failed: {:?}", e.error))?;
        b.join.await.map_err(|_| "B join lost")?.map_err(|e| format!("B cleanup: {:?}", e.error))?;
        let stale = a.result.await.map_err(|_| "A result owner lost")?.unwrap_err();
        a.join.await.map_err(|_| "A join lost")?.map_err(|e| format!("A cleanup: {:?}", e.error))?;
        assert_eq!(stale.error, ProtocolError::StaleReference);
        assert!(!stale.cleanup_integrity_lost);
        assert_eq!(held.releases(), 1);
        assert_eq!(held.metadata_calls(), 1);
        assert_eq!(b_held.releases(), 1);
        let b_handles = b_held.handles();
        assert!(held.handles().iter().all(|old| !b_handles.contains(old)));
        // The supersession-aware hold is after an actual reply. It does not
        // model dropping an arbitrary hung CDP resource-producing command.
        held.release();
        tokio::task::yield_now().await;
        assert_eq!(held.metadata_calls(), 1);
        assert_eq!(held.releases(), 1);
        for object in held.handles() {
            assert!(browser.client.send_command("Runtime.callFunctionOn", Some(json!({
                "objectId":object,"functionDeclaration":"function(){return true}","returnByValue":true})), Some(&session)).await.is_err());
        }
        fn find_button(node: &Value) -> Option<String> {
            if node["role"] == "button" { return node["ref"]["id"].as_str().map(str::to_owned); }
            node["children"].as_array()?.iter().find_map(find_button)
        }
        let id = find_button(&current["root"]).ok_or("B button missing")?;
        let current_refs = refs.lock().unwrap().clone();
        let (x, y, effective) = crate::native::element::resolve_element_center(
            &browser.client, &session, &current_refs, &id, &HashMap::new(), true).await?;
        for kind in ["mousePressed", "mouseReleased"] {
            browser.client.send_command("Input.dispatchMouseEvent", Some(json!({
                "type":kind,"x":x,"y":y,"button":"left","clickCount":1})), Some(&effective)).await?;
        }
        assert_eq!(evaluate_on(&browser.client, &session, "document.querySelector('button').textContent").await?, json!("Clicked"));
        Ok::<(), String>(())
    }.await;
    browser.close().await.unwrap();
    result.unwrap();
}

#[tokio::test]
#[ignore = "hosted Chromium: valid newer cancellation cannot revive old capture or retire committed refs"]
async fn chromium_cancelled_newer_admission_preserves_committed_observed_located_and_viewport() {
    use crate::native::browser::{evaluate_on, BrowserManager};
    use crate::native::client_observation::equivalence_tests::hold_metadata;
    let mut browser = BrowserManager::launch(Default::default(), None)
        .await
        .unwrap();
    let result = async {
        let session = browser.active_session_id()?.to_owned();
        let target = browser.active_target_id()?.to_owned();
        evaluate_on(&browser.client, &session,
            r#"document.body.innerHTML='<button data-testid="current" onclick="this.textContent=\'Clicked\'">Click</button>';true"#).await?;
        let owner = Owner::new(browser.client.clone(), &session, &target, "hosted-failed-newer").await;
        let refs = Arc::new(Mutex::new(RefMap::new()));
        let dispatch = ObservationDispatch::new(refs.clone());
        let (op, _s0_cancel) = operation(2001);
        let s0 = dispatch.clone().start(owner.context(), observe(), op);
        let committed = s0.result.await.map_err(|_| "S0 result lost")?.map_err(|e| format!("S0 failed: {:?}", e.error))?;
        s0.join.await.map_err(|_| "S0 join lost")?.map_err(|e| format!("S0 cleanup: {:?}", e.error))?;
        let revision = committed["revision"].as_str().ok_or("S0 revision missing")?.parse::<u64>().map_err(|_| "S0 revision malformed")?;
        let (op, _query_cancel) = operation(2002);
        let query = dispatch.clone().start(owner.context(), DispatchRequest::Query(QueryRequest {
            purpose: QueryPurpose::Fixture,
            options: serde_json::from_value(json!({"expression":{"kind":"query","query":{"kind":"testId","value":{"kind":"string","value":"current","exact":true}}},
                "testIdAttribute":"data-testid","secureFieldSelector":"input[type=password]"})).unwrap(),
        }), op);
        let located = query.result.await.map_err(|_| "located result lost")?.map_err(|e| format!("located failed: {:?}", e.error))?;
        query.join.await.map_err(|_| "located join lost")?.map_err(|e| format!("located cleanup: {:?}", e.error))?;
        let located_ref = located["nodes"][0]["ref"].clone();
        let before = refs.lock().unwrap().ref_ids();
        let (op, _a_cancel) = operation(2003);
        let (_guard, held) = hold_metadata(&op);
        let a = dispatch.clone().start(owner.context(), observe(), op);
        tokio::time::timeout(Duration::from_secs(8), held.reached()).await.map_err(|_| "A metadata missing")?;
        let (op, cancel_b) = operation(2004);
        let b = dispatch.prepare(owner.context(), observe(), op).map_err(|e| format!("B admission: {e:?}"))?;
        cancel_b.send_replace(CancelSignal::Requested);
        let b = dispatch.clone().start_prepared(b);
        let refused = b.result.await.map_err(|_| "B result lost")?.unwrap_err();
        b.join.await.map_err(|_| "B join lost")?.map_err(|e| format!("B cleanup: {:?}", e.error))?;
        assert_eq!(refused.error, ProtocolError::Cancelled);
        let stale = tokio::time::timeout(Duration::from_secs(8), a.result).await.map_err(|_| "A failed to retire")?.map_err(|_| "A result lost")?.unwrap_err();
        a.join.await.map_err(|_| "A join lost")?.map_err(|e| format!("A cleanup: {:?}", e.error))?;
        assert_eq!(stale.error, ProtocolError::StaleReference);
        assert!(!stale.cleanup_integrity_lost);
        assert_eq!(held.releases(), 1);
        assert_eq!(held.metadata_calls(), 1);
        held.release();
        assert_eq!(dispatch.publication.lock().await.observed_revision, revision);
        let current = refs.lock().unwrap().clone();
        assert_eq!(current.ref_ids(), before);
        let located_id = located_ref["id"].as_str().ok_or("located ref missing")?;
        let located_revision = located_ref["revision"].as_str().ok_or("located issuance missing")?;
        assert!(current.get(&parse_ref(located_id).unwrap()).unwrap().matches_reference(
            "hosted-failed-newer", 1, &session, located_revision));
        assert!(current.matches_viewport_reference("hosted-failed-newer", 1, &session,
            committed["viewportRef"]["id"].as_str().unwrap(), committed["viewportRef"]["revision"].as_str().unwrap()));
        let (x, y, effective) = crate::native::element::resolve_element_center(
            &browser.client, &session, &current, located_id, &HashMap::new(), true).await?;
        for kind in ["mousePressed", "mouseReleased"] {
            browser.client.send_command("Input.dispatchMouseEvent", Some(json!({
                "type":kind,"x":x,"y":y,"button":"left","clickCount":1})), Some(&effective)).await?;
        }
        assert_eq!(evaluate_on(&browser.client, &session, "document.querySelector('button').textContent").await?, json!("Clicked"));
        Ok::<(), String>(())
    }.await;
    browser.close().await.unwrap();
    result.unwrap();
}

fn trace_request() -> DispatchRequest {
    DispatchRequest::Screenshot(ScreenshotRequest {
        secure_field_selector: "input[type=password]".into(),
        purpose: ScreenshotPurpose::Trace,
    })
}
fn commit_trace(
    dispatch: &ObservationDispatch,
    prepared: &PreparedDispatch,
    publication: &mut Publication,
    revision: u64,
    refs: RefMap,
) -> Result<(), ProtocolError> {
    dispatch.commit_staged(
        &prepared.context.page,
        &prepared.operation,
        None,
        prepared.trace.as_ref(),
        prepared.retirement_fence,
        publication,
        PublicationKind::TraceViewport,
        revision,
        refs,
    )
}
#[tokio::test]
async fn first_trace_is_page_only_stable_and_failed_issuance_is_burned() {
    let (owner, server) = peer().await;
    let refs = Arc::new(Mutex::new(RefMap::new()));
    let dispatch = ObservationDispatch::new(refs.clone());
    let (op, _cancel) = operation(1);
    let trace = dispatch
        .prepare(owner.context(), trace_request(), op)
        .unwrap();
    assert!(trace.capture.is_none());
    assert!(dispatch.captures.lock().unwrap().latest.is_empty());
    let mut publication = dispatch.publication.lock().await;
    let revision = publication
        .stage_revision(PublicationKind::TraceViewport)
        .unwrap();
    assert_ne!(revision, 0);
    let mut abandoned = refs.lock().unwrap().clone();
    let burned = abandoned
        .try_viewport_ref("scope", 1, "session", revision)
        .unwrap()
        .id
        .clone();
    // A staged failed transaction installs nothing and does not recycle its ID.
    drop(abandoned);
    assert!(!refs.lock().unwrap().is_viewport_ref(&burned));
    let revision = publication
        .stage_revision(PublicationKind::TraceViewport)
        .unwrap();
    let mut staged = refs.lock().unwrap().clone();
    let viewport = staged
        .try_viewport_ref("scope", 1, "session", revision)
        .unwrap()
        .clone();
    assert_ne!(viewport.id, burned);
    commit_trace(&dispatch, &trace, &mut publication, revision, staged).unwrap();
    assert_eq!(publication.published_revision, 0);
    assert_eq!(publication.observed_revision, 0);
    assert!(refs.lock().unwrap().ref_ids().is_empty());
    let next_revision = publication
        .stage_revision(PublicationKind::TraceViewport)
        .unwrap();
    let mut next = refs.lock().unwrap().clone();
    assert_eq!(
        next.try_viewport_ref("scope", 1, "session", next_revision)
            .unwrap(),
        &viewport
    );
    commit_trace(&dispatch, &trace, &mut publication, next_revision, next).unwrap();
    assert!(refs.lock().unwrap().matches_viewport_reference(
        "scope",
        1,
        "session",
        &viewport.id,
        &revision.to_string()
    ));
    server.abort();
}
#[tokio::test]
async fn trace_fences_none_and_some_without_superseding_observe_or_other_traces() {
    let (owner, server) = peer().await;
    let refs = Arc::new(Mutex::new(RefMap::new()));
    let dispatch = ObservationDispatch::new(refs.clone());
    let (op, _cancel) = operation(1);
    let first = dispatch
        .prepare(owner.context(), trace_request(), op)
        .unwrap();
    let (op, _cancel) = operation(2);
    let observed = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let mut publication = dispatch.publication.lock().await;
    let revision = publication
        .stage_revision(PublicationKind::TraceViewport)
        .unwrap();
    assert_eq!(
        commit_trace(
            &dispatch,
            &first,
            &mut publication,
            revision,
            refs.lock().unwrap().clone()
        ),
        Err(ProtocolError::StaleReference)
    );
    let (op, _cancel) = operation(3);
    let trace = dispatch
        .prepare(owner.context(), trace_request(), op)
        .unwrap();
    let (op, _cancel) = operation(4);
    let other = dispatch
        .prepare(owner.context(), trace_request(), op)
        .unwrap();
    assert!(!*observed.capture.as_ref().unwrap().retired.borrow());
    assert_eq!(dispatch.captures.lock().unwrap().latest.len(), 1);
    // Observe may still publish, and traces cannot install staged node membership.
    let semantic_revision = publication
        .stage_revision(PublicationKind::Snapshot)
        .unwrap();
    let (semantic, id) = staged(&owner, &refs.lock().unwrap(), semantic_revision, 10);
    commit(
        &dispatch,
        &observed,
        &mut publication,
        semantic_revision,
        semantic,
    )
    .unwrap();
    for trace in [&trace, &other] {
        let revision = publication
            .stage_revision(PublicationKind::TraceViewport)
            .unwrap();
        let mut copy = refs.lock().unwrap().clone();
        copy.retire_all_references();
        copy.try_viewport_ref("scope", 1, "session", revision)
            .unwrap();
        commit_trace(&dispatch, trace, &mut publication, revision, copy).unwrap();
        assert!(refs
            .lock()
            .unwrap()
            .get(&id)
            .unwrap()
            .is_current_observed(semantic_revision));
        assert_eq!(publication.published_revision, semantic_revision);
        assert_eq!(publication.observed_revision, semantic_revision);
    }
    let (op, _cancel) = operation(5);
    let _new = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let copy = refs.lock().unwrap().clone();
    assert_eq!(
        commit_trace(&dispatch, &trace, &mut publication, revision, copy),
        Err(ProtocolError::StaleReference)
    );
    let (op, _cancel) = operation(5);
    assert!(matches!(
        dispatch.prepare(owner.context(), trace_request(), op),
        Err(ProtocolError::StaleReference)
    ));
    server.abort();
}
#[tokio::test]
async fn trace_requires_exact_scope_generation_and_attachment_owner() {
    let (owner, server) = peer().await;
    let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
    for mismatch in ["scope", "generation", "session"] {
        let mut context = owner.context();
        match mismatch {
            "scope" => context.scope.identity_scope = "other".into(),
            "generation" => context.scope.generation += 1,
            "session" => context.page.page_session_id = "other".into(),
            _ => unreachable!(),
        }
        let (op, _cancel) = operation(1);
        assert!(
            matches!(
                dispatch.prepare(context, trace_request(), op),
                Err(ProtocolError::StaleScope)
            ),
            "{mismatch}"
        );
        assert!(dispatch.captures.lock().unwrap().latest.is_empty());
    }
    server.abort();
}
#[test]
fn screenshot_purpose_is_closed_and_defaults_to_plain_pixels() {
    let request: ScreenshotRequest =
        serde_json::from_value(json!({"secureFieldSelector":"input"})).unwrap();
    assert_eq!(request.purpose, ScreenshotPurpose::PixelsOnly);
    assert!(serde_json::from_value::<ScreenshotRequest>(
        json!({"secureFieldSelector":"input", "purpose":"observe"})
    )
    .is_err());
}

// Full dispatcher coverage using the same empty-DOM/source-holder protocol as
// the fallback fixture. These tests exercise real PNG decoding and journal
// cleanup, but deliberately make no claim about renderer masking fidelity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureDispatchCase {
    TraceMaskFailure,
    TraceRestoreFailure,
    TraceFenceAfterCapture,
    InitialPressure,
    FreshFallbackPressure,
    ConfiguredOversize,
}

async fn capture_dispatch_case(case: CaptureDispatchCase) {
    use crate::native::client_blobs::BlobLimits;
    use base64::Engine;
    use futures_util::SinkExt;
    let pressure = matches!(
        case,
        CaptureDispatchCase::InitialPressure | CaptureDispatchCase::FreshFallbackPressure
    );
    let fallback = case == CaptureDispatchCase::FreshFallbackPressure;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let mut png = std::io::Cursor::new(Vec::new());
    image::DynamicImage::new_rgba8(10, 10)
        .write_to(&mut png, image::ImageFormat::Png)
        .unwrap();
    let png = base64::engine::general_purpose::STANDARD.encode(png.into_inner());
    let source = Arc::new(Mutex::new(Vec::new()));
    let peer_source = source.clone();
    let mask_releases = Arc::new(Mutex::new(Vec::new()));
    let peer_mask_releases = mask_releases.clone();
    let captures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peer_captures = captures.clone();
    let (capture_reached, capture_receipt) = oneshot::channel();
    let (capture_release, capture_resume) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut capture_reached = Some(capture_reached);
        let mut capture_resume = Some(capture_resume);
        let mut verifies = 0;
        while let Some(Ok(message)) = socket.next().await {
            let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
            let method = request["method"].as_str().unwrap();
            let result = match method {
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
                    assert_eq!(request["params"]["contextId"], 1);
                    assert_eq!(request["sessionId"], "session");
                    assert_eq!(request["params"]["objectGroup"], "capture-source-2-frame");
                    peer_source.lock().unwrap().push("holder");
                    json!({"result":{"type":"object","objectId":"source-holder"}})
                }
                "Runtime.callFunctionOn" => {
                    assert_eq!(request["params"]["objectId"], "source-holder");
                    assert_eq!(request["sessionId"], "session");
                    assert_eq!(request["params"]["objectGroup"], "capture-source-2-frame");
                    let phase = match request["params"]["functionDeclaration"].as_str().unwrap() {
                        "function(){return this.verify()}" => {
                            verifies += 1;
                            "verify"
                        }
                        "function(){return this.remove()}" => "remove",
                        other => panic!("unexpected source-holder call: {other}"),
                    };
                    peer_source.lock().unwrap().push(phase);
                    json!({"result":{"type":"boolean","value":!(case == CaptureDispatchCase::TraceMaskFailure && phase == "verify" && verifies == 2)}})
                }
                "Runtime.releaseObjectGroup" => {
                    assert_eq!(request["sessionId"], "session");
                    match request["params"]["objectGroup"].as_str().unwrap() {
                        // Independent coverage owns a separate read-only group,
                        // including when this finite fixture contains no nodes.
                        "capture-2-frame" => {
                            peer_mask_releases
                                .lock()
                                .unwrap()
                                .push(peer_captures.load(Ordering::SeqCst));
                        }
                        "capture-source-2-frame" => {
                            peer_source.lock().unwrap().push("release");
                        }
                        other => panic!("unexpected capture object group: {other}"),
                    }
                    json!({})
                }
                "Page.captureScreenshot" => {
                    peer_captures.fetch_add(1, Ordering::SeqCst);
                    if case == CaptureDispatchCase::TraceFenceAfterCapture {
                        capture_reached.take().unwrap().send(()).unwrap();
                        capture_resume.take().unwrap().await.unwrap();
                    }
                    json!({"data":png})
                }
                "Animation.enable" | "Animation.setPlaybackRate" | "Animation.disable" => json!({}),
                other => panic!("unexpected capture command: {other}"),
            };
            let response = if case == CaptureDispatchCase::TraceRestoreFailure
                && method == "Animation.setPlaybackRate"
                && request["params"]["playbackRate"].as_f64() == Some(1.0)
            {
                json!({"id":request["id"],"sessionId":request["sessionId"],"error":{"code":-32000,"message":"synthetic restoration refusal"}})
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
    let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
    let mut owner = Owner::new(client, "session", "target", "scope").await;
    let limit = if case == CaptureDispatchCase::ConfiguredOversize {
        32
    } else {
        64 * 1024 * 1024
    };
    owner.blobs = Arc::new(
        BlobStore::new(BlobLimits {
            max_blob_bytes: limit,
            max_total_bytes: if pressure {
                128 * 1024 * 1024
            } else {
                2 * limit
            },
            max_handles: 8,
        })
        .unwrap(),
    );
    owner.blobs.activate_scope(owner.scope.clone()).unwrap();
    // A tiny retained artifact is sufficient: 1 + 64 + 64 MiB exceeds the
    // default 128 MiB total, whereas 1 + 64 + 32 MiB fits. Reservations allocate
    // no giant buffers, and the protected screenshot itself is only 10 by 10.
    let retained = owner
        .blobs
        .insert_sealed(owner.scope.clone(), b"v")
        .unwrap();
    let active = pressure.then(|| owner.blobs.reserve_producer(owner.scope.clone()).unwrap());
    if pressure {
        assert!(matches!(
            owner.blobs.reserve_producer(owner.scope.clone()),
            Err(BlobError::QuotaExceeded)
        ));
        drop(
            owner
                .blobs
                .reserve_bounded_producer(owner.scope.clone(), client_capture::MAX_PNG_BYTES)
                .unwrap(),
        );
    }
    let refs = Arc::new(Mutex::new(RefMap::new()));
    let dispatch = ObservationDispatch::new(refs.clone());
    let (initial, observed) = staged(&owner, &refs.lock().unwrap(), 7, 10);
    *refs.lock().unwrap() = initial;
    let located = refs
        .lock()
        .unwrap()
        .try_bind_located(
            11,
            "button",
            owner.binding(),
            LocatedIssuance {
                identity_scope: "scope".into(),
                generation: 1,
                revision: 5,
            },
            None,
        )
        .unwrap();
    {
        let mut publication = dispatch.publication.lock().await;
        publication.revision = 7;
        publication.published_revision = 7;
        publication.observed_revision = 7;
    }
    let prior_ids = refs.lock().unwrap().ref_ids();
    // Existing authority must survive trace failures. The None -> Some fence
    // case intentionally starts with no admission, despite committed refs.
    let initial_admission = if !pressure && case != CaptureDispatchCase::TraceFenceAfterCapture {
        let (op, _cancel) = operation(1);
        Some(dispatch.prepare(owner.context(), observe(), op).unwrap())
    } else {
        None
    };
    if fallback {
        // Reuse the scoped semantic failure seam: only the semantic outcome is
        // injected; fresh producer admission, capture, restoration and publish run.
        *dispatch.semantic_failure_for_test.lock().unwrap() =
            Some(ObservationError::DeadlineExceeded);
    }
    let request = if fallback {
        DispatchRequest::Observe(ObserveRequest {
            options: ObserveFlags {
                pixel_fallback: true,
                ..Default::default()
            },
            test_id_attribute: "data-testid".into(),
            secure_field_selector: "input[type=password]".into(),
        })
    } else {
        trace_request()
    };
    let (op, _cancel) = operation(2);
    let task = dispatch.clone().start(owner.context(), request, op);
    let newer = if case == CaptureDispatchCase::TraceFenceAfterCapture {
        tokio::time::timeout(Duration::from_secs(5), capture_receipt)
            .await
            .unwrap()
            .unwrap();
        let (op, _cancel) = operation(3);
        let admitted = dispatch.prepare(owner.context(), observe(), op).unwrap();
        capture_release.send(()).unwrap();
        Some(admitted)
    } else {
        None
    };
    let result = tokio::time::timeout(Duration::from_secs(5), task.result)
        .await
        .unwrap()
        .unwrap();
    task.join.await.unwrap().unwrap();
    assert_eq!(captures.load(Ordering::SeqCst), 1);
    assert_eq!(
        *mask_releases.lock().unwrap(),
        if case == CaptureDispatchCase::TraceMaskFailure {
            vec![0]
        } else {
            vec![0, 1]
        },
        "independent coverage groups must be released before and after capture, unless source verification refuses the post-capture pass"
    );
    assert_eq!(
        *source.lock().unwrap(),
        ["holder", "verify", "verify", "remove", "release"]
    );
    if pressure {
        let output = result.unwrap();
        let pixels = if fallback { &output["pixels"] } else { &output };
        assert_eq!(pixels["width"], 10);
        assert_eq!(pixels["height"], 10);
        let handle = pixels["handle"].as_str().unwrap();
        assert!(owner
            .blobs
            .read(&owner.scope, handle, 0, 8)
            .unwrap()
            .starts_with(b"\x89PNG"));
        owner.blobs.release(&owner.scope, handle).unwrap();
        assert_eq!(
            owner.blobs.release(&owner.scope, handle),
            Err(BlobError::Missing)
        );
        if fallback {
            assert_eq!(output["treeUnavailable"], true);
        }
    } else {
        let failure = result.unwrap_err();
        assert_eq!(
            failure.error,
            match case {
                CaptureDispatchCase::TraceMaskFailure => ProtocolError::PolicyDenied,
                CaptureDispatchCase::TraceRestoreFailure => ProtocolError::BrowserFailure,
                CaptureDispatchCase::TraceFenceAfterCapture => ProtocolError::StaleReference,
                CaptureDispatchCase::ConfiguredOversize => ProtocolError::CapacityExceeded,
                _ => unreachable!(),
            }
        );
        assert_eq!(
            failure.cleanup_integrity_lost,
            case == CaptureDispatchCase::TraceRestoreFailure
        );
    }
    if !fallback {
        let publication = dispatch.publication.lock().await;
        assert_eq!(
            (
                publication.published_revision,
                publication.observed_revision
            ),
            (7, 7)
        );
        let current = refs.lock().unwrap();
        assert_eq!(current.ref_ids(), prior_ids);
        assert!(current.get(&observed).unwrap().is_current_observed(7));
        assert!(current
            .get(&located)
            .unwrap()
            .matches_reference("scope", 1, "session", "5"));
        if !pressure {
            // No viewport existed before capture. Asking a disposable clone for
            // one now must create a new issuance, not recover a leaked staging ID.
            let mut copy = current.clone();
            assert_eq!(
                copy.try_viewport_ref("scope", 1, "session", 999)
                    .unwrap()
                    .issuance
                    .revision,
                999
            );
        }
    }
    for admitted in [initial_admission.as_ref(), newer.as_ref()]
        .into_iter()
        .flatten()
    {
        let ticket = admitted.capture.as_ref().unwrap();
        assert!(!*ticket.retired.borrow());
        let authority = dispatch.captures.lock().unwrap();
        assert_eq!(authority.latest.len(), 1);
        assert!(Arc::ptr_eq(&authority.latest[0], ticket));
    }
    assert_eq!(
        owner.targets.inventory().is_err(),
        case == CaptureDispatchCase::TraceRestoreFailure
    );
    assert_eq!(
        owner
            .blobs
            .read(&owner.scope, &retained.handle, 0, 1)
            .unwrap(),
        b"v"
    );
    drop(active);
    owner.blobs.release(&owner.scope, &retained.handle).unwrap();
    // Fill the entire budget after the operation: a leaked producer OR finished
    // blob would make the second reservation fail. Integrity rejects double free.
    let first = owner.blobs.reserve_producer(owner.scope.clone()).unwrap();
    let second = owner.blobs.reserve_producer(owner.scope.clone()).unwrap();
    assert!(matches!(
        owner.blobs.reserve_bounded_producer(owner.scope.clone(), 1),
        Err(BlobError::QuotaExceeded)
    ));
    drop((first, second));
    owner.blobs.check_budget_integrity().unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn trace_dispatch_mask_failure_releases_source_and_preserves_observe() {
    capture_dispatch_case(CaptureDispatchCase::TraceMaskFailure).await;
}
#[tokio::test]
async fn trace_dispatch_restore_failure_seals_without_publishing_viewport() {
    capture_dispatch_case(CaptureDispatchCase::TraceRestoreFailure).await;
}
#[tokio::test]
async fn trace_dispatch_post_blob_fence_releases_blob_without_publishing_viewport() {
    capture_dispatch_case(CaptureDispatchCase::TraceFenceAfterCapture).await;
}
#[tokio::test]
async fn protected_initial_dispatch_fits_retained_video_and_active_producer_pressure() {
    capture_dispatch_case(CaptureDispatchCase::InitialPressure).await;
}
#[tokio::test]
async fn protected_fresh_fallback_dispatch_fits_retained_video_and_active_producer_pressure() {
    capture_dispatch_case(CaptureDispatchCase::FreshFallbackPressure).await;
}
#[tokio::test]
async fn protected_dispatch_configured_quota_oversize_restores_and_releases_every_charge() {
    capture_dispatch_case(CaptureDispatchCase::ConfiguredOversize).await;
}

#[tokio::test]
async fn uncertainty_retirement_fences_additive_trace_and_capture_without_recycling_refs() {
    let (owner, server) = peer().await;
    let refs = Arc::new(Mutex::new(RefMap::new()));
    let dispatch = ObservationDispatch::new(refs.clone());
    let (op, _cancel) = operation(1);
    let capture = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let (op, _cancel) = operation(2);
    let trace = dispatch
        .prepare(owner.context(), trace_request(), op)
        .unwrap();
    let old_fence = capture.retirement_fence;
    let (old_refs, old_node) = staged(&owner, &refs.lock().unwrap(), 1, 101);
    *refs.lock().unwrap() = old_refs.clone();
    let old_viewport = refs
        .lock()
        .unwrap()
        .try_viewport_ref("scope", 1, "session", 1)
        .unwrap()
        .id
        .clone();
    let next_before = refs.lock().unwrap().try_allocate_ref().unwrap();
    dispatch.retire_interaction().await.unwrap();
    assert!(dispatch.publication_fence().unwrap() > old_fence);
    assert!(!refs.lock().unwrap().is_viewport_ref(&old_viewport));
    assert!(refs.lock().unwrap().get(&old_node).is_none());
    let mut publication = dispatch.publication.lock().await;
    assert_eq!(publication.observed_revision, 0);
    assert_eq!(
        commit(&dispatch, &capture, &mut publication, 1, old_refs.clone()),
        Err(ProtocolError::StaleReference)
    );
    assert_eq!(
        commit_trace(&dispatch, &trace, &mut publication, 1, old_refs.clone()),
        Err(ProtocolError::StaleReference)
    );
    // Additive queries and pixels have no CaptureAdmission. They still cannot
    // bypass the one retirement fence to publish old refs or artifacts.
    for kind in [PublicationKind::AdditiveQuery, PublicationKind::PixelsOnly] {
        assert_eq!(
            dispatch.commit_staged(
                &capture.context.page,
                &capture.operation,
                None,
                None,
                old_fence,
                &mut publication,
                kind,
                1,
                old_refs.clone()
            ),
            Err(ProtocolError::StaleReference)
        );
    }
    drop(publication);
    let next_after = refs.lock().unwrap().try_allocate_ref().unwrap();
    assert_ne!(next_before, next_after);
    assert_ne!(old_node, next_after);
    assert_ne!(old_viewport, next_after);
    // Owner/connection/attachment and service authority remain live.
    owner.gate.enter(false).unwrap().check().unwrap();
    assert!(owner.targets.inventory().is_ok());
    drop(capture);
    drop(trace);
    drop(dispatch);
    drop(owner);
    server.abort();
}

#[path = "client_optional_mask_retirement_tests.rs"]
mod optional_mask_retirement_tests;

#[tokio::test]
async fn remote_debt_wait_leaves_callback_ui_free_and_supersession_retires_without_ack() {
    use crate::native::client_debt::{OperationKey, OwnerDebtLedger};
    let (owner, server) = peer().await;
    let ledger = OwnerDebtLedger::new(1, "scope".into());
    owner.client.install_debt_ledger(ledger.clone()).unwrap();
    let journal = ledger
        .operation(
            OperationKey {
                generation: 1,
                operation_seq: 99,
            },
            "target".into(),
            "session".into(),
        )
        .unwrap();
    let input = ledger
        .reserve_command(
            Some(&journal),
            "Input.dispatchMouseEvent",
            Some(&json!({"type":"mousePressed"})),
            Some("session"),
        )
        .unwrap()
        .submit()
        .unwrap();
    let refs = Arc::new(Mutex::new(RefMap::new()));
    let dispatch = ObservationDispatch::new(refs);
    let (op, _cancel) = operation(1);
    let a = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let mut task = dispatch.clone().start_prepared(a);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut task.result)
            .await
            .is_err()
    );
    // A late paused browser event must be able to enter and release the input.
    let reservation = owner.ui.reserve_callback().unwrap();
    let (callback, _cancel_callback) = operation(3);
    let entered = tokio::time::timeout(
        Duration::from_millis(100),
        reservation.enter(callback.deadline, callback.cancellation),
    )
    .await
    .unwrap()
    .unwrap();
    drop(entered);
    let (op, _cancel_next) = operation(2);
    let _replacement = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let failure = tokio::time::timeout(Duration::from_millis(100), task.result)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.error, ProtocolError::StaleReference);
    assert!(!failure.cleanup_integrity_lost);
    task.join.await.unwrap().unwrap();
    assert_eq!(ledger.snapshot().input_debt, 1);
    assert_eq!(dispatch.publication.lock().await.revision, 0);
    drop(input);
    owner.client.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn remote_debt_ack_cannot_admit_a_replacement_with_reused_textual_ids() {
    use crate::native::client_debt::{OperationKey, OwnerDebtLedger};
    let (owner, server) = peer().await;
    let ledger = OwnerDebtLedger::new(1, "scope".into());
    owner.client.install_debt_ledger(ledger.clone()).unwrap();
    let journal = ledger
        .operation(
            OperationKey {
                generation: 1,
                operation_seq: 99,
            },
            "target".into(),
            "session".into(),
        )
        .unwrap();
    let input = ledger
        .reserve_command(
            Some(&journal),
            "Input.dispatchMouseEvent",
            Some(&json!({"type":"mousePressed"})),
            Some("session"),
        )
        .unwrap()
        .submit()
        .unwrap();
    let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
    let (op, _cancel) = operation(1);
    let captured = dispatch.prepare(owner.context(), observe(), op).unwrap();
    let mut task = dispatch.clone().start_prepared(captured);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut task.result)
            .await
            .is_err()
    );
    owner.targets.detach("target").unwrap();
    owner
        .targets
        .attached("context", "target".into(), "session".into(), "page".into())
        .unwrap();
    owner.targets.configured("target").unwrap();
    owner
        .targets
        .resume_permit("target")
        .await
        .unwrap()
        .complete()
        .unwrap();
    input.settle(
        &serde_json::from_value(json!({"id":1,"sessionId":"session","result":{}})).unwrap(),
    );
    let failure = tokio::time::timeout(Duration::from_secs(1), task.result)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.error, ProtocolError::StaleScope);
    task.join.await.unwrap().unwrap();
    assert_eq!(ledger.snapshot().input_debt, 0);
    assert_eq!(dispatch.publication.lock().await.revision, 0);
    owner.client.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn field_read_waits_for_debt_only_outside_a_live_callback_before_acquisition() {
    use crate::native::client_debt::{OperationKey, OwnerDebtLedger};
    use crate::native::client_session::{ClientSession, DecisionKind, DecisionOwner};
    use futures_util::SinkExt;
    use std::sync::atomic::AtomicUsize;
    for callback in [false, true] {
        let acquired = Arc::new(AtomicUsize::new(0));
        let seen = acquired.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(message) = socket.next().await {
                let message = message.expect("mock CDP websocket protocol failed");
                let text = match message {
                    tokio_tungstenite::tungstenite::Message::Close(_) => break,
                    tokio_tungstenite::tungstenite::Message::Text(text) => text,
                    other => panic!("unexpected mock CDP websocket frame: {other:?}"),
                };
                let request: Value = serde_json::from_str(&text).unwrap();
                assert_eq!(request["method"], "Page.getFrameTree");
                seen.fetch_add(1, Ordering::SeqCst);
                // Refuse the first read after admission: this test proves the
                // exact acquisition boundary, not renderer value semantics.
                if socket.send(tokio_tungstenite::tungstenite::Message::Text(
                    json!({"id":request["id"],"sessionId":request["sessionId"],"error":{"code":-32000,"message":"synthetic acquisition boundary"}}).to_string()
                )).await.is_err() { break; }
            }
        });
        let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
        let owner = Owner::new(client, "session", "target", "scope").await;
        let ledger = OwnerDebtLedger::new(1, "scope".into());
        owner.client.install_debt_ledger(ledger.clone()).unwrap();
        let parent = ledger
            .operation(
                OperationKey {
                    generation: 1,
                    operation_seq: 99,
                },
                "target".into(),
                "session".into(),
            )
            .unwrap();
        let mut input = Some(
            ledger
                .reserve_command(
                    Some(&parent),
                    "Input.dispatchMouseEvent",
                    Some(&json!({"type":"mousePressed"})),
                    Some("session"),
                )
                .unwrap()
                .submit()
                .unwrap(),
        );
        let broker = Arc::new(ClientSession::new());
        let decision = if callback {
            Some(
                broker
                    .decision_scoped(
                        1,
                        DecisionOwner::Scope,
                        DecisionKind::Authentication,
                        5000,
                        None,
                        Some("scope".into()),
                    )
                    .unwrap(),
            )
        } else {
            None
        };
        let operation = broker
            .admit_callback(
                1,
                1,
                5000,
                decision.as_ref().map(|decision| decision.token.as_str()),
            )
            .unwrap();
        assert!(broker.start(1, 1).unwrap());
        let journal = ledger
            .operation(
                OperationKey {
                    generation: 1,
                    operation_seq: 1,
                },
                "target".into(),
                "session".into(),
            )
            .unwrap();
        journal.bind_operation(&operation).unwrap();
        let refs = Arc::new(Mutex::new(RefMap::new()));
        let dispatch = ObservationDispatch::new(refs.clone());
        let request = DispatchRequest::ReadFields(FieldReadRequest { broker, fields: vec![observation::ReadField::Text], options: serde_json::from_value(json!({"expression":{"kind":"selector","selector":"button"},"secureFieldSelector":"input[type=password]"})).unwrap() });
        let prepared = dispatch
            .prepare(owner.context(), request, operation)
            .unwrap();
        let mut task = journal
            .scope(async { dispatch.clone().start_prepared(prepared) })
            .await;
        if !callback {
            assert!(
                tokio::time::timeout(Duration::from_millis(10), &mut task.result)
                    .await
                    .is_err()
            );
            assert_eq!(acquired.load(Ordering::SeqCst), 0);
            assert_eq!(ledger.snapshot().input_debt, 1);
            input.take().unwrap().settle(
                &serde_json::from_value(json!({"id":1,"sessionId":"session","result":{}})).unwrap(),
            );
        }
        let failure = tokio::time::timeout(Duration::from_secs(1), task.result)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(failure.error, ProtocolError::BrowserFailure);
        task.join.await.unwrap().unwrap();
        assert_eq!(acquired.load(Ordering::SeqCst), 1);
        assert_eq!(ledger.snapshot().input_debt, if callback { 1 } else { 0 });
        assert!(refs.lock().unwrap().ref_ids().is_empty());
        assert_eq!(dispatch.publication.lock().await.revision, 0);
        drop(input);
        owner.client.close().await;
        server.await.unwrap();
    }
}
