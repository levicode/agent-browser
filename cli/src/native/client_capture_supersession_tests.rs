//! Admission/commit branch proof plus a separately ignored real Chromium race.
//! The in-memory commit cases are not evidence of renderer cleanup/actionability.
use super::*;
use crate::native::cdp::client::CdpClient;
use crate::native::client_browser::ExecutionGate;
use crate::native::client_targets::ClientTargets;
use crate::native::element::{ExactBinding, LocatedIssuance};
use futures_util::StreamExt;

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
        DispatchRequest::Screenshot(CaptureRequest {
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
