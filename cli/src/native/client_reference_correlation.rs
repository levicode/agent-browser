//! Closed, production-wire-visible fixture identity correlation. This neither
//! evaluates a locator nor publishes references or page content. A live source's
//! acquisition identity is not its independently resolved future action target.
use super::*;
use crate::native::client_observation::NodeReference;
use crate::native::element::{
    ExactBinding, NativeReferenceKind, RefLifetime, MAX_EXACT_REFERENCES,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CorrelateRequest {
    pub located: Vec<NodeReference>,
    pub observed: Vec<NodeReference>,
}

type FrameIdentity = (String, String, String, String);
type NodeIdentity = (FrameIdentity, i64);
fn frame_identity(binding: &ExactBinding) -> FrameIdentity {
    (
        binding.page_session.clone(),
        binding.session.clone(),
        binding.frame.clone(),
        binding.loader.clone(),
    )
}
fn canonical_positive(value: &str) -> bool {
    value
        .parse::<u64>()
        .is_ok_and(|number| number > 0 && number.to_string() == value)
}
fn canonical_ref(reference: &NodeReference) -> Result<String, ProtocolError> {
    let id = reference
        .id
        .strip_prefix("@e")
        .filter(|id| canonical_positive(id))
        .ok_or(ProtocolError::InvalidArguments)?;
    if !canonical_positive(&reference.revision) {
        return Err(ProtocolError::InvalidArguments);
    }
    Ok(format!("e{id}"))
}
struct Authority<'a> {
    refs: &'a RefMap,
    scope: &'a str,
    generation: u64,
    page_session: &'a str,
    observed_revision: u64,
    frames: &'a [ObservationFrame],
}
struct Plan {
    bindings: Vec<(ExactBinding, i64)>,
    matches: Vec<Option<NodeReference>>,
}
fn plan(
    request: &CorrelateRequest,
    authority: Authority<'_>,
    check: impl Fn() -> Result<(), ProtocolError>,
) -> Result<Plan, ProtocolError> {
    if request
        .located
        .len()
        .checked_add(request.observed.len())
        .is_none_or(|n| n > MAX_EXACT_REFERENCES)
    {
        return Err(ProtocolError::CapacityExceeded);
    }
    if authority.observed_revision == 0 {
        return Err(ProtocolError::StaleReference);
    }
    let frames = authority
        .frames
        .iter()
        .map(|frame| frame_identity(&frame.binding))
        .collect::<HashSet<_>>();
    let mut observed = HashMap::<NodeIdentity, NodeReference>::new();
    let mut bindings = HashMap::<NodeIdentity, ExactBinding>::new();
    let mut located = Vec::with_capacity(request.located.len());
    for (is_observed, candidates) in [(true, &request.observed), (false, &request.located)] {
        let mut ids = HashSet::new();
        for (index, reference) in candidates.iter().enumerate() {
            if index % 64 == 0 {
                check()?;
            }
            let id = canonical_ref(reference)?;
            if !ids.insert(id.clone()) || authority.refs.is_viewport_ref(&reference.id) {
                return Err(ProtocolError::InvalidArguments);
            }
            let entry = authority
                .refs
                .get(&id)
                .ok_or(ProtocolError::StaleReference)?;
            if is_observed != matches!(entry.lifetime, RefLifetime::Observed) {
                return Err(ProtocolError::InvalidArguments);
            }
            if !entry.matches_scope(
                authority.scope,
                authority.generation,
                authority.page_session,
            ) {
                return Err(ProtocolError::StaleScope);
            }
            if !entry.matches_reference(
                authority.scope,
                authority.generation,
                authority.page_session,
                &reference.revision,
            ) {
                return Err(ProtocolError::StaleReference);
            }
            if is_observed && !entry.is_current_observed(authority.observed_revision) {
                return Err(ProtocolError::StaleReference);
            }
            let binding = entry
                .exact_binding
                .as_ref()
                .ok_or(ProtocolError::StaleReference)?;
            if !frames.contains(&frame_identity(binding)) {
                return Err(ProtocolError::StaleReference);
            }
            if entry.kind != NativeReferenceKind::Dom {
                if is_observed && entry.kind == NativeReferenceKind::ReadOnlyCssPseudo {
                    continue;
                }
                return Err(ProtocolError::InvalidArguments);
            }
            let backend = entry
                .backend_node_id
                .filter(|id| *id > 0)
                .ok_or(ProtocolError::StaleReference)?;
            // Actionability is deliberately not identity: document and Text
            // nodes are legitimate semantic DOM nodes without input authority.
            let key = (frame_identity(binding), backend);
            bindings
                .entry(key.clone())
                .or_insert_with(|| binding.clone());
            if is_observed {
                if observed.insert(key, reference.clone()).is_some() {
                    return Err(ProtocolError::BrowserFailure);
                }
            } else {
                located.push(key);
            }
        }
    }
    let matches = located
        .into_iter()
        .map(|key| observed.get(&key).cloned())
        .collect();
    let bindings = bindings
        .into_iter()
        .map(|((_, backend), binding)| (binding, backend))
        .collect();
    check()?;
    Ok(Plan { bindings, matches })
}

pub(super) async fn run(
    dispatch: &ObservationDispatch,
    context: &DispatchContext,
    request: &CorrelateRequest,
    operation: &OperationLease,
    observed_revision: u64,
    cleanup: &AtomicBool,
) -> Result<Value, ProtocolError> {
    // Caller holds UI then publication. No stage_revision/commit_refs path is
    // entered, including on failure. Existing retained settlement owns cleanup.
    let frames = verified_frames_with_cleanup(&context.page, operation, Some(cleanup)).await?;
    let planned = {
        let refs = dispatch
            .refs
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        plan(
            request,
            Authority {
                refs: &refs,
                scope: &context.scope.identity_scope,
                generation: operation.generation,
                page_session: &context.page.page_session_id,
                observed_revision,
                frames: &frames,
            },
            || check(&context.page, operation),
        )?
    };
    observation::validate_acquisition_bindings(
        &context.page.client,
        &frames,
        &planned.bindings,
        operation,
    )
    .await
    .map_err(|error| observation_error_with_cleanup(error, cleanup))?;
    let after = verified_frames_with_cleanup(&context.page, operation, Some(cleanup)).await?;
    same_frames(&frames, &after)?;
    check(&context.page, operation)?;
    let value = json!({"identityScope":context.scope.identity_scope,"matches":planned.matches});
    bounded_result(&value)?;
    check(&context.page, operation)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::element::{LiveQueryOrigin, LocatedIssuance};
    fn binding() -> ExactBinding {
        ExactBinding {
            page_session: "page".into(),
            session: "session".into(),
            frame: "frame".into(),
            loader: "loader".into(),
            actionable: true,
        }
    }
    fn frame() -> ObservationFrame {
        ObservationFrame {
            binding: binding(),
            parent_frame_id: None,
            owner_backend_id: None,
            url: "about:blank".into(),
            offset_x: 0.0,
            offset_y: 0.0,
            frame_path: vec![],
        }
    }
    fn node(id: &str, revision: u64) -> NodeReference {
        NodeReference {
            id: format!("@{id}"),
            revision: revision.to_string(),
        }
    }
    fn located(refs: &mut RefMap, backend: i64) -> NodeReference {
        node(
            &refs
                .try_bind_located(
                    backend,
                    "button",
                    binding(),
                    LocatedIssuance {
                        identity_scope: "scope".into(),
                        generation: 7,
                        revision: 2,
                    },
                    Some(LiveQueryOrigin::new("immutable-live-source".into())),
                )
                .unwrap(),
            2,
        )
    }
    fn build(request: &CorrelateRequest, refs: &RefMap) -> Result<Plan, ProtocolError> {
        plan(
            request,
            Authority {
                refs,
                scope: "scope",
                generation: 7,
                page_session: "page",
                observed_revision: 5,
                frames: &[frame()],
            },
            || Ok(()),
        )
    }
    #[test]
    fn distinct_issuances_correlate_without_changing_identity_or_source() {
        let mut refs = RefMap::new();
        refs.begin_observation("scope", 7, 5);
        let a = located(&mut refs, 42);
        let b = located(&mut refs, 42);
        let c = located(&mut refs, 43);
        let mut semantic = binding();
        semantic.actionable = false;
        let observed = node(&refs.try_bind_exact(42, "button", "", semantic).unwrap(), 5);
        let pseudo = node(
            &refs
                .try_bind_readonly_pseudo(44, "text", binding())
                .unwrap(),
            5,
        );
        let before = (
            refs.ref_ids(),
            refs.retained_identity_counts(),
            refs.retained_query_origin_bytes(),
            refs.next_ref_num(),
        );
        let request = CorrelateRequest {
            located: vec![a.clone(), b, c],
            observed: vec![pseudo, observed.clone()],
        };
        let result = build(&request, &refs).unwrap();
        assert_eq!(
            result.matches,
            vec![Some(observed.clone()), Some(observed), None]
        );
        assert_eq!(result.bindings.len(), 2);
        assert_eq!(
            before,
            (
                refs.ref_ids(),
                refs.retained_identity_counts(),
                refs.retained_query_origin_bytes(),
                refs.next_ref_num()
            )
        );
        assert_eq!(
            refs.get(a.id.trim_start_matches('@'))
                .unwrap()
                .live_query
                .as_ref()
                .unwrap()
                .source
                .as_ref(),
            "immutable-live-source"
        );
    }
    #[test]
    fn stable_observed_issuance_correlates_only_in_current_committed_membership() {
        let mut refs = RefMap::new();
        refs.begin_observation("scope", 7, 4);
        let acquired = located(&mut refs, 42);
        let id = refs.bind_exact(42, "button", "", binding());
        let original = node(&id, 4);
        refs.begin_observation("scope", 7, 5);
        assert_eq!(refs.bind_exact(42, "button", "", binding()), id);
        let request = CorrelateRequest {
            located: vec![acquired],
            observed: vec![original.clone()],
        };
        assert_eq!(
            build(&request, &refs).unwrap().matches,
            vec![Some(original)]
        );
        let baseline = refs.clone();
        refs.retain_snapshot_entries(&baseline, &Default::default());
        assert!(matches!(
            build(&request, &refs),
            Err(ProtocolError::StaleReference)
        ));
        // A valid old issuance in an active but differently committed snapshot
        // also does not prove membership in the authority's current snapshot5.
        refs.begin_observation("scope", 7, 6);
        refs.bind_exact(42, "button", "", binding());
        assert!(matches!(
            build(&request, &refs),
            Err(ProtocolError::StaleReference)
        ));
    }

    #[test]
    fn malformed_wrong_population_stale_revision_and_unpublished_refs_refuse() {
        let mut refs = RefMap::new();
        refs.begin_observation("scope", 7, 5);
        let acquired = located(&mut refs, 42);
        let observed = node(
            &refs.try_bind_exact(42, "button", "", binding()).unwrap(),
            5,
        );
        for (located, observed, error) in [
            (
                vec![acquired.clone(), acquired.clone()],
                vec![observed.clone()],
                ProtocolError::InvalidArguments,
            ),
            (
                vec![observed.clone()],
                vec![observed.clone()],
                ProtocolError::InvalidArguments,
            ),
            (
                vec![acquired.clone()],
                vec![acquired.clone()],
                ProtocolError::InvalidArguments,
            ),
            (
                vec![node("e999", 2)],
                vec![observed.clone()],
                ProtocolError::StaleReference,
            ),
            (
                vec![NodeReference {
                    id: acquired.id.clone(),
                    revision: "02".into(),
                }],
                vec![observed.clone()],
                ProtocolError::InvalidArguments,
            ),
            (
                vec![NodeReference {
                    id: acquired.id.clone(),
                    revision: "3".into(),
                }],
                vec![observed.clone()],
                ProtocolError::StaleReference,
            ),
            (
                vec![acquired.clone()],
                vec![NodeReference {
                    id: observed.id.clone(),
                    revision: "4".into(),
                }],
                ProtocolError::StaleReference,
            ),
        ] {
            assert!(
                matches!(build(&CorrelateRequest{located,observed},&refs),Err(actual) if actual==error)
            );
        }
        let mut unpublished = refs.clone();
        let staged = node(
            &unpublished
                .try_bind_exact(99, "button", "", binding())
                .unwrap(),
            5,
        );
        assert!(matches!(
            build(
                &CorrelateRequest {
                    located: vec![acquired],
                    observed: vec![staged]
                },
                &refs
            ),
            Err(ProtocolError::StaleReference)
        ));
    }
    #[test]
    fn wrong_scope_document_and_viewport_cannot_correlate() {
        let mut refs = RefMap::new();
        refs.begin_observation("scope", 7, 5);
        let acquired = located(&mut refs, 42);
        let observed = node(
            &refs.try_bind_exact(42, "button", "", binding()).unwrap(),
            5,
        );
        let request = CorrelateRequest {
            located: vec![acquired.clone()],
            observed: vec![observed.clone()],
        };
        for (scope, generation, page) in [
            ("other", 7, "page"),
            ("scope", 8, "page"),
            ("scope", 7, "other"),
        ] {
            assert!(matches!(
                plan(
                    &request,
                    Authority {
                        refs: &refs,
                        scope,
                        generation,
                        page_session: page,
                        observed_revision: 5,
                        frames: &[frame()]
                    },
                    || Ok(())
                ),
                Err(ProtocolError::StaleScope)
            ));
        }
        let mut changed = frame();
        changed.binding.loader = "replacement".into();
        assert!(matches!(
            plan(
                &request,
                Authority {
                    refs: &refs,
                    scope: "scope",
                    generation: 7,
                    page_session: "page",
                    observed_revision: 5,
                    frames: &[changed]
                },
                || Ok(())
            ),
            Err(ProtocolError::StaleReference)
        ));
        let viewport = node(&refs.try_viewport_ref("scope", 7, "page", 5).unwrap().id, 5);
        assert!(matches!(
            build(
                &CorrelateRequest {
                    located: vec![acquired],
                    observed: vec![viewport]
                },
                &refs
            ),
            Err(ProtocolError::InvalidArguments)
        ));
        assert!(matches!(
            plan(
                &request,
                Authority {
                    refs: &refs,
                    scope: "scope",
                    generation: 7,
                    page_session: "page",
                    observed_revision: 5,
                    frames: &[frame()]
                },
                || Err(ProtocolError::Cancelled)
            ),
            Err(ProtocolError::Cancelled)
        ));
    }
    #[tokio::test]
    async fn actual_dispatch_correlates_once_without_publishing_and_rejects_replacement() {
        use crate::native::cdp::client::CdpClient;
        use crate::native::client_browser::ExecutionGate;
        use crate::native::client_targets::ClientTargets;
        use futures_util::{SinkExt, StreamExt};
        use std::sync::atomic::AtomicUsize;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let present = Arc::new(AtomicBool::new(true));
        let inventories = Arc::new(AtomicUsize::new(0));
        let server_present = present.clone();
        let server_inventories = inventories.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = ws.next().await {
                if message.is_close() {
                    break;
                }
                let Ok(text) = message.to_text() else { break };
                let request: Value = serde_json::from_str(text).unwrap();
                let result = match request["method"].as_str().unwrap() {
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"frame","loaderId":"loader","url":"about:blank"}}})
                    }
                    "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                    "DOM.getDocument" => {
                        server_inventories.fetch_add(1, Ordering::SeqCst);
                        let children = if server_present.load(Ordering::SeqCst) {
                            json!([{"nodeType":1,"backendNodeId":42},{"nodeType":1,"backendNodeId":43}])
                        } else {
                            json!([{"nodeType":1,"backendNodeId":43}])
                        };
                        json!({"root":{"nodeType":9,"backendNodeId":1,"children":children}})
                    }
                    method => panic!(
                        "correlation must not acquire metadata, masks, handles or input: {method}"
                    ),
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
            .attached("context", "target".into(), "page".into(), "page".into())
            .unwrap();
        targets.configured("target").unwrap();
        targets
            .resume_permit("target")
            .await
            .unwrap()
            .complete()
            .unwrap();
        targets.acknowledge_enrollment().unwrap();
        let gate = Arc::new(ExecutionGate::default());
        let blobs = Arc::new(BlobStore::new(Default::default()).unwrap());
        let scope = BlobScope {
            generation: 7,
            identity_scope: "scope".into(),
        };
        blobs.activate_scope(scope.clone()).unwrap();
        let refs = Arc::new(Mutex::new(RefMap::new()));
        let dispatch = ObservationDispatch::new(refs.clone());
        let exact = ExactBinding {
            session: "page".into(),
            ..binding()
        };
        let (acquired, other, observed) = {
            let mut staged = refs.lock().unwrap().clone();
            let acquired = node(
                &staged
                    .try_bind_located(
                        42,
                        "button",
                        exact.clone(),
                        LocatedIssuance {
                            identity_scope: "scope".into(),
                            generation: 7,
                            revision: 1,
                        },
                        None,
                    )
                    .unwrap(),
                1,
            );
            let other = node(
                &staged
                    .try_bind_located(
                        43,
                        "button",
                        exact.clone(),
                        LocatedIssuance {
                            identity_scope: "scope".into(),
                            generation: 7,
                            revision: 1,
                        },
                        None,
                    )
                    .unwrap(),
                1,
            );
            let mut publication = dispatch.publication.lock().await;
            let revision = publication
                .stage_revision(PublicationKind::Snapshot)
                .unwrap();
            staged.begin_observation("scope", 7, revision);
            let observed = node(
                &staged.try_bind_exact(42, "button", "", exact).unwrap(),
                revision,
            );
            publication.commit_refs(
                PublicationKind::Snapshot,
                revision,
                &mut refs.lock().unwrap(),
                staged,
            );
            (acquired, other, observed)
        };
        let before_refs = {
            let refs = refs.lock().unwrap();
            (
                refs.ref_ids(),
                refs.retained_identity_counts(),
                refs.retained_query_origin_bytes(),
                refs.next_ref_num(),
            )
        };
        let before_publication = {
            let publication = dispatch.publication.lock().await;
            (
                publication.revision,
                publication.published_revision,
                publication.observed_revision,
            )
        };
        let ui = Arc::new(UiGate::default());
        let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        for sequence in 1..=2 {
            if sequence == 2 {
                present.store(false, Ordering::SeqCst);
            }
            let task = dispatch.clone().start(
                DispatchContext {
                    #[cfg(feature = "acceptance-faults")]
                    faults: Arc::new(crate::native::client_test_faults::FaultController::default()),
                    attachment: targets.owned_target("target").unwrap(),
                    page: BrowserExecutionLease {
                        client: client.clone(),
                        page_session_id: "page".into(),
                        target_id: "target".into(),
                        identity_scope: "scope".into(),
                        permit: gate.enter(false).unwrap(),
                        targets: targets.clone(),
                    },
                    ui: ui.clone(),
                    blobs: blobs.clone(),
                    scope: scope.clone(),
                    policy: ReadPolicy {
                        test_id_attribute: "data-testid".into(),
                        secure_field_selector: "input[type=\"password\" i]".into(),
                    },
                },
                DispatchRequest::Correlate(CorrelateRequest {
                    located: vec![acquired.clone(), other.clone()],
                    observed: vec![observed.clone()],
                }),
                OperationLease {
                    generation: 7,
                    sequence,
                    is_callback: false,
                    deadline: Instant::now() + Duration::from_secs(5),
                    cancellation: cancellation.clone(),
                },
            );
            let result = task.result.await.unwrap();
            task.join.await.unwrap().unwrap();
            if sequence == 1 {
                assert_eq!(
                    result.unwrap(),
                    json!({"identityScope":"scope","matches":[observed,null]})
                );
            } else {
                let failure = result.unwrap_err();
                assert_eq!(failure.error, ProtocolError::StaleReference);
                assert!(!failure.cleanup_integrity_lost);
            }
            {
                let current = refs.lock().unwrap();
                assert_eq!(
                    before_refs,
                    (
                        current.ref_ids(),
                        current.retained_identity_counts(),
                        current.retained_query_origin_bytes(),
                        current.next_ref_num()
                    )
                );
            }
            let publication = dispatch.publication.lock().await;
            assert_eq!(
                before_publication,
                (
                    publication.revision,
                    publication.published_revision,
                    publication.observed_revision
                )
            );
        }
        assert_eq!(
            inventories.load(Ordering::SeqCst),
            2,
            "one DOM inventory per command, not per candidate"
        );
        client.close().await;
        server.await.unwrap();
    }
}
