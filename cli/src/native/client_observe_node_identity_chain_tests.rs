//! Layered native chain only: frozen semantic refs/frames -> real CDP node
//! resolver/geometry -> the production dispatcher guard -> final settlement.
//! No AX/ARIA/metadata responder, hook, browser, beforeunload or worker fixture.
use super::super::cdp::client::CdpClient;
use super::super::client_browser::{settle_observation_dispatch, ExecutionGate};
use super::super::client_debt::{OperationJournalHandle, OperationKey, OwnerDebtLedger};
use super::super::client_geometry::{GeometryError, NodeGeometryOrigin};
use super::super::client_protocol::Effects;
use super::super::client_targets::ClientTargets;
use super::*;
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::AtomicUsize;
use tokio::sync::{watch, Notify};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplyCase {
    ResolveNegative,
    BoxNegative,
    ResolveWrongType,
    ResolveMissingType,
    ResolveObjectId,
    ResolveUnserializable,
    ResolveException,
    BoxWrongType,
    BoxObjectId,
    BoxNullSubtype,
    BoxMissingValue,
    DocumentNegative,
    ConcurrentHard,
    CleanupFailure,
}
struct Script {
    case: ReplyCase,
    multi: bool,
    resolved: AtomicBool,
    recheck: AtomicBool,
    change_child: AtomicBool,
    pause_recheck: AtomicBool,
    recheck_seen: Notify,
    continue_recheck: Notify,
    released: Notify,
    flush_releases: AtomicBool,
    releases: AtomicUsize,
    commands: Mutex<Vec<String>>,
}
impl Script {
    fn tree(&self) -> Value {
        let loader =
            if self.case == ReplyCase::DocumentNegative && self.resolved.load(Ordering::SeqCst) {
                "successor"
            } else {
                "loader"
            };
        let mut root =
            json!({"frame":{"id":"frame","loaderId":loader,"url":"https://fixture.invalid/"}});
        if self.multi {
            let child_loader = if self.recheck.load(Ordering::SeqCst)
                && self.change_child.load(Ordering::SeqCst)
            {
                "new-child"
            } else {
                "child-loader"
            };
            root["childFrames"] = json!([{"frame":{"id":"child","parentId":"frame","loaderId":child_loader,"url":"https://fixture.invalid/child"}}]);
        }
        json!({"frameTree":root})
    }
    fn native_response(&self, request: &Value) -> Result<Value, ()> {
        let method = request["method"].as_str().unwrap();
        let params = &request["params"];
        match method {
            "Page.getFrameTree" => Ok(self.tree()),
            "Page.getLayoutMetrics" => Ok(
                json!({"cssVisualViewport":{"clientWidth":800,"clientHeight":600,"offsetX":0,"offsetY":0,"scale":1},"cssLayoutViewport":{"clientWidth":800,"clientHeight":600}}),
            ),
            "Page.createIsolatedWorld" => {
                Ok(json!({"executionContextId":if params["frameId"]=="child" {12} else {11}}))
            }
            "DOM.getFrameOwner" => Ok(json!({"backendNodeId":3})),
            "DOM.resolveNode" => {
                let backend = params["backendNodeId"].as_i64().unwrap();
                if backend == 2 && self.case == ReplyCase::DocumentNegative {
                    self.resolved.store(true, Ordering::SeqCst);
                }
                Ok(
                    json!({"object":{"type":"object","subtype":"node","objectId":format!("node-{backend}")}}),
                )
            }
            "DOM.getBoxModel" => Ok(
                json!({"model":{"border":[0,0,100,0,100,100,0,100],"content":[0,0,100,0,100,100,0,100],"width":100,"height":100}}),
            ),
            "Runtime.callFunctionOn" => {
                let function = params["functionDeclaration"].as_str().unwrap();
                let object = params["objectId"].as_str().unwrap();
                let is_node = object == "node-2" || object == "node-4";
                if is_node && object == "node-4" && self.case == ReplyCase::ConcurrentHard {
                    return Err(());
                }
                if function == super::super::client_geometry::BOX_PROOF {
                    if object == "node-3" {
                        return Ok(
                            json!({"result":{"type":"object","value":{"connected":true,"frameOwner":true,"width":100,"height":100}}}),
                        );
                    }
                    let mut response =
                        json!({"result":{"type":"object","value":{"connected":false}}});
                    match self.case {
                        ReplyCase::BoxWrongType => response["result"]["type"] = "string".into(),
                        ReplyCase::BoxObjectId => {
                            response["result"]["objectId"] = "unexpected-handle".into()
                        }
                        ReplyCase::BoxNullSubtype => response["result"]["subtype"] = "null".into(),
                        ReplyCase::BoxMissingValue => {
                            response["result"].as_object_mut().unwrap().remove("value");
                        }
                        _ => {}
                    }
                    return Ok(response);
                }
                // Native frame-owner geometry, not semantic role/name metadata.
                if object == "node-3" && function.contains("selector") {
                    return Ok(
                        json!({"result":{"type":"object","value":{"x":0,"y":0,"selector":"iframe"}}}),
                    );
                }
                if function.contains("Object.getOwnPropertyDescriptor(p,'isConnected')") {
                    let false_at_resolution = is_node
                        && !matches!(
                            self.case,
                            ReplyCase::BoxNegative
                                | ReplyCase::BoxWrongType
                                | ReplyCase::BoxObjectId
                                | ReplyCase::BoxNullSubtype
                                | ReplyCase::BoxMissingValue
                                | ReplyCase::DocumentNegative
                        );
                    let mut response =
                        json!({"result":{"type":"boolean","value":!false_at_resolution}});
                    if is_node {
                        match self.case {
                            ReplyCase::ResolveWrongType => {
                                response["result"]["type"] = "string".into()
                            }
                            ReplyCase::ResolveMissingType => {
                                response["result"].as_object_mut().unwrap().remove("type");
                            }
                            ReplyCase::ResolveObjectId => {
                                response["result"]["objectId"] = "unexpected-handle".into()
                            }
                            ReplyCase::ResolveUnserializable => {
                                response["result"]["unserializableValue"] = "NaN".into()
                            }
                            ReplyCase::ResolveException => {
                                response["exceptionDetails"] = json!({"text":"synthetic refusal"})
                            }
                            _ => {}
                        }
                    }
                    return Ok(response);
                }
                Err(())
            }
            "Runtime.releaseObjectGroup" => {
                self.releases.fetch_add(1, Ordering::SeqCst);
                if self.case == ReplyCase::CleanupFailure {
                    Err(())
                } else {
                    Ok(json!({}))
                }
            }
            "Runtime.releaseObject" => Ok(json!({})),
            _ => Err(()),
        }
    }
}
fn reply_envelope(request: &Value, result: Result<Value, ()>) -> Value {
    let mut response = match result {
        Ok(value) => json!({"id":request["id"],"result":value}),
        Err(()) => {
            json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic native refusal"}})
        }
    };
    if let Some(session) = request.get("sessionId") {
        response["sessionId"] = session.clone();
    }
    response
}
#[test]
fn layered_peer_echoes_exact_session_for_success_and_error() {
    let scoped = json!({"id":9,"sessionId":"exact-session"});
    for result in [Ok(json!({})), Err(())] {
        let response = reply_envelope(&scoped, result);
        assert_eq!(response["sessionId"], scoped["sessionId"]);
        assert_eq!(response["id"], 9);
    }
    assert!(reply_envelope(&json!({"id":10}), Ok(json!({})))
        .get("sessionId")
        .is_none());
}
struct Fixture {
    client: Arc<CdpClient>,
    dispatch: Arc<ObservationDispatch>,
    context: CaptureContext,
    operation: OperationLease,
    capture: Arc<CaptureAdmission>,
    fence: u64,
    journal: OperationJournalHandle,
    cancellation: watch::Sender<CancelSignal>,
    script: Arc<Script>,
    server: tokio::task::JoinHandle<()>,
}
fn frame(child: bool) -> ObservationFrame {
    ObservationFrame {
        binding: super::super::element::ExactBinding {
            page_session: "session".into(),
            session: "session".into(),
            frame: if child { "child" } else { "frame" }.into(),
            loader: if child { "child-loader" } else { "loader" }.into(),
            actionable: false,
        },
        parent_frame_id: child.then(|| "frame".into()),
        owner_backend_id: child.then_some(3),
        url: if child {
            "https://fixture.invalid/child"
        } else {
            "https://fixture.invalid/"
        }
        .into(),
        offset_x: 0.,
        offset_y: 0.,
        frame_path: if child { vec!["iframe".into()] } else { vec![] },
    }
}
async fn fixture(case: ReplyCase, multi: bool) -> Fixture {
    let script = Arc::new(Script {
        case,
        multi,
        resolved: AtomicBool::new(false),
        recheck: AtomicBool::new(false),
        change_child: AtomicBool::new(false),
        pause_recheck: AtomicBool::new(false),
        recheck_seen: Notify::new(),
        continue_recheck: Notify::new(),
        released: Notify::new(),
        flush_releases: AtomicBool::new(false),
        releases: AtomicUsize::new(0),
        commands: Mutex::new(vec![]),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let peer = script.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut held_releases = Vec::new();
        while let Some(Ok(message)) = ws.next().await {
            let Ok(text) = message.to_text() else {
                continue;
            };
            let request: Value = serde_json::from_str(text).unwrap();
            let method = request["method"].as_str().unwrap();
            peer.commands.lock().unwrap().push(method.into());
            if method == "Page.getFrameTree"
                && peer.recheck.load(Ordering::SeqCst)
                && peer.pause_recheck.swap(false, Ordering::SeqCst)
            {
                peer.recheck_seen.notify_one();
                peer.continue_recheck.notified().await;
            }
            if method == "Runtime.releaseObjectGroup" {
                peer.released.notify_one();
                if peer.case == ReplyCase::CleanupFailure {
                    held_releases.push(reply_envelope(&request, peer.native_response(&request)));
                    continue;
                }
            }
            // A deterministic reply boundary, not a production cleanup wait.
            if peer.flush_releases.load(Ordering::SeqCst) {
                for response in held_releases.drain(..) {
                    ws.send(tokio_tungstenite::tungstenite::Message::Text(
                        response.to_string(),
                    ))
                    .await
                    .unwrap();
                }
            }
            let response = reply_envelope(&request, peer.native_response(&request));
            if ws
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
    let ledger = OwnerDebtLedger::new(1, "scope".into());
    ledger.bind_context("context").unwrap();
    ledger.bind_session("context", "target", "session").unwrap();
    client.install_debt_ledger(ledger.clone()).unwrap();
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
    targets.acknowledge_enrollment().unwrap();
    let gate = Arc::new(ExecutionGate::default());
    let scope = BlobScope {
        generation: 1,
        identity_scope: "scope".into(),
    };
    let blobs = Arc::new(BlobStore::new(Default::default()).unwrap());
    blobs.activate_scope(scope.clone()).unwrap();
    let dispatch = ObservationDispatch::new(Arc::new(Mutex::new(RefMap::new())));
    let (cancellation, receiver) = watch::channel(CancelSignal::None);
    let operation = OperationLease {
        is_callback: false,
        generation: 1,
        sequence: 1,
        deadline: Instant::now() + Duration::from_secs(5),
        cancellation: receiver,
    };
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
    let context = DispatchContext {
        #[cfg(feature = "acceptance-faults")]
        faults: Arc::new(Default::default()),
        page: BrowserExecutionLease {
            client: client.clone(),
            page_session_id: "session".into(),
            target_id: "target".into(),
            identity_scope: "scope".into(),
            permit: gate.enter(false).unwrap(),
            targets: targets.clone(),
        },
        query_authority: None,
        attachment: targets.owned_target("target").unwrap(),
        ui: Arc::new(UiGate::default()),
        blobs,
        scope,
        policy: ReadPolicy {
            frame_policy: Default::default(),
            test_id_attribute: "data-testid".into(),
            secure_field_selector: "input[type=password]".into(),
        },
    };
    let prepared = dispatch
        .prepare(
            context,
            DispatchRequest::Observe(ObserveRequest {
                continuation: None,
                options: ObserveFlags::default(),
                test_id_attribute: "data-testid".into(),
                secure_field_selector: "input[type=password]".into(),
            }),
            operation,
        )
        .unwrap();
    let frames = if multi {
        vec![frame(false), frame(true)]
    } else {
        vec![frame(false)]
    };
    Fixture {
        client,
        dispatch,
        context: CaptureContext {
            page: prepared.context.page,
            frames,
            opaque_frames: HashSet::new(),
            inventory_complete: true,
        },
        operation: prepared.operation,
        capture: prepared.capture.unwrap(),
        fence: prepared.retirement_fence,
        journal,
        cancellation,
        script,
        server,
    }
}
async fn project(fixture: &Fixture) -> observation::ObserveGeometryFailure {
    let mut staged = fixture.dispatch.refs.lock().unwrap().clone();
    staged.begin_observation("scope", 1, 1);
    let mut nodes = Vec::new();
    let count = if fixture.script.multi || fixture.script.case == ReplyCase::ConcurrentHard {
        2
    } else {
        1
    };
    for index in 0..count {
        let frame = &fixture.context.frames[if fixture.script.multi { index } else { 0 }];
        let id = staged.bind_exact(
            if index == 0 { 2 } else { 4 },
            "",
            "",
            frame.binding.clone(),
        );
        let node: SemanticNode = serde_json::from_value(json!({
            "ref":{"id":format!("@{id}"),"revision":"1"},"states":{},"attributes":{},
            "rect":{"x":0,"y":0,"width":100,"height":100},"children":[]
        }))
        .unwrap();
        nodes.push(node);
    }
    fixture
        .journal
        .scope(async {
            let geometry = GeometrySnapshot::capture(
                &fixture.client,
                "session",
                &fixture.context.frames,
                &fixture.operation,
            )
            .await
            .unwrap();
            let Err(failure) = observation::project_observe_geometry(
                &fixture.client,
                &fixture.context.frames,
                &staged,
                &geometry,
                &mut nodes,
                &fixture.operation,
            )
            .await
            else {
                panic!("negative node was published")
            };
            assert!(fixture.dispatch.refs.lock().unwrap().ref_ids().is_empty());
            failure
        })
        .await
}
async fn classify(
    fixture: &Fixture,
    failure: observation::ObserveGeometryFailure,
) -> DispatchFailure {
    let dirty = AtomicBool::new(false);
    let error = geometry_error_with_cleanup(failure.error, &dirty);
    let rejected = DispatchFailure {
        error,
        identity_scope: "scope".into(),
        cleanup_integrity_lost: dirty.load(Ordering::SeqCst),
    };
    fixture.script.recheck.store(true, Ordering::SeqCst);
    fixture
        .journal
        .scope(fixture.dispatch.finish_node_resample_failure(
            &fixture.context,
            &fixture.operation,
            Some(&fixture.capture),
            fixture.fence,
            rejected,
            &failure.negatives,
        ))
        .await
}
fn settle(failure: DispatchFailure) -> (super::super::client_transport::NativeOutcome, bool) {
    // Calls the production outcome mapper with a completed local test task.
    // This does NOT prove public Observe owner-join or final release ACK success;
    // pending/rejected release custody is asserted independently in the ledger.
    settle_observation_dispatch(Ok(Err(failure)), Ok(Ok(())), true)
}
async fn close(fixture: Fixture) {
    assert!(!fixture
        .script
        .commands
        .lock()
        .unwrap()
        .iter()
        .any(|method| method.starts_with("Accessibility.")
            || method == "DOMSnapshot.captureSnapshot"));
    fixture.client.close().await;
    fixture.server.abort();
    let _ = fixture.server.await;
}
#[tokio::test]
async fn frozen_input_layered_positive_node_proofs_require_same_document_and_clean_settlement() {
    for case in [ReplyCase::ResolveNegative, ReplyCase::BoxNegative] {
        let fixture = fixture(case, false).await;
        let deadline = fixture.operation.deadline;
        let failure = project(&fixture).await;
        assert_eq!(failure.negatives.len(), 1);
        let expected = if case == ReplyCase::ResolveNegative {
            NodeGeometryOrigin::ResolveNodeNegative
        } else {
            NodeGeometryOrigin::BoxNodeNegative
        };
        assert_eq!(failure.origin, expected);
        let (outcome, dirty) = settle(classify(&fixture, failure).await);
        assert_eq!(outcome.result, Err(ProtocolError::StaleReference));
        assert_eq!(outcome.effects, Effects::NotDispatched);
        assert!(!dirty);
        assert_eq!(fixture.operation.deadline, deadline);
        assert!(fixture.dispatch.refs.lock().unwrap().ref_ids().is_empty());
        assert!(fixture.dispatch.refs.lock().unwrap().next_ref_num() > 1);
        tokio::time::timeout_at(
            fixture.operation.deadline.into(),
            fixture.script.released.notified(),
        )
        .await
        .unwrap();
        fixture
            .journal
            .scope(
                fixture
                    .client
                    .send_command_no_params("Page.getFrameTree", Some("session")),
            )
            .await
            .unwrap();
        let debt = fixture.client.debt_ledger().unwrap().snapshot();
        assert_eq!(debt.object_debt, 0);
        assert!(!debt.integrity_lost);
        close(fixture).await;
    }
}
#[tokio::test]
async fn frozen_input_layered_malformed_envelopes_and_document_negative_do_not_mint_node_retry() {
    for case in [
        ReplyCase::ResolveWrongType,
        ReplyCase::ResolveMissingType,
        ReplyCase::ResolveObjectId,
        ReplyCase::ResolveUnserializable,
        ReplyCase::ResolveException,
        ReplyCase::BoxWrongType,
        ReplyCase::BoxObjectId,
        ReplyCase::BoxNullSubtype,
        ReplyCase::BoxMissingValue,
        ReplyCase::DocumentNegative,
    ] {
        let fixture = fixture(case, false).await;
        let failure = project(&fixture).await;
        assert!(failure.negatives.is_empty());
        let (outcome, _) = settle(classify(&fixture, failure).await);
        assert_ne!(outcome.result, Err(ProtocolError::StaleReference));
        close(fixture).await;
    }
}
#[tokio::test]
async fn frozen_input_layered_concurrent_backend_refusal_dominates_positive_node_negative() {
    let fixture = fixture(ReplyCase::ConcurrentHard, false).await;
    let failure = project(&fixture).await;
    assert!(matches!(failure.error, GeometryError::CleanupFailed { .. }));
    assert!(failure.negatives.is_empty());
    assert_eq!(failure.origin, NodeGeometryOrigin::MixedHard);
    let (outcome, dirty) = settle(classify(&fixture, failure).await);
    assert!(dirty);
    assert_eq!(outcome.effects, Effects::Unknown);
    close(fixture).await;
}
#[tokio::test]
async fn frozen_input_layered_every_negative_frame_must_survive_revalidation() {
    let fixture = fixture(ReplyCase::ResolveNegative, true).await;
    let failure = project(&fixture).await;
    assert_eq!(failure.negatives.len(), 2);
    fixture.script.change_child.store(true, Ordering::SeqCst);
    let (outcome, dirty) = settle(classify(&fixture, failure).await);
    assert_eq!(outcome.result, Err(ProtocolError::StaleScope));
    assert_eq!(outcome.effects, Effects::NotDispatched);
    assert!(!dirty);
    close(fixture).await;
}
#[tokio::test]
async fn frozen_input_layered_cancel_and_retirement_cross_real_frame_read_await() {
    for mode in 0..3 {
        let fixture = fixture(ReplyCase::ResolveNegative, false).await;
        let failure = project(&fixture).await;
        assert_eq!(failure.negatives.len(), 1);
        fixture.script.pause_recheck.store(true, Ordering::SeqCst);
        let mutation = async {
            fixture.script.recheck_seen.notified().await;
            match mode {
                0 => {
                    fixture.cancellation.send(CancelSignal::Requested).unwrap();
                }
                1 => {
                    fixture
                        .cancellation
                        .send(CancelSignal::DeadlineExceeded)
                        .unwrap();
                }
                _ => {
                    fixture.dispatch.retire_interaction().await.unwrap();
                }
            }
            fixture.script.continue_recheck.notify_one();
        };
        let (failure, ()) = tokio::time::timeout_at(fixture.operation.deadline.into(), async {
            tokio::join!(classify(&fixture, failure), mutation)
        })
        .await
        .expect("real recheck boundary was not reached");
        let (outcome, _) = settle(failure);
        let expected = match mode {
            0 => ProtocolError::Cancelled,
            1 => ProtocolError::DeadlineExceeded,
            _ => ProtocolError::StaleScope,
        };
        assert_eq!(outcome.result, Err(expected));
        close(fixture).await;
    }
}
#[tokio::test]
async fn frozen_input_layered_failed_readonly_release_is_never_not_dispatched_retry() {
    let fixture = fixture(ReplyCase::CleanupFailure, false).await;
    let failure = project(&fixture).await;
    assert_eq!(failure.negatives.len(), 1);
    tokio::time::timeout_at(
        fixture.operation.deadline.into(),
        fixture.script.released.notified(),
    )
    .await
    .unwrap();
    fixture.script.flush_releases.store(true, Ordering::SeqCst);
    // FIFO delivery of the following reply follows the release refusal. This
    // is test synchronization, never a new production cleanup wait.
    let _ = fixture
        .journal
        .scope(
            fixture
                .client
                .send_command_no_params("Page.getFrameTree", Some("session")),
        )
        .await;
    let ledger = fixture.client.debt_ledger().unwrap();
    assert!(!ledger.snapshot().integrity_lost);
    assert!(ledger
        .operation_has_rejected_cleanup(
            OperationKey {
                generation: 1,
                operation_seq: 1
            },
            "scope"
        )
        .unwrap());
    assert!(!ledger
        .operation_has_rejected_cleanup(
            OperationKey {
                generation: 1,
                operation_seq: 2
            },
            "scope"
        )
        .unwrap());
    assert_eq!(
        ledger.operation_has_rejected_cleanup(
            OperationKey {
                generation: 2,
                operation_seq: 1
            },
            "scope"
        ),
        Err(ProtocolError::StaleScope)
    );
    assert_eq!(
        ledger.operation_has_rejected_cleanup(
            OperationKey {
                generation: 1,
                operation_seq: 1
            },
            "foreign-scope"
        ),
        Err(ProtocolError::StaleScope)
    );
    let (outcome, dirty) = settle(classify(&fixture, failure).await);
    assert!(dirty);
    assert_eq!(outcome.effects, Effects::Unknown);
    close(fixture).await;
}
#[tokio::test]
async fn frozen_input_layered_pending_cleanup_handoff_and_later_rejection_keep_original_custody() {
    let fixture = fixture(ReplyCase::CleanupFailure, false).await;
    let failure = project(&fixture).await;
    tokio::time::timeout_at(
        fixture.operation.deadline.into(),
        fixture.script.released.notified(),
    )
    .await
    .unwrap();
    let ledger = fixture.client.debt_ledger().unwrap();
    let key = OperationKey {
        generation: 1,
        operation_seq: 1,
    };
    assert!(ledger.snapshot().object_debt > 0);
    assert!(!ledger.operation_has_rejected_cleanup(key, "scope").unwrap());
    let (outcome, dirty) = settle(classify(&fixture, failure).await);
    assert!(!dirty);
    assert_eq!(outcome.result, Err(ProtocolError::StaleReference));
    assert_eq!(outcome.effects, Effects::NotDispatched);
    // After the guard's point-in-time decision, a rejected reply does not
    // retroactively rewrite outcome or transfer this operation's retained debt.
    fixture.script.flush_releases.store(true, Ordering::SeqCst);
    fixture
        .journal
        .scope(
            fixture
                .client
                .send_command_no_params("Page.getFrameTree", Some("session")),
        )
        .await
        .unwrap();
    assert!(ledger.operation_has_rejected_cleanup(key, "scope").unwrap());
    assert!(ledger.snapshot().object_debt > 0);
    assert!(!ledger
        .operation_has_rejected_cleanup(
            OperationKey {
                generation: 1,
                operation_seq: 2
            },
            "scope"
        )
        .unwrap());
    assert_eq!(outcome.effects, Effects::NotDispatched);
    close(fixture).await;
}
#[tokio::test]
async fn frozen_input_layered_rejected_cleanup_arriving_during_recheck_blocks_node_retry() {
    let fixture = fixture(ReplyCase::CleanupFailure, false).await;
    let failure = project(&fixture).await;
    tokio::time::timeout_at(
        fixture.operation.deadline.into(),
        fixture.script.released.notified(),
    )
    .await
    .unwrap();
    fixture.script.pause_recheck.store(true, Ordering::SeqCst);
    let deliver = async {
        fixture.script.recheck_seen.notified().await;
        fixture.script.flush_releases.store(true, Ordering::SeqCst);
        fixture.script.continue_recheck.notify_one();
    };
    let (failure, ()) = tokio::time::timeout_at(fixture.operation.deadline.into(), async {
        tokio::join!(classify(&fixture, failure), deliver)
    })
    .await
    .unwrap();
    assert!(fixture
        .client
        .debt_ledger()
        .unwrap()
        .operation_has_rejected_cleanup(
            OperationKey {
                generation: 1,
                operation_seq: 1
            },
            "scope"
        )
        .unwrap());
    let (outcome, dirty) = settle(failure);
    assert!(dirty);
    assert_eq!(outcome.effects, Effects::Unknown);
    close(fixture).await;
}
#[tokio::test]
async fn frozen_input_layered_strict_geometry_consumers_keep_old_hard_refusal() {
    let fixture = fixture(ReplyCase::ResolveNegative, false).await;
    fixture
        .journal
        .scope(async {
            let geometry = GeometrySnapshot::capture(
                &fixture.client,
                "session",
                &fixture.context.frames,
                &fixture.operation,
            )
            .await
            .unwrap();
            let semantic = geometry
                .node_semantic_bounds(
                    &fixture.client,
                    &fixture.context.frames[0],
                    2,
                    &fixture.operation,
                )
                .await;
            assert!(matches!(semantic, Err(GeometryError::StaleIdentity)));
            let strict = geometry
                .node_border_polygons(
                    &fixture.client,
                    &fixture.context.frames[0],
                    2,
                    &fixture.operation,
                )
                .await;
            assert!(matches!(strict, Err(GeometryError::CleanupFailed { .. })));
        })
        .await;
    close(fixture).await;
}
