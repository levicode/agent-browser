//! Retained semantic-fallback obligation #15, without a typed-failure injection.
//! The strict peer supplies the CDP exception shape of MASK_READER's detached
//! node guard. It is not a renderer and does not prove an actual DOM detachment.
use super::*;
use crate::native::client_browser::settle_observation_dispatch;
use crate::native::client_observation::equivalence_tests::hold_metadata;
use crate::native::client_protocol::Effects;
use futures_util::SinkExt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeReply {
    DetachedException,
    ProtocolRejection,
}

impl ProbeReply {
    fn capture_reason(self) -> CaptureReason {
        match self {
            Self::DetachedException => CaptureReason::MaskingUnproven,
            Self::ProtocolRejection => CaptureReason::BrowserFailure,
        }
    }

    fn dispatch_error(self) -> ProtocolError {
        match self {
            Self::DetachedException => ProtocolError::DeadlineExceeded,
            Self::ProtocolRejection => ProtocolError::BrowserFailure,
        }
    }
}

struct MaskFailurePeer {
    owner: Owner,
    reply: ProbeReply,
    commands: Arc<Mutex<Vec<Value>>>,
    stop: oneshot::Sender<()>,
    server: tokio::task::JoinHandle<HashMap<String, Vec<String>>>,
}

impl MaskFailurePeer {
    async fn start(sequence: u64, reply: ProbeReply, semantic: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let commands = Arc::new(Mutex::new(Vec::<Value>::new()));
        let log = commands.clone();
        let (stop, mut stopping) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let metadata_group = format!("native-metadata-{sequence}");
            let security_group = format!("native-security-{sequence}");
            let mask_group = format!("capture-{sequence}-frame");
            let mut groups = HashMap::<String, Vec<String>>::new();
            let mut released = HashMap::<String, Vec<String>>::new();
            let mut metadata_replied = false;
            let mut stabilized = false;
            let mut probe_failed = false;
            let mut restored = false;
            loop {
                let message = tokio::select! {
                    _ = &mut stopping => break,
                    message = socket.next() => message.unwrap().unwrap(),
                };
                let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                let method = request["method"].as_str().unwrap();
                // This test-owned transport fence is not observation work.
                if method == "Browser.getVersion" {
                    assert!(request.get("sessionId").is_none());
                    socket
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            json!({"id":request["id"],"result":{}}).to_string(),
                        ))
                        .await
                        .unwrap();
                    continue;
                }
                assert_eq!(request["sessionId"], "session");
                log.lock().unwrap().push(request.clone());
                let group = request["params"]["objectGroup"].as_str();
                if metadata_replied && !released.contains_key(&metadata_group) {
                    assert_eq!(method, "Runtime.releaseObjectGroup");
                    assert_eq!(group, Some(metadata_group.as_str()));
                }
                if probe_failed {
                    assert!(
                        method == "Runtime.releaseObjectGroup"
                            || method == "Animation.setPlaybackRate",
                        "failed independent coverage may only clean up, never acquire pixels"
                    );
                }
                let mut protocol_rejection = false;
                let result = match method {
                    "Page.getFrameTree" => json!({"frameTree":{"frame":{
                        "id":"frame","loaderId":"loader","url":"https://fixture.invalid/"
                    }}}),
                    "Page.getLayoutMetrics" => json!({
                        "cssVisualViewport":{"clientWidth":100,"clientHeight":80,"scale":1,"offsetX":0,"offsetY":0},
                        "cssLayoutViewport":{"clientWidth":100,"clientHeight":80}
                    }),
                    "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                    "DOM.getDocument" => {
                        assert!(semantic);
                        if metadata_replied {
                            assert!(stabilized);
                            assert_eq!(request["params"], json!({"depth":0,"pierce":false}));
                            json!({"root":{"nodeType":9,"backendNodeId":1}})
                        } else {
                            json!({"root":{"nodeType":9,"backendNodeId":1,"children":[{
                                "nodeType":1,"nodeName":"BUTTON","localName":"button","backendNodeId":7
                            }]}})
                        }
                    }
                    "Accessibility.getFullAXTree" => {
                        assert!(semantic && !metadata_replied);
                        json!({"nodes":[
                            {"nodeId":"root","backendDOMNodeId":1,"role":{"type":"role","value":"RootWebArea"}},
                            {"nodeId":"button","backendDOMNodeId":7,"role":{"type":"role","value":"button"}}
                        ]})
                    }
                    "DOM.resolveNode" => {
                        let group = group.unwrap();
                        if group == mask_group {
                            assert!(stabilized);
                            assert_eq!(request["params"]["backendNodeId"], 7);
                            assert_eq!(request["params"]["executionContextId"], 1);
                        } else {
                            assert!(semantic && !metadata_replied);
                            assert!(group == metadata_group || group == security_group);
                        }
                        let object = format!("{group}-node-{}", request["params"]["backendNodeId"]);
                        groups
                            .entry(group.to_owned())
                            .or_default()
                            .push(object.clone());
                        json!({"object":{"objectId":object,"subtype":"node"}})
                    }
                    "Runtime.getProperties" => {
                        assert!(semantic && !metadata_replied);
                        assert_eq!(
                            request["params"]["objectId"],
                            format!("{security_group}-inventory")
                        );
                        json!({"result":[{"name":"focused","value":{"type":"object","subtype":"null","value":null}}]})
                    }
                    "Runtime.callFunctionOn" => {
                        let group = group.unwrap();
                        let declaration =
                            request["params"]["functionDeclaration"].as_str().unwrap();
                        if group == mask_group {
                            assert!(stabilized && !probe_failed);
                            assert_eq!(request["params"]["executionContextId"], 1);
                            assert_eq!(request["params"]["returnByValue"], true);
                            assert_eq!(
                                request["params"]["arguments"],
                                json!([
                                    {"value":"input[type=password]"},
                                    {"objectId":format!("{mask_group}-node-7")}
                                ])
                            );
                            assert_eq!(groups[&mask_group], [format!("{mask_group}-node-7")]);
                            // Pin the actual emitted independent reader and its
                            // native connectivity/owner guard, not an error name.
                            assert!(declaration.starts_with("function(selector,...nodes)"));
                            assert!(declaration.contains(
                                "Object.getOwnPropertyDescriptor(Node.prototype,'isConnected').get"
                            ));
                            assert!(declaration.contains("Object.getOwnPropertyDescriptor(Node.prototype,'ownerDocument').get"));
                            assert!(declaration.contains("if(!connected.call(node)||owner.call(node)!==document)throw Error('stale');"));
                            probe_failed = true;
                            protocol_rejection = reply == ProbeReply::ProtocolRejection;
                            let exception_object = format!("{mask_group}-exception");
                            if !protocol_rejection {
                                groups
                                    .get_mut(&mask_group)
                                    .unwrap()
                                    .push(exception_object.clone());
                            }
                            // A successful CDP command whose JS body threw has
                            // exceptionDetails; a rejected CDP command does not.
                            json!({
                                "result":{"type":"object","subtype":"error","objectId":exception_object,"description":"Error: stale"},
                                "exceptionDetails":{"exceptionId":1,"text":"Uncaught","lineNumber":0,"columnNumber":0,
                                    "exception":{"type":"object","subtype":"error","objectId":exception_object,"description":"Error: stale"}}
                            })
                        } else {
                            assert!(semantic && !metadata_replied);
                            let object = request["params"]["objectId"].as_str().unwrap();
                            assert!(groups[group].iter().any(|owned| owned == object));
                            if group == security_group {
                                assert!(declaration
                                    .starts_with("function(selector,authorRoots,...roots)"));
                                let object = format!("{group}-inventory");
                                groups.get_mut(group).unwrap().push(object.clone());
                                json!({"result":{"objectId":object}})
                            } else {
                                assert_eq!(group, metadata_group);
                                assert!(declaration
                                    .starts_with("function(testId,secureSelector,...nodes)"));
                                assert_eq!(request["params"]["returnByValue"], true);
                                let values = request["params"]["arguments"].as_array().unwrap().iter().skip(2).map(|argument| {
                                    let object = argument["objectId"].as_str().unwrap();
                                    assert!(groups[group].iter().any(|owned| owned == object));
                                    if object.ends_with("-node-1") {
                                        json!({"attributes":{},"labels":[],"states":{},"rect":null,"author":{"nodeType":9,"visible":true}})
                                    } else {
                                        assert!(object.ends_with("-node-7"));
                                        json!({"attributes":{},"labels":[],"states":{},"rect":null,"handlerProbe":true,"author":{"nodeType":1,"tag":"button","visible":true}})
                                    }
                                }).collect::<Vec<_>>();
                                assert_eq!(values.len(), 2);
                                metadata_replied = true;
                                json!({"result":{"value":values}})
                            }
                        }
                    }
                    "Runtime.releaseObjectGroup" => {
                        let group = group.unwrap();
                        let objects = groups
                            .remove(group)
                            .expect("release must own the exact live group");
                        assert!(
                            released.insert(group.to_owned(), objects).is_none(),
                            "group released twice"
                        );
                        json!({})
                    }
                    "Animation.enable" => {
                        assert!(!stabilized);
                        if semantic {
                            assert!(metadata_replied && released.contains_key(&metadata_group));
                        }
                        json!({})
                    }
                    "Animation.getPlaybackRate" => json!({"playbackRate":1}),
                    "Animation.setPlaybackRate" => {
                        if request["params"]["playbackRate"].as_f64() == Some(0.0) {
                            assert!(!stabilized);
                            stabilized = true;
                        } else {
                            assert_eq!(request["params"]["playbackRate"], 1.0);
                            assert!(probe_failed && released.contains_key(&mask_group));
                            assert!(!restored);
                            restored = true;
                        }
                        json!({})
                    }
                    "DOMSnapshot.captureSnapshot" => {
                        assert!(stabilized);
                        json!({"strings":["frame"],"documents":[{"frameId":0,"nodes":{"nodeType":[1],"backendNodeId":[7]}}]})
                    }
                    other => panic!("unexpected failed-mask command: {other}"),
                };
                let response = if protocol_rejection {
                    // Deliberately the same words as the detached JS exception:
                    // transport failure must not become a semantic timeout.
                    json!({"id":request["id"],"sessionId":"session","error":{"code":-32000,"message":"Error: stale"}})
                } else {
                    json!({"id":request["id"],"sessionId":"session","result":result})
                };
                socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        response.to_string(),
                    ))
                    .await
                    .unwrap();
            }
            assert!(
                groups.is_empty(),
                "all acquired objects need acknowledged cleanup"
            );
            assert!(probe_failed && restored);
            assert_eq!(released.len(), if semantic { 3 } else { 1 });
            released
        });
        let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
        Self {
            owner: Owner::new(client, "session", "target", "scope").await,
            reply,
            commands,
            stop,
            server,
        }
    }

    async fn finish(self, sequence: u64, semantic: bool) {
        assert_eq!(self.owner.client.pending_len().await, 0);
        assert!(self.owner.targets.inventory().is_ok());
        self.owner.gate.enter(false).unwrap().check().unwrap();
        self.owner.blobs.check_budget_integrity().unwrap();
        // Two full default reservations occupy the entire byte budget. Even a
        // leftover bounded capture producer would prevent the second one.
        let first = self
            .owner
            .blobs
            .reserve_producer(self.owner.scope.clone())
            .unwrap();
        let second = self
            .owner
            .blobs
            .reserve_producer(self.owner.scope.clone())
            .unwrap();
        assert!(matches!(
            self.owner.blobs.reserve_producer(self.owner.scope.clone()),
            Err(BlobError::QuotaExceeded)
        ));
        drop((first, second));
        {
            let log = self.commands.lock().unwrap();
            assert!(!log
                .iter()
                .any(|request| request["method"] == "Page.captureScreenshot"));
            assert!(!log
                .iter()
                .any(|request| request["method"] == "Runtime.evaluate"));
            assert!(!log.iter().any(|request| request["params"]["objectGroup"]
                .as_str()
                .is_some_and(|group| group.starts_with("capture-source-"))));
            assert_eq!(
                log.iter()
                    .filter(|request| request["method"] == "DOMSnapshot.captureSnapshot")
                    .count(),
                1
            );
        }
        self.stop.send(()).unwrap();
        let released = self.server.await.unwrap();
        let mask_group = format!("capture-{sequence}-frame");
        let mut expected = vec![format!("{mask_group}-node-7")];
        if self.reply == ProbeReply::DetachedException {
            expected.push(format!("{mask_group}-exception"));
        }
        assert_eq!(released[&mask_group], expected);
        if semantic {
            let metadata_group = format!("native-metadata-{sequence}");
            let mut handles = released[&metadata_group].clone();
            handles.sort();
            assert_eq!(
                handles,
                [
                    format!("{metadata_group}-node-1"),
                    format!("{metadata_group}-node-7")
                ]
            );
            let security_group = format!("native-security-{sequence}");
            assert_eq!(
                released[&security_group],
                [
                    format!("{security_group}-node-1"),
                    format!("{security_group}-inventory")
                ]
            );
        }
    }
}

async fn typed_independent_failure(reply: ProbeReply, sequence: u64) {
    let peer = MaskFailurePeer::start(sequence, reply, false).await;
    let (mut op, _cancel) = operation(sequence);
    op.deadline = Instant::now() + Duration::from_millis(80);
    let page = peer.owner.context().page;
    let frames = verified_frames(&page, &op).await.unwrap();
    let context = CaptureContext {
        page,
        frames,
        inventory_complete: true,
    };
    let mut journal = ProtectedReadJournal::begin(&context.page, &op).unwrap();
    journal.stabilize_animations().await.unwrap();
    let geometry = GeometrySnapshot::capture(
        &context.page.client,
        &context.page.page_session_id,
        &context.frames,
        &op,
    )
    .await
    .unwrap();
    let failure = match client_capture::capture_under_journal(
        &context,
        &CaptureRequest {
            secure_field_selector: "input[type=password]".into(),
        },
        &op,
        &mut journal,
        &geometry,
    )
    .await
    {
        Err(failure) => failure,
        Ok(_) => panic!("independent probe must refuse before pixels"),
    };
    assert_eq!(
        failure,
        CaptureAttemptFailure {
            phase: CapturePhase::IndependentCoverage,
            reason: reply.capture_reason(),
        }
    );
    journal.restore().await.unwrap();
    journal.check().unwrap();
    drop(journal);
    drop(context);
    peer.finish(sequence, false).await;
}

async fn semantic_deadline_then_mask_failure(reply: ProbeReply, sequence: u64) {
    let peer = MaskFailurePeer::start(sequence, reply, true).await;
    let refs = Arc::new(Mutex::new(RefMap::new()));
    let dispatch = ObservationDispatch::new(refs.clone());
    let (mut op, _cancel) = operation(sequence);
    let started = Instant::now();
    op.deadline = started + Duration::from_millis(80);
    let original_deadline = op.deadline;
    let (_hold_guard, held) = hold_metadata(&op);
    let mut task = dispatch.clone().start(
        peer.owner.context(),
        DispatchRequest::Observe(ObserveRequest {
            options: ObserveFlags {
                pixels: false,
                pixel_fallback: true,
                comparable: false,
            },
            test_id_attribute: "data-testid".into(),
            secure_field_selector: "input[type=password]".into(),
        }),
        op,
    );
    tokio::time::timeout_at(original_deadline.into(), held.reached())
        .await
        .expect("reach actual metadata within original budget");
    assert_eq!(held.metadata_calls(), 1);
    assert_eq!(held.releases(), 0);
    assert_eq!(held.handles().len(), 2);
    assert!(refs.lock().unwrap().ref_ids().is_empty());
    assert!(matches!(
        task.result.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    // The production semantic subdeadline, not a fault or manual release,
    // starts the fresh independent probe under the same original deadline.
    let (output, cleanup) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(task.result, task.join)
    })
    .await
    .expect("failed fallback must settle without releasing old metadata");
    let completed = Instant::now();
    assert!(completed >= started + Duration::from_millis(60));
    assert!(
        completed < original_deadline,
        "failure and restoration must fit the unchanged 80 ms budget"
    );
    assert!(matches!(&cleanup, Ok(Ok(()))));
    let (settled, dirty) = settle_observation_dispatch(output, cleanup);
    assert!(!dirty);
    assert_eq!(settled.effects, Effects::NotDispatched);
    assert_eq!(settled.result, Err(reply.dispatch_error()));
    assert_eq!(held.releases(), 1);
    assert!(refs.lock().unwrap().ref_ids().is_empty());
    assert_eq!(dispatch.publication.lock().await.published_revision, 0);
    assert_eq!(dispatch.publication.lock().await.observed_revision, 0);
    let terminal_commands = peer.commands.lock().unwrap().clone();
    held.release();
    tokio::task::yield_now().await;
    peer.owner
        .client
        .send_command("Browser.getVersion", None, None)
        .await
        .unwrap();
    tokio::task::yield_now().await;
    assert_eq!(
        *peer.commands.lock().unwrap(),
        terminal_commands,
        "late metadata must not resume traversal, source masks or screenshot"
    );
    assert_eq!(held.metadata_calls(), 1);
    assert_eq!(held.releases(), 1);
    assert!(refs.lock().unwrap().ref_ids().is_empty());
    peer.finish(sequence, true).await;
}

#[tokio::test]
async fn detached_mask_reader_exception_has_typed_independent_coverage_provenance() {
    typed_independent_failure(ProbeReply::DetachedException, 8511).await;
}

#[tokio::test]
async fn rejected_mask_reader_command_remains_typed_browser_failure() {
    typed_independent_failure(ProbeReply::ProtocolRejection, 8512).await;
}

#[tokio::test]
async fn detached_mask_probe_preserves_original_semantic_timeout_without_pixels() {
    semantic_deadline_then_mask_failure(ProbeReply::DetachedException, 8513).await;
}

#[tokio::test]
async fn rejected_mask_probe_does_not_hide_browser_failure_behind_semantic_timeout() {
    semantic_deadline_then_mask_failure(ProbeReply::ProtocolRejection, 8514).await;
}
