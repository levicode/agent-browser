//! Partial native transfers of legacy capture obligations #1, #3 and #4.
//! These hold actual resource-producing CDP replies past the semantic deadline,
//! not a post-reply hook or a backend error. Successful cases ACK within the
//! unchanged 80 ms parent budget. They do NOT prove the old successful-terminal-
//! before-manual-resource-ACK ordering: unknown resource settlement stays hard.
//! Like the existing metadata-deadline fixture, this is an untracked dispatcher
//! peer. The negative proves cleanup uncertainty/quarantine, not ledger admission
//! or renderer garbage collection.
use super::*;
use crate::native::client_browser::settle_observation_dispatch;
use crate::native::client_protocol::Effects;
use base64::Engine;
use futures_util::SinkExt;
use std::sync::atomic::AtomicUsize;
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    FirstResource,
    Candidate,
    StartedSiblings,
    MissingAck,
}

#[tokio::test]
async fn first_native_acquisition_deadline_cleans_before_fresh_fallback() {
    acquisition_deadline(Boundary::FirstResource).await;
}

#[tokio::test]
async fn candidate_acquisition_deadline_stops_metadata_before_fresh_fallback() {
    acquisition_deadline(Boundary::Candidate).await;
}

#[tokio::test]
async fn candidate_deadline_drains_all_started_siblings_before_group_release() {
    acquisition_deadline(Boundary::StartedSiblings).await;
}

#[tokio::test]
async fn unacknowledged_candidate_deadline_never_becomes_clean_fallback() {
    acquisition_deadline(Boundary::MissingAck).await;
}

async fn fence(client: &CdpClient) {
    tokio::time::timeout(
        Duration::from_secs(1),
        client.send_command("Browser.getVersion", None, None),
    )
    .await
    .expect("peer transport fence must finish")
    .unwrap();
}

async fn acquisition_deadline(boundary: Boundary) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let commands = Arc::new(Mutex::new(Vec::<Value>::new()));
    let log = commands.clone();
    let captures = Arc::new(AtomicUsize::new(0));
    let capture_log = captures.clone();
    let (reached_tx, reached) = oneshot::channel();
    let (release, mut resume) = mpsc::unbounded_channel::<i64>();
    let (acked_tx, mut acked) = mpsc::unbounded_channel::<i64>();
    let (stop, mut stopping) = oneshot::channel();
    // Fixture encoding and transport setup do not consume the operation budget.
    let mut bytes = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        10,
        10,
        image::Rgba([17, 83, 149, 255]),
    ))
    .write_to(&mut bytes, image::ImageFormat::Png)
    .unwrap();
    let png = base64::engine::general_purpose::STANDARD.encode(bytes.into_inner());
    let sequence = 8201;
    let metadata_group = format!("native-metadata-{sequence}");
    let security_group = format!("native-security-{sequence}");
    let held_group = if boundary == Boundary::FirstResource {
        security_group.clone()
    } else {
        metadata_group.clone()
    };
    let peer_held_group = held_group.clone();
    let peer_metadata_group = metadata_group.clone();
    let peer_security_group = security_group.clone();
    let expected_started = if boundary == Boundary::FirstResource {
        1
    } else {
        2
    };
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut groups = HashMap::<String, Vec<String>>::new();
        let mut released = HashMap::<String, Vec<String>>::new();
        let mut held = HashMap::<i64, Value>::new();
        let mut reached_tx = Some(reached_tx);
        let mut started = Vec::new();
        let mut acknowledgements = Vec::new();
        let mut held_released_at = None;
        let mut fallback_started = false;
        let mut source_cycle = Vec::new();
        let mut empty_mask_releases = 0;
        loop {
            let message = tokio::select! {
                _ = &mut stopping => break,
                backend = resume.recv(), if !held.is_empty() => {
                    let backend = backend.expect("release controller disappeared");
                    let response = held.remove(&backend).expect("only an outstanding exact acquisition may be released");
                    socket.send(tokio_tungstenite::tungstenite::Message::Text(response.to_string())).await.unwrap();
                    acknowledgements.push(backend);
                    acked_tx.send(backend).unwrap();
                    continue;
                }
                message = socket.next() => message.unwrap().unwrap(),
            };
            let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
            let method = request["method"].as_str().unwrap();
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
            if !started.is_empty() && held_released_at.is_none() {
                assert!(
                    (method == "DOM.resolveNode" && started.len() < expected_started)
                        || method == "Runtime.releaseObjectGroup",
                    "held acquisition may only drain started siblings and its exact group"
                );
                assert_eq!(group, Some(peer_held_group.as_str()));
            } else if held_released_at.is_some() {
                assert_ne!(
                    boundary,
                    Boundary::MissingAck,
                    "uncertain cleanup cannot start fallback"
                );
            }
            let result = match method {
                "Page.getFrameTree" => {
                    json!({"frameTree":{"frame":{"id":"frame","loaderId":"loader","url":"https://fixture.invalid/"}}})
                }
                "Page.getLayoutMetrics" => {
                    json!({"cssVisualViewport":{"clientWidth":10,"clientHeight":10,"scale":1,"offsetX":0,"offsetY":0},"cssLayoutViewport":{"clientWidth":10,"clientHeight":10}})
                }
                "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                "DOM.getDocument" => {
                    if held_released_at.is_some() {
                        assert!(fallback_started, "retired semantic traversal cannot resume");
                        assert_eq!(request["params"], json!({"depth":0,"pierce":false}));
                        json!({"root":{"nodeType":9,"backendNodeId":1}})
                    } else {
                        json!({"root":{"nodeType":9,"nodeName":"#document","backendNodeId":1,"children":[{"nodeType":1,"nodeName":"BUTTON","localName":"button","backendNodeId":7}]}})
                    }
                }
                "Accessibility.getFullAXTree" => {
                    assert!(started.is_empty(), "retired AX enumeration restarted");
                    json!({"nodes":[{"nodeId":"root","backendDOMNodeId":1,"role":{"type":"role","value":"RootWebArea"}},{"nodeId":"button","backendDOMNodeId":7,"role":{"type":"role","value":"button"}}]})
                }
                "DOM.resolveNode" => {
                    assert!(
                        held_released_at.is_none(),
                        "retired reader acquired another handle"
                    );
                    let group = group.unwrap();
                    assert!(group == peer_metadata_group || group == peer_security_group);
                    let backend = request["params"]["backendNodeId"].as_i64().unwrap();
                    let object = format!("{group}-node-{backend}");
                    groups
                        .entry(group.to_owned())
                        .or_default()
                        .push(object.clone());
                    let value = json!({"object":{"objectId":object,"subtype":"node"}});
                    if group == peer_held_group {
                        assert!(!started.contains(&backend), "acquisition replayed");
                        started.push(backend);
                        let hold = backend == 1 || boundary == Boundary::StartedSiblings;
                        if hold {
                            assert!(held
                                .insert(
                                    backend,
                                    json!({"id":request["id"],"sessionId":"session","result":value})
                                )
                                .is_none());
                        } else {
                            acknowledgements.push(backend);
                        }
                        // Candidate arrival order is not ownership order. Only
                        // signal after every required acquisition was observed
                        // and any withheld response was registered for release.
                        if started.len() == expected_started {
                            reached_tx.take().unwrap().send(Instant::now()).unwrap();
                        }
                        if hold {
                            continue;
                        }
                    }
                    value
                }
                "Runtime.getProperties" => {
                    assert!(
                        started.is_empty(),
                        "late acquisition must not enumerate properties"
                    );
                    assert_eq!(
                        request["params"]["objectId"],
                        format!("{peer_security_group}-inventory")
                    );
                    json!({"result":[{"name":"focused","value":{"type":"object","subtype":"null","value":null}}]})
                }
                "Runtime.callFunctionOn" => {
                    let declaration = request["params"]["functionDeclaration"].as_str().unwrap();
                    let group = group.unwrap();
                    let object = request["params"]["objectId"].as_str().unwrap();
                    assert!(groups[group].iter().any(|owned| owned == object));
                    assert_ne!(group, peer_metadata_group, "expired candidate acquisition must not execute metadata or enumerate another stage");
                    if group == peer_security_group {
                        assert!(
                            started.is_empty(),
                            "expired first acquisition must not execute its inventory"
                        );
                        assert!(declaration.starts_with("function(selector,authorRoots,...roots)"));
                        let object = format!("{group}-inventory");
                        groups.get_mut(group).unwrap().push(object.clone());
                        json!({"result":{"objectId":object}})
                    } else {
                        assert!(fallback_started);
                        assert_eq!(group, format!("capture-source-{sequence}-frame"));
                        source_cycle.push(match declaration {
                            "function(){return this.verify()}" => "verify",
                            "function(){return this.remove()}" => "remove",
                            other => panic!("unexpected fallback call: {other}"),
                        });
                        json!({"result":{"value":true}})
                    }
                }
                "Runtime.releaseObjectGroup" => {
                    let group = group.unwrap();
                    if group == format!("capture-{sequence}-frame") {
                        assert!(fallback_started);
                        assert!(!groups.contains_key(group));
                        empty_mask_releases += 1;
                        assert!(empty_mask_releases <= 2);
                    } else {
                        let objects = groups
                            .remove(group)
                            .expect("cleanup must target the exact owned group");
                        assert!(
                            released.insert(group.to_owned(), objects).is_none(),
                            "group released more than once"
                        );
                        if group == peer_held_group {
                            assert_eq!(started.len(), expected_started);
                            if boundary == Boundary::MissingAck {
                                assert_eq!(
                                    held.len(),
                                    1,
                                    "missing resource ACK is not secretly settled"
                                );
                                assert_eq!(acknowledgements, [7]);
                            } else {
                                assert!(
                                    held.is_empty(),
                                    "cleanup must drain every already-started sibling"
                                );
                                assert_eq!(acknowledgements.len(), expected_started);
                            }
                            held_released_at = Some(Instant::now());
                        } else if group == format!("capture-source-{sequence}-frame") {
                            source_cycle.push("release");
                        } else {
                            assert_eq!(group, peer_security_group);
                        }
                    }
                    json!({})
                }
                "Animation.enable" => {
                    assert!(held_released_at.is_some() && held.is_empty());
                    assert!(!fallback_started, "fresh fallback must start exactly once");
                    fallback_started = true;
                    json!({})
                }
                "Animation.getPlaybackRate" => {
                    assert!(fallback_started);
                    json!({"playbackRate":1})
                }
                "Animation.setPlaybackRate" => {
                    assert!(fallback_started);
                    assert!(matches!(
                        request["params"]["playbackRate"].as_f64(),
                        Some(0.0 | 1.0)
                    ));
                    json!({})
                }
                "DOMSnapshot.captureSnapshot" => {
                    assert!(fallback_started);
                    json!({"strings":["frame"],"documents":[{"frameId":0,"nodes":{"nodeType":[],"backendNodeId":[]}}]})
                }
                "Runtime.evaluate" => {
                    assert!(fallback_started);
                    let group = group.unwrap();
                    assert_eq!(group, format!("capture-source-{sequence}-frame"));
                    assert_eq!(request["params"]["contextId"], 1);
                    assert!(groups
                        .insert(group.to_owned(), vec!["fresh-source-holder".into()])
                        .is_none());
                    source_cycle.push("holder");
                    json!({"result":{"objectId":"fresh-source-holder"}})
                }
                "Page.captureScreenshot" => {
                    assert!(fallback_started && held.is_empty());
                    assert_eq!(source_cycle, ["holder", "verify"]);
                    assert_eq!(capture_log.fetch_add(1, Ordering::SeqCst), 0);
                    json!({"data":png})
                }
                other => panic!("unexpected acquisition-deadline command: {other}"),
            };
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    json!({"id":request["id"],"sessionId":"session","result":result}).to_string(),
                ))
                .await
                .unwrap();
        }
        assert!(groups.is_empty());
        assert!(
            held.is_empty(),
            "the test must also deliver the withheld terminal-late ACK"
        );
        (
            released,
            source_cycle,
            held_released_at.unwrap(),
            empty_mask_releases,
            acknowledgements,
        )
    });
    let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
    let owner = Owner::new(client.clone(), "session", "target", "scope").await;
    let refs = Arc::new(Mutex::new(RefMap::new()));
    let dispatch = ObservationDispatch::new(refs.clone());
    let (mut operation, _cancel) = operation(sequence);
    let started = Instant::now();
    operation.deadline = started + Duration::from_millis(80);
    let original_deadline = operation.deadline;
    let timing = semantic_lease_at(&operation, false, started);
    let mut task = dispatch.clone().start(
        owner.context(),
        DispatchRequest::Observe(ObserveRequest {
            options: ObserveFlags {
                pixels: false,
                pixel_fallback: true,
                comparable: false,
            },
            test_id_attribute: "data-testid".into(),
            secure_field_selector: "input[type=password]".into(),
        }),
        operation,
    );
    let acquisitions_started_at = tokio::time::timeout_at(original_deadline.into(), reached)
        .await
        .expect("all required native acquisitions must start inside the original budget")
        .unwrap();
    // The production semantic lease was made before these requests. Its
    // deadline is no later than this bound computed with the same helper at
    // the later acquisition checkpoint. No test hook or longer lease is used.
    let semantic_deadline_bound =
        semantic_lease_at(&timing, true, acquisitions_started_at).deadline;
    tokio::time::sleep_until(semantic_deadline_bound.into()).await;
    assert!(matches!(
        task.result.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(refs.lock().unwrap().ref_ids().is_empty());
    assert_eq!(captures.load(Ordering::SeqCst), 0);
    assert!(!commands
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["method"] == "Runtime.releaseObjectGroup"
            && r["params"]["objectGroup"] == held_group));

    let release_started_at = Instant::now();
    let mut first_ack_at = None;
    let mut sibling_fence_at = None;
    let mut second_ack_at = None;
    if boundary != Boundary::MissingAck {
        release.send(1).unwrap();
        assert_eq!(acked.recv().await, Some(1));
        first_ack_at = Some(Instant::now());
        if boundary == Boundary::StartedSiblings {
            // A real transport roundtrip acknowledges delivery of the first
            // late reply while its already-started sibling is still withheld.
            // No timed sleep or injected backend error stands in for drainage.
            fence(&client).await;
            sibling_fence_at = Some(Instant::now());
            assert!(matches!(
                task.result.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert_eq!(captures.load(Ordering::SeqCst), 0);
            assert!(!commands
                .lock()
                .unwrap()
                .iter()
                .any(|r| r["method"] == "Runtime.releaseObjectGroup"
                    && r["params"]["objectGroup"] == held_group));
            release.send(7).unwrap();
            assert_eq!(acked.recv().await, Some(7));
            second_ack_at = Some(Instant::now());
        }
    }
    // This is only a deadlock watchdog. Success must still finish before the
    // original 80 ms deadline; unknown-resource cleanup may outlive that budget.
    let (output, cleanup) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(task.result, task.join)
    })
    .await
    .expect("retained acquisition and cleanup must settle");
    let completed = Instant::now();
    assert!(matches!(&cleanup, Ok(Ok(()))));
    let (settled, dirty) = settle_observation_dispatch(output, cleanup);
    let fallback = boundary != Boundary::MissingAck;
    assert_eq!(dirty, !fallback);
    if fallback {
        assert!(
            completed < original_deadline,
            "fresh fallback must fit the unchanged 80 ms budget: completed_us={} acquisitions_us={} semantic_bound_us={} release_us={} first_ack_us={:?} sibling_fence_us={:?} second_ack_us={:?} captures={} commands={} result_ok={} dirty={}",
            completed.duration_since(started).as_micros(),
            acquisitions_started_at.duration_since(started).as_micros(),
            semantic_deadline_bound.duration_since(started).as_micros(),
            release_started_at.duration_since(started).as_micros(),
            first_ack_at.map(|at| at.duration_since(started).as_micros()),
            sibling_fence_at.map(|at| at.duration_since(started).as_micros()),
            second_ack_at.map(|at| at.duration_since(started).as_micros()),
            captures.load(Ordering::SeqCst),
            commands.lock().unwrap().len(),
            settled.result.is_ok(),
            dirty
        );
        assert_eq!(settled.effects, Effects::Completed);
        let value = settled.result.unwrap();
        assert_eq!(value["treeUnavailable"], true);
        assert_eq!(value["truncated"], true);
        assert_eq!(value["pixels"]["width"], 10);
        assert_eq!(value["pixels"]["height"], 10);
        assert_eq!(value["root"].as_object().unwrap().len(), 1);
        let root = parse_ref(value["root"]["ref"]["id"].as_str().unwrap()).unwrap();
        assert_eq!(
            refs.lock().unwrap().ref_ids(),
            HashSet::from([root.clone()])
        );
        assert_eq!(
            refs.lock().unwrap().get(&root).unwrap().backend_node_id,
            Some(1)
        );
        let handle = value["pixels"]["handle"].as_str().unwrap();
        let length = usize::try_from(value["pixels"]["size"].as_u64().unwrap()).unwrap();
        let returned = owner.blobs.read(&owner.scope, handle, 0, length).unwrap();
        assert_eq!(returned.len(), length);
        let decoded = image::load_from_memory_with_format(&returned, image::ImageFormat::Png)
            .unwrap()
            .to_rgba8();
        assert_eq!(decoded.dimensions(), (10, 10));
        assert!(decoded
            .pixels()
            .all(|pixel| *pixel == image::Rgba([17, 83, 149, 255])));
        owner.blobs.release(&owner.scope, handle).unwrap();
    } else {
        assert!(
            completed >= original_deadline,
            "unacknowledged ownership must not use a value-only fast exit"
        );
        assert_eq!(settled.effects, Effects::Unknown);
        assert_eq!(settled.result, Err(ProtocolError::DeadlineExceeded));
        assert!(refs.lock().unwrap().ref_ids().is_empty());
    }
    assert_eq!(captures.load(Ordering::SeqCst), usize::from(fallback));
    {
        let publication = dispatch.publication.lock().await;
        assert_eq!(
            (
                publication.published_revision,
                publication.observed_revision
            ),
            (u64::from(fallback), u64::from(fallback))
        );
    }
    let terminal_refs = refs.lock().unwrap().ref_ids();
    let terminal_commands = commands.lock().unwrap().clone();
    if !fallback {
        // Missing ACK is the explicit counterexample to the old success
        // ordering: its terminal is dirty, unpublished and owner-quarantining.
        release.send(1).unwrap();
        assert_eq!(acked.recv().await, Some(1));
    }
    fence(&client).await;
    assert_eq!(
        *commands.lock().unwrap(),
        terminal_commands,
        "late acquisition cannot resume traversal, publication, screenshot or duplicate cleanup"
    );
    assert_eq!(refs.lock().unwrap().ref_ids(), terminal_refs);
    assert_eq!(captures.load(Ordering::SeqCst), usize::from(fallback));
    {
        let publication = dispatch.publication.lock().await;
        assert_eq!(
            (
                publication.published_revision,
                publication.observed_revision
            ),
            (u64::from(fallback), u64::from(fallback))
        );
    }
    assert_eq!(client.pending_len().await, 0);
    assert_eq!(owner.targets.inventory().is_ok(), fallback);
    owner.blobs.check_budget_integrity().unwrap();
    stop.send(()).unwrap();
    let (released, source_cycle, released_at, empty_mask_releases, acknowledgements) =
        server.await.unwrap();
    assert!(released_at >= semantic_deadline_bound);
    let mut expected = vec![format!("{held_group}-node-1")];
    if expected_started == 2 {
        expected.push(format!("{held_group}-node-7"));
    }
    let mut released_held = released[&held_group].clone();
    released_held.sort();
    expected.sort();
    assert_eq!(released_held, expected);
    if boundary != Boundary::FirstResource {
        assert_eq!(
            released[&security_group],
            [
                format!("{security_group}-node-1"),
                format!("{security_group}-inventory")
            ]
        );
    }
    assert_eq!(
        released.len(),
        usize::from(boundary != Boundary::FirstResource) + 1 + usize::from(fallback)
    );
    assert_eq!(empty_mask_releases, if fallback { 2 } else { 0 });
    assert_eq!(
        source_cycle,
        if fallback {
            vec!["holder", "verify", "verify", "remove", "release"]
        } else {
            vec![]
        }
    );
    assert_eq!(
        acknowledgements,
        match boundary {
            Boundary::FirstResource => vec![1],
            Boundary::StartedSiblings => vec![1, 7],
            Boundary::Candidate | Boundary::MissingAck => vec![7, 1],
        }
    );
}
