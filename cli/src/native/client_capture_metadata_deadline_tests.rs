//! Legacy observation-capture obligations #2 and #6, at the native dispatcher.
//! The existing hold is after a real CDP metadata reply, not a withheld resource
//! ACK. Renderer disposal/actionability remains the separate Chromium proof.
use super::*;
use crate::native::client_browser::settle_observation_dispatch;
use crate::native::client_observation::equivalence_tests::hold_metadata;
use crate::native::client_protocol::Effects;
use base64::Engine;
use futures_util::SinkExt;
use std::sync::atomic::AtomicUsize;

#[tokio::test]
async fn stalled_metadata_falls_back_within_original_budget_and_never_resumes() {
    metadata_deadline(true).await;
}

#[tokio::test]
async fn stalled_metadata_without_fallback_expires_without_screenshot_or_late_traversal() {
    metadata_deadline(false).await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FinalPublicationChange {
    None,
    Loader,
    Viewport,
}

#[tokio::test]
async fn fallback_final_frame_change_never_publishes_pixels_or_references() {
    metadata_deadline_case(true, FinalPublicationChange::Loader).await;
}

#[tokio::test]
async fn fallback_final_viewport_change_never_publishes_pixels_or_references() {
    metadata_deadline_case(true, FinalPublicationChange::Viewport).await;
}

async fn metadata_deadline(fallback: bool) {
    metadata_deadline_case(fallback, FinalPublicationChange::None).await;
}

async fn metadata_deadline_case(fallback: bool, final_change: FinalPublicationChange) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let commands = Arc::new(Mutex::new(Vec::<Value>::new()));
    let log = commands.clone();
    let transport_timing = Arc::new(Mutex::new(
        Vec::<(Instant, Instant, String, &'static str)>::with_capacity(128),
    ));
    let peer_timing = transport_timing.clone();
    let captures = Arc::new(AtomicUsize::new(0));
    let capture_log = captures.clone();
    let changed = Arc::new(AtomicUsize::new(0));
    let peer_changed = changed.clone();
    let (stop, mut stopping) = oneshot::channel();
    // Encode the fixture before starting the original 80 ms operation budget.
    let mut bytes = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        10,
        10,
        image::Rgba([17, 83, 149, 255]),
    ))
    .write_to(&mut bytes, image::ImageFormat::Png)
    .unwrap();
    let png_bytes = bytes.into_inner();
    let png = base64::engine::general_purpose::STANDARD.encode(&png_bytes);
    let sequence = 8101;
    let metadata_group = format!("native-metadata-{sequence}");
    let security_group = format!("native-security-{sequence}");
    let peer_metadata_group = metadata_group.clone();
    let peer_security_group = security_group.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut groups = HashMap::<String, Vec<String>>::new();
        let mut released = HashMap::<String, Vec<String>>::new();
        let mut empty_mask_releases = 0;
        let mut source_cycle = Vec::new();
        let mut metadata_replied = false;
        let mut metadata_released_at = None;
        let mut fallback_started = false;
        let mut animations_restored = false;
        let mut restored_geometry_read = false;
        loop {
            let message = tokio::select! {
                _ = &mut stopping => break,
                message = socket.next() => message.unwrap().unwrap(),
            };
            let received_at = Instant::now();
            let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
            let method = request["method"].as_str().unwrap();
            // A test-owned transport fence after terminal settlement is not an
            // observation command, and cannot make the retired reader continue.
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
            let phase = if group == Some(peer_metadata_group.as_str()) {
                "metadata"
            } else if group == Some(peer_security_group.as_str()) {
                "security"
            } else if group.is_some_and(|group| group.starts_with("capture-source-")) {
                "source-mask"
            } else {
                "other"
            };
            if metadata_replied && metadata_released_at.is_none() {
                assert_eq!(
                    method, "Runtime.releaseObjectGroup",
                    "held metadata must only settle its exact group"
                );
                assert_eq!(group, Some(peer_metadata_group.as_str()));
            } else if metadata_released_at.is_some() {
                assert!(
                    fallback,
                    "tree-only deadline must not dispatch any later work"
                );
            }
            let result = match method {
                "Page.getFrameTree" => {
                    let loader = if restored_geometry_read
                        && final_change == FinalPublicationChange::Loader
                    {
                        peer_changed.fetch_add(1, Ordering::SeqCst);
                        "replaced-loader"
                    } else {
                        "loader"
                    };
                    json!({"frameTree":{"frame":{"id":"frame","loaderId":loader,"url":"https://fixture.invalid/"}}})
                }
                "Page.getLayoutMetrics" => {
                    let width = if restored_geometry_read
                        && final_change == FinalPublicationChange::Viewport
                    {
                        peer_changed.fetch_add(1, Ordering::SeqCst);
                        11
                    } else {
                        10
                    };
                    if animations_restored {
                        // The first metrics read after restoration belongs to
                        // geometry revalidation. Change only the final proof.
                        restored_geometry_read = true;
                    }
                    json!({"cssVisualViewport":{"clientWidth":width,"clientHeight":10,"scale":1,"offsetX":0,"offsetY":0},"cssLayoutViewport":{"clientWidth":width,"clientHeight":10}})
                }
                "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                "DOM.getDocument" => {
                    if metadata_replied {
                        assert!(
                            fallback_started,
                            "old DOM traversal cannot resume after its metadata deadline"
                        );
                        assert_eq!(request["params"], json!({"depth":0,"pierce":false}));
                        json!({"root":{"nodeType":9,"backendNodeId":1}})
                    } else {
                        json!({"root":{"nodeType":9,"nodeName":"#document","backendNodeId":1,"children":[{"nodeType":1,"nodeName":"BUTTON","localName":"button","backendNodeId":7}]}})
                    }
                }
                "Accessibility.getFullAXTree" => {
                    assert!(!metadata_replied, "retired semantic traversal restarted");
                    json!({"nodes":[{"nodeId":"root","backendDOMNodeId":1,"role":{"type":"role","value":"RootWebArea"}},{"nodeId":"button","backendDOMNodeId":7,"role":{"type":"role","value":"button"}}]})
                }
                "DOM.resolveNode" => {
                    assert!(
                        !metadata_replied,
                        "retired metadata acquired another handle"
                    );
                    let group = group.unwrap();
                    assert!(group == peer_metadata_group || group == peer_security_group);
                    let object = format!("{group}-node-{}", request["params"]["backendNodeId"]);
                    groups
                        .entry(group.to_owned())
                        .or_default()
                        .push(object.clone());
                    json!({"object":{"objectId":object,"subtype":"node"}})
                }
                "Runtime.getProperties" => {
                    assert!(!metadata_replied, "retired metadata enumerated properties");
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
                    assert!(groups
                        .get(group)
                        .unwrap()
                        .iter()
                        .any(|owned| owned == object));
                    if group == peer_security_group {
                        assert!(!metadata_replied);
                        assert!(declaration.starts_with("function(selector,authorRoots,...roots)"));
                        let object = format!("{group}-inventory");
                        groups.get_mut(group).unwrap().push(object.clone());
                        json!({"result":{"objectId":object}})
                    } else if group == peer_metadata_group {
                        assert!(!metadata_replied, "retired metadata executed another batch");
                        assert!(declaration.starts_with("function(testId,secureSelector,...nodes)"));
                        assert_eq!(request["params"]["returnByValue"], true);
                        let values = request["params"]["arguments"].as_array().unwrap().iter().skip(2).map(|argument| {
                            let object = argument["objectId"].as_str().unwrap();
                            assert!(groups[group].iter().any(|owned| owned == object));
                            if object.ends_with("-node-1") {
                                json!({"attributes":{},"labels":[],"states":{},"rect":null,"author":{"nodeType":9,"visible":true}})
                            } else {
                                assert!(object.ends_with("-node-7"));
                                // A real next-stage onclick probe would be required
                                // if this valid metadata were allowed to continue.
                                json!({"attributes":{},"labels":[],"states":{},"rect":null,"handlerProbe":true,"author":{"nodeType":1,"tag":"button","visible":true}})
                            }
                        }).collect::<Vec<_>>();
                        assert_eq!(values.len(), 2);
                        metadata_replied = true;
                        json!({"result":{"value":values}})
                    } else {
                        assert!(fallback_started);
                        assert_eq!(group, format!("capture-source-{sequence}-frame"));
                        let phase = match declaration {
                            "function(){return this.verify()}" => "verify",
                            "function(){return this.remove()}" => "remove",
                            other => panic!("unexpected post-deadline call: {other}"),
                        };
                        source_cycle.push(phase);
                        json!({"result":{"value":true}})
                    }
                }
                "Runtime.releaseObjectGroup" => {
                    let group = group.unwrap();
                    if group == format!("capture-{sequence}-frame") {
                        // Before/after independent mask inventories each settle
                        // an empty read-only group. Neither owns metadata handles.
                        assert!(fallback_started);
                        assert!(!groups.contains_key(group));
                        empty_mask_releases += 1;
                        assert!(empty_mask_releases <= 2);
                    } else {
                        let objects = groups
                            .remove(group)
                            .expect("release must own the exact live group");
                        assert!(
                            released.insert(group.to_owned(), objects).is_none(),
                            "owned group released twice"
                        );
                        if group == peer_metadata_group {
                            assert!(metadata_replied);
                            metadata_released_at = Some(Instant::now());
                        } else if group == format!("capture-source-{sequence}-frame") {
                            source_cycle.push("release");
                        } else {
                            assert_eq!(group, peer_security_group);
                        }
                    }
                    json!({})
                }
                "Animation.enable" => {
                    assert!(fallback && metadata_released_at.is_some());
                    assert!(
                        !fallback_started,
                        "fallback must start once, only after metadata cleanup"
                    );
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
                    if request["params"]["playbackRate"].as_f64() == Some(1.0) {
                        animations_restored = true;
                    }
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
                        .insert(group.to_owned(), vec!["source-holder".into()])
                        .is_none());
                    source_cycle.push("holder");
                    json!({"result":{"objectId":"source-holder"}})
                }
                "Page.captureScreenshot" => {
                    assert!(fallback_started);
                    assert_eq!(source_cycle, ["holder", "verify"]);
                    assert_eq!(capture_log.fetch_add(1, Ordering::SeqCst), 0);
                    json!({"data":png})
                }
                other => panic!("unexpected metadata-deadline command: {other}"),
            };
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    json!({"id":request["id"],"sessionId":request["sessionId"],"result":result})
                        .to_string(),
                ))
                .await
                .unwrap();
            peer_timing.lock().unwrap().push((
                received_at,
                Instant::now(),
                method.to_owned(),
                phase,
            ));
        }
        assert!(
            groups.is_empty(),
            "every acquired handle must have acknowledged group cleanup"
        );
        (
            released,
            source_cycle,
            metadata_released_at.unwrap(),
            empty_mask_releases,
        )
    });
    let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
    let owner = Owner::new(client.clone(), "session", "target", "scope").await;
    let refs = Arc::new(Mutex::new(RefMap::new()));
    let dispatch = ObservationDispatch::new(refs.clone());
    let (mut operation, _cancel) = operation(sequence);
    let started = Instant::now();
    operation.deadline = started + Duration::from_millis(80);
    if final_change != FinalPublicationChange::None {
        // New refusal controls need enough time to prove a specific final
        // identity/viewport rejection. The original two deadline controls keep
        // their unchanged real 80ms budget and assertions.
        operation.deadline = started + Duration::from_millis(800);
    }
    let original_deadline = operation.deadline;
    let (_hold_guard, held) = hold_metadata(&operation);
    let mut task = dispatch.clone().start(
        owner.context(),
        DispatchRequest::Observe(ObserveRequest {
            continuation: None,
            options: ObserveFlags {
                pixels: false,
                pixel_fallback: fallback,
                comparable: false,
            },
            test_id_attribute: "data-testid".into(),
            secure_field_selector: "input[type=password]".into(),
        }),
        operation,
    );
    tokio::time::timeout_at(original_deadline.into(), held.reached())
        .await
        .expect("must reach the actual metadata reply within the original budget");
    let metadata_held_at = Instant::now();
    assert_eq!(held.metadata_calls(), 1);
    assert_eq!(held.releases(), 0);
    let mut handles = held.handles();
    handles.sort();
    assert_eq!(
        handles,
        [
            format!("{metadata_group}-node-1"),
            format!("{metadata_group}-node-7")
        ]
    );
    assert_eq!(captures.load(Ordering::SeqCst), 0);
    assert!(refs.lock().unwrap().ref_ids().is_empty());
    assert!(matches!(
        task.result.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    // Only the original semantic/parent deadline releases the hold. There is
    // no cancellation, superseding request, injected error, or manual release.
    let ((output, result_at), (cleanup, cleanup_at)) =
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(async { (task.result.await, Instant::now()) }, async {
                (task.join.await, Instant::now())
            },)
        })
        .await
        .expect("expired metadata must settle without manually releasing it");
    let completed = Instant::now();
    assert!(matches!(&cleanup, Ok(Ok(()))));
    let (settled, dirty) = settle_observation_dispatch(output, cleanup);
    if completed >= original_deadline
        || settled.result.is_err()
        || std::env::var_os("E2E_METADATA_DEADLINE_TRACE").is_some()
    {
        let elapsed = |at: Instant| at.saturating_duration_since(started).as_micros();
        eprintln!(
            "metadata-deadline-timing fallback={fallback} held_us={} result_us={} cleanup_us={} completed_us={} parent_us={} result_ok={} dirty={dirty}",
            elapsed(metadata_held_at),
            elapsed(result_at),
            elapsed(cleanup_at),
            elapsed(completed),
            elapsed(original_deadline),
            settled.result.is_ok(),
        );
        for (index, (received, replied, method, phase)) in
            transport_timing.lock().unwrap().iter().enumerate()
        {
            eprintln!(
                "metadata-deadline-cdp index={index} method={method} phase={phase} received_us={} replied_us={}",
                elapsed(*received),
                elapsed(*replied),
            );
        }
    }
    assert!(!dirty);
    assert_eq!(held.releases(), 1);
    if final_change != FinalPublicationChange::None {
        assert_eq!(
            settled.result,
            Err(if final_change == FinalPublicationChange::Loader {
                ProtocolError::StaleReference
            } else {
                ProtocolError::StaleScope
            })
        );
        assert!(changed.load(Ordering::SeqCst) > 0);
        assert_eq!(captures.load(Ordering::SeqCst), 1);
        assert!(refs.lock().unwrap().ref_ids().is_empty());
        assert_eq!(dispatch.publication.lock().await.published_revision, 0);
        assert_eq!(dispatch.publication.lock().await.observed_revision, 0);
        let terminal_commands = commands.lock().unwrap().clone();
        held.release();
        tokio::task::yield_now().await;
        client
            .send_command("Browser.getVersion", None, None)
            .await
            .unwrap();
        tokio::task::yield_now().await;
        assert_eq!(*commands.lock().unwrap(), terminal_commands);
        assert_eq!(held.metadata_calls(), 1);
        assert_eq!(held.releases(), 1);
        assert_eq!(client.pending_len().await, 0);
        assert!(owner.targets.inventory().is_ok());
        owner.blobs.check_budget_integrity().unwrap();
        // Two maximum producers fill the default total quota. Any leaked
        // pixel body or producer charge would prevent the second reservation.
        let first = owner.blobs.reserve_producer(owner.scope.clone()).unwrap();
        let second = owner.blobs.reserve_producer(owner.scope.clone()).unwrap();
        drop((first, second));
        stop.send(()).unwrap();
        let (released, source_cycle, _, empty_mask_releases) = server.await.unwrap();
        let mut released_metadata = released[&metadata_group].clone();
        released_metadata.sort();
        assert_eq!(released_metadata, handles);
        assert_eq!(released.len(), 3);
        assert_eq!(
            released[&format!("capture-source-{sequence}-frame")],
            ["source-holder"]
        );
        assert_eq!(empty_mask_releases, 2);
        assert_eq!(
            source_cycle,
            ["holder", "verify", "verify", "remove", "release"]
        );
        return;
    }
    if fallback {
        assert!(
            completed < original_deadline,
            "fresh fallback must fit the unchanged 80 ms budget"
        );
        assert_eq!(settled.effects, Effects::Completed);
        let value = settled.result.unwrap();
        assert_eq!(value["treeUnavailable"], true);
        assert_eq!(value["truncated"], true);
        assert_eq!(value["root"].as_object().unwrap().len(), 1);
        let root = parse_ref(value["root"]["ref"]["id"].as_str().unwrap()).unwrap();
        let published = refs.lock().unwrap();
        assert_eq!(published.ref_ids(), HashSet::from([root.clone()]));
        assert_eq!(published.get(&root).unwrap().backend_node_id, Some(1));
        drop(published);
        assert_eq!(value["pixels"]["width"], 10);
        assert_eq!(value["pixels"]["height"], 10);
        let handle = value["pixels"]["handle"].as_str().unwrap();
        let length = usize::try_from(value["pixels"]["size"].as_u64().unwrap()).unwrap();
        let returned = owner.blobs.read(&owner.scope, handle, 0, length).unwrap();
        assert_eq!(returned.len(), length);
        // Raster protection may re-encode the PNG. Compare the actual fresh
        // image, not incidental compressed bytes from the synthetic peer.
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
            "tree-only metadata must receive the full original budget"
        );
        assert_eq!(settled.effects, Effects::NotDispatched);
        assert_eq!(settled.result, Err(ProtocolError::DeadlineExceeded));
        assert!(refs.lock().unwrap().ref_ids().is_empty());
    }
    assert_eq!(captures.load(Ordering::SeqCst), usize::from(fallback));
    assert_eq!(
        dispatch.publication.lock().await.published_revision,
        u64::from(fallback)
    );
    assert_eq!(
        dispatch.publication.lock().await.observed_revision,
        u64::from(fallback)
    );
    let committed_refs = refs.lock().unwrap().ref_ids();
    let terminal_commands = commands.lock().unwrap().clone();
    held.release();
    tokio::task::yield_now().await;
    client
        .send_command("Browser.getVersion", None, None)
        .await
        .unwrap();
    tokio::task::yield_now().await;
    assert_eq!(
        *commands.lock().unwrap(),
        terminal_commands,
        "late metadata must not resume traversal, screenshot, or cleanup"
    );
    assert_eq!(held.metadata_calls(), 1);
    assert_eq!(held.releases(), 1);
    assert_eq!(held.handles().len(), 2);
    assert_eq!(refs.lock().unwrap().ref_ids(), committed_refs);
    assert_eq!(
        dispatch.publication.lock().await.published_revision,
        u64::from(fallback)
    );
    assert_eq!(captures.load(Ordering::SeqCst), usize::from(fallback));
    assert_eq!(client.pending_len().await, 0);
    assert!(owner.targets.inventory().is_ok());
    owner.blobs.check_budget_integrity().unwrap();
    stop.send(()).unwrap();
    let (released, source_cycle, released_at, empty_mask_releases) = server.await.unwrap();
    let mut released_metadata = released[&metadata_group].clone();
    released_metadata.sort();
    assert_eq!(released_metadata, handles);
    assert_eq!(
        released[&security_group],
        [
            format!("{security_group}-node-1"),
            format!("{security_group}-inventory")
        ]
    );
    assert_eq!(released.len(), if fallback { 3 } else { 2 });
    if fallback {
        assert_eq!(
            released[&format!("capture-source-{sequence}-frame")],
            ["source-holder"]
        );
    }
    assert_eq!(empty_mask_releases, if fallback { 2 } else { 0 });
    assert!(
        released_at
            >= if fallback {
                started + Duration::from_millis(60)
            } else {
                original_deadline
            }
    );
    assert_eq!(
        source_cycle,
        if fallback {
            vec!["holder", "verify", "verify", "remove", "release"]
        } else {
            vec![]
        }
    );
}
