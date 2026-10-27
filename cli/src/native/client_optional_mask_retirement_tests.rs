//! Original observation-capture obligations #8 and #10, through Dispatch.start.
//! Screenshot deadline cases separately bound the safe subset of obligation #9;
//! semantic publication is independent of the retained raw-capture join.
//! The peer implements protocol responses, not a renderer: no pixel-fidelity claim.
use super::*;
use base64::Engine;
use futures_util::SinkExt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    OptionalDeadline,
    OptionalShortDeadline,
    OptionalScreenshotShortDeadline,
    MissingScreenshotAck,
    CancelInventory,
    CancelUnacknowledgedObject,
    OptionalResourceShortDeadline,
    CancelShortUnacknowledgedObject,
    CancelDirtyRestore,
    CancelShortDirtyRestore,
    PrivacyFailure,
    GeometryFailure,
    SupersededBeforeCutoff,
    DetachedBeforeCutoff,
}

async fn optional_mask_retirement(case: Case) {
    let screenshot = matches!(
        case,
        Case::OptionalScreenshotShortDeadline | Case::MissingScreenshotAck
    );
    // Build a valid late PNG outside the unchanged operation budget. The
    // withheld reply is real screenshot-shaped data, never a synthetic error.
    let png = if screenshot {
        let mut bytes = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgba8(100, 80)
            .write_to(&mut bytes, image::ImageFormat::Png)
            .unwrap();
        Some(base64::engine::general_purpose::STANDARD.encode(bytes.into_inner()))
    } else {
        None
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let commands = Arc::new(Mutex::new(Vec::<Value>::new()));
    let peer_commands = commands.clone();
    let (reached_tx, reached) = oneshot::channel();
    let (release, mut resume) = oneshot::channel();
    let (late_tx, late) = oneshot::channel();
    let mut release = Some(release);
    let mut late = Some(late);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        if screenshot {
            stream.set_nodelay(true).unwrap();
        }
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut held = None;
        let mut reached_tx = Some(reached_tx);
        let mut late_tx = Some(late_tx);
        let mut raw_acked = false;
        loop {
            // Holding one reply must not block cleanup ACKs on the same session.
            let message = tokio::select! {
                _ = &mut resume, if held.is_some() => {
                    let response: Value = held.take().unwrap();
                    ws.send(tokio_tungstenite::tungstenite::Message::Text(response.to_string())).await.unwrap();
                    if screenshot { raw_acked = true; }
                    late_tx.take().unwrap().send(()).unwrap();
                    continue;
                }
                message = ws.next() => match message { Some(Ok(message)) => message, _ => break },
            };
            let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
            assert_eq!(request["sessionId"], "session");
            peer_commands.lock().unwrap().push(request.clone());
            let method = request["method"].as_str().unwrap();
            let group = request["params"]["objectGroup"].as_str();
            let result = match method {
                "Page.getFrameTree" => {
                    json!({"frameTree":{"frame":{"id":"frame","loaderId":"loader","url":"https://fixture.invalid/"}}})
                }
                "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                "Page.getLayoutMetrics" => {
                    json!({"cssVisualViewport":{"clientWidth":100,"clientHeight":80,"offsetX":0,"offsetY":0,"scale":1},"cssLayoutViewport":{"clientWidth":100,"clientHeight":80}})
                }
                "Animation.getPlaybackRate" => json!({"playbackRate":1}),
                "Animation.enable" | "Animation.setPlaybackRate" | "Animation.disable" => json!({}),
                "DOM.getDocument" => {
                    json!({"root":{"nodeType":9,"backendNodeId":1,"children":[{"nodeType":1,"nodeName":"BUTTON","localName":"button","backendNodeId":7}]}})
                }
                "Accessibility.getFullAXTree" => {
                    json!({"nodes":[{"nodeId":"document","backendDOMNodeId":1,"role":{"type":"role","value":"RootWebArea"},"childIds":["button"]},{"nodeId":"button","parentId":"document","backendDOMNodeId":7,"role":{"type":"role","value":"button"},"name":{"type":"computedString","value":"Button"}}]})
                }
                "DOM.resolveNode" => {
                    json!({"object":{"objectId":format!("{}-node-{}",group.unwrap_or("geometry"), request["params"]["backendNodeId"]),"subtype":"node"}})
                }
                "DOM.getBoxModel" => json!({"model":{"border":[0,0,100,0,100,80,0,80]}}),
                "Runtime.getProperties" => {
                    json!({"result":[{"name":"focused","value":{"type":"object","subtype":"null","value":null}}]})
                }
                "DOMSnapshot.captureSnapshot" => {
                    json!({"strings":["frame"],"documents":[{"frameId":0,"nodes":{"nodeType":[1],"backendNodeId":[7]}}]})
                }
                "Runtime.callFunctionOn" => {
                    let declaration = request["params"]["functionDeclaration"].as_str().unwrap();
                    if screenshot && group == Some("capture-source-1-frame") {
                        assert_eq!(request["params"]["objectId"], "source-holder");
                        if declaration == "function(){return this.remove()}" {
                            assert!(
                                raw_acked,
                                "source custody cannot end before the exact raw ACK"
                            );
                        }
                        assert!(matches!(
                            declaration,
                            "function(){return this.verify()}" | "function(){return this.remove()}" | "function(selector,...nodes){return this.install(selector,nodes)}"
                        ));
                        json!({"result":{"value":true}})
                    } else if group == Some("capture-1-frame") {
                        json!({"result":{"value":{"count":0,"masks":[],"secure":[],"opaque":case == Case::PrivacyFailure,"unsafeGeometry":case == Case::GeometryFailure}}})
                    } else if declaration.contains("Array.from(result)") {
                        json!({"result":{"objectId":"security"}})
                    } else if declaration.contains("const read=") {
                        let values = request["params"]["arguments"].as_array().unwrap().iter().skip(2).map(|arg| {
                            let object = arg["objectId"].as_str().unwrap();
                            if object.ends_with("node-1") {
                                json!({"attributes":{},"labels":[],"states":{},"rect":null,"author":{"nodeType":9,"visible":true}})
                            } else {
                                assert!(object.ends_with("node-7"));
                                json!({"attributes":{},"labels":[],"states":{},"rect":{"x":0,"y":0,"width":100,"height":80},"author":{"nodeType":1,"tag":"button","visible":true}})
                            }
                        }).collect::<Vec<_>>();
                        json!({"result":{"value":values}})
                    } else if declaration == crate::native::client_geometry::BOX_PROOF {
                        json!({"result":{"value":{"connected":true,"frameOwner":false}}})
                    } else if declaration
                        .contains("Object.getOwnPropertyDescriptor(p,'isConnected')")
                    {
                        json!({"result":{"value":true}})
                    } else {
                        panic!("unexpected semantic function: {declaration}");
                    }
                }
                "Runtime.releaseObjectGroup"
                    if screenshot && group == Some("capture-source-1-frame") =>
                {
                    assert!(
                        raw_acked,
                        "source group cannot be released before the exact raw ACK"
                    );
                    json!({})
                }
                "Runtime.releaseObject" | "Runtime.releaseObjectGroup" => json!({}),
                "Runtime.evaluate" if screenshot => {
                    assert_eq!(group, Some("capture-source-1-frame"));
                    assert_eq!(request["params"]["contextId"], 1);
                    json!({"result":{"objectId":"source-holder"}})
                }
                "Page.captureScreenshot" => {
                    assert!(
                        screenshot,
                        "abandoned or refused mask probe must never start a screenshot"
                    );
                    json!({"data":png.as_ref().unwrap()})
                }
                method => panic!("unexpected mask-retirement command: {method}"),
            };
            let dirty_restore = matches!(
                case,
                Case::CancelDirtyRestore | Case::CancelShortDirtyRestore
            ) && method == "Animation.setPlaybackRate"
                && request["params"]["playbackRate"].as_f64() == Some(1.0);
            let response = if dirty_restore {
                json!({"id":request["id"],"sessionId":"session","error":{"code":-32000,"message":"synthetic restoration refusal"}})
            } else {
                json!({"id":request["id"],"sessionId":"session","result":result})
            };
            let hold = if screenshot {
                method == "Page.captureScreenshot"
            } else if matches!(
                case,
                Case::CancelUnacknowledgedObject
                    | Case::CancelShortUnacknowledgedObject
                    | Case::OptionalResourceShortDeadline
            ) {
                method == "Runtime.callFunctionOn" && group == Some("capture-1-frame")
            } else {
                matches!(
                    case,
                    Case::OptionalDeadline
                        | Case::OptionalShortDeadline
                        | Case::CancelInventory
                        | Case::SupersededBeforeCutoff
                        | Case::DetachedBeforeCutoff
                        | Case::CancelDirtyRestore
                        | Case::CancelShortDirtyRestore
                ) && method == "DOMSnapshot.captureSnapshot"
            };
            if hold {
                assert!(held.replace(response).is_none());
                reached_tx.take().unwrap().send(()).unwrap();
            } else {
                ws.send(tokio_tungstenite::tungstenite::Message::Text(
                    response.to_string(),
                ))
                .await
                .unwrap();
            }
        }
    });
    let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
    let owner = Owner::new(client, "session", "target", "scope").await;
    let refs = Arc::new(Mutex::new(RefMap::new()));
    let dispatch = ObservationDispatch::new(refs.clone());
    let (mut op, cancel) = operation(1);
    // Preserve the original 80ms deadline for the value-only mask boundary.
    // Keep separate generous-budget cases and paired 80ms resource/dirty
    // negatives: mandatory 250ms resource settlement may outlive that budget.
    let budget = if matches!(
        case,
        Case::OptionalShortDeadline
            | Case::OptionalResourceShortDeadline
            | Case::OptionalScreenshotShortDeadline
            | Case::MissingScreenshotAck
            | Case::CancelInventory
            | Case::SupersededBeforeCutoff
            | Case::DetachedBeforeCutoff
            | Case::CancelShortUnacknowledgedObject
            | Case::CancelShortDirtyRestore
    ) {
        Duration::from_millis(80)
    } else {
        Duration::from_secs(4)
    };
    op.deadline = Instant::now() + budget;
    let deadline = op.deadline;
    #[cfg(feature = "acceptance-faults")]
    let mut retained = screenshot.then(|| {
        crate::native::client_capture::retained_capture_test::register(&owner.client, op.sequence)
    });
    #[allow(unused_mut)] // The acceptance raw-ACK cases inspect the pending receiver.
    let mut task = dispatch.clone().start(
        owner.context(),
        DispatchRequest::Observe(ObserveRequest {
            options: ObserveFlags {
                pixels: true,
                pixel_fallback: false,
                comparable: false,
            },
            test_id_attribute: "data-testid".into(),
            secure_field_selector: "input[type=password]".into(),
        }),
        op,
    );
    #[allow(unused_mut)] // Set only by the acceptance raw-ACK cases.
    let mut early_result = None;
    #[allow(unused_mut)]
    let mut published_at = None;
    let delayed = !matches!(case, Case::PrivacyFailure | Case::GeometryFailure);
    if delayed {
        tokio::time::timeout(Duration::from_secs(2), reached)
            .await
            .unwrap()
            .unwrap();
        // A complete semantic read has finished before the independent mask read.
        let log = commands.lock().unwrap();
        assert!(log
            .iter()
            .any(|r| r["method"] == "Runtime.releaseObjectGroup"
                && r["params"]["objectGroup"] == "native-metadata-1"));
        assert!(
            refs.lock().unwrap().ref_ids().is_empty(),
            "staging is not publication"
        );
        drop(log);
        if case == Case::SupersededBeforeCutoff {
            let (newer, _cancel_newer) = operation(2);
            let admitted = dispatch.prepare(owner.context(), observe(), newer).unwrap();
            drop(admitted); // Admission alone retires the old publication ticket.
        } else if case == Case::DetachedBeforeCutoff {
            owner.targets.detach(&owner.target).unwrap();
        } else if !screenshot
            && !matches!(
                case,
                Case::OptionalDeadline
                    | Case::OptionalShortDeadline
                    | Case::OptionalResourceShortDeadline
            )
        {
            cancel.send_replace(CancelSignal::Requested);
        }
        if case == Case::OptionalResourceShortDeadline {
            let result = tokio::time::timeout_at(deadline.into(), &mut task.result)
                .await
                .expect("resource custody must not consume the original 80ms result budget")
                .expect("result sender retained");
            published_at = Some(Instant::now());
            assert!(task.receipt.is_sealed_observation());
            assert!(!task.receipt.cleanup_failed_before_publication());
            assert!(
                !task.join.is_finished(),
                "unacknowledged resource still needs settlement"
            );
            assert!(result.as_ref().unwrap().get("pixels").is_none());
            early_result = Some(result);
        }
        #[cfg(feature = "acceptance-faults")]
        if screenshot {
            // Causal notification from the actual raw-capture timeout branch;
            // no sleep, deadline rewrite, manufactured failure, or early ACK.
            let (_registration, entered) = retained.take().unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), entered)
                    .await
                    .unwrap()
                    .unwrap(),
                crate::native::client_capture::CaptureReason::Deadline
            );
            let result = tokio::time::timeout_at(deadline.into(), &mut task.result)
                .await
                .expect("sealed tree must beat the original 80ms deadline")
                .expect("result sender retained");
            published_at = Some(Instant::now());
            assert!(task.receipt.is_sealed_observation());
            assert!(
                !task.join.is_finished(),
                "raw custody must remain joined after the semantic result"
            );
            assert!(result.as_ref().unwrap().get("pixels").is_none());
            early_result = Some(result);
            assert!(!commands
                .lock()
                .unwrap()
                .iter()
                .any(|r| r["params"]["functionDeclaration"] == "function(){return this.remove()}"));
            if case == Case::OptionalScreenshotShortDeadline {
                release.take().unwrap().send(()).unwrap();
                tokio::time::timeout(Duration::from_secs(1), late.take().unwrap())
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
    }
    let result = match early_result {
        Some(result) => result,
        None => tokio::time::timeout(Duration::from_secs(5), task.result)
            .await
            .unwrap()
            .unwrap(),
    };
    let result_time = published_at.unwrap_or_else(Instant::now);
    let joined = task.join.await.unwrap();
    if matches!(
        case,
        Case::MissingScreenshotAck | Case::OptionalResourceShortDeadline
    ) {
        let failure = joined.unwrap_err();
        assert_eq!(failure.error, ProtocolError::CleanupFailed);
        assert!(failure.cleanup_integrity_lost);
    } else {
        joined.unwrap();
    }
    let terminal = Instant::now();
    // Preserve every original assertion and budget. Emit only closed test case,
    // protocol outcome/custody facts and offsets from the original deadline.
    // Print after the join, never on the producer's critical publication path.
    let timing = task.receipt.optional_timing();
    let relative_us = |at: Instant| -> i128 {
        if at >= deadline {
            at.duration_since(deadline).as_micros() as i128
        } else {
            -(deadline.duration_since(at).as_micros() as i128)
        }
    };
    eprintln!(
        "native-optional-mask-timing case={:?} ok={} error={} dirty={} sealed={} cutoff_deadline_us={:?} cutoff_selected_us={:?} attempt_us={:?} sent_us={:?} received_us={} joined_us={}",
        case,
        result.is_ok(),
        serde_json::to_string(&result.as_ref().err().map(|failure| &failure.error)).unwrap(),
        result.as_ref().err().is_some_and(|failure| failure.cleanup_integrity_lost),
        task.receipt.is_sealed_observation(),
        timing.cutoff_deadline.map(relative_us),
        timing.cutoff_selected.map(relative_us),
        timing.publication_attempt.map(relative_us),
        timing.result_sent.map(relative_us),
        relative_us(result_time),
        relative_us(terminal),
    );
    if matches!(
        case,
        Case::OptionalDeadline
            | Case::OptionalShortDeadline
            | Case::OptionalScreenshotShortDeadline
            | Case::CancelInventory
    ) {
        assert!(
            result_time < deadline,
            "immutable result must not consume the parent budget waiting for cleanup"
        );
    }
    if matches!(
        case,
        Case::OptionalDeadline
            | Case::OptionalShortDeadline
            | Case::OptionalScreenshotShortDeadline
            | Case::MissingScreenshotAck
            | Case::OptionalResourceShortDeadline
            | Case::PrivacyFailure
            | Case::GeometryFailure
    ) {
        if !matches!(case, Case::PrivacyFailure | Case::GeometryFailure) {
            assert!(
                result_time >= deadline - (budget / 5).min(Duration::from_millis(500)),
                "optional capture must not finish before its earliest possible subdeadline"
            );
        }
        assert!(
            result_time < deadline,
            "cleanup grace is not the result budget"
        );
        let value = result.unwrap();
        assert!(value.get("treeUnavailable").is_none());
        assert!(value.get("pixels").is_none());
        assert_eq!(value["truncated"], false);
        assert_eq!(value["root"]["role"], "document");
        let children = value["root"]["children"].as_array().unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0]["role"], "button");
        assert_eq!(children[0]["name"], "Button");
        let id = children[0]["ref"]["id"]
            .as_str()
            .unwrap()
            .trim_start_matches('@');
        {
            let current = refs.lock().unwrap();
            let entry = current.get(id).unwrap();
            assert_eq!(entry.backend_node_id, Some(7));
            assert!(entry.is_current_observed(1));
            assert_eq!(entry.exact_binding.as_ref().unwrap(), &owner.binding());
        }
        if !matches!(
            case,
            Case::MissingScreenshotAck | Case::OptionalResourceShortDeadline
        ) {
            let (action, _cancel) = operation(2);
            assert_eq!(dispatch.snapshot_for_action(&action).await.unwrap().0, 1);
        }
    } else {
        let failure = result.unwrap_err();
        if case == Case::DetachedBeforeCutoff {
            assert!(matches!(
                failure.error,
                ProtocolError::StaleScope | ProtocolError::StaleReference
            ));
        }
        assert_eq!(
            failure.error,
            match case {
                Case::CancelInventory
                | Case::CancelDirtyRestore
                | Case::CancelShortDirtyRestore => ProtocolError::Cancelled,
                Case::CancelUnacknowledgedObject
                | Case::CancelShortUnacknowledgedObject
                | Case::OptionalResourceShortDeadline
                | Case::MissingScreenshotAck => ProtocolError::CleanupFailed,
                Case::PrivacyFailure | Case::GeometryFailure => ProtocolError::PolicyDenied,
                Case::SupersededBeforeCutoff => ProtocolError::StaleReference,
                Case::DetachedBeforeCutoff => failure.error.clone(),
                _ => unreachable!(),
            }
        );
        assert_eq!(
            failure.cleanup_integrity_lost,
            matches!(
                case,
                Case::CancelUnacknowledgedObject
                    | Case::CancelShortUnacknowledgedObject
                    | Case::MissingScreenshotAck
                    | Case::CancelDirtyRestore
                    | Case::CancelShortDirtyRestore
            )
        );
        assert!(refs.lock().unwrap().ref_ids().is_empty());
        let published = dispatch.publication.lock().await;
        assert_eq!(
            (published.published_revision, published.observed_revision),
            (0, 0)
        );
    }
    assert_eq!(owner.client.pending_len().await, 0);
    if matches!(
        case,
        Case::CancelShortUnacknowledgedObject
            | Case::MissingScreenshotAck
            | Case::OptionalResourceShortDeadline
    ) {
        assert!(
            terminal >= deadline,
            "unknown resource settlement must not inherit the value-only fast exit"
        );
    }
    let terminal_refs = refs.lock().unwrap().ref_ids();
    let terminal_commands = commands.lock().unwrap().len();
    if delayed {
        // Value-only mask replies may remain held past terminal success. Raw
        // raw-pixel cleanup still requires its exact ACK and restoration;
        // missing ACK reaches cleanup failure after immutable semantic success.
        if let Some(release) = release.take() {
            release.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(1), late.take().unwrap())
                .await
                .unwrap()
                .unwrap();
        }
        // A same-session roundtrip fences processing of the late reply; it is
        // not an arbitrary sleep offered as evidence of no continuation.
        tokio::time::timeout(
            Duration::from_secs(1),
            owner
                .client
                .send_command("Page.getLayoutMetrics", None, Some("session")),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(commands.lock().unwrap().len(), terminal_commands + 1);
    }
    assert_eq!(refs.lock().unwrap().ref_ids(), terminal_refs);
    assert_eq!(owner.client.pending_len().await, 0);
    {
        let log = commands.lock().unwrap();
        for group in ["native-security-1", "native-metadata-1"] {
            assert_eq!(
                log.iter()
                    .filter(|r| r["method"] == "Runtime.releaseObjectGroup"
                        && r["params"]["objectGroup"] == group)
                    .count(),
                1,
                "exact semantic group cleanup: {group}"
            );
        }
        assert_eq!(
            log.iter()
                .filter(|r| r["method"] == "Runtime.releaseObjectGroup"
                    && r["params"]["objectGroup"] == "capture-1-frame")
                .count(),
            usize::from(matches!(
                case,
                Case::CancelUnacknowledgedObject
                    | Case::CancelShortUnacknowledgedObject
                    | Case::OptionalResourceShortDeadline
                    | Case::PrivacyFailure
                    | Case::GeometryFailure
                    | Case::OptionalScreenshotShortDeadline
                    | Case::MissingScreenshotAck
            ))
        );
        assert_eq!(
        log.iter().filter(|r| r["method"] == "Runtime.releaseObject")
            .map(|r| r["params"]["objectId"].as_str().unwrap()).collect::<Vec<_>>(),
        ["native-exact-node-7"],
        "semantic geometry's exact object is released once; semantic refs retain backend identity, not remote handles"
    );
        if screenshot {
            assert_eq!(
                log.iter()
                    .filter(|r| r["method"] == "Page.captureScreenshot")
                    .count(),
                1
            );
            let source = log
                .iter()
                .filter(|r| r["params"]["objectGroup"] == "capture-source-1-frame")
                .collect::<Vec<_>>();
            assert_eq!(
                source
                    .iter()
                    .filter(|r| r["method"] == "Runtime.evaluate")
                    .count(),
                1
            );
            assert_eq!(
                source
                    .iter()
                    .filter(|r| r["params"]["functionDeclaration"]
                        == "function(){return this.verify()}")
                    .count(),
                1
            );
            assert_eq!(
                source
                    .iter()
                    .filter(|r| r["params"]["functionDeclaration"]
                        == "function(selector,...nodes){return this.install(selector,nodes)}")
                    .count(),
                1
            );
            for method in [
                "function(){return this.remove()}",
                "Runtime.releaseObjectGroup",
            ] {
                assert_eq!(
                    source
                        .iter()
                        .filter(|r| r["params"]["functionDeclaration"] == method
                            || r["method"] == method)
                        .count(),
                    usize::from(case == Case::OptionalScreenshotShortDeadline)
                );
            }
        } else {
            assert!(!log.iter().any(|r| r["method"] == "Page.captureScreenshot"
                || r["params"]["objectGroup"]
                    .as_str()
                    .is_some_and(|g| g.starts_with("capture-source-"))));
        }
        assert_eq!(
            log.iter()
                .filter(|r| r["method"] == "Animation.setPlaybackRate"
                    && r["params"]["playbackRate"].as_f64() == Some(1.0))
                .count(),
            usize::from(case != Case::MissingScreenshotAck)
        );
    }
    assert_eq!(
        owner.targets.inventory().is_err(),
        matches!(
            case,
            Case::CancelUnacknowledgedObject
                | Case::CancelShortUnacknowledgedObject
                | Case::OptionalResourceShortDeadline
                | Case::MissingScreenshotAck
                | Case::CancelDirtyRestore
                | Case::CancelShortDirtyRestore
        )
    );
    // No producer or finished-blob charge may survive optional omission/failure.
    let first = owner.blobs.reserve_producer(owner.scope.clone()).unwrap();
    let second = owner.blobs.reserve_producer(owner.scope.clone()).unwrap();
    drop((first, second));
    owner.blobs.check_budget_integrity().unwrap();
    server.abort();
    assert!(
        server.await.unwrap_err().is_cancelled(),
        "peer must not have panicked"
    );
}

#[tokio::test]
async fn optional_mask_deadline_keeps_complete_actionable_tree_and_discards_late_reply() {
    optional_mask_retirement(Case::OptionalDeadline).await;
}
#[tokio::test]
async fn cancelled_mask_inventory_cleans_staging_before_late_reply_without_screenshot() {
    optional_mask_retirement(Case::CancelInventory).await;
}
#[tokio::test]
async fn cancelled_resource_mask_without_ack_is_not_clean_cancellation() {
    optional_mask_retirement(Case::CancelUnacknowledgedObject).await;
}
#[tokio::test]
async fn cancelled_mask_dirty_restore_never_publishes_or_claims_clean_cleanup() {
    optional_mask_retirement(Case::CancelDirtyRestore).await;
}
#[tokio::test]
async fn optional_mask_privacy_refusal_omits_pixels_but_preserves_independent_tree() {
    optional_mask_retirement(Case::PrivacyFailure).await;
}
#[tokio::test]
async fn optional_mask_geometry_refusal_omits_pixels_but_preserves_independent_tree() {
    optional_mask_retirement(Case::GeometryFailure).await;
}

#[tokio::test]
async fn optional_mask_original_eighty_ms_budget_preserves_complete_tree_before_late_reply() {
    optional_mask_retirement(Case::OptionalShortDeadline).await;
}

/// Receiver detachment is not remote settlement. Exercise an installed owner
/// ledger, not just the untracked dispatcher fixture above.
#[tokio::test]
async fn interrupted_value_only_mask_snapshot_retains_exact_debt_until_late_reply() {
    use crate::native::client_debt::{
        command_scope, CommandCategory, OperationKey, OwnerDebtLedger,
    };
    use crate::native::client_observation::{
        retained_read_command, with_capture_retirement, CaptureRetirement, ObservationError,
    };
    for cancelled in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let (reached_tx, reached) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let message = ws.next().await.unwrap().unwrap();
            let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
            assert_eq!(request["method"], "DOMSnapshot.captureSnapshot");
            assert_eq!(request["sessionId"], "session");
            assert_eq!(request["params"], json!({"computedStyles":[]}));
            reached_tx.send(()).unwrap();
            resume.await.unwrap();
            ws.send(tokio_tungstenite::tungstenite::Message::Text(json!({"id":request["id"],"sessionId":"session","result":{"strings":["frame"],"documents":[]}}).to_string())).await.unwrap();
            while let Some(Ok(message)) = ws.next().await {
                assert!(
                    !message.is_text(),
                    "late value-only reply must not trigger cleanup or application commands"
                );
            }
        });
        let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
        let ledger = OwnerDebtLedger::new(1, "scope".into());
        client.install_debt_ledger(ledger.clone()).unwrap();
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
        let (mut op, cancel) = operation(1);
        op.deadline = Instant::now() + Duration::from_millis(80);
        let parent_deadline = op.deadline;
        let pixel = pixel_lease(&op);
        let pixel_deadline = pixel.deadline;
        let (retirement_sender, retirement) = tokio::sync::watch::channel(false);
        let sender = client.clone();
        let task = tokio::spawn(async move {
            journal
                .scope(with_capture_retirement(
                    Some(CaptureRetirement::new(retirement)),
                    command_scope(
                        CommandCategory::ApplicationRead,
                        false,
                        retained_read_command(
                            &sender,
                            "session",
                            "DOMSnapshot.captureSnapshot",
                            json!({"computedStyles":[]}),
                            &pixel,
                        ),
                    ),
                ))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), reached)
            .await
            .unwrap()
            .unwrap();
        if cancelled {
            cancel.send_replace(CancelSignal::Requested);
        }
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        let terminal = Instant::now();
        assert_eq!(
            result,
            Err(if cancelled {
                ObservationError::Cancelled
            } else {
                ObservationError::DeadlineExceeded
            })
        );
        assert!(
            terminal < parent_deadline,
            "read-only mask settlement must fit the original 80ms budget"
        );
        if !cancelled {
            assert!(terminal >= pixel_deadline);
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while client.pending_len().await != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let retained = ledger.snapshot();
        assert_eq!(
            retained.outstanding_commands, 1,
            "dropping the waiter must not erase remote processing debt"
        );
        assert_eq!((retained.input_debt, retained.object_debt), (0, 0));
        assert!(!retained.integrity_lost);
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while ledger.snapshot().outstanding_commands != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let settled = ledger.snapshot();
        assert_eq!((settled.input_debt, settled.object_debt), (0, 0));
        assert!(!settled.integrity_lost);
        assert_eq!(client.pending_len().await, 0);
        drop(retirement_sender);
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
async fn eighty_ms_resource_mask_without_ack_remains_cleanup_failed_after_parent_deadline() {
    optional_mask_retirement(Case::CancelShortUnacknowledgedObject).await;
}
#[tokio::test]
async fn eighty_ms_cancelled_mask_dirty_restore_retains_cleanup_uncertainty() {
    optional_mask_retirement(Case::CancelShortDirtyRestore).await;
}

// The existing exact-client notification is available in the hosted acceptance
// harness. These test-only cases hold actual Page.captureScreenshot responses.
#[cfg(feature = "acceptance-faults")]
#[tokio::test]
async fn optional_screenshot_eighty_ms_clean_late_ack_keeps_complete_tree_without_pixels() {
    optional_mask_retirement(Case::OptionalScreenshotShortDeadline).await;
}

#[cfg(feature = "acceptance-faults")]
#[tokio::test]
async fn optional_screenshot_eighty_ms_missing_ack_publishes_only_tree_and_preserves_custody() {
    optional_mask_retirement(Case::MissingScreenshotAck).await;
}

#[tokio::test]
async fn i10_t06_newer_admission_before_optional_cutoff_never_commits_old_staging() {
    optional_mask_retirement(Case::SupersededBeforeCutoff).await;
}
#[tokio::test]
async fn i10_t06_detached_page_before_optional_cutoff_never_publishes_sealed_tree() {
    optional_mask_retirement(Case::DetachedBeforeCutoff).await;
}

#[tokio::test]
async fn sealed_tree_keeps_unacknowledged_resource_failure_in_retained_join() {
    optional_mask_retirement(Case::OptionalResourceShortDeadline).await;
}
