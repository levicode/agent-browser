//! Real framed-CDP readonly custody tests. ACKs are held by the peer, not faked.
use super::*;
use crate::native::client_debt::{OperationJournalHandle, OperationKey, OwnerDebtLedger};
use futures_util::{SinkExt, StreamExt};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

struct Peer {
    client: CdpClient,
    ledger: Arc<OwnerDebtLedger>,
    journal: OperationJournalHandle,
    operation: OperationLease,
    _cancel: tokio::sync::watch::Sender<CancelSignal>,
    releases: mpsc::UnboundedReceiver<Value>,
    replies: mpsc::UnboundedSender<Value>,
    log: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Peer {
    async fn new(child: bool, bad_proof: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (release_tx, releases) = mpsc::unbounded_channel();
        let (replies, mut reply_rx) = mpsc::unbounded_channel::<Value>();
        let log = Arc::new(Mutex::new(Vec::new()));
        let recorded = log.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            loop {
                tokio::select! {
                    reply = reply_rx.recv() => {
                        let Some(reply) = reply else { break; };
                        if socket.send(Message::Text(reply.to_string())).await.is_err() { break; }
                    }
                    message = socket.next() => {
                        let Some(Ok(Message::Text(text))) = message else { break; };
                        let request: Value = serde_json::from_str(&text).unwrap();
                        recorded.lock().unwrap().push(request.clone());
                        assert_eq!(request["sessionId"], "page");
                        let result = match request["method"].as_str().unwrap() {
                            "Page.getFrameTree" => {
                                let mut root = json!({"frame":{"id":"root","loaderId":"doc","url":"about:blank"}});
                                if child { root["childFrames"] = json!([{"frame":{"id":"child","parentId":"root","loaderId":"child-doc","url":"about:blank"}}]); }
                                json!({"frameTree":root})
                            }
                            "Page.getLayoutMetrics" => json!({"cssVisualViewport":{"clientWidth":10,"clientHeight":10,"offsetX":0,"offsetY":0,"scale":1},"cssLayoutViewport":{"clientWidth":10,"clientHeight":10}}),
                            "Page.createIsolatedWorld" => json!({"executionContextId":3}),
                            "DOM.getFrameOwner" => json!({"backendNodeId":2}),
                            // Deliberately reuse textual IDs across successive groups.
                            // The product must not queue a raw ID release for them.
                            "DOM.resolveNode" => json!({"object":{"type":"object","subtype":"node","objectId":"reused-readonly-handle"}}),
                            "DOM.getBoxModel" => json!({"model":{"border":[0,0,10,0,10,10,0,10],"content":[0,0,10,0,10,10,0,10]}}),
                            "Runtime.callFunctionOn" => {
                                if bad_proof {
                                    json!({"result":{"objectId":"aux-result"},"exceptionDetails":{"exception":{"objectId":"aux-exception"}}})
                                } else if request["params"]["functionDeclaration"] == BOX_PROOF {
                                    json!({"result":{"value":{"connected":true,"frameOwner":child,"width":10,"height":10}}})
                                } else if request["params"]["functionDeclaration"] == crate::native::client_observation::FRAME_OWNER_GEOMETRY {
                                    json!({"result":{"value":{"x":0,"y":0,"selector":"#child"}}})
                                } else {
                                    json!({"result":{"value":true}})
                                }
                            }
                            "Runtime.releaseObject" | "Runtime.releaseObjectGroup" => {
                                release_tx.send(request).unwrap();
                                continue;
                            }
                            other => panic!("unmodeled readonly custody command {other}: {request}"),
                        };
                        let reply = json!({"id":request["id"],"sessionId":request["sessionId"],"result":result});
                        if socket.send(Message::Text(reply.to_string())).await.is_err() { break; }
                    }
                }
            }
        });
        let client = CdpClient::connect(&url).await.unwrap();
        let ledger = OwnerDebtLedger::new(1, "readonly-disposal".into());
        client.install_debt_ledger(ledger.clone()).unwrap();
        let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline: Instant::now() + Duration::from_secs(2),
            cancellation,
        };
        let journal = ledger
            .operation(
                OperationKey {
                    generation: 1,
                    operation_seq: 1,
                },
                "target".into(),
                "page".into(),
            )
            .unwrap();
        journal.bind_operation(&operation).unwrap();
        Self {
            client,
            ledger,
            journal,
            operation,
            _cancel,
            releases,
            replies,
            log,
            task,
        }
    }
    fn binding(&self) -> element::ExactBinding {
        element::ExactBinding {
            page_session: "page".into(),
            session: "page".into(),
            frame: "root".into(),
            loader: "doc".into(),
            actionable: false,
        }
    }
    async fn next_release(&mut self) -> Value {
        tokio::time::timeout(Duration::from_secs(1), self.releases.recv())
            .await
            .unwrap()
            .unwrap()
    }
    fn ack(&self, request: &Value) {
        self.replies
            .send(json!({"id":request["id"],"sessionId":request["sessionId"],"result":{}}))
            .unwrap();
    }
    async fn wait_debt(&self, count: u32) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while self.ledger.snapshot().object_debt != count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    async fn close(self) {
        self.client.close().await;
        self.task.await.unwrap();
    }
}

#[tokio::test]
async fn semantic_box_held_group_ack_preserves_eighty_ms_and_exact_later_group() {
    let mut peer = Peer::new(false, false).await;
    let binding = peer.binding();
    let mut held = Vec::new();
    for _ in 0..2 {
        let operation = OperationLease {
            is_callback: peer.operation.is_callback,
            generation: peer.operation.generation,
            sequence: peer.operation.sequence,
            deadline: Instant::now() + Duration::from_millis(80),
            cancellation: peer.operation.cancellation.clone(),
        };
        let result = tokio::time::timeout(
            Duration::from_millis(80),
            peer.journal.scope(read_exact_box_impl(
                &peer.client,
                &binding,
                1,
                &operation,
                false,
                true,
            )),
        )
        .await
        .expect("readonly disposal consumed semantic deadline")
        .unwrap();
        assert_eq!(result.0["model"]["border"][2], 10);
        held.push(peer.next_release().await);
    }
    assert!(held
        .iter()
        .all(|r| r["method"] == "Runtime.releaseObjectGroup"));
    assert_ne!(
        held[0]["params"]["objectGroup"],
        held[1]["params"]["objectGroup"]
    );
    assert_eq!(peer.ledger.snapshot().object_debt, 2);
    assert!(
        peer.client
            .install_debt_ledger(OwnerDebtLedger::new(2, "replacement".into()))
            .is_err(),
        "pending custody cannot transfer to replacement owner"
    );
    peer.ack(&held[0]);
    peer.wait_debt(1).await;
    assert_eq!(
        peer.ledger.snapshot().outstanding_commands,
        1,
        "old release must not clear later same-text acquisition"
    );
    peer.ack(&held[1]);
    peer.wait_debt(0).await;
    assert!(!peer
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["method"] == "Runtime.releaseObject"));
    peer.close().await;
}

#[tokio::test]
async fn semantic_frame_owner_held_group_ack_does_not_consume_eighty_ms() {
    let mut peer = Peer::new(true, false).await;
    let operation = OperationLease {
        is_callback: peer.operation.is_callback,
        generation: peer.operation.generation,
        sequence: peer.operation.sequence,
        deadline: Instant::now() + Duration::from_millis(80),
        cancellation: peer.operation.cancellation.clone(),
    };
    let frames = tokio::time::timeout(
        Duration::from_millis(80),
        peer.journal.scope(
            crate::native::client_observation::enumerate_semantic_frames(
                &peer.client,
                "page",
                &HashMap::new(),
                &operation,
            ),
        ),
    )
    .await
    .expect("frame owner disposal consumed semantic deadline")
    .unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[1].frame_path, vec!["#child"]);
    let held = peer.next_release().await;
    assert_eq!(held["method"], "Runtime.releaseObjectGroup");
    assert_eq!(peer.ledger.snapshot().object_debt, 1);
    peer.ack(&held);
    peer.wait_debt(0).await;
    peer.close().await;
}

#[tokio::test]
async fn refused_semantic_geometry_keeps_primary_failure_and_all_group_custody() {
    let mut peer = Peer::new(false, true).await;
    let binding = peer.binding();
    let result = tokio::time::timeout(
        Duration::from_millis(80),
        peer.journal.scope(read_exact_box_impl(
            &peer.client,
            &binding,
            1,
            &peer.operation,
            false,
            true,
        )),
    )
    .await
    .expect("refused readonly proof waited for disposal ACK");
    assert!(
        result.is_err(),
        "group handoff cannot validate malformed semantic proof"
    );
    let held = peer.next_release().await;
    assert_eq!(held["method"], "Runtime.releaseObjectGroup");
    assert_eq!(peer.ledger.snapshot().object_debt, 1);
    assert!(!peer
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["method"] == "Runtime.releaseObject"));
    peer.ack(&held);
    peer.wait_debt(0).await;
    peer.close().await;
}

#[tokio::test]
async fn wrong_session_readonly_group_ack_never_discharges_semantic_box_custody() {
    let mut peer = Peer::new(false, false).await;
    let binding = peer.binding();
    peer.journal
        .scope(read_exact_box_impl(
            &peer.client,
            &binding,
            1,
            &peer.operation,
            false,
            true,
        ))
        .await
        .unwrap();
    let held = peer.next_release().await;
    peer.replies
        .send(json!({"id":held["id"],"sessionId":"other-page","result":{}}))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !peer.ledger.snapshot().integrity_lost {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(peer.ledger.snapshot().object_debt, 1);
    peer.close().await;
}

#[tokio::test]
async fn strict_action_and_pixel_geometry_still_wait_for_exact_object_release() {
    let mut peer = Peer::new(false, false).await;
    let binding = peer.binding();
    let release = {
        let read = peer.journal.scope(read_exact_box_impl(
            &peer.client,
            &binding,
            1,
            &peer.operation,
            false,
            false,
        ));
        tokio::pin!(read);
        let release = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                _ = &mut read => panic!("strict read completed without exact release ACK"),
                release = peer.releases.recv() => release.unwrap(),
            }
        })
        .await
        .unwrap();
        assert_eq!(release["method"], "Runtime.releaseObject");
        assert!(tokio::time::timeout(Duration::from_millis(80), &mut read)
            .await
            .is_err());
        peer.ack(&release);
        read.await.unwrap();
        release
    };
    assert_eq!(release["params"]["objectId"], "reused-readonly-handle");
    peer.wait_debt(0).await;
    peer.close().await;
}

#[tokio::test]
async fn refused_frame_owner_proof_keeps_group_custody_without_publishing_frames() {
    let mut peer = Peer::new(true, true).await;
    let result = tokio::time::timeout(
        Duration::from_millis(80),
        peer.journal.scope(
            crate::native::client_observation::enumerate_semantic_frames(
                &peer.client,
                "page",
                &HashMap::new(),
                &peer.operation,
            ),
        ),
    )
    .await
    .expect("refused frame owner waited for disposal ACK");
    assert!(result.is_err());
    let held = peer.next_release().await;
    assert_eq!(held["method"], "Runtime.releaseObjectGroup");
    assert_eq!(peer.ledger.snapshot().object_debt, 1);
    assert!(!peer
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["method"] == "Runtime.releaseObject"));
    peer.ack(&held);
    peer.wait_debt(0).await;
    peer.close().await;
}

#[tokio::test]
async fn old_readonly_group_release_after_new_same_text_acquisition_keeps_new_group_live() {
    use crate::native::client_debt::{command_scope, native_object_group, CommandCategory};
    let mut peer = Peer::new(false, false).await;
    let mut groups = Vec::new();
    for _ in 0..2 {
        let group = peer
            .client
            .readonly_group_instance("native-semantic-box-1")
            .unwrap();
        let value = peer
            .journal
            .scope(native_object_group(
                &group,
                command_scope(
                    CommandCategory::ApplicationObject,
                    false,
                    peer.client.send_command(
                        "DOM.resolveNode",
                        Some(json!({"backendNodeId":1,"objectGroup":group})),
                        Some("page"),
                    ),
                ),
            ))
            .await
            .unwrap();
        assert_eq!(value["object"]["objectId"], "reused-readonly-handle");
        groups.push(group);
    }
    assert_ne!(groups[0], groups[1]);
    assert_eq!(peer.ledger.snapshot().object_debt, 2);
    // The older release is not even queued until the newer same-text object
    // acquisition has completed. It cannot depend on release-before-acquire.
    peer.journal
        .scope(async {
            peer.client
                .handoff_readonly_group_release("page", &groups[0])
        })
        .await
        .unwrap();
    let old_release = peer.next_release().await;
    assert_eq!(old_release["params"]["objectGroup"], groups[0]);
    peer.ack(&old_release);
    peer.wait_debt(1).await;
    let proof = peer.journal.scope(native_object_group(&groups[1], command_scope(
        CommandCategory::ApplicationRead, false,
        peer.client.send_command("Runtime.callFunctionOn", Some(json!({"objectId":"reused-readonly-handle","objectGroup":groups[1],"functionDeclaration":"function(){return true}","returnByValue":true})), Some("page")),
    ))).await.unwrap();
    assert_eq!(proof["result"]["value"], true);
    assert!(!peer.ledger.snapshot().integrity_lost);
    peer.journal
        .scope(async {
            peer.client
                .handoff_readonly_group_release("page", &groups[1])
        })
        .await
        .unwrap();
    let new_release = peer.next_release().await;
    assert_eq!(new_release["params"]["objectGroup"], groups[1]);
    peer.ack(&new_release);
    peer.wait_debt(0).await;
    assert!(!peer
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["method"] == "Runtime.releaseObject"));
    peer.close().await;
}

fn semantic_bounds_frame(peer: &Peer) -> ObservationFrame {
    ObservationFrame {
        binding: peer.binding(),
        offset_x: 0.0,
        offset_y: 0.0,
        frame_path: vec![],
        parent_frame_id: None,
        owner_backend_id: None,
        url: "about:blank".into(),
    }
}

#[tokio::test]
async fn strict_snapshot_semantic_bounds_debt_never_discharges_strict_polygon_object() {
    let mut peer = Peer::new(false, false).await;
    let frame = semantic_bounds_frame(&peer);
    let geometry = peer
        .journal
        .scope(GeometrySnapshot::capture(
            &peer.client,
            "page",
            &[frame.clone()],
            &peer.operation,
        ))
        .await
        .unwrap();
    let operation = OperationLease {
        is_callback: peer.operation.is_callback,
        generation: peer.operation.generation,
        sequence: peer.operation.sequence,
        deadline: Instant::now() + Duration::from_millis(80),
        cancellation: peer.operation.cancellation.clone(),
    };
    let bounds = tokio::time::timeout(
        Duration::from_millis(80),
        peer.journal
            .scope(geometry.node_semantic_bounds(&peer.client, &frame, 1, &operation)),
    )
    .await
    .expect("pure bounds waited for disposal ACK")
    .unwrap();
    assert_eq!(bounds.bounds().width, 10.0);
    let group = peer.next_release().await;
    assert_eq!(group["method"], "Runtime.releaseObjectGroup");
    assert_eq!(peer.ledger.snapshot().object_debt, 1);
    {
        let strict = peer.journal.scope(geometry.node_border_polygons(
            &peer.client,
            &frame,
            1,
            &peer.operation,
        ));
        tokio::pin!(strict);
        let object = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                _ = &mut strict => panic!("strict polygon skipped exact object release"),
                release = peer.releases.recv() => release.unwrap(),
            }
        })
        .await
        .unwrap();
        assert_eq!(object["method"], "Runtime.releaseObject");
        assert_eq!(object["params"]["objectId"], "reused-readonly-handle");
        assert_eq!(peer.ledger.snapshot().object_debt, 2);
        peer.ack(&group);
        peer.wait_debt(1).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(80), &mut strict)
                .await
                .is_err(),
            "readonly group ACK must not settle later strict object custody"
        );
        peer.ack(&object);
        assert_eq!(strict.await.unwrap().len(), 1);
    }
    peer.wait_debt(0).await;
    assert!(!peer.ledger.snapshot().integrity_lost);
    peer.close().await;
}

#[tokio::test]
async fn semantic_snapshot_rejects_strict_polygon_before_any_new_cdp_work() {
    let peer = Peer::new(false, false).await;
    let frame = semantic_bounds_frame(&peer);
    let frames = [frame.clone()];
    let proof = SemanticFrameProof::for_test(&frames, &[], "readonly-disposal", 1, &peer.operation);
    let geometry = peer
        .journal
        .scope(GeometrySnapshot::capture_semantic(
            &peer.client,
            "page",
            &frames,
            &proof,
            &ObservationFramePolicy::default(),
            "readonly-disposal",
            1,
            &peer.operation,
        ))
        .await
        .unwrap();
    let before = peer.log.lock().unwrap().len();
    assert!(matches!(
        peer.journal
            .scope(geometry.node_border_polygons(&peer.client, &frame, 1, &peer.operation))
            .await,
        Err(GeometryError::IncompleteInventory)
    ));
    assert_eq!(
        peer.log.lock().unwrap().len(),
        before,
        "semantic snapshot must not acquire a strict action/pixel object"
    );
    assert_eq!(peer.ledger.snapshot().object_debt, 0);
    peer.close().await;
}
