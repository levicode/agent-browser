//! Source-only regression coverage for immutable owner views and bootstrap debt.
//! The loopback peer releases replies explicitly; no browser or sleep is needed.

use super::*;
use crate::native::client_debt::{
    command_scope, CommandCategory, InitializationWork, OperationKey, ScopeCleanupCommand,
};
use crate::native::client_session::{CancelSignal, OperationLease};
use serde_json::json;
use std::future::Future;
use std::time::Instant;
use tokio::net::TcpListener;

const TEST_BOUND: Duration = Duration::from_secs(3);

struct OwnerPeer {
    root: Arc<CdpClient>,
    requests: mpsc::UnboundedReceiver<Value>,
    replies: mpsc::UnboundedSender<Value>,
    log: Arc<std::sync::Mutex<Vec<Value>>>,
    task: JoinHandle<()>,
}

impl OwnerPeer {
    async fn connect() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let (request_tx, requests) = mpsc::unbounded_channel();
        let (replies, mut reply_rx) = mpsc::unbounded_channel::<Value>();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let peer_log = log.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            loop {
                tokio::select! {
                    reply = reply_rx.recv() => {
                        let Some(reply) = reply else { break };
                        socket.send(Message::Text(reply.to_string())).await.unwrap();
                    }
                    message = socket.next() => match message {
                        Some(Ok(Message::Text(text))) => {
                            let request: Value = serde_json::from_str(&text).unwrap();
                            peer_log.lock().unwrap().push(request.clone());
                            request_tx.send(request).unwrap();
                        }
                        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                        _ => {}
                    }
                }
            }
        });
        let root = Arc::new(
            tokio::time::timeout(TEST_BOUND, CdpClient::connect(&endpoint))
                .await
                .expect("loopback connection exceeded its bound")
                .unwrap(),
        );
        Self {
            root,
            requests,
            replies,
            log,
            task,
        }
    }

    async fn request(&mut self, method: &str) -> Value {
        let request = tokio::time::timeout(TEST_BOUND, self.requests.recv())
            .await
            .expect("expected command was not submitted")
            .expect("loopback peer stopped");
        assert_eq!(request["method"], method);
        request
    }

    fn acknowledge(&self, request: &Value, result: Value) {
        let mut response = json!({"id":request["id"], "result":result});
        if let Some(session) = request.get("sessionId") {
            response["sessionId"] = session.clone();
        }
        self.replies.send(response).unwrap();
    }

    async fn exchange(
        &mut self,
        view: &CdpClient,
        method: &str,
        params: Option<Value>,
        session: Option<&str>,
        result: Value,
    ) -> Value {
        let (reply, ()) = tokio::time::timeout(TEST_BOUND, async {
            tokio::join!(view.send_command(method, params.clone(), session), async {
                let request = self.request(method).await;
                assert_eq!(request.get("params"), params.as_ref());
                assert_eq!(request.get("sessionId").and_then(Value::as_str), session);
                self.acknowledge(&request, result);
            })
        })
        .await
        .expect("gated command exchange exceeded its bound");
        reply.unwrap()
    }

    async fn event(&self, events: &mut broadcast::Receiver<CdpEvent>, event: Value) {
        self.replies.send(event.clone()).unwrap();
        let delivered = tokio::time::timeout(TEST_BOUND, events.recv())
            .await
            .expect("reader event barrier exceeded its bound")
            .unwrap();
        assert_eq!(delivered.method, event["method"].as_str().unwrap());
        assert_eq!(delivered.session_id.as_deref(), event["sessionId"].as_str());
        // The reader observes ledger state before broadcasting this event.
    }

    async fn finish(self, expected_methods: &[&str]) {
        self.root.close().await;
        tokio::time::timeout(TEST_BOUND, self.task)
            .await
            .expect("loopback peer did not close")
            .unwrap();
        let log = self.log.lock().unwrap();
        let methods: Vec<_> = log
            .iter()
            .map(|request| request["method"].as_str().unwrap())
            .collect();
        assert_eq!(
            methods, expected_methods,
            "a denied command reached the wire"
        );
    }
}

fn operation(generation: u64, deadline: Instant) -> (watch::Sender<CancelSignal>, OperationLease) {
    let (cancel, cancellation) = watch::channel(CancelSignal::None);
    (
        cancel,
        OperationLease {
            is_callback: false,
            generation,
            sequence: 1,
            deadline,
            cancellation,
        },
    )
}

async fn rejected<T>(future: impl Future<Output = Result<T, String>>) {
    assert!(tokio::time::timeout(TEST_BOUND, future)
        .await
        .expect("denied command waited for a remote response")
        .is_err());
}

async fn retire_owner(peer: &mut OwnerPeer, ledger: &Arc<OwnerDebtLedger>, context: &str) {
    ledger.retire_after_context_destroy(context).unwrap();
    assert!(
        !ledger.replacement_ready(),
        "retirement alone must not authorize replacement"
    );
    assert!(
        peer.root
            .install_debt_ledger(OwnerDebtLedger::new(
                999,
                "unacknowledged-replacement".into()
            ))
            .is_err(),
        "an unacknowledged phase-two cleanup permitted replacement"
    );
    let root = peer.root.clone();
    let (result, ()) = tokio::join!(
        root.send_owner_cleanup(
            Some(ledger.clone()),
            OwnerCleanupCommand::DisableAutoAttach,
            Instant::now() + TEST_BOUND,
        ),
        async {
            let request = peer.request("Target.setAutoAttach").await;
            assert_eq!(
                request["params"],
                json!({"autoAttach":false,"waitForDebuggerOnStart":false,"flatten":true})
            );
            assert!(
                !ledger.replacement_ready(),
                "submission is not a phase-two ACK"
            );
            peer.acknowledge(&request, json!({}));
        }
    );
    result.unwrap();
    assert!(ledger.replacement_ready());
}

#[tokio::test]
async fn stale_owner_views_and_pre_native_inspect_cannot_borrow_replacement_authority() {
    let mut peer = OwnerPeer::connect().await;
    let inspect = peer.root.inspect_handle();
    let old = OwnerDebtLedger::new(1, "old-owner".into());
    old.bind_context("old-context").unwrap();
    old.bind_session("old-context", "old-target", "old-session")
        .unwrap();
    peer.root.install_debt_ledger(old.clone()).unwrap();
    let old_view = peer.root.owner_view(old.clone()).unwrap();
    let reserved = old_view
        .reserve_tracked_command("Page.getFrameTree", None, Some("old-session"))
        .unwrap();
    let (_cancel, lease) = operation(2, Instant::now() + Duration::from_secs(30));
    let new = OwnerDebtLedger::unpublished(&lease, "new-owner".into(), true).unwrap();
    assert!(peer.root.install_debt_ledger(new.clone()).is_err());
    retire_owner(&mut peer, &old, "old-context").await;
    peer.root.install_debt_ledger(new.clone()).unwrap();
    let new_view = peer.root.owner_view(new.clone()).unwrap();

    rejected(old_view.send_command("Page.getFrameTree", None, Some("old-session"))).await;
    rejected(old_view.send_command_no_wait("Runtime.enable", None, Some("old-session"))).await;
    rejected(old_view.send_reserved_command(
        "Page.getFrameTree",
        None,
        Some("old-session"),
        reserved,
    ))
    .await;
    rejected(old_view.send_reserved_command("Runtime.enable", None, Some("old-session"), None))
        .await;
    let replacement_reservation = new_view
        .reserve_tracked_command("Browser.getVersion", None, None)
        .unwrap();
    rejected(old_view.send_reserved_command(
        "Browser.getVersion",
        None,
        None,
        replacement_reservation,
    ))
    .await;
    let raw =
        json!({"id":9001,"method":"Runtime.evaluate","params":{"expression":"must_not_run()"}})
            .to_string();
    rejected(inspect.send_raw(raw.clone())).await;
    rejected(peer.root.send_raw(raw)).await;
    rejected(peer.root.send_command("Browser.getVersion", None, None)).await;

    old_view.close().await;
    assert!(!peer.root.transport.closed.load(Ordering::SeqCst));
    assert!(Arc::ptr_eq(&old_view.transport, &new_view.transport));
    peer.exchange(
        &new_view,
        "Target.createBrowserContext",
        Some(json!({"disposeOnDetach":true})),
        None,
        json!({"browserContextId":"new-context"}),
    )
    .await;
    assert_eq!(new.bound_context().as_deref(), Some("new-context"));
    peer.finish(&["Target.setAutoAttach", "Target.createBrowserContext"])
        .await;
}

#[tokio::test]
async fn acquisition_reservation_cannot_be_laundered_into_runtime_evaluation() {
    let peer = OwnerPeer::connect().await;
    let (_cancel, lease) = operation(1, Instant::now() + Duration::from_secs(30));
    let ledger = OwnerDebtLedger::unpublished(&lease, "bootstrap".into(), true).unwrap();
    peer.root.install_debt_ledger(ledger.clone()).unwrap();
    let view = peer.root.owner_view(ledger.clone()).unwrap();
    let create = json!({"disposeOnDetach":true});
    let reservation = view
        .reserve_tracked_command("Target.createBrowserContext", Some(&create), None)
        .unwrap();
    rejected(view.send_reserved_command(
        "Runtime.evaluate",
        Some(json!({"expression":"must_not_run()"})),
        None,
        reservation,
    ))
    .await;
    assert_eq!(ledger.snapshot().outstanding_commands, 0);
    assert_eq!(ledger.bound_context(), None);
    peer.finish(&[]).await;
}

#[tokio::test]
async fn acquisition_ack_binds_context_target_and_session_before_continuation() {
    let mut peer = OwnerPeer::connect().await;
    let (_cancel, lease) = operation(1, Instant::now() + Duration::from_secs(30));
    let ledger = OwnerDebtLedger::unpublished(&lease, "bootstrap".into(), true).unwrap();
    peer.root.install_debt_ledger(ledger.clone()).unwrap();
    let view = peer.root.owner_view(ledger.clone()).unwrap();
    let create = json!({"disposeOnDetach":true});
    let (created, ()) = tokio::time::timeout(TEST_BOUND, async {
        tokio::join!(
            async {
                let result = view
                    .send_command("Target.createBrowserContext", Some(create), None)
                    .await
                    .unwrap();
                // No intervening await: reader-owned acquisition precedes delivery.
                assert_eq!(ledger.bound_context().as_deref(), Some("exact-context"));
                result
            },
            async {
                let request = peer.request("Target.createBrowserContext").await;
                assert_eq!(ledger.bound_context(), None);
                peer.acknowledge(&request, json!({"browserContextId":"exact-context"}));
            }
        )
    })
    .await
    .expect("create ACK did not reach its waiter");
    assert_eq!(created["browserContextId"], "exact-context");
    assert!(ledger.bind_context("different-context").is_err());
    rejected(view.send_command(
        "Target.createTarget",
        Some(json!({"url":"about:blank","browserContextId":"wrong-context"})),
        None,
    ))
    .await;
    peer.exchange(
        &view,
        "Target.createTarget",
        Some(json!({"url":"about:blank","browserContextId":"exact-context"})),
        None,
        json!({"targetId":"exact-target"}),
    )
    .await;
    rejected(view.send_command(
        "Target.attachToTarget",
        Some(json!({"targetId":"unknown-target","flatten":true})),
        None,
    ))
    .await;
    peer.exchange(
        &view,
        "Target.attachToTarget",
        Some(json!({"targetId":"exact-target","flatten":true})),
        None,
        json!({"sessionId":"exact-session"}),
    )
    .await;
    assert!(ledger
        .bind_session("exact-context", "different-target", "exact-session")
        .is_err());
    assert!(ledger
        .bind_session("wrong-context", "exact-target", "exact-session")
        .is_err());
    ledger
        .bind_session("exact-context", "exact-target", "exact-session")
        .unwrap();
    ledger.publish_initialization(|| Ok(())).unwrap();
    peer.finish(&[
        "Target.createBrowserContext",
        "Target.createTarget",
        "Target.attachToTarget",
    ])
    .await;
}

#[tokio::test]
async fn unpublished_application_commands_are_denied_even_with_category_overrides() {
    let peer = OwnerPeer::connect().await;
    let (_cancel, lease) = operation(1, Instant::now() + Duration::from_secs(30));
    let ledger = OwnerDebtLedger::unpublished(&lease, "unpublished".into(), true).unwrap();
    ledger.bind_context("context").unwrap();
    ledger.bind_session("context", "target", "session").unwrap();
    peer.root.install_debt_ledger(ledger.clone()).unwrap();
    let view = peer.root.owner_view(ledger.clone()).unwrap();
    for (method, params) in [
        ("Input.insertText", json!({"text":"must-not-be-typed"})),
        (
            "Runtime.evaluate",
            json!({"expression":"must_not_run()","returnByValue":true}),
        ),
    ] {
        rejected(view.send_command_no_wait(method, Some(params.clone()), Some("session"))).await;
        for category in [
            CommandCategory::Enrollment,
            CommandCategory::CleanupOther,
            CommandCategory::Destroy,
        ] {
            rejected(command_scope(
                category,
                false,
                view.send_command_no_wait(method, Some(params.clone()), Some("session")),
            ))
            .await;
        }
    }
    assert_eq!(ledger.snapshot().outstanding_commands, 0);
    peer.finish(&[]).await;
}

#[tokio::test]
async fn cancellation_while_waiting_for_writer_prevents_first_context_submission() {
    let peer = OwnerPeer::connect().await;
    let (cancel, lease) = operation(1, Instant::now() + Duration::from_secs(30));
    let ledger = OwnerDebtLedger::unpublished(&lease, "cancel-before-create".into(), true).unwrap();
    peer.root.install_debt_ledger(ledger.clone()).unwrap();
    let view = peer.root.owner_view(ledger.clone()).unwrap();
    let writer = peer.root.transport.ws_tx.lock().await;
    let mut create = Box::pin(view.send_command(
        "Target.createBrowserContext",
        Some(json!({"disposeOnDetach":true})),
        None,
    ));
    assert!(futures_util::poll!(create.as_mut()).is_pending());
    assert_eq!(ledger.snapshot().outstanding_commands, 1);
    cancel.send_replace(CancelSignal::Requested);
    drop(writer);
    rejected(create).await;
    assert_eq!(ledger.snapshot().outstanding_commands, 0);
    assert_eq!(ledger.bound_context(), None);
    assert!(OwnerDebtLedger::unpublished(&lease, "cancelled-create-owner".into(), true).is_err());
    peer.finish(&[]).await;
}

#[tokio::test]
async fn cancellation_revokes_reserved_bootstrap_continuations_but_not_exact_context_cleanup() {
    let mut peer = OwnerPeer::connect().await;
    let (cancel, lease) = operation(1, Instant::now() + Duration::from_secs(30));
    let ledger = OwnerDebtLedger::unpublished(&lease, "cancelled-bootstrap".into(), true).unwrap();
    ledger.bind_context("acquired-context").unwrap();
    peer.root.install_debt_ledger(ledger.clone()).unwrap();
    let view = peer.root.owner_view(ledger.clone()).unwrap();
    let params = json!({"url":"about:blank","browserContextId":"acquired-context"});
    let reserved = view
        .reserve_tracked_command("Target.createTarget", Some(&params), None)
        .unwrap();
    cancel.send_replace(CancelSignal::Requested);
    assert!(OwnerDebtLedger::unpublished(&lease, "new-cancelled-owner".into(), true).is_err());
    rejected(view.send_reserved_command(
        "Target.createTarget",
        Some(params.clone()),
        None,
        reserved,
    ))
    .await;
    rejected(view.send_command("Target.createTarget", Some(params), None)).await;
    let committed = AtomicBool::new(false);
    assert!(ledger
        .publish_initialization(|| {
            committed.store(true, Ordering::SeqCst);
            Ok(())
        })
        .is_err());
    assert!(!committed.load(Ordering::SeqCst));
    rejected(view.send_command(
        "Target.disposeBrowserContext",
        Some(json!({"browserContextId":"unrelated-context"})),
        None,
    ))
    .await;
    peer.exchange(
        &view,
        "Target.disposeBrowserContext",
        Some(json!({"browserContextId":"acquired-context"})),
        None,
        json!({}),
    )
    .await;
    peer.finish(&["Target.disposeBrowserContext"]).await;
}

#[tokio::test]
async fn expired_create_ack_is_bound_without_reviving_initialization_or_blocking_cleanup() {
    let mut peer = OwnerPeer::connect().await;
    let (_expired_cancel, expired) = operation(1, Instant::now() - Duration::from_secs(1));
    assert!(OwnerDebtLedger::unpublished(&expired, "already-expired".into(), true).is_err());
    let (_cancel, lease) = operation(1, Instant::now() + Duration::from_secs(1));
    let ledger = OwnerDebtLedger::unpublished(&lease, "expiring-bootstrap".into(), true).unwrap();
    peer.root.install_debt_ledger(ledger.clone()).unwrap();
    let view = peer.root.owner_view(ledger.clone()).unwrap();
    let mut events = view.subscribe();
    let mut create = Box::pin(view.send_command(
        "Target.createBrowserContext",
        Some(json!({"disposeOnDetach":true})),
        None,
    ));
    let request = tokio::select! {
        request = peer.request("Target.createBrowserContext") => request,
        result = create.as_mut() => panic!("create completed before its held ACK: {result:?}"),
    };
    // The held ACK forces the actual application timeout, rather than using a
    // sleep or guessing when the command reached the reader.
    let result = tokio::time::timeout(TEST_BOUND, create).await.unwrap();
    assert!(result.is_err());
    assert!(Instant::now() >= lease.deadline);
    assert_eq!(ledger.bound_context(), None);
    assert_eq!(ledger.snapshot().outstanding_commands, 1);
    peer.acknowledge(&request, json!({"browserContextId":"late-context"}));
    peer.event(
        &mut events,
        json!({"method":"Target.targetInfoChanged","params":{"targetInfo":{"targetId":"barrier"}}}),
    )
    .await;
    assert_eq!(ledger.bound_context().as_deref(), Some("late-context"));
    assert_eq!(ledger.snapshot().outstanding_commands, 0);
    rejected(view.send_command(
        "Target.createTarget",
        Some(json!({"url":"about:blank","browserContextId":"late-context"})),
        None,
    ))
    .await;
    assert!(ledger.publish_initialization(|| Ok(())).is_err());
    assert_eq!(
        ledger.initialization_deadline("Target.disposeBrowserContext"),
        None
    );
    rejected(view.send_command(
        "Target.disposeBrowserContext",
        Some(json!({"browserContextId":"other-context"})),
        None,
    ))
    .await;
    peer.exchange(
        &view,
        "Target.disposeBrowserContext",
        Some(json!({"browserContextId":"late-context"})),
        None,
        json!({}),
    )
    .await;
    retire_owner(&mut peer, &ledger, "late-context").await;
    peer.finish(&[
        "Target.createBrowserContext",
        "Target.disposeBrowserContext",
        "Target.setAutoAttach",
    ])
    .await;
}

#[tokio::test]
async fn retired_session_events_do_not_populate_or_discharge_replacement_realms() {
    let mut peer = OwnerPeer::connect().await;
    let old = OwnerDebtLedger::new(1, "old-event-owner".into());
    old.bind_context("old-context").unwrap();
    old.bind_session("old-context", "old-target", "old-session")
        .unwrap();
    peer.root.install_debt_ledger(old.clone()).unwrap();
    retire_owner(&mut peer, &old, "old-context").await;
    let (_cancel, lease) = operation(2, Instant::now() + Duration::from_secs(30));
    let new = OwnerDebtLedger::unpublished(&lease, "new-event-owner".into(), true).unwrap();
    new.bind_context("new-context").unwrap();
    new.bind_session("new-context", "new-target", "new-session")
        .unwrap();
    new.publish_initialization(|| Ok(())).unwrap();
    peer.root.install_debt_ledger(new.clone()).unwrap();
    let view = peer.root.owner_view(new.clone()).unwrap();
    let mut events = view.subscribe();
    let baseline = new.snapshot().descriptor_bytes;
    peer.event(&mut events, json!({"method":"Runtime.executionContextCreated","sessionId":"old-session","params":{"context":{"id":7}}})).await;
    assert_eq!(
        new.snapshot().descriptor_bytes,
        baseline,
        "old-session metadata entered the replacement ledger"
    );
    assert!(!new.snapshot().integrity_lost);
    peer.event(&mut events, json!({"method":"Runtime.executionContextCreated","sessionId":"new-session","params":{"context":{"id":7}}})).await;
    assert!(new.snapshot().descriptor_bytes > baseline);

    let journal = new
        .operation(
            OperationKey {
                generation: 2,
                operation_seq: 2,
            },
            "new-target".into(),
            "new-session".into(),
        )
        .unwrap();
    let params = json!({"backendNodeId":1,"executionContextId":7});
    let (result, ()) = tokio::time::timeout(TEST_BOUND, async {
        tokio::join!(
            journal.scope(view.send_command("DOM.resolveNode", Some(params), Some("new-session"))),
            async {
                let request = peer.request("DOM.resolveNode").await;
                peer.acknowledge(&request, json!({"object":{"objectId":"new-object"}}));
            }
        )
    })
    .await
    .expect("object acquisition ACK did not reach its waiter");
    result.unwrap();
    assert_eq!(new.snapshot().object_debt, 1);
    for (session, context) in [("old-session", 7), ("new-session", 8)] {
        peer.event(&mut events, json!({"method":"Runtime.executionContextDestroyed","sessionId":session,"params":{"executionContextId":context}})).await;
        assert_eq!(
            new.snapshot().object_debt,
            1,
            "an inexact realm event discharged a live object"
        );
    }
    peer.event(&mut events, json!({"method":"Runtime.executionContextDestroyed","sessionId":"new-session","params":{"executionContextId":7}})).await;
    assert_eq!(new.snapshot().object_debt, 0);
    assert!(!new.snapshot().integrity_lost);
    peer.finish(&["Target.setAutoAttach", "DOM.resolveNode"])
        .await;
}

#[tokio::test]
async fn unpublished_known_session_can_read_its_own_target_info_without_target_parameter() {
    let mut peer = OwnerPeer::connect().await;
    let (_cancel, lease) = operation(1, Instant::now() + Duration::from_secs(30));
    let ledger = OwnerDebtLedger::unpublished(&lease, "session-target-info".into(), true).unwrap();
    ledger.bind_context("context").unwrap();
    ledger.bind_session("context", "target", "session").unwrap();
    peer.root.install_debt_ledger(ledger.clone()).unwrap();
    let view = peer.root.owner_view(ledger.clone()).unwrap();
    rejected(view.send_command("Target.getTargetInfo", Some(json!({})), None)).await;
    rejected(view.send_command(
        "Target.getTargetInfo",
        Some(json!({})),
        Some("unknown-session"),
    ))
    .await;
    let result = peer
        .exchange(
            &view,
            "Target.getTargetInfo",
            Some(json!({})),
            Some("session"),
            json!({"targetInfo":{"targetId":"target","browserContextId":"context"}}),
        )
        .await;
    assert_eq!(result["targetInfo"]["targetId"], "target");
    assert_eq!(ledger.snapshot().outstanding_commands, 0);
    assert!(!ledger.snapshot().integrity_lost);
    peer.finish(&["Target.getTargetInfo"]).await;
}

#[tokio::test]
async fn late_recording_attach_ack_retains_exact_session_without_reviving_cancelled_work() {
    let mut peer = OwnerPeer::connect().await;
    let (cancel, lease) = operation(1, Instant::now() + Duration::from_secs(30));
    let ledger =
        OwnerDebtLedger::unpublished(&lease, "cancelled-recording-attach".into(), true).unwrap();
    ledger.bind_context("recording-context").unwrap();
    ledger
        .bind_session("recording-context", "recording-target", "control-session")
        .unwrap();
    peer.root.install_debt_ledger(ledger.clone()).unwrap();
    let view = peer.root.owner_view(ledger.clone()).unwrap();
    ledger
        .initialization_work(InitializationWork::Recording, &lease, async {
            ledger.register_recording_target("recording-target")
        })
        .await
        .unwrap()
        .unwrap();
    let mut events = view.subscribe();
    let mut attach = Box::pin(ledger.initialization_work(
        InitializationWork::Recording,
        &lease,
        view.send_command(
            "Target.attachToTarget",
            Some(json!({"targetId":"recording-target","flatten":true})),
            None,
        ),
    ));
    let request = tokio::select! {
        request = peer.request("Target.attachToTarget") => request,
        result = attach.as_mut() => panic!("recording attach completed before its held ACK: {result:?}"),
    };
    assert_eq!(
        request["params"],
        json!({"targetId":"recording-target","flatten":true})
    );
    assert_eq!(ledger.snapshot().outstanding_commands, 1);
    cancel.send_replace(CancelSignal::Requested);
    let result = tokio::time::timeout(TEST_BOUND, attach).await.unwrap();
    assert!(
        matches!(result, Ok(Err(_)) | Err(_)),
        "cancelled attach retained an application waiter"
    );
    assert_eq!(
        ledger.snapshot().outstanding_commands,
        1,
        "dropping the waiter must not erase submitted attach debt"
    );
    assert!(peer.root.transport.pending.lock().await.is_empty());

    peer.acknowledge(&request, json!({"sessionId":"late-recording-session"}));
    peer.event(&mut events, json!({"method":"Target.targetInfoChanged","params":{"targetInfo":{"targetId":"ack-barrier"}}})).await;
    assert_eq!(ledger.snapshot().outstanding_commands, 0);
    assert!(
        ledger
            .bind_session(
                "recording-context",
                "wrong-target",
                "late-recording-session"
            )
            .is_err(),
        "reader failed to retain the exact late recording session"
    );
    ledger
        .bind_session(
            "recording-context",
            "recording-target",
            "late-recording-session",
        )
        .unwrap();
    rejected(view.send_command(
        "Page.startScreencast",
        Some(json!({"format":"jpeg"})),
        Some("late-recording-session"),
    ))
    .await;
    rejected(view.send_command("Runtime.enable", None, Some("late-recording-session"))).await;
    assert!(ledger
        .initialization_work(InitializationWork::Recording, &lease, async {})
        .await
        .is_err());
    assert!(ledger.publish_initialization(|| Ok(())).is_err());
    assert!(!ledger.snapshot().integrity_lost);
    assert!(
        !ledger.replacement_ready(),
        "an attach ACK retains ownership; it is not detach or context-destruction proof"
    );
    // No detach or destruction has been acknowledged. The exact session stays
    // owned for cleanup; this test deliberately makes no reaped/clean claim.
    peer.finish(&["Target.attachToTarget"]).await;
}

#[tokio::test]
async fn borrowed_owner_rejects_context_ownership_and_cleanup_uses_only_its_exact_budget() {
    let mut peer = OwnerPeer::connect().await;
    let (cancel, lease) = operation(1, Instant::now() + Duration::from_secs(1));
    let ledger = OwnerDebtLedger::unpublished(&lease, "borrowed-context".into(), false).unwrap();
    peer.root.install_debt_ledger(ledger.clone()).unwrap();
    let view = peer.root.owner_view(ledger.clone()).unwrap();
    rejected(view.send_command(
        "Target.createBrowserContext",
        Some(json!({"disposeOnDetach":true})),
        None,
    ))
    .await;
    ledger.bind_context("external-context").unwrap();
    ledger
        .bind_session("external-context", "external-target", "borrowed-session")
        .unwrap();
    rejected(view.send_command(
        "Target.disposeBrowserContext",
        Some(json!({"browserContextId":"external-context"})),
        None,
    ))
    .await;

    // A real initialization waiter, not a sleep, establishes the original
    // application deadline while the independently owned cleanup remains usable.
    let mut events = view.subscribe();
    let mut info = Box::pin(view.send_command(
        "Target.getTargetInfo",
        Some(json!({})),
        Some("borrowed-session"),
    ));
    let request = tokio::select! {
        request = peer.request("Target.getTargetInfo") => request,
        result = info.as_mut() => panic!("target info completed before its held ACK: {result:?}"),
    };
    assert!(tokio::time::timeout(TEST_BOUND, info)
        .await
        .unwrap()
        .is_err());
    assert!(Instant::now() >= lease.deadline);
    cancel.send_replace(CancelSignal::Requested);
    assert_eq!(ledger.snapshot().outstanding_commands, 1);
    peer.acknowledge(
        &request,
        json!({"targetInfo":{"targetId":"external-target","browserContextId":"external-context"}}),
    );
    peer.event(&mut events, json!({"method":"Target.targetInfoChanged","params":{"targetInfo":{"targetId":"info-ack-barrier"}}})).await;
    assert_eq!(ledger.snapshot().outstanding_commands, 0);

    rejected(view.send_command_no_wait(
        "Runtime.runIfWaitingForDebugger",
        Some(json!({})),
        Some("borrowed-session"),
    ))
    .await;
    for category in [
        CommandCategory::CleanupOther,
        CommandCategory::Destroy,
        CommandCategory::Enrollment,
    ] {
        rejected(command_scope(
            category,
            false,
            view.send_command_no_wait(
                "Runtime.runIfWaitingForDebugger",
                Some(json!({})),
                Some("borrowed-session"),
            ),
        ))
        .await;
    }
    for launder_method in ["Runtime.runIfWaitingForDebugger", "Runtime.evaluate"] {
        let (method, params, session) = ScopeCleanupCommand::ResumeDebugger {
            session: "borrowed-session".into(),
        }
        .envelope()
        .unwrap();
        let reservation = ledger
            .reserve_scope_cleanup(
                method,
                &params,
                session.as_deref(),
                Instant::now() + TEST_BOUND,
            )
            .unwrap();
        let supplied_params = if launder_method == method {
            params
        } else {
            json!({"expression":"must_not_run()"})
        };
        rejected(view.send_reserved_command(
            launder_method,
            Some(supplied_params),
            session.as_deref(),
            Some(reservation),
        ))
        .await;
    }
    assert_eq!(ledger.snapshot().outstanding_commands, 0);
    rejected(peer.root.send_scope_cleanup(
        ScopeCleanupCommand::ResumeDebugger {
            session: "borrowed-session".into(),
        },
        Instant::now() + TEST_BOUND,
    ))
    .await;

    let (result, ()) = tokio::join!(
        view.send_scope_cleanup(
            ScopeCleanupCommand::ResumeDebugger {
                session: "borrowed-session".into()
            },
            Instant::now() + TEST_BOUND,
        ),
        async {
            let request = peer.request("Runtime.runIfWaitingForDebugger").await;
            assert_eq!(request["sessionId"], "borrowed-session");
            assert_eq!(request["params"], json!({}));
            peer.acknowledge(&request, json!({}));
        }
    );
    result.unwrap();

    let cleanup_deadline = Instant::now() + Duration::from_secs(1);
    let mut disable = Box::pin(view.send_scope_cleanup(
        ScopeCleanupCommand::DisableNetwork {
            session: "borrowed-session".into(),
        },
        cleanup_deadline,
    ));
    let request = tokio::select! {
        request = peer.request("Network.disable") => request,
        result = disable.as_mut() => panic!("network cleanup completed before its held ACK: {result:?}"),
    };
    assert_eq!(request["sessionId"], "borrowed-session");
    assert_eq!(request["params"], json!({}));
    assert!(tokio::time::timeout(TEST_BOUND, disable)
        .await
        .unwrap()
        .is_err());
    assert!(Instant::now() >= cleanup_deadline);
    assert_eq!(
        ledger.snapshot().outstanding_commands,
        1,
        "cleanup timeout is retained remote debt, not reaping proof"
    );
    rejected(view.send_scope_cleanup(
        ScopeCleanupCommand::DisableNetwork {
            session: "borrowed-session".into(),
        },
        cleanup_deadline,
    ))
    .await;
    assert_eq!(ledger.snapshot().outstanding_commands, 1);
    peer.acknowledge(&request, json!({}));
    peer.event(&mut events, json!({"method":"Target.targetInfoChanged","params":{"targetInfo":{"targetId":"cleanup-ack-barrier"}}})).await;
    assert_eq!(ledger.snapshot().outstanding_commands, 0);
    assert_eq!(ledger.bound_context().as_deref(), Some("external-context"));
    assert!(!ledger.snapshot().integrity_lost);
    assert!(ledger.publish_initialization(|| Ok(())).is_err());
    assert!(
        !ledger.replacement_ready(),
        "ACKing individual obligations does not prove the borrowed context was destroyed"
    );
    peer.finish(&[
        "Target.getTargetInfo",
        "Runtime.runIfWaitingForDebugger",
        "Network.disable",
    ])
    .await;
}
