//! Safe resource-ownership portion of legacy capture obligation #5 only.
//! Legacy contentFrame() returned a frame value (null in its fixture), not a
//! newly acquired element. Native enumeration instead resolves an owner object
//! before the semantic lease exists, under the unchanged 80 ms parent deadline.
//! Its late owner must be reclaimed, but no 60 ms successful fallback is claimed.
//! Cleanup can outlive the business deadline. An exact, accounted object-release
//! debt is not an input debt or lost integrity: retained does not mean settled.
use super::*;
use crate::native::client_browser::settle_observation_dispatch;
use crate::native::client_debt::{AdmissionClass, OperationKey, OwnerDebtLedger};
use crate::native::client_protocol::Effects;
use futures_util::SinkExt;

#[tokio::test]
async fn frame_owner_deadline_owns_and_releases_late_handle_without_continuation() {
    frame_owner_deadline(false).await;
}

#[tokio::test]
async fn frame_owner_deadline_retains_unacknowledged_release_debt_until_exact_late_ack() {
    frame_owner_deadline(true).await;
}

async fn fence(client: &CdpClient) {
    tokio::time::timeout(
        Duration::from_secs(1),
        client.send_command("Browser.getVersion", None, None),
    )
    .await
    .expect("transport fence must finish")
    .unwrap();
}

async fn frame_owner_deadline(withhold_release_ack: bool) {
    const OBJECT: &str = "late-exact-frame-owner";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let commands = Arc::new(Mutex::new(Vec::<Value>::new()));
    let log = commands.clone();
    let (reached_tx, reached) = oneshot::channel();
    let (release_owner, mut owner_resume) = oneshot::channel();
    let (release_started_tx, release_started) = oneshot::channel();
    let (release_cleanup, mut cleanup_resume) = oneshot::channel();
    let (cleanup_acked_tx, cleanup_acked) = oneshot::channel();
    let (stop, mut stopping) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut reached_tx = Some(reached_tx);
        let mut release_started_tx = Some(release_started_tx);
        let mut cleanup_acked_tx = Some(cleanup_acked_tx);
        let mut owner_response = None::<Value>;
        let mut cleanup_response = None::<Value>;
        let mut owner_requested = false;
        let mut owner_acked_at = None;
        let mut cleanup_requested = false;
        loop {
            let message = tokio::select! {
                _ = &mut stopping => break,
                result = &mut owner_resume, if owner_response.is_some() => {
                    result.unwrap();
                    assert!(!cleanup_requested);
                    let reply = owner_response.take().unwrap();
                    socket.send(tokio_tungstenite::tungstenite::Message::Text(reply.to_string())).await.unwrap();
                    owner_acked_at = Some(Instant::now());
                    continue;
                }
                result = &mut cleanup_resume, if cleanup_response.is_some() => {
                    result.unwrap();
                    let reply = cleanup_response.take().unwrap();
                    socket.send(tokio_tungstenite::tungstenite::Message::Text(reply.to_string())).await.unwrap();
                    cleanup_acked_tx.take().unwrap().send(()).unwrap();
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
            if owner_requested {
                assert_eq!(method, "Runtime.releaseObject", "late owner must not resume geometry, frame enumeration, metadata or screenshot");
            }
            let result = match method {
                "Page.getFrameTree" => json!({"frameTree":{
                    "frame":{"id":"frame","loaderId":"loader","url":"https://fixture.invalid/"},
                    "childFrames":[
                        {"frame":{"id":"child","parentId":"frame","loaderId":"child-loader","url":"https://fixture.invalid/child"}},
                        {"frame":{"id":"unvisited","parentId":"frame","loaderId":"unvisited-loader","url":"https://fixture.invalid/unvisited"}}
                    ]
                }}),
                "Page.createIsolatedWorld" => {
                    assert_eq!(
                        request["params"]["worldName"],
                        "agent-browser-native-observation"
                    );
                    match request["params"]["frameId"].as_str().unwrap() {
                        "frame" => json!({"executionContextId":1}),
                        "child" => json!({"executionContextId":2}),
                        other => panic!("deadline must stop before the next frame: {other}"),
                    }
                }
                "DOM.getFrameOwner" => {
                    assert_eq!(request["params"], json!({"frameId":"child"}));
                    json!({"backendNodeId":42})
                }
                "DOM.resolveNode" => {
                    assert_eq!(
                        request["params"],
                        json!({"backendNodeId":42,"executionContextId":1,"objectGroup":"native-frame-enumeration"})
                    );
                    assert!(!owner_requested);
                    owner_requested = true;
                    assert!(owner_response.replace(json!({"id":request["id"],"sessionId":"session","result":{"object":{"type":"object","subtype":"node","objectId":OBJECT}}})).is_none());
                    reached_tx.take().unwrap().send(()).unwrap();
                    continue;
                }
                "Runtime.releaseObject" => {
                    assert!(
                        owner_acked_at.is_some(),
                        "cleanup must own the actual late object reply"
                    );
                    assert!(!cleanup_requested, "exact owner must be released only once");
                    assert_eq!(request["params"], json!({"objectId":OBJECT}));
                    cleanup_requested = true;
                    assert!(cleanup_response
                        .replace(json!({"id":request["id"],"sessionId":"session","result":{}}))
                        .is_none());
                    release_started_tx.take().unwrap().send(()).unwrap();
                    continue;
                }
                other => panic!("unexpected frame-owner deadline command: {other}"),
            };
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    json!({"id":request["id"],"sessionId":"session","result":result}).to_string(),
                ))
                .await
                .unwrap();
        }
        assert!(cleanup_requested);
        assert!(owner_response.is_none() && cleanup_response.is_none());
        owner_acked_at.unwrap()
    });
    let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
    let owner = Owner::new(client.clone(), "session", "target", "scope").await;
    let ledger = OwnerDebtLedger::new(1, "scope".into());
    client.install_debt_ledger(ledger.clone()).unwrap();
    let sequence = 8301;
    let journal = ledger
        .operation(
            OperationKey {
                generation: 1,
                operation_seq: sequence,
            },
            "target".into(),
            "session".into(),
        )
        .unwrap();
    let refs = Arc::new(Mutex::new(RefMap::new()));
    let dispatch = ObservationDispatch::new(refs.clone());
    let (mut operation, _cancel) = operation(sequence);
    operation.deadline = Instant::now() + Duration::from_millis(80);
    let deadline = operation.deadline;
    journal.bind_operation(&operation).unwrap();
    let mut task = journal
        .scope(async {
            dispatch.clone().start(
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
            )
        })
        .await;
    tokio::time::timeout_at(deadline.into(), reached)
        .await
        .expect("actual owner acquisition must start inside the original 80 ms budget")
        .unwrap();
    assert!(journal.has_accounted_object_creation("session"));
    assert_eq!(journal.snapshot().object_debt, 1);
    tokio::time::sleep_until(deadline.into()).await;
    assert!(matches!(
        task.result.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(refs.lock().unwrap().ref_ids().is_empty());
    release_owner.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), release_started)
        .await
        .expect("late owner must reach its exact release, not disappear with the deadline")
        .unwrap();
    // The real transport ledger records the returned object before delivering
    // its waiter. It now owns a concrete object and its outstanding cleanup,
    // not merely the peer's synthetic bookkeeping or an anonymous creation slot.
    assert!(!journal.has_accounted_object_creation("session"));
    assert!(ledger.accounted_object_release("session", OBJECT));
    assert!(!ledger.accounted_object_release("other-session", OBJECT));
    assert!(!ledger.accounted_object_release("session", "other-object"));
    let pending = ledger.snapshot();
    assert_eq!(
        (
            pending.input_debt,
            pending.object_debt,
            pending.outstanding_commands
        ),
        (0, 1, 1)
    );
    assert!(!pending.integrity_lost);
    assert_eq!(journal.snapshot().object_debt, 1);
    assert!(matches!(
        task.result.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    let mut release_cleanup = Some(release_cleanup);
    if !withhold_release_ack {
        release_cleanup.take().unwrap().send(()).unwrap();
    }
    // Watchdog only, not an extended operation budget. The parent is already
    // expired; native acquisition/release settlement retains its existing bound.
    let (output, cleanup) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(task.result, task.join)
    })
    .await
    .expect("native retained ownership settlement must finish");
    let terminal = Instant::now();
    assert!(terminal >= deadline);
    eprintln!(
        "frame-owner-deadline: release_ack_withheld={withhold_release_ack}, terminal_after_parent_us={}",
        terminal.saturating_duration_since(deadline).as_micros()
    );
    assert!(matches!(&cleanup, Ok(Ok(()))));
    let (settled, dirty) = settle_observation_dispatch(output, cleanup);
    assert_eq!(settled.result, Err(ProtocolError::DeadlineExceeded));
    assert_eq!(settled.effects, Effects::NotDispatched);
    assert!(
        !dirty,
        "accounted release debt is not untracked cleanup uncertainty"
    );
    assert!(owner.targets.inventory().is_ok());
    assert!(refs.lock().unwrap().ref_ids().is_empty());
    {
        let publication = dispatch.publication.lock().await;
        assert_eq!(
            (
                publication.published_revision,
                publication.observed_revision
            ),
            (0, 0)
        );
    }
    let retained = ledger.snapshot();
    let outstanding = u32::from(withhold_release_ack);
    assert_eq!(
        (
            retained.input_debt,
            retained.object_debt,
            retained.outstanding_commands
        ),
        (0, outstanding, outstanding)
    );
    assert!(!retained.integrity_lost);
    assert_eq!(journal.snapshot().object_debt, outstanding);
    assert_eq!(
        ledger.accounted_object_release("session", OBJECT),
        withhold_release_ack
    );
    // Existing admission allows bounded object-only debt below its capacity
    // limit. Input debt and lost integrity are different, blocking contracts.
    assert_eq!(ledger.check_admission(AdmissionClass::Reference), Ok(()));
    let next_journal = ledger
        .operation(
            OperationKey {
                generation: 1,
                operation_seq: sequence + 1,
            },
            "target".into(),
            "session".into(),
        )
        .unwrap();
    assert_eq!(next_journal.snapshot().object_debt, 0);
    assert_eq!(
        journal.snapshot().object_debt,
        outstanding,
        "a new operation must not clear the exact old owner's debt"
    );
    assert_eq!(ledger.snapshot().object_debt, outstanding);
    let terminal_commands = commands.lock().unwrap().clone();
    if withhold_release_ack {
        release_cleanup.take().unwrap().send(()).unwrap();
    }
    tokio::time::timeout(Duration::from_secs(1), cleanup_acked)
        .await
        .unwrap()
        .unwrap();
    // The operation journal scope has ended. Bind this harness-only fence to
    // the exact owner without reviving the retired operation's authority.
    let fence_client = client.owner_view(ledger.clone()).unwrap();
    fence(&fence_client).await;
    let cleared = ledger.snapshot();
    assert_eq!(
        (
            cleared.input_debt,
            cleared.object_debt,
            cleared.outstanding_commands
        ),
        (0, 0, 0)
    );
    assert!(!cleared.integrity_lost);
    assert_eq!(journal.snapshot().object_debt, 0);
    assert_eq!(next_journal.snapshot().object_debt, 0);
    assert!(!ledger.accounted_object_release("session", OBJECT));
    assert_eq!(
        *commands.lock().unwrap(),
        terminal_commands,
        "late cleanup ACK must not resume enumeration, geometry, screenshot or duplicate release"
    );
    assert!(refs.lock().unwrap().ref_ids().is_empty());
    {
        let publication = dispatch.publication.lock().await;
        assert_eq!(
            (
                publication.published_revision,
                publication.observed_revision
            ),
            (0, 0)
        );
    }
    assert_eq!(client.pending_len().await, 0);
    assert!(owner.targets.inventory().is_ok());
    owner.blobs.check_budget_integrity().unwrap();
    let log = commands.lock().unwrap();
    assert_eq!(
        log.iter()
            .map(|r| r["method"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "Page.getFrameTree",
            "Page.getFrameTree",
            "Page.createIsolatedWorld",
            "Page.createIsolatedWorld",
            "DOM.getFrameOwner",
            "Page.createIsolatedWorld",
            "DOM.resolveNode",
            "Runtime.releaseObject",
        ]
    );
    drop(log);
    stop.send(()).unwrap();
    assert!(
        server.await.unwrap() >= deadline,
        "the actual owner reply must be late, not an injected error or supersession"
    );
}
