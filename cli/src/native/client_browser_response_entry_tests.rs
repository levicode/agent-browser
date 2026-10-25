//! Full framed page.evaluate admission alongside a real response subscription.
//! A finite CDP peer models the original public evaluation envelope and network
//! events; it does not execute JavaScript or establish the historical E2E cause.
use super::*;
use tokio::sync::mpsc;

fn evaluation() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/response-evaluate-entry.json"
    ))
    .unwrap()
}
fn expression() -> String {
    let a = evaluation();
    format!("(async()=>{{const value=await ({} )({}); return {{value:value===undefined?null:value}};}})()",
        a["source"].as_str().unwrap(), serde_json::to_string(&a["argument"]).unwrap())
}
fn request_event(id: &str, url: &str) -> Value {
    json!({"method":"Network.requestWillBeSent","sessionId":"session-1","params":{
        "requestId":id,"loaderId":"followup-loader","documentURL":"https://synthetic.test/",
        "request":{"url":url,"method":"GET","headers":{},"initialPriority":"Low","referrerPolicy":"strict-origin-when-cross-origin"},
        "timestamp":1.0,"wallTime":1.0,"redirectHasExtraInfo":false,"initiator":{"type":"other"},"type":"Fetch","frameId":"frame-session-1","hasUserGesture":false}})
}
fn response_event(id: &str, url: &str) -> Value {
    json!({"method":"Network.responseReceived","sessionId":"session-1","params":{
        "requestId":id,"loaderId":"followup-loader","timestamp":2.0,"type":"Fetch","hasExtraInfo":false,
        "response":{"url":url,"status":200,"statusText":"OK","headers":{"content-type":"application/json"},
            "mimeType":"application/json","charset":"utf-8","connectionReused":true,"connectionId":1,"encodedDataLength":11,"securityState":"secure"}}})
}
fn finish_event(id: &str) -> Value {
    json!({"method":"Network.loadingFinished","sessionId":"session-1","params":{
        "requestId":id,"timestamp":3.0,"encodedDataLength":11}})
}

// Only these two exact value-returning commands are handled locally. Everything
// else passes unchanged to the existing finite startup/navigation/cleanup peer.
async fn response_peer() -> (
    String,
    mpsc::Sender<Value>,
    Arc<Mutex<Vec<Value>>>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let (backend, _, backend_task) = peer(false).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let (emit, mut events) = mpsc::channel::<Value>(8);
    let commands = Arc::new(Mutex::new(Vec::new()));
    let log = commands.clone();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let (mut backend, _) = tokio_tungstenite::connect_async(backend).await.unwrap();
        loop {
            tokio::select! {
                event = events.recv() => {
                    let Some(event) = event else { break; };
                    if socket.send(Message::Text(event.to_string())).await.is_err() { break; }
                }
                message = backend.next() => {
                    let Some(Ok(message)) = message else { break; };
                    if socket.send(message).await.is_err() { break; }
                }
                message = socket.next() => {
                    let Some(Ok(Message::Text(text))) = message else { break; };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    log.lock().unwrap().push(request.clone());
                    let result = match request["method"].as_str().unwrap() {
                        "Runtime.evaluate" if request["params"]["expression"] == expression() => {
                            assert_eq!(request["sessionId"], "session-1");
                            assert_eq!(request["params"]["awaitPromise"], true);
                            assert_eq!(request["params"]["returnByValue"], true);
                            assert_eq!(request["params"]["userGesture"], true);
                            Some(json!({"result":{"type":"object","value":{"value":{"ok":true,"value":null}}}}))
                        }
                        "Runtime.evaluate" => {
                            assert_eq!(request["params"]["expression"], "location.href");
                            None
                        }
                        "Network.getResponseBody" => {
                            assert_eq!(request["sessionId"], "session-1");
                            assert_eq!(request["params"], json!({"requestId":"full-body"}));
                            Some(json!({"body":"{\"ok\":true}","base64Encoded":false}))
                        }
                        _ => None,
                    };
                    if let Some(result) = result {
                        let reply = json!({"id":request["id"],"sessionId":request["sessionId"],"result":result});
                        if socket.send(Message::Text(reply.to_string())).await.is_err() { break; }
                    } else if backend.send(Message::Text(text)).await.is_err() { break; }
                }
            }
        }
        let _ = backend.close(None).await;
    });
    (endpoint, emit, commands, task, backend_task)
}

async fn read_entry_frame(fixture: &mut FramedFixture) -> Value {
    for _ in 0..32 {
        let frame = tokio::time::timeout(Duration::from_secs(3), fixture.read())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame["generation"], 1);
        if frame["type"] == "event" {
            fixture.event_sequence += 1;
            assert_eq!(frame["sequence"], fixture.event_sequence);
            assert_eq!(
                frame["payload"]["identityScope"].as_str(),
                fixture.scope.as_deref()
            );
            if frame["event"] == "network.response" {
                return frame;
            }
            validate_fixture_notice(&frame).unwrap();
        } else {
            return frame;
        }
    }
    panic!("response entry event bound exceeded");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryCase {
    Applied,
    Pending,
    Deadline,
    Cancel,
    FutureIngress,
    Navigation,
    Realm,
    Detached,
}
impl EntryCase {
    fn expected_error(self) -> Option<&'static str> {
        match self {
            Self::Applied | Self::Pending => None,
            Self::Deadline => Some("deadline-exceeded"),
            Self::Cancel => Some("cancelled"),
            Self::FutureIngress | Self::Detached => Some("scope-unavailable"),
            Self::Navigation | Self::Realm => Some("stale-scope"),
        }
    }
}
async fn response_entry_case_inner(case: EntryCase) -> Value {
    let (endpoint, emit, log, peer, backend) = response_peer().await;
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture = framed(
        browser.clone(),
        broker.clone(),
        Arc::new(RestartFlush::default()),
    );
    fixture.ready().await.unwrap();
    let opened = fixture
        .command(
            "scope.open",
            fixture_scope_open("connect", Some(&endpoint)),
            5,
        )
        .await
        .unwrap();
    let scope = opened["identityScope"].as_str().unwrap().to_owned();
    fixture.scope = Some(scope.clone());
    fixture
        .command("scope.configure", fixture_configuration(&scope, None), 5)
        .await
        .unwrap();
    fixture
        .command("network.routes.replace", fixture_routes(&scope), 5)
        .await
        .unwrap();
    fixture.registry = 1;
    fixture
        .command(
            "page.navigate",
            json!({"identityScope":scope,"url":"https://synthetic.test/","waitUntil":"load"}),
            5,
        )
        .await
        .unwrap();
    let enrollment = browser
        .owner
        .lock()
        .await
        .as_ref()
        .unwrap()
        .runtime
        .as_ref()
        .unwrap()
        .enrollment
        .clone();
    let page = browser.page_lease(false).await.unwrap();
    let ledger = page.client.debt_ledger().unwrap();
    let revision = ledger
        .capture_eval_revision(&page.page_session_id, &page.target_id)
        .unwrap();
    let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
    let operation = OperationLease {
        is_callback: false,
        generation: 1,
        sequence: fixture.sequence,
        deadline: Instant::now() + Duration::from_secs(2),
        cancellation,
    };
    // An ordinary prior request started and received headers before subscribing.
    // Its completion may legally arrive after goto has returned. No missing
    // lifecycle event, fabricated watermark, or post-hoc ledger is installed.
    let before = enrollment.response_entry_state_for_test()["received"]
        .as_u64()
        .unwrap();
    emit.send(request_event(
        "prior-request",
        "https://synthetic.test/prior",
    ))
    .await
    .unwrap();
    emit.send(response_event(
        "prior-request",
        "https://synthetic.test/prior",
    ))
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while enrollment.response_entry_state_for_test()["received"]
            .as_u64()
            .unwrap()
            < before + 2
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    enrollment.response_entry_drain_for_test(&operation).await;
    let baseline = enrollment.response_entry_state_for_test();
    let schedule = enrollment.response_entry_schedule_for_test();
    emit.send(finish_event("prior-request")).await.unwrap();
    schedule.event_received().await;
    let paused = enrollment.response_entry_state_for_test();
    assert_eq!(
        paused["received"].as_u64().unwrap(),
        baseline["received"].as_u64().unwrap() + 1
    );
    assert_eq!(paused["applied"], baseline["applied"]);
    for key in [
        "epoch",
        "frames",
        "failure",
        "reconciled",
        "pending",
        "unresumed",
    ] {
        assert_eq!(paused[key], baseline[key], "changed {key}");
    }
    assert_eq!(paused["failure"], false);
    assert_eq!(paused["reconciled"], true);
    assert_eq!(paused["pending"], 0);
    assert_eq!(paused["unresumed"], 0);
    assert!(!ledger.snapshot().integrity_lost);
    assert_eq!(ledger.snapshot().input_debt, 0);
    assert_eq!(ledger.snapshot().outstanding_commands, 0);
    assert_eq!(
        ledger
            .capture_eval_revision(&page.page_session_id, &page.target_id)
            .unwrap(),
        revision
    );
    let release = if case == EntryCase::Pending {
        let schedule = schedule.clone();
        Some(tokio::spawn(async move {
            schedule.release_at_eval_entry().await;
        }))
    } else if case == EntryCase::Applied {
        schedule.release();
        enrollment.response_entry_drain_for_test(&operation).await;
        None
    } else {
        None
    };
    drop(page);
    let before_commands = log.lock().unwrap().len();
    // The public Promise.all branches send independent native requests. Keep
    // the subscription and evaluation in flight together, with the original
    // full-body case's 2000 ms step budget, rather than invoking a private gate.
    fixture.sequence += 1;
    let subscription_sequence = fixture.sequence;
    fixture.write(json!({"type":"request","id":"response-subscribe","generation":1,"operationSeq":subscription_sequence,
        "timeoutMs":2000,"command":"network.responses.subscribe","args":{"identityScope":scope}})).await.unwrap();
    fixture.sequence += 1;
    let evaluate_sequence = fixture.sequence;
    let mut args = evaluation();
    args["identityScope"] = scope.clone().into();
    fixture.write(json!({"type":"request","id":"response-evaluate","generation":1,"operationSeq":evaluate_sequence,
        "timeoutMs":2000,"command":"page.evaluate","args":args})).await.unwrap();
    let mut future_gate = None;
    if !matches!(case, EntryCase::Applied | EntryCase::Pending) {
        // On the current-thread runtime this notification is consumed only
        // after the real pre-UI wait has frozen its watermark and yielded.
        schedule.eval_entered().await;
        if case == EntryCase::Cancel {
            fixture
                .write(
                    json!({"type":"cancel","id":"cancel-response-evaluate","generation":1,
                "operationSeq":evaluate_sequence}),
                )
                .await
                .unwrap();
        }
        if matches!(
            case,
            EntryCase::FutureIngress
                | EntryCase::Navigation
                | EntryCase::Realm
                | EntryCase::Detached
        ) {
            // Keep this later event unapplied until the first operation has
            // refused. Reader-observed revocation itself must fence evaluation;
            // scheduling of the later supervisor cannot choose the error.
            future_gate = Some(enrollment.response_entry_schedule_for_test());
            let event = match case {
                EntryCase::FutureIngress => {
                    request_event("later-request", "https://synthetic.test/later")
                }
                EntryCase::Navigation => {
                    json!({"method":"Page.frameNavigated","sessionId":"session-1","params":{
                    "type":"Navigation","frame":{"id":"frame-session-1","loaderId":"next-loader","url":"https://synthetic.test/next",
                        "domainAndRegistry":"synthetic.test","securityOrigin":"https://synthetic.test","mimeType":"text/html",
                        "secureContextType":"Secure","crossOriginIsolatedContextType":"NotIsolated","gatedAPIFeatures":[]}}})
                }
                EntryCase::Realm => {
                    json!({"method":"Runtime.executionContextsCleared","sessionId":"session-1","params":{}})
                }
                EntryCase::Detached => {
                    json!({"method":"Target.detachedFromTarget","params":{"sessionId":"session-1","targetId":"page-1"}})
                }
                _ => unreachable!(),
            };
            let before = enrollment.response_entry_state_for_test()["received"]
                .as_u64()
                .unwrap();
            emit.send(event).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while enrollment.response_entry_state_for_test()["received"]
                    .as_u64()
                    .unwrap()
                    < before + 1
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            schedule.release();
            if let Some(gate) = &future_gate {
                gate.event_received().await;
            }
        }
    }
    let mut subscription = None;
    let mut evaluated = None;
    let mut cancel_ack = false;
    for _ in 0..3 {
        let frame = read_entry_frame(&mut fixture).await;
        if frame["type"] == "control-result" {
            assert_eq!(case, EntryCase::Cancel);
            assert_eq!(frame["id"], "cancel-response-evaluate");
            assert_eq!(frame["accepted"], true);
            assert_eq!(frame["scopeState"], "usable");
            assert!(!cancel_ack);
            cancel_ack = true;
        } else {
            assert_eq!(frame["type"], "result");
            assert_eq!(frame["scopeState"], "usable");
            if frame["id"] == "response-subscribe" {
                assert_eq!(frame["operationSeq"], subscription_sequence);
                assert_eq!(frame["ok"], true);
                assert_eq!(frame["effects"], "completed");
                assert!(subscription
                    .replace(frame["data"]["subscriptionId"].as_str().unwrap().to_owned())
                    .is_none());
            } else {
                assert_eq!(frame["id"], "response-evaluate");
                assert_eq!(frame["operationSeq"], evaluate_sequence);
                assert!(evaluated.replace(frame).is_none());
            }
        }
        if subscription.is_some()
            && evaluated.is_some()
            && (case != EntryCase::Cancel || cancel_ack)
        {
            break;
        }
    }
    assert_eq!(cancel_ack, case == EntryCase::Cancel);
    // A later received event stays unapplied until the original request has
    // already returned its exact refusal. Following the moving watermark would
    // time out here instead and cannot masquerade as this successful negative.
    if let Some(gate) = future_gate {
        gate.release();
    }
    if matches!(case, EntryCase::Deadline | EntryCase::Cancel) {
        schedule.release();
    }
    if let Some(release) = release {
        release.await.unwrap();
    }
    let evaluated = evaluated.unwrap();
    let drain_operation = OperationLease {
        deadline: Instant::now() + Duration::from_secs(2),
        ..operation
    };
    enrollment
        .response_entry_drain_for_test(&drain_operation)
        .await;
    if case == EntryCase::Navigation {
        assert!(enrollment.response_entry_state_for_test()["frames"]
            .as_array()
            .unwrap()
            .iter()
            .any(|frame| frame[2] == "next-loader"));
    }
    if case == EntryCase::Detached {
        assert!(enrollment.response_entry_state_for_test()["frames"]
            .as_array()
            .unwrap()
            .iter()
            .all(|frame| frame[1] != "session-1"));
    }
    assert_eq!(
        evaluated["ok"],
        case.expected_error().is_none(),
        "case={case:?}; evaluate={evaluated}"
    );
    let sent = log.lock().unwrap()[before_commands..]
        .iter()
        .filter(|r| r["method"] == "Runtime.evaluate" && r["params"]["expression"] == expression())
        .count();
    if evaluated["ok"] == true {
        assert_eq!(sent, 1);
        assert_eq!(evaluated["effects"], "completed");
        assert_eq!(evaluated["data"], json!({"value":{"ok":true,"value":null}}));
        for event in [
            request_event("full-body", "https://synthetic.test/api/full"),
            response_event("full-body", "https://synthetic.test/api/full"),
            finish_event("full-body"),
        ] {
            emit.send(event).await.unwrap();
        }
        let response = read_entry_frame(&mut fixture).await;
        assert_eq!(response["event"], "network.response");
        assert_eq!(
            response["payload"]["url"],
            "https://synthetic.test/api/full"
        );
        assert_eq!(response["payload"]["status"], 200);
        let handle = response["payload"]["handle"].as_str().unwrap();
        let body = fixture
            .command(
                "network.body.read",
                json!({"identityScope":scope,"handle":handle,"offset":0,"maxBytes":1024}),
                5,
            )
            .await
            .unwrap();
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            body["base64"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(String::from_utf8(bytes.clone()).unwrap(), "{\"ok\":true}");
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({"ok":true})
        );
        assert_eq!(body["eof"], true);
        fixture
            .command(
                "network.body.release",
                json!({"identityScope":scope,"handle":handle}),
                2,
            )
            .await
            .unwrap();
    } else {
        assert_eq!(sent, 0, "refused evaluation must not reach CDP");
        assert_eq!(evaluated["error"]["code"], case.expected_error().unwrap());
        assert_eq!(evaluated["effects"], "not-dispatched");
    }
    // A retired page cannot issue a fresh resource command. Scope cleanup owns
    // its remaining local subscription; all live-page cases still unsubscribe.
    let unsubscribe = if case == EntryCase::Detached {
        None
    } else {
        Some(
            fixture
                .command(
                    "network.responses.unsubscribe",
                    json!({"identityScope":scope,"subscriptionId":subscription.unwrap()}),
                    2,
                )
                .await,
        )
    };
    assert!(
        !ledger.snapshot().integrity_lost,
        "integrity lost after evaluate: {evaluated}"
    );
    assert_eq!(
        broker.health().unwrap().1,
        ScopeState::Usable,
        "after evaluate: {evaluated}"
    );
    let scope_end = fixture
        .command("scope.end", json!({"identityScope":scope}), 5)
        .await;
    let cleanup = tokio::time::timeout(Duration::from_secs(15), fixture.finish()).await;
    drop(emit);
    let peer_join = tokio::time::timeout(Duration::from_secs(2), peer).await;
    let backend_join = tokio::time::timeout(Duration::from_secs(2), backend).await;
    assert_eq!(unsubscribe.is_none(), case == EntryCase::Detached);
    if let Some(unsubscribe) = unsubscribe {
        assert!(
            unsubscribe.is_ok(),
            "unsubscribe={unsubscribe:?}; first evaluate={evaluated}"
        );
    }
    assert!(
        scope_end.is_ok(),
        "scope.end={scope_end:?}; first evaluate={evaluated}"
    );
    assert!(
        matches!(cleanup, Ok(Ok(()))),
        "cleanup={cleanup:?}; first evaluate={evaluated}"
    );
    assert!(
        matches!(peer_join, Ok(Ok(()))),
        "response peer={peer_join:?}; first evaluate={evaluated}"
    );
    assert!(
        matches!(backend_join, Ok(Ok(()))),
        "backend peer={backend_join:?}; first evaluate={evaluated}"
    );
    evaluated
}

async fn response_entry_case(case: EntryCase) -> Value {
    tokio::time::timeout(Duration::from_secs(30), response_entry_case_inner(case))
        .await
        .expect("response command-entry fixture exceeded its outer test bound")
}
#[tokio::test]
async fn response_entry_applied_network_positive_reads_full_text_and_json() {
    response_entry_case(EntryCase::Applied).await;
}
#[tokio::test]
async fn response_entry_unapplied_network_waits_then_reads_full_text_and_json() {
    response_entry_case(EntryCase::Pending).await;
}
#[tokio::test]
async fn response_entry_pending_network_preserves_original_deadline_without_dispatch() {
    response_entry_case(EntryCase::Deadline).await;
}
#[tokio::test]
async fn response_entry_pending_network_preserves_user_cancel_without_dispatch() {
    response_entry_case(EntryCase::Cancel).await;
}
#[tokio::test]
async fn response_entry_does_not_chase_later_received_network_events() {
    response_entry_case(EntryCase::FutureIngress).await;
}
#[tokio::test]
async fn response_entry_rejects_loader_change_during_ingress_wait() {
    response_entry_case(EntryCase::Navigation).await;
}
#[tokio::test]
async fn response_entry_rejects_realm_change_during_ingress_wait() {
    response_entry_case(EntryCase::Realm).await;
}
#[tokio::test]
async fn response_entry_rejects_exact_session_detach_during_ingress_wait() {
    response_entry_case(EntryCase::Detached).await;
}
