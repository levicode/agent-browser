//! P08 source-only regression, included as a cfg(test) child of client_browser.
//! Written against client_browser 70b0d55f and review-v2 enrollment 813609e6,
//! debt b87d02f8, network 5821123b, targets d42af235. Not executed here.
//! A loopback CDP peer exercises the actual reader, broker, owner and teardown.
//! No enrollment-index access, fabricated proof, ledger writes, or host closure.
use super::*;
use crate::native::client_actions::{fixture_configuration, FixtureOperations};
use crate::native::client_debt::AdmissionClass;
use crate::native::client_protocol::{Effects, ServerMessage};
use crate::native::client_session::{CancelSignal, ClientSession, OperationLease};
use crate::native::client_transport::{ClientEventSink, ClientExecutor};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};
use tokio_tungstenite::tungstenite::Message;

const BOUND: Duration = Duration::from_secs(20);
const ROOT: &str = "host-page";
const ROOT_SESSION: &str = "host-session";
const OTHER: &str = "other-host-page";
const OTHER_SESSION: &str = "other-host-session";

#[derive(Clone, Copy, PartialEq, Eq)]
enum ObserverCase {
    Absent,
    Acknowledged,
    AcknowledgedUnpaused,
    PauseMissing,
    PauseMalformed,
    PageEnableWithheld,
    ResumeWithheld,
}
impl ObserverCase {
    fn withheld_method(self) -> Option<&'static str> {
        match self {
            Self::PageEnableWithheld => Some("Page.enable"),
            Self::ResumeWithheld => Some("Runtime.runIfWaitingForDebugger"),
            _ => None,
        }
    }
    fn no_resume(self) -> bool {
        matches!(
            self,
            Self::AcknowledgedUnpaused | Self::PauseMissing | Self::PauseMalformed
        )
    }
}
enum PeerEvent {
    AttachObserver,
    RemoveRoot,
    Eof,
}
#[derive(Default)]
struct WireEvidence {
    requests: Vec<Value>,
    acknowledgements: Vec<(u64, String)>,
    root_present: bool,
    observer_present: bool,
}

fn target(id: &str) -> Value {
    json!({"targetId":id,"type":"page","browserContextId":"host-context",
        "url":"about:blank","title":"","attached":true})
}

async fn peer(
    case: ObserverCase,
) -> (
    String,
    Arc<Mutex<WireEvidence>>,
    mpsc::Sender<PeerEvent>,
    Arc<Semaphore>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let evidence = Arc::new(Mutex::new(WireEvidence {
        root_present: true,
        ..Default::default()
    }));
    let recorded = evidence.clone();
    let observer_boundary = Arc::new(Semaphore::new(0));
    let boundary = observer_boundary.clone();
    let (send, mut events) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        loop {
            tokio::select! {
                event = events.recv() => {
                    let event = event.expect("fixture control channel disappeared");
                    let value = match event {
                        PeerEvent::AttachObserver => {
                            assert!(case != ObserverCase::Absent);
                            recorded.lock().unwrap().observer_present = true;
                            let mut params = json!({"sessionId":OTHER_SESSION,
                                "waitingForDebugger":true,"targetInfo":target(OTHER)});
                            match case {
                                ObserverCase::AcknowledgedUnpaused => params["waitingForDebugger"] = json!(false),
                                ObserverCase::PauseMissing => { params.as_object_mut().unwrap().remove("waitingForDebugger"); }
                                ObserverCase::PauseMalformed => params["waitingForDebugger"] = json!("false"),
                                _ => {}
                            }
                            json!({"method":"Target.attachedToTarget","params":params})
                        }
                        PeerEvent::RemoveRoot => {
                            recorded.lock().unwrap().root_present = false;
                            json!({"method":"Target.detachedFromTarget","params":{
                                "sessionId":ROOT_SESSION,"targetId":ROOT}})
                        }
                        PeerEvent::Eof => {
                            // Peer-originated close and socket drop, never local
                            // ClientBrowser/CdpClient close masquerading as EOF.
                            socket.send(Message::Close(None)).await.unwrap();
                            break;
                        }
                    };
                    socket.send(Message::Text(value.to_string())).await.unwrap();
                }
                incoming = socket.next() => {
                    let incoming = incoming.expect("client closed before fixture EOF").unwrap();
                    let text = match incoming {
                        Message::Text(text) => text,
                        Message::Ping(bytes) => {
                            socket.send(Message::Pong(bytes)).await.unwrap();
                            continue;
                        }
                        other => panic!("unexpected client websocket frame: {other:?}"),
                    };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    recorded.lock().unwrap().requests.push(request.clone());
                    let method = request["method"].as_str().unwrap();
                    let session = request["sessionId"].as_str().unwrap_or("");
                    // Observation-only enrollment must never gain application,
                    // Fetch, script, input, recording, or host-lifetime powers.
                    if session == OTHER_SESSION {
                        assert!(matches!(method, "Page.enable" | "Page.getFrameTree"
                            | "Target.setAutoAttach" | "Runtime.runIfWaitingForDebugger"),
                            "unexpected observer command: {request}");
                        if method == "Target.setAutoAttach" {
                            assert_eq!(request["params"], json!({"autoAttach":true,
                                "waitForDebuggerOnStart":false,"flatten":true,
                                "filter":[{"type":"browser","exclude":true},{"type":"tab","exclude":true},{}]}));
                        }
                    }
                    if case.withheld_method() == Some(method) && session == OTHER_SESSION
                    {
                        boundary.add_permits(1);
                        // Remain able to emit root-detach and EOF. This exact
                        // submitted command deliberately receives no response.
                        continue;
                    }
                    let result = match method {
                        "Browser.getVersion" => json!({"protocolVersion":"1.3",
                            "product":"Synthetic Chromium/1.0","revision":"synthetic",
                            "userAgent":"Synthetic Chromium Linux","jsVersion":"synthetic"}),
                        "Target.getBrowserContexts" => json!({"browserContextIds":[],
                            "defaultBrowserContextId":"host-context"}),
                        "Target.getTargets" => {
                            let state = recorded.lock().unwrap();
                            let mut infos = Vec::new();
                            if state.root_present { infos.push(target(ROOT)); }
                            if state.observer_present { infos.push(target(OTHER)); }
                            json!({"targetInfos":infos})
                        }
                        "Target.getTargetInfo" => {
                            assert_eq!(request["params"]["targetId"], ROOT);
                            assert!(recorded.lock().unwrap().root_present);
                            json!({"targetInfo":target(ROOT)})
                        }
                        "Target.attachToTarget" => {
                            assert_eq!(request["params"]["targetId"], ROOT);
                            json!({"sessionId":ROOT_SESSION})
                        }
                        "Page.getFrameTree" => json!({"frameTree":{"frame":{
                            "id":format!("frame-{session}"),"loaderId":format!("loader-{session}"),
                            "url":"about:blank"}}}),
                        "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":"host-script"}),
                        "Page.enable" | "Runtime.enable" | "Network.enable" | "WebMCP.enable"
                        | "DOM.enable" | "DOM.disable" | "Network.setBypassServiceWorker"
                        | "Fetch.enable" | "Fetch.disable" | "Page.setLifecycleEventsEnabled"
                        | "Target.setDiscoverTargets" | "Target.setAutoAttach"
                        | "Runtime.runIfWaitingForDebugger" | "Page.removeScriptToEvaluateOnNewDocument"
                        | "Emulation.setEmulatedMedia" | "Browser.setDownloadBehavior" => json!({}),
                        other => panic!("unmodeled or forbidden P08 CDP command {other}: {request}"),
                    };
                    let mut response = json!({"id":request["id"],"result":result});
                    if !session.is_empty() { response["sessionId"] = session.into(); }
                    socket.send(Message::Text(response.to_string())).await.unwrap();
                    recorded.lock().unwrap().acknowledgements.push((
                        request["id"].as_u64().unwrap(), session.to_owned()));
                    if session == OTHER_SESSION && (method == "Runtime.runIfWaitingForDebugger"
                        || (case.no_resume() && method == "Target.setAutoAttach")) {
                        boundary.add_permits(1);
                    }
                }
            }
        }
    });
    (endpoint, evidence, send, observer_boundary, task)
}

struct Outcome {
    drained: Result<(), ProtocolError>,
    final_proof: Result<(), ProtocolError>,
    terminal_proof: Result<(), ProtocolError>,
    ledger_proof: Result<(), ProtocolError>,
    ended: Result<Value, ProtocolError>,
    shutdown: Result<(), ProtocolError>,
    owner_retained: bool,
    directory_retained: bool,
    callback_fences: usize,
}

async fn run(case: ObserverCase) -> Outcome {
    let (endpoint, evidence, emit, observer_boundary, peer_task) = peer(case).await;
    let broker = Arc::new(ClientSession::new());
    let browser = ClientBrowser::new(broker.clone());
    let (sink, mut notices) = ClientEventSink::test_channel(broker.clone());
    browser.set_event_sink(sink.clone()).unwrap();
    let mut operations = FixtureOperations::new(broker);
    let opened = operations
        .execute_written(
            &browser,
            &sink,
            "scope.open",
            json!({"source":"connect","context":"persistent","endpoint":endpoint}),
            10,
        )
        .await
        .unwrap();
    assert_eq!(opened.effects, Effects::Completed);
    let opened = opened.result.unwrap();
    let scope = opened["identityScope"].as_str().unwrap().to_owned();
    let configured = operations
        .execute_written(
            &browser,
            &sink,
            "scope.configure",
            fixture_configuration(&scope, None),
            10,
        )
        .await
        .unwrap();
    assert_eq!(configured.result, Ok(Value::Null));
    assert_eq!(configured.effects, Effects::Completed);

    let (client, enrollment, targets, actions, directory) = {
        let owner = browser.owner.lock().await;
        let owner = owner.as_ref().unwrap();
        assert!(!owner.owns_context);
        let runtime = owner.runtime.as_ref().unwrap();
        let directory = runtime
            .configuration
            .lock()
            .unwrap()
            .download_directory
            .as_ref()
            .unwrap()
            .path()
            .to_owned();
        (
            owner.manager.client.clone(),
            runtime.enrollment.clone(),
            owner.targets.clone(),
            runtime.actions.clone(),
            directory,
        )
    };
    assert!(directory.is_dir());
    assert!(!actions.is_recording_armed().await.unwrap());
    let root = targets.owned_target(ROOT).unwrap();
    assert!(root.resumed);
    assert_eq!(
        root.purpose,
        Some(crate::native::client_targets::TargetPurpose::Application)
    );
    let ledger = client.debt_ledger().unwrap();
    assert!(ledger.matches_owner(1, &scope));
    let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
    let operation = || OperationLease {
        is_callback: false,
        generation: 1,
        sequence: 0,
        deadline: Instant::now() + BOUND,
        cancellation: cancellation.clone(),
    };

    if case != ObserverCase::Absent {
        emit.send(PeerEvent::AttachObserver).await.unwrap();
        tokio::time::timeout(BOUND, observer_boundary.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        assert!(targets.owned_target(OTHER).is_err());
    }
    if case.withheld_method().is_none() {
        // The final wire ACK alone is insufficient. Public attestation drains
        // pending enrollment and checks resumed application XOR observer entries;
        // inventory requires this unauthorized same-context page to be an observer.
        enrollment.attest_capture(&operation()).await.unwrap();
        assert!(targets.owned_target(OTHER).is_err());
        assert_eq!(ledger.snapshot().outstanding_commands, 0);
    } else {
        assert_eq!(ledger.snapshot().outstanding_commands, 1);
    }
    assert_eq!(ledger.snapshot().input_debt, 0);
    assert_eq!(ledger.snapshot().object_debt, 0);
    assert!(!ledger.snapshot().integrity_lost);

    emit.send(PeerEvent::RemoveRoot).await.unwrap();
    tokio::time::timeout(BOUND, async {
        while targets.owned_target(ROOT).is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // This read-only registry proof also excludes surviving Application targets,
    // recorder reservations and unknown bootstrap creations before EOF/sealing.
    assert_eq!(targets.check_final_local_cleanup(), Ok(()));
    if case.withheld_method().is_none() {
        // A second complete capture fence proves the observer is still live,
        // resumed and observation-only after the root's actual detach event.
        enrollment.attest_capture(&operation()).await.unwrap();
        assert_eq!(ledger.snapshot().outstanding_commands, 0);
    }
    assert_eq!(ledger.snapshot().input_debt, 0);
    assert_eq!(ledger.snapshot().object_debt, 0);
    assert!(!actions.is_recording_armed().await.unwrap());
    {
        let wire = evidence.lock().unwrap();
        assert!(!wire.root_present);
        assert_eq!(wire.observer_present, case != ObserverCase::Absent);
        for request in &wire.requests {
            let key = (
                request["id"].as_u64().unwrap(),
                request["sessionId"].as_str().unwrap_or("").to_owned(),
            );
            let held = request["sessionId"] == OTHER_SESSION
                && request["method"].as_str() == case.withheld_method();
            assert_eq!(wire.acknowledgements.contains(&key), !held, "{request}");
        }
        if case == ObserverCase::Acknowledged {
            let methods: Vec<_> = wire
                .requests
                .iter()
                .filter(|request| request["sessionId"] == OTHER_SESSION)
                .map(|request| request["method"].as_str().unwrap())
                .collect();
            for required in [
                "Page.enable",
                "Page.getFrameTree",
                "Target.setAutoAttach",
                "Runtime.runIfWaitingForDebugger",
            ] {
                assert!(
                    methods.contains(&required),
                    "missing observer ACK: {required}"
                );
            }
        }
        if case.no_resume() {
            assert!(!wire
                .requests
                .iter()
                .any(|request| request["sessionId"] == OTHER_SESSION
                    && request["method"] == "Runtime.runIfWaitingForDebugger"));
        }
    }

    emit.send(PeerEvent::Eof).await.unwrap();
    let mut closed = client.remote_connection_closed();
    tokio::time::timeout(BOUND, async {
        while !*closed.borrow_and_update() {
            closed.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(BOUND, peer_task)
        .await
        .unwrap()
        .unwrap();
    let drained = tokio::time::timeout(BOUND, enrollment.drain())
        .await
        .unwrap();
    let final_proof = enrollment.final_local_connection_proof().and_then(|proof| {
        proof.check_client(&client)?;
        proof.check_targets(&targets)
    });
    let terminal_proof = enrollment.terminal_connection_proof().map(|_| ());
    let ledger_proof = ledger.check_final_local_eof(1, &scope);
    assert!(ledger.snapshot().integrity_lost);
    assert!(ledger.check_admission(AdmissionClass::Input).is_err());
    if case.withheld_method().is_some() {
        assert!(
            ledger.snapshot().outstanding_commands >= 1,
            "EOF must not waive the withheld observer initialization command"
        );
    }
    {
        let owner = browser.owner.lock().await;
        let owner = owner
            .as_ref()
            .expect("original owner must remain journaled");
        assert_eq!(owner.identity_scope, scope);
        assert!(Arc::ptr_eq(&owner.manager.client, &client));
        assert!(Arc::ptr_eq(&owner.targets, &targets));
        assert!(Arc::ptr_eq(
            &owner.runtime.as_ref().unwrap().enrollment,
            &enrollment
        ));
        assert!(owner.reconnect_proof.is_none());
        assert!(owner.replacement_actions.is_none());
    }
    let ended = tokio::time::timeout(BOUND, browser.end_scope(scope.clone(), 0))
        .await
        .unwrap();
    let owner_retained = {
        let owner = browser.owner.lock().await;
        if let Some(owner) = owner.as_ref() {
            assert_eq!(owner.identity_scope, scope);
            assert!(Arc::ptr_eq(&owner.manager.client, &client));
            assert!(Arc::ptr_eq(&owner.targets, &targets));
            assert!(Arc::ptr_eq(
                &owner.runtime.as_ref().unwrap().enrollment,
                &enrollment
            ));
        }
        owner.is_some()
    };
    let directory_retained = directory.exists();
    // Retain and assert shutdown's actual result in every test; never discard it.
    let shutdown = tokio::time::timeout(BOUND, browser.shutdown())
        .await
        .unwrap();
    let mut callback_fences = 0;
    while let Ok(notice) = notices.try_recv() {
        if matches!(notice, ServerMessage::Event { ref event, .. }
            if event == "scope.callbacks-retired")
        {
            callback_fences += 1;
        }
    }
    let wire = evidence.lock().unwrap();
    assert!(!wire.root_present);
    assert_eq!(wire.observer_present, case != ObserverCase::Absent);
    assert!(!wire.requests.iter().any(|request| {
        let method = request["method"].as_str().unwrap();
        method.starts_with("Input.")
            || matches!(
                method,
                "Browser.close"
                    | "Target.closeTarget"
                    | "Target.disposeBrowserContext"
                    | "Target.createTarget"
                    | "Page.startScreencast"
                    | "Page.stopScreencast"
                    | "Runtime.evaluate"
                    | "Runtime.callFunctionOn"
            )
    }));
    Outcome {
        drained,
        final_proof,
        terminal_proof,
        ledger_proof,
        ended,
        shutdown,
        owner_retained,
        directory_retained,
        callback_fences,
    }
}

#[tokio::test]
async fn p08_control_missing_root_without_observer_allows_final_local_cleanup() {
    let result = run(ObserverCase::Absent).await;
    assert_eq!(result.drained, Ok(()));
    assert_eq!(result.final_proof, Ok(()));
    assert_eq!(result.ledger_proof, Ok(()));
    assert_eq!(result.terminal_proof, Err(ProtocolError::StaleScope));
    assert_eq!(result.ended, Ok(Value::Null));
    assert_eq!(result.shutdown, Ok(()));
    assert!(!result.owner_retained);
    assert!(!result.directory_retained);
    assert_eq!(result.callback_fences, 1);
}

#[tokio::test]
async fn p08_desired_missing_root_with_settled_observer_allows_final_local_cleanup() {
    let result = run(ObserverCase::Acknowledged).await;
    // The opposite defect characterization remains frozen with source5c7dfd75;
    // it is not an additional contract on this repaired source.
    assert_eq!(result.drained, Ok(()));
    assert_eq!(result.final_proof, Ok(()));
    assert_eq!(result.ledger_proof, Ok(()));
    assert_eq!(
        result.ended,
        Ok(Value::Null),
        "a fully ACKed observation-only host page must not block final-local EOF cleanup"
    );
    assert_eq!(result.terminal_proof, Err(ProtocolError::StaleScope));
    assert_eq!(result.shutdown, Ok(()));
    assert!(!result.owner_retained);
    assert!(!result.directory_retained);
    assert_eq!(result.callback_fences, 1);
}

#[tokio::test]
async fn p08_withheld_observer_initialization_ack_is_not_waived_by_root_eof() {
    let result = run(ObserverCase::PageEnableWithheld).await;
    assert!(result.drained.is_err());
    assert_eq!(result.ledger_proof, Err(ProtocolError::ScopeUnavailable));
    assert_eq!(result.final_proof, Err(ProtocolError::CleanupFailed));
    assert_eq!(result.ended, Err(ProtocolError::CleanupFailed));
    assert_eq!(result.shutdown, Err(ProtocolError::CleanupFailed));
    assert!(result.owner_retained);
    assert!(result.directory_retained);
}

#[tokio::test]
async fn p08_explicitly_unpaused_observer_ends_without_any_resume() {
    let result = run(ObserverCase::AcknowledgedUnpaused).await;
    assert_eq!(result.drained, Ok(()));
    assert_eq!(result.final_proof, Ok(()));
    assert_eq!(result.ledger_proof, Ok(()));
    assert_eq!(result.terminal_proof, Err(ProtocolError::StaleScope));
    assert_eq!(result.ended, Ok(Value::Null));
    assert_eq!(result.shutdown, Ok(()));
    assert!(!result.owner_retained);
    assert!(!result.directory_retained);
    assert_eq!(result.callback_fences, 1);
}

#[tokio::test]
async fn p08_unknown_pause_and_unacknowledged_resume_remain_cleanup_failures() {
    for case in [
        ObserverCase::PauseMissing,
        ObserverCase::PauseMalformed,
        ObserverCase::ResumeWithheld,
    ] {
        let result = run(case).await;
        assert!(result.drained.is_err());
        assert_eq!(result.ledger_proof, Err(ProtocolError::ScopeUnavailable));
        assert_eq!(result.final_proof, Err(ProtocolError::CleanupFailed));
        assert_eq!(result.ended, Err(ProtocolError::CleanupFailed));
        assert_eq!(result.shutdown, Err(ProtocolError::CleanupFailed));
        assert!(result.owner_retained);
        assert!(result.directory_retained);
    }
}
