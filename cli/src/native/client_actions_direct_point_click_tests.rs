use super::*;

// This prefix already receives session-correct CDP ACKs in the existing peer.
// These exact modes add observational timestamps to their private request log.
pub(super) const MODE: &str = "direct-point-original-clicks";
pub(super) const HTML5_EARLY_MODE: &str = "direct-point-html5-early";
pub(super) const HTML5_LATE_MODE: &str = "direct-point-html5-late";
pub(super) const HTML5_REJECT_MODE: &str = "direct-point-html5-reject";
pub(super) const ENABLE_REJECT_MODE: &str = "direct-point-enable-error-ack";
pub(super) const MOVE_REJECT_MODE: &str = "direct-point-move-error-ack";
pub(super) const MOVE_OWN_ERROR_MODE: &str = "direct-point-move-own-error-ack";
pub(super) const CAPACITY_MODE: &str = "direct-point-capacity";
pub(super) const SWIPE_MODE: &str = "direct-point-original-pointer-swipe";
pub(super) const POINTER_MODE: &str = "direct-point-original-pointer";
pub(super) const PACED_MODE: &str = "direct-point-original-pointer-paced";
pub(super) const CANCEL_MODE: &str = "direct-point-original-pointer-cancel";
pub(super) const WHEEL_MODE: &str = "direct-point-original-pointer-wheel";

pub(super) fn is_pointer_mode(mode: &str) -> bool {
    matches!(mode, POINTER_MODE | SWIPE_MODE | PACED_MODE | CANCEL_MODE | WHEEL_MODE | HTML5_EARLY_MODE | HTML5_LATE_MODE | HTML5_REJECT_MODE | CAPACITY_MODE | ENABLE_REJECT_MODE | MOVE_REJECT_MODE | MOVE_OWN_ERROR_MODE)
}

pub(super) fn is_swipe_mode(mode: &str) -> bool {
    matches!(mode, SWIPE_MODE | PACED_MODE | CANCEL_MODE | HTML5_EARLY_MODE | HTML5_LATE_MODE | HTML5_REJECT_MODE | CAPACITY_MODE | ENABLE_REJECT_MODE | MOVE_REJECT_MODE | MOVE_OWN_ERROR_MODE)
}

pub(super) fn holds_pointer_reply(mode: &str, request: &Value) -> bool {
    ((mode == HTML5_EARLY_MODE || mode == HTML5_LATE_MODE)
        && request["method"] == "Input.dispatchDragEvent" && request["params"]["type"] == "drop")
        || (mode == CAPACITY_MODE && request["method"] == "Runtime.evaluate"
            && request["params"]["objectGroup"].as_str().is_some_and(|g| g.starts_with("native-point-drag-")))
        || (mode == PACED_MODE
        && request["method"] == "Input.dispatchMouseEvent"
        && request["params"]["type"] == "mouseMoved"
        && request["params"]["x"].as_f64() == Some(50.0))
        || (mode == CANCEL_MODE
            && request["method"] == "Input.dispatchMouseEvent"
            && request["params"]["type"] == "mouseReleased")
        || (mode == WHEEL_MODE && request["method"] == "Runtime.evaluate")
}

pub(super) fn record_receipt(request: &mut Value, elapsed: Duration) {
    request["directPointPeerReceiptNanos"] =
        json!(u64::try_from(elapsed.as_nanos()).expect("fixture clock fits u64 nanoseconds"));
    request["directPointPeerReceiptMicros"] =
        json!(u64::try_from(elapsed.as_micros()).expect("fixture clock fits u64 microseconds"));
}

// Reproduce the existing direct-point fixture's exact attachment and guards.
// These are real native input calls over mock CDP, with no DOM/matcher reply.
pub(super) async fn owned_pointer_fixture(
    mode: &'static str,
) -> (
    Fixture,
    Arc<client_debt::OwnerDebtLedger>,
    OperationJournalHandle,
) {
    let f = fixture(mode).await;
    f.page
        .targets
        .attached("context", "target".into(), "page".into(), "page".into())
        .unwrap();
    f.page.targets.configured("target").unwrap();
    f.page
        .targets
        .resume_permit("target")
        .await
        .unwrap()
        .complete()
        .unwrap();
    install_pointer_ledger(f)
}

fn install_pointer_ledger(mut f: Fixture) -> (Fixture, Arc<client_debt::OwnerDebtLedger>, OperationJournalHandle) {
    let ledger = client_debt::OwnerDebtLedger::new(1, "scope".into());
    f.page.client.install_debt_ledger(ledger.clone()).unwrap();
    f.page.client = f.page.client.owner_view(ledger.clone()).unwrap();
    let journal = ledger
        .operation(
            client_debt::OperationKey {
                generation: 1,
                operation_seq: 1,
            },
            "target".into(),
            "page".into(),
        )
        .unwrap();
    journal.bind_operation(&f.op).unwrap();
    f.replies.lock().unwrap().clear();
    (f, ledger, journal)
}

// Unlike clicks, swipes require real enrollment and exact isolated-realm evidence.
// This fixture does not pre-insert a target or replace its original operation.
async fn owned_swipe_fixture(mode: &'static str) -> (
    Fixture, Arc<client_debt::OwnerDebtLedger>, OperationJournalHandle,
    Arc<super::super::super::client_enrollment::ClientEnrollment>,
    tokio::sync::mpsc::Receiver<super::super::super::client_protocol::ServerMessage>,
) {
    assert!(is_swipe_mode(mode));
    let (mut f, ledger, journal) = install_pointer_ledger(fixture(mode).await);
    // Real enrollment binds session tenure only inside its already owned context.
    ledger.bind_context(&f.page.targets.context_id).unwrap();
    let broker = Arc::new(super::super::super::client_session::ClientSession::new());
    let (owner, state, notices) = preparation_settlement_owner(&f, broker).await;
    f.state = state;
    // Initialization is outside the action trace, not outside its original deadline.
    f.log.lock().unwrap().clear();
    f.replies.lock().unwrap().clear();
    (f, ledger, journal, owner, notices)
}

async fn assert_original_click(action: Value, button: &str, count: i32, hold_ms: u64) {
    let (f, ledger, journal) = owned_pointer_fixture(MODE).await;
    let gate = Arc::new(super::super::super::client_ui::UiGate::default());
    let ui = gate
        .enter(false, false, f.op.deadline, f.op.cancellation.clone())
        .await
        .unwrap();
    let input = tokio::sync::Mutex::new(());
    let original_deadline = f.op.deadline;
    let result = ClientActions::default()
        .execute_direct_point(
            DirectPointContext {
                realm_authority: ActionRealmAuthority::UntrackedFixture,
                page: &f.page,
                operation: &f.op,
                page_state: &f.state,
                journal: &journal,
                ui,
                input: input.lock().await,
            },
            &json!({
                "identityScope": "scope", "point": { "x": 10, "y": 20 },
                "action": action,
            }),
        )
        .await
        .expect("the actual direct-point action must finish with its original lease");
    assert_eq!(result, Value::Null);
    assert_eq!(f.op.deadline, original_deadline);

    let log = f.log.lock().unwrap().clone();
    assert!(log.iter().all(|request| {
        request["method"] == "Input.dispatchMouseEvent" && request["sessionId"] == "page"
    }));
    for request in &log {
        assert_eq!(request["params"]["x"].as_f64(), Some(10.0));
        assert_eq!(request["params"]["y"].as_f64(), Some(20.0));
        assert_eq!(request["params"]["modifiers"], 0);
    }
    let mask = match button {
        "left" => 1,
        "right" => 2,
        _ => unreachable!("the original click variants use left or right"),
    };
    let mut expected = vec![json!(["mouseMoved", "none", 0, null])];
    for click in 1..=count {
        expected.push(json!(["mousePressed", button, mask, click]));
        expected.push(json!(["mouseReleased", button, 0, click]));
    }
    let actual: Vec<_> = log
        .iter()
        .map(|request| {
            let params = &request["params"];
            json!([
                params["type"],
                params["button"],
                params["buttons"],
                params["clickCount"],
            ])
        })
        .collect();
    assert_eq!(actual, expected);
    if hold_ms != 0 {
        let down_us = log[1]["directPointPeerReceiptMicros"].as_u64().unwrap();
        let up_us = log[2]["directPointPeerReceiptMicros"].as_u64().unwrap();
        // Real monotonic peer receipt time includes transport/scheduling latency.
        // This asserts the native down/up interval, not overall test duration.
        assert!(
            up_us.checked_sub(down_us).unwrap() >= hold_ms * 1_000,
            "the original direct-point long press must hold for at least {hold_ms}ms"
        );
    }
    let settled = journal.snapshot();
    assert!(settled.mutation_dispatched);
    assert_eq!(settled.input_debt, 0);
    assert_eq!(settled.object_debt, 0);
    assert!(!settled.integrity_lost);
    assert_eq!(ledger.snapshot().input_debt, 0);
    assert_eq!(f.state.mouse_state().unwrap().buttons, 0);
}

#[tokio::test]
async fn direct_point_original_tap_at_10_20() {
    assert_original_click(json!({ "kind": "tap" }), "left", 1, 0).await;
}

#[tokio::test]
async fn direct_point_original_double_tap_at_10_20() {
    assert_original_click(json!({ "kind": "doubleTap" }), "left", 2, 0).await;
}

#[tokio::test]
async fn direct_point_original_secondary_tap_at_10_20() {
    assert_original_click(json!({ "kind": "secondaryTap" }), "right", 1, 0).await;
}

#[tokio::test]
async fn direct_point_original_long_press_at_10_20_holds_700_ms() {
    assert_original_click(
        json!({ "kind": "longPress", "durationMs": 700 }),
        "left",
        1,
        700,
    )
    .await;
}

async fn execute_original_pointer(
    f: &Fixture,
    owner: Option<&Arc<super::super::super::client_enrollment::ClientEnrollment>>,
    journal: &OperationJournalHandle,
    args: &Value,
) -> Result<Value, ActionFailure> {
    let gate = Arc::new(super::super::super::client_ui::UiGate::default());
    let ui = gate
        .enter(false, false, f.op.deadline, f.op.cancellation.clone())
        .await
        .unwrap();
    let input = tokio::sync::Mutex::new(());
    let input_guard = input.lock().await;
    ClientActions::default()
        .execute_direct_point(
            DirectPointContext {
                realm_authority: match owner {
                    Some(owner) => ActionRealmAuthority::Enrolled(owner),
                    None => ActionRealmAuthority::UntrackedFixture,
                },
                page: &f.page,
                operation: &f.op,
                page_state: &f.state,
                journal,
                ui,
                input: input_guard,
            },
            args,
        )
        .await
}

type PointerTraceEvent<'a> = (&'a str, f64, f64, &'a str, i64, Option<i64>);

fn assert_pointer_trace(f: &Fixture, expected: &[PointerTraceEvent<'_>]) {
    let inputs = mouse_inputs(f);
    let actual: Vec<_> = inputs
        .iter()
        .map(|request| {
            assert_eq!(request["method"], "Input.dispatchMouseEvent");
            assert_eq!(request["sessionId"], "page");
            let p = &request["params"];
            assert_eq!(p["modifiers"], 0);
            (
                p["type"].as_str().unwrap(),
                p["x"].as_f64().unwrap(),
                p["y"].as_f64().unwrap(),
                p["button"].as_str().unwrap(),
                p["buttons"].as_i64().unwrap(),
                p["clickCount"].as_i64(),
            )
        })
        .collect();
    assert_eq!(actual.as_slice(), expected);
    assert!(f.log.lock().unwrap().iter().all(|request| {
        allowed_pointer_command(request)
    }));
}

pub(super) fn assert_pointer_settled(
    f: &Fixture,
    ledger: &client_debt::OwnerDebtLedger,
    journal: &OperationJournalHandle,
) {
    let operation = journal.snapshot();
    assert!(operation.mutation_dispatched);
    assert_eq!(operation.input_debt, 0);
    assert_eq!(operation.object_debt, 0);
    assert!(!operation.integrity_lost);
    let owner = ledger.snapshot();
    assert_eq!(owner.input_debt, 0);
    assert_eq!(owner.object_debt, 0);
    assert_eq!(owner.outstanding_commands, 0);
    assert!(!owner.integrity_lost);
    assert_eq!(f.state.mouse_state().unwrap().buttons, 0);
    let log = f.log.lock().unwrap().clone();
    if log.iter().any(|r| r["params"]["objectId"] == "point-move-probe") {
        let disposals: Vec<_> = log.iter().filter(|r| r["params"]["functionDeclaration"] == "function(){return this.dispose()}").collect();
        let groups: Vec<_> = log.iter().filter(|r| r["method"] == "Runtime.releaseObjectGroup").collect();
        assert_eq!(disposals.len(), 1);
        assert_eq!(groups.len(), 1);
        assert_eq!(log.iter().rev().find(|r| r["method"] == "Input.setInterceptDrags").unwrap()["params"]["enabled"], false);
        for request in log.iter().filter(|r| r["method"] != "Browser.getVersion") {
            exact_pointer_ack(f, request);
        }
    }
}

pub(super) fn exact_pointer_ack(f: &Fixture, request: &Value) -> Value {
    let replies = f.replies.lock().unwrap();
    let matching: Vec<_> = replies
        .iter()
        .filter(|entry| entry["request"]["id"] == request["id"])
        .collect();
    assert_eq!(matching.len(), 1, "the original command must be ACKed once");
    let entry = matching[0];
    for field in ["id", "sessionId", "method", "params"] {
        assert_eq!(entry["request"][field], request[field]);
    }
    assert_eq!(entry["reply"]["id"], request["id"]);
    assert_eq!(entry["reply"]["sessionId"], request["sessionId"]);
    assert!(entry["reply"].get("error").is_none());
    assert!(entry["reply"].get("result").is_some());
    entry.clone()
}

pub(super) async fn wait_for_held_pointer_request(f: &Fixture, mode: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let held = f
                .log
                .lock()
                .unwrap()
                .iter()
                .find(|request| holds_pointer_reply(mode, request))
                .cloned();
            if let Some(request) = held {
                return request;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the actual producer must reach the held transport reply")
}

#[tokio::test]
async fn direct_point_original_fractional_tap_and_swipe_round_to_css_pixels() {
    for (point, action, expected) in [
        (
            json!({"x":332,"y":158.875}),
            json!({"kind":"tap"}),
            vec![
                ("mouseMoved", 332., 159., "none", 0, None),
                ("mousePressed", 332., 159., "left", 1, Some(1)),
                ("mouseReleased", 332., 159., "left", 0, Some(1)),
            ],
        ),
        (
            json!({"x":10.4,"y":20.5}),
            json!({"kind":"swipeTo","target":{"x":110.6,"y":20.5}}),
            vec![
                ("mouseMoved", 10., 21., "none", 0, None),
                ("mousePressed", 10., 21., "left", 1, Some(1)),
                ("mouseMoved", 61., 21., "left", 1, None),
                ("mouseMoved", 111., 21., "left", 1, None),
                ("mouseReleased", 111., 21., "left", 0, Some(1)),
            ],
        ),
    ] {
        let swipe = action["kind"] == "swipeTo";
        let (f, ledger, journal, owner, _notices) = if swipe {
            let (f, ledger, journal, owner, notices) = owned_swipe_fixture(SWIPE_MODE).await;
            (f, ledger, journal, Some(owner), Some(notices))
        } else {
            let (f, ledger, journal) = owned_pointer_fixture(POINTER_MODE).await;
            (f, ledger, journal, None, None)
        };
        let result = execute_original_pointer(
            &f,
            owner.as_ref(),
            &journal,
            &json!({
                "identityScope":"scope", "point":point, "action":action,
            }),
        )
        .await
        .unwrap();
        assert_eq!(result, Value::Null);
        assert_pointer_trace(&f, &expected);
        if !swipe {
            assert!(f.log.lock().unwrap().iter().all(|request| request["method"] == "Input.dispatchMouseEvent"),
                "fractional tap must remain independent of enrollment/realms");
        }
        for request in mouse_inputs(&f) {
            exact_pointer_ack(&f, &request);
        }
        assert_pointer_settled(&f, &ledger, &journal);
        if let Some(owner) = owner { owner.seal(); owner.drain().await.unwrap(); }
    }
}

#[tokio::test]
async fn direct_point_original_swipe_to_110_20_uses_midpoint() {
    let (f, ledger, journal, owner, _notices) = owned_swipe_fixture(SWIPE_MODE).await;
    let result = execute_original_pointer(
        &f,
        Some(&owner),
        &journal,
        &json!({
            "identityScope":"scope", "point":{"x":10,"y":20},
            "action":{"kind":"swipeTo","target":{"x":110,"y":20}},
        }),
    )
    .await
    .unwrap();
    assert_eq!(result, Value::Null);
    assert_pointer_trace(
        &f,
        &[
            ("mouseMoved", 10., 20., "none", 0, None),
            ("mousePressed", 10., 20., "left", 1, Some(1)),
            ("mouseMoved", 60., 20., "left", 1, None),
            ("mouseMoved", 110., 20., "left", 1, None),
            ("mouseReleased", 110., 20., "left", 0, Some(1)),
        ],
    );
    for request in mouse_inputs(&f) {
        exact_pointer_ack(&f, &request);
    }
    assert_pointer_settled(&f, &ledger, &journal);
    owner.seal();
    owner.drain().await.unwrap();
}

#[tokio::test]
async fn direct_point_original_swipe_to_70_20_paces_three_moves_over_48_ms() {
    let (f, ledger, journal, owner, _notices) = owned_swipe_fixture(PACED_MODE).await;
    let args = json!({"identityScope":"scope", "point":{"x":10,"y":20},
        "action":{"kind":"swipeTo","target":{"x":70,"y":20},"durationMs":48}});
    let action = execute_original_pointer(&f, Some(&owner), &journal, &args);
    tokio::pin!(action);
    let held = tokio::select! {
        result = &mut action => panic!("action settled before its second move ACK: {result:?}"),
        request = wait_for_held_pointer_request(&f, PACED_MODE) => request,
    };
    assert!(tokio::time::timeout(Duration::from_millis(5), &mut action)
        .await
        .is_err());
    assert_pointer_trace(
        &f,
        &[
            ("mouseMoved", 10., 20., "none", 0, None),
            ("mousePressed", 10., 20., "left", 1, Some(1)),
            ("mouseMoved", 30., 20., "left", 1, None),
            ("mouseMoved", 50., 20., "left", 1, None),
        ],
    );
    assert_eq!(f.state.mouse_state().unwrap().buttons, 1);
    assert_eq!(journal.snapshot().input_debt, 1);
    assert!(!f
        .replies
        .lock()
        .unwrap()
        .iter()
        .any(|entry| entry["request"]["id"] == held["id"]));
    f.page
        .client
        .send_command_no_params("Browser.getVersion", None)
        .await
        .unwrap();
    assert_eq!(action.await.unwrap(), Value::Null);
    assert_pointer_trace(
        &f,
        &[
            ("mouseMoved", 10., 20., "none", 0, None),
            ("mousePressed", 10., 20., "left", 1, Some(1)),
            ("mouseMoved", 30., 20., "left", 1, None),
            ("mouseMoved", 50., 20., "left", 1, None),
            ("mouseMoved", 70., 20., "left", 1, None),
            ("mouseReleased", 70., 20., "left", 0, Some(1)),
        ],
    );
    let inputs = mouse_inputs(&f);
    // The producer starts its pacing clock only after receiving the press ACK.
    // The peer's pre-send instant is therefore a causal lower bound, in the
    // same monotonic clock as every move receipt. Total test time is not used.
    let start = exact_pointer_ack(&f, &inputs[1])["directPointPeerAckStartNanos"]
        .as_u64()
        .unwrap();
    for (request, due_ms) in inputs[2..5].iter().zip([16_u64, 32, 48]) {
        let receipt = request["directPointPeerReceiptNanos"].as_u64().unwrap();
        assert!(
            receipt.checked_sub(start).unwrap() >= due_ms * 1_000_000,
            "paced move arrived before its {due_ms}ms causal due-time bound"
        );
    }
    for request in &inputs {
        exact_pointer_ack(&f, request);
    }
    assert_eq!(
        exact_pointer_ack(&f, &held)["heldUntilRequest"]["method"],
        "Browser.getVersion"
    );
    assert_pointer_settled(&f, &ledger, &journal);
    owner.seal();
    owner.drain().await.unwrap();
}

#[tokio::test]
async fn direct_point_original_swipe_to_70_20_cancel_after_first_move_releases_once() {
    let (f, ledger, journal, owner, _notices) = owned_swipe_fixture(CANCEL_MODE).await;
    let args = json!({"identityScope":"scope", "point":{"x":10,"y":20},
        "action":{"kind":"swipeTo","target":{"x":70,"y":20},"durationMs":48}});
    let action = execute_original_pointer(&f, Some(&owner), &journal, &args);
    tokio::pin!(action);
    let release = tokio::select! {
        result = &mut action => panic!("action settled before its cleanup release ACK: {result:?}"),
        request = wait_for_held_pointer_request(&f, CANCEL_MODE) => request,
    };
    assert_eq!(*f.op.cancellation.borrow(), CancelSignal::Requested);
    assert!(tokio::time::timeout(Duration::from_millis(5), &mut action)
        .await
        .is_err());
    let expected = [
        ("mouseMoved", 10., 20., "none", 0, None),
        ("mousePressed", 10., 20., "left", 1, Some(1)),
        ("mouseMoved", 30., 20., "left", 1, None),
        ("mouseReleased", 30., 20., "left", 0, Some(1)),
    ];
    assert_pointer_trace(&f, &expected);
    assert_eq!(
        f.state.mouse_state().unwrap().buttons,
        1,
        "unacknowledged cleanup is not released input"
    );
    assert_eq!(journal.snapshot().input_debt, 1);
    assert!(!f
        .replies
        .lock()
        .unwrap()
        .iter()
        .any(|entry| entry["request"]["id"] == release["id"]));
    f.page
        .client
        .send_command_no_params("Browser.getVersion", None)
        .await
        .unwrap();
    let failure = action.await.unwrap_err();
    assert_eq!(failure.error, ProtocolError::Cancelled);
    assert_eq!(failure.effects, Effects::Unknown);
    assert!(!failure.cleanup_failed);
    assert_pointer_trace(&f, &expected);
    for request in mouse_inputs(&f) {
        exact_pointer_ack(&f, &request);
    }
    assert_eq!(
        exact_pointer_ack(&f, &release)["heldUntilRequest"]["method"],
        "Browser.getVersion"
    );
    assert_pointer_settled(&f, &ledger, &journal);
    owner.seal();
    owner.drain().await.unwrap();
}

fn mouse_inputs(f: &Fixture) -> Vec<Value> {
    f.inputs().into_iter().filter(|request| request["method"] == "Input.dispatchMouseEvent").collect()
}

fn allowed_pointer_command(request: &Value) -> bool {
    match request["method"].as_str().unwrap() {
        "Input.dispatchMouseEvent" => request["sessionId"] == "page",
        "Browser.getVersion" => request.get("sessionId").is_none(),
        "Input.setInterceptDrags" => request["sessionId"] == "page" && request["params"]["enabled"].is_boolean(),
        "Page.createIsolatedWorld" => request["sessionId"] == "page"
            && request["params"]["frameId"] == "main"
            && request["params"]["worldName"] == "agent-browser-native-observation",
        "Runtime.evaluate" => request["sessionId"] == "page"
            && request["params"]["expression"] == format!("({})()", super::super::point_drag::CREATE_MOVE_PROBE)
            && request["params"]["contextId"] == 1
            && request["params"]["objectGroup"] == "native-point-drag-1-1-0",
        "Runtime.callFunctionOn" => request["sessionId"] == "page"
            && request["params"]["objectId"] == "point-move-probe"
            && matches!(request["params"]["functionDeclaration"].as_str(),
                Some("function(){return this.arm()}" | "function(){return this.finish()}" | "function(){return this.dispose()}")),
        "Runtime.releaseObjectGroup" => request["sessionId"] == "page"
            && request["params"]["objectGroup"] == "native-point-drag-1-1-0",
        _ => false,
    }
}

// Protocol fixture, NOT renderer behavior evidence: a negative receipt is only
// returned after this peer actually received the corresponding held mouse move.
#[derive(Default)]
pub(super) struct PointProbePeer {
    created: bool,
    armed: bool,
    moved: bool,
    intercept: bool,
    disposed: bool,
}
impl PointProbePeer {
    pub(super) fn reply(&mut self, mode: &str, request: &Value) -> Option<Value> {
        if !is_swipe_mode(mode) || mode == CAPACITY_MODE { return None; }
        let method = request["method"].as_str().unwrap();
        let p = &request["params"];
        match method {
            "Runtime.evaluate" if p["objectGroup"] == "native-point-drag-1-1-0" => {
                assert!(allowed_pointer_command(request));
                assert!(!self.created);
                self.created = true;
                Some(json!({"result":{"type":"object","objectId":"point-move-probe"}}))
            }
            "Runtime.callFunctionOn" if p["objectId"] == "point-move-probe" => {
                assert!(allowed_pointer_command(request));
                assert!(self.created && !self.disposed);
                match p["functionDeclaration"].as_str().unwrap() {
                    "function(){return this.arm()}" => {
                        assert!(!self.armed);
                        self.armed = true; self.moved = false;
                        Some(json!({"result":{"value":true}}))
                    }
                    "function(){return this.finish()}" => {
                        assert!(self.armed && self.moved && self.intercept);
                        self.armed = false;
                        Some(json!({"result":{"value":if html5_mode(mode) { "drag" } else { "no-drag" }}}))
                    }
                    "function(){return this.dispose()}" => {
                        assert!(!self.intercept, "disable must precede observer teardown");
                        self.armed = false; self.disposed = true;
                        Some(json!({"result":{"value":true}}))
                    }
                    _ => unreachable!(),
                }
            }
            "Input.setInterceptDrags" => {
                assert!(allowed_pointer_command(request));
                let enabled = p["enabled"].as_bool().unwrap();
                // A known enable ErrorAck does not simulate an enabled browser.
                if mode != ENABLE_REJECT_MODE || !enabled { self.intercept = enabled; }
                if enabled { assert!(self.armed); }
                Some(json!({}))
            }
            "Input.dispatchMouseEvent" if p["type"] == "mouseMoved" && p["buttons"] == 1 => {
                assert!(self.armed && self.intercept);
                // The peer rejects this command before any trusted move receipt.
                if mode != MOVE_REJECT_MODE { self.moved = true; }
                None
            }
            "Runtime.releaseObjectGroup" if p["objectGroup"] == "native-point-drag-1-1-0" => {
                assert!(self.disposed);
                Some(json!({}))
            }
            _ => None,
        }
    }
}

pub(super) fn html5_mode(mode: &str) -> bool {
    matches!(mode, HTML5_EARLY_MODE | HTML5_LATE_MODE | HTML5_REJECT_MODE | MOVE_OWN_ERROR_MODE)
}
pub(super) fn native_drag_data() -> Value {
    json!({"items":[{"mimeType":"text/plain","data":"native-fixture-payload"}],"dragOperationsMask":1})
}
pub(super) fn native_drag_event() -> Value {
    json!({"method":"Input.dragIntercepted","sessionId":"page","params":{"data":native_drag_data()}})
}
pub(super) fn intercept_event(mode: &str, request: &Value, after_ack: bool) -> bool {
    html5_mode(mode) && (mode == HTML5_LATE_MODE) == after_ack
        && request["method"] == "Input.dispatchMouseEvent"
        && request["params"]["type"] == "mouseMoved"
        && request["params"]["buttons"] == 1
}

fn html5_protocol(f: &Fixture, failed: bool) {
    let mouse = mouse_inputs(f);
    let business_mouse: Vec<_> = mouse.iter().filter(|r| r["params"]["type"] != "mouseReleased")
        .map(|r| (r["params"]["type"].as_str().unwrap(), r["params"]["x"].as_f64().unwrap(), r["params"]["y"].as_f64().unwrap())).collect();
    assert_eq!(business_mouse, [("mouseMoved",10.,20.),("mousePressed",10.,20.),("mouseMoved",60.,20.)]);
    assert_eq!(mouse.iter().filter(|r| r["params"]["type"] == "mouseReleased").count(), usize::from(failed));
    let inputs = f.inputs();
    let drag: Vec<_> = inputs.iter().filter(|r| r["method"] == "Input.dispatchDragEvent").collect();
    let types: Vec<_> = drag.iter().map(|r| r["params"]["type"].as_str().unwrap()).collect();
    assert_eq!(types, if failed { vec!["dragEnter","dragOver","drop","dragCancel"] } else { vec!["dragEnter","dragOver","drop"] });
    for (index, request) in drag.iter().enumerate() {
        assert_eq!(request["sessionId"], "page");
        if index < 3 {
            assert_eq!(request["params"]["data"], native_drag_data());
            assert_eq!(request["params"]["x"].as_f64(), Some(if index == 0 {60.} else {110.}));
            assert_eq!(request["params"]["y"].as_f64(), Some(20.));
        }
    }
    assert!(f.log.lock().unwrap().iter().all(|r| allowed_pointer_command(r) || r["method"] == "Input.dispatchDragEvent"));
}

// Controlled transport positives, not a substitute for the unchanged real-browser board test.
#[tokio::test]
async fn direct_point_html5_early_and_late_interception_wait_for_exact_drop_ack() {
    for mode in [HTML5_EARLY_MODE, HTML5_LATE_MODE] {
        let (f, ledger, journal, owner, _notices) = owned_swipe_fixture(mode).await;
        let original_deadline = f.op.deadline;
        let args = json!({"identityScope":"scope","point":{"x":10,"y":20},"action":{"kind":"swipeTo","target":{"x":110,"y":20}}});
        let action = execute_original_pointer(&f, Some(&owner), &journal, &args);
        tokio::pin!(action);
        let drop_request = tokio::select! {
            result = &mut action => panic!("completed before exact drop ACK: {result:?}"),
            held = wait_for_held_pointer_request(&f, mode) => held,
        };
        assert!(tokio::time::timeout(Duration::from_millis(5), &mut action).await.is_err());
        assert!(!f.replies.lock().unwrap().iter().any(|r| r["request"]["id"] == drop_request["id"]));
        html5_protocol(&f, false);
        f.page.client.send_command_no_params("Browser.getVersion", None).await.unwrap();
        assert_eq!(action.await.unwrap(), Value::Null);
        assert_eq!(f.op.deadline, original_deadline);
        assert_eq!(exact_pointer_ack(&f, &drop_request)["heldUntilRequest"]["method"], "Browser.getVersion");
        html5_protocol(&f, false);
        assert_pointer_settled(&f, &ledger, &journal);
        owner.seal(); owner.drain().await.unwrap();
    }
}

#[tokio::test]
async fn direct_point_html5_rejected_drop_is_failure_and_cleans_own_drag_once() {
    let (f, ledger, journal, owner, _notices) = owned_swipe_fixture(HTML5_REJECT_MODE).await;
    let args = json!({"identityScope":"scope","point":{"x":10,"y":20},"action":{"kind":"swipeTo","target":{"x":110,"y":20}}});
    let failure = execute_original_pointer(&f, Some(&owner), &journal, &args).await.unwrap_err();
    assert_eq!(failure.error, ProtocolError::BrowserFailure);
    assert_eq!(failure.effects, Effects::Unknown);
    assert!(!failure.cleanup_failed, "known application ErrorAck must not invent a cleanup failure");
    html5_protocol(&f, true);
    let log = f.log.lock().unwrap().clone();
    let drop_request = log.iter().find(|r| r["params"]["type"] == "drop").unwrap();
    let reply = f.replies.lock().unwrap().iter().find(|r| r["request"]["id"] == drop_request["id"]).unwrap().clone();
    assert!(reply["reply"].get("error").is_some());
    let kinds: Vec<_> = log.iter().filter_map(|r| r["params"]["type"].as_str()).collect();
    let cancel = kinds.iter().position(|kind| *kind == "dragCancel").unwrap();
    let release = kinds.iter().position(|kind| *kind == "mouseReleased").unwrap();
    assert!(cancel < release);
    assert_eq!(f.state.mouse_state().unwrap().buttons, 0);
    // The original application error survives independently of acknowledged
    // observer disposal and input cleanup; it must not become CleanupFailed.
    assert_eq!(log.iter().filter(|r| r["params"]["functionDeclaration"] == "function(){return this.dispose()}").count(), 1);
    assert_eq!(log.iter().filter(|r| r["method"] == "Runtime.releaseObjectGroup").count(), 1);
    assert_eq!(ledger.snapshot().object_debt, 0);
    assert_eq!(journal.snapshot().input_debt, 0);
    owner.seal(); owner.drain().await.unwrap();
}

pub(super) fn capacity_frame_tree() -> Value {
    let children: Vec<_> = (0..32).map(|index| json!({"frame":{
        "id":format!("capacity-{index:02}"),"parentId":"main","loaderId":format!("capacity-doc-{index}"),"url":"about:blank"
    }})).collect();
    json!({"frameTree":{"frame":{"id":"main","loaderId":"doc","url":"about:blank"},"childFrames":children}})
}
pub(super) fn probe_context(mode: &str, request: &Value) -> i64 {
    if mode != CAPACITY_MODE || request["params"]["frameId"] == "main" { return 1; }
    request["params"]["frameId"].as_str().unwrap().strip_prefix("capacity-").unwrap().parse::<i64>().unwrap() + 2
}
#[derive(Default)]
pub(super) struct CapacityProbePeer {
    objects: std::collections::BTreeMap<String, (String, bool, bool)>,
}
impl CapacityProbePeer {
    pub(super) fn reply(&mut self, mode: &str, request: &Value) -> Option<Value> {
        if mode != CAPACITY_MODE { return None; }
        let p = &request["params"];
        match request["method"].as_str().unwrap() {
            "Runtime.evaluate" if p["objectGroup"].as_str().is_some_and(|g| g.starts_with("native-point-drag-")) => {
                assert_eq!(request["sessionId"], "page");
                assert_eq!(p["expression"], format!("({})()", super::super::point_drag::CREATE_MOVE_PROBE));
                assert_eq!(p["returnByValue"], false);
                let group = p["objectGroup"].as_str().unwrap().to_owned();
                let object = format!("capacity-probe-{}", self.objects.len());
                assert!(self.objects.insert(object.clone(), (group, false, false)).is_none());
                Some(json!({"result":{"type":"object","objectId":object}}))
            }
            "Runtime.callFunctionOn" if p["objectId"].as_str().is_some_and(|id| id.starts_with("capacity-probe-")) => {
                assert_eq!(p["functionDeclaration"], "function(){return this.dispose()}", "capacity rejection occurs before observer arm or press");
                let (_, disposed, released) = self.objects.get_mut(p["objectId"].as_str().unwrap()).unwrap();
                assert!(!*disposed && !*released);
                *disposed = true;
                Some(json!({"result":{"value":true}}))
            }
            "Runtime.releaseObjectGroup" if p["objectGroup"].as_str().is_some_and(|g| g.starts_with("native-point-drag-")) => {
                let (_, disposed, released) = self.objects.values_mut().find(|(group, _, _)| p["objectGroup"].as_str() == Some(group.as_str())).unwrap();
                assert!(*disposed && !*released);
                *released = true;
                Some(json!({}))
            }
            _ => None,
        }
    }
}

async fn unacknowledged_capacity_creation(f: &Fixture) -> Value {
    loop {
        let log = f.log.lock().unwrap().clone();
        let replies = f.replies.lock().unwrap().clone();
        if let Some(request) = log.iter().find(|r| holds_pointer_reply(CAPACITY_MODE, r)
            && !replies.iter().any(|reply| reply["request"]["id"] == r["id"])) {
            return request.clone();
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[tokio::test]
async fn direct_point_existing_object_capacity_rejects_before_press_and_cleans_every_observer() {
    let (f, ledger, journal, owner, _notices) = owned_swipe_fixture(CAPACITY_MODE).await;
    // The shared one-frame geometry setup must not shrink the action's actual
    // enrolled frame inventory. This reads the real enrollment capability.
    assert_eq!(owner.capture_point_drag_realms(&f.page, &f.op).unwrap().bindings().len(), 33);
    let original_deadline = f.op.deadline;
    let args = json!({"identityScope":"scope","point":{"x":10,"y":20},"action":{"kind":"swipeTo","target":{"x":110,"y":20}}});
    let action = execute_original_pointer(&f, Some(&owner), &journal, &args);
    tokio::pin!(action);
    let mut peak = 0;
    let mut creations = Vec::new();
    let failure = loop {
        let request = tokio::select! {
            result = &mut action => break result.expect_err("33 enrolled realms must not evade the existing object capacity"),
            request = unacknowledged_capacity_creation(&f) => request,
        };
        assert!(creations.iter().all(|id| id != &request["id"]), "one creation ACK per original request");
        creations.push(request["id"].clone());
        let count = ledger.snapshot().object_debt;
        peak = peak.max(count);
        assert!(count <= client_debt::MAX_OBJECT_DEBT);
        assert!(mouse_inputs(&f).is_empty(), "probe setup must fail before source move or press");
        f.page.client.send_command_no_params("Browser.getVersion", None).await.unwrap();
        exact_pointer_ack(&f, &request);
    };
    assert_eq!(failure.error, ProtocolError::CapacityExceeded);
    assert_eq!(failure.effects, Effects::NotDispatched);
    assert!(!failure.cleanup_failed);
    assert_eq!(f.op.deadline, original_deadline);
    assert_eq!(client_debt::MAX_OBJECT_DEBT, 32);
    assert_eq!(peak, 32, "use the actual ledger capacity, not a new fixed frame cap");
    assert!(!creations.is_empty() && creations.len() < 33);
    let log = f.log.lock().unwrap().clone();
    assert!(mouse_inputs(&f).is_empty());
    assert!(!log.iter().any(|r| r["method"] == "Input.setInterceptDrags" || r["method"] == "Input.dispatchDragEvent"));
    let disposed: Vec<_> = log.iter().filter(|r| r["params"]["functionDeclaration"] == "function(){return this.dispose()}").collect();
    let released: Vec<_> = log.iter().filter(|r| r["method"] == "Runtime.releaseObjectGroup").collect();
    assert_eq!(disposed.len(), creations.len());
    assert_eq!(released.len(), creations.len());
    for request in disposed.into_iter().chain(released) { exact_pointer_ack(&f, request); }
    let state = ledger.snapshot();
    assert_eq!(state.object_debt, 0);
    assert_eq!(state.input_debt, 0);
    assert_eq!(state.outstanding_commands, 0);
    assert!(!state.integrity_lost);
    assert_eq!(journal.snapshot().object_debt, 0);
    assert_eq!(journal.snapshot().input_debt, 0);
    assert_eq!(f.state.mouse_state().unwrap().buttons, 0);
    owner.seal(); owner.drain().await.unwrap();
}

pub(super) fn known_input_error(mode: &str, request: &Value) -> bool {
    (mode == ENABLE_REJECT_MODE && request["method"] == "Input.setInterceptDrags"
        && request["params"]["enabled"] == true)
        || (matches!(mode, MOVE_REJECT_MODE | MOVE_OWN_ERROR_MODE) && request["method"] == "Input.dispatchMouseEvent"
            && request["params"]["type"] == "mouseMoved" && request["params"]["buttons"] == 1)
}

async fn assert_known_input_error_preserves_observation_evidence(mode: &'static str) {
    let (f, ledger, journal, owner, _notices) = owned_swipe_fixture(mode).await;
    let original_deadline = f.op.deadline;
    let args = json!({"identityScope":"scope","point":{"x":10,"y":20},
        "action":{"kind":"swipeTo","target":{"x":110,"y":20}}});
    let failure = execute_original_pointer(&f, Some(&owner), &journal, &args).await.unwrap_err();
    assert_eq!(failure.error, ProtocolError::BrowserFailure);
    assert_eq!(failure.effects, Effects::Unknown);
    // An ErrorAck is terminal, but is not a passive no-drag receipt. Only the
    // no-move branch or an actual own receipt plus cancellation proves cleanup.
    assert_eq!(failure.cleanup_failed, mode == MOVE_REJECT_MODE);
    assert_eq!(f.op.deadline, original_deadline);
    let log = f.log.lock().unwrap().clone();
    assert!(log.iter().all(|r| allowed_pointer_command(r) || (mode == MOVE_OWN_ERROR_MODE && r["method"] == "Input.dispatchDragEvent")));
    let rejected: Vec<_> = log.iter().filter(|request| known_input_error(mode, request)).collect();
    assert_eq!(rejected.len(), 1, "the failed application command is never replayed");
    let replies = f.replies.lock().unwrap().clone();
    let errors: Vec<_> = replies.iter().filter(|r| r["reply"].get("error").is_some()).collect();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["request"]["id"], rejected[0]["id"]);
    assert_eq!(errors[0]["reply"]["id"], rejected[0]["id"]);
    assert_eq!(errors[0]["reply"]["sessionId"], "page");
    assert_eq!(errors[0]["reply"]["error"]["code"], -32000);
    for request in log.iter().filter(|request| request["id"] != rejected[0]["id"]) {
        exact_pointer_ack(&f, request);
    }
    let mouse = mouse_inputs(&f);
    let held_moves: Vec<_> = mouse.iter().filter(|r| r["params"]["type"] == "mouseMoved" && r["params"]["buttons"] == 1).collect();
    assert_eq!(held_moves.len(), usize::from(mode != ENABLE_REJECT_MODE));
    assert_eq!(mouse[0]["params"]["type"], "mouseMoved");
    assert_eq!(mouse[0]["params"]["x"].as_f64(), Some(10.));
    assert_eq!(mouse[0]["params"]["y"].as_f64(), Some(20.));
    assert_eq!(mouse[1]["params"]["type"], "mousePressed");
    if mode != ENABLE_REJECT_MODE {
        assert_eq!(held_moves[0]["params"]["x"].as_f64(), Some(60.));
        assert_eq!(held_moves[0]["params"]["y"].as_f64(), Some(20.));
    }
    assert_eq!(mouse.iter().filter(|r| r["params"]["type"] == "mouseReleased").count(), 1);
    assert_eq!(mouse.len(), if mode != ENABLE_REJECT_MODE { 4 } else { 3 });
    let drag: Vec<_> = log.iter().filter(|r| r["method"] == "Input.dispatchDragEvent").collect();
    if mode == MOVE_OWN_ERROR_MODE {
        assert_eq!(drag.len(), 1);
        assert_eq!(drag[0]["params"]["type"], "dragCancel");
    } else {
        assert!(drag.is_empty(), "no own receipt means no dragCancel authority");
    }
    assert!(!log.iter().any(|r| r["params"]["functionDeclaration"] == "function(){return this.finish()}"));
    let enables: Vec<_> = log.iter().enumerate().filter(|(_,r)| r["method"] == "Input.setInterceptDrags" && r["params"]["enabled"] == true).collect();
    let disables: Vec<_> = log.iter().enumerate().filter(|(_,r)| r["method"] == "Input.setInterceptDrags" && r["params"]["enabled"] == false).collect();
    let disposals: Vec<_> = log.iter().enumerate().filter(|(_,r)| r["params"]["functionDeclaration"] == "function(){return this.dispose()}").collect();
    let releases: Vec<_> = log.iter().enumerate().filter(|(_,r)| r["method"] == "Runtime.releaseObjectGroup").collect();
    assert_eq!(enables.len(), 1);
    assert_eq!(disables.len(), 1);
    assert_eq!(disposals.len(), 1);
    assert_eq!(releases.len(), 1);
    let mouse_release = log.iter().position(|r| r["params"]["type"] == "mouseReleased").unwrap();
    assert!(enables[0].0 < disables[0].0 && disables[0].0 < mouse_release);
    assert!(mouse_release < disposals[0].0 && disposals[0].0 < releases[0].0);
    let settled = journal.snapshot();
    assert!(settled.mutation_dispatched);
    assert_eq!(settled.input_debt, 0);
    assert_eq!(settled.object_debt, 0);
    assert!(!settled.integrity_lost);
    let settled = ledger.snapshot();
    assert_eq!(settled.input_debt, 0);
    assert_eq!(settled.object_debt, 0);
    assert_eq!(settled.outstanding_commands, 0);
    assert!(!settled.integrity_lost);
    if !failure.cleanup_failed { assert_eq!(f.state.mouse_state().unwrap().buttons, 0); }
    owner.seal(); owner.drain().await.unwrap();
}

#[tokio::test]
async fn direct_point_enable_error_ack_before_held_move_preserves_primary_and_cleans() {
    assert_known_input_error_preserves_observation_evidence(ENABLE_REJECT_MODE).await;
}
#[tokio::test]
async fn direct_point_held_move_error_ack_without_drag_receipt_preserves_unknown() {
    assert_known_input_error_preserves_observation_evidence(MOVE_REJECT_MODE).await;
}

#[tokio::test]
async fn direct_point_held_move_error_ack_with_own_receipt_cleans_without_replay() {
    assert_known_input_error_preserves_observation_evidence(MOVE_OWN_ERROR_MODE).await;
}
