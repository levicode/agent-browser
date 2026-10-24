use super::*;

// This prefix already receives session-correct CDP ACKs in the existing peer.
// These exact modes add observational timestamps to their private request log.
pub(super) const MODE: &str = "direct-point-original-clicks";
pub(super) const POINTER_MODE: &str = "direct-point-original-pointer";
pub(super) const PACED_MODE: &str = "direct-point-original-pointer-paced";
pub(super) const CANCEL_MODE: &str = "direct-point-original-pointer-cancel";
pub(super) const WHEEL_MODE: &str = "direct-point-original-pointer-wheel";

pub(super) fn is_pointer_mode(mode: &str) -> bool {
    matches!(mode, POINTER_MODE | PACED_MODE | CANCEL_MODE | WHEEL_MODE)
}

pub(super) fn holds_pointer_reply(mode: &str, request: &Value) -> bool {
    (mode == PACED_MODE
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
    let mut f = fixture(mode).await;
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
    let inputs = f.inputs();
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
        request["method"] == "Input.dispatchMouseEvent" || request["method"] == "Browser.getVersion"
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
        let (f, ledger, journal) = owned_pointer_fixture(POINTER_MODE).await;
        let result = execute_original_pointer(
            &f,
            &journal,
            &json!({
                "identityScope":"scope", "point":point, "action":action,
            }),
        )
        .await
        .unwrap();
        assert_eq!(result, Value::Null);
        assert_pointer_trace(&f, &expected);
        for request in f.inputs() {
            exact_pointer_ack(&f, &request);
        }
        assert_pointer_settled(&f, &ledger, &journal);
    }
}

#[tokio::test]
async fn direct_point_original_swipe_to_110_20_uses_midpoint() {
    let (f, ledger, journal) = owned_pointer_fixture(POINTER_MODE).await;
    let result = execute_original_pointer(
        &f,
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
    for request in f.inputs() {
        exact_pointer_ack(&f, &request);
    }
    assert_pointer_settled(&f, &ledger, &journal);
}

#[tokio::test]
async fn direct_point_original_swipe_to_70_20_paces_three_moves_over_48_ms() {
    let (f, ledger, journal) = owned_pointer_fixture(PACED_MODE).await;
    let args = json!({"identityScope":"scope", "point":{"x":10,"y":20},
        "action":{"kind":"swipeTo","target":{"x":70,"y":20},"durationMs":48}});
    let action = execute_original_pointer(&f, &journal, &args);
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
    let inputs = f.inputs();
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
}

#[tokio::test]
async fn direct_point_original_swipe_to_70_20_cancel_after_first_move_releases_once() {
    let (f, ledger, journal) = owned_pointer_fixture(CANCEL_MODE).await;
    let args = json!({"identityScope":"scope", "point":{"x":10,"y":20},
        "action":{"kind":"swipeTo","target":{"x":70,"y":20},"durationMs":48}});
    let action = execute_original_pointer(&f, &journal, &args);
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
    for request in f.inputs() {
        exact_pointer_ack(&f, &request);
    }
    assert_eq!(
        exact_pointer_ack(&f, &release)["heldUntilRequest"]["method"],
        "Browser.getVersion"
    );
    assert_pointer_settled(&f, &ledger, &journal);
}
