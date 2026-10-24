use super::*;

// This prefix already receives session-correct CDP ACKs in the existing peer.
// Only this new mode adds observational timestamps to its private request log.
pub(super) const MODE: &str = "direct-point-original-clicks";

pub(super) fn record_receipt(request: &mut Value, elapsed: Duration) {
    request["directPointPeerReceiptMicros"] = json!(
        u64::try_from(elapsed.as_micros()).expect("fixture clock fits u64 microseconds")
    );
}

// Reproduce the existing direct-point fixture's exact attachment and guards.
// These are real native input calls over mock CDP, with no DOM/matcher reply.
async fn assert_original_click(action: Value, button: &str, count: i32, hold_ms: u64) {
    let mut f = fixture(MODE).await;
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
