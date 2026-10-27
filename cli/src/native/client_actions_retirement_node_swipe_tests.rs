use super::*;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

pub(super) const BLOCKED: &str = "retirement-node-swipe-blocked";
pub(super) const CENTRE: &str = "retirement-node-swipe-centre";
pub(super) const POINTER: &str = "retirement-node-swipe-pointer";
pub(super) const UNKNOWN: &str = "retirement-node-swipe-unknown";
pub(super) const ZERO: &str = "retirement-node-swipe-known-zero";
pub(super) const EDGE: &str = "retirement-node-swipe-right-edge";
pub(super) const COVERED: &str = "retirement-node-swipe-covered-pointer";
pub(super) const OVERFLOW: &str = "retirement-node-swipe-overflow-child";
pub(super) const IFRAME: &str = "retirement-node-swipe-iframe";
const RENDER: &str = "document.hidden?true:new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>resolve(true))))";

pub(super) fn is_mode(mode: &str) -> bool {
    matches!(
        mode,
        BLOCKED | CENTRE | POINTER | UNKNOWN | ZERO | EDGE | COVERED | OVERFLOW | IFRAME
    )
}
pub(super) fn holds_render(mode: &str, request: &Value) -> bool {
    is_mode(mode)
        && request["method"] == "Runtime.evaluate"
        && request["params"]["expression"] == RENDER
}
fn initial_pointer(mode: &str) -> Value {
    match mode {
        POINTER | COVERED | IFRAME => json!({"x":80,"y":70}),
        OVERFLOW => json!({"x":120,"y":50}),
        UNKNOWN => Value::Null,
        ZERO => json!({"x":0,"y":0}),
        EDGE => json!({"x":400,"y":150}),
        _ => json!({"x":800,"y":600}),
    }
}

pub(super) async fn observed_request(
    mode: &str,
    request: &Value,
    scrolled: bool,
    pointer: Option<(f64, f64)>,
) -> Value {
    let mut observed = request.clone();
    let source = request["params"]["functionDeclaration"]
        .as_str()
        .unwrap_or("");
    if request["method"] != "Runtime.callFunctionOn"
        || !source.contains("const rect=this.getBoundingClientRect()")
    {
        return observed;
    }
    assert_eq!(request["params"]["objectId"], "exact-node");
    let input = json!({"functionDeclaration":source,"arguments":request["params"]["arguments"],
        "offscreen":mode==BLOCKED && !scrolled,"initialPointer":initial_pointer(mode),
        "currentPointer":pointer.map(|(x,y)|json!({"x":x,"y":y})),"coverPointer":mode==COVERED,
        "overflowDescendant":mode==OVERFLOW,"iframe":mode==IFRAME});
    let mut child = Command::new("node")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/native-node-swipe-geometry.cjs"
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("installed Node is required; never download one");
    // Inherit the established environment, including RUST_MIN_STACK. No env_clear.
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let bytes = input.to_string().into_bytes();
    let completed = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::try_join!(
            async move {
                stdin.write_all(&bytes).await?;
                drop(stdin);
                Ok::<_, std::io::Error>(())
            },
            async move {
                let mut b = Vec::new();
                stdout.read_to_end(&mut b).await?;
                Ok::<_, std::io::Error>(b)
            },
            async move {
                let mut b = Vec::new();
                stderr.read_to_end(&mut b).await?;
                Ok::<_, std::io::Error>(b)
            },
            child.wait(),
        )
    })
    .await;
    let (stdout, stderr, status) = match completed {
        Ok(Ok(((), stdout, stderr, status))) => (stdout, stderr, status),
        failure => {
            let killed = child.start_kill();
            let reaped = child.wait().await.unwrap();
            panic!("owned scripted DOM failed: {failure:?}; kill={killed:?}; reap={reaped:?}");
        }
    };
    assert!(
        status.success(),
        "native-emitted geometry failed: {}",
        String::from_utf8_lossy(&stderr)
    );
    observed["nodeSwipeScript"] = serde_json::from_slice(&stdout).unwrap();
    observed
}

async fn setup(
    mode: &'static str,
) -> (
    Fixture,
    Arc<client_debt::OwnerDebtLedger>,
    OperationJournalHandle,
) {
    let (f, ledger, journal) = direct_point_clicks::owned_pointer_fixture(mode).await;
    if mode != UNKNOWN {
        journal.scope(ClientActions::default().execute(f.context(), "browser.pointer",
            &json!({"identityScope":"scope","point":initial_pointer(mode),"action":{"kind":"hover"}}))).await.unwrap();
        assert_eq!(
            f.state.known_pointer_position(&f.page, &f.op).unwrap(),
            Some((
                initial_pointer(mode)["x"].as_f64().unwrap(),
                initial_pointer(mode)["y"].as_f64().unwrap()
            ))
        );
    } else {
        assert_eq!(
            f.state.known_pointer_position(&f.page, &f.op).unwrap(),
            None
        );
    }
    let before = f.state.mouse_state().unwrap();
    println!(
        "RETIREMENT_NODE_SETUP {}",
        json!({"mode":mode,"initialPointer":initial_pointer(mode),"inputs":f.inputs(),"mouse":format!("{before:?}")})
    );
    f.log.lock().unwrap().clear();
    f.replies.lock().unwrap().clear();
    (f, ledger, journal)
}

async fn phase(
    f: &Fixture,
    ledger: &Arc<client_debt::OwnerDebtLedger>,
    journal: &OperationJournalHandle,
    mode: &'static str,
    action: Value,
    (delta, point): ((f64, f64), (f64, f64)),
    move_expected: bool,
) -> Vec<Value> {
    let start = f.log.lock().unwrap().len();
    let deadline = f.op.deadline;
    // This is the fixture's existing independent5s component lease, never an
    // altered7ms adapter operation or a7ms end-to-end success claim.
    let args = json!({"identityScope":"scope","ref":{"id":"@e1","revision":"1"},"action":action});
    let actions = ClientActions::default();
    let producer = journal.scope(actions.execute(f.context(), "browser.perform", &args));
    tokio::pin!(producer);
    let render = tokio::select! {
        result=&mut producer => panic!("native node swipe settled before render ACK: {result:?}"),
        render=async {
            tokio::time::timeout(Duration::from_secs(1),async {
                loop {
                    if let Some(request)=f.log.lock().unwrap().iter().skip(start).find(|r|holds_render(mode,r)).cloned(){break request;}
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }).await.expect("actual node producer must reach render within existing fixture gate")
        } => render,
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(5), &mut producer)
            .await
            .is_err()
    );
    let pending = f.log.lock().unwrap()[start..].to_vec();
    let wheels: Vec<_> = pending
        .iter()
        .filter(|r| {
            r["method"] == "Input.dispatchMouseEvent" && r["params"]["type"] == "mouseWheel"
        })
        .collect();
    assert_eq!(wheels.len(), 1);
    let wheel = wheels[0];
    assert_eq!(wheel["sessionId"], "page");
    assert_eq!(wheel["params"]["x"].as_f64(), Some(point.0));
    assert_eq!(wheel["params"]["y"].as_f64(), Some(point.1));
    assert_eq!(wheel["params"]["deltaX"].as_f64(), Some(delta.0));
    assert_eq!(wheel["params"]["deltaY"].as_f64(), Some(delta.1));
    let move_index = pending.iter().rposition(|r| {
        r["method"] == "Input.dispatchMouseEvent" && r["params"]["type"] == "mouseMoved"
    });
    let wheel_index = pending.iter().position(|r| r["id"] == wheel["id"]).unwrap();
    let render_index = pending
        .iter()
        .position(|r| r["id"] == render["id"])
        .unwrap();
    assert!(wheel_index < render_index);
    if move_expected {
        let movement = move_index.expect("outside/unknown pointer must still be aimed");
        assert!(movement < wheel_index);
        assert_eq!(pending[movement]["params"]["x"].as_f64(), Some(point.0));
        assert_eq!(pending[movement]["params"]["y"].as_f64(), Some(point.1));
    } else {
        assert!(
            move_index.is_none(),
            "known current-point wheel needs no repositioning"
        );
    }
    let wheel_ack = direct_point_clicks::exact_pointer_ack(f, wheel);
    assert!(f
        .replies
        .lock()
        .unwrap()
        .iter()
        .all(|r| r["request"]["id"] != render["id"]));
    assert_eq!(render["params"]["awaitPromise"], true);
    assert_eq!(render["params"]["returnByValue"], true);
    f.page
        .client
        .send_command_no_params("Browser.getVersion", None)
        .await
        .unwrap();
    assert_eq!(producer.await.unwrap(), Value::Null);
    assert_eq!(f.op.deadline, deadline);
    let render_ack = direct_point_clicks::exact_pointer_ack(f, &render);
    assert_eq!(
        render_ack["heldUntilRequest"]["method"],
        "Browser.getVersion"
    );
    let log = f.log.lock().unwrap()[start..].to_vec();
    for request in &log {
        direct_point_clicks::exact_pointer_ack(f, request);
    }
    if move_expected {
        assert!(log.iter().any(|r| r["method"] == "DOM.getBoxModel"));
    }
    let size = if mode == OVERFLOW {
        (100, 100)
    } else {
        (400, 300)
    };
    assert!(log
        .iter()
        .any(|r| r["nodeSwipeScript"]["result"]["width"] == size.0
            && r["nodeSwipeScript"]["result"]["height"] == size.1));
    assert!(log
        .iter()
        .filter(|r| r["method"] == "DOM.resolveNode")
        .all(|r| r["params"]["backendNodeId"] == 42));
    let debt = journal.snapshot();
    assert_eq!(debt.input_debt, 0);
    assert_eq!(debt.object_debt, 0);
    assert!(!debt.integrity_lost);
    assert_eq!(ledger.snapshot().outstanding_commands, 0);
    assert_eq!(f.state.mouse_state().unwrap().buttons, 0);
    println!(
        "RETIREMENT_NODE_PHASE {}",
        json!({"mode":mode,"args":args,"componentLeaseMs":5000,"adapterBudgetMs":7,
        "not7msEndToEndProof":true,"expectedDelta":[delta.0,delta.1],"expectedPoint":[point.0,point.1],"moveExpected":move_expected,"log":log,"replies":f.replies.lock().unwrap().clone(),
        "wheelAck":wheel_ack,"renderAck":render_ack,"inputDebt":debt.input_debt,"objectDebt":debt.object_debt})
    );
    log
}

#[tokio::test]
async fn node400x300_blocked_preaim_down_then_fast_left_waits_for_each_render() {
    let (f, ledger, journal) = setup(BLOCKED).await;
    let down = phase(
        &f,
        &ledger,
        &journal,
        BLOCKED,
        json!({"kind":"swipe","direction":"down"}),
        ((0., 150.), (200., 150.)),
        true,
    )
    .await;
    assert!(down
        .iter()
        .any(|r| r["nodeSwipeScript"]["offscreen"] == true));
    let scroll = down
        .iter()
        .position(|r| r["method"] == "DOM.scrollIntoViewIfNeeded")
        .unwrap();
    let movement = down
        .iter()
        .position(|r| r["method"] == "Input.dispatchMouseEvent")
        .unwrap();
    assert!(scroll < movement);
    phase(
        &f,
        &ledger,
        &journal,
        BLOCKED,
        json!({"kind":"swipe","direction":"left","momentum":"fast"}),
        ((-600., 0.), (200., 150.)),
        false,
    )
    .await;
}

#[tokio::test]
async fn node400x300_clear_centre_moves200_150_before_down150() {
    let (f, ledger, journal) = setup(CENTRE).await;
    phase(
        &f,
        &ledger,
        &journal,
        CENTRE,
        json!({"kind":"swipe","direction":"down"}),
        ((0., 150.), (200., 150.)),
        true,
    )
    .await;
}

#[tokio::test]
async fn node400x300_pointer80_70_preserves_position_across_directions() {
    let (f, ledger, journal) = setup(POINTER).await;
    phase(
        &f,
        &ledger,
        &journal,
        POINTER,
        json!({"kind":"swipe","direction":"down"}),
        ((0., 150.), (80., 70.)),
        false,
    )
    .await;
    phase(
        &f,
        &ledger,
        &journal,
        POINTER,
        json!({"kind":"swipe","direction":"left","momentum":"fast"}),
        ((-600., 0.), (80., 70.)),
        false,
    )
    .await;
}
#[tokio::test]
async fn node400x300_unknown_default_zero_still_aims_at_centre() {
    let (f, ledger, journal) = setup(UNKNOWN).await;
    phase(
        &f,
        &ledger,
        &journal,
        UNKNOWN,
        json!({"kind":"swipe","direction":"down"}),
        ((0., 150.), (200., 150.)),
        true,
    )
    .await;
    phase(
        &f,
        &ledger,
        &journal,
        UNKNOWN,
        json!({"kind":"swipe","direction":"left","momentum":"fast"}),
        ((-600., 0.), (200., 150.)),
        false,
    )
    .await;
}
#[tokio::test]
async fn node400x300_known_zero_is_distinct_from_unknown_zero() {
    let (f, ledger, journal) = setup(ZERO).await;
    phase(
        &f,
        &ledger,
        &journal,
        ZERO,
        json!({"kind":"swipe","direction":"down"}),
        ((0., 150.), (0., 0.)),
        false,
    )
    .await;
}
#[tokio::test]
async fn node400x300_pointer_on_right_edge_still_aims_at_centre() {
    let (f, ledger, journal) = setup(EDGE).await;
    phase(
        &f,
        &ledger,
        &journal,
        EDGE,
        json!({"kind":"swipe","direction":"down"}),
        ((0., 150.), (200., 150.)),
        true,
    )
    .await;
}
#[tokio::test]
async fn node400x300_covered_pointer_does_not_bypass_centre_targeting() {
    let (f, ledger, journal) = setup(COVERED).await;
    phase(
        &f,
        &ledger,
        &journal,
        COVERED,
        json!({"kind":"swipe","direction":"down"}),
        ((0., 150.), (200., 150.)),
        true,
    )
    .await;
}
#[tokio::test]
async fn node100x100_overflow_child_keeps_hovered_pointer120_50() {
    let (f, ledger, journal) = setup(OVERFLOW).await;
    phase(
        &f,
        &ledger,
        &journal,
        OVERFLOW,
        json!({"kind":"swipe","direction":"down"}),
        ((0., 50.), (120., 50.)),
        false,
    )
    .await;
}
#[tokio::test]
async fn node400x300_iframe_uses_original_centre_targeting() {
    let (f, ledger, journal) = setup(IFRAME).await;
    phase(
        &f,
        &ledger,
        &journal,
        IFRAME,
        json!({"kind":"swipe","direction":"down"}),
        ((0., 150.), (200., 150.)),
        true,
    )
    .await;
}
#[tokio::test]
async fn node400x300_explicit_hover_keeps_centre_mode_then_swipe_reuses_it() {
    let (f, ledger, journal) = setup(POINTER).await;
    journal.scope(ClientActions::default().execute(f.context(),"browser.perform",
        &json!({"identityScope":"scope","ref":{"id":"@e1","revision":"1"},"action":{"kind":"hover"}}))).await.unwrap();
    assert_eq!(
        f.state.known_pointer_position(&f.page, &f.op).unwrap(),
        Some((200., 150.))
    );
    assert!(f
        .inputs()
        .iter()
        .any(|request| request["params"]["type"] == "mouseMoved"
            && request["params"]["x"].as_f64() == Some(200.)
            && request["params"]["y"].as_f64() == Some(150.)));
    f.log.lock().unwrap().clear();
    f.replies.lock().unwrap().clear();
    phase(
        &f,
        &ledger,
        &journal,
        POINTER,
        json!({"kind":"swipe","direction":"down"}),
        ((0., 150.), (200., 150.)),
        false,
    )
    .await;
}
