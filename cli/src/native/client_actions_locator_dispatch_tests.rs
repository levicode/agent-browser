use super::*;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

// These tests exercise ClientActions::execute("browser.perform") over the
// existing mock CDP connection. These private modes leave all existing fixture
// modes unchanged: one records peer receipt time, and two execute the actual
// emitted function to produce their CDP result and inspect the scripted DOM.
pub(super) const CLOCK_MODE: &str = "legacy-locator-dispatch";
const CLEAR_MODE: &str = "legacy-locator-clear";
const SELECT_MODE: &str = "legacy-locator-select-index";

pub(super) async fn observed_request(mode: &str, request: &Value, elapsed: Duration) -> Value {
    let mut observed = request.clone();
    if mode == CLOCK_MODE {
        observed["legacyObservedAtMicros"] =
            json!(u64::try_from(elapsed.as_micros()).expect("fixture clock fits u64 microseconds"));
    }
    if request["method"] == "Runtime.callFunctionOn" {
        let source = request["params"]["functionDeclaration"].as_str();
        let kind = match mode {
            CLEAR_MODE if source == Some(PREPARE_FILL) => Some("input"),
            SELECT_MODE if source == Some(SELECT_OPTION) => Some("select"),
            _ => None,
        };
        if let Some(kind) = kind {
            observed["legacyScriptResult"] = evaluate_emitted_function(request, kind).await;
        }
    }
    observed
}

// This is a scripted DOM, not Chromium. The function and arguments come from
// the real native request. No copy or replacement of the selection/fill
// algorithm lives here, and a canned CDP success cannot satisfy the assertions.
const SCRIPTED_DOM: &str = r#"
const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const document = {};
globalThis.document = document;
globalThis.HTMLInputElement = class {};
globalThis.HTMLTextAreaElement = class {};
globalThis.HTMLSelectElement = class {};
const events = [];
const node = input.kind === 'select'
  ? Object.assign(new HTMLSelectElement(), {
      options: [
        { value: '2', label: 'Value decoy', selected: true },
        { value: 'middle', label: '2', selected: false },
        { value: 'third-value', label: 'Third label', selected: false },
      ],
    })
  : Object.assign(new HTMLInputElement(), {
      type: 'text', value: 'populated field', readOnly: false,
      focused: false, selected: false,
      focus() { this.focused = true; },
      select() { this.selected = true; },
    });
Object.assign(node, {
  isConnected: true, ownerDocument: document,
  matches(selector) {
    if (selector !== ':disabled') throw new Error('unexpected selector');
    return false;
  },
  dispatchEvent(event) {
    events.push([event.type, event.bubbles, event.composed]);
    return true;
  },
});
const action = eval('(' + input.functionDeclaration + ')');
const result = action.apply(node, input.arguments.map(argument => argument.value));
process.stdout.write(JSON.stringify({
  result, events,
  selected: node.options?.map(option => option.selected),
  selectedValues: node.options?.filter(option => option.selected).map(option => option.value),
  focused: node.focused, fieldSelected: node.selected, fieldValue: node.value,
}));
"#;

async fn evaluate_emitted_function(request: &Value, kind: &str) -> Value {
    let input = json!({
        "kind": kind,
        "functionDeclaration": request["params"]["functionDeclaration"],
        "arguments": request["params"]["arguments"],
    });
    let mut child = Command::new("node")
        .args(["-e", SCRIPTED_DOM])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("these tests require an already-installed Node runtime; never download one");
    let mut stdin = child.stdin.take().expect("script input");
    let mut stdout = child.stdout.take().expect("script output");
    let mut stderr = child.stderr.take().expect("script errors");
    let input = input.to_string().into_bytes();
    // Bound this helper below the fixture's unchanged 5s operation lease.
    // Read both pipes while writing so backpressure cannot stall the peer.
    let completed = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::try_join!(
            async move {
                stdin.write_all(&input).await?;
                drop(stdin);
                Ok::<_, std::io::Error>(())
            },
            async move {
                let mut bytes = Vec::new();
                stdout.read_to_end(&mut bytes).await?;
                Ok::<_, std::io::Error>(bytes)
            },
            async move {
                let mut bytes = Vec::new();
                stderr.read_to_end(&mut bytes).await?;
                Ok::<_, std::io::Error>(bytes)
            },
            child.wait(),
        )
    })
    .await;
    let (stdout, stderr, status) = match completed {
        Ok(Ok(((), stdout, stderr, status))) => (stdout, stderr, status),
        failure => {
            // Only this owned Node child is terminated. Reap it before failing;
            // kill_on_drop also guards cancellation of the fixture task.
            let killed = child.start_kill();
            let reaped = child
                .wait()
                .await
                .expect("owned Node fixture child must be reaped after failure");
            panic!("Node fixture failed: {failure:?}; kill={killed:?}; reap={reaped:?}");
        }
    };
    assert!(
        status.success(),
        "native-emitted script failed: {}",
        String::from_utf8_lossy(&stderr)
    );
    serde_json::from_slice(&stdout).unwrap()
}

#[tokio::test]
async fn locator_long_press_witnesses_original_900_ms_hold() {
    let f = fixture(CLOCK_MODE).await;
    ClientActions::default()
        .execute(
            f.context(),
            "browser.perform",
            &json!({
                "identityScope": "scope", "ref": { "id": "@e1", "revision": "1" },
                "action": { "kind": "longPress", "durationMs": 900 }
            }),
        )
        .await
        .unwrap();
    let inputs = f.inputs();
    let presses: Vec<_> = inputs
        .iter()
        .enumerate()
        .filter(|(_, request)| request["params"]["type"] == "mousePressed")
        .collect();
    let releases: Vec<_> = inputs
        .iter()
        .enumerate()
        .filter(|(_, request)| request["params"]["type"] == "mouseReleased")
        .collect();
    assert_eq!(presses.len(), 1);
    assert_eq!(releases.len(), 1);
    let (press_index, press) = presses[0];
    let (release_index, release) = releases[0];
    assert!(press_index < release_index);
    assert_eq!(press["params"]["button"], "left");
    assert_eq!(press["params"]["clickCount"], 1);
    assert_eq!(release["params"]["x"], press["params"]["x"]);
    assert_eq!(release["params"]["y"], press["params"]["y"]);
    assert_eq!(release["params"]["buttons"], 0);
    let down_us = press["legacyObservedAtMicros"].as_u64().unwrap();
    let up_us = release["legacyObservedAtMicros"].as_u64().unwrap();
    // Real monotonic peer-receipt time, including loopback/scheduling latency.
    // No Tokio clock is paused or advanced, and the fixture keeps its 5s lease.
    assert!(
        up_us.checked_sub(down_us).unwrap() >= 900_000,
        "the actual native down/up interval must preserve the original 900ms hold"
    );
}

#[tokio::test]
async fn locator_clear_uses_exact_empty_value_then_fallback_delete() {
    let f = fixture(CLEAR_MODE).await;
    ClientActions::default()
        .execute(
            f.context(),
            "browser.perform",
            &json!({
                "identityScope": "scope", "ref": { "id": "@e1", "revision": "1" },
                "action": { "kind": "clear" }
            }),
        )
        .await
        .unwrap();
    let log = f.log.lock().unwrap();
    let preparations: Vec<_> = log
        .iter()
        .enumerate()
        .filter(|(_, request)| {
            request["method"] == "Runtime.callFunctionOn"
                && request["params"]["functionDeclaration"] == PREPARE_FILL
        })
        .collect();
    assert_eq!(preparations.len(), 1);
    let (prepare_index, preparation) = preparations[0];
    assert_eq!(preparation["params"]["arguments"], json!([{ "value": "" }]));
    let rendered = &preparation["legacyScriptResult"];
    assert_eq!(rendered["result"], json!({ "complete": false }));
    assert_eq!(rendered["focused"], true);
    assert_eq!(rendered["fieldSelected"], true);
    // Preparation selects the populated field. The following native Delete is
    // observed on CDP; this fixture does not simulate its renderer-side effect.
    assert_eq!(rendered["fieldValue"], "populated field");
    let deletes: Vec<_> = log
        .iter()
        .enumerate()
        .filter(|(_, request)| {
            request["method"] == "Input.dispatchKeyEvent" && request["params"]["key"] == "Delete"
        })
        .collect();
    assert_eq!(deletes.len(), 2);
    assert!(prepare_index < deletes[0].0);
    assert!(deletes[0].0 < deletes[1].0);
    assert_eq!(deletes[0].1["params"]["type"], "rawKeyDown");
    assert_eq!(deletes[1].1["params"]["type"], "keyUp");
    let inputs: Vec<_> = log
        .iter()
        .filter(|request| {
            request["method"]
                .as_str()
                .is_some_and(|method| method.starts_with("Input."))
        })
        .collect();
    assert_eq!(inputs, vec![deletes[0].1, deletes[1].1]);
    assert!(!log.iter().any(|request| {
        request["method"] == "Input.insertText"
            && request["params"]["text"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
    }));
}

#[tokio::test]
async fn locator_select_option_positive_index_two_executes_native_selection() {
    let f = fixture(SELECT_MODE).await;
    ClientActions::default()
        .execute(
            f.context(),
            "browser.perform",
            &json!({
                "identityScope": "scope", "ref": { "id": "@e1", "revision": "1" },
                "action": { "kind": "selectOption", "value": { "index": 2 } }
            }),
        )
        .await
        .unwrap();
    let log = f.log.lock().unwrap();
    let selections: Vec<_> = log
        .iter()
        .filter(|request| {
            request["method"] == "Runtime.callFunctionOn"
                && request["params"]["functionDeclaration"] == SELECT_OPTION
        })
        .collect();
    assert_eq!(selections.len(), 1);
    assert_eq!(
        selections[0]["params"]["arguments"],
        json!([{ "value": { "index": 2 } }])
    );
    let selected = &selections[0]["legacyScriptResult"];
    assert_eq!(selected["result"], true);
    assert_eq!(selected["selected"], json!([false, false, true]));
    assert_eq!(selected["selectedValues"], json!(["third-value"]));
    assert_eq!(
        selected["events"],
        json!([["input", true, true], ["change", true, false]])
    );
}
