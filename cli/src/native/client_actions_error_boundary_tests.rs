use super::*;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

const PREFIX: &str = "preparation-fill-admissibility-";
pub(super) fn is_mode(mode: &str) -> bool {
    mode.starts_with(PREFIX)
}

// Scripted elements, not Chromium. Run the production function and arguments
// from each actual Runtime.callFunctionOn request. Never manufacture refusal.
const SCRIPTED_ELEMENT: &str = r#"
const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const calls = [];
const writes = [];
const document = {
  createRange() { calls.push('createRange'); return { selectNodeContents() { calls.push('selectNodeContents'); } }; },
  getSelection() { return { removeAllRanges() { calls.push('removeAllRanges'); }, addRange() { calls.push('addRange'); } }; },
};
globalThis.document = document;
globalThis.HTMLInputElement = class {};
globalThis.HTMLTextAreaElement = class {};
let kind = input.kind;
if (kind === 'race-readonly') kind = input.preflight ? 'input' : 'readonly';
let base;
if (['input', 'readonly', 'disabled'].includes(kind) || kind.startsWith('unsupported-')) base = new HTMLInputElement();
else if (kind === 'textarea') base = new HTMLTextAreaElement();
else if (kind === 'inherited-contenteditable') base = Object.create({ isContentEditable: true });
else base = {};
Object.assign(base, {
  isConnected: true, ownerDocument: document,
  readOnly: kind === 'readonly', type: kind.startsWith('unsupported-') ? kind.slice('unsupported-'.length) : 'text',
  matches(selector) {
    if (selector !== ':disabled') throw new Error('unexpected selector');
    return kind === 'disabled';
  },
  focus() { calls.push('focus'); },
  select() { calls.push('select'); },
  dispatchEvent(event) { calls.push(event.type); return true; },
});
if (kind !== 'inherited-contenteditable') base.isContentEditable = kind === 'contenteditable';
const node = new Proxy(base, {
  set(target, key, value) { writes.push(String(key)); return Reflect.set(target, key, value); },
  defineProperty(target, key, descriptor) { writes.push(String(key)); return Reflect.defineProperty(target, key, descriptor); },
  deleteProperty(target, key) { writes.push(String(key)); return Reflect.deleteProperty(target, key); },
});
const action = eval('(' + input.functionDeclaration + ')');
const result = action.apply(node, input.arguments.map(argument => argument.value));
process.stdout.write(JSON.stringify({ result, calls, writes,
  inheritedEditable: kind === 'inherited-contenteditable' && node.isContentEditable && !Object.hasOwn(node, 'isContentEditable') }));
"#;

pub(super) async fn observe(mode: &str, request: &Value, observed: &mut Value) {
    if request["method"] != "Runtime.callFunctionOn" {
        return;
    }
    let source = request["params"]["functionDeclaration"].as_str();
    if source != Some(FILL_ADMISSIBILITY) && source != Some(PREPARE_FILL) {
        return;
    }
    let preflight = source == Some(FILL_ADMISSIBILITY);
    let input = json!({
        "kind": mode.strip_prefix(PREFIX).unwrap(),
        "preflight": preflight,
        "functionDeclaration": request["params"]["functionDeclaration"],
        "arguments": request["params"]["arguments"],
    })
    .to_string()
    .into_bytes();
    let mut child = Command::new("node")
        .args(["-e", SCRIPTED_ELEMENT])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("the fixture requires an installed Node runtime; never download one");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
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
            let killed = child.start_kill();
            let reaped = child.wait().await.expect("reap owned Node child");
            panic!("Node fixture failed: {failure:?}; kill={killed:?}; reap={reaped:?}");
        }
    };
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    observed["actionErrorScriptResult"] = serde_json::from_slice(&stdout).unwrap();
    observed["fillPreflight"] = json!(preflight);
}

async fn exercise(mode: &'static str, sensitive: bool, succeeds: bool, raced: bool) {
    use super::super::super::{client_protocol::ScopeState, client_session::ClientSession};
    let broker = Arc::new(ClientSession::new());
    let mut f = fixture_scoped(mode, mode).await;
    let ledger = client_debt::OwnerDebtLedger::new(1, mode.into());
    ledger.bind_context("context").unwrap();
    f.page.client.install_debt_ledger(ledger.clone()).unwrap();
    f.page.client = f.page.client.owner_view(ledger.clone()).unwrap();
    let (owner, state, _notices) = preparation_settlement_owner(&f, broker.clone()).await;
    {
        let enrollment_replies = f.replies.lock().unwrap();
        assert!(enrollment_replies
            .iter()
            .any(|entry| entry["request"]["sessionId"] == "page"));
        for entry in enrollment_replies.iter() {
            assert_eq!(
                entry["reply"]["sessionId"], entry["request"]["sessionId"],
                "enrollment ACK must preserve the exact CDP session"
            );
        }
    }
    assert!(!ledger.snapshot().integrity_lost);
    assert_eq!(ledger.snapshot().outstanding_commands, 0);
    // Same five-second fixture lease. The extra read gets no extra budget.
    f.op = broker.admit(1, 1, 5_000).unwrap();
    assert!(broker.start(1, 1).unwrap());
    let deadline = f.op.deadline;
    let authority = owner
        .capture_settled_input_authority(&f.page, &f.op)
        .unwrap();
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
    f.log.lock().unwrap().clear();
    f.replies.lock().unwrap().clear();
    let value = if sensitive {
        "hunter2-plaintext"
    } else {
        "gamma"
    };
    let result = journal
        .scope(ClientActions::default().execute(
            ActionContext {
                realm_authority: ActionRealmAuthority::Enrolled(&owner),
                page_state: &state,
                ..f.context()
            },
            "browser.perform",
            &json!({"identityScope":mode,"ref":{"id":"@e1","revision":"1"},
            "action":{"kind":"fill","value":value,"sensitive":sensitive}}),
        ))
        .await;
    assert_eq!(f.op.deadline, deadline);
    assert!(Instant::now() < deadline);
    authority.check(&owner, &f.page, &f.op).unwrap();
    let effects = if succeeds {
        result.unwrap();
        Effects::Completed
    } else {
        let failure = result.unwrap_err();
        assert_eq!(failure.error, ProtocolError::NotActionable);
        assert_eq!(
            failure.effects,
            if raced {
                Effects::Unknown
            } else {
                Effects::NotDispatched
            }
        );
        assert!(!failure.cleanup_failed);
        assert_eq!(
            failure.reason,
            if mode.ends_with("-div") {
                Some(ActionReason::FillUnsupportedTarget)
            } else {
                None
            }
        );
        assert!(!format!("{failure:?}").contains(value));
        failure.effects
    };
    let snapshot = journal.snapshot();
    assert_eq!(snapshot.mutation_dispatched, succeeds || raced);
    assert_eq!(snapshot.input_debt, 0);
    assert_eq!(snapshot.object_debt, 0);
    assert!(!snapshot.integrity_lost);
    assert_eq!(ledger.snapshot().outstanding_commands, 0);
    assert_eq!(
        broker.settle(1, 1, effects).unwrap(),
        if raced {
            ScopeState::Quarantined
        } else {
            ScopeState::Usable
        }
    );
    let requests = f.log.lock().unwrap().clone();
    let replies = f.replies.lock().unwrap().clone();
    owner.close().await.unwrap();

    let probes: Vec<_> = requests
        .iter()
        .enumerate()
        .filter(|(_, r)| r["fillPreflight"] == true)
        .collect();
    assert_eq!(probes.len(), 1);
    let (probe_index, probe) = probes[0];
    assert_eq!(probe["sessionId"], "page");
    assert_eq!(probe["params"]["objectId"], "exact-node");
    assert_eq!(probe["params"]["arguments"], json!([]));
    assert!(!probe.to_string().contains(value));
    assert_eq!(probe["actionErrorScriptResult"]["calls"], json!([]));
    assert_eq!(probe["actionErrorScriptResult"]["writes"], json!([]));
    if mode.ends_with("inherited-contenteditable") {
        assert_eq!(probe["actionErrorScriptResult"]["inheritedEditable"], true);
    }
    let preparations: Vec<_> = requests
        .iter()
        .enumerate()
        .filter(|(_, r)| r["fillPreflight"] == false)
        .collect();
    assert_eq!(preparations.len(), usize::from(succeeds || raced));
    if let Some((index, prepare)) = preparations.first() {
        assert!(*index > probe_index);
        assert_eq!(prepare["params"]["objectId"], probe["params"]["objectId"]);
        assert_eq!(prepare["params"]["arguments"], json!([{"value":value}]));
        if raced {
            assert_eq!(probe["actionErrorScriptResult"]["result"], true);
            assert_eq!(
                prepare["actionErrorScriptResult"]["result"],
                json!({"status":"not-actionable"})
            );
            assert_eq!(prepare["actionErrorScriptResult"]["calls"], json!([]));
            assert_eq!(prepare["actionErrorScriptResult"]["writes"], json!([]));
        }
    }
    let inputs: Vec<_> = requests
        .iter()
        .filter(|r| {
            r["method"]
                .as_str()
                .is_some_and(|m| m.starts_with("Input."))
        })
        .collect();
    if succeeds {
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0]["method"], "Input.insertText");
        assert_eq!(inputs[0]["params"]["text"], value);
    } else {
        assert!(inputs.is_empty());
    }
    let releases: Vec<_> = requests
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            r["method"] == "Runtime.releaseObject" && r["params"]["objectId"] == "exact-node"
        })
        .collect();
    assert_eq!(releases.len(), 1);
    assert!(releases[0].0 > probe_index);
    assert!(replies
        .iter()
        .any(|entry| entry["request"]["id"] == releases[0].1["id"]
            && entry["reply"].get("error").is_none()
            && entry["reply"]["result"] == json!({})));
}

#[tokio::test]
async fn sensitive_div_fill_refuses_before_mutation_and_releases_exact_owned_handle() {
    exercise("preparation-fill-admissibility-div", true, false, false).await;
}
#[tokio::test]
async fn ordinary_div_fill_refuses_before_mutation_and_releases_exact_owned_handle() {
    exercise("preparation-fill-admissibility-div", false, false, false).await;
}
#[tokio::test]
async fn disabled_readonly_and_unsupported_fields_refuse_before_fill_mutation() {
    for mode in [
        "preparation-fill-admissibility-disabled",
        "preparation-fill-admissibility-readonly",
        "preparation-fill-admissibility-unsupported-button",
        "preparation-fill-admissibility-unsupported-checkbox",
        "preparation-fill-admissibility-unsupported-file",
        "preparation-fill-admissibility-unsupported-hidden",
        "preparation-fill-admissibility-unsupported-image",
        "preparation-fill-admissibility-unsupported-radio",
        "preparation-fill-admissibility-unsupported-range",
        "preparation-fill-admissibility-unsupported-reset",
        "preparation-fill-admissibility-unsupported-submit",
        "preparation-fill-admissibility-unsupported-color",
    ] {
        exercise(mode, true, false, false).await;
    }
}
#[tokio::test]
async fn valid_fields_and_inherited_contenteditable_keep_original_fill_path() {
    for mode in [
        "preparation-fill-admissibility-input",
        "preparation-fill-admissibility-textarea",
        "preparation-fill-admissibility-contenteditable",
        "preparation-fill-admissibility-inherited-contenteditable",
    ] {
        exercise(mode, false, true, false).await;
    }
}
#[tokio::test]
async fn readonly_race_after_fill_probe_keeps_mutation_unknown_without_input() {
    exercise(
        "preparation-fill-admissibility-race-readonly",
        true,
        false,
        true,
    )
    .await;
}
