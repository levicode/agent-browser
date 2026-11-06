// Hosted regression for levicode/agent-browser#52. A pointer action on the
// hash sub-route failed in 18 to 20 ms with no button press: the action's
// in-flight geometry refresh re-read the session frame tree without the
// inventory's proven opaque `<object>` omissions, so the refresh refused
// `IncompleteInventory` (surfaced as `unsupported-capability`) after only the
// preparation scroll had been submitted. The page shape mirrors the reported
// UAT route: a hash sub-route, an input, a table with several clickable rows,
// three `<object>` plugin documents, and a real hash navigation.
use super::*;
use crate::native::client_protocol::Effects;
use crate::native::client_transport::{ClientEventSink, ClientExecutor, NativeOutcome};
use std::time::Instant;

const ROUTE_PAGE: &str = r##"()=>{
  document.body.innerHTML='<h1>Home</h1><nav><a id="to-label" href="#/account_label">labels</a></nav><input id="account" aria-label="Account ID"><div id="plugins"></div><div id="app"></div>';
  for(let index=0;index<3;index+=1){
    const plugin=document.createElement('object');
    plugin.type='text/html';
    plugin.data='about:blank';
    plugin.width=1;
    plugin.height=1;
    plugin.dataset['plugin']=String(index);
    document.getElementById('plugins').append(plugin);
  }
  const rows=Array.from({length:40},(_,index)=>'<tr><td>account '+index+'</td><td><button type="button" aria-label="Edit account '+index+'" onclick="this.dataset.clicks=String(Number(this.dataset.clicks||0)+1)">Edit</button></td></tr>').join('');
  const render=()=>{
    document.getElementById('app').innerHTML=location.hash.indexOf('#/account_label')===0
      ? '<h1>Labels</h1><table><tbody>'+rows+'</tbody></table>'
      : '<h1>Home</h1>';
  };
  window.addEventListener('hashchange',render);
  location.hash='#/home';
  render();
  return new Promise(resolve=>setTimeout(()=>resolve(document.querySelectorAll('object').length),300));
}"##;

async fn run(
    browser: &crate::native::client_browser::ClientBrowser,
    operations: &mut FixtureOperations,
    sink: &ClientEventSink,
    command: &str,
    args: Value,
    seconds: u64,
) -> Result<NativeOutcome, String> {
    operations
        .execute_written(browser, sink, command, args, seconds)
        .await
        .map_err(|error| format!("{command} admission/settlement: {error:?}"))
}

fn observed_ref(node: &Value, name: &str) -> Option<Value> {
    if node["role"].as_str() == Some("button")
        && node["name"].as_str() == Some(name)
        && node["ref"].is_object()
    {
        return Some(node["ref"].clone());
    }
    node["children"]
        .as_array()?
        .iter()
        .find_map(|child| observed_ref(child, name))
}

fn attributed(node: &Value, name: &str) -> usize {
    let mut count = usize::from(node["name"].as_str() == Some(name));
    if let Some(children) = node["children"].as_array() {
        for child in children {
            count += attributed(child, name);
        }
    }
    count
}

#[tokio::test]
#[ignore = "requires hosted Chromium: hash sub-route with opaque object plugin documents and a table tap"]
async fn e2e_tap_on_object_hash_route_dispatches_after_preparation() {
    use crate::native::client_browser::ClientBrowser;
    use crate::native::client_session::ClientSession;

    let broker = Arc::new(ClientSession::new());
    let browser = ClientBrowser::new(broker.clone());
    let (sink, _events) = ClientEventSink::test_channel(broker.clone());
    browser.set_event_sink(sink.clone()).unwrap();
    let mut operations = FixtureOperations::new(broker.clone());
    let opened = run(
        &browser,
        &mut operations,
        &sink,
        "scope.open",
        fixture_scope_open("launch", None),
        30,
    )
    .await
    .unwrap()
    .result
    .unwrap();
    let scope = opened["identityScope"].as_str().unwrap().to_owned();
    eprintln!("native-opaque-route-tap scope opened");
    for (command, args) in [
        (
            "scope.configure",
            fixture_configuration(&scope, None),
        ),
        (
            "page.activate",
            json!({"identityScope":scope}),
        ),
        (
            "page.evaluate",
            json!({"identityScope":scope,"source":ROUTE_PAGE,"argument":null}),
        ),
    ] {
        run(&browser, &mut operations, &sink, command, args, 30)
            .await
            .unwrap()
            .result
            .unwrap();
    }
    eprintln!("native-opaque-route-tap page built");
    let switched = run(
        &browser,
        &mut operations,
        &sink,
        "page.evaluate",
        json!({"identityScope":scope,"source":"()=>{location.hash='#/account_label'; return location.hash;}","argument":null}),
        30,
    )
    .await
    .unwrap()
    .result
    .unwrap();
    assert_eq!(switched["value"], json!("#/account_label"));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let snapshot = run(
        &browser,
        &mut operations,
        &sink,
        "browser.observe",
        json!({"identityScope":scope,"testIdAttribute":"data-testid","secureFieldSelector":FIXTURE_SECURE_SELECTOR,"options":{"pixels":false}}),
        60,
    )
    .await
    .unwrap()
    .result
    .unwrap();
    assert!(
        attributed(&snapshot["root"], "Edit account 3") >= 1,
        "observed table row action must be addressable"
    );
    let reference = observed_ref(&snapshot["root"], "Edit account 3").unwrap();
    eprintln!("native-opaque-route-tap ref={reference}");

    eprintln!("native-opaque-route-tap observed");
    let started = Instant::now();
    let outcome = run(
        &browser,
        &mut operations,
        &sink,
        "browser.perform",
        json!({"identityScope":scope,"ref":reference,"action":{"kind":"tap"}}),
        30,
    )
    .await
    .unwrap();
    let elapsed = started.elapsed();
    eprintln!(
        "native-opaque-route-tap elapsed_ms={} result={:?} effects={:?} retention={:?}",
        elapsed.as_millis(),
        outcome.result,
        outcome.effects,
        outcome.retention
    );
    assert_eq!(
        outcome.result,
        Ok(Value::Null),
        "a tap whose target sits in the author document must dispatch after preparation \
         even when the same session owns opaque object plugin frames"
    );
    assert_eq!(outcome.effects, Effects::Completed);
    let clicks = run(
        &browser,
        &mut operations,
        &sink,
        "page.evaluate",
        json!({"identityScope":scope,"source":"()=>document.querySelector('button[aria-label=\"Edit account 3\"]').dataset.clicks ?? ''","argument":null}),
        30,
    )
    .await
    .unwrap()
    .result
    .unwrap();
    assert_eq!(clicks["value"], json!("1"), "the tap must press exactly once");
    // The reported UAT failure was a fast refusal, not a timeout.
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "the action must not consume the remaining budget: {elapsed:?}"
    );
    let cleanup = browser.shutdown().await;
    assert!(cleanup.is_ok(), "cleanup: {cleanup:?}");
}
