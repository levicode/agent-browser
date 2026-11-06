// Hosted regression for one large sub-route observation. The page shape mirrors
// the reported 28-37 s field observation: a large DOM with a hash sub-route and
// hundreds of CSS pseudo markers and inline hint receivers. Every
// batch used to re-read the full frame DOM and re-prove each inline receiver,
// which made the observation scale with batches times the whole tree.
use super::*;
use crate::native::client_transport::ClientExecutor;
use std::time::{Duration, Instant};

const LARGE_PAGE: &str = r#"()=>{
  const parts=['<main id="app">','<style>.label::before{content:"";display:inline-block;width:2px;height:2px}.card::after{content:"";display:block;height:1px}</style>','<h1>Account overview</h1>','<div id="toolbar"></div>'];
  let buttons=0,wrappers=0;
  for(let s=0;s<20;s++){
    parts.push('<section class="card" aria-label="Section '+s+'"><h2>Section '+s+'</h2>');
    for(let i=0;i<35;i++){
      parts.push('<div class="row" data-index="'+s+'-'+i+'"><span class="label">Row '+s+'-'+i+'</span>');
      parts.push('<button type="button" aria-label="Action '+s+'-'+i+'">Action '+s+'-'+i+'</button>');
      parts.push('<span aria-hidden="true">filler</span><span aria-hidden="true">filler</span></div>');
      buttons++;wrappers++;
    }
    parts.push('</section>');
  }
  parts.push('</main>');
  document.body.innerHTML=parts.join('');
  // A real management list keeps most of its DOM out of the semantic tree: a
  // hidden archive and anonymous wrappers are read by the observation but
  // compacted away. 950 hidden rows plus their text nodes make the candidate
  // count about five times the emitted node count, as on the reported page.
  const archive=document.createElement('div');
  archive.style.display='none';
  document.getElementById('app').appendChild(archive);
  // Text nodes, not extra elements: the field page's extra candidates are
  // mostly character data inside wrappers that compact folds away.
  for(let g=0;g<6800;g++){archive.appendChild(document.createTextNode('ghost '+g+' '));}
  location.hash='#/account_label';
  return {elements:document.querySelectorAll('*').length,buttons,wrappers,hash:location.hash};
}"#;

async fn observe_run(
    browser: &crate::native::client_browser::ClientBrowser,
    operations: &mut FixtureOperations,
    sink: &crate::native::client_transport::ClientEventSink,
    command: &str,
    args: Value,
    seconds: u64,
) -> Result<Value, String> {
    operations
        .execute_written(browser, sink, command, args, seconds)
        .await
        .map_err(|error| format!("{command} admission/settlement: {error:?}"))?
        .result
        .map_err(|error| format!("{command}: {error:?}"))
}

fn semantic_node_count(node: &Value) -> usize {
    let mut count = usize::from(node.is_object());
    if let Some(children) = node["children"].as_array() {
        for child in children {
            count += semantic_node_count(child);
        }
    }
    count
}


// The dense, pseudo-light page shape of the reported 1,476-node UAT account
// list: a large light DOM, no CSS pseudo markers, no inline click handlers and
// no shadow trees. It isolates the per-node identity read from the pseudo and
// hint work the other regression covers.
const DENSE_LIGHT_PAGE: &str = r#"()=>{
  const parts=['<main id="app">','<h1>Account overview</h1>','<div id="toolbar"></div>'];
  let rows=0;
  for(let s=0;s<24;s++){
    parts.push('<section class="card" aria-label="Section '+s+'"><h2>Section '+s+'</h2>');
    for(let i=0;i<30;i++){
      parts.push('<div class="row" data-index="'+s+'-'+i+'"><div class="cell"><span class="label">Row '+s+'-'+i+'</span></div>');
      parts.push('<button type="button" aria-label="Action '+s+'-'+i+'">Action '+s+'-'+i+'</button>');
      parts.push('<div class="filler" aria-hidden="true"><span>f</span></div></div>');
      rows++;
    }
    parts.push('</section>');
  }
  parts.push('</main>');
  document.body.innerHTML=parts.join('');
  // The reported page carries three visible plugin objects. They are opaque
  // native frames: the observation must inventory them without reading their
  // subtrees as semantic nodes.
  for(let o=0;o<3;o++){
    const holder=document.createElement('div');
    holder.innerHTML='<object type="text/html" width="300" height="160" data="data:text/html;charset=utf-8,'+encodeURIComponent('<p>plugin '+o+'</p>')+'"></object>';
    document.getElementById('app').appendChild(holder);
  }
  // Eight open shadow roots mirror the field page's custom-element hosts.
  for(let h=0;h<8;h++){
    const host=document.createElement('div');
    host.id='shadow-host-'+h;
    document.getElementById('app').appendChild(host);
    const root=host.attachShadow({mode:'open'});
    root.innerHTML='<span>shadow '+h+'</span>';
  }
  location.hash='#/account_label';
  return {elements:document.querySelectorAll('*').length,objects:document.querySelectorAll('object').length,rows,shadows:8,hash:location.hash};
}"#;

#[tokio::test]
#[ignore = "requires hosted Chromium: large sub-route observation latency budget"]
async fn e2e_observe_pseudo_heavy_page_stays_within_budget() {
    use crate::native::client_browser::ClientBrowser;
    use crate::native::client_session::ClientSession;
    use crate::native::client_transport::ClientEventSink;

    let broker = Arc::new(ClientSession::new());
    let browser = ClientBrowser::new(broker.clone());
    let (sink, _events) = ClientEventSink::test_channel(broker.clone());
    browser.set_event_sink(sink.clone()).unwrap();
    let mut operations = FixtureOperations::new(broker.clone());
    let opened = observe_run(
        &browser,
        &mut operations,
        &sink,
        "scope.open",
        fixture_scope_open("launch", None),
        30,
    )
    .await
    .unwrap();
    let scope = opened["identityScope"].as_str().unwrap().to_owned();
    observe_run(
        &browser,
        &mut operations,
        &sink,
        "scope.configure",
        fixture_configuration(&scope, None),
        30,
    )
    .await
    .unwrap();
    observe_run(
        &browser,
        &mut operations,
        &sink,
        "page.activate",
        json!({"identityScope":scope}),
        30,
    )
    .await
    .unwrap();
    let built = observe_run(
        &browser,
        &mut operations,
        &sink,
        "page.evaluate",
        json!({"identityScope":scope,"source":LARGE_PAGE,"argument":null}),
        30,
    )
    .await
    .unwrap();
    assert_eq!(built["value"]["hash"], "#/account_label");
    assert!(
        built["value"]["elements"].as_u64().unwrap_or(0) > 3_500,
        "the regression page must stay large enough to exercise many batches"
    );
    eprintln!("OBSERVE page={}", built["value"]);

    for (label, options, budget) in [
        ("tree", json!({}), Duration::from_secs(12)),
        ("pixels", json!({"pixels":true}), Duration::from_secs(15)),
    ] {
        let start = Instant::now();
        let snapshot = observe_run(
            &browser,
            &mut operations,
            &sink,
            "browser.observe",
            json!({
                "identityScope":scope,
                "testIdAttribute":"data-testid",
                "secureFieldSelector":FIXTURE_SECURE_SELECTOR,
                "options":options
            }),
            120,
        )
        .await
        .unwrap();
        let elapsed = start.elapsed();
        let bytes = serde_json::to_vec(&snapshot).map(|value| value.len()).unwrap_or(0);
        eprintln!(
            "OBSERVE [{label}] elapsed_ms={} nodes={} bytes={}",
            elapsed.as_millis(),
            semantic_node_count(&snapshot["root"]),
            bytes
        );
        assert!(
            elapsed < budget,
            "observation[{label}] took {elapsed:?}, above {budget:?}"
        );
    }
    let cleanup = browser.shutdown().await;
    assert!(cleanup.is_ok(), "cleanup: {cleanup:?}");
}

// Baseline bed for the staged dense-page work: the same shape the field
// observation measured (1,476 nodes), printed with its native phase map so each
// optimization step can compare capture cost rather than a wall-clock guess.
#[tokio::test]
#[ignore = "requires hosted Chromium: dense light-DOM observation baseline"]
async fn e2e_observe_dense_light_page_prints_phase_baseline() {
    use crate::native::client_browser::ClientBrowser;
    use crate::native::client_session::ClientSession;
    use crate::native::client_transport::ClientEventSink;

    let broker = Arc::new(ClientSession::new());
    let browser = ClientBrowser::new(broker.clone());
    let (sink, _events) = ClientEventSink::test_channel(broker.clone());
    browser.set_event_sink(sink.clone()).unwrap();
    let mut operations = FixtureOperations::new(broker.clone());
    let opened = observe_run(
        &browser,
        &mut operations,
        &sink,
        "scope.open",
        fixture_scope_open("launch", None),
        30,
    )
    .await
    .unwrap();
    let scope = opened["identityScope"].as_str().unwrap().to_owned();
    observe_run(
        &browser,
        &mut operations,
        &sink,
        "scope.configure",
        fixture_configuration(&scope, None),
        30,
    )
    .await
    .unwrap();
    observe_run(
        &browser,
        &mut operations,
        &sink,
        "page.activate",
        json!({"identityScope":scope}),
        30,
    )
    .await
    .unwrap();
    let built = observe_run(
        &browser,
        &mut operations,
        &sink,
        "page.evaluate",
        json!({"identityScope":scope,"source":DENSE_LIGHT_PAGE,"argument":null}),
        30,
    )
    .await
    .unwrap();
    assert_eq!(built["value"]["hash"], "#/account_label");
    assert!(
        built["value"]["elements"].as_u64().unwrap_or(0) > 4_000,
        "the dense page must stay large enough to exercise many batches"
    );
    eprintln!("OBSERVE dense page={}", built["value"]);
    assert_eq!(built["value"]["objects"], 3, "the dense page must keep the three opaque plugin frames");

    let start = Instant::now();
    let snapshot = observe_run(
        &browser,
        &mut operations,
        &sink,
        "browser.observe",
        json!({
            "identityScope":scope,
            "testIdAttribute":"data-testid",
            "secureFieldSelector":FIXTURE_SECURE_SELECTOR,
            "options":{}
        }),
        120,
    )
    .await
    .unwrap();
    let elapsed = start.elapsed();
    let bytes = serde_json::to_vec(&snapshot).map(|value| value.len()).unwrap_or(0);
    eprintln!(
        "OBSERVE [dense-light] elapsed_ms={} nodes={} bytes={} phases={}",
        elapsed.as_millis(),
        semantic_node_count(&snapshot["root"]),
        bytes,
        snapshot["phases"]
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "dense light observation took {elapsed:?}"
    );
    let cleanup = browser.shutdown().await;
    assert!(cleanup.is_ok(), "cleanup: {cleanup:?}");
}
