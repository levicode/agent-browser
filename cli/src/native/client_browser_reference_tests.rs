//! Hosted attempt-retirement equivalent for located native references.
//! Included as a child of client_browser so inspection remains test-only.
use super::super::client_actions::{
    fixture_configuration, fixture_scope_open, FixtureOperations, FIXTURE_SECURE_SELECTOR,
};
use super::super::client_transport::ClientExecutor;
use super::*;
use serde_json::{json, Value};

#[test]
fn shared_fixture_setup_obeys_actual_strict_browser_schemas() {
    for site in [None, Some("127.0.0.1")] {
        let mut args = fixture_configuration("synthetic-scope", site);
        assert_eq!(args["secureFieldSelector"], FIXTURE_SECURE_SELECTOR);
        args.as_object_mut().unwrap().remove("identityScope");
        let request: ConfigureRequest = serde_json::from_value(args.clone()).unwrap();
        assert_eq!(request.validate(false), Ok(()));
        let mut bad = args.clone();
        bad["secureFieldSelector"] = json!("input[type=password]");
        assert_eq!(
            serde_json::from_value::<ConfigureRequest>(bad)
                .unwrap()
                .validate(false),
            Err(ProtocolError::InvalidArguments)
        );
        args["unexpected"] = json!(true);
        assert!(serde_json::from_value::<ConfigureRequest>(args).is_err());
    }
    for (source, endpoint) in [
        ("launch", None),
        (
            "connect",
            Some("ws://127.0.0.1:9222/devtools/browser/synthetic"),
        ),
        ("reuse", None),
    ] {
        let mut args = fixture_scope_open(source, endpoint);
        assert!(serde_json::from_value::<OpenRequest>(args.clone()).is_ok());
        args["unexpected"] = json!(true);
        assert!(serde_json::from_value::<OpenRequest>(args).is_err());
    }
}

async fn command(
    browser: &ClientBrowser,
    ops: &mut FixtureOperations,
    name: &str,
    args: Value,
) -> Result<Value, String> {
    ops.execute_written(
        browser,
        browser
            .event_sink
            .get()
            .ok_or("fixture event sink missing")?,
        name,
        args,
        30,
    )
    .await
    .map_err(|error| format!("fixture admission/settlement: {error:?}"))?
    .result
    .map_err(|error| format!("{name}: {error:?}"))
}
async fn configure(
    browser: &ClientBrowser,
    ops: &mut FixtureOperations,
    scope: &str,
) -> Result<(), String> {
    command(
        browser,
        ops,
        "scope.configure",
        fixture_configuration(scope, None),
    )
    .await?;
    command(
        browser,
        ops,
        "page.activate",
        json!({"identityScope":scope}),
    )
    .await?;
    Ok(())
}
async fn seed_and_query(
    browser: &ClientBrowser,
    ops: &mut FixtureOperations,
    scope: &str,
) -> Result<Value, String> {
    {
        let page = browser
            .page_lease(false)
            .await
            .map_err(|e| format!("page lease: {e:?}"))?;
        super::super::browser::evaluate_on(&page.client,&page.page_session_id,
            r#"document.body.innerHTML='<button id="located" onclick="this.dataset.clicks=String(Number(this.dataset.clicks||0)+1)">Located</button>'; true"#).await?;
        page.permit
            .check()
            .map_err(|e| format!("seed permit: {e:?}"))?;
    }
    let result = command(
        browser,
        ops,
        "fixture.query",
        json!({"identityScope":scope,"expression":{"kind":"selector","selector":"#located"}}),
    )
    .await?;
    let nodes = result["nodes"].as_array().ok_or("query nodes missing")?;
    if nodes.len() != 1 {
        return Err(format!("query returned {} nodes", nodes.len()));
    }
    let reference = nodes[0]["ref"].clone();
    if reference["id"].as_str().is_none() || reference["revision"].as_str().is_none() {
        return Err("query did not return canonical exact reference".into());
    }
    Ok(reference)
}
async fn clicks(browser: &ClientBrowser) -> Result<Value, String> {
    let page = browser
        .page_lease(false)
        .await
        .map_err(|e| format!("page lease: {e:?}"))?;
    super::super::browser::evaluate_on(
        &page.client,
        &page.page_session_id,
        "Number(document.querySelector('#located').dataset.clicks||0)",
    )
    .await
}

#[tokio::test]
#[ignore = "requires hosted Chromium: located references retire through real scope end/reopen"]
async fn chromium_located_reference_retirement_across_owned_attempts() {
    let mut host = super::super::browser::BrowserManager::launch(Default::default(), None)
        .await
        .unwrap();
    let browser = ClientBrowser::new(Arc::new(super::super::client_session::ClientSession::new()));
    let (sink, _events) =
        super::super::client_transport::ClientEventSink::test_channel(browser.broker.clone());
    browser.set_event_sink(sink).unwrap();
    let mut ops = FixtureOperations::new(browser.broker.clone());
    let result:Result<(),String>=async {
        let opened=command(&browser,&mut ops,"scope.open",fixture_scope_open("connect",Some(host.get_cdp_url()))).await?;
        let first_scope=opened["identityScope"].as_str().ok_or("missing first scope")?.to_owned();
        configure(&browser,&mut ops,&first_scope).await?;
        let old_reference=seed_and_query(&browser,&mut ops,&first_scope).await?;
        let old_id=old_reference["id"].as_str().unwrap().to_owned();
        let old_key=super::super::element::parse_ref(&old_id).ok_or("invalid old canonical ref")?;
        {
            let refs=browser.refs.lock().map_err(|_|"reference lock poisoned")?;
            let counts=refs.retained_identity_counts();
            if refs.get(&old_key).is_none() || counts.0==0 || counts.1==0 { return Err("actual query was not committed to both native identity populations".into()); }
        }
        command(&browser,&mut ops,"browser.perform",json!({"identityScope":first_scope,"ref":old_reference,"action":{"kind":"tap"}})).await?;
        if clicks(&browser).await?!=json!(1) { return Err("old admitted exact reference was not actionable".into()); }
        let (old_context,old_targets,old_blob_scope)={
            let owner=browser.owner.lock().await;
            let owner=owner.as_ref().ok_or("missing first owner")?;
            (owner.context_id.clone(),owner.targets.clone(),owner.runtime.as_ref().ok_or("missing first runtime")?.scope.clone())
        };
        let old_blob=browser.blobs.insert_sealed(old_blob_scope.clone(),b"synthetic-attempt-resource").map_err(|e|format!("seed blob: {e:?}"))?;
        // Actual retained production lifecycle; no direct map clearing, manual
        // enrollment acknowledgment, artificial disposal counter or scope swap.
        command(&browser,&mut ops,"scope.end",json!({"identityScope":first_scope})).await?;
        if browser.owner.lock().await.is_some() || browser.page_lease(false).await.is_ok() { return Err("scope.end retained live page owner".into()); }
        if old_targets.inventory().is_ok() { return Err("old native target registry remains usable".into()); }
        if browser.blobs.borrow_sealed(&old_blob_scope,&old_blob.handle).is_ok() { return Err("old attempt blob authority survived retirement".into()); }
        if browser.refs.lock().map_err(|_|"reference lock poisoned")?.retained_identity_counts()!=(0,0) { return Err("scope.end retained native map or durable document identities".into()); }
        let contexts=host.client.send_command_no_params("Target.getBrowserContexts",None).await?;
        if contexts["browserContextIds"].as_array().ok_or("missing context inventory")?.contains(&json!(old_context)) { return Err("old owned context survived acknowledged end".into()); }
        let reopened=command(&browser,&mut ops,"scope.open",fixture_scope_open("reuse",None)).await?;
        let scope=reopened["identityScope"].as_str().ok_or("missing replacement scope")?.to_owned();
        if scope==first_scope { return Err("replacement reused old identity scope".into()); }
        configure(&browser,&mut ops,&scope).await?;
        let current=seed_and_query(&browser,&mut ops,&scope).await?;
        if current["id"]==old_id { return Err("replacement reused canonical located ID".into()); }
        if browser.refs.lock().map_err(|_|"reference lock poisoned")?.get(&old_key).is_some() { return Err("old exact ID aliased replacement native map".into()); }
        // Use the NEW revision and NEW scope deliberately: rejection must be
        // stale located identity, not merely a mismatched revision or scope.
        let stale=ops.execute_written(&browser,browser.event_sink.get().ok_or("fixture event sink missing")?,"browser.perform",json!({"identityScope":scope,"ref":{"id":old_id,"revision":current["revision"]},"action":{"kind":"tap"}}),30).await.map_err(|e|format!("stale action admission/settlement: {e:?}"))?;
        if stale.result!=Err(ProtocolError::StaleReference) { return Err(format!("old ID under replacement was not stale: {:?}",stale.result)); }
        if clicks(&browser).await?!=json!(0) { return Err("stale old ID mutated replacement element".into()); }
        command(&browser,&mut ops,"browser.perform",json!({"identityScope":scope,"ref":current,"action":{"kind":"tap"}})).await?;
        if clicks(&browser).await?!=json!(1) { return Err("current replacement ID did not act exactly once".into()); }
        Ok(())
    }.await;
    // Retain cleanup even when the behavioral body returns a failure.
    let cleanup = browser.shutdown().await;
    let host_cleanup = host.close().await;
    result.unwrap();
    cleanup.unwrap();
    host_cleanup.unwrap();
}
