//! Hosted attempt-retirement equivalent for located native references.
//! Included as a child of client_browser so inspection remains test-only.
use super::super::client_session::{CancelSignal, OperationLease};
use super::super::client_transport::ClientExecutor;
use super::*;
use serde_json::{json, Value};

struct Operations {
    next: u64,
    cancellation: tokio::sync::watch::Receiver<CancelSignal>,
}
impl Operations {
    fn lease(&mut self) -> OperationLease {
        self.next += 1;
        OperationLease {
            generation: 1,
            sequence: self.next,
            is_callback: false,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
            cancellation: self.cancellation.clone(),
        }
    }
}
async fn command(
    browser: &ClientBrowser,
    ops: &mut Operations,
    name: &str,
    args: Value,
) -> Result<Value, String> {
    browser
        .execute(
            name.into(),
            args.as_object()
                .ok_or("fixture args must be object")?
                .clone(),
            ops.lease(),
        )
        .await
        .result
        .map_err(|error| format!("{name}: {error:?}"))
}
async fn configure(
    browser: &ClientBrowser,
    ops: &mut Operations,
    scope: &str,
) -> Result<(), String> {
    command(
        browser,
        ops,
        "scope.configure",
        json!({
            "identityScope":scope,
            "testIdAttribute":"data-testid",
            "secureFieldSelector":"input[type=\"password\" i]",
            "requestPolicy":{},
            "downloads":{"source":"local"}
        }),
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
    ops: &mut Operations,
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
    let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
    let mut ops = Operations {
        next: 0,
        cancellation,
    };
    let result:Result<(),String>=async {
        let opened=browser.open(OpenRequest::Connect{endpoint:host.get_cdp_url().to_owned(),persistent:false,options:Default::default()},ops.lease()).await.map_err(|e|format!("first open: {e:?}"))?;
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
        browser.end_scope(first_scope.clone()).await.map_err(|e|format!("scope.end: {e:?}"))?;
        if browser.owner.lock().await.is_some() || browser.page_lease(false).await.is_ok() { return Err("scope.end retained live page owner".into()); }
        if old_targets.inventory().is_ok() { return Err("old native target registry remains usable".into()); }
        if browser.blobs.borrow_sealed(&old_blob_scope,&old_blob.handle).is_ok() { return Err("old attempt blob authority survived retirement".into()); }
        if browser.refs.lock().map_err(|_|"reference lock poisoned")?.retained_identity_counts()!=(0,0) { return Err("scope.end retained native map or durable document identities".into()); }
        let contexts=host.client.send_command_no_params("Target.getBrowserContexts",None).await?;
        if contexts["browserContextIds"].as_array().ok_or("missing context inventory")?.contains(&json!(old_context)) { return Err("old owned context survived acknowledged end".into()); }
        let reopened=browser.open(OpenRequest::Reuse{options:Default::default()},ops.lease()).await.map_err(|e|format!("replacement open: {e:?}"))?;
        let scope=reopened["identityScope"].as_str().ok_or("missing replacement scope")?.to_owned();
        if scope==first_scope { return Err("replacement reused old identity scope".into()); }
        configure(&browser,&mut ops,&scope).await?;
        let current=seed_and_query(&browser,&mut ops,&scope).await?;
        if current["id"]==old_id { return Err("replacement reused canonical located ID".into()); }
        if browser.refs.lock().map_err(|_|"reference lock poisoned")?.get(&old_key).is_some() { return Err("old exact ID aliased replacement native map".into()); }
        // Use the NEW revision and NEW scope deliberately: rejection must be
        // stale located identity, not merely a mismatched revision or scope.
        let stale=browser.execute("browser.perform".into(),json!({"identityScope":scope,"ref":{"id":old_id,"revision":current["revision"]},"action":{"kind":"tap"}}).as_object().unwrap().clone(),ops.lease()).await;
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
