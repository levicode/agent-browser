//! Native equivalents of Web's observable contracts, not its old DOM arrays.
//! This module and its exact-operation hooks are absent from release binaries.
use super::super::browser::{evaluate_on, BrowserManager};
use super::*;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex, OnceLock,
};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Mode {
    Lifetime,
    Navigate,
    Detach,
    Deadline,
}
struct Hook {
    mode: Mode,
    calls: AtomicUsize,
    handles: Mutex<Vec<String>>,
    trigger: usize,
}
static HOOKS: OnceLock<Mutex<HashMap<u64, Arc<Hook>>>> = OnceLock::new();
static SEQUENCE: AtomicU64 = AtomicU64::new(1_000_000);
struct HookGuard(u64);
impl Drop for HookGuard {
    fn drop(&mut self) {
        if let Some(h) = HOOKS.get() {
            h.lock().unwrap().remove(&self.0);
        }
    }
}
fn hook(lease: &OperationLease) -> Option<Arc<Hook>> {
    HOOKS
        .get()
        .and_then(|h| h.lock().unwrap().get(&lease.sequence).cloned())
}
fn install(lease: &OperationLease, mode: Mode, trigger: usize) -> (HookGuard, Arc<Hook>) {
    let value = Arc::new(Hook {
        mode,
        calls: AtomicUsize::new(0),
        handles: Mutex::new(Vec::new()),
        trigger,
    });
    assert!(HOOKS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .insert(lease.sequence, value.clone())
        .is_none());
    (HookGuard(lease.sequence), value)
}
fn operation() -> (OperationLease, tokio::sync::watch::Sender<CancelSignal>) {
    let (tx, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
    (
        OperationLease {
            is_callback: false,
            generation: 1,
            sequence: SEQUENCE.fetch_add(1, Ordering::SeqCst),
            deadline: Instant::now() + Duration::from_secs(30),
            cancellation,
        },
        tx,
    )
}
pub(super) fn instrument(method: &str, mut args: Value, lease: &OperationLease) -> Value {
    if let Some(h) = hook(lease) {
        if matches!(h.mode, Mode::Lifetime)
            && method == "Runtime.callFunctionOn"
            && args["functionDeclaration"]
                .as_str()
                .is_some_and(|s| s.starts_with("function(testId,secureSelector,...nodes)"))
        {
            args["functionDeclaration"]=json!(format!("function(testId,secureSelector,...nodes){{const read={METADATA};const result=nodes.map(node=>read.call(node,testId,secureSelector));(globalThis.__nativeLifetimeWeak??=[]).push(new WeakRef(nodes),new WeakRef(result));return result;}}"));
        }
    }
    args
}
pub(super) async fn after_command(
    client: &CdpClient,
    session: &str,
    method: &str,
    site: &str,
    value: &Value,
    lease: &OperationLease,
) -> Result<(), ObservationError> {
    let Some(h) = hook(lease) else { return Ok(()) };
    if matches!(h.mode, Mode::Lifetime) && method == "DOM.resolveNode" {
        if let Some(id) = value["object"]["objectId"].as_str() {
            h.handles.lock().unwrap().push(id.into());
        }
    }
    if site != "metadata-batch" {
        return Ok(());
    }
    if value.get("exceptionDetails").is_some() || !value["result"]["value"].is_array() {
        return Err(ObservationError::BackendFailure);
    }
    let call = h.calls.fetch_add(1, Ordering::SeqCst) + 1;
    if call != h.trigger {
        return Ok(());
    }
    match h.mode {
        Mode::Lifetime => (),
        Mode::Navigate => {
            tokio::time::timeout(Duration::from_secs(3), async {
                let before = client
                    .send_command_no_params("Page.getFrameTree", Some(session))
                    .await?;
                let old = before["frameTree"]["frame"]["loaderId"].clone();
                client
                    .send_command(
                        "Page.navigate",
                        Some(json!({"url":"data:text/html,<button>Replacement</button>"})),
                        Some(session),
                    )
                    .await?;
                loop {
                    let after = client
                        .send_command_no_params("Page.getFrameTree", Some(session))
                        .await?;
                    if after["frameTree"]["frame"]["loaderId"] != old {
                        return Ok::<(), String>(());
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .map_err(|_| ObservationError::BackendFailure)?
            .map_err(|_| ObservationError::BackendFailure)?;
        }
        Mode::Detach => {
            client.send_command("Runtime.evaluate",Some(json!({"expression":"document.querySelector('iframe').remove();true","returnByValue":true})),Some(session)).await.map_err(|_|ObservationError::BackendFailure)?;
        }
        Mode::Deadline => {
            tokio::time::sleep_until((lease.deadline + Duration::from_millis(10)).into()).await
        }
    }
    Ok(())
}
fn flatten(roots: &[SemanticNode]) -> Vec<&SemanticNode> {
    let mut out = Vec::new();
    let mut pending: Vec<_> = roots.iter().rev().collect();
    while let Some(node) = pending.pop() {
        out.push(node);
        pending.extend(node.children.iter().rev());
    }
    out
}
async fn frames(browser: &BrowserManager, op: &OperationLease) -> Vec<ObservationFrame> {
    enumerate_frames(
        &browser.client,
        browser.active_session_id().unwrap(),
        &HashMap::new(),
        op,
    )
    .await
    .unwrap()
}
async fn query_testid(
    browser: &BrowserManager,
    frames: &[ObservationFrame],
    refs: &mut RefMap,
    op: &OperationLease,
    id: &str,
) -> SemanticNode {
    let options:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"query","query":{"kind":"testId","value":{"kind":"string","value":id,"exact":true}}}})).unwrap();
    let result = query(
        &browser.client,
        frames,
        refs,
        "equivalence",
        1,
        &options,
        op,
    )
    .await
    .unwrap();
    assert_eq!(result.nodes.len(), 1);
    result.nodes.into_iter().next().unwrap()
}
#[tokio::test]
#[ignore = "hosted Chromium: real AX controls, exact labels and native budget accounting"]
async fn chromium_twenty_controls_budget_and_frame_truncation_contract() {
    let mut browser = BrowserManager::launch(Default::default(), None)
        .await
        .unwrap();
    let result=async {
        let session=browser.active_session_id()?;let(op,_tx)=operation();
        evaluate_on(&browser.client,session,"document.body.innerHTML='<main>'+Array.from({length:20},(_,i)=>'<button>Button '+i+'</button>').join('')+'</main>';true").await?;
        let inventory=frames(&browser,&op).await;let mut refs=RefMap::new();
        let whole=observe(&browser.client,&inventory,&mut refs,"equivalence",1,&ObservationOptions{max_nodes:100,..Default::default()},&op).await?;
        assert!(!whole.truncated);
        let buttons:Vec<_>=flatten(&whole.roots).into_iter().filter(|n|n.role.as_deref()==Some("button")).collect();
        assert_eq!(buttons.len(),20);
        let mut identities=std::collections::HashSet::new();
        for button in &buttons {
            assert!(identities.insert(button.reference.id.clone()));
            let id=super::super::element::parse_ref(&button.reference.id).unwrap();
            assert!(refs.get(&id).unwrap().exact_binding.as_ref().unwrap().actionable);
        }
        let names:std::collections::BTreeSet<_>=buttons.into_iter().map(|n|n.name.clone().unwrap()).collect();
        assert_eq!(names,(0..20).map(|i|format!("Button {i}")).collect());
        let cut=observe(&browser.client,&inventory,&mut refs,"equivalence",2,&ObservationOptions{max_nodes:5,..Default::default()},&op).await?;
        assert!(cut.truncated);assert_eq!(flatten(&cut.roots).len(),5);
        evaluate_on(&browser.client,session,r#"new Promise(resolve=>{document.body.innerHTML='<button>One</button>';const f=document.createElement('iframe');f.onload=()=>resolve(true);f.srcdoc='<button>Inside</button>';document.body.append(f);})"#).await?;
        let inventory=frames(&browser,&op).await;assert_eq!(inventory.len(),2);
        // Frame admission belongs to owner policy. Measure the native main AX
        // count, not the retired DOM reader's incidental count of three nodes.
        let main=observe(&browser.client,&inventory[..1],&mut refs,"equivalence",3,&ObservationOptions::default(),&op).await?;
        let budget=flatten(&main.roots).len();assert!(!main.truncated);
        let whole=observe(&browser.client,&inventory,&mut refs,"equivalence",4,&ObservationOptions::default(),&op).await?;
        assert!(!whole.truncated);assert!(flatten(&whole.roots).iter().any(|n|n.role.as_deref()==Some("button")&&n.name.as_deref()==Some("Inside")));
        let cut=observe(&browser.client,&inventory,&mut refs,"equivalence",5,&ObservationOptions{max_nodes:budget,..Default::default()},&op).await?;
        assert!(cut.truncated);assert!(flatten(&cut.roots).iter().all(|n|n.name.as_deref()!=Some("Inside")));assert_eq!(flatten(&cut.roots).len(),budget);
        // Explicitly excluded frames do not consume the admitted-frame budget.
        let excluded=observe(&browser.client,&inventory[..1],&mut refs,"equivalence",6,&ObservationOptions{max_nodes:budget,..Default::default()},&op).await?;
        assert!(!excluded.truncated);Ok::<(),String>(())
    }.await;
    browser.close().await.unwrap();
    result.unwrap();
}
#[tokio::test]
#[ignore = "hosted Chromium: actual embedded-control labels and password-descendant names"]
async fn chromium_embedded_control_and_password_public_labels_contract() {
    let mut browser = BrowserManager::launch(Default::default(), None)
        .await
        .unwrap();
    let result=async {
        let session=browser.active_session_id()?;let(op,_tx)=operation();
        evaluate_on(&browser.client,session,r#"document.body.innerHTML='<label for="qty">Qty <input value="5"> items</label><input id="qty" data-testid="label-for"><button data-testid="secure">Unlock <input type="password" value="synthetic-secret"> now</button><label for="pin">PIN <input type="password" value="synthetic-secret"> field</label><input id="pin" data-testid="secure-label">';true"#).await?;
        let inventory=frames(&browser,&op).await;let mut refs=RefMap::new();let qty=query_testid(&browser,&inventory,&mut refs,&op,"label-for").await;
        assert_eq!(qty.labels,vec!["Qty items"]);
        let label:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"query","query":{"kind":"label","value":{"kind":"string","value":"Qty items","exact":true}}}})).unwrap();
        let found=query(&browser.client,&inventory,&mut refs,"equivalence",1,&label,&op).await?;assert_eq!(found.nodes.len(),1);assert_eq!(found.nodes[0].test_id.as_deref(),Some("label-for"));
        let button=query_testid(&browser,&inventory,&mut refs,&op,"secure").await;let pin=query_testid(&browser,&inventory,&mut refs,&op,"secure-label").await;
        assert_eq!(button.name.as_deref(),Some("Unlock now"));assert_eq!(pin.name.as_deref(),Some("PIN field"));
        assert!(!serde_json::to_string(&[qty,button,pin]).unwrap().contains("synthetic-secret"));
        let whole=observe(&browser.client,&inventory,&mut refs,"equivalence",2,&ObservationOptions::default(),&op).await?;
        assert!(!serde_json::to_string(&whole).unwrap().contains("synthetic-secret"));
        for(id,name)in[("secure","Unlock now"),("secure-label","PIN field")]{assert_eq!(flatten(&whole.roots).into_iter().find(|n|n.test_id.as_deref()==Some(id)).and_then(|n|n.name.as_deref()),Some(name));}
        evaluate_on(&browser.client,session,r#"document.body.innerHTML='<span id="public-name">Preferred name</span><button data-testid="precedence" aria-label="Secondary name" aria-labelledby="public-name">Unlock <input type="password" value="synthetic-secret"> now</button><button data-testid="blocks"><span style="display:block">Unlock</span><input type="password" value="synthetic-secret"><span style="display:block">now</span></button><button data-testid="ambiguous"><img alt="Icon"><input type="password" value="synthetic-secret"> now</button>';true"#).await?;
        let precedence=query_testid(&browser,&inventory,&mut refs,&op,"precedence").await;
        assert_eq!(precedence.name.as_deref(),Some("Preferred name"));
        let blocks=query_testid(&browser,&inventory,&mut refs,&op,"blocks").await;
        assert_eq!(blocks.name.as_deref(),Some("Unlock now"));
        let ambiguous=query_testid(&browser,&inventory,&mut refs,&op,"ambiguous").await;
        assert!(ambiguous.name.is_none(),"Unproven icon name must not be replaced by arbitrary text");
        assert!(!serde_json::to_string(&[precedence,blocks,ambiguous]).unwrap().contains("synthetic-secret"));
        Ok::<(),String>(())
    }.await;
    browser.close().await.unwrap();
    result.unwrap();
}
#[tokio::test]
#[ignore = "hosted Chromium: actual metadata WeakRefs, released groups and latest native exact click"]
async fn chromium_observation_metadata_gc_and_exact_ref_actionability() {
    let mut browser = BrowserManager::launch(Default::default(), None)
        .await
        .unwrap();
    let result=async {
        let session=browser.active_session_id()?;let(op,_tx)=operation();
        evaluate_on(&browser.client,session,r#"document.body.innerHTML='<button onclick="this.textContent=\'Clicked\'">Click</button>';true"#).await?;
        let inventory=frames(&browser,&op).await;let mut refs=RefMap::new();let(_guard,h)=install(&op,Mode::Lifetime,usize::MAX);let mut latest=None;
        for revision in 1..=3{let observation=observe(&browser.client,&inventory,&mut refs,"equivalence",revision,&ObservationOptions::default(),&op).await?;let buttons:Vec<_>=flatten(&observation.roots).into_iter().filter(|n|n.role.as_deref()==Some("button")).collect();assert_eq!(buttons.len(),1);latest=Some(buttons[0].reference.id.clone());}
        assert_eq!(h.calls.load(Ordering::SeqCst),3);
        let objects=h.handles.lock().unwrap().clone();assert!(!objects.is_empty());
        for object in objects {let old=browser.client.send_command("Runtime.callFunctionOn",Some(json!({"objectId":object,"functionDeclaration":"function(){return true}","returnByValue":true})),Some(session)).await;assert!(old.is_err(),"Released observation remote handle remained live");}
        let world=browser.client.send_command("Page.createIsolatedWorld",Some(json!({"frameId":inventory[0].binding.frame,"worldName":"agent-browser-native-observation"})),Some(session)).await?;
        browser.client.send_command_no_params("HeapProfiler.collectGarbage",Some(session)).await?;
        let dead=browser.client.send_command("Runtime.evaluate",Some(json!({"contextId":world["executionContextId"],"expression":"[globalThis.__nativeLifetimeWeak.length,globalThis.__nativeLifetimeWeak.filter(ref=>ref.deref()===undefined).length]","returnByValue":true})),Some(session)).await?;
        assert_eq!(dead["result"]["value"],json!([6,6]));
        let id=latest.unwrap();let(x,y,effective)=super::super::element::resolve_element_center(&browser.client,session,&refs,&id,&HashMap::new(),true).await?;
        for kind in ["mousePressed","mouseReleased"]{browser.client.send_command("Input.dispatchMouseEvent",Some(json!({"type":kind,"x":x,"y":y,"button":"left","clickCount":1})),Some(&effective)).await?;}
        assert_eq!(evaluate_on(&browser.client,session,"document.querySelector('button').textContent").await?,json!("Clicked"));Ok::<(),String>(())
    }.await;
    browser.close().await.unwrap();
    result.unwrap();
}
#[tokio::test]
#[ignore = "hosted Chromium: mutation after real metadata distinguishes stale document/frame from deadline"]
async fn chromium_observation_retirement_races_are_stale_not_deadline() {
    for mode in [Mode::Navigate, Mode::Detach, Mode::Deadline] {
        let mut browser = BrowserManager::launch(Default::default(), None)
            .await
            .unwrap();
        let result=async {
        let session=browser.active_session_id()?;let(mut op,_tx)=operation();
        evaluate_on(&browser.client,session,r#"new Promise(resolve=>{document.body.innerHTML='<button>Main</button>';const f=document.createElement('iframe');f.onload=()=>resolve(true);f.srcdoc='<button>Child</button>';document.body.append(f);})"#).await?;
        let inventory=frames(&browser,&op).await;let mut refs=RefMap::new();let before=refs.ref_ids().len();
        let(_guard,h)=install(&op,mode,if matches!(mode,Mode::Detach){2}else{1});if matches!(mode,Mode::Deadline){op.deadline=Instant::now()+Duration::from_secs(2);}
        let result=observe(&browser.client,&inventory,&mut refs,"equivalence",1,&ObservationOptions::default(),&op).await;
        assert_eq!(result.unwrap_err(),if matches!(mode,Mode::Deadline){ObservationError::DeadlineExceeded}else{ObservationError::StaleReference});assert!(h.calls.load(Ordering::SeqCst)>=h.trigger);assert_eq!(refs.ref_ids().len(),before);Ok::<(),String>(())
    }.await;
        browser.close().await.unwrap();
        result.unwrap();
    }
}

#[tokio::test]
#[ignore = "hosted Chromium: exact read retirement after acquired metadata preserves typed stale/deadline"]
async fn chromium_exact_read_retirement_races_are_stale_not_deadline() {
    for mode in [Mode::Navigate, Mode::Detach, Mode::Deadline] {
        let mut browser = BrowserManager::launch(Default::default(), None)
            .await
            .unwrap();
        let result=async {
        let session=browser.active_session_id()?;let(mut op,_tx)=operation();
        evaluate_on(&browser.client,session,r#"new Promise(resolve=>{document.body.innerHTML='<button data-testid="main">Main</button>';const f=document.createElement('iframe');f.onload=()=>resolve(true);f.srcdoc='<button data-testid="child">Child</button>';document.body.append(f);})"#).await?;
        let inventory=frames(&browser,&op).await;let mut refs=RefMap::new();
        let observed=observe(&browser.client,&inventory,&mut refs,"equivalence",1,&ObservationOptions::default(),&op).await?;
        let target=flatten(&observed.roots).into_iter().find(|n|n.test_id.as_deref()==Some(if matches!(mode,Mode::Detach){"child"}else{"main"})).unwrap().reference.id.clone();
        let before=refs.ref_ids().len();let(_guard,h)=install(&op,mode,1);if matches!(mode,Mode::Deadline){op.deadline=Instant::now()+Duration::from_secs(2);}
        let options:ReadOptions=serde_json::from_value(json!({"ref":target})).unwrap();
        let result=read(&browser.client,&inventory,&mut refs,"equivalence",2,&options,&op).await;
        assert_eq!(result.unwrap_err(),if matches!(mode,Mode::Deadline){ObservationError::DeadlineExceeded}else{ObservationError::StaleReference});assert_eq!(h.calls.load(Ordering::SeqCst),1);assert_eq!(refs.ref_ids().len(),before);Ok::<(),String>(())
    }.await;
        browser.close().await.unwrap();
        result.unwrap();
    }
}
#[test]
fn metadata_lifetime_hook_is_exact_operation_scoped() {
    let (lease, _tx) = operation();
    let (other, _tx2) = operation();
    let (_guard, _) = install(&lease, Mode::Lifetime, usize::MAX);
    let source = json!({"functionDeclaration":format!("function(testId,secureSelector,...nodes) {{ const read={METADATA}; return nodes.map(node=>read.call(node,testId,secureSelector)); }}")});
    assert_eq!(
        instrument("Runtime.callFunctionOn", source.clone(), &other),
        source
    );
    assert!(
        instrument("Runtime.callFunctionOn", source, &lease)["functionDeclaration"]
            .as_str()
            .unwrap()
            .contains("new WeakRef")
    );
}

#[tokio::test]
#[ignore = "hosted Chromium: same-document additive query quota and exact identity lifetime"]
async fn chromium_query_churn_bounds_durable_metadata_without_evicting_authority() {
    let mut browser = BrowserManager::launch(Default::default(), None)
        .await
        .unwrap();
    let result=async {
        let session=browser.active_session_id()?;let(op,_tx)=operation();
        evaluate_on(&browser.client,session,"document.body.innerHTML='<button id=current aria-label=Current>Current</button>';true").await?;
        let inventory=frames(&browser,&op).await;let mut refs=RefMap::new();refs.set_exact_limit_for_test(16);
        let options:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"selector","selector":"#current"}})).unwrap();
        // Exact-label acquisitions remain pinned, independently of the live selector.
        let pinned_options:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"query","query":{"kind":"label","value":{"kind":"string","value":"Current","exact":true}}}})).unwrap();
        let pinned=query(&browser.client,&inventory,&mut refs,"churn",1,&pinned_options,&op).await?;
        assert_eq!(pinned.nodes.len(),1);let pinned_id=pinned.nodes[0].reference.id.clone();
        let first=query(&browser.client,&inventory,&mut refs,"churn",1,&options,&op).await?;
        assert_eq!(first.nodes.len(),1);let old=first.nodes[0].reference.id.clone();let mut current=old.clone();
        assert_eq!(refs.retained_identity_counts(),(2,0),"Located issuances remain bounded without entering the observed durable cache");
        let mut ids=std::collections::HashSet::from([old.clone(),pinned_id.clone()]);let mut rejected=false;
        for revision in 2..32 {
            evaluate_on(&browser.client,session,"window.previous=document.querySelector('#current');window.previous.replaceWith(Object.assign(document.createElement('button'),{id:'current',textContent:'Current',ariaLabel:'Current'}));true").await?;
            let before=(refs.ref_ids(),refs.retained_identity_counts());
            match query(&browser.client,&inventory,&mut refs,"churn",revision,&options,&op).await {
                Ok(found)=>{assert_eq!(found.nodes.len(),1);current=found.nodes[0].reference.id.clone();assert!(ids.insert(current.clone()),"A retired DOM identity must never be rebound");let(map,durable)=refs.retained_identity_counts();assert_eq!(map,ids.len());assert_eq!(durable,0);assert!(map<=16);},
                Err(ObservationError::ResourceLimit)=>{assert_eq!((refs.ref_ids(),refs.retained_identity_counts()),before);rejected=true;evaluate_on(&browser.client,session,"document.querySelector('#current').replaceWith(window.previous);true").await?;break;},
                Err(error)=>return Err(format!("Unexpected churn failure: {error:?}")),
            }
        }
        assert!(rejected,"Bounded query admission must eventually reject churn");
        let before=(refs.ref_ids(),refs.retained_identity_counts());
        assert_eq!(query(&browser.client,&inventory,&mut refs,"churn",100,&options,&op).await.unwrap_err(),ObservationError::ResourceLimit);
        assert_eq!((refs.ref_ids(),refs.retained_identity_counts()),before,"Refusal must not publish or recycle any issuance");
        let pinned_read:ReadOptions=serde_json::from_value(json!({"ref":pinned_id})).unwrap();
        assert_eq!(read(&browser.client,&inventory,&mut refs,"churn",1,&pinned_read,&op).await.unwrap_err(),ObservationError::StaleReference);
        let old_read:ReadOptions=serde_json::from_value(json!({"ref":old.clone()})).unwrap();
        let live=read(&browser.client,&inventory,&mut refs,"churn",1,&old_read,&op).await?;
        assert_eq!(live["ref"]["id"],old);assert_eq!(live["ref"]["revision"],"1");
        assert_eq!(live["name"],"Current");
        assert_eq!((refs.ref_ids(),refs.retained_identity_counts()),before,"Temporary live resolution must not mint or replace authority");
        evaluate_on(&browser.client,session,"document.querySelector('#current').onclick=()=>document.querySelector('#current').textContent='Clicked';true").await?;
        let(x,y,effective)=super::super::element::resolve_element_center(&browser.client,session,&refs,&current,&HashMap::new(),true).await?;
        for kind in ["mousePressed","mouseReleased"]{browser.client.send_command("Input.dispatchMouseEvent",Some(json!({"type":kind,"x":x,"y":y,"button":"left","clickCount":1})),Some(&effective)).await?;}
        let text=browser.client.send_command("Runtime.evaluate",Some(json!({"expression":"document.querySelector('#current').textContent","returnByValue":true})),Some(session)).await?;
        assert_eq!(text["result"]["value"],"Clicked");
        Ok::<(),String>(())
    }.await;
    browser.close().await.unwrap();
    result.unwrap();
}
