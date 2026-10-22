//! Native equivalents of Web's observable contracts, not its old DOM arrays.
//! This module and its exact-operation hooks are absent from release binaries.
use super::super::browser::{evaluate_on, BrowserManager};
use super::*;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex, OnceLock,
};
use std::time::{Duration, Instant};

/// A hold on an actual metadata reply, after node handles were acquired. This
/// remains test-only and does not add a public fault command or raw identifiers.
pub(crate) struct MetadataHold {
    generation: u64,
    sequence: u64,
    cancellation: tokio::sync::watch::Receiver<CancelSignal>,
    reached: tokio::sync::watch::Sender<bool>,
    released: tokio::sync::watch::Sender<bool>,
    handles: Mutex<Vec<String>>,
    releases: AtomicUsize,
    calls: AtomicUsize,
}
impl MetadataHold {
    pub(crate) async fn reached(&self) {
        let mut receiver = self.reached.subscribe();
        while !*receiver.borrow_and_update() {
            receiver
                .changed()
                .await
                .expect("metadata hold owner dropped");
        }
    }
    pub(crate) fn release(&self) {
        self.released.send_replace(true);
    }
    pub(crate) fn handles(&self) -> Vec<String> {
        self.handles.lock().unwrap().clone()
    }
    pub(crate) fn releases(&self) -> usize {
        self.releases.load(Ordering::SeqCst)
    }
    pub(crate) fn metadata_calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    fn owns(&self, lease: &OperationLease) -> bool {
        self.generation == lease.generation
            && self.sequence == lease.sequence
            && self.cancellation.same_channel(&lease.cancellation)
    }
}
static METADATA_HOLDS: OnceLock<Mutex<Vec<Arc<MetadataHold>>>> = OnceLock::new();
pub(crate) struct MetadataHoldGuard(Arc<MetadataHold>);
impl Drop for MetadataHoldGuard {
    fn drop(&mut self) {
        self.0.release();
        if let Some(holds) = METADATA_HOLDS.get() {
            holds
                .lock()
                .unwrap()
                .retain(|value| !Arc::ptr_eq(value, &self.0));
        }
    }
}
pub(crate) fn hold_metadata(lease: &OperationLease) -> (MetadataHoldGuard, Arc<MetadataHold>) {
    let (reached, _) = tokio::sync::watch::channel(false);
    let (released, _) = tokio::sync::watch::channel(false);
    let hold = Arc::new(MetadataHold {
        generation: lease.generation,
        sequence: lease.sequence,
        cancellation: lease.cancellation.clone(),
        reached,
        released,
        handles: Mutex::new(Vec::new()),
        releases: AtomicUsize::new(0),
        calls: AtomicUsize::new(0),
    });
    let mut holds = METADATA_HOLDS.get_or_init(Default::default).lock().unwrap();
    assert!(!holds.iter().any(|value| value.owns(lease)));
    holds.push(hold.clone());
    (MetadataHoldGuard(hold.clone()), hold)
}
fn metadata_hold(lease: &OperationLease) -> Option<Arc<MetadataHold>> {
    METADATA_HOLDS.get().and_then(|holds| {
        holds
            .lock()
            .unwrap()
            .iter()
            .find(|value| value.owns(lease))
            .cloned()
    })
}
pub(super) fn after_group_release(lease: &OperationLease, group: &str) {
    if group == format!("native-metadata-{}", lease.sequence) {
        if let Some(hold) = metadata_hold(lease) {
            hold.releases.fetch_add(1, Ordering::SeqCst);
        }
    }
}
async fn metadata_checkpoint(
    method: &str,
    site: &str,
    group: Option<&str>,
    value: &Value,
    lease: &OperationLease,
) -> Result<(), ObservationError> {
    let Some(hold) = metadata_hold(lease) else {
        return Ok(());
    };
    let metadata_group = format!("native-metadata-{}", lease.sequence);
    if method == "DOM.resolveNode" && group == Some(metadata_group.as_str()) {
        if let Some(object) = value["object"]["objectId"].as_str() {
            hold.handles.lock().unwrap().push(object.to_owned());
        }
    }
    if site != "metadata-batch" || group != Some(metadata_group.as_str()) {
        return Ok(());
    }
    if value.get("exceptionDetails").is_some() || !value["result"]["value"].is_array() {
        return Err(ObservationError::BackendFailure);
    }
    hold.calls.fetch_add(1, Ordering::SeqCst);
    hold.reached.send_replace(true);
    let mut release = hold.released.subscribe();
    let mut cancellation = lease.cancellation.clone();
    loop {
        check(lease)?;
        if *release.borrow_and_update() {
            return Ok(());
        }
        tokio::select! {
            _ = release.changed() => {},
            _ = cancellation.changed() => return Err(ObservationError::Cancelled),
            _ = tokio::time::sleep_until(lease.deadline.into()) => return Err(ObservationError::DeadlineExceeded),
            _ = capture_retired() => return check(lease),
        }
    }
}

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
    group: Option<&str>,
    value: &Value,
    lease: &OperationLease,
) -> Result<(), ObservationError> {
    metadata_checkpoint(method, site, group, value, lease).await?;
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
#[ignore = "hosted Chromium: unique native author focus, selection, closed roots, UA controls and stale cleanup"]
async fn chromium_closed_shadow_unique_focus_and_selection_contract() {
    let mut browser = BrowserManager::launch(Default::default(), None)
        .await
        .unwrap();
    let result = async {
        let session = browser.active_session_id()?;
        for (outer, inner) in [("open", "open"), ("open", "closed"), ("closed", "open"), ("closed", "closed")] {
            let (op, _tx) = operation();
            // These fixture-only references control focus; native acquisition
            // never reads them or needs an author shadow-root registry.
            let fixture = format!(r#"(() => {{
                document.body.innerHTML=Array.from({{length:80}},(_,i)=>'<button>Padding '+i+'</button>').join('')+'<input type="date" data-testid="native-date"><div tabindex="0" role="group" aria-label="Outer host" data-testid="outer-host"></div>';
                const host=document.querySelector('[data-testid="outer-host"]');
                const root=host.attachShadow({{mode:'{outer}'}});
                root.innerHTML='<input aria-label="Pin" data-testid="pin" value="release approved"><div tabindex="0" role="group" aria-label="Inner host" data-testid="inner-host"></div>';
                const nestedHost=root.querySelector('[data-testid="inner-host"]');
                const nested=nestedHost.attachShadow({{mode:'{inner}'}});
                nested.innerHTML='<input aria-label="Tone" data-testid="tone" value="release approved"><input type="password" aria-label="Secret" data-testid="secret" value="synthetic-focus-secret"><div contenteditable="true" role="textbox" aria-label="Editor" data-testid="editor">release approved</div><span data-testid="outside">unrelated selection</span>';
                globalThis.nativeFocusFixture={{host,root,nestedHost,nested,pin:root.querySelector('input'),tone:nested.querySelector('[data-testid="tone"]'),secret:nested.querySelector('[data-testid="secret"]'),editor:nested.querySelector('[data-testid="editor"]'),outside:nested.querySelector('[data-testid="outside"]')}};
                nativeFocusFixture.pin.focus();nativeFocusFixture.pin.setSelectionRange(8,16);return true;
            }})()"#);
            evaluate_on(&browser.client, session, &fixture).await?;
            let inventory = frames(&browser, &op).await;
            let mut refs = RefMap::new();
            let pin = query_testid(&browser, &inventory, &mut refs, &op, "pin").await;
            assert_eq!(pin.states.get("focused"), Some(&true));
            assert_eq!(pin.selection.as_deref(), Some("approved"));
            let observed = observe(&browser.client, &inventory, &mut refs, "equivalence", 1, &ObservationOptions::default(), &op).await?;
            let focused: Vec<_> = flatten(&observed.roots).into_iter().filter(|node| node.states.get("focused") == Some(&true)).collect();
            assert_eq!(focused.len(), 1, "{outer}/{inner}");
            assert_eq!(focused[0].test_id.as_deref(), Some("pin"));
            let pin_read: ReadOptions = serde_json::from_value(json!({"ref":focused[0].reference.id,"fields":["states","selection"]})).unwrap();
            let fresh = read(&browser.client, &inventory, &mut refs, "equivalence", 1, &pin_read, &op).await?;
            assert_eq!(fresh["states"]["focused"], true);
            assert_eq!(fresh["selection"], "approved");

            evaluate_on(&browser.client, session, "nativeFocusFixture.tone.focus();nativeFocusFixture.tone.setSelectionRange(8,16);true").await?;
            let fresh = read(&browser.client, &inventory, &mut refs, "equivalence", 1, &pin_read, &op).await?;
            assert!(fresh["states"].get("focused").is_none(), "False focus is omitted at the public boundary");
            assert!(fresh["selection"].is_null());
            let tone = query_testid(&browser, &inventory, &mut refs, &op, "tone").await;
            assert_eq!(tone.states.get("focused"), Some(&true));
            assert_eq!(tone.selection.as_deref(), Some("approved"));
            let pin = query_testid(&browser, &inventory, &mut refs, &op, "pin").await;
            assert_ne!(pin.states.get("focused"), Some(&true));
            assert!(pin.selection.is_none());
            let observed = observe(&browser.client, &inventory, &mut refs, "equivalence", 2, &ObservationOptions::default(), &op).await?;
            let focused: Vec<_> = flatten(&observed.roots).into_iter().filter(|node| node.states.get("focused") == Some(&true)).collect();
            assert_eq!(focused.len(), 1);
            assert_eq!(focused[0].test_id.as_deref(), Some("tone"));

            let selected = evaluate_on(&browser.client, session, r#"(() => {
                const {editor,nested}=nativeFocusFixture;editor.focus();
                const range=document.createRange();range.setStart(editor.firstChild,8);range.setEnd(editor.firstChild,16);
                const selection=document.getSelection();selection.removeAllRanges();selection.addRange(range);
                return {focused:nested.activeElement===editor,contains:editor.contains(selection.getRangeAt(0).commonAncestorContainer),text:selection.toString()};
            })()"#).await?;
            assert_eq!(selected, json!({"focused":true,"contains":true,"text":"approved"}), "Native closed-root range fixture must establish containment, not replace selection getters");
            let editor = query_testid(&browser, &inventory, &mut refs, &op, "editor").await;
            assert_eq!(editor.states.get("focused"), Some(&true));
            assert_eq!(editor.selection.as_deref(), Some("approved"));
            let observed = observe(&browser.client, &inventory, &mut refs, "equivalence", 3, &ObservationOptions::default(), &op).await?;
            let focused: Vec<_> = flatten(&observed.roots).into_iter().filter(|node| node.states.get("focused") == Some(&true)).collect();
            assert_eq!(focused.len(), 1);
            assert_eq!(focused[0].test_id.as_deref(), Some("editor"));
            assert_eq!(focused[0].selection.as_deref(), Some("approved"));
            let editor_read: ReadOptions = serde_json::from_value(json!({"ref":focused[0].reference.id,"fields":["states","selection"]})).unwrap();
            let fresh = read(&browser.client, &inventory, &mut refs, "equivalence", 3, &editor_read, &op).await?;
            assert_eq!(fresh["states"]["focused"], true);
            assert_eq!(fresh["selection"], "approved");
            let outside = evaluate_on(&browser.client, session, r#"(() => {
                const {editor,outside,nested}=nativeFocusFixture;
                const range=document.createRange();range.selectNodeContents(outside);
                const selection=document.getSelection();selection.removeAllRanges();selection.addRange(range);
                return {focused:nested.activeElement===editor,contains:editor.contains(selection.getRangeAt(0).commonAncestorContainer),text:selection.toString()};
            })()"#).await?;
            assert_eq!(outside, json!({"focused":true,"contains":false,"text":"unrelated selection"}), "Outside-selection proof must keep the editor focused");
            let fresh = read(&browser.client, &inventory, &mut refs, "equivalence", 3, &editor_read, &op).await?;
            assert_eq!(fresh["states"]["focused"], true);
            assert!(fresh["selection"].is_null());
            let editor = query_testid(&browser, &inventory, &mut refs, &op, "editor").await;
            assert_eq!(editor.states.get("focused"), Some(&true));
            assert!(editor.selection.is_none());

            evaluate_on(&browser.client, session, "nativeFocusFixture.host.focus();nativeFocusFixture.root.activeElement===null").await?.as_bool().filter(|value| *value).expect("Fixture host must be the active leaf");
            let host = query_testid(&browser, &inventory, &mut refs, &op, "outer-host").await;
            assert_eq!(host.states.get("focused"), Some(&true));
            assert_ne!(query_testid(&browser, &inventory, &mut refs, &op, "tone").await.states.get("focused"), Some(&true));
            evaluate_on(&browser.client, session, "document.querySelector('[data-testid=native-date]').focus();true").await?;
            let native = query_testid(&browser, &inventory, &mut refs, &op, "native-date").await;
            assert_eq!(native.states.get("focused"), Some(&true), "UA implementation focus belongs to the author control");
            evaluate_on(&browser.client, session, "nativeFocusFixture.secret.focus();nativeFocusFixture.secret.setSelectionRange(0,9);true").await?;
            let secret = query_testid(&browser, &inventory, &mut refs, &op, "secret").await;
            assert_eq!(secret.states.get("focused"), Some(&true));
            assert_eq!(secret.states.get("secure"), Some(&true));
            assert!(secret.selection.is_none());
            assert!(secret.value.is_none());
            let observed = observe(&browser.client, &inventory, &mut refs, "equivalence", 4, &ObservationOptions::default(), &op).await?;
            assert!(!serde_json::to_string(&observed).unwrap().contains("synthetic-focus-secret"));

            evaluate_on(&browser.client, session, "nativeFocusFixture.tone.focus();true").await?;
            let observed = observe(&browser.client, &inventory, &mut refs, "equivalence", 5, &ObservationOptions::default(), &op).await?;
            let tone = flatten(&observed.roots).into_iter().find(|node| node.test_id.as_deref() == Some("tone")).unwrap();
            let tone_read: ReadOptions = serde_json::from_value(json!({"ref":tone.reference.id})).unwrap();
            let before = refs.ref_ids();
            if outer == "closed" && inner == "closed" {
                // Existing exact-operation navigation hook retires the loader
                // after metadata, not a new focus lifecycle subsystem.
                let (_guard, hook) = install(&op, Mode::Navigate, 1);
                assert_eq!(read(&browser.client, &inventory, &mut refs, "equivalence", 5, &tone_read, &op).await.unwrap_err(), ObservationError::StaleReference);
                assert_eq!(hook.calls.load(Ordering::SeqCst), 1);
            } else {
                evaluate_on(&browser.client, session, "nativeFocusFixture.host.remove();true").await?;
                assert_eq!(read(&browser.client, &inventory, &mut refs, "equivalence", 5, &tone_read, &op).await.unwrap_err(), ObservationError::StaleReference);
            }
            assert_eq!(refs.ref_ids(), before, "Refusal must not publish a focus identity");
        }
        Ok::<(), String>(())
    }.await;
    browser.close().await.unwrap();
    result.unwrap();
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

#[tokio::test]
async fn capture_retirement_is_task_scoped_and_does_not_leak_to_spawned_work() {
    assert!(!capture_superseded());
    assert!(!capture_retirement_active());
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let (lease, cancel) = operation();
    with_capture_retirement(Some(CaptureRetirement::new(receiver)), async {
        assert!(capture_retirement_active());
        assert_eq!(check(&lease), Ok(()));
        stop.send_replace(true);
        capture_retired().await;
        assert_eq!(check(&lease), Err(ObservationError::Superseded));
        assert!(!tokio::spawn(async { capture_superseded() }).await.unwrap());
        with_capture_retirement(None, async {
            assert!(!capture_retirement_active());
            assert!(!capture_superseded());
            assert_eq!(check(&lease), Ok(()));
        })
        .await;
        assert!(capture_superseded());
        cancel.send_replace(CancelSignal::Requested);
        assert_eq!(check(&lease), Err(ObservationError::Cancelled));
    })
    .await;
    assert!(!capture_superseded());
}

#[tokio::test]
async fn closed_retirement_channel_does_not_manufacture_supersession() {
    let (stop, receiver) = tokio::sync::watch::channel(false);
    drop(stop);
    with_capture_retirement(Some(CaptureRetirement::new(receiver)), async {
        assert!(!capture_superseded());
        assert!(
            tokio::time::timeout(Duration::from_millis(1), capture_retired())
                .await
                .is_err()
        );
    })
    .await;
}

#[tokio::test]
async fn established_deadline_and_cleanup_failure_are_not_relabeled_superseded() {
    let (stop, receiver) = tokio::sync::watch::channel(true);
    let (mut lease, cancel) = operation();
    lease.deadline = Instant::now();
    with_capture_retirement(Some(CaptureRetirement::new(receiver)), async {
        assert_eq!(check(&lease), Err(ObservationError::DeadlineExceeded));
        cancel.send_replace(CancelSignal::Requested);
        assert_eq!(check(&lease), Err(ObservationError::Cancelled));
        assert_eq!(
            settled_stop(ObservationError::DeadlineExceeded, &lease),
            ObservationError::DeadlineExceeded
        );
        let dirty = ObservationError::CleanupFailed {
            primary: Some(Box::new(ObservationError::Superseded)),
        };
        assert_eq!(settled_stop(dirty.clone(), &lease), dirty);
    })
    .await;
    drop(stop);
}

#[tokio::test]
async fn superseded_resource_reply_is_owned_before_exact_group_cleanup() {
    use futures_util::{SinkExt, StreamExt};
    for (late_reply, fail_cleanup) in [(true, false), (true, true), (false, false)] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (late_tx, late_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut started = Some(started_tx);
            let mut late = Some(late_rx);
            let mut methods = Vec::new();
            while let Some(Ok(message)) = socket.next().await {
                if !message.is_text() {
                    continue;
                }
                let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                let method = request["method"].as_str().unwrap();
                methods.push(method.to_owned());
                let result = match method {
                    "DOM.resolveNode" => {
                        started.take().unwrap().send(()).unwrap();
                        if !late_reply {
                            continue;
                        }
                        late.take().unwrap().await.unwrap();
                        json!({"object":{"type":"object","subtype":"node","objectId":"late-owned-node"}})
                    }
                    "Runtime.releaseObjectGroup" => {
                        assert_eq!(request["params"]["objectGroup"], "owned-retirement-test");
                        if fail_cleanup {
                            socket.send(tokio_tungstenite::tungstenite::Message::Text(json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic cleanup refusal"}}).to_string())).await.unwrap();
                            break;
                        }
                        json!({})
                    }
                    other => panic!("retired work dispatched downstream command {other}"),
                };
                socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        json!({"id":request["id"],"result":result}).to_string(),
                    ))
                    .await
                    .unwrap();
                if method == "Runtime.releaseObjectGroup" {
                    break;
                }
            }
            methods
        });
        let client = CdpClient::connect(&url).await.unwrap();
        let (mut lease, _cancel) = operation();
        if !late_reply {
            lease.deadline = Instant::now() + Duration::from_millis(50);
        }
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let owned = Arc::new(AtomicUsize::new(0));
        let read = with_capture_retirement(Some(CaptureRetirement::new(receiver)), async {
            let result = async {
                let remote = command(
                    &client,
                    "session",
                    "DOM.resolveNode",
                    json!({"backendNodeId":42,"objectGroup":"owned-retirement-test"}),
                    &lease,
                )
                .await?;
                assert_eq!(remote["object"]["objectId"], "late-owned-node");
                owned.fetch_add(1, Ordering::SeqCst);
                check(&lease)?;
                panic!("superseded acquisition resumed downstream work");
                #[allow(unreachable_code)]
                Ok::<(), ObservationError>(())
            }
            .await;
            settle_object_group(&client, "session", "owned-retirement-test", result, &lease).await
        });
        let retire = async {
            started_rx.await.unwrap();
            stop.send_replace(true);
            // Supersession must not truncate a resource command to the 250 ms
            // caller-cancellation cleanup budget. Its original lease is live.
            if late_reply {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            let _ = late_tx.send(());
        };
        let (result, ()) = tokio::join!(read, retire);
        assert_eq!(owned.load(Ordering::SeqCst), usize::from(late_reply));
        if late_reply && !fail_cleanup {
            assert_eq!(result, Err(ObservationError::Superseded));
        } else {
            assert!(matches!(
                result,
                Err(ObservationError::CleanupFailed { .. })
            ));
        }
        assert_eq!(
            server.await.unwrap(),
            ["DOM.resolveNode", "Runtime.releaseObjectGroup"]
        );
    }
}

#[tokio::test]
async fn metadata_hold_hook_retires_and_reports_only_its_acked_group() {
    let (lease, _cancel) = operation();
    let (other, _other_cancel) = operation();
    let (_guard, hold) = hold_metadata(&lease);
    let group = format!("native-metadata-{}", lease.sequence);
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let held = with_capture_retirement(Some(CaptureRetirement::new(receiver)), async {
        metadata_checkpoint(
            "DOM.resolveNode",
            "other-native-command",
            Some(&group),
            &json!({"object":{"objectId":"held-node"}}),
            &lease,
        )
        .await
        .unwrap();
        metadata_checkpoint(
            "Runtime.callFunctionOn",
            "metadata-batch",
            Some(&group),
            &json!({"result":{"value":[]}}),
            &lease,
        )
        .await
    });
    let retire = async {
        hold.reached().await;
        assert_eq!(hold.handles(), ["held-node"]);
        assert_eq!(hold.metadata_calls(), 1);
        assert_eq!(hold.releases(), 0);
        stop.send_replace(true);
    };
    let (result, ()) = tokio::join!(held, retire);
    assert_eq!(result, Err(ObservationError::Superseded));
    after_group_release(&other, &group);
    after_group_release(&lease, "native-security-not-metadata");
    assert_eq!(hold.releases(), 0);
    after_group_release(&lease, &group);
    assert_eq!(hold.releases(), 1);
    hold.release();
    assert_eq!(hold.metadata_calls(), 1);
}

#[tokio::test]
async fn metadata_acquisition_error_drains_started_sibling_before_group_release() {
    use futures_util::{SinkExt, StreamExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut first = None;
        let mut acquisitions = 0;
        let mut late_ack = false;
        while let Some(Ok(message)) = socket.next().await {
            if !message.is_text() {
                continue;
            }
            let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
            let result = match request["method"].as_str().unwrap() {
                "Page.createIsolatedWorld" => json!({"executionContextId":3}),
                "DOM.resolveNode" => {
                    acquisitions += 1;
                    if first.is_none() {
                        first = Some(request["id"].clone());
                        continue;
                    }
                    socket.send(tokio_tungstenite::tungstenite::Message::Text(json!({"id":first.take().unwrap(),"error":{"code":-32000,"message":"synthetic first acquisition failure"}}).to_string())).await.unwrap();
                    // The second acquisition is live. Early try_collect would
                    // drop it and release its group before its reply arrives.
                    tokio::select! {
                        request = socket.next() => panic!("group cleanup ran before started sibling settled: {}", request.is_some()),
                        _ = tokio::time::sleep(Duration::from_millis(30)) => {},
                    }
                    late_ack = true;
                    json!({"object":{"type":"object","subtype":"node","objectId":"sibling-owned"}})
                }
                "Runtime.releaseObjectGroup" => {
                    assert!(late_ack);
                    assert_eq!(acquisitions, 2);
                    socket
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            json!({"id":request["id"],"result":{}}).to_string(),
                        ))
                        .await
                        .unwrap();
                    return;
                }
                other => panic!("failed metadata acquisition dispatched {other}"),
            };
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    json!({"id":request["id"],"result":result}).to_string(),
                ))
                .await
                .unwrap();
        }
        panic!("metadata group was never released");
    });
    let client = CdpClient::connect(&url).await.unwrap();
    let (lease, _cancel) = operation();
    let frame = ObservationFrame {
        parent_frame_id: None,
        owner_backend_id: None,
        url: "https://synthetic.invalid/".into(),
        binding: ExactBinding {
            page_session: "session".into(),
            session: "session".into(),
            frame: "root".into(),
            loader: "document".into(),
            actionable: false,
        },
        offset_x: 0.,
        offset_y: 0.,
        frame_path: Vec::new(),
    };
    let first: AXNode =
        serde_json::from_value(json!({"nodeId":"one","backendDOMNodeId":41})).unwrap();
    let second: AXNode =
        serde_json::from_value(json!({"nodeId":"two","backendDOMNodeId":42})).unwrap();
    let result = read_batch_with_refs(
        &client,
        &frame,
        &[&first, &second],
        None,
        1,
        &ObservationOptions::default(),
        &lease,
        false,
        &SecurityInventory::default(),
    )
    .await;
    assert_eq!(result.unwrap_err(), ObservationError::BackendFailure);
    server.await.unwrap();
}
