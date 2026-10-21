//! Strict context-scoped storage-state transfer. No file IO, application navigation,
//! partial-success fallback, or plaintext diagnostic payloads live here.
use super::cdp::client::CdpClient;
use super::client_session::{CancelSignal, OperationLease};
use super::client_targets::{ClientTargets, TargetPurpose};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;

const MAX_STATE_BYTES: usize = 32 * 1024 * 1024;
const MAX_ORIGINS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    InvalidInput,
    IncompleteInventory,
    UnsupportedValue,
    Cancelled,
    Deadline,
    BrowserFailure,
    CleanupIntegrityLost,
}

/// Supplied by the native lifecycle owner under exclusive state admission.
/// Origins include every visited origin, not only currently open documents.
pub struct NativeStateContext<'a> {
    pub client: &'a CdpClient,
    pub context_id: &'a str,
    pub targets: &'a Arc<ClientTargets>,
    pub origins: &'a [String],
    pub origins_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeState {
    pub version: u32,
    pub cookies: Vec<Value>,
    pub origins: Vec<OriginState>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OriginState {
    pub origin: String,
    pub local_storage: Vec<StorageEntry>,
    /// Structured-clone graphs, database versions, stores and indexes. The
    /// schema is checked in the isolated bootstrap realm before any write.
    pub indexed_db: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageEntry {
    pub name: String,
    pub value: String,
}

fn check(operation: &OperationLease) -> Result<(), StateError> {
    if *operation.cancellation.borrow() != CancelSignal::None {
        return Err(StateError::Cancelled);
    }
    if std::time::Instant::now() >= operation.deadline {
        return Err(StateError::Deadline);
    }
    Ok(())
}
async fn command(
    client: &CdpClient,
    session: Option<&str>,
    method: &str,
    args: Value,
    operation: &OperationLease,
) -> Result<Value, StateError> {
    check(operation)?;
    let mut cancelled = operation.cancellation.clone();
    tokio::select! {
        value = client.send_command(method, Some(args), session) => { check(operation)?; value.map_err(|_| StateError::BrowserFailure) },
        _ = cancelled.changed() => Err(StateError::Cancelled),
        _ = tokio::time::sleep_until(operation.deadline.into()) => Err(StateError::Deadline),
    }
}
fn origin(value: &str) -> Result<(), StateError> {
    let parsed = url::Url::parse(value).map_err(|_| StateError::InvalidInput)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.origin().ascii_serialization() != value
    {
        return Err(StateError::InvalidInput);
    }
    Ok(())
}
fn validate_context(context: &NativeStateContext<'_>) -> Result<(), StateError> {
    if context.context_id.is_empty()
        || context.targets.context_id != context.context_id
        || !context.origins_complete
    {
        return Err(StateError::IncompleteInventory);
    }
    if context.origins.len() > MAX_ORIGINS {
        return Err(StateError::InvalidInput);
    }
    let mut unique = HashSet::new();
    for value in context.origins {
        origin(value)?;
        if !unique.insert(value) {
            return Err(StateError::InvalidInput);
        }
    }
    Ok(())
}
/// Cookies are round-tripped without dropping partition semantics. Opaque
/// partition keys cannot be restored and are refused rather than broadened.
fn cookie_parameters(cookie: &Value) -> Result<Value, StateError> {
    let fields = cookie.as_object().ok_or(StateError::InvalidInput)?;
    let allowed = [
        "name",
        "value",
        "domain",
        "path",
        "expires",
        "httpOnly",
        "secure",
        "sameSite",
        "priority",
        "sameParty",
        "sourceScheme",
        "sourcePort",
        "partitionKey",
        "partitionKeyOpaque",
        "size",
        "session",
    ];
    if fields.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(StateError::UnsupportedValue);
    }
    if fields.get("partitionKeyOpaque").and_then(Value::as_bool) == Some(true) {
        return Err(StateError::UnsupportedValue);
    }
    for key in ["name", "value", "domain", "path"] {
        if !fields.get(key).is_some_and(Value::is_string) {
            return Err(StateError::InvalidInput);
        }
    }
    for key in [
        "httpOnly",
        "secure",
        "sameParty",
        "session",
        "partitionKeyOpaque",
    ] {
        if fields.get(key).is_some_and(|value| !value.is_boolean()) {
            return Err(StateError::InvalidInput);
        }
    }
    for (key, choices) in [
        ("sameSite", &["Strict", "Lax", "None"][..]),
        ("priority", &["Low", "Medium", "High"][..]),
        ("sourceScheme", &["Unset", "NonSecure", "Secure"][..]),
    ] {
        if fields
            .get(key)
            .is_some_and(|value| !value.as_str().is_some_and(|value| choices.contains(&value)))
        {
            return Err(StateError::InvalidInput);
        }
    }
    if fields
        .get("expires")
        .is_some_and(|value| !value.as_f64().is_some_and(f64::is_finite))
        || fields
            .get("size")
            .is_some_and(|value| value.as_u64().is_none())
        || fields.get("sourcePort").is_some_and(|value| {
            !value
                .as_i64()
                .is_some_and(|port| (-1..=65535).contains(&port))
        })
    {
        return Err(StateError::InvalidInput);
    }
    if let Some(partition) = fields.get("partitionKey") {
        let partition = partition.as_object().ok_or(StateError::InvalidInput)?;
        if partition.len() != 2
            || !partition
                .get("hasCrossSiteAncestor")
                .is_some_and(Value::is_boolean)
        {
            return Err(StateError::InvalidInput);
        }
        origin(
            partition
                .get("topLevelSite")
                .and_then(Value::as_str)
                .ok_or(StateError::InvalidInput)?,
        )?;
    }
    let mut result = fields.clone();
    for key in ["size", "session", "partitionKeyOpaque"] {
        result.remove(key);
    }
    Ok(Value::Object(result))
}
fn validate_state(state: &NativeState) -> Result<(), StateError> {
    if state.version != 1 || state.origins.len() > MAX_ORIGINS {
        return Err(StateError::InvalidInput);
    }
    if serde_json::to_vec(state)
        .map_err(|_| StateError::InvalidInput)?
        .len()
        > MAX_STATE_BYTES
    {
        return Err(StateError::InvalidInput);
    }
    let mut origins = HashSet::new();
    for item in &state.origins {
        origin(&item.origin)?;
        if !origins.insert(&item.origin) || !item.indexed_db.is_array() {
            return Err(StateError::InvalidInput);
        }
        let mut keys = HashSet::new();
        if item
            .local_storage
            .iter()
            .any(|entry| !keys.insert(&entry.name))
        {
            return Err(StateError::InvalidInput);
        }
    }
    for cookie in &state.cookies {
        cookie_parameters(cookie)?;
    }
    Ok(())
}

/// A synthetic, intercepted document with an origin but no application script.
/// The lifecycle owner must classify all targets created during this exclusive
/// transaction as bootstrap targets, never hand their requests to user routes.
struct Bootstrap {
    target: String,
    session: String,
}
struct PrivateSubscription<'a> {
    client: &'a CdpClient,
    session: &'a str,
}
impl Drop for PrivateSubscription<'_> {
    fn drop(&mut self) {
        self.client.unsubscribe_session(self.session);
    }
}
async fn close_bootstrap(client: &CdpClient, target: &str) -> Result<(), StateError> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.send_command("Target.closeTarget", Some(json!({"targetId":target})), None),
    )
    .await
    {
        Ok(Ok(value)) if value.get("success").and_then(Value::as_bool) == Some(true) => Ok(()),
        _ => Err(StateError::CleanupIntegrityLost),
    }
}
async fn bootstrap(
    context: &NativeStateContext<'_>,
    origin: &str,
    operation: &OperationLease,
) -> Result<Bootstrap, StateError> {
    // Reserve exact purpose before browser-side creation. No URL/opener guess
    // and no second target attachment competes with the native event owner.
    let mut reservation = context
        .targets
        .reserve_creation(TargetPurpose::StateBootstrap)
        .map_err(|_| StateError::IncompleteInventory)?;
    // Creation may have happened if acknowledgement is lost. The caller must
    // dispose the replacement context on any uncertainty, not reuse it.
    let created = command(
        context.client,
        None,
        "Target.createTarget",
        json!({"url":"about:blank","browserContextId":context.context_id}),
        operation,
    )
    .await
    .map_err(|_| StateError::CleanupIntegrityLost)?;
    let target = created["targetId"]
        .as_str()
        .ok_or(StateError::CleanupIntegrityLost)?
        .to_owned();
    let result = async {
        let mut cancellation=operation.cancellation.clone();
        tokio::select! {
            result=context.targets.wait_attached(&target)=>result.map_err(|_|StateError::IncompleteInventory)?,
            _=cancellation.changed()=>return Err(StateError::Cancelled),
            _=tokio::time::sleep_until(operation.deadline.into())=>return Err(StateError::Deadline),
        }
        reservation.claim(&target).map_err(|_|StateError::IncompleteInventory)?;
        let attachment=context.targets.owned_target(&target).map_err(|_|StateError::IncompleteInventory)?;
        if attachment.kind!="page" || attachment.purpose!=Some(TargetPurpose::StateBootstrap) {return Err(StateError::IncompleteInventory);}
        let session=attachment.session_id;
        drop(reservation);
        command(context.client, Some(&session), "Page.enable", json!({}), operation).await?;
        command(context.client, Some(&session), "Page.setLifecycleEventsEnabled", json!({"enabled":true}), operation).await?;
        command(context.client, Some(&session), "Network.enable", json!({}), operation).await?;
        command(context.client, Some(&session), "Network.setBypassServiceWorker", json!({"bypass":true}), operation).await?;
        // Session-private delivery is bounded; no unrelated tenant events enter
        // this receiver. The native registry reserves this target to state IO.
        let mut events = context.client.subscribe_session(&session);
        let _subscription = PrivateSubscription { client: context.client, session: &session };
        command(context.client, Some(&session), "Fetch.enable", json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}]}), operation).await?;
        context.targets.configured(&target).map_err(|_|StateError::IncompleteInventory)?;
        let resume=tokio::select! {
            result=context.targets.resume_permit(&target)=>result.map_err(|_|StateError::IncompleteInventory)?,
            _=cancellation.changed()=>return Err(StateError::Cancelled),
            _=tokio::time::sleep_until(operation.deadline.into())=>return Err(StateError::Deadline),
        };
        command(context.client,Some(&session),"Runtime.runIfWaitingForDebugger",json!({}),operation).await?;
        resume.complete().map_err(|_|StateError::IncompleteInventory)?;
        let url = format!("{origin}/__agent_browser_state_bootstrap__");
        let navigate = command(context.client, Some(&session), "Page.navigate", json!({"url":url}), operation);
        tokio::pin!(navigate);
        let mut fulfilled = false;
        let mut navigation: Option<Value> = None;
        let mut loaded = HashSet::new();
        let mut cancelled = operation.cancellation.clone();
        let result = loop {
            if let Some(result) = &navigation {
                if result.get("errorText").is_some() { break Err(StateError::BrowserFailure); }
                if result["loaderId"].as_str().is_some_and(|id| loaded.contains(id)) { break Ok(result.clone()); }
            }
            tokio::select! {
                result = &mut navigate, if navigation.is_none() => navigation = Some(result?),
                _ = cancelled.changed() => break Err(StateError::Cancelled),
                _ = tokio::time::sleep_until(operation.deadline.into()) => break Err(StateError::Deadline),
                event = events.recv() => {
                    let event = event.ok_or(StateError::BrowserFailure)?;
                    if event.method == "Page.lifecycleEvent" && event.params["name"].as_str() == Some("DOMContentLoaded") {
                        if let Some(loader) = event.params["loaderId"].as_str() { loaded.insert(loader.to_owned()); }
                        continue;
                    }
                    if event.method != "Fetch.requestPaused" { continue; }
                    let id = event.params["requestId"].as_str().ok_or(StateError::BrowserFailure)?;
                    if fulfilled || event.params["request"]["url"].as_str() != Some(&url) || event.params["resourceType"].as_str() != Some("Document") {
                        command(context.client, Some(&session), "Fetch.failRequest", json!({"requestId":id,"errorReason":"BlockedByClient"}), operation).await?;
                        return Err(StateError::BrowserFailure);
                    }
                    command(context.client, Some(&session), "Fetch.fulfillRequest", json!({"requestId":id,"responseCode":200,"responseHeaders":[{"name":"Content-Type","value":"text/html"},{"name":"Content-Security-Policy","value":"default-src 'none'; script-src 'none'"}],"body":"PCFkb2N0eXBlIGh0bWw+PHRpdGxlPjwvdGl0bGU+"}), operation).await?;
                    fulfilled = true;
                }
            }
        }?;
        context.client.unsubscribe_session(&session);
        if !fulfilled || result.get("errorText").is_some() { return Err(StateError::BrowserFailure); }
        // Fetch stays enabled until this target closes. No favicon or unexpected
        // resource is ever allowed to escape to the real network.
        Ok(Bootstrap { target: target.clone(), session: session.clone() })
    }.await;
    match result {
        Ok(page) => Ok(page),
        Err(error) => {
            close_bootstrap(context.client, &target).await?;
            Err(error)
        }
    }
}
async fn evaluate(
    context: &NativeStateContext<'_>,
    page: &Bootstrap,
    expression: String,
    operation: &OperationLease,
) -> Result<Value, StateError> {
    let tree = command(
        context.client,
        Some(&page.session),
        "Page.getFrameTree",
        json!({}),
        operation,
    )
    .await?;
    let frame = tree["frameTree"]["frame"]["id"]
        .as_str()
        .ok_or(StateError::BrowserFailure)?;
    let world = command(
        context.client,
        Some(&page.session),
        "Page.createIsolatedWorld",
        json!({"frameId":frame,"worldName":"agent-browser-state"}),
        operation,
    )
    .await?;
    let realm = world["executionContextId"]
        .as_i64()
        .ok_or(StateError::BrowserFailure)?;
    let result = command(
        context.client,
        Some(&page.session),
        "Runtime.evaluate",
        json!({"expression":expression,"contextId":realm,"awaitPromise":true,"returnByValue":true}),
        operation,
    )
    .await?;
    if result.get("exceptionDetails").is_some() {
        return Err(StateError::UnsupportedValue);
    }
    result["result"]
        .get("value")
        .cloned()
        .ok_or(StateError::BrowserFailure)
}

/// Export every required category or fail; no failed origin becomes an empty one.
pub async fn export_state(
    context: &NativeStateContext<'_>,
    operation: &OperationLease,
) -> Result<NativeState, StateError> {
    validate_context(context)?;
    let value = command(
        context.client,
        None,
        "Storage.getCookies",
        json!({"browserContextId":context.context_id}),
        operation,
    )
    .await?;
    let cookies = value["cookies"]
        .as_array()
        .ok_or(StateError::BrowserFailure)?
        .clone();
    for cookie in &cookies {
        cookie_parameters(cookie)?;
    }
    let mut origins = Vec::new();
    for origin in context.origins {
        let page = bootstrap(context, origin, operation).await?;
        let result = evaluate(
            context,
            &page,
            format!("({STATE_SCRIPT})('export', null)"),
            operation,
        )
        .await;
        close_bootstrap(context.client, &page.target).await?;
        let mut entry: OriginState =
            serde_json::from_value(result?).map_err(|_| StateError::BrowserFailure)?;
        if entry.origin != *origin {
            return Err(StateError::BrowserFailure);
        }
        entry.origin = origin.clone();
        origins.push(entry);
    }
    let state = NativeState {
        version: 1,
        cookies,
        origins,
    };
    validate_state(&state)?;
    check(operation)?;
    Ok(state)
}

/// Import only into a newly owned blank context. Any failure requires that
/// entire context to be discarded before application navigation is admitted.
pub async fn import_state(
    context: &NativeStateContext<'_>,
    state: &NativeState,
    operation: &OperationLease,
) -> Result<(), StateError> {
    validate_context(context)?;
    validate_state(state)?;
    if !context.origins.is_empty() {
        return Err(StateError::InvalidInput);
    }
    let cookies: Vec<Value> = state
        .cookies
        .iter()
        .map(cookie_parameters)
        .collect::<Result<_, _>>()?;
    command(
        context.client,
        None,
        "Storage.setCookies",
        json!({"browserContextId":context.context_id,"cookies":cookies}),
        operation,
    )
    .await?;
    for item in &state.origins {
        let page = bootstrap(context, &item.origin, operation).await?;
        let payload = serde_json::to_string(item).map_err(|_| StateError::InvalidInput)?;
        let result = evaluate(
            context,
            &page,
            format!("({STATE_SCRIPT})('import', {payload})"),
            operation,
        )
        .await;
        close_bootstrap(context.client, &page.target).await?;
        if result? != Value::Bool(true) {
            return Err(StateError::BrowserFailure);
        }
    }
    check(operation)
}

// Runs only in a native-owned isolated synthetic document. IndexedDB uses its
// normal structured-clone semantics; this codec preserves cycles and binary,
// date, bigint, map, set, blob and file values instead of JSON-flattening them.
const STATE_SCRIPT: &str = r#"async function(mode, input) {
 const fail=()=>{throw new Error('Unsupported state value');};
 const request=r=>new Promise((yes,no)=>{r.onsuccess=()=>yes(r.result);r.onerror=()=>no(new Error('State request failed'));});
 const completion=t=>new Promise((yes,no)=>{t.oncomplete=yes;t.onerror=t.onabort=()=>no(new Error('State transaction failed'));});
 const base64=b=>{let s='';for(let i=0;i<b.length;i+=8192)s+=String.fromCharCode(...b.subarray(i,i+8192));return btoa(s);};
 const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
 async function encode(value) {
  const nodes=[],seen=new Map();
  async function visit(v,depth=0) {
   if(depth>256||nodes.length>100000)fail();
   if(v===undefined)return {u:true};
   if(typeof v==='bigint')return {b:String(v)};
   if(typeof v==='number'&&(!Number.isFinite(v)||Object.is(v,-0)))return {n:Object.is(v,-0)?'-0':String(v)};
   if(v===null||['string','boolean','number'].includes(typeof v))return {v};
   if(typeof v!=='object')fail();
   if(seen.has(v))return {r:seen.get(v)};
   const id=nodes.length;seen.set(v,id);nodes.push(null);
   let n;
   if(v instanceof Date)n={t:'date',v:Number.isNaN(v.getTime())?'NaN':String(v.getTime())};
   else if(v instanceof URL)n={t:'url',v:v.href};
   else if(v instanceof Error)n={t:'error',name:String(v.name),message:String(v.message),stack:typeof v.stack==='string'?v.stack:String(v.name)+': '+String(v.message),cause:Object.hasOwn(v,'cause')?await visit(v.cause,depth+1):undefined};
   else if(v instanceof RegExp)n={t:'regexp',source:v.source,flags:v.flags};
   else if(v instanceof ArrayBuffer)n={t:'buffer',data:base64(new Uint8Array(v))};
   else if(ArrayBuffer.isView(v)){const kind=v.constructor.name;if(!['Int8Array','Uint8Array','Uint8ClampedArray','Int16Array','Uint16Array','Int32Array','Uint32Array','Float32Array','Float64Array','BigInt64Array','BigUint64Array','DataView'].includes(kind))fail();n={t:'view',kind,buffer:await visit(v.buffer,depth+1),offset:v.byteOffset,length:v instanceof DataView?v.byteLength:v.length};}
   else if(v instanceof Blob)n={t:v instanceof File?'file':'blob',type:v.type,name:v instanceof File?v.name:undefined,lastModified:v instanceof File?v.lastModified:undefined,data:base64(new Uint8Array(await v.arrayBuffer()))};
   else if(v instanceof Map){n={t:'map',entries:[]};for(const [k,x]of v)n.entries.push([await visit(k,depth+1),await visit(x,depth+1)]);}
   else if(v instanceof Set){n={t:'set',values:[]};for(const x of v)n.values.push(await visit(x,depth+1));}
   else if(Array.isArray(v)||Object.getPrototypeOf(v)===Object.prototype||Object.getPrototypeOf(v)===null){n={t:Array.isArray(v)?'array':'object',entries:[]};if(Array.isArray(v)){if(v.length>10000000)fail();n.length=v.length;}for(const k of Object.keys(v))n.entries.push([k,await visit(v[k],depth+1)]);}
   else fail();
   nodes[id]=n;return {r:id};
  }
  return {root:await visit(value),nodes};
 }
 function decode(graph) {
  if(!graph||!Array.isArray(graph.nodes)||graph.nodes.length>100000)fail();
  const cache=new Map(),active=new Set();
  function visit(v,depth=0) {
   if(depth>256||!v||typeof v!=='object'||Object.keys(v).length!==1)fail();
   if('v'in v){if(v.v!==null&&!['number','string','boolean'].includes(typeof v.v))fail();return v.v;}
   if(v.u===true)return undefined;
   if(typeof v.b==='string')return BigInt(v.b);
   if(typeof v.n==='string'&&['NaN','Infinity','-Infinity','-0'].includes(v.n))return v.n==='-0'?-0:Number(v.n);
   if(!Number.isSafeInteger(v.r)||v.r<0||v.r>=graph.nodes.length)fail();
   if(cache.has(v.r))return cache.get(v.r);
   if(active.has(v.r))fail();active.add(v.r);
   const n=graph.nodes[v.r];if(!n||typeof n!=='object')fail();let out;
   switch(n.t){
    case 'date':out=new Date(n.v==='NaN'?NaN:Number(n.v));break;
    case 'url':if(typeof n.v!=='string')fail();out=new URL(n.v);break;
    case 'error':if(typeof n.name!=='string'||typeof n.message!=='string'||typeof n.stack!=='string')fail();out=new Error(n.message);out.name=n.name;out.stack=n.stack;break;
    case 'regexp':out=new RegExp(n.source,n.flags);break;
    case 'buffer':out=bytes(n.data).buffer;break;
    case 'view':{const types={Int8Array,Uint8Array,Uint8ClampedArray,Int16Array,Uint16Array,Int32Array,Uint32Array,Float32Array,Float64Array,BigInt64Array,BigUint64Array,DataView};const C=Object.hasOwn(types,n.kind)?types[n.kind]:null;if(!C||!Number.isSafeInteger(n.offset)||!Number.isSafeInteger(n.length)||n.offset<0||n.length<0)fail();out=new C(visit(n.buffer,depth+1),n.offset,n.length);break;}
    case 'blob':out=new Blob([bytes(n.data)],{type:n.type});break;
    case 'file':out=new File([bytes(n.data)],n.name,{type:n.type,lastModified:n.lastModified});break;
    case 'map':out=new Map();break;
    case 'set':out=new Set();break;
    case 'array':if(!Number.isSafeInteger(n.length)||n.length<0||n.length>10000000)fail();out=new Array(n.length);break;
    case 'object':out={};break;
    default:fail();
   }
   cache.set(v.r,out);
   if(n.t==='error'&&n.cause!==undefined)Object.defineProperty(out,'cause',{value:visit(n.cause,depth+1),writable:true,configurable:true});
   if(n.t==='map')for(const [k,x]of n.entries)out.set(visit(k,depth+1),visit(x,depth+1));
   if(n.t==='set')for(const x of n.values)out.add(visit(x,depth+1));
   if(n.t==='object'||n.t==='array'){const keys=new Set();if(!Array.isArray(n.entries))fail();for(const [k,x]of n.entries){if(typeof k!=='string'||keys.has(k))fail();keys.add(k);if(n.t==='array'&&(k==='length'||/^(0|[1-9][0-9]*)$/.test(k)&&Number(k)<4294967295&&Number(k)>=n.length))fail();Object.defineProperty(out,k,{value:visit(x,depth+1),writable:true,enumerable:true,configurable:true});}}
   active.delete(v.r);return out;
  }
  return visit(graph.root);
 }
 const keyPath=k=>k===null||typeof k==='string'||Array.isArray(k)&&k.every(v=>typeof v==='string');
 if(mode==='export') {
  const result={origin:location.origin,localStorage:[],indexedDb:[]};
  for(let i=0;i<localStorage.length;i++){const name=localStorage.key(i);if(name===null)fail();const value=localStorage.getItem(name);if(value===null)fail();result.localStorage.push({name,value});}
  for(const info of await indexedDB.databases()) {
   if(typeof info.name!=='string'||!Number.isSafeInteger(info.version)||info.version<1)fail();
   const opening=indexedDB.open(info.name,info.version);opening.onupgradeneeded=()=>opening.transaction.abort();const db=await request(opening);
   try {
    const names=Array.from(db.objectStoreNames),saved={name:db.name,version:db.version,stores:[]};
    if(names.length){const tx=db.transaction(names,'readonly'),done=completion(tx);const pending=names.map(name=>{
     const store=tx.objectStore(name),meta={name,keyPath:store.keyPath,autoIncrement:store.autoIncrement,indexes:Array.from(store.indexNames,k=>{const x=store.index(k);return {name:x.name,keyPath:x.keyPath,unique:x.unique,multiEntry:x.multiEntry};}),records:[]};
     return new Promise((yes,no)=>{const cursor=store.openCursor();cursor.onerror=()=>no(new Error('State cursor failed'));cursor.onsuccess=()=>{const c=cursor.result;if(!c){yes(meta);return;}meta.records.push({key:c.key,value:c.value});c.continue();};});
    });const [stores]=await Promise.all([Promise.all(pending),done]);
    for(const store of stores){for(const record of store.records){record.key=await encode(record.key);record.value=await encode(record.value);}saved.stores.push(store);}}
    result.indexedDb.push(saved);
   } finally { db.close(); }
  }
  if(JSON.stringify(result).length>33554432)fail();return result;
 }
 if(mode!=='import'||!input||input.origin!==location.origin||!Array.isArray(input.localStorage)||!Array.isArray(input.indexedDb))fail();
 // Decode and validate the whole origin before its first persistent write.
 const databaseNames=new Set(),prepared=[];
 for(const db of input.indexedDb){
  if(typeof db.name!=='string'||databaseNames.has(db.name)||!Number.isSafeInteger(db.version)||db.version<1||!Array.isArray(db.stores))fail();databaseNames.add(db.name);
  const stores=new Set();const copy={name:db.name,version:db.version,stores:[]};
  for(const s of db.stores){if(typeof s.name!=='string'||stores.has(s.name)||!keyPath(s.keyPath)||typeof s.autoIncrement!=='boolean'||!Array.isArray(s.indexes)||!Array.isArray(s.records))fail();stores.add(s.name);
   const indexes=new Set();for(const x of s.indexes){if(typeof x.name!=='string'||indexes.has(x.name)||!keyPath(x.keyPath)||x.keyPath===null||typeof x.unique!=='boolean'||typeof x.multiEntry!=='boolean')fail();indexes.add(x.name);}
   copy.stores.push({...s,records:s.records.map(r=>({key:decode(r.key),value:decode(r.value)}))});}
  prepared.push(copy);
 }
 const keys=new Set();for(const x of input.localStorage){if(typeof x.name!=='string'||typeof x.value!=='string'||keys.has(x.name))fail();keys.add(x.name);}
 if(localStorage.length||(await indexedDB.databases()).length)throw new Error('State destination is not blank');
 for(const x of input.localStorage)localStorage.setItem(x.name,x.value);
 for(const saved of prepared){
  const opening=indexedDB.open(saved.name,saved.version);
  opening.onupgradeneeded=event=>{if(event.oldVersion!==0){opening.transaction.abort();return;}for(const s of saved.stores){const store=opening.result.createObjectStore(s.name,{keyPath:s.keyPath,autoIncrement:s.autoIncrement});for(const x of s.indexes)store.createIndex(x.name,x.keyPath,{unique:x.unique,multiEntry:x.multiEntry});}};
  const db=await request(opening);
  try {if(saved.stores.length){const tx=db.transaction(saved.stores.map(s=>s.name),'readwrite'),done=completion(tx);for(const s of saved.stores){const store=tx.objectStore(s.name);for(const r of s.records){if(s.keyPath===null)store.add(r.value,r.key);else store.add(r.value);}}await done;}}finally{db.close();}
 }
 return true;
}"#;

/// Import the former public engine envelope's DATA only. This is a validated
/// format conversion, not a Playwright runtime or a relabelled native snapshot.
pub fn convert_playwright_state(input: Value) -> Result<NativeState, StateError> {
    if serde_json::to_vec(&input)
        .map_err(|_| StateError::InvalidInput)?
        .len()
        > MAX_STATE_BYTES
    {
        return Err(StateError::InvalidInput);
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Legacy {
        cookies: Vec<Value>,
        origins: Vec<LegacyOrigin>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct LegacyOrigin {
        origin: String,
        local_storage: Vec<StorageEntry>,
        #[serde(default, rename = "indexedDB")]
        databases: Vec<LegacyDatabase>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyDatabase {
        name: String,
        version: u64,
        stores: Vec<LegacyStore>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct LegacyStore {
        name: String,
        #[serde(default)]
        key_path: Option<String>,
        #[serde(default)]
        key_path_array: Option<Vec<String>>,
        auto_increment: bool,
        indexes: Vec<LegacyIndex>,
        records: Vec<Value>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct LegacyIndex {
        name: String,
        #[serde(default)]
        key_path: Option<String>,
        #[serde(default)]
        key_path_array: Option<Vec<String>>,
        unique: bool,
        multi_entry: bool,
    }
    fn key_path(single: Option<String>, array: Option<Vec<String>>) -> Result<Value, StateError> {
        match (single, array) {
            (Some(_), Some(_)) => Err(StateError::InvalidInput),
            (Some(v), None) => Ok(json!(v)),
            (None, Some(v)) => Ok(json!(v)),
            (None, None) => Ok(Value::Null),
        }
    }
    fn record_graph(
        record: &serde_json::Map<String, Value>,
        plain: &str,
        encoded: &str,
        required: bool,
    ) -> Result<Value, StateError> {
        match (record.get(plain), record.get(encoded)) {
            (Some(_), Some(_)) => Err(StateError::InvalidInput),
            (Some(value), None) => LegacyGraph::convert(value, false),
            (None, Some(value)) => LegacyGraph::convert(value, true),
            (None, None) if !required => Ok(json!({"root":{"u":true},"nodes":[]})),
            _ => Err(StateError::InvalidInput),
        }
    }
    let legacy: Legacy = serde_json::from_value(input).map_err(|_| StateError::InvalidInput)?;
    let mut cookies = Vec::new();
    for cookie in legacy.cookies {
        let mut cookie = cookie
            .as_object()
            .cloned()
            .ok_or(StateError::InvalidInput)?;
        let ancestor = cookie.remove("_crHasCrossSiteAncestor");
        if ancestor.as_ref().is_some_and(|v| !v.is_boolean()) {
            return Err(StateError::InvalidInput);
        }
        if let Some(partition) = cookie.remove("partitionKey") {
            let site = partition.as_str().ok_or(StateError::InvalidInput)?;
            origin(site)?;
            cookie.insert("partitionKey".into(),json!({"topLevelSite":site,"hasCrossSiteAncestor":ancestor.and_then(|v|v.as_bool()).unwrap_or(true)}));
        } else if ancestor.is_some() {
            return Err(StateError::InvalidInput);
        }
        let cookie = Value::Object(cookie);
        cookie_parameters(&cookie)?;
        cookies.push(cookie);
    }
    let mut origins = Vec::new();
    for source in legacy.origins {
        let mut databases = Vec::new();
        let mut database_names = HashSet::new();
        for database in source.databases {
            if database.version == 0
                || database.version > 9_007_199_254_740_991
                || !database_names.insert(database.name.clone())
            {
                return Err(StateError::InvalidInput);
            }
            let mut stores = Vec::new();
            let mut store_names = HashSet::new();
            for store in database.stores {
                if !store_names.insert(store.name.clone()) {
                    return Err(StateError::InvalidInput);
                }
                let path = key_path(store.key_path, store.key_path_array)?;
                let mut indexes = Vec::new();
                let mut index_names = HashSet::new();
                for index in store.indexes {
                    if !index_names.insert(index.name.clone()) {
                        return Err(StateError::InvalidInput);
                    }
                    let index_path = key_path(index.key_path, index.key_path_array)?;
                    if index_path.is_null() {
                        return Err(StateError::InvalidInput);
                    }
                    indexes.push(json!({"name":index.name,"keyPath":index_path,"unique":index.unique,"multiEntry":index.multi_entry}));
                }
                let mut records = Vec::new();
                for record in store.records {
                    let record = record.as_object().ok_or(StateError::InvalidInput)?;
                    if record.keys().any(|k| {
                        !matches!(k.as_str(), "key" | "keyEncoded" | "value" | "valueEncoded")
                    }) {
                        return Err(StateError::InvalidInput);
                    }
                    if !path.is_null()
                        && (record.contains_key("key") || record.contains_key("keyEncoded"))
                    {
                        return Err(StateError::InvalidInput);
                    }
                    let key = record_graph(record, "key", "keyEncoded", path.is_null())?;
                    let value = record_graph(record, "value", "valueEncoded", true)?;
                    records.push(json!({"key":key,"value":value}));
                }
                stores.push(json!({"name":store.name,"keyPath":path,"autoIncrement":store.auto_increment,"indexes":indexes,"records":records}));
            }
            databases
                .push(json!({"name":database.name,"version":database.version,"stores":stores}));
        }
        origins.push(OriginState {
            origin: source.origin,
            local_storage: source.local_storage,
            indexed_db: json!(databases),
        });
    }
    let state = NativeState {
        version: 1,
        cookies,
        origins,
    };
    validate_state(&state)?;
    Ok(state)
}

#[derive(Default)]
struct LegacyGraph {
    nodes: Vec<Value>,
    ids: std::collections::HashMap<u64, usize>,
}
impl LegacyGraph {
    fn convert(value: &Value, encoded: bool) -> Result<Value, StateError> {
        // Reject excessive raw nesting iteratively before recursive codec work.
        // Legacy encoded containers add wrapper objects/arrays at each level;
        // this cap also keeps conversion below the native thread stack budget.
        let mut pending = vec![(value, 0usize)];
        let mut visited = 0usize;
        while let Some((item, depth)) = pending.pop() {
            visited += 1;
            if depth > 128 || visited > 100_000 {
                return Err(StateError::InvalidInput);
            }
            match item {
                Value::Array(items) => pending.extend(items.iter().map(|item| (item, depth + 1))),
                Value::Object(items) => {
                    pending.extend(items.values().map(|item| (item, depth + 1)))
                }
                _ => {}
            }
            if pending.len() > 100_000 {
                return Err(StateError::InvalidInput);
            }
        }
        let mut graph = Self::default();
        let root = graph.visit(value, encoded, 0)?;
        Ok(json!({"root":root,"nodes":graph.nodes}))
    }
    fn allocate(&mut self, node: Value) -> Result<usize, StateError> {
        if self.nodes.len() >= 100_000 {
            return Err(StateError::InvalidInput);
        }
        let id = self.nodes.len();
        self.nodes.push(node);
        Ok(id)
    }
    fn tagged(&mut self, node: Value) -> Result<Value, StateError> {
        let id = self.allocate(node)?;
        Ok(json!({"r":id}))
    }
    fn visit(&mut self, value: &Value, encoded: bool, depth: usize) -> Result<Value, StateError> {
        if depth > 256 {
            return Err(StateError::InvalidInput);
        }
        if !encoded {
            return match value {
                Value::Array(items) => {
                    let id = self.allocate(Value::Null)?;
                    let entries = items
                        .iter()
                        .enumerate()
                        .map(|(i, v)| Ok(json!([i.to_string(), self.visit(v, false, depth + 1)?])))
                        .collect::<Result<Vec<_>, StateError>>()?;
                    self.nodes[id] = json!({"t":"array","length":items.len(),"entries":entries});
                    Ok(json!({"r":id}))
                }
                Value::Object(items) => {
                    let id = self.allocate(Value::Null)?;
                    let entries = items
                        .iter()
                        .map(|(k, v)| Ok(json!([k, self.visit(v, false, depth + 1)?])))
                        .collect::<Result<Vec<_>, StateError>>()?;
                    self.nodes[id] = json!({"t":"object","entries":entries});
                    Ok(json!({"r":id}))
                }
                _ => Ok(json!({"v":value})),
            };
        }
        let Some(object) = value.as_object() else {
            return if value.is_array() {
                Err(StateError::InvalidInput)
            } else {
                Ok(json!({"v":value}))
            };
        };
        if let Some(reference) = object.get("ref") {
            if object.len() != 1 {
                return Err(StateError::InvalidInput);
            }
            let id = reference
                .as_u64()
                .and_then(|id| self.ids.get(&id))
                .ok_or(StateError::InvalidInput)?;
            return Ok(json!({"r":id}));
        }
        let tags: [&str; 14] = [
            "v", "d", "u", "bi", "e", "r", "a", "o", "m", "s", "ta", "ab", "h", "fn",
        ];
        let present: Vec<_> = tags
            .iter()
            .copied()
            .filter(|tag| object.contains_key(*tag))
            .collect();
        if present.len() != 1 {
            return Err(StateError::InvalidInput);
        }
        let tag = present[0];
        let container = matches!(tag, "a" | "o" | "m" | "s");
        if object
            .keys()
            .any(|key| key != tag && !(container && key == "id"))
        {
            return Err(StateError::InvalidInput);
        }
        let field = &object[tag];
        let text = || field.as_str().ok_or(StateError::InvalidInput);
        match tag {
            "h" | "fn" => Err(StateError::UnsupportedValue),
            "v" => match text()? {
                "undefined" => Ok(json!({"u":true})),
                "null" => Ok(json!({"v":null})),
                v @ ("NaN" | "Infinity" | "-Infinity" | "-0") => Ok(json!({"n":v})),
                _ => Err(StateError::InvalidInput),
            },
            "bi" => {
                let number = text()?;
                let digits = number.strip_prefix('-').unwrap_or(number);
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(StateError::InvalidInput);
                }
                Ok(json!({"b":number}))
            }
            "d" => {
                let timestamp = if field.is_null() {
                    "NaN".to_owned()
                } else {
                    chrono::DateTime::parse_from_rfc3339(text()?)
                        .map_err(|_| StateError::InvalidInput)?
                        .timestamp_millis()
                        .to_string()
                };
                self.tagged(json!({"t":"date","v":timestamp}))
            }
            "u" => {
                let href = text()?;
                url::Url::parse(href).map_err(|_| StateError::InvalidInput)?;
                self.tagged(json!({"t":"url","v":href}))
            }
            "r" => {
                let value = field.as_object().ok_or(StateError::InvalidInput)?;
                if value.len() != 2 {
                    return Err(StateError::InvalidInput);
                }
                let source = value
                    .get("p")
                    .and_then(Value::as_str)
                    .ok_or(StateError::InvalidInput)?;
                let flags = value
                    .get("f")
                    .and_then(Value::as_str)
                    .ok_or(StateError::InvalidInput)?;
                self.tagged(json!({"t":"regexp","source":source,"flags":flags}))
            }
            "e" => {
                let value = field.as_object().ok_or(StateError::InvalidInput)?;
                if value.len() != 3 {
                    return Err(StateError::InvalidInput);
                }
                let name = value
                    .get("n")
                    .and_then(Value::as_str)
                    .ok_or(StateError::InvalidInput)?;
                let message = value
                    .get("m")
                    .and_then(Value::as_str)
                    .ok_or(StateError::InvalidInput)?;
                let stack = value
                    .get("s")
                    .and_then(Value::as_str)
                    .ok_or(StateError::InvalidInput)?;
                self.tagged(json!({"t":"error","name":name,"message":message,"stack":stack}))
            }
            "ab" | "ta" => {
                use base64::Engine;
                let value = field.as_object().ok_or(StateError::InvalidInput)?;
                if value.len() != if tag == "ab" { 1 } else { 2 } {
                    return Err(StateError::InvalidInput);
                }
                let data = value
                    .get("b")
                    .and_then(Value::as_str)
                    .ok_or(StateError::InvalidInput)?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|_| StateError::InvalidInput)?;
                if bytes.len() > MAX_STATE_BYTES {
                    return Err(StateError::InvalidInput);
                }
                let buffer = self.tagged(json!({"t":"buffer","data":data}))?;
                if tag == "ab" {
                    return Ok(buffer);
                }
                let (kind, size) = match value
                    .get("k")
                    .and_then(Value::as_str)
                    .ok_or(StateError::InvalidInput)?
                {
                    "i8" => ("Int8Array", 1),
                    "ui8" => ("Uint8Array", 1),
                    "ui8c" => ("Uint8ClampedArray", 1),
                    "i16" => ("Int16Array", 2),
                    "ui16" => ("Uint16Array", 2),
                    "i32" => ("Int32Array", 4),
                    "ui32" => ("Uint32Array", 4),
                    "f32" => ("Float32Array", 4),
                    "f64" => ("Float64Array", 8),
                    "bi64" => ("BigInt64Array", 8),
                    "bui64" => ("BigUint64Array", 8),
                    _ => return Err(StateError::UnsupportedValue),
                };
                if bytes.len() % size != 0 {
                    return Err(StateError::InvalidInput);
                }
                self.tagged(json!({"t":"view","kind":kind,"buffer":buffer,"offset":0,"length":bytes.len()/size}))
            }
            _ => {
                let external = object
                    .get("id")
                    .and_then(Value::as_u64)
                    .ok_or(StateError::InvalidInput)?;
                if self.ids.contains_key(&external) {
                    return Err(StateError::InvalidInput);
                }
                let id = self.allocate(Value::Null)?;
                self.ids.insert(external, id);
                let items = field.as_array().ok_or(StateError::InvalidInput)?;
                let node = match tag {
                    "a" => {
                        let entries = items
                            .iter()
                            .enumerate()
                            .map(|(i, v)| {
                                Ok(json!([i.to_string(), self.visit(v, true, depth + 1)?]))
                            })
                            .collect::<Result<Vec<_>, StateError>>()?;
                        json!({"t":"array","length":items.len(),"entries":entries})
                    }
                    "s" => {
                        let values = items
                            .iter()
                            .map(|v| self.visit(v, true, depth + 1))
                            .collect::<Result<Vec<_>, _>>()?;
                        json!({"t":"set","values":values})
                    }
                    "o" | "m" => {
                        let mut entries = Vec::new();
                        let mut keys = HashSet::new();
                        for item in items {
                            let item = item.as_object().ok_or(StateError::InvalidInput)?;
                            if item.len() != 2 || !item.contains_key("k") || !item.contains_key("v")
                            {
                                return Err(StateError::InvalidInput);
                            }
                            let key = if tag == "o" {
                                let key = item["k"].as_str().ok_or(StateError::InvalidInput)?;
                                if !keys.insert(key) {
                                    return Err(StateError::InvalidInput);
                                }
                                json!(key)
                            } else {
                                self.visit(&item["k"], true, depth + 1)?
                            };
                            entries.push(json!([key, self.visit(&item["v"], true, depth + 1)?]));
                        }
                        json!({"t":if tag=="o"{"object"}else{"map"},"entries":entries})
                    }
                    _ => return Err(StateError::InvalidInput),
                };
                self.nodes[id] = node;
                Ok(json!({"r":id}))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn origin_scope_rejects_credentials_paths_and_opaque_origins() {
        for value in [
            "file:///tmp/x",
            "https://user:secret@example.test",
            "https://example.test/path",
            "null",
            "https://example.test/",
        ] {
            assert_eq!(origin(value), Err(StateError::InvalidInput));
        }
        origin("https://example.test").unwrap();
        origin("http://127.0.0.1:8080").unwrap();
    }
    #[test]
    fn opaque_cookie_partition_is_not_broadened() {
        let mut cookie = json!({"name":"n","value":"synthetic","domain":"example.test","path":"/","partitionKeyOpaque":true});
        assert_eq!(
            cookie_parameters(&cookie),
            Err(StateError::UnsupportedValue)
        );
        cookie["partitionKeyOpaque"] = json!("true");
        assert_eq!(cookie_parameters(&cookie), Err(StateError::InvalidInput));
        cookie["partitionKeyOpaque"] = json!(false);
        cookie["partitionKey"] =
            json!({"topLevelSite":"https://example.test","hasCrossSiteAncestor":true});
        assert_eq!(
            cookie_parameters(&cookie).unwrap()["partitionKey"],
            cookie["partitionKey"]
        );
    }
    #[test]
    fn duplicate_origins_and_unsupported_categories_fail() {
        let item = OriginState {
            origin: "https://example.test".into(),
            local_storage: vec![],
            indexed_db: json!([]),
        };
        let state = NativeState {
            version: 1,
            cookies: vec![],
            origins: vec![item.clone(), item],
        };
        assert_eq!(validate_state(&state), Err(StateError::InvalidInput));
        assert!(serde_json::from_value::<NativeState>(
            json!({"version":1,"cookies":[],"origins":[],"sessionStorage":[]})
        )
        .is_err());
    }
    fn legacy_payload(record: Value, inline: bool) -> Value {
        let mut store =
            json!({"name":"synthetic","autoIncrement":false,"indexes":[],"records":[record]});
        if inline {
            store["keyPathArray"] = json!(["tenant", "id"]);
        }
        json!({"cookies":[],"origins":[{"origin":"https://fixture.test","localStorage":[],"indexedDB":[{"name":"db","version":1,"stores":[store]}]}]})
    }
    #[test]
    fn legacy_partition_metadata_and_compound_keys_are_preserved() {
        let mut input = legacy_payload(json!({"value":{"tenant":"synthetic","id":7}}), true);
        input["cookies"] = json!([{"name":"session","value":"synthetic","domain":"fixture.test","path":"/","partitionKey":"https://example.test","_crHasCrossSiteAncestor":false}]);
        let state = convert_playwright_state(input).unwrap();
        assert_eq!(
            state.cookies[0]["partitionKey"],
            json!({"topLevelSite":"https://example.test","hasCrossSiteAncestor":false})
        );
        let store = &state.origins[0].indexed_db[0]["stores"][0];
        assert_eq!(store["keyPath"], json!(["tenant", "id"]));
        assert_eq!(store["records"][0]["key"]["root"], json!({"u":true}));
    }
    #[test]
    fn legacy_official_cyclic_map_set_and_typed_array_encoding_converts() {
        // Generated by installed official Playwright1.64.1 StorageScript._trySerialize.
        let encoded = json!({"o":[{"k":"n","v":{"v":"NaN"}},{"k":"b","v":{"bi":"12"}},{"k":"date","v":{"d":"1970-01-01T00:00:00.123Z"}},{"k":"typed","v":{"ta":{"b":"AQD//w==","k":"ui16"}}},{"k":"map","v":{"m":[{"k":"x","v":{"ref":1}}],"id":2}},{"k":"set","v":{"s":[{"ref":1}],"id":3}},{"k":"self","v":{"ref":1}}],"id":1});
        let graph = LegacyGraph::convert(&encoded, true).unwrap();
        assert_eq!(graph["root"], json!({"r":0}));
        assert_eq!(graph["nodes"][0]["entries"][6], json!(["self",{"r":0}]));
        let nodes = graph["nodes"].as_array().unwrap();
        assert!(nodes
            .iter()
            .any(|n| n["t"] == "view" && n["kind"] == "Uint16Array" && n["length"] == 2));
        assert!(nodes.iter().any(|n| n["t"] == "date" && n["v"] == "123"));
        assert!(nodes
            .iter()
            .any(|n| n["t"] == "map" && n["entries"][0][1] == json!({"r":0})));
    }
    #[test]
    fn legacy_invalid_reference_and_active_handles_are_rejected() {
        for value in [
            json!({"ref":99}),
            json!({"a":[{"o":[],"id":1}],"id":1}),
            json!({"h":0}),
            json!({"fn":"__pw_fn_synthetic"}),
            json!({"v":"null","d":"2020-01-01"}),
            json!({"ta":{"b":"AQ==","k":"ui16"}}),
        ] {
            assert!(
                LegacyGraph::convert(&value, true).is_err(),
                "accepted malformed graph"
            );
        }
        let mut deep = json!(0);
        for id in (1..300).rev() {
            deep = Value::Object(serde_json::Map::from_iter([
                ("a".into(), Value::Array(vec![deep])),
                ("id".into(), json!(id)),
            ]));
        }
        assert_eq!(
            LegacyGraph::convert(&deep, true),
            Err(StateError::InvalidInput)
        );
    }
    #[test]
    fn legacy_missing_values_are_not_invented_and_falsey_values_survive() {
        assert!(matches!(
            convert_playwright_state(legacy_payload(json!({"key":0}), false)),
            Err(StateError::InvalidInput)
        ));
        let state = convert_playwright_state(legacy_payload(json!({"key":0,"value":false}), false))
            .unwrap();
        let record = &state.origins[0].indexed_db[0]["stores"][0]["records"][0];
        assert_eq!(record["key"]["root"], json!({"v":0}));
        assert_eq!(record["value"]["root"], json!({"v":false}));
        let graph = LegacyGraph::convert(&json!({"__proto__":{"polluted":true}}), false).unwrap();
        assert_eq!(graph["nodes"][0]["entries"][0][0], "__proto__");
        // Browser reconstruction is separately exercised with an own __proto__
        // property; this pure conversion test preserves the literal data key.
    }
    #[tokio::test]
    #[ignore = "requires real Chromium; required strict state import browser gate"]
    async fn chromium_duplicate_state_records_fail_instead_of_overwriting() {
        use super::super::client_browser::OwnedBrowser;
        for duplicate in [false, true] {
            let mut owner = OwnedBrowser::launch(Default::default(), None)
                .await
                .unwrap();
            let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let operation = OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
                cancellation,
            };
            let mut input = legacy_payload(json!({"key":7,"value":"synthetic-first"}), false);
            if duplicate {
                input["origins"][0]["indexedDB"][0]["stores"][0]["records"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"key":7,"value":"synthetic-second"}));
            }
            let state = convert_playwright_state(input).unwrap();
            let context = NativeStateContext {
                client: &owner.manager.client,
                context_id: &owner.context_id,
                targets: &owner.targets,
                origins: &[],
                origins_complete: true,
            };
            let result = import_state(&context, &state, &operation).await;
            let exported = if !duplicate && result.is_ok() {
                let origins = vec!["https://fixture.test".to_owned()];
                export_state(
                    &NativeStateContext {
                        origins: &origins,
                        ..context
                    },
                    &operation,
                )
                .await
            } else {
                Err(StateError::InvalidInput)
            };
            // Even failure disposes the replacement context before assertions.
            let cleanup = owner.close().await;
            assert!(
                cleanup.is_ok(),
                "synthetic replacement context cleanup failed"
            );
            if duplicate {
                assert_eq!(result, Err(StateError::UnsupportedValue));
            } else {
                assert_eq!(result, Ok(()), "valid control import failed");
                let exported = exported.expect("valid control export failed");
                let records = &exported.origins[0].indexed_db[0]["stores"][0]["records"];
                assert_eq!(records.as_array().unwrap().len(), 1);
                assert_eq!(records[0]["value"]["root"], json!({"v":"synthetic-first"}));
            }
        }
    }
}
