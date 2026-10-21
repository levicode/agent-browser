//! Complete context-scoped state transfer. No file IO, application navigation,
//! partial-success fallback, or plaintext diagnostic payloads live here.
use super::cdp::client::CdpClient;
use super::client_session::{CancelSignal, OperationLease};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;

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
    if context.context_id.is_empty() || !context.origins_complete {
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
        let attached = command(context.client, None, "Target.attachToTarget", json!({"targetId":target,"flatten":true}), operation).await?;
        let session = attached["sessionId"].as_str().ok_or(StateError::BrowserFailure)?.to_owned();
        command(context.client, Some(&session), "Page.enable", json!({}), operation).await?;
        command(context.client, Some(&session), "Page.setLifecycleEventsEnabled", json!({"enabled":true}), operation).await?;
        command(context.client, Some(&session), "Network.enable", json!({}), operation).await?;
        command(context.client, Some(&session), "Network.setBypassServiceWorker", json!({"bypass":true}), operation).await?;
        // Session-private delivery is bounded; no unrelated tenant events enter
        // this receiver. The native registry reserves this target to state IO.
        let mut events = context.client.subscribe_session(&session);
        let _subscription = PrivateSubscription { client: context.client, session: &session };
        command(context.client, Some(&session), "Fetch.enable", json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}]}), operation).await?;
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
   else if(v instanceof RegExp)n={t:'regexp',source:v.source,flags:v.flags};
   else if(v instanceof ArrayBuffer)n={t:'buffer',data:base64(new Uint8Array(v))};
   else if(ArrayBuffer.isView(v))n={t:'view',kind:v.constructor.name,buffer:await visit(v.buffer,depth+1),offset:v.byteOffset,length:v instanceof DataView?v.byteLength:v.length};
   else if(v instanceof Blob)n={t:v instanceof File?'file':'blob',type:v.type,name:v instanceof File?v.name:undefined,lastModified:v instanceof File?v.lastModified:undefined,data:base64(new Uint8Array(await v.arrayBuffer()))};
   else if(v instanceof Map){n={t:'map',entries:[]};for(const [k,x]of v)n.entries.push([await visit(k,depth+1),await visit(x,depth+1)]);}
   else if(v instanceof Set){n={t:'set',values:[]};for(const x of v)n.values.push(await visit(x,depth+1));}
   else if(Array.isArray(v)||Object.getPrototypeOf(v)===Object.prototype||Object.getPrototypeOf(v)===null){n={t:Array.isArray(v)?'array':'object',entries:[]};if(Array.isArray(v))n.length=v.length;for(const k of Object.keys(v))n.entries.push([k,await visit(v[k],depth+1)]);}
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
   if(n.t==='map')for(const [k,x]of n.entries)out.set(visit(k,depth+1),visit(x,depth+1));
   if(n.t==='set')for(const x of n.values)out.add(visit(x,depth+1));
   if(n.t==='object'||n.t==='array')for(const [k,x]of n.entries){if(typeof k!=='string'||k==='length'&&n.t==='array')fail();Object.defineProperty(out,k,{value:visit(x,depth+1),writable:true,enumerable:true,configurable:true});}
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
    });const stores=await Promise.all(pending);await done;
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
  try {if(saved.stores.length){const tx=db.transaction(saved.stores.map(s=>s.name),'readwrite'),done=completion(tx);for(const s of saved.stores){const store=tx.objectStore(s.name);for(const r of s.records){if(s.keyPath===null)store.put(r.value,r.key);else store.put(r.value);}}await done;}}finally{db.close();}
 }
 return true;
}"#;

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
}
