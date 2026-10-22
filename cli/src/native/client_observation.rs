//! Typed native observations. Browser identity and node ownership stay native;
//! clients receive only canonical references and semantic data.
use super::{
    cdp::{
        client::CdpClient,
        types::{AXNode, GetFullAXTreeResult},
    },
    client_session::{CancelSignal, OperationLease},
    element::{ExactBinding, LiveQueryOrigin, LocatedIssuance, RefEntry, RefMap},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
#[path = "client_observation/author_projection.rs"]
mod author_projection;

/// Public failures are semantic categories, never raw CDP text or string heuristics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationError {
    InvalidArguments,
    StaleReference,
    Cancelled,
    DeadlineExceeded,
    BackendFailure,
    PolicyDenied,
    ResourceLimit,
    CleanupFailed {
        primary: Option<Box<ObservationError>>,
    },
}
impl std::fmt::Display for ObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for ObservationError {}
impl From<String> for ObservationError {
    fn from(_: String) -> Self {
        Self::BackendFailure
    }
}
impl From<&str> for ObservationError {
    fn from(_: &str) -> Self {
        Self::BackendFailure
    }
}
impl From<ObservationError> for String {
    fn from(error: ObservationError) -> String {
        error.to_string()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeReference {
    pub id: String,
    pub revision: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemanticNode {
    #[serde(skip)]
    author: Option<author_projection::Facts>,
    #[serde(skip)]
    pub labels: Vec<String>,
    #[serde(skip)]
    pub(crate) safe_public_name: Option<String>,
    #[serde(rename = "ref")]
    pub reference: NodeReference,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_purpose: Option<String>,
    #[serde(serialize_with = "serialize_public_states")]
    pub states: BTreeMap<String, bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<i64>,
    pub attributes: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rect: Option<Rect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub frame_path: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub children: Vec<SemanticNode>,
}
// Match the public semantic-node contract at every wire boundary, not only
// compact observations. Raw flags remain available to native visibility,
// identity, action, and security checks; explicit false control states survive.
fn serialize_public_states<S: serde::Serializer>(
    states: &BTreeMap<String, bool>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_map(states.iter().filter(|(name, value)| {
        **value || !matches!(name.as_str(), "disabled" | "focused" | "hidden" | "secure")
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    #[serde(skip)]
    pub(crate) hidden_frame_proof: HiddenFrameProof,
    pub identity_scope: String,
    #[serde(with = "revision_wire")]
    pub revision: u64,
    pub roots: Vec<SemanticNode>,
    pub viewport_ref: NodeReference,
    pub truncated: bool,
}
// Keep native counters numeric, but never expose a u64 as a JavaScript number.
mod revision_wire {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(revision: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&revision.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.is_empty()
            || !text.bytes().all(|byte| byte.is_ascii_digit())
            || (text.len() > 1 && text.starts_with('0'))
        {
            return Err(serde::de::Error::custom(
                "revision must be a canonical decimal string",
            ));
        }
        text.parse().map_err(serde::de::Error::custom)
    }
}
/// Explicit browser-owned frame input; policy selects frames before this layer.
#[derive(Clone, Debug)]
pub struct ObservationFrame {
    pub parent_frame_id: Option<String>,
    pub owner_backend_id: Option<i64>,
    pub url: String,
    pub binding: ExactBinding,
    pub offset_x: f64,
    pub offset_y: f64,
    pub frame_path: Vec<String>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationOptions {
    #[serde(default = "default_nodes")]
    pub max_nodes: usize,
    #[serde(default = "default_test_id")]
    pub test_id_attribute: String,
    #[serde(default = "default_secure_selector")]
    pub secure_field_selector: String,
}
fn default_nodes() -> usize {
    10000
}
fn default_secure_selector() -> String {
    "input[type=\"password\" i]".into()
}
fn default_test_id() -> String {
    "data-testid".into()
}
impl Default for ObservationOptions {
    fn default() -> Self {
        Self {
            max_nodes: default_nodes(),
            test_id_attribute: default_test_id(),
            secure_field_selector: default_secure_selector(),
        }
    }
}
fn check(lease: &OperationLease) -> Result<(), ObservationError> {
    if *lease.cancellation.borrow() != CancelSignal::None {
        return Err(ObservationError::Cancelled);
    }
    if std::time::Instant::now() >= lease.deadline {
        return Err(ObservationError::DeadlineExceeded);
    }
    Ok(())
}
async fn command(
    client: &CdpClient,
    session: &str,
    method: &str,
    args: Value,
    lease: &OperationLease,
) -> Result<Value, ObservationError> {
    check(lease)?;
    #[cfg(test)]
    let args = equivalence_tests::instrument(method, args, lease);
    let mut cancellation = lease.cancellation.clone();
    #[cfg(test)]
    let diagnostic_site = diagnostic_site(&args);
    tokio::select! {
        result = client.send_command(method, Some(args), Some(session)) => {
            check(lease)?;
            #[cfg(test)]
            match &result {
                Ok(value) => diagnostic_exception(method, diagnostic_site, value),
                Err(_) => eprintln!("native observation protocol failure at {method}; details omitted"),
            }
            #[cfg(test)]
            if let Ok(value) = &result {
                equivalence_tests::after_command(client, session, method, diagnostic_site, value, lease).await?;
            }
            result.map_err(|_|ObservationError::BackendFailure)
        }
        _ = cancellation.changed() => Err(ObservationError::Cancelled),
        _ = tokio::time::sleep_until(lease.deadline.into()) => Err(ObservationError::DeadlineExceeded),
    }
}
#[cfg(test)]
fn diagnostic_site(args: &Value) -> &'static str {
    match args["functionDeclaration"].as_str() {
        Some(value) if value.starts_with("function(testId,secureSelector,...nodes)") => {
            "metadata-batch"
        }
        Some(value) if value == METADATA => "metadata-single",
        Some(value) if value.starts_with("function(selector,...roots)") => "security-inventory",
        Some(value) if value == MATCH_QUERY => "query-match",
        _ => "other-native-command",
    }
}
#[cfg(test)]
fn diagnostic_exception(method: &str, site: &str, value: &Value) {
    let Some(details) = value.get("exceptionDetails") else {
        return;
    };
    let class = details["exception"]["className"]
        .as_str()
        .filter(|name| {
            matches!(
                *name,
                "TypeError" | "ReferenceError" | "SyntaxError" | "RangeError" | "Error"
            )
        })
        .unwrap_or("unclassified");
    let category = if details["exception"]["description"]
        .as_str()
        .is_some_and(|v| v.starts_with("TypeError: Illegal invocation"))
    {
        "illegal-invocation"
    } else {
        "unclassified"
    };
    eprintln!("native observation renderer failure at {method}/{site}: class={class}, category={category}, line={:?}, column={:?}; details omitted",details["lineNumber"].as_u64(),details["columnNumber"].as_u64());
}

async fn validate_frame(
    client: &CdpClient,
    frame: &ObservationFrame,
    lease: &OperationLease,
) -> Result<(), ObservationError> {
    let tree = command(
        client,
        &frame.binding.session,
        "Page.getFrameTree",
        json!({}),
        lease,
    )
    .await?;
    fn loader<'a>(tree: &'a Value, id: &str) -> Option<&'a str> {
        if tree["frame"]["id"].as_str() == Some(id) {
            return tree["frame"]["loaderId"].as_str();
        }
        tree["childFrames"]
            .as_array()?
            .iter()
            .find_map(|child| loader(child, id))
    }
    if loader(&tree["frameTree"], &frame.binding.frame) != Some(frame.binding.loader.as_str()) {
        return Err(ObservationError::StaleReference);
    }
    Ok(())
}
fn reference_allocation_error(error: super::element::RefAllocationError) -> ObservationError {
    match error {
        super::element::RefAllocationError::Capacity => ObservationError::ResourceLimit,
        super::element::RefAllocationError::Exhausted => ObservationError::BackendFailure,
    }
}

async fn settle_object_group<T>(
    client: &CdpClient,
    session: &str,
    group: &str,
    result: Result<T, ObservationError>,
) -> Result<T, ObservationError> {
    let release = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        client.send_command(
            "Runtime.releaseObjectGroup",
            Some(json!({"objectGroup":group})),
            Some(session),
        ),
    )
    .await;
    if matches!(release, Ok(Ok(_))) {
        result
    } else {
        Err(ObservationError::CleanupFailed {
            primary: result.err().map(Box::new),
        })
    }
}

// A resolved frame owner is temporary authority, even when the read fails.
// Cleanup uses a fresh bounded budget rather than the expired read lease.
async fn settle_owner_object<T>(
    client: &CdpClient,
    session: &str,
    object: &str,
    result: Result<T, ObservationError>,
) -> Result<T, ObservationError> {
    let release = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        client.send_command(
            "Runtime.releaseObject",
            Some(json!({"objectId":object})),
            Some(session),
        ),
    )
    .await;
    if matches!(release, Ok(Ok(_))) {
        result
    } else {
        Err(ObservationError::CleanupFailed {
            primary: result.err().map(Box::new),
        })
    }
}

fn private_use_glyph(ch: char) -> bool {
    matches!(ch as u32, 0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD)
}
fn glyphs_as_spaces(text: &str) -> String {
    text.chars()
        .map(|ch| if private_use_glyph(ch) { ' ' } else { ch })
        .collect()
}
fn ecmascript_whitespace(ch: char) -> bool {
    matches!(ch as u32, 0x0009..=0x000D | 0x0020 | 0x00A0 | 0x1680 | 0x2000..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000 | 0xFEFF)
}
fn normalize_public_label(label: &str) -> String {
    glyphs_as_spaces(label)
        .split(ecmascript_whitespace)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}
fn reported_public_name(name: String, title: Option<&str>) -> Option<String> {
    if !name.chars().any(private_use_glyph) {
        return Some(name);
    }
    let normalized = normalize_public_label(&name);
    if !normalized.is_empty() {
        return Some(normalized);
    }
    title
        .map(|title| title.trim_matches(ecmascript_whitespace))
        .filter(|title| !title.is_empty())
        .map(str::to_owned)
}
// Concrete public ARIA vocabulary. Abstract/unknown tokens do not suppress
// native editing-host semantics; HTML tokenization excludes Unicode spaces.
fn authored_role(attributes: &Value) -> Option<&str> {
    attributes["role"]
        .as_str()?
        .split_ascii_whitespace()
        .find(|role| {
            matches!(
                *role,
                "alert"
                    | "alertdialog"
                    | "application"
                    | "article"
                    | "banner"
                    | "blockquote"
                    | "button"
                    | "caption"
                    | "cell"
                    | "checkbox"
                    | "code"
                    | "columnheader"
                    | "combobox"
                    | "complementary"
                    | "contentinfo"
                    | "definition"
                    | "deletion"
                    | "dialog"
                    | "directory"
                    | "document"
                    | "emphasis"
                    | "feed"
                    | "figure"
                    | "form"
                    | "generic"
                    | "grid"
                    | "gridcell"
                    | "group"
                    | "heading"
                    | "img"
                    | "insertion"
                    | "link"
                    | "list"
                    | "listbox"
                    | "listitem"
                    | "log"
                    | "main"
                    | "mark"
                    | "marquee"
                    | "math"
                    | "meter"
                    | "menu"
                    | "menubar"
                    | "menuitem"
                    | "menuitemcheckbox"
                    | "menuitemradio"
                    | "navigation"
                    | "none"
                    | "note"
                    | "option"
                    | "paragraph"
                    | "presentation"
                    | "progressbar"
                    | "radio"
                    | "radiogroup"
                    | "region"
                    | "row"
                    | "rowgroup"
                    | "rowheader"
                    | "scrollbar"
                    | "search"
                    | "searchbox"
                    | "separator"
                    | "slider"
                    | "spinbutton"
                    | "status"
                    | "strong"
                    | "subscript"
                    | "superscript"
                    | "switch"
                    | "tab"
                    | "table"
                    | "tablist"
                    | "tabpanel"
                    | "term"
                    | "textbox"
                    | "time"
                    | "timer"
                    | "toolbar"
                    | "tooltip"
                    | "tree"
                    | "treegrid"
                    | "treeitem"
            )
        })
}
fn ax_string(value: &Option<super::cdp::types::AXValue>) -> Option<String> {
    value
        .as_ref()?
        .value
        .as_ref()?
        .as_str()
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}
// Targeted metadata on an already-resolved native DOM handle. It neither walks
// the DOM nor creates identities. Password text/value/selection/attribute values
// are excluded in the renderer before any data is transferred to the client.
const METADATA: &str = r#"function(testId,secureSelector,boundedObservation=false,protectedEditor=false,simpleNameInventory=false) {
 const nodeProto=Node.prototype;
 if (!Object.getOwnPropertyDescriptor(nodeProto,'isConnected').get.call(this) || (this!==document && Object.getOwnPropertyDescriptor(nodeProto,'ownerDocument').get.call(this)!==document)) return {__nativeStatus:'stale-reference'};
 const e=this.nodeType===1?this:null, doc=this.ownerDocument||this;
 try { Element.prototype.matches.call(document.documentElement,secureSelector); } catch { return {__nativeStatus:'invalid-arguments'}; }
 const secureSelectorAll='input[type="password" i],'+secureSelector;
 function composedSecure(node){
   const seen=new Set();for(let p=node;p&&!seen.has(p);p=p.parentElement||(p.getRootNode&&p.getRootNode().host)){seen.add(p);if(p.nodeType===1&&Element.prototype.matches.call(p,secureSelectorAll))return true;}return false;
 }
 const secureElement=e||this.parentElement||this.getRootNode()?.host;
 const secure=composedSecure(secureElement);
 const secureDescendants=!!e&&!!Element.prototype.querySelector.call(e,secureSelectorAll);
 const normalize=s=>String(s??'').replace(/\s+/g,' ').trim();
 function safeLabelText(node,excludeAriaHidden=false){
   if(!node||composedSecure(node.nodeType===1?node:node.parentElement||node.getRootNode()?.host))return '';
   const pending=[node],parts=[];let count=0;
   while(pending.length){const n=pending.pop();if(++count>10000)return null;if(n===' '){parts.push(' ');continue;}
     if(n.nodeType===3){if(!composedSecure(n.parentElement||n.getRootNode()?.host))parts.push(n.textContent);continue;}
     if(n.nodeType!==1&&n.nodeType!==9&&n.nodeType!==11)continue;
     if(n.nodeType===1){
       // Associated label queries use accessible=false name text: decorative
       // aria-hidden descendants contribute nothing. IDREF roots retain their
       // separate policy; this flag never changes security exclusion.
       if(excludeAriaHidden&&(n.getAttribute('aria-hidden')||'').toLowerCase()==='true')continue;
       if(composedSecure(n)||Element.prototype.matches.call(n,'input,textarea,select,script,style'))continue;
       // Text is not an adequate replacement for icon/alternative naming.
       if(n.shadowRoot||Element.prototype.matches.call(n,'img,svg,canvas,slot')||n.hasAttribute('aria-label')||n.hasAttribute('aria-labelledby'))return null;
       const style=doc.defaultView.getComputedStyle(n);if(style.display==='none'||style.visibility==='hidden')continue;
       if(!['inline','contents','inline-block','inline-flex','inline-grid'].includes(style.display)){parts.push(' ');pending.push(' ');}
     }
     for(let i=n.childNodes.length-1;i>=0;i--)pending.push(n.childNodes[i]);
   }
   return normalize(parts.join(''));
 }
 // A deliberately incomplete naming proof, not an alternate accname reader.
 // Native inventory must first rule out author shadow roots, including closed.
 function completeSimpleLabel(root,named){
   const pending=[root];let text='',count=0;
   while(pending.length){
     const n=pending.pop();if(++count>512)return null;
     if(n===' '){text+=' ';if(text.length>512)return null;continue;}
     if(n===named)continue;
     if(n.nodeType===3){const value=n.nodeValue||'';if(value.length>512-text.length)return null;text+=value;continue;}
     if(n.nodeType!==1)return null;
     if(composedSecure(n))return null;
     const css=doc.defaultView.getComputedStyle(n);
     if((n.getAttribute('aria-hidden')||'').toLowerCase()==='true'||css.display==='none'||css.visibility==='hidden')continue;
     if(n.shadowRoot||Element.prototype.matches.call(n,'input,textarea,select,button,meter,progress,output,img,svg,math,canvas,video,audio,iframe,slot,script,style')||
       ['aria-label','aria-labelledby','title','alt','role','contenteditable'].some(a=>n.hasAttribute(a)))return null;
     for(const pseudo of ['::before','::after']){
       const content=doc.defaultView.getComputedStyle(n,pseudo).content;
       if(content!=='none'&&content!=='normal'&&content!=='')return null;
     }
     if(n!==root&&(n.localName==='br'||css.display!=='inline')){text+=' ';pending.push(' ');}
     if(text.length>512||n.childNodes.length>512-count||pending.length+n.childNodes.length>512)return null;
     for(let i=n.childNodes.length-1;i>=0;i--)pending.push(n.childNodes[i]);
   }
   return normalize(text);
 }
 // A closed, small content-name proof for native buttons, not a general
 // accname implementation. Null means unavailable; an empty string is a
 // complete anonymous result. Native inventory excludes author shadow roots.
 function completeButtonName(root){
   let count=0;
   function token(n,depth){
     if(++count>512||depth>64)return null;
     if(n.nodeType===3){const value=n.nodeValue||'';return value.length<=512?value:null;}
     if(n.nodeType!==1||composedSecure(n)||n.shadowRoot||n.isContentEditable)return null;
     const css=doc.defaultView.getComputedStyle(n);
     if((n.getAttribute('aria-hidden')||'').toLowerCase()==='true'||css.display==='none'||css.visibility==='hidden')return '';
     if(['aria-label','aria-labelledby','alt','contenteditable'].some(a=>n.hasAttribute(a))||
       n.hasAttribute('role')&&(n!==root||n.getAttribute('role')!=='button'))return null;
     for(const pseudo of ['::before','::after']){
       const content=doc.defaultView.getComputedStyle(n,pseudo).content;
       if(content!=='none'&&content!=='normal'&&content!=='')return null;
     }
     if(n!==root){
       if(n instanceof SVGSVGElement){
         // AX omission alone proves nothing: only a genuinely empty SVG with
         // geometry/presentation attributes is an empty contribution here.
         if(n.childNodes.length||Array.from(n.attributes).some(a=>!['id','class','style','width','height','viewBox','x','y','xmlns'].includes(a.name)))return null;
         return '';
       }
       if(!(n instanceof HTMLElement)||!['span','div','p','abbr','b','strong','em','i','small','br'].includes(n.localName))return null;
     }
     if(n.childNodes.length>512-count)return null;
     let out='';
     for(const child of n.childNodes){
       const value=token(child,depth+1);if(value===null)return null;
       const block=child.nodeType===1&&(child.localName==='br'||doc.defaultView.getComputedStyle(child).display!=='inline');
       if(out.length+value.length+(block?2:0)>512)return null;
       out+=block?' '+value+' ':value;
     }
     // Preserve raw whitespace: even a block boundary suppresses a
     // descendant's title. Inert does not suppress name-from-content.
     if(n===root||out!=='')return out;
     const title=n.getAttribute('title')||'';
     return title.length<=512?title.trim():null;
   }
   const content=token(root,0);if(content===null)return null;
   const name=normalize(content);if(name)return name;
   // Unlike a descendant title, the button's own title follows normalized
   // content and preserves internal whitespace, as the original reader does.
   const title=root.getAttribute('title')||'';
   return title.length<=512?title.trim():null;
 }
 function safeText(node){
   if(!node)return null;if(node.nodeType===3)return composedSecure(node.parentElement||node.getRootNode()?.host)?null:node.textContent;
   return secureDescendants?safeLabelText(node):node.innerText;
 }
 // Reduce only the protected href scalar, before renderer metadata crosses
 // the boundary. Exact reads keep authored attributes; resolution uses this
 // receiver's current owner document, including base elements and frame bases.
 function protectedHref(value){
   const markers=(query,fragment)=>(query?'?…':'')+(fragment?'#…':'');
   try {
     const url=new URL(value,doc.baseURI),tail=markers(url.search!=='',url.hash!=='');
     if(url.protocol==='blob:'){
       let inner;try{inner=new URL(url.pathname);}catch{return 'blob:…';}
       return inner.origin==='null'?'blob:…':'blob:'+inner.origin+inner.pathname+tail;
     }
     if(url.origin!=='null')return url.origin+url.pathname+tail;
     if(url.protocol==='mailto:'||url.protocol==='tel:')return url.protocol+url.pathname+tail;
     return url.protocol+'…';
   } catch {
     // Preserve the public malformed-target fallback and empty-tail distinction.
     // Never include parser exceptions, which can contain the original target.
     const fragment=value.indexOf('#'),before=fragment<0?value:value.slice(0,fragment),query=before.indexOf('?');
     return (query<0?before:before.slice(0,query))+markers(query>=0&&query+1<before.length,fragment>=0&&fragment+1<value.length);
   }
 }
 const attrs={}; if(e) for(const a of e.attributes) if(!(secure&&a.name.toLowerCase()==='value')) attrs[a.name]=boundedObservation&&a.name==='href'?protectedHref(a.value):a.value;
 const style=e?doc.defaultView.getComputedStyle(e):null;
 // Geometry and visibility are separate: a zero-area layout box is still
 // a box, and display:contents can paint descendants without having one.
 const r=e&&e.getClientRects().length?e.getBoundingClientRect():null;
 function renderVisible(root) {
   const pending=[root];let count=0;
   while(pending.length){
     const node=pending.pop();if(++count>10000)throw new Error('visibility resource limit');
     const computed=doc.defaultView.getComputedStyle(node);
     if(computed.display==='contents'){
       // Contents has no box for checkVisibility to inspect. Its flat-tree
       // ancestors can still suppress all descendant painting.
       let suppressed=false,branch=node;
       for(let p=node.assignedSlot||node.parentElement||node.getRootNode()?.host;p;branch=p,p=p.assignedSlot||p.parentElement||p.getRootNode()?.host){
         if(++count>10000)throw new Error('visibility resource limit');
         if(doc.defaultView.getComputedStyle(p).contentVisibility==='hidden'){suppressed=true;break;}
         if(p.localName==='details'&&!p.open&&Array.from(p.children).find(child=>child.localName==='summary')!==branch){suppressed=true;break;}
       }
       if(suppressed)continue;
       for(const child of node.childNodes){
         if(child.nodeType===1)pending.push(child);
         else if(child.nodeType===3&&computed.visibility==='visible'){
           const range=doc.createRange();range.selectNode(child);
           const box=range.getBoundingClientRect();
           if(box.width>0&&box.height>0)return true;
         }
       }
       continue;
     }
     // Native rendering knows closed details and skipped flat-tree content.
     // Opacity is intentionally ignored, as in the public visibility API.
     if(!node.checkVisibility({visibilityProperty:true,opacityProperty:false,contentVisibilityAuto:false}))continue;
     const box=node.getBoundingClientRect();if(box.width>0&&box.height>0)return true;
   }
   return false;
 }
 const hidden=!!e&&!renderVisible(e);
 const focused=!!e&&doc.activeElement===e;
 let selection=null;
 if(!secure&&focused&&typeof e.selectionStart==='number'&&e.selectionEnd>e.selectionStart) selection=e.value.slice(e.selectionStart,e.selectionEnd);
 else if(!secure&&focused&&e.isContentEditable) selection=String(doc.getSelection()||'')||null;
 const ac=(e&&e.getAttribute('autocomplete')||'').toLowerCase().split(/\s+/);
 const purpose=((e&&Element.prototype.matches.call(e,'input[type="password" i]'))||ac.includes('current-password')||ac.includes('new-password'))?'password':secure?'generic-secret':ac.includes('one-time-code')?'one-time-code':ac.includes('username')?'username':'none';
 const associated=e&&e.labels?Array.from(e.labels):[];
 const referenced=e?(e.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean).map(id=>e.getRootNode().getElementById?.(id)||doc.getElementById(id)).filter(Boolean):[];
 const labelNodes=[...referenced,...associated];
 const labelTexts=[...referenced.map(node=>safeLabelText(node)),...associated.map(node=>safeLabelText(node,true))];
 const labels=e?[e.getAttribute('aria-label'),...labelTexts].filter(s=>s!=null&&s!=='').map(normalize):[];
 let completeButtonContentName=null;
 if(simpleNameInventory&&e instanceof HTMLButtonElement&&e.localName==='button'&&!secure&&!secureDescendants&&!protectedEditor&&
   associated.length===0&&!e.hasAttribute('aria-label')&&!e.hasAttribute('aria-labelledby')&&
   (!e.hasAttribute('role')||e.getAttribute('role')==='button'))completeButtonContentName=completeButtonName(e);
 let simpleAssociatedName=null;
 if(simpleNameInventory&&e&&!secure&&!protectedEditor&&associated.length>0&&associated.length<=32&&
   !(e.getAttribute('aria-label')||'').trim()&&!(e.getAttribute('aria-labelledby')||'').trim()){
   const names=associated.map(label=>completeSimpleLabel(label,e));
   if(names.every(name=>name!==null)&&names.reduce((sum,name)=>sum+name.length+1,0)<=512)simpleAssociatedName=normalize(names.join(' '))||null;
 }
 // Complete-empty is distinct from unavailable: a whitespace contribution
 // suppresses title/own-content fallback in the original IDREF computation.
 let completeEmptyReference=false;
 const referenceAttribute=e?(e.getAttribute('aria-labelledby')||''):'';
 if(simpleNameInventory&&e&&!secure&&!protectedEditor&&referenceAttribute.length<=4096&&referenceAttribute.trim()){
   const root=Node.prototype.getRootNode.call(e),ids=referenceAttribute.trim().split(/\s+/);
   if(root===doc&&ids.length<=32){
     let complete=true,targets=0,scanned=0;
     for(const id of ids){
       const target=root.getElementById(id);
       if(!target)continue;
       targets++;
       if(!(target instanceof HTMLElement)||!['span','div','p','label','abbr','b','strong','em','i','small'].includes(target.localName)||
         target.hasAttribute('role')||target.hasAttribute('contenteditable')||target.hasAttribute('aria-labelledby')||composedSecure(target)||target.shadowRoot||
         (target.getAttribute('aria-label')||'').trim()||target.hasAttribute('alt')||
         target.childNodes.length===0||target.childNodes.length>512){complete=false;break;}
       for(const pseudo of ['::before','::after']){
         const content=doc.defaultView.getComputedStyle(target,pseudo).content;
         if(content!=='none'&&content!=='normal'&&content!==''){complete=false;break;}
       }
       if(!complete)break;
       let chars=0;
       for(const child of target.childNodes){
         if(++scanned>512||child.nodeType!==3){complete=false;break;}
         const value=child.nodeValue||'';
         if(value.length>512-chars||!/^\s*$/.test(value)){complete=false;break;}
         chars+=value.length;
       }
       if(!complete||chars===0){complete=false;break;}
     }
     completeEmptyReference=complete&&targets>0;
   }
 }
 const labelledSecure=labelNodes.some(n=>Element.prototype.querySelector.call(n,secureSelectorAll));
 let safePublicName=null;
 if(e&&!secure&&(secureDescendants||labelledSecure)){
   if(referenced.length){const values=referenced.map(node=>safeLabelText(node));if(values.every(s=>s!==null))safePublicName=normalize(values.join(' '));}
   else if(e.hasAttribute('aria-label'))safePublicName=normalize(e.getAttribute('aria-label'));
   else if(labelNodes.length&&labelTexts.every(s=>s!==null))safePublicName=normalize(labelTexts.join(' '));
   else if(secureDescendants)safePublicName=safeLabelText(e);
 }
 let selector=null;if(e&&e.id)selector='#'+CSS.escape(e.id);else if(e&&e.hasAttribute(testId))selector='['+CSS.escape(testId)+'='+JSON.stringify(e.getAttribute(testId))+']';
 const secureText=secure&&(!e||!Element.prototype.matches.call(e,'input,textarea,select'));
 const unsafeLabel=!!e&&(e.getAttribute('aria-labelledby')||'').split(/\s+/).some(id=>composedSecure(doc.getElementById(id)));
 const tag=e?e.localName:'';
 let pageLevelLandmark=null;
 if(tag==='header'||tag==='footer'){
   pageLevelLandmark=true;
   // Public landmark scope includes authored sections across shadow hosts.
   // This fact changes role projection only, never native ownership.
   const scope='article,aside,main,nav,section,[role~="article"],[role~="complementary"],[role~="main"],[role~="navigation"],[role~="region"]';
   let depth=0;
   for(let p=e;p;p=p.parentElement||Node.prototype.getRootNode.call(p)?.host||null){
     if(++depth>256)return {__nativeStatus:'resource-limit'};
     if(Element.prototype.matches.call(p,scope)){pageLevelLandmark=false;break;}
   }
 }

 const editingHost=!!e&&e instanceof HTMLElement&&e.isContentEditable&&
   !['svg','math','canvas','video','audio','iframe','img','hr','br','wbr','area','a','button','input','textarea','select'].includes(tag)&&
   !(e.parentElement instanceof HTMLElement&&e.parentElement.isContentEditable);
 let editorValue=null;
 if(editingHost&&!secure&&!secureDescendants&&!protectedEditor){
   // innerText supplies browser-rendered spaces/newlines, not a second DOM reader.
   // Avoid a codepoint array or an unbounded normalized copy in observation mode.
   const rendered=e.innerText, raw=e.textContent||'';
   if(!/[^\ufeff]/.test(raw)||(!/[^\s\ufeff]/.test(raw)&&/^\ufeff*\n\ufeff*(?![\s\S])/.test(rendered)))editorValue='';
   else { editorValue=''; for(const ch of rendered){if(ch==='\ufeff')continue;editorValue+=ch;if(boundedObservation&&editorValue.length>=512){editorValue=editorValue.slice(0,512);break;}} }
 }
 const inline=!!style&&(style.display.startsWith('inline')||style.display.startsWith('ruby')||style.display==='contents');
 const breaking=!!e&&(Element.prototype.matches.call(e,'br,input,textarea,select,button,iframe')||e.isContentEditable);
 const action=!!e&&(e.hasAttribute('onclick')||tag==='a'||/^\s*[-+]?\d/.test(e.getAttribute('tabindex')||''));
 const suppress=!!e&&(Element.prototype.matches.call(e,'script,style,head,template,noscript')||(e.getAttribute('aria-hidden')||'').toLowerCase()==='true'||e.hasAttribute('inert')||style.display==='none');
 let textVisible=false;
 if(this.nodeType===3&&!secure){
   const parent=this.parentElement||this.getRootNode()?.host;
   if(parent&&doc.defaultView.getComputedStyle(parent).visibility==='visible'){
     const range=doc.createRange();range.selectNode(this);const box=range.getBoundingClientRect();textVisible=box.width>0&&box.height>0;
   }
 }
 let authorText='';
 if(boundedObservation&&this.nodeType===3&&!secure&&textVisible){
   let scanned=0,emitted=0,space=false;
   // Stop before materializing an unbounded normalized string or codepoint array.
   for(const ch of String(this.nodeValue||'')){
     if(++scanned>16384)return {__nativeStatus:'resource-limit'};
     const whitespace=/\s/u.test(ch);
     if(!whitespace||!space){authorText+=whitespace?' ':ch;if(++emitted===513)break;}
     space=whitespace;
   }
 }
 // Exact renderer control state, unlike AX, keeps disabled option selection and
 // ignores stale ARIA on native controls. These remain untrusted semantic facts.
 const checkable=!!e&&tag==='input'&&e instanceof HTMLInputElement&&(e.type==='checkbox'||e.type==='radio');
 const nativeOption=!!e&&tag==='option'&&e instanceof HTMLOptionElement;
 const controlStates={};
 if(checkable)controlStates.checked=e.checked;
 else if(e&&e.hasAttribute('aria-checked'))controlStates.checked=e.getAttribute('aria-checked')==='true';
 if(nativeOption)controlStates.selected=e.selected;
 else if(e&&e.getAttribute('aria-selected')!==null)controlStates.selected=e.getAttribute('aria-selected').toLowerCase()==='true';
 const author={tag,nodeType:this.nodeType,inline,breaking,action,suppress,skipsContent:!!style&&style.contentVisibility==='hidden',lineVisible:tag==='slot'?style.visibility==='visible':null,visible:this.nodeType===9||textVisible||!!e&&!hidden,text:authorText};
 return {author,controlStates,pageLevelLandmark,completeButtonContentName,simpleAssociatedName,completeEmptyReference,handlerProbe:boundedObservation&&!!e&&e instanceof HTMLElement&&!action&&inline&&!breaking&&!suppress&&(tag==='slot'?style.visibility==='visible':!hidden),editingHost,selector,safePublicName,redactName:secureText||unsafeLabel,labels:secureText||unsafeLabel?[]:labels,secureDescendants,attributes:attrs,text:secure||boundedObservation||protectedEditor?null:safeText(this),
 value:secure||(boundedObservation&&checkable)?null:editingHost?editorValue:e&&typeof e.value==='string'?e.value:null,selection, inputPurpose:purpose,
 testId:e?e.getAttribute(testId):null, states:{secure,hidden,focused,disabled:!!e&&(Element.prototype.matches.call(e,':disabled')||e.getAttribute('aria-disabled')==='true')},
 rect:r?{x:r.x,y:r.y,width:r.width,height:r.height}:null};
}"#;
#[allow(clippy::too_many_arguments)] // Explicit browser ownership, revision, policy, and deadline inputs.
async fn read_backend(
    client: &CdpClient,
    frame: &ObservationFrame,
    backend: i64,
    ax: &AXNode,
    revision: u64,
    options: &ObservationOptions,
    lease: &OperationLease,
    bounded: bool,
) -> Result<SemanticNode, ObservationError> {
    if ax.backend_d_o_m_node_id != Some(backend) {
        return Err(ObservationError::StaleReference);
    }
    validate_frame(client, frame, lease).await?;
    let acquisition_policy = security_inventory(client, frame, options, lease).await?;
    validate_frame(client, frame, lease).await?;
    let mut node = read_batch_with_refs(
        client,
        frame,
        &[ax],
        None,
        revision,
        options,
        lease,
        bounded,
        &acquisition_policy,
    )
    .await?
    .into_iter()
    .next()
    .ok_or(ObservationError::BackendFailure)?;
    // Metadata acquisition can race document/frame retirement. Revalidate the
    // exact identity before the next DOM inventory and after a failed inventory;
    // only positive retirement evidence changes a backend error into stale.
    validate_frame(client, frame, lease).await?;
    let security = match security_inventory(client, frame, options, lease).await {
        Ok(security) => security,
        Err(ObservationError::BackendFailure) => {
            validate_frame(client, frame, lease).await?;
            return Err(ObservationError::BackendFailure);
        }
        Err(error) => return Err(error),
    };
    apply_security(&mut node, backend, &security);
    Ok(node)
}
fn project_node(
    frame: &ObservationFrame,
    backend: i64,
    ax: &AXNode,
    refs: &mut RefMap,
    revision: u64,
    data: &Value,
    bounded: bool,
) -> Result<SemanticNode, ObservationError> {
    project_node_with_refs(frame, backend, ax, Some(refs), revision, data, bounded)
}
#[allow(clippy::too_many_arguments)]
fn project_node_with_refs(
    frame: &ObservationFrame,
    backend: i64,
    ax: &AXNode,
    refs: Option<&mut RefMap>,
    revision: u64,
    data: &Value,
    bounded: bool,
) -> Result<SemanticNode, ObservationError> {
    match data["__nativeStatus"].as_str() {
        Some("stale-reference") => return Err(ObservationError::StaleReference),
        Some("invalid-arguments") => return Err(ObservationError::InvalidArguments),
        Some("resource-limit") => return Err(ObservationError::ResourceLimit),
        Some(_) => return Err(ObservationError::BackendFailure),
        None => {}
    }
    let mut role = ax_string(&ax.role).map(|role| match role.as_str() {
        "img" => "image".into(),
        "Iframe" => "iframe".into(),
        "Date" | "DateTime" | "InputTime" | "ColorWell" => "textbox".into(),
        "RootWebArea" | "WebArea" => "document".into(),
        "StaticText" | "ListMarker" => "text".into(),
        _ => role,
    });
    let author = data
        .get("author")
        .map(|value| {
            serde_json::from_value::<author_projection::Facts>(value.clone())
                .map_err(|_| ObservationError::BackendFailure)
        })
        .transpose()?;
    if author.is_some()
        // AX has already selected the effective role. An arbitrary authored
        // attribute is not evidence that an incidental AX role was requested:
        // ARIA token separation is ASCII whitespace, not Unicode whitespace.
        && !data["attributes"]["role"].as_str().is_some_and(|authored| {
            authored.split_ascii_whitespace().any(|token| {
                Some(token) == role.as_deref()
                    && !matches!(token, "LabelText" | "sectionheader" | "sectionfooter")
            })
        })
        && matches!(
            role.as_deref(),
            Some(
                "generic"
                    | "none"
                    | "LabelText"
                    | "sectionheader"
                    | "sectionfooter"
                    | "paragraph"
                    | "strong"
                    | "emphasis"
                    | "code"
                    | "superscript"
                    | "subscript"
            )
        )
    {
        role = None;
    }
    // These author tags have no implicit public role. Native AX names such as
    // DisclosureTriangle/term/definition are not additional public vocabulary.
    if author
        .as_ref()
        .is_some_and(|facts| matches!(facts.tag.as_str(), "summary" | "dt" | "dd"))
        && authored_role(&data["attributes"]).is_none()
    {
        role = None;
    }
    if author.as_ref().is_some_and(|facts| facts.tag == "iframe") && role.is_none() {
        role = Some("iframe".into());
    }
    if data["pageLevelLandmark"] == false
        && author
            .as_ref()
            .is_some_and(|facts| matches!(facts.tag.as_str(), "header" | "footer"))
        && authored_role(&data["attributes"]).is_none()
    {
        role = None;
    }
    if data["editingHost"] == true {
        role = Some(
            match authored_role(&data["attributes"]) {
                Some("img") => "image",
                Some(role) => role,
                None => "textbox",
            }
            .to_owned(),
        );
    }
    let mut binding = frame.binding.clone();
    binding.actionable = !matches!(role.as_deref(), Some("document" | "text" | "InlineTextBox"))
        && !author
            .as_ref()
            .is_some_and(|facts| matches!(facts.node_type, 3 | 9));
    let (id, issued_revision) = if let Some(refs) = refs {
        let id = if data["__nativeReadonlyPseudo"] == true {
            refs.try_bind_readonly_pseudo(backend, role.as_deref().unwrap_or(""), binding)
        } else {
            refs.try_bind_exact(backend, role.as_deref().unwrap_or(""), "", binding)
        }
        .map_err(reference_allocation_error)?;
        let issued = refs
            .get(&id)
            .and_then(RefEntry::issued_revision)
            .ok_or(ObservationError::StaleReference)?;
        (format!("@{id}"), issued)
    } else {
        // Internal candidates never carry public reference authority.
        (String::new(), revision)
    };
    let mut node = SemanticNode {
        author,
        reference: NodeReference {
            id,
            revision: issued_revision.to_string(),
        },
        role,
        name: ax_string(&ax.name).filter(|name| !name.is_empty()),
        frame_path: frame.frame_path.clone(),
        ..Default::default()
    };
    // Only a complete native-gated simple label can fill absent AX naming.
    // Apply before security selection, so security can still clear the name.
    if node.name.is_none()
        && data["states"]["secure"] != true
        && data["secureDescendants"] != true
        && data["redactName"] != true
        && data["attributes"]["aria-label"]
            .as_str()
            .is_none_or(|s| s.trim_matches(ecmascript_whitespace).is_empty())
        && data["attributes"]["aria-labelledby"]
            .as_str()
            .is_none_or(|s| s.trim_matches(ecmascript_whitespace).is_empty())
    {
        node.name = data["simpleAssociatedName"]
            .as_str()
            .filter(|name| !name.is_empty())
            .map(str::to_owned);
    }
    // Complete content evidence can correct an incomplete AX name, including
    // a proven empty name. Apply before all existing security selection and
    // normalization; query, exact read, and observation share this projection.
    if let Some(value) = data
        .get("completeButtonContentName")
        .filter(|v| !v.is_null())
    {
        let name = value.as_str().ok_or("Invalid complete button name")?;
        if name.chars().count() > 512 {
            return Err(ObservationError::BackendFailure);
        }
        if node.role.as_deref() == Some("button")
            && node
                .author
                .as_ref()
                .is_some_and(|facts| facts.tag == "button")
            && data["__nativeReadonlyPseudo"] != true
            && data["states"]["secure"] != true
            && data["secureDescendants"] != true
            && data["redactName"] != true
            && data["attributes"]["aria-label"].is_null()
            && data["attributes"]["aria-labelledby"].is_null()
            && data["attributes"]["role"]
                .as_str()
                .is_none_or(|role| role == "button")
        {
            node.name = (!name.is_empty()).then(|| name.to_owned());
        }
    }
    node.safe_public_name = data["safePublicName"]
        .as_str()
        .filter(|v| !v.is_empty())
        .map(str::to_owned);
    if data["secureDescendants"] == true
        || data["redactName"] == true
        || node.safe_public_name.is_some()
    {
        node.name = node.safe_public_name.clone();
    }
    if data["completeEmptyReference"] == true {
        // Empty referenced content is positive provenance, not permission to
        // restore a title or fall back to the element's own AX content.
        node.name = None;
    }
    // Normalize the selected, security-approved name once for every consumer.
    // A title cannot resurrect a name removed by the secure-content policy.
    let title = if data["secureDescendants"] == true
        || data["redactName"] == true
        || !data["safePublicName"].is_null()
    {
        None
    } else {
        data["attributes"]["title"].as_str()
    };
    node.name = node.name.and_then(|name| reported_public_name(name, title));
    node.safe_public_name = node
        .safe_public_name
        .and_then(|name| reported_public_name(name, None));
    node.labels = serde_json::from_value::<Vec<String>>(data["labels"].clone())
        .map_err(|_| "Invalid labels")?
        .into_iter()
        .map(|label| normalize_public_label(&label))
        .collect();
    node.attributes =
        serde_json::from_value(data["attributes"].clone()).map_err(|_| "Invalid attributes")?;
    node.states = serde_json::from_value(data["states"].clone()).map_err(|_| "Invalid states")?;
    for p in ax.properties.as_deref().unwrap_or_default() {
        if ["checked", "selected", "expanded", "pressed", "disabled"].contains(&p.name.as_str()) {
            if let Some(value) = p.value.value.as_ref().and_then(|v| {
                v.as_bool().or_else(|| match v.as_str() {
                    Some("true") => Some(true),
                    Some("false") => Some(false),
                    _ => None,
                })
            }) {
                // Native :disabled includes fieldset/optgroup semantics; AX also
                // supplies inherited aria-disabled on applicable widget roles.
                let value =
                    value || (p.name == "disabled" && node.states.get("disabled") == Some(&true));
                node.states.insert(p.name.clone(), value);
            }
        }
        if p.name == "level" {
            node.level = p.value.value.as_ref().and_then(Value::as_i64);
        }
    }
    if data["__nativeReadonlyPseudo"] != true {
        if let Some(states) = data.get("controlStates") {
            let states = states.as_object().ok_or("Invalid control states")?;
            for (name, value) in states {
                if !matches!(name.as_str(), "checked" | "selected") {
                    return Err(ObservationError::BackendFailure);
                }
                node.states.insert(
                    name.clone(),
                    value.as_bool().ok_or("Invalid control state")?,
                );
            }
        }
    }
    node.selector = data["selector"].as_str().map(str::to_owned);
    node.text = data["text"].as_str().map(str::to_owned);
    node.value = data["value"].as_str().map(str::to_owned);
    node.selection = data["selection"].as_str().map(str::to_owned);
    node.test_id = data["testId"].as_str().map(str::to_owned);
    node.input_purpose = data["inputPurpose"].as_str().map(str::to_owned);
    node.rect = serde_json::from_value(data["rect"].clone()).map_err(|_| "Invalid rectangle")?;
    if let Some(rect) = node.rect.as_mut() {
        rect.x += frame.offset_x;
        rect.y += frame.offset_y;
    }
    if node.states.get("secure") == Some(&true) {
        node.value = None;
        node.text = None;
        node.selection = None;
        node.attributes.remove("value");
    }
    if bounded {
        node.safe_public_name = node
            .safe_public_name
            .map(|name| name.chars().take(256).collect());
        node.attributes.retain(|name, _| {
            matches!(
                name.as_str(),
                "type" | "autocomplete" | "href" | "role" | "placeholder"
            ) || name.starts_with("aria-")
        });
        // Bounded METADATA already reduced href against its exact document.
        // Preserve its explicit query/fragment elision markers and whole path.
        for (field, limit) in [
            (&mut node.name, 256),
            (&mut node.text, 512),
            (&mut node.selection, 512),
        ] {
            if let Some(value) = field {
                *value = value.chars().take(limit).collect();
            }
        }
    }
    Ok(node)
}

// Capture parents first so an exact, validated hidden iframe owner can exclude
// its document before any child content is acquired. A missing/cyclic parent is
// not evidence of invisibility and must fail closed.
fn observation_frame_order(
    frames: &[ObservationFrame],
) -> Result<Vec<&ObservationFrame>, ObservationError> {
    if frames.len() > 100_000 {
        return Err(ObservationError::ResourceLimit);
    }
    let mut by_id = HashMap::new();
    for frame in frames {
        if by_id.insert(frame.binding.frame.as_str(), frame).is_some() {
            return Err(ObservationError::BackendFailure);
        }
    }
    let mut ordered = Vec::with_capacity(frames.len());
    for frame in frames {
        let mut ancestor = frame;
        let mut depth = 0usize;
        while let Some(parent) = ancestor.parent_frame_id.as_deref() {
            depth += 1;
            if depth > 256 {
                return Err(ObservationError::BackendFailure);
            }
            ancestor = by_id
                .get(parent)
                .copied()
                .ok_or(ObservationError::BackendFailure)?;
        }
        ordered.push((depth, frame));
    }
    ordered.sort_by_key(|(depth, _)| *depth);
    Ok(ordered.into_iter().map(|(_, frame)| frame).collect())
}

/// Private positive exclusion evidence. Public serialization never carries it;
/// omitted/truncated semantic nodes are not evidence of hidden frame content.
#[derive(Clone, Debug, Default)]
pub(crate) struct HiddenFrameProof {
    inventory: Vec<ObservationFrame>,
    owners: Vec<(ObservationFrame, ObservationFrame)>,
    excluded: std::collections::HashSet<String>,
    test_id_attribute: String,
    secure_field_selector: String,
}
impl HiddenFrameProof {
    #[cfg(test)]
    pub(crate) fn for_test(frames: &[ObservationFrame], direct_hidden_children: &[&str]) -> Self {
        let direct: std::collections::HashSet<_> = direct_hidden_children.iter().copied().collect();
        let hidden = frames
            .iter()
            .filter(|frame| direct.contains(frame.binding.frame.as_str()))
            .map(|frame| {
                (
                    frame.parent_frame_id.clone().expect("hidden child parent"),
                    frame.owner_backend_id.expect("hidden child owner"),
                )
            })
            .collect();
        let mut excluded = std::collections::HashSet::new();
        for frame in observation_frame_order(frames).unwrap() {
            if direct.contains(frame.binding.frame.as_str())
                || frame
                    .parent_frame_id
                    .as_ref()
                    .is_some_and(|parent| excluded.contains(parent))
            {
                excluded.insert(frame.binding.frame.clone());
            }
        }
        Self::new(frames, &hidden, excluded, &ObservationOptions::default()).unwrap()
    }
    fn new(
        frames: &[ObservationFrame],
        hidden: &std::collections::HashSet<(String, i64)>,
        excluded: std::collections::HashSet<String>,
        options: &ObservationOptions,
    ) -> Result<Self, ObservationError> {
        let mut owners = Vec::new();
        for child in frames {
            let Some(parent_id) = &child.parent_frame_id else {
                continue;
            };
            if excluded.contains(parent_id) {
                continue;
            }
            let backend = child
                .owner_backend_id
                .ok_or(ObservationError::BackendFailure)?;
            if hidden.contains(&(parent_id.clone(), backend)) {
                let parent = frames
                    .iter()
                    .find(|frame| &frame.binding.frame == parent_id)
                    .ok_or(ObservationError::BackendFailure)?;
                owners.push((parent.clone(), child.clone()));
            }
        }
        let proof = Self {
            inventory: frames.to_vec(),
            owners,
            excluded,
            test_id_attribute: options.test_id_attribute.clone(),
            secure_field_selector: options.secure_field_selector.clone(),
        };
        proof.validate_inventory(frames)?;
        Ok(proof)
    }
    pub(crate) fn excluded_frames(&self) -> &std::collections::HashSet<String> {
        &self.excluded
    }

    pub(crate) fn validate_inventory(
        &self,
        frames: &[ObservationFrame],
    ) -> Result<(), ObservationError> {
        let ordered = observation_frame_order(frames)?;
        if frames.len() != self.inventory.len() {
            return Err(ObservationError::StaleReference);
        }
        for expected in &self.inventory {
            let actual = frames
                .iter()
                .find(|frame| frame.binding.frame == expected.binding.frame)
                .ok_or(ObservationError::StaleReference)?;
            if actual.binding != expected.binding
                || actual.parent_frame_id != expected.parent_frame_id
                || actual.owner_backend_id != expected.owner_backend_id
            {
                return Err(ObservationError::StaleReference);
            }
        }
        let mut direct = std::collections::HashSet::new();
        for (parent, child) in &self.owners {
            let actual = frames
                .iter()
                .find(|frame| frame.binding.frame == child.binding.frame)
                .ok_or(ObservationError::StaleReference)?;
            let actual_parent = frames
                .iter()
                .find(|frame| frame.binding.frame == parent.binding.frame)
                .ok_or(ObservationError::StaleReference)?;
            if actual.binding != child.binding
                || actual.parent_frame_id.as_ref() != Some(&parent.binding.frame)
                || actual.owner_backend_id != child.owner_backend_id
                || child.owner_backend_id.is_none_or(|id| id <= 0)
                || actual_parent.binding != parent.binding
                || !direct.insert(child.binding.frame.clone())
            {
                return Err(ObservationError::StaleReference);
            }
        }
        let mut closure = std::collections::HashSet::new();
        for frame in ordered {
            if direct.contains(&frame.binding.frame)
                || frame
                    .parent_frame_id
                    .as_ref()
                    .is_some_and(|parent| closure.contains(parent))
            {
                closure.insert(frame.binding.frame.clone());
            }
        }
        if closure != self.excluded {
            return Err(ObservationError::BackendFailure);
        }
        Ok(())
    }

    pub(crate) async fn revalidate(
        &self,
        client: &CdpClient,
        lease: &OperationLease,
    ) -> Result<(), ObservationError> {
        check(lease)?;
        self.validate_inventory(&self.inventory)?;
        for (index, (parent, child)) in self.owners.iter().enumerate() {
            check(lease)?;
            let session = &parent.binding.session;
            let group = format!("native-hidden-proof-{}-{index}", lease.sequence);
            let result = async {
                validate_frame(client, parent, lease).await?;
                validate_frame(client, child, lease).await?;
                let backend = child.owner_backend_id.ok_or(ObservationError::BackendFailure)?;
                let owner = command(client, session, "DOM.getFrameOwner", json!({"frameId":child.binding.frame}), lease).await?;
                if owner["backendNodeId"].as_i64().ok_or(ObservationError::BackendFailure)? != backend { return Err(ObservationError::StaleReference); }
                let world = command(client, session, "Page.createIsolatedWorld", json!({"frameId":parent.binding.frame,"worldName":"agent-browser-native-observation"}), lease).await?;
                let context = world["executionContextId"].as_i64().ok_or(ObservationError::BackendFailure)?;
                let remote = command(client, session, "DOM.resolveNode", json!({"backendNodeId":backend,"executionContextId":context,"objectGroup":group}), lease).await?;
                if remote["object"]["subtype"] != "node" { return Err(ObservationError::BackendFailure); }
                let object = remote["object"]["objectId"].as_str().ok_or(ObservationError::BackendFailure)?;
                // The same metadata reader validates the native receiver/document.
                // Bounded + protected-editor modes prevent raw text/value reads;
                // only the fixed identity/hidden facts leave this call.
                let function = format!("function(testId,secureSelector){{const read={METADATA};const data=read.call(this,testId,secureSelector,true,true,false);return {{status:data.__nativeStatus,nodeType:data.author?.nodeType,tag:data.author?.tag,hidden:data.states?.hidden}};}}");
                let reply = command(client, session, "Runtime.callFunctionOn", json!({"objectId":object,"objectGroup":group,"functionDeclaration":function,"arguments":[{"value":self.test_id_attribute},{"value":self.secure_field_selector}],"returnByValue":true}), lease).await?;
                if reply.get("exceptionDetails").is_some() { return Err(ObservationError::BackendFailure); }
                let facts = &reply["result"]["value"];
                if facts["status"] == "stale-reference" { return Err(ObservationError::StaleReference); }
                if !facts["status"].is_null() || facts["nodeType"] != 1 || facts["tag"] != "iframe" { return Err(ObservationError::BackendFailure); }
                match facts["hidden"].as_bool() {
                    Some(true) => {},
                    Some(false) => return Err(ObservationError::StaleReference),
                    None => return Err(ObservationError::BackendFailure),
                }
                validate_frame(client, parent, lease).await?;
                validate_frame(client, child, lease).await
            }.await;
            settle_object_group(client, session, &group, result).await?;
        }
        Ok(())
    }
}

fn proven_hidden_iframe(node: &SemanticNode) -> bool {
    node.states.get("hidden") == Some(&true)
        && node
            .author
            .as_ref()
            .is_some_and(|facts| facts.node_type == 1 && facts.tag == "iframe")
}

fn frame_has_hidden_owner(
    frame: &ObservationFrame,
    hidden_owners: &std::collections::HashSet<(String, i64)>,
    skipped_frames: &std::collections::HashSet<String>,
) -> Result<bool, ObservationError> {
    let Some(parent) = frame.parent_frame_id.as_ref() else {
        return Ok(false);
    };
    let backend = frame
        .owner_backend_id
        .ok_or(ObservationError::BackendFailure)?;
    Ok(skipped_frames.contains(parent) || hidden_owners.contains(&(parent.clone(), backend)))
}

/// Capture all requested frames to staging state. A late failure never publishes
/// a partial tree or reference registry. Reserved IDs remain consumed.
pub async fn observe(
    client: &CdpClient,
    frames: &[ObservationFrame],
    refs: &mut RefMap,
    identity_scope: &str,
    revision: u64,
    options: &ObservationOptions,
    lease: &OperationLease,
) -> Result<Observation, ObservationError> {
    if frames.is_empty() || options.max_nodes == 0 || options.max_nodes > 100000 {
        return Err(ObservationError::InvalidArguments);
    }
    let mut staged = refs.clone();
    staged.begin_observation(identity_scope, lease.generation, revision);
    let mut frame_roots: HashMap<String, Vec<SemanticNode>> = HashMap::new();
    let mut count = 0;
    let mut truncated = false;
    let ordered_frames = observation_frame_order(frames)?;
    let mut hidden_owners = std::collections::HashSet::new();
    let mut skipped_frames = std::collections::HashSet::new();
    for frame in ordered_frames {
        check(lease)?;
        if frame_has_hidden_owner(frame, &hidden_owners, &skipped_frames)? {
            skipped_frames.insert(frame.binding.frame.clone());
            continue;
        }
        validate_frame(client, frame, lease).await?;
        let value = command(
            client,
            &frame.binding.session,
            "Accessibility.getFullAXTree",
            json!({"frameId":frame.binding.frame}),
            lease,
        )
        .await?;
        let tree: GetFullAXTreeResult =
            serde_json::from_value(value).map_err(|_| ObservationError::BackendFailure)?;
        let security = security_inventory(client, frame, options, lease).await?;
        let dom = frame_dom(client, frame, lease).await?;
        let graph = author_projection::Graph::read(&dom["root"])?;
        if graph
            .ids
            .iter()
            .any(|id| security.browser_internal.contains(id))
        {
            return Err(ObservationError::BackendFailure);
        }
        staged
            .check_exact_admission(&frame.binding, &graph.ids)
            .map_err(reference_allocation_error)?;
        let ax_by_backend: HashMap<i64, &AXNode> = tree
            .nodes
            .iter()
            .filter(|ax| ax_string(&ax.role).as_deref() != Some("InlineTextBox"))
            .filter_map(|ax| ax.backend_d_o_m_node_id.map(|id| (id, ax)))
            .collect();
        let candidates: Vec<AXNode> = graph
            .ids
            .iter()
            .map(|id| {
                ax_by_backend
                    .get(id)
                    .map(|ax| (*ax).clone())
                    .unwrap_or(AXNode {
                        node_id: String::new(),
                        role: None,
                        name: None,
                        value: None,
                        description: None,
                        properties: None,
                        child_ids: None,
                        backend_d_o_m_node_id: Some(*id),
                        ignored: None,
                    })
            })
            .collect();
        let mut nodes = HashMap::new();
        for chunk in candidates.chunks(64) {
            let batch = read_batch(
                client,
                frame,
                &chunk.iter().collect::<Vec<_>>(),
                &mut staged,
                revision,
                options,
                lease,
                true,
                &security,
            )
            .await?;
            for (ax, mut node) in chunk.iter().zip(batch) {
                let id = ax
                    .backend_d_o_m_node_id
                    .ok_or(ObservationError::BackendFailure)?;
                apply_security(&mut node, id, &security);
                nodes.insert(id, node);
            }
        }
        // Publish this proof only after revalidating the exact parent loader.
        // The key is the native owner backend ID, never a selector/name match.
        validate_frame(client, frame, lease).await?;
        hidden_owners.extend(
            nodes
                .iter()
                .filter(|(_, node)| proven_hidden_iframe(node))
                .map(|(id, _)| (frame.binding.frame.clone(), *id)),
        );
        let (roots, frame_truncated) =
            author_projection::compact(&graph, nodes, options.max_nodes - count)?;
        let mut pending = roots.iter().collect::<Vec<_>>();
        while let Some(node) = pending.pop() {
            count += 1;
            pending.extend(node.children.iter());
        }
        truncated |= frame_truncated;
        frame_roots.insert(frame.binding.frame.clone(), roots);
        validate_frame(client, frame, lease).await?;
    }
    let mut pending: Vec<&ObservationFrame> = frames.iter().collect();
    pending.sort_by_key(|f| std::cmp::Reverse(f.frame_path.len()));
    for child in pending
        .iter()
        .filter(|f| f.parent_frame_id.is_some() && !skipped_frames.contains(&f.binding.frame))
    {
        let parent = child.parent_frame_id.as_ref().unwrap();
        let backend = child.owner_backend_id.ok_or("Missing native frame owner")?;
        let owner = staged
            .durable_ref(&child.binding.page_session, Some(parent), backend)
            .map(|id| format!("@{id}"));
        let children = frame_roots.remove(&child.binding.frame).unwrap_or_default();
        fn attach(
            nodes: &mut [SemanticNode],
            id: &str,
            children: &mut Option<Vec<SemanticNode>>,
        ) -> bool {
            for node in nodes {
                if node.reference.id == id {
                    node.children.extend(children.take().unwrap_or_default());
                    return true;
                }
                if attach(&mut node.children, id, children) {
                    return true;
                }
            }
            false
        }
        let attached = owner.as_ref().is_some_and(|id| {
            frame_roots
                .get_mut(parent)
                .is_some_and(|nodes| attach(nodes, id, &mut Some(children)))
        });
        if !attached && !truncated {
            return Err("Frame owner absent from native observation".into());
        }
    }
    let mut roots = Vec::new();
    for frame in frames.iter().filter(|f| f.parent_frame_id.is_none()) {
        roots.extend(frame_roots.remove(&frame.binding.frame).unwrap_or_default());
    }
    for root in &mut roots {
        scrub_sensitive_ancestors(root);
    }
    let viewport = staged
        .try_viewport_ref(
            identity_scope,
            lease.generation,
            &query_root(frames)?.binding.page_session,
            revision,
        )
        .map_err(|_| ObservationError::BackendFailure)?;
    let viewport_ref = NodeReference {
        id: format!("@{}", viewport.id),
        revision: viewport.issuance.revision.to_string(),
    };
    // Acquiring metadata does not publish authority for hidden/compacted-away
    // candidates. Preserve located authority and exactly the emitted observed
    // tree; the shared monotonic allocator still burns every staged reservation.
    let mut published = std::collections::HashSet::new();
    let mut pending = roots.iter().collect::<Vec<_>>();
    while let Some(node) = pending.pop() {
        let id = super::element::parse_ref(&node.reference.id)
            .ok_or(ObservationError::BackendFailure)?;
        published.insert(id);
        pending.extend(node.children.iter());
    }
    staged.retain_snapshot_entries(refs, &published);
    let hidden_frame_proof =
        HiddenFrameProof::new(frames, &hidden_owners, skipped_frames, options)?;
    check(lease)?;
    *refs = staged;
    Ok(Observation {
        hidden_frame_proof,
        identity_scope: identity_scope.into(),
        revision,
        roots,
        viewport_ref,
        truncated,
    })
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum TextPattern {
    String { value: String, exact: bool },
    Regexp { source: String, flags: String },
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemanticQuery {
    pub kind: QueryKind,
    pub value: TextPattern,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<TextPattern>,
    #[serde(default)]
    pub states: BTreeMap<RoleState, bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visible: Option<bool>,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RoleState {
    Checked,
    Disabled,
    Selected,
    Expanded,
    Pressed,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum QueryKind {
    Role,
    Label,
    Placeholder,
    Text,
    DisplayValue,
    TestId,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum QueryIndex {
    Number(usize),
    Position(IndexPosition),
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IndexPosition {
    First,
    Last,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum LocatorExpression {
    Query {
        query: SemanticQuery,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<Box<LocatorExpression>>,
    },
    Filter {
        source: Box<LocatorExpression>,
        #[serde(rename = "hasText", skip_serializing_if = "Option::is_none")]
        has_text: Option<TextPattern>,
        #[serde(skip_serializing_if = "Option::is_none")]
        has: Option<Box<LocatorExpression>>,
    },
    Index {
        source: Box<LocatorExpression>,
        index: QueryIndex,
    },
    Selector {
        selector: String,
    },
    Frame {
        selector: String,
        source: Box<LocatorExpression>,
    },
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryOptions {
    pub expression: LocatorExpression,
    #[serde(default = "default_test_id")]
    pub test_id_attribute: String,
    #[serde(default = "default_secure_selector")]
    pub secure_field_selector: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResult {
    pub identity_scope: String,
    #[serde(with = "revision_wire")]
    pub revision: u64,
    pub nodes: Vec<SemanticNode>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ReadField {
    Role,
    Name,
    Text,
    Value,
    Selection,
    TestId,
    InputPurpose,
    States,
    Level,
    Attributes,
    Rect,
    Selector,
    FramePath,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadOptions {
    #[serde(rename = "ref")]
    pub reference: String,
    pub fields: Option<Vec<ReadField>>,
    #[serde(default = "default_test_id")]
    pub test_id_attribute: String,
    #[serde(default = "default_secure_selector")]
    pub secure_field_selector: String,
}
/// A full read is unbounded. Field selection is a wire projection, never a way
/// to bypass secure-field checks or native identity validation.
/// Unlike the public engine session's cached locate read, this native primitive
/// freshly resolves live sources or reads an exact acquisition. It preserves
/// the requested ID and stored issuance revision without publication.
pub async fn read(
    client: &CdpClient,
    frames: &[ObservationFrame],
    refs: &mut RefMap,
    identity_scope: &str,
    _revision: u64,
    options: &ReadOptions,
    lease: &OperationLease,
) -> Result<Value, ObservationError> {
    if refs.is_viewport_ref(&options.reference) {
        return Err(ObservationError::InvalidArguments);
    }
    let id =
        super::element::parse_ref(&options.reference).ok_or(ObservationError::InvalidArguments)?;
    let entry = refs
        .get(&id)
        .cloned()
        .ok_or(ObservationError::StaleReference)?;
    let root = query_root(frames)?;
    if !entry.matches_scope(identity_scope, lease.generation, &root.binding.page_session) {
        return Err(ObservationError::StaleReference);
    }
    let issued_revision = entry
        .issued_revision()
        .ok_or(ObservationError::StaleReference)?;
    let acquired = entry
        .exact_binding
        .as_ref()
        .ok_or(ObservationError::InvalidArguments)?;
    let resolved = match &entry.live_query {
        Some(origin) => Some(resolve_live_query(client, frames, origin, acquired, lease).await?),
        None => None,
    };
    let binding = resolved
        .as_ref()
        .map(|resolved| &resolved.binding)
        .unwrap_or(acquired);
    let backend = resolved
        .as_ref()
        .map(|resolved| resolved.backend_node_id)
        .or(entry.backend_node_id)
        .ok_or(ObservationError::StaleReference)?;
    let frame = frames
        .iter()
        .find(|frame| {
            frame.binding.page_session == binding.page_session
                && frame.binding.session == binding.session
                && frame.binding.frame == binding.frame
                && frame.binding.loader == binding.loader
        })
        .ok_or(ObservationError::StaleReference)?;
    validate_frame_ancestry(client, frames, frame, lease).await?;
    let partial = command(
        client,
        &binding.session,
        "Accessibility.getPartialAXTree",
        json!({"backendNodeId":backend,"fetchRelatives":false}),
        lease,
    )
    .await?;
    let tree: GetFullAXTreeResult =
        serde_json::from_value(partial).map_err(|_| ObservationError::BackendFailure)?;
    let ax = tree
        .nodes
        .iter()
        .find(|n| n.backend_d_o_m_node_id == Some(backend))
        .ok_or(ObservationError::StaleReference)?;
    let mut node = read_backend(
        client,
        frame,
        backend,
        ax,
        issued_revision,
        &ObservationOptions {
            test_id_attribute: options.test_id_attribute.clone(),
            secure_field_selector: options.secure_field_selector.clone(),
            ..Default::default()
        },
        lease,
        false,
    )
    .await?;
    validate_frame_ancestry(client, frames, frame, lease).await?;
    check(lease)?;
    node.reference = NodeReference {
        id: format!("@{id}"),
        revision: issued_revision.to_string(),
    };
    let result = project_read_fields(node, options.fields.as_deref())?;
    Ok(result)
}

fn project_read_fields(
    mut node: SemanticNode,
    fields: Option<&[ReadField]>,
) -> Result<Value, ObservationError> {
    let secure = node.states.get("secure") == Some(&true);
    if secure {
        node.value = None;
        node.text = None;
        node.selection = None;
        node.attributes.remove("value");
    }
    let mut result = serde_json::to_value(node).map_err(|_| ObservationError::BackendFailure)?;
    if let Some(fields) = fields {
        let names: Vec<String> = fields
            .iter()
            .map(|field| {
                serde_json::to_value(field)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        result
            .as_object_mut()
            .unwrap()
            .retain(|key, _| key == "ref" || names.contains(key) || (secure && key == "states"));
        // Mandatory policy metadata survives even a value-only projection. The
        // fixture guard must deny a secure read, not mistake omission for empty.
        if secure && !names.iter().any(|name| name == "states") {
            result["states"] = json!({"secure":true});
        }
    }
    Ok(result)
}

// Matching runs in the browser JavaScript realm to preserve the caller's JS
// RegExp semantics (including flags); no Rust-regex approximation is used.
const MATCH_QUERY: &str = r#"function(expression, data, labels, safeNames, secureSelector, protectedAncestors, ...elements) {
 const norm=s=>String(s??'').replace(/[\u200b\u200c\u200d\ufeff]/g,'').replace(/\s+/g,' ').trim();
 function match(p,s,testId=false) { if(p.kind==='regexp') return new RegExp(p.source,p.flags).test(String(s??'')); if(testId)return String(s??'')===p.value; const a=norm(s),b=norm(p.value); return p.exact?a===b:a.toLowerCase().includes(b.toLowerCase()); }
 if(elements.some(e=>!e.isConnected||e.ownerDocument!==document))return {error:'stale-reference'};
 const all=elements.map((_,i)=>i);
 // Filter text is a private matching fact, not rendered SemanticNode.text.
 // Read authored text nodes in light DOM/open roots, never editable values,
 // closed-root inventories, accessible names, or public display-text metadata.
 const secureNodes=new Set(elements.filter((_,i)=>data[i].states.secure));
 const protectedNodes=new Set(elements.filter((_,i)=>protectedAncestors[i]));
 const secureSelectorAll='input[type="password" i],'+secureSelector;
 const matcherCache=new Map(),matcherLimit={};let matcherWork=0,matcherChars=0;
 function matcherStep(){if(++matcherWork>1000000)throw matcherLimit;}
 function secureNode(node){return node.nodeType===1&&(secureNodes.has(node)||Element.prototype.matches.call(node,secureSelectorAll));}
 function matcherText(root){
  if(matcherCache.has(root))return matcherCache.get(root);
  if(protectedNodes.has(root)){matcherCache.set(root,null);return null;}
  // A directly resolved node can sit inside a secure closed shadow host.
  const seen=new Set();let depth=0;
  for(let node=root;node;node=node.parentElement||node.getRootNode()?.host){
   matcherStep();if(++depth>256||seen.has(node))throw matcherLimit;seen.add(node);
   if(secureNode(node)){matcherCache.set(root,null);return null;}
  }
  const pending=[[root,0]],parts=[];let length=0;
  while(pending.length){
   matcherStep();const [node,depth]=pending.pop();if(depth>256)throw matcherLimit;
   if(node.nodeType===3){
    const text=node.nodeValue||'';length+=text.length;matcherChars+=text.length;
    if(length>1048576||matcherChars>8388608)throw matcherLimit;parts.push(text);continue;
   }
   if(node.nodeType!==1&&node.nodeType!==11)continue;
   // Refuse, rather than concatenate around, a newly protected descendant.
   if(secureNode(node)||protectedNodes.has(node)){matcherCache.set(root,null);return null;}
   if(['SCRIPT','STYLE','NOSCRIPT'].includes(node.nodeName)||document.head?.contains(node))continue;
   // Playwright treats only these non-editable input values as button labels.
   if(node instanceof HTMLInputElement&&['submit','button','reset'].includes(node.type)){
    if(node.isContentEditable){matcherCache.set(root,null);return null;}
    const text=node.value;length+=text.length;matcherChars+=text.length;
    if(length>1048576||matcherChars>8388608)throw matcherLimit;parts.push(text);continue;
   }
   // shadowRoot exposes open author roots only. A native handle within a
   // closed root remains queryable, but its text never escapes through its host.
   const shadow=node.shadowRoot,children=node.childNodes;
   if(pending.length+children.length+(shadow?1:0)>100000)throw matcherLimit;
   if(shadow)pending.push([shadow,depth+1]);
   for(let i=children.length-1;i>=0;i--)pending.push([children[i],depth+1]);
  }
  const text=parts.join('');matcherCache.set(root,text);return text;
 }
 function matchFilterText(pattern,element){
  const text=matcherText(element);if(text===null)return false;
  if(pattern.kind==='regexp')return new RegExp(pattern.source,pattern.flags).test(text);
  // Playwright's hasText string option is always a case-insensitive substring;
  // its whitespace rules differ from the public semantic-text projection.
  const normalize=s=>String(s).replace(/[\u200b\u00ad]/g,'').trim().replace(/\s+/g,' ');
  return normalize(text).toLowerCase().includes(normalize(pattern.value).toLowerCase());
 }
 const contains=(a,b)=>{if(a===b)return false;let node=elements[b];const seen=new Set();while(node&&!seen.has(node)){seen.add(node);node=node.parentNode||(node.getRootNode&&node.getRootNode().host);if(node===elements[a])return true;}return false;};
 const redacted=[];
 for(let i=0;i<data.length;i++)if(data.some((n,j)=>n.states.secure&&contains(i,j))){redacted.push(i);if(safeNames[i]!==null)data[i].name=safeNames[i];else delete data[i].name;delete data[i].text;delete data[i].selection;delete data[i].value;labels[i]=[];}
 function semantic(q,i) {
  const n=data[i],e=elements[i]; if(q.visible&&n.states.hidden)return false;
  if(q.kind==='role') {
   if(n.states.hidden||q.value.kind!=='string'||n.role!==q.value.value)return false;
   if(q.name&&!match(q.name,n.name))return false;
   if(q.level!==undefined&&n.level!==q.level)return false;
   return Object.entries(q.states||{}).every(([k,v])=>n.states[k]===v);
  }
  if(q.kind==='label')return labels[i].some(s=>match(q.value,s));
  if(q.kind==='placeholder')return n.attributes.placeholder!==undefined&&match(q.value,n.attributes.placeholder);
  if(q.kind==='testId')return n.testId!==undefined&&match(q.value,n.testId,true);
  if(q.kind==='displayValue')return e.nodeType===1&&e.matches('input:not([type="checkbox" i]):not([type="radio" i]),textarea,select')&&!n.states.secure&&match(q.value,n.value);
  if(q.kind==='text')return n.text!==undefined&&match(q.value,n.text);
  throw new Error('Unknown semantic query');
 }
 function evaluate(x,scope=all) {
  switch(x.kind) {
   case 'selector': {
    if(x.selector.startsWith('//')||x.selector.startsWith('xpath=')) {
     const xpath=x.selector.replace(/^xpath=/,'');
     return scope.filter(i=>{const d=elements[i].ownerDocument; const r=d.evaluate(xpath,d,null,XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,null); for(let j=0;j<r.snapshotLength;j++)if(r.snapshotItem(j)===elements[i])return true;return false;});
    }
    return scope.filter(i=>elements[i].nodeType===1&&elements[i].matches(x.selector));
   }
   case 'query': {
    const roots=x.scope?evaluate(x.scope,scope):null;
    let candidates=roots?scope.filter(i=>roots.some(root=>contains(root,i))):scope;
    candidates=candidates.filter(i=>semantic(x.query,i));
    // Text selectors select the deepest matching element, not every ancestor.
    if(x.query.kind==='text') candidates=candidates.filter(i=>!candidates.some(j=>contains(i,j)));
    return candidates;
   }
   case 'filter': return evaluate(x.source,scope).filter(i=>(!x.hasText||matchFilterText(x.hasText,elements[i]))&&(!x.has||evaluate(x.has,scope.filter(j=>contains(i,j))).length>0));
   case 'index': {const a=evaluate(x.source,scope);const i=x.index==='first'?0:x.index==='last'?a.length-1:x.index;return i>=0&&i<a.length?[a[i]]:[];}
   case 'frame': throw new Error('Frame expression must be resolved by native frame scope');
   default: throw new Error('Unknown locator expression');
  }
 }
 try { return {indices:evaluate(expression),redacted}; } catch(error) { return {error:error===matcherLimit?"resource-limit":"invalid-arguments"}; }
}"#;

/// Query matching and publication are separate: each acquisition publishes fresh
/// located IDs, while retained live sources later resolve without an allocator.
pub async fn query(
    client: &CdpClient,
    frames: &[ObservationFrame],
    refs: &mut RefMap,
    identity_scope: &str,
    revision: u64,
    options: &QueryOptions,
    lease: &OperationLease,
) -> Result<QueryResult, ObservationError> {
    validate_expression(&options.expression, 0)?;
    let (path, expression) = split_frame_expression(&options.expression)?;
    let frame = query_frame(client, frames, &path, options, lease, false).await?;
    let evaluated = evaluate_query(client, frame, &expression, options, lease).await?;
    let pinned = query_uses_pinned_handles(&expression);
    let origin_budget = refs
        .located_origin_budget(evaluated.matches.len())
        .map_err(reference_allocation_error)?;
    let mut origin_bytes = 0usize;
    let origins = evaluated
        .matches
        .iter()
        .enumerate()
        .map(|(index, matched)| {
            if index % 32 == 0 {
                check(lease)?;
            }
            if pinned {
                return Ok(None);
            }
            let source = LiveQuerySource {
                options: options.clone(),
                selection: retained_query_selection(
                    evaluated.projection_count,
                    matched.projection_index,
                ),
            };
            let source =
                serde_json::to_string(&source).map_err(|_| ObservationError::BackendFailure)?;
            origin_bytes = origin_bytes
                .checked_add(source.len())
                .ok_or(ObservationError::ResourceLimit)?;
            if origin_bytes > origin_budget {
                return Err(ObservationError::ResourceLimit);
            }
            Ok(Some(LiveQueryOrigin::new(source)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    check(lease)?;
    let mut staged = refs.clone();
    check(lease)?;
    let mut nodes = Vec::with_capacity(evaluated.matches.len());
    let issuance = LocatedIssuance {
        identity_scope: identity_scope.into(),
        generation: lease.generation,
        revision,
    };
    let mut admitted = staged
        .admit_located_batch(&origins)
        .map_err(reference_allocation_error)?;
    for (index, (matched, origin)) in evaluated.matches.into_iter().zip(origins).enumerate() {
        if index % 32 == 0 {
            check(lease)?;
        }
        let mut node = matched.node;
        let binding = actionable_binding(frame, &node);
        let id = admitted
            .try_bind(
                matched.backend_node_id,
                node.role.as_deref().unwrap_or(""),
                binding,
                issuance.clone(),
                origin,
            )
            .map_err(reference_allocation_error)?;
        node.reference = NodeReference {
            id: format!("@{id}"),
            revision: revision.to_string(),
        };
        nodes.push(node);
    }
    validate_frame_ancestry(client, frames, frame, lease).await?;
    check(lease)?;
    *refs = staged;
    Ok(QueryResult {
        identity_scope: identity_scope.into(),
        revision,
        nodes,
    })
}

fn actionable_binding(frame: &ObservationFrame, node: &SemanticNode) -> ExactBinding {
    let mut binding = frame.binding.clone();
    binding.actionable = !matches!(
        node.role.as_deref(),
        Some("document" | "text" | "InlineTextBox")
    ) && !node
        .author
        .as_ref()
        .is_some_and(|facts| matches!(facts.node_type, 3 | 9));
    binding
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "index",
    rename_all = "camelCase",
    deny_unknown_fields
)]
enum LiveQuerySelection {
    Strict,
    Nth(usize),
}

fn retained_query_selection(projection_count: usize, original_index: usize) -> LiveQuerySelection {
    if projection_count == 1 {
        LiveQuerySelection::Strict
    } else {
        LiveQuerySelection::Nth(original_index)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LiveQuerySource {
    options: QueryOptions,
    selection: LiveQuerySelection,
}

struct QueryMatch {
    backend_node_id: i64,
    node: SemanticNode,
    projection_index: usize,
}

struct QueryEvaluation {
    projection_count: usize,
    matches: Vec<QueryMatch>,
}

/// Selection evidence is temporary; it never replaces acquisition evidence on
/// the RefEntry and never mints a public reference.
pub(crate) struct ResolvedQuery {
    pub backend_node_id: i64,
    pub binding: ExactBinding,
    pub frame: ObservationFrame,
    pub node: SemanticNode,
}

// Mirrors the outer projected source: predicate-pinned queries stay pinned
// through filter/index, but an inner scope or has query does not pin its parent.
fn query_uses_pinned_handles(expression: &LocatorExpression) -> bool {
    match expression {
        LocatorExpression::Query { query, .. } => {
            matches!(query.kind, QueryKind::DisplayValue)
                || matches!(
                    (&query.kind, &query.value),
                    (QueryKind::Label, TextPattern::String { exact: true, .. })
                )
        }
        LocatorExpression::Filter { source, .. }
        | LocatorExpression::Index { source, .. }
        | LocatorExpression::Frame { source, .. } => query_uses_pinned_handles(source),
        LocatorExpression::Selector { .. } => false,
    }
}

/// Resolve the whole stored query against the current document of its original
/// Page owner. Captured leaf loaders/backends are not live-query authority.
pub(crate) async fn resolve_live_query(
    client: &CdpClient,
    frames: &[ObservationFrame],
    origin: &LiveQueryOrigin,
    acquisition_binding: &ExactBinding,
    lease: &OperationLease,
) -> Result<ResolvedQuery, ObservationError> {
    let source: LiveQuerySource =
        serde_json::from_str(&origin.source).map_err(|_| ObservationError::BackendFailure)?;
    validate_expression(&source.options.expression, 0)?;
    let (path, expression) = split_frame_expression(&source.options.expression)?;
    let root = query_root(frames)?;
    if root.binding.page_session != acquisition_binding.page_session {
        return Err(ObservationError::StaleReference);
    }
    let frame = query_frame(client, frames, &path, &source.options, lease, true).await?;
    let evaluated = evaluate_query(client, frame, &expression, &source.options, lease).await?;
    let selected_index = match source.selection {
        LiveQuerySelection::Strict => {
            if evaluated.projection_count != 1 {
                return Err(ObservationError::StaleReference);
            }
            0
        }
        LiveQuerySelection::Nth(index) => index,
    };
    let matched = evaluated
        .matches
        .into_iter()
        .find(|matched| matched.projection_index == selected_index)
        .ok_or(ObservationError::StaleReference)?;
    validate_frame_ancestry(client, frames, frame, lease).await?;
    validate_frame(client, root, lease).await?;
    check(lease)?;
    Ok(ResolvedQuery {
        backend_node_id: matched.backend_node_id,
        binding: actionable_binding(frame, &matched.node),
        frame: frame.clone(),
        node: matched.node,
    })
}

fn query_root(frames: &[ObservationFrame]) -> Result<&ObservationFrame, ObservationError> {
    let mut roots = frames
        .iter()
        .filter(|frame| frame.parent_frame_id.is_none());
    let root = roots.next().ok_or(ObservationError::StaleReference)?;
    if roots.next().is_some() {
        return Err(ObservationError::StaleReference);
    }
    Ok(root)
}

async fn query_frame<'a>(
    client: &CdpClient,
    frames: &'a [ObservationFrame],
    path: &[String],
    options: &QueryOptions,
    lease: &OperationLease,
    retained: bool,
) -> Result<&'a ObservationFrame, ObservationError> {
    let mut frame = query_root(frames)?;
    for selector in path {
        frame = select_frame(client, frames, frame, selector, options, lease)
            .await
            .map_err(|error| match error {
                FrameSelectionError::Cardinality => {
                    if retained {
                        ObservationError::StaleReference
                    } else {
                        ObservationError::InvalidArguments
                    }
                }
                FrameSelectionError::Observation(error) => error,
            })?;
    }
    Ok(frame)
}

/// Recheck every native frame/owner edge of the selected document, rather than
/// treating a same-looking leaf or numeric backend as ancestry proof.
async fn validate_frame_ancestry(
    client: &CdpClient,
    frames: &[ObservationFrame],
    frame: &ObservationFrame,
    lease: &OperationLease,
) -> Result<(), ObservationError> {
    let mut current = frame;
    let mut seen = std::collections::HashSet::new();
    loop {
        if !seen.insert(current.binding.frame.as_str()) {
            return Err(ObservationError::StaleReference);
        }
        validate_frame(client, current, lease).await?;
        let Some(parent_id) = &current.parent_frame_id else {
            break;
        };
        let parent = frames
            .iter()
            .find(|candidate| &candidate.binding.frame == parent_id)
            .ok_or(ObservationError::StaleReference)?;
        if parent.binding.page_session != current.binding.page_session {
            return Err(ObservationError::StaleReference);
        }
        let owner = command(
            client,
            &parent.binding.session,
            "DOM.getFrameOwner",
            json!({"frameId":current.binding.frame}),
            lease,
        )
        .await?;
        if owner["backendNodeId"].as_i64() != current.owner_backend_id {
            return Err(ObservationError::StaleReference);
        }
        current = parent;
    }
    Ok(())
}

/// Read-only correlation validates immutable acquisition evidence, never a live
/// source. Native DOM inventory is acquired once per involved document, not once
/// per candidate; it emits no metadata and does not allocate new native refs.
pub(crate) async fn validate_acquisition_bindings(
    client: &CdpClient,
    frames: &[ObservationFrame],
    bindings: &[(ExactBinding, i64)],
    lease: &OperationLease,
) -> Result<(), ObservationError> {
    check(lease)?;
    if bindings.len() > 100_000 || frames.len() > 256 {
        return Err(ObservationError::ResourceLimit);
    }
    let mut grouped: HashMap<(String, String, String, String), std::collections::HashSet<i64>> =
        HashMap::new();
    for (index, (binding, backend)) in bindings.iter().enumerate() {
        if index % 256 == 0 {
            check(lease)?;
        }
        grouped
            .entry((
                binding.page_session.clone(),
                binding.session.clone(),
                binding.frame.clone(),
                binding.loader.clone(),
            ))
            .or_default()
            .insert(*backend);
    }
    if grouped.len() > 256 {
        return Err(ObservationError::ResourceLimit);
    }
    for ((page_session, session, frame_id, loader), expected) in grouped {
        check(lease)?;
        let frame = frames
            .iter()
            .find(|frame| {
                frame.binding.page_session == page_session
                    && frame.binding.session == session
                    && frame.binding.frame == frame_id
                    && frame.binding.loader == loader
            })
            .ok_or(ObservationError::StaleReference)?;
        validate_frame_ancestry(client, frames, frame, lease).await?;
        let dom = frame_dom(client, frame, lease).await?;
        let present = acquisition_backend_inventory(&dom["root"], lease)?;
        if !expected.is_subset(&present) {
            return Err(ObservationError::StaleReference);
        }
        validate_frame_ancestry(client, frames, frame, lease).await?;
        check(lease)?;
    }
    Ok(())
}

fn acquisition_backend_inventory(
    root: &Value,
    lease: &OperationLease,
) -> Result<std::collections::HashSet<i64>, ObservationError> {
    let mut present = std::collections::HashSet::new();
    let mut pending = vec![(root, 0usize)];
    let mut visited = 0usize;
    while let Some((node, depth)) = pending.pop() {
        visited += 1;
        if visited.is_multiple_of(256) {
            check(lease)?;
        }
        if visited > 100_000 || depth > 256 {
            return Err(ObservationError::ResourceLimit);
        }
        if node["shadowRootType"] == "user-agent" || node.get("pseudoType").is_some() {
            continue;
        }
        if matches!(node["nodeType"].as_i64(), Some(1 | 3 | 9)) {
            present.insert(
                node["backendNodeId"]
                    .as_i64()
                    .ok_or(ObservationError::BackendFailure)?,
            );
        }
        // Do not descend through child contentDocument or pseudoElements. A
        // child document is independently fenced and inventoried in its group.
        for key in ["children", "shadowRoots"] {
            if let Some(children) = node.get(key) {
                let children = children
                    .as_array()
                    .ok_or(ObservationError::BackendFailure)?;
                if pending.len().saturating_add(children.len()) > 100_000 {
                    return Err(ObservationError::ResourceLimit);
                }
                pending.extend(children.iter().map(|child| (child, depth + 1)));
            }
        }
    }
    check(lease)?;
    Ok(present)
}

pub(crate) async fn validate_acquisition_binding(
    client: &CdpClient,
    frames: &[ObservationFrame],
    entry: &RefEntry,
    lease: &OperationLease,
) -> Result<(), ObservationError> {
    let binding = entry
        .exact_binding
        .clone()
        .ok_or(ObservationError::StaleReference)?;
    let backend = entry
        .backend_node_id
        .ok_or(ObservationError::StaleReference)?;
    validate_acquisition_bindings(client, frames, &[(binding, backend)], lease).await
}

/// Public semantic serialization is sparse; matching must still distinguish
/// explicit false states from missing values. This payload stays in the query
/// realm and is never returned as a public SemanticNode.
fn query_match_metadata(nodes: &[SemanticNode]) -> Result<Value, ObservationError> {
    let mut payload = serde_json::to_value(nodes).map_err(|_| ObservationError::BackendFailure)?;
    let rows = payload
        .as_array_mut()
        .ok_or(ObservationError::BackendFailure)?;
    for (row, node) in rows.iter_mut().zip(nodes) {
        row["states"] =
            serde_json::to_value(&node.states).map_err(|_| ObservationError::BackendFailure)?;
    }
    Ok(payload)
}

/// Shared DOM/AX/security acquisition with no reference allocator or registry.
/// Publication and live resolution consume the same complete projection result.
async fn evaluate_query(
    client: &CdpClient,
    frame: &ObservationFrame,
    expression: &LocatorExpression,
    options: &QueryOptions,
    lease: &OperationLease,
) -> Result<QueryEvaluation, ObservationError> {
    let session = &frame.binding.session;
    validate_frame(client, frame, lease).await?;
    let ax_value = command(
        client,
        session,
        "Accessibility.getFullAXTree",
        json!({"frameId":frame.binding.frame}),
        lease,
    )
    .await?;
    let tree: GetFullAXTreeResult =
        serde_json::from_value(ax_value).map_err(|_| ObservationError::BackendFailure)?;
    let ax_by_backend: HashMap<i64, &AXNode> = tree
        .nodes
        .iter()
        .filter_map(|n| n.backend_d_o_m_node_id.map(|b| (b, n)))
        .collect();
    // DOM.getDocument includes shadow roots. Query candidates are real elements,
    // including those omitted from the AX tree; semantic role comes from AX.
    let dom = frame_dom(client, frame, lease).await?;
    let ids = author_query_ids(&dom["root"])?;
    let mut nodes = Vec::new();
    let metadata_options = ObservationOptions {
        test_id_attribute: options.test_id_attribute.clone(),
        secure_field_selector: options.secure_field_selector.clone(),
        ..Default::default()
    };
    let security = security_inventory(client, frame, &metadata_options, lease).await?;
    let group = format!("native-query-{}", lease.sequence);
    let result=async {
        let ax_nodes:Vec<AXNode>=ids.iter().map(|backend|ax_by_backend.get(backend).map(|n|(*n).clone()).unwrap_or(AXNode{node_id:String::new(),role:None,name:None,value:None,description:None,properties:None,child_ids:None,backend_d_o_m_node_id:Some(*backend),ignored:None})).collect();
        for chunk in ax_nodes.chunks(64) {
            nodes.extend(read_batch_with_refs(client,frame,&chunk.iter().collect::<Vec<_>>(),None,0,&metadata_options,lease,false,&security).await?);
        }
        for (backend,node) in ids.iter().zip(&mut nodes){apply_security(node,*backend,&security);}
        let world=command(client,session,"Page.createIsolatedWorld",json!({"frameId":frame.binding.frame,"worldName":"agent-browser-native-observation"}),lease).await?;
        let context=world["executionContextId"].as_i64().ok_or("Missing query realm")?;
        use futures_util::{stream,StreamExt,TryStreamExt};
        let objects:Vec<String>=stream::iter(ids.iter().copied().map(|backend: i64| {
            let group=&group;
            async move {
                let value=command(client,session,"DOM.resolveNode",json!({"backendNodeId":backend,"executionContextId":context,"objectGroup":group}),lease).await?;
                value["object"]["objectId"].as_str().map(str::to_owned).ok_or(ObservationError::StaleReference)
            }
        })).buffered(16).try_collect().await?;
        if objects.is_empty() { return Ok(QueryEvaluation { projection_count: 0, matches: Vec::new() }); }
        let mut arguments=vec![json!({"value":expression}),json!({"value":query_match_metadata(&nodes)?}),json!({"value":nodes.iter().map(|n|&n.labels).collect::<Vec<_>>()}),json!({"value":nodes.iter().map(|n|&n.safe_public_name).collect::<Vec<_>>()}),json!({"value":options.secure_field_selector}),json!({"value":ids.iter().map(|id|security.ancestors.contains(id)).collect::<Vec<_>>()})];
        arguments.extend(objects.iter().map(|id|json!({"objectId":id})));
        let result=command(client,session,"Runtime.callFunctionOn",json!({"objectId":objects[0],"functionDeclaration":MATCH_QUERY,"arguments":arguments,"returnByValue":true}),lease).await?;
        if result.get("exceptionDetails").is_some(){return Err(ObservationError::BackendFailure);}
        let value=&result["result"]["value"];
        match value["error"].as_str(){Some("stale-reference")=>return Err(ObservationError::StaleReference),Some("invalid-arguments")=>return Err(ObservationError::InvalidArguments),Some("resource-limit")=>return Err(ObservationError::ResourceLimit),Some(_)=>return Err(ObservationError::BackendFailure),None=>{}}
        let indices:Vec<usize>=serde_json::from_value(value["indices"].clone()).map_err(|_|ObservationError::BackendFailure)?;
        let redacted:Vec<usize>=serde_json::from_value(value["redacted"].clone()).map_err(|_|ObservationError::BackendFailure)?;
        for index in redacted { let node=nodes.get_mut(index).ok_or(ObservationError::BackendFailure)?;scrub_ancestor_content(node); }
        let projection_count = indices.len();
        let matches = indices.into_iter().enumerate().map(|(projection_index, i)| {
            nodes.get(i).cloned().zip(ids.get(i).copied()).map(|(node, backend_node_id)| {
                QueryMatch { backend_node_id, node, projection_index }
            }).ok_or(ObservationError::BackendFailure)
        }).collect::<Result<Vec<_>, ObservationError>>()?;
        // The projection count/index is captured before this final public-read
        // visibility hold, matching the old surface's reads/candidates split.
        let matches = matches.into_iter().filter(|matched| {
            !projection_holds_visible(expression) || matched.node.states.get("hidden") != Some(&true)
        }).collect();
        Ok(QueryEvaluation { projection_count, matches })
    }.await;
    let result = settle_object_group(client, session, &group, result).await;
    let nodes = result?;
    validate_frame(client, frame, lease).await?;
    check(lease)?;
    Ok(nodes)
}

fn projection_holds_visible(expression: &LocatorExpression) -> bool {
    match expression {
        LocatorExpression::Query { query, .. } => query.visible == Some(true),
        LocatorExpression::Filter { source, .. } | LocatorExpression::Frame { source, .. } => {
            projection_holds_visible(source)
        }
        LocatorExpression::Index { source, .. } if query_uses_pinned_handles(source) => {
            projection_holds_visible(source)
        }
        _ => false,
    }
}

#[derive(Debug, Clone)]
struct PseudoOrigin {
    backend: i64,
    pseudo_type: String,
}
fn pseudo_origins(root: &Value) -> Result<HashMap<i64, PseudoOrigin>, ObservationError> {
    let mut result = HashMap::new();
    let mut pending = vec![(root, None, 0usize)];
    let mut visited = 0usize;
    while let Some((node, origin, depth)) = pending.pop() {
        visited += 1;
        if visited > 100_000 || depth > 256 {
            return Err(ObservationError::BackendFailure);
        }
        let backend = node["backendNodeId"].as_i64();
        let pseudo = node["pseudoType"].as_str();
        let current = if let Some(kind) = pseudo {
            let origin = origin.ok_or(ObservationError::BackendFailure)?;
            let backend = backend.ok_or(ObservationError::BackendFailure)?;
            if result
                .insert(
                    backend,
                    PseudoOrigin {
                        backend: origin,
                        pseudo_type: kind.into(),
                    },
                )
                .is_some()
            {
                return Err(ObservationError::BackendFailure);
            }
            Some(origin)
        } else if node["nodeType"] == 1 {
            backend
        } else {
            origin
        };
        for key in ["children", "shadowRoots", "pseudoElements"] {
            if let Some(children) = node[key].as_array() {
                pending.extend(children.iter().rev().map(|n| (n, current, depth + 1)));
            }
        }
    }
    Ok(result)
}
fn verified_pseudo_origin(
    remote: &Value,
    described: &Value,
    backend: i64,
    origins: &HashMap<i64, PseudoOrigin>,
) -> Result<i64, ObservationError> {
    if remote["className"] != "CSSPseudoElement" || remote["type"] != "object" {
        return Err(ObservationError::BackendFailure);
    }
    let origin = origins
        .get(&backend)
        .ok_or(ObservationError::StaleReference)?;
    let node = &described["node"];
    if node["backendNodeId"].as_i64() != Some(backend)
        || node["nodeType"] != 1
        || node["pseudoType"].as_str() != Some(origin.pseudo_type.as_str())
    {
        return Err(ObservationError::StaleReference);
    }
    Ok(origin.backend)
}
fn readonly_pseudo_metadata(data: &Value, ax: &AXNode) -> Value {
    if data.get("__nativeStatus").is_some() {
        return data.clone();
    }
    if !data.is_object()
        || !data["states"]["secure"].is_boolean()
        || !data["states"]["hidden"].is_boolean()
    {
        return json!({"__nativeStatus":"invalid-native-metadata"});
    }
    let protected = data["states"]["secure"] == true
        || data["secureDescendants"] == true
        || data["redactName"] == true;
    json!({"author":{"visible":true},"__nativeReadonlyPseudo":true,"redactName":protected,"secureDescendants":data["secureDescendants"],"labels":[],"attributes":{},"states":{"secure":data["states"]["secure"]==true,"hidden":data["states"]["hidden"]==true,"disabled":true},"text":if protected{None}else{ax_string(&ax.name)},"rect":null})
}

// A CSS pseudo keeps its own native identity, but metadata executes against
// its proven originating element. Acquisition policy must follow that receiver.
fn metadata_receiver_protection(
    nodes: &[&AXNode],
    origins: &[Option<i64>],
    policy: &SecurityInventory,
) -> Result<Vec<bool>, ObservationError> {
    if nodes.len() != origins.len() {
        return Err(ObservationError::BackendFailure);
    }
    nodes
        .iter()
        .zip(origins)
        .map(|(node, origin)| {
            let receiver = origin
                .or(node.backend_d_o_m_node_id)
                .ok_or(ObservationError::BackendFailure)?;
            Ok(policy.ancestors.contains(&receiver))
        })
        .collect()
}

// This is untrusted page semantics only, never identity or security authority.
// Omitting executionContextId selects the native node document's MAIN world:
// Blink core/inspector/resolve_node.cc ResolveNode, ToScriptStateForMainWorld.
const MAIN_ONCLICK_HINT: &str = "function() { return typeof this.onclick === 'function'; }";
const EXACT_HINT_RECEIVER: &str = "function() { const p=Node.prototype; return Object.getOwnPropertyDescriptor(p,'isConnected').get.call(this) === true && Object.getOwnPropertyDescriptor(p,'ownerDocument').get.call(this) === document; }";

async fn hint_boolean(
    client: &CdpClient,
    session: &str,
    object: &str,
    function: &str,
    group: &str,
    lease: &OperationLease,
) -> Result<bool, ObservationError> {
    let reply = command(
        client,
        session,
        "Runtime.callFunctionOn",
        json!({
            "objectId":object,"functionDeclaration":function,
            "throwOnSideEffect":true,"returnByValue":true,"objectGroup":group
        }),
        lease,
    )
    .await?;
    let mut result = if reply.get("exceptionDetails").is_some()
        || reply["result"]["type"] != "boolean"
        || reply["result"].get("objectId").is_some()
    {
        Err(ObservationError::BackendFailure)
    } else {
        reply["result"]["value"]
            .as_bool()
            .ok_or(ObservationError::BackendFailure)
    };
    // Unexpected object/exception handles need cleanup even on refused replies.
    let mut handles = std::collections::HashSet::new();
    for handle in [
        reply["result"]["objectId"].as_str(),
        reply["exceptionDetails"]["exception"]["objectId"].as_str(),
    ]
    .into_iter()
    .flatten()
    {
        if handle != object && handles.insert(handle) {
            result = settle_owner_object(client, session, handle, result).await;
        }
    }
    result
}

fn collect_hint_results<T>(
    results: Vec<Result<T, ObservationError>>,
) -> Result<Vec<T>, ObservationError> {
    let mut values = Vec::new();
    let mut primary = None;
    let mut cleanup_failed = false;
    for result in results {
        match result {
            Ok(value) => values.push(value),
            Err(ObservationError::CleanupFailed { primary: cause }) => {
                cleanup_failed = true;
                if primary.is_none() {
                    primary = cause.map(|error| *error);
                }
            }
            Err(error) => {
                if primary.is_none() {
                    primary = Some(error);
                }
            }
        }
    }
    if cleanup_failed {
        Err(ObservationError::CleanupFailed {
            primary: primary.map(Box::new),
        })
    } else if let Some(error) = primary {
        Err(error)
    } else {
        Ok(values)
    }
}

async fn main_onclick_hint(
    client: &CdpClient,
    frame: &ObservationFrame,
    backend: i64,
    isolated_object: &str,
    lease: &OperationLease,
) -> Result<bool, ObservationError> {
    // No group has been acquired yet: expired admissions need no cleanup.
    check(lease)?;
    let session = &frame.binding.session;
    let group = format!("native-onclick-{}-{backend}", lease.sequence);
    let result = async {
        validate_frame(client, frame, lease).await?;
        if !hint_boolean(
            client,
            session,
            isolated_object,
            EXACT_HINT_RECEIVER,
            &group,
            lease,
        )
        .await?
        {
            return Err(ObservationError::StaleReference);
        }
        let resolved = command(
            client,
            session,
            "DOM.resolveNode",
            json!({"backendNodeId":backend,"objectGroup":group}),
            lease,
        )
        .await?;
        if resolved["object"]["type"] != "object" || resolved["object"]["subtype"] != "node" {
            return Err(ObservationError::BackendFailure);
        }
        let object = resolved["object"]["objectId"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or(ObservationError::BackendFailure)?;
        let described = command(
            client,
            session,
            "DOM.describeNode",
            json!({"objectId":object,"depth":0}),
            lease,
        )
        .await?;
        if described["node"]["backendNodeId"].as_i64() != Some(backend)
            || described["node"]["nodeType"] != 1
        {
            return Err(ObservationError::StaleReference);
        }
        let hint = hint_boolean(client, session, object, MAIN_ONCLICK_HINT, &group, lease).await?;
        if !hint_boolean(
            client,
            session,
            isolated_object,
            EXACT_HINT_RECEIVER,
            &group,
            lease,
        )
        .await?
        {
            return Err(ObservationError::StaleReference);
        }
        validate_frame(client, frame, lease).await?;
        Ok(hint)
    }
    .await;
    #[cfg(test)]
    if result.is_err() {
        // Fixed diagnostic only: page exception descriptions/values are private.
        eprintln!("native observation onclick hint refused: side-effect-restricted exact receiver read unavailable");
    }
    settle_object_group(client, session, &group, result).await
}

#[allow(clippy::too_many_arguments)] // Same explicit ownership contract as the single-node reader.
async fn read_batch(
    client: &CdpClient,
    frame: &ObservationFrame,
    nodes: &[&AXNode],
    refs: &mut RefMap,
    revision: u64,
    options: &ObservationOptions,
    lease: &OperationLease,
    bounded: bool,
    acquisition_policy: &SecurityInventory,
) -> Result<Vec<SemanticNode>, ObservationError> {
    read_batch_with_refs(
        client,
        frame,
        nodes,
        Some(refs),
        revision,
        options,
        lease,
        bounded,
        acquisition_policy,
    )
    .await
}
#[allow(clippy::too_many_arguments)]
async fn read_batch_with_refs(
    client: &CdpClient,
    frame: &ObservationFrame,
    nodes: &[&AXNode],
    mut refs: Option<&mut RefMap>,
    revision: u64,
    options: &ObservationOptions,
    lease: &OperationLease,
    bounded: bool,
    acquisition_policy: &SecurityInventory,
) -> Result<Vec<SemanticNode>, ObservationError> {
    use futures_util::{stream, StreamExt, TryStreamExt};
    if nodes.is_empty() {
        return Ok(Vec::new());
    }
    let session = &frame.binding.session;
    let group = format!("native-metadata-{}", lease.sequence);
    let result=async {
        let world=command(client,session,"Page.createIsolatedWorld",json!({"frameId":frame.binding.frame,"worldName":"agent-browser-native-observation"}),lease).await?;
        let context=world["executionContextId"].as_i64().ok_or("Missing isolated realm")?;
        let backend_ids:Vec<Option<i64>>=nodes.iter().map(|ax|ax.backend_d_o_m_node_id).collect();
        let resolved:Vec<Value>=stream::iter(backend_ids.into_iter().map(|backend| {
            let group=&group;
            async move {
                command(client,session,"DOM.resolveNode",json!({"backendNodeId":backend,"executionContextId":context,"objectGroup":group}),lease).await
            }
        })).buffered(16).try_collect().await?;
        let has_pseudo=resolved.iter().any(|value|value["object"]["subtype"]!="node");
        let origins=if has_pseudo{pseudo_origins(&frame_dom(client,frame,lease).await?["root"])?}else{HashMap::new()};
        let mut objects=Vec::with_capacity(nodes.len());let mut pseudo=Vec::with_capacity(nodes.len());
        for (ax,value) in nodes.iter().zip(&resolved){
            let remote=&value["object"];
            if remote["subtype"]=="node" { objects.push(remote["objectId"].as_str().ok_or(ObservationError::StaleReference)?.to_owned());pseudo.push(None);continue; }
            let backend=ax.backend_d_o_m_node_id.ok_or(ObservationError::BackendFailure)?;
            let described=command(client,session,"DOM.describeNode",json!({"backendNodeId":backend,"depth":0}),lease).await?;
            #[cfg(test)]
            eprintln!("native non-node classification: cssPseudo={}, nativePseudo={}, markerRole={}",remote["className"]=="CSSPseudoElement",described["node"]["pseudoType"].is_string(),ax_string(&ax.role).as_deref()==Some("ListMarker"));
            let origin=verified_pseudo_origin(remote,&described,backend,&origins)?;
            let owner=command(client,session,"DOM.resolveNode",json!({"backendNodeId":origin,"executionContextId":context,"objectGroup":group}),lease).await?;
            if owner["object"]["subtype"]!="node"{return Err(ObservationError::StaleReference);}
            objects.push(owner["object"]["objectId"].as_str().ok_or(ObservationError::StaleReference)?.to_owned());pseudo.push(Some(origin));
        }
        let mut arguments=vec![json!({"value":options.test_id_attribute}),json!({"value":options.secure_field_selector})];
        arguments.extend(objects.iter().map(|o|json!({"objectId":o})));
        let protected_editors = metadata_receiver_protection(nodes, &pseudo, acquisition_policy)?;
        let protected_editors = serde_json::to_string(&protected_editors).map_err(|_| ObservationError::BackendFailure)?;
        let simple_name_inventory=acquisition_policy.simple_name_inventory;
        let function=format!("function(testId,secureSelector,...nodes) {{ const read={METADATA}; const protectedEditors={protected_editors}; return nodes.map((node,index)=>read.call(node,testId,secureSelector,{bounded},protectedEditors[index],{simple_name_inventory})); }}");
        let result=command(client,session,"Runtime.callFunctionOn",json!({"objectId":objects[0],"functionDeclaration":function,"arguments":arguments,"returnByValue":true}),lease).await?;
        if result.get("exceptionDetails").is_some(){
            #[cfg(test)]
            diagnostic_receivers(client,session,&objects,lease).await;
            return Err(ObservationError::BackendFailure);
        }
        let mut values=result["result"]["value"].as_array().ok_or("Missing metadata batch")?.clone();
        if values.len()!=nodes.len(){return Err("Incomplete metadata batch".into());}
        // Own the bounded descriptors before entering the async stream. Nested
        // borrowed filter/zip iterators are not sufficiently general for the
        // Send future required by the spawned operation dispatcher.
        let mut hint_candidates = Vec::new();
        for index in 0..nodes.len() {
            if pseudo[index].is_none() && values[index]["handlerProbe"] == true {
                let backend = nodes[index].backend_d_o_m_node_id.ok_or(ObservationError::BackendFailure)?;
                hint_candidates.push((index,backend,objects[index].clone()));
            }
        }
        let hints: Vec<Result<(usize,bool),ObservationError>> = stream::iter(hint_candidates.into_iter()
            .map(|(index,backend,object)| async move {
                Ok::<_,ObservationError>((index,main_onclick_hint(client,frame,backend,&object,lease).await?))
            })).buffered(16).collect().await;
        // Drain every started helper before propagating failure: dropping an
        // in-flight helper would skip its mandatory object-group cleanup.
        let hints = collect_hint_results(hints)?;
        for (index,hint) in hints { if hint { values[index]["author"]["action"]=json!(true); } }
        let policy=if has_pseudo{Some(security_inventory(client,frame,options,lease).await?)}else{None};
        if has_pseudo {
            let current=pseudo_origins(&frame_dom(client,frame,lease).await?["root"])?;
            for ((ax,remote),origin) in nodes.iter().zip(&resolved).zip(&pseudo) {
                if let Some(origin)=origin {
                    let backend=ax.backend_d_o_m_node_id.ok_or(ObservationError::BackendFailure)?;
                    let described=command(client,session,"DOM.describeNode",json!({"backendNodeId":backend,"depth":0}),lease).await?;
                    if verified_pseudo_origin(&remote["object"],&described,backend,&current)?!=*origin{return Err(ObservationError::StaleReference);}
                }
            }
        }
        // The originating element supplies security policy only. Identity stays
        // the native pseudo backend, never the origin's DOM reference.
        nodes.iter().zip(&values).zip(pseudo).map(|((ax,data),origin)|{
            let readonly=if origin.is_some(){readonly_pseudo_metadata(data,ax)}else{data.clone()};
            let mut node=match refs.as_deref_mut() {
                Some(refs)=>project_node(frame,ax.backend_d_o_m_node_id.unwrap(),ax,refs,revision,&readonly,bounded),
                None=>project_node_with_refs(frame,ax.backend_d_o_m_node_id.unwrap(),ax,None,revision,&readonly,bounded),
            }?;
            if let (Some(origin),Some(policy))=(origin,&policy){apply_security(&mut node,origin,policy);if node.states.get("secure")==Some(&true){scrub_content(&mut node);}}
            Ok(node)
        }).collect()
    }.await;
    let result = settle_object_group(client, session, &group, result).await;
    result
}

/// Failure-only test diagnostics. Only fixed booleans and bounded ordinals leave
/// the renderer; never print remote values, descriptions, identities, or text.
#[cfg(test)]
async fn diagnostic_receivers(
    client: &CdpClient,
    session: &str,
    objects: &[String],
    lease: &OperationLease,
) {
    let Some(first) = objects.first() else {
        return;
    };
    let result=command(client,session,"Runtime.callFunctionOn",json!({
        "objectId":first,"arguments":objects.iter().map(|id|json!({"objectId":id})).collect::<Vec<_>>(),"returnByValue":true,
        "functionDeclaration":r#"function(...nodes){return nodes.map(node=>{
          const descriptor=Object.getOwnPropertyDescriptor(Node.prototype,'isConnected');
          let getterOk=false,connected=false;
          try{connected=descriptor.get.call(node);getterOk=true;}catch{}
          return {isNode:node instanceof Node,isDocument:node===document,isGlobal:node===globalThis,isObject:typeof node==='object',hasGetter:typeof descriptor?.get==='function',getterOk,connected:connected===true};
        });}"#
    }),lease).await;
    if let Ok(value) = result {
        if let Some(rows) = value["result"]["value"].as_array() {
            for (index, row) in rows.iter().take(64).enumerate() {
                eprintln!("native metadata receiver index={index}: isNode={:?}, isDocument={:?}, isGlobal={:?}, isObject={:?}, hasGetter={:?}, getterOk={:?}, connected={:?}",row["isNode"].as_bool(),row["isDocument"].as_bool(),row["isGlobal"].as_bool(),row["isObject"].as_bool(),row["hasGetter"].as_bool(),row["getterOk"].as_bool(),row["connected"].as_bool());
            }
        }
    }
}

async fn frame_dom(
    client: &CdpClient,
    frame: &ObservationFrame,
    lease: &OperationLease,
) -> Result<Value, ObservationError> {
    let session = &frame.binding.session;
    let frame_tree = command(client, session, "Page.getFrameTree", json!({}), lease).await?;
    let dom =
        if frame_tree["frameTree"]["frame"]["id"].as_str() == Some(frame.binding.frame.as_str()) {
            command(
                client,
                session,
                "DOM.getDocument",
                json!({"depth":-1,"pierce":true}),
                lease,
            )
            .await?
        } else {
            let owner = command(
                client,
                session,
                "DOM.getFrameOwner",
                json!({"frameId":frame.binding.frame}),
                lease,
            )
            .await?;
            let owner = command(
                client,
                session,
                "DOM.describeNode",
                json!({"backendNodeId":owner["backendNodeId"],"depth":1,"pierce":true}),
                lease,
            )
            .await?;
            let backend = owner["node"]["contentDocument"]["backendNodeId"]
                .as_i64()
                .ok_or("Frame document is unavailable")?;
            let document = command(
                client,
                session,
                "DOM.describeNode",
                json!({"backendNodeId":backend,"depth":-1,"pierce":true}),
                lease,
            )
            .await?;
            json!({"root":document["node"]})
        };
    Ok(dom)
}
fn scrub_content(node: &mut SemanticNode) {
    node.name = None;
    node.text = None;
    node.value = None;
    node.selection = None;
    node.labels.clear();
    node.attributes.remove("value");
}
fn scrub_ancestor_content(node: &mut SemanticNode) {
    let public_name = node.safe_public_name.clone();
    scrub_content(node);
    node.name = public_name;
}
fn scrub_sensitive_ancestors(node: &mut SemanticNode) -> bool {
    let mut descendant = false;
    for child in &mut node.children {
        descendant |= scrub_sensitive_ancestors(child);
    }
    if descendant {
        scrub_ancestor_content(node);
    }
    descendant || node.states.get("secure") == Some(&true)
}

/// AX order is not an identity or topology guarantee. Build retained-node
/// adjacency first, then assemble bottom-up without recursion or repeated walks.
#[cfg(test)]
fn assemble_forest(
    order: &[AXNode],
    mut nodes: HashMap<String, SemanticNode>,
) -> Result<Vec<SemanticNode>, ObservationError> {
    let mut parents: HashMap<&str, &str> = HashMap::new();
    for ax in order {
        for child in ax.child_ids.as_deref().unwrap_or_default() {
            if parents.insert(child, &ax.node_id).is_some() {
                return Err("AX node has multiple parents".into());
            }
        }
    }
    let index: HashMap<&str, &AXNode> = order.iter().map(|n| (n.node_id.as_str(), n)).collect();
    let mut walk: Vec<&str> = order
        .iter()
        .filter(|n| !parents.contains_key(n.node_id.as_str()))
        .map(|n| n.node_id.as_str())
        .collect();
    walk.reverse();
    let mut rank = HashMap::new();
    while let Some(id) = walk.pop() {
        if rank.insert(id, rank.len()).is_some() {
            return Err("AX tree contains cycle".into());
        }
        if let Some(ax) = index.get(id) {
            for child in ax.child_ids.as_deref().unwrap_or_default().iter().rev() {
                walk.push(child);
            }
        }
    }
    let retained: std::collections::HashSet<String> = nodes.keys().cloned().collect();
    let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();
    let mut roots = Vec::new();
    let mut nearest: HashMap<String, Option<String>> = HashMap::new();
    for ax in order {
        if !retained.contains(&ax.node_id) {
            continue;
        }
        let mut trail = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut p = parents.get(ax.node_id.as_str()).copied();
        let parent = loop {
            match p {
                None => break None,
                Some(id) => {
                    if id == ax.node_id || !seen.insert(id) {
                        return Err("AX tree contains cycle".into());
                    }
                    if retained.contains(id) {
                        break Some(id.to_string());
                    }
                    if let Some(cached) = nearest.get(id) {
                        break cached.clone();
                    }
                    trail.push(id);
                    p = parents.get(id).copied();
                }
            }
        };
        for id in trail {
            nearest.insert(id.into(), parent.clone());
        }
        if let Some(parent) = parent {
            adjacency
                .entry(parent)
                .or_default()
                .push(ax.node_id.clone());
        } else {
            roots.push(ax.node_id.clone());
        }
    }
    for children in adjacency.values_mut() {
        children.sort_by_key(|id| rank.get(id.as_str()).copied().unwrap_or(usize::MAX));
    }
    roots.sort_by_key(|id| rank.get(id.as_str()).copied().unwrap_or(usize::MAX));
    let mut stack: Vec<(String, bool, usize)> = roots
        .iter()
        .rev()
        .map(|id| (id.clone(), false, 0))
        .collect();
    let mut done = HashMap::new();
    let mut visited = std::collections::HashSet::new();
    while let Some((id, exit, depth)) = stack.pop() {
        if depth > 512 {
            return Err("AX nesting limit exceeded".into());
        }
        if !exit {
            if !visited.insert(id.clone()) {
                return Err("AX tree contains cycle".into());
            }
            stack.push((id.clone(), true, depth));
            for child in adjacency.get(&id).into_iter().flatten().rev() {
                stack.push((child.clone(), false, depth + 1));
            }
        } else {
            let mut node = nodes.remove(&id).ok_or("Missing retained AX node")?;
            for child in adjacency.get(&id).into_iter().flatten() {
                node.children
                    .push(done.remove(child).ok_or("Invalid AX topology")?);
            }
            done.insert(id, node);
        }
    }
    if !nodes.is_empty() {
        return Err("AX tree has no reachable root".into());
    }
    roots
        .into_iter()
        .map(|id| done.remove(&id).ok_or_else(|| "Missing AX root".into()))
        .collect()
}

/// Enumerate only the executor's owned page and attached frame sessions. Missing
/// renderer ownership is an error, never permission to attach an arbitrary tab.
fn joined_frame_children(tree: &Value, parent: &str, owned: &HashMap<String, Value>) -> Vec<Value> {
    let mut children = tree["childFrames"].as_array().cloned().unwrap_or_default();
    // Renderer trees may omit remote roots. Join only native parentId edges
    // from independently owned renderer trees, never target IDs or URLs.
    let mut remote = owned
        .values()
        .filter(|root| {
            root["frame"]["parentId"].as_str() == Some(parent)
                && !children
                    .iter()
                    .any(|child| child["frame"]["id"] == root["frame"]["id"])
        })
        .cloned()
        .collect::<Vec<_>>();
    remote.sort_by(|a, b| a["frame"]["id"].as_str().cmp(&b["frame"]["id"].as_str()));
    children.extend(remote);
    children
}
pub async fn enumerate_frames(
    client: &CdpClient,
    page_session: &str,
    iframe_sessions: &HashMap<String, String>,
    lease: &OperationLease,
) -> Result<Vec<ObservationFrame>, ObservationError> {
    if iframe_sessions.len() > 256 {
        return Err(ObservationError::InvalidArguments);
    }
    let mut owned_trees = HashMap::new();
    for (frame, session) in iframe_sessions {
        let tree = command(client, session, "Page.getFrameTree", json!({}), lease).await?;
        if tree["frameTree"]["frame"]["id"].as_str() != Some(frame.as_str()) {
            return Err(ObservationError::StaleReference);
        }
        owned_trees.insert(frame.clone(), tree["frameTree"].clone());
    }
    let tree = command(client, page_session, "Page.getFrameTree", json!({}), lease).await?;
    let mut queue = std::collections::VecDeque::from([(tree["frameTree"].clone(), None::<usize>)]);
    let mut frames: Vec<ObservationFrame> = Vec::new();
    let mut visited = std::collections::HashSet::new();
    while let Some((mut tree, parent)) = queue.pop_front() {
        let id = tree["frame"]["id"]
            .as_str()
            .ok_or(ObservationError::StaleReference)?
            .to_owned();
        if !visited.insert(id.clone()) {
            return Err(ObservationError::StaleReference);
        }
        if let Some(owned) = owned_trees.remove(&id) {
            if let Some(loader) = tree["frame"]["loaderId"].as_str().filter(|v| !v.is_empty()) {
                if owned["frame"]["loaderId"].as_str() != Some(loader) {
                    return Err(ObservationError::StaleReference);
                }
            }
            tree = owned;
        }
        if let Some(declared) = tree["frame"]["parentId"].as_str() {
            if parent.map(|index| frames[index].binding.frame.as_str()) != Some(declared) {
                return Err(ObservationError::StaleReference);
            }
        }
        if frames.len() >= 256 {
            return Err("Frame limit exceeded".into());
        }
        let frame = &tree["frame"];
        let id = frame["id"]
            .as_str()
            .ok_or("Frame identity unavailable")?
            .to_string();
        let loader = frame["loaderId"]
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or("Frame document identity unavailable")?
            .to_string();
        let session = iframe_sessions.get(&id).cloned().unwrap_or_else(|| {
            parent
                .map(|index| frames[index].binding.session.clone())
                .unwrap_or_else(|| page_session.into())
        });
        // Prove this session owns the document before issuing any metadata read.
        command(
            client,
            &session,
            "Page.createIsolatedWorld",
            json!({"frameId":id,"worldName":"agent-browser-native-observation"}),
            lease,
        )
        .await?;
        let mut descriptor = ObservationFrame {
            binding: ExactBinding {
                page_session: page_session.into(),
                session,
                frame: id.clone(),
                loader,
                actionable: false,
            },
            offset_x: 0.0,
            offset_y: 0.0,
            frame_path: Vec::new(),
            parent_frame_id: None,
            owner_backend_id: None,
            url: frame["url"].as_str().unwrap_or("").into(),
        };
        if let Some(parent) = parent {
            let parent = &frames[parent];
            let owner = command(
                client,
                &parent.binding.session,
                "DOM.getFrameOwner",
                json!({"frameId":id}),
                lease,
            )
            .await?;
            let backend = owner["backendNodeId"]
                .as_i64()
                .ok_or("Frame owner identity unavailable")?;
            let world=command(client,&parent.binding.session,"Page.createIsolatedWorld",json!({"frameId":parent.binding.frame,"worldName":"agent-browser-native-observation"}),lease).await?;
            let resolved=command(client,&parent.binding.session,"DOM.resolveNode",json!({"backendNodeId":backend,"executionContextId":world["executionContextId"],"objectGroup":"native-frame-enumeration"}),lease).await?;
            let object = resolved["object"]["objectId"]
                .as_str()
                .ok_or("Frame owner unavailable")?;
            let value=command(client,&parent.binding.session,"Runtime.callFunctionOn",json!({"objectId":object,"functionDeclaration":r#"function(){
                if(this.ownerDocument!==document||!this.isConnected)throw new Error('Frame owner moved');
                const r=this.getBoundingClientRect();let e=this,parts=[];
                while(e&&e.nodeType===1){if(e.id){parts.unshift('#'+CSS.escape(e.id));break;}let p=e.parentElement;let index=p?Array.from(p.children).indexOf(e)+1:1;parts.unshift(e.localName+':nth-child('+index+')');e=p;}
                return {x:r.x+this.clientLeft,y:r.y+this.clientTop,selector:parts.join(' > ')};
            }"#,"returnByValue":true}),lease).await;
            let value = value.and_then(|value| {
                if value.get("exceptionDetails").is_some() {
                    Err(ObservationError::StaleReference)
                } else {
                    Ok(value)
                }
            });
            let value = settle_owner_object(client, &parent.binding.session, object, value).await?;
            let data = &value["result"]["value"];
            descriptor.offset_x =
                parent.offset_x + data["x"].as_f64().ok_or("Frame offset unavailable")?;
            descriptor.offset_y =
                parent.offset_y + data["y"].as_f64().ok_or("Frame offset unavailable")?;
            descriptor.frame_path = parent.frame_path.clone();
            descriptor.frame_path.push(
                data["selector"]
                    .as_str()
                    .ok_or("Frame selector unavailable")?
                    .into(),
            );
            descriptor.parent_frame_id = Some(parent.binding.frame.clone());
            descriptor.owner_backend_id = Some(backend);
        }
        let index = frames.len();
        frames.push(descriptor);
        for child in joined_frame_children(&tree, &id, &owned_trees) {
            queue.push_back((child, Some(index)));
        }
    }
    if !owned_trees.is_empty() {
        #[cfg(test)]
        eprintln!(
            "native frame inventory: unreachable owned roots={}, roots with native parent={}",
            owned_trees.len(),
            owned_trees
                .values()
                .filter(|v| v["frame"]["parentId"].is_string())
                .count()
        );
        return Err(ObservationError::StaleReference);
    }
    for frame in &frames {
        validate_frame(client, frame, lease).await?;
    }
    Ok(frames)
}

fn validate_expression(
    expression: &LocatorExpression,
    depth: usize,
) -> Result<(), ObservationError> {
    if depth > 64 {
        return Err(ObservationError::InvalidArguments);
    }
    match expression {
        LocatorExpression::Query { query, scope } => {
            if matches!(query.kind, QueryKind::Role)
                && !matches!(query.value, TextPattern::String { .. })
            {
                return Err(ObservationError::InvalidArguments);
            }
            if let Some(scope) = scope {
                validate_expression(scope, depth + 1)?;
            }
        }
        LocatorExpression::Filter { source, has, .. } => {
            validate_expression(source, depth + 1)?;
            if let Some(has) = has {
                validate_expression(has, depth + 1)?;
            }
        }
        LocatorExpression::Index { source, .. } | LocatorExpression::Frame { source, .. } => {
            validate_expression(source, depth + 1)?
        }
        LocatorExpression::Selector { selector } => {
            if selector.is_empty() {
                return Err(ObservationError::InvalidArguments);
            }
        }
    }
    Ok(())
}
fn split_frame_expression(
    expression: &LocatorExpression,
) -> Result<(Vec<String>, LocatorExpression), ObservationError> {
    match expression {
        LocatorExpression::Frame { selector, source } => {
            let (mut path, expr) = split_frame_expression(source)?;
            path.insert(0, selector.clone());
            Ok((path, expr))
        }
        LocatorExpression::Index { source, index } => {
            let (path, expr) = split_frame_expression(source)?;
            Ok((
                path,
                LocatorExpression::Index {
                    source: Box::new(expr),
                    index: index.clone(),
                },
            ))
        }
        LocatorExpression::Filter {
            source,
            has_text,
            has,
        } => {
            if let Some(has) = has {
                if !split_frame_expression(has)?.0.is_empty() {
                    return Err(ObservationError::InvalidArguments);
                }
            }
            let (path, expr) = split_frame_expression(source)?;
            Ok((
                path,
                LocatorExpression::Filter {
                    source: Box::new(expr),
                    has_text: has_text.clone(),
                    has: has.clone(),
                },
            ))
        }
        LocatorExpression::Query {
            query,
            scope: Some(scope),
        } => {
            let (path, expr) = split_frame_expression(scope)?;
            Ok((
                path,
                LocatorExpression::Query {
                    query: query.clone(),
                    scope: Some(Box::new(expr)),
                },
            ))
        }
        _ => Ok((Vec::new(), expression.clone())),
    }
}
enum FrameSelectionError {
    Cardinality,
    Observation(ObservationError),
}
impl From<ObservationError> for FrameSelectionError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

async fn select_frame<'a>(
    client: &CdpClient,
    frames: &'a [ObservationFrame],
    parent: &ObservationFrame,
    selector: &str,
    options: &QueryOptions,
    lease: &OperationLease,
) -> Result<&'a ObservationFrame, FrameSelectionError> {
    // Count all matches in the parent DOM before consulting the owned frame
    // inventory. A matching non-frame or pending/unowned iframe must not vanish
    // and turn an ambiguous selector into apparent uniqueness.
    let expression = LocatorExpression::Selector {
        selector: selector.strip_prefix("css=").unwrap_or(selector).into(),
    };
    let evaluated = evaluate_query(client, parent, &expression, options, lease).await?;
    if evaluated.projection_count != 1 || evaluated.matches.len() != 1 {
        return Err(FrameSelectionError::Cardinality);
    }
    let backend = evaluated.matches[0].backend_node_id;
    let mut children = frames.iter().filter(|child| {
        child.parent_frame_id.as_deref() == Some(parent.binding.frame.as_str())
            && child.owner_backend_id == Some(backend)
            && child.binding.page_session == parent.binding.page_session
    });
    let child = children.next().ok_or(ObservationError::StaleReference)?;
    if children.next().is_some() {
        return Err(ObservationError::StaleReference.into());
    }
    validate_frame_ancestry(client, frames, child, lease).await?;
    Ok(child)
}

#[derive(Default)]
struct SecurityInventory {
    browser_internal: std::collections::HashSet<i64>,
    ancestors: std::collections::HashSet<i64>,
    label_ids: std::collections::HashSet<String>,
    // Conservative: simple-name completion is declined for an entire frame
    // containing any author shadow root, even when this receiver is unrelated.
    simple_name_inventory: bool,
}
/// Browser implementation shadow trees are not author controls. Keep their
/// native identities out of the author observation without rebinding them to
/// the host. Open and closed author roots remain independently observable.
fn browser_internal_ids(root: &Value) -> Result<std::collections::HashSet<i64>, ObservationError> {
    let mut result = std::collections::HashSet::new();
    let mut pending = vec![(root, false, 0usize)];
    let mut visited = 0usize;
    while let Some((node, internal, depth)) = pending.pop() {
        visited += 1;
        if visited > 100_000 || depth > 256 {
            return Err(ObservationError::ResourceLimit);
        }
        let internal = internal || node["shadowRootType"] == "user-agent";
        if internal {
            result.insert(
                node["backendNodeId"]
                    .as_i64()
                    .ok_or(ObservationError::BackendFailure)?,
            );
        }
        for key in ["children", "shadowRoots", "pseudoElements"] {
            if let Some(children) = node[key].as_array() {
                if pending.len().saturating_add(children.len()) > 100_000 {
                    return Err(ObservationError::ResourceLimit);
                }
                pending.extend(children.iter().map(|child| (child, internal, depth + 1)));
            }
        }
    }
    Ok(result)
}
fn author_query_ids(root: &Value) -> Result<Vec<i64>, ObservationError> {
    let internal = browser_internal_ids(root)?;
    Ok(bounded_dom_ids(root, &[1], 100_000)?
        .into_iter()
        .filter(|id| !internal.contains(id))
        .collect())
}
fn apply_security(node: &mut SemanticNode, backend: i64, security: &SecurityInventory) {
    let labelled = node.attributes.get("aria-labelledby").is_some_and(|ids| {
        ids.split_whitespace()
            .any(|id| security.label_ids.contains(id))
    });
    // Secure nodes already have their content projected safely. Retain their
    // public labels so a password control remains discoverable by label.
    let sensitive_ancestor =
        security.ancestors.contains(&backend) && node.states.get("secure") != Some(&true);
    if sensitive_ancestor || labelled {
        scrub_ancestor_content(node);
    }
}
/// Bounded, iterative traversal avoids native stack exhaustion on hostile DOMs.
fn security_root_ids(root: &Value) -> Result<Vec<i64>, ObservationError> {
    let ids = bounded_dom_ids(root, &[9, 11], 10_000)?;
    if ids.is_empty() {
        return Err(ObservationError::BackendFailure);
    }
    Ok(ids)
}
fn bounded_dom_ids(
    root: &Value,
    node_types: &[i64],
    limit: usize,
) -> Result<Vec<i64>, ObservationError> {
    let mut pending = vec![(root, 0usize)];
    let mut roots = Vec::new();
    let mut visited = 0usize;
    while let Some((node, depth)) = pending.pop() {
        visited += 1;
        if depth > 256 || visited > 100_000 {
            return Err(ObservationError::BackendFailure);
        }
        // CSS pseudo trees are not DOM locator candidates. Their read-only AX
        // identities are projected separately and never fed to MATCH_QUERY.
        if node.get("pseudoType").is_some() {
            continue;
        }
        if node["nodeType"]
            .as_i64()
            .is_some_and(|kind| node_types.contains(&kind))
        {
            roots.push(
                node["backendNodeId"]
                    .as_i64()
                    .ok_or(ObservationError::BackendFailure)?,
            );
            if roots.len() > limit {
                return Err(ObservationError::BackendFailure);
            }
        }
        for key in ["children", "shadowRoots"] {
            if let Some(children) = node[key].as_array() {
                if pending.len().saturating_add(children.len()) > 100_000 {
                    return Err(ObservationError::BackendFailure);
                }
                pending.extend(children.iter().rev().map(|child| (child, depth + 1)));
            }
        }
    }
    Ok(roots)
}
/// Enumerate native shadow-root handles, not every element. CSS matching stays
/// in Chromium, including closed roots supplied by DOM.getDocument(pierce).
/// Only sensitive ancestors' identities are returned; no field values are read.
fn simple_name_inventory(
    root: &Value,
    roots: &[i64],
    internal: &std::collections::HashSet<i64>,
) -> bool {
    root["nodeType"] == 9 && roots.iter().filter(|id| !internal.contains(id)).count() == 1
}

async fn security_inventory(
    client: &CdpClient,
    frame: &ObservationFrame,
    options: &ObservationOptions,
    lease: &OperationLease,
) -> Result<SecurityInventory, ObservationError> {
    use futures_util::{stream, StreamExt, TryStreamExt};
    let dom = frame_dom(client, frame, lease).await?;
    let ids = security_root_ids(&dom["root"])?;
    let browser_internal = browser_internal_ids(&dom["root"])?;
    let simple_name_inventory = simple_name_inventory(&dom["root"], &ids, &browser_internal);
    let session = &frame.binding.session;
    let group = format!("native-security-{}", lease.sequence);
    let result=async{
        let world=command(client,session,"Page.createIsolatedWorld",json!({"frameId":frame.binding.frame,"worldName":"agent-browser-native-observation"}),lease).await?;
        let context=world["executionContextId"].as_i64().ok_or(ObservationError::BackendFailure)?;
        let objects:Vec<String>=stream::iter(ids.into_iter().map(|backend|{let group=&group;async move{
            let object=command(client,session,"DOM.resolveNode",json!({"backendNodeId":backend,"executionContextId":context,"objectGroup":group}),lease).await?;
            object["object"]["objectId"].as_str().map(str::to_owned).ok_or(ObservationError::BackendFailure)
        }})).buffered(16).try_collect().await?;
        let mut args=vec![json!({"value":options.secure_field_selector})];args.extend(objects.iter().map(|o|json!({"objectId":o})));
        let result=command(client,session,"Runtime.callFunctionOn",json!({"objectId":objects[0],"arguments":args,"objectGroup":group,"functionDeclaration":r#"function(selector,...roots){
            const result=new Set();const all='input[type="password" i],'+selector;
            for(const root of roots){if(root!==document&&root.ownerDocument!==document)throw new Error('stale root');
                for(const secure of root.querySelectorAll(all)){const seen=new Set();for(let p=secure;p&&!seen.has(p);p=p.parentElement||(p.getRootNode&&p.getRootNode().host)){seen.add(p);result.add(p);}}
            }return Array.from(result);
        }"#,"returnByValue":false}),lease).await?;
        if result.get("exceptionDetails").is_some(){return Err(ObservationError::BackendFailure);}
        let array=result["result"]["objectId"].as_str().ok_or(ObservationError::BackendFailure)?;
        let properties=command(client,session,"Runtime.getProperties",json!({"objectId":array,"ownProperties":true}),lease).await?;
        let handles:Vec<String>=properties["result"].as_array().ok_or(ObservationError::BackendFailure)?.iter().filter(|p|p["name"].as_str().is_some_and(|s|s.parse::<usize>().is_ok())).map(|p|p["value"]["objectId"].as_str().map(str::to_owned).ok_or(ObservationError::BackendFailure)).collect::<Result<_,_>>()?;
        let descriptions:Vec<Value>=stream::iter(handles.into_iter().map(|object|async move{command(client,session,"DOM.describeNode",json!({"objectId":object}),lease).await})).buffered(16).try_collect().await?;
        let mut security=SecurityInventory { browser_internal, simple_name_inventory, ..Default::default() };
        for description in descriptions{
            let node=&description["node"];security.ancestors.insert(node["backendNodeId"].as_i64().ok_or(ObservationError::BackendFailure)?);
            if let Some(attributes)=node["attributes"].as_array(){for pair in attributes.as_chunks::<2>().0{if pair[0]=="id"{if let Some(id)=pair[1].as_str(){security.label_ids.insert(id.to_string());}}}}
        }
        Ok(security)
    }.await;
    let result = settle_object_group(client, session, &group, result).await;
    result
}

/// Project staged semantic rectangles through the same native proof used by
/// protected pixels. Callers must revalidate the proof before publication. This
/// does not allocate, resolve selectors, or turn read-only AX identities into DOM.
pub async fn project_geometry(
    client: &CdpClient,
    frames: &[ObservationFrame],
    refs: &RefMap,
    geometry: &super::client_geometry::GeometrySnapshot,
    nodes: &mut [SemanticNode],
    lease: &OperationLease,
) -> Result<(), super::client_geometry::GeometryError> {
    use super::client_geometry::GeometryError;
    use futures_util::{stream, StreamExt, TryStreamExt};
    let mut pending = nodes.iter().map(|node| (node, 0usize)).collect::<Vec<_>>();
    let mut requests = Vec::new();
    let mut visited = 0usize;
    while let Some((node, depth)) = pending.pop() {
        visited += 1;
        if visited > 100_000 || depth > 256 {
            return Err(GeometryError::InvalidGeometry);
        }
        pending.extend(node.children.iter().map(|child| (child, depth + 1)));
        if node.rect.is_none() {
            continue;
        }
        let id =
            super::element::parse_ref(&node.reference.id).ok_or(GeometryError::StaleIdentity)?;
        let entry = refs.get(&id).ok_or(GeometryError::StaleIdentity)?;
        if entry.kind != super::element::NativeReferenceKind::Dom {
            return Err(GeometryError::InvalidGeometry);
        }
        let binding = entry
            .exact_binding
            .as_ref()
            .ok_or(GeometryError::StaleIdentity)?;
        let frame = frames
            .iter()
            .find(|frame| {
                frame.binding.page_session == binding.page_session
                    && frame.binding.session == binding.session
                    && frame.binding.frame == binding.frame
                    && frame.binding.loader == binding.loader
            })
            .ok_or(GeometryError::StaleIdentity)?
            .clone();
        requests.push((
            node.reference.id.clone(),
            frame,
            entry.backend_node_id.ok_or(GeometryError::StaleIdentity)?,
        ));
    }
    let rectangles: HashMap<String, Rect> =
        stream::iter(requests.into_iter().map(|(id, frame, backend)| async move {
            let b = geometry
                .node_semantic_bounds(client, &frame, backend, lease)
                .await?
                .bounds();
            Ok::<_, GeometryError>((
                id,
                Rect {
                    x: b.x,
                    y: b.y,
                    width: b.width,
                    height: b.height,
                },
            ))
        }))
        .buffered(16)
        .try_collect()
        .await?;
    fn apply(nodes: &mut [SemanticNode], rectangles: &HashMap<String, Rect>) {
        for node in nodes {
            if let Some(rect) = rectangles.get(&node.reference.id) {
                node.rect = Some(rect.clone());
            }
            apply(&mut node.children, rectangles);
        }
    }
    apply(nodes, &rectangles);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_query_payload_preserves_false_states_independent_of_public_projection() {
        let states = [
            "disabled", "focused", "hidden", "secure", "checked", "selected", "expanded", "pressed",
        ]
        .into_iter()
        .map(|state| (state.to_owned(), false))
        .collect::<BTreeMap<_, _>>();
        let node = SemanticNode {
            states: states.clone(),
            ..Default::default()
        };
        let payload = query_match_metadata(&[node]).unwrap();
        assert_eq!(payload[0]["states"], serde_json::to_value(states).unwrap());
    }

    #[test]
    fn author_observation_excludes_only_browser_owned_shadow_identities() {
        let dom = json!({"nodeType":9,"backendNodeId":1,"children":[
            {"nodeType":1,"backendNodeId":2,"shadowRoots":[
                {"shadowRootType":"user-agent","backendNodeId":3,"children":[
                    {"nodeType":1,"backendNodeId":4,"pseudoElements":[{"backendNodeId":5}]}]}]},
            {"nodeType":1,"backendNodeId":6,"shadowRoots":[
                {"shadowRootType":"closed","backendNodeId":7,"children":[{"nodeType":1,"backendNodeId":8}]}]},
            {"nodeType":1,"backendNodeId":9,"pseudoElements":[{"backendNodeId":10,"pseudoType":"marker"}]}
        ]});
        assert_eq!(
            browser_internal_ids(&dom).unwrap(),
            std::collections::HashSet::from([3, 4, 5])
        );
        assert!(browser_internal_ids(&json!({"shadowRootType":"user-agent"})).is_err());
        assert_eq!(author_query_ids(&dom).unwrap(), vec![2, 6, 8, 9]);
    }
    #[test]
    fn native_control_roles_use_the_public_vocabulary_without_rebinding() {
        for (native, public) in [
            ("Date", "textbox"),
            ("DateTime", "textbox"),
            ("InputTime", "textbox"),
            ("ColorWell", "textbox"),
            ("Iframe", "iframe"),
        ] {
            let mut ax = ax("control", 42, &[]);
            ax.role.as_mut().unwrap().value = Some(json!(native));
            let mut refs = observed_refs();
            let node = project_node(&frame(), 42, &ax, &mut refs, 1, &metadata(), true).unwrap();
            assert_eq!(node.role.as_deref(), Some(public));
            assert_eq!(
                refs.get(node.reference.id.trim_start_matches('@'))
                    .unwrap()
                    .backend_node_id,
                Some(42)
            );
        }
    }
    #[test]
    fn implicit_landmarks_obey_author_section_scope_without_changing_explicit_roles() {
        for (tag, native) in [("header", "banner"), ("footer", "contentinfo")] {
            let mut node = ax("landmark", 42, &[]);
            node.role.as_mut().unwrap().value = Some(json!(native));
            let mut data = metadata();
            data["author"]["tag"] = json!(tag);
            data["pageLevelLandmark"] = json!(false);
            let projected =
                project_node(&frame(), 42, &node, &mut observed_refs(), 1, &data, true).unwrap();
            assert_eq!(projected.role, None);
            data["attributes"]["role"] = json!(native);
            assert_eq!(
                project_node(&frame(), 42, &node, &mut observed_refs(), 1, &data, true)
                    .unwrap()
                    .role
                    .as_deref(),
                Some(native)
            );
            data["attributes"] = json!({});
            data["pageLevelLandmark"] = json!(true);
            assert_eq!(
                project_node(&frame(), 42, &node, &mut observed_refs(), 1, &data, true)
                    .unwrap()
                    .role
                    .as_deref(),
                Some(native)
            );
        }
    }

    #[test]
    fn simple_name_inventory_declines_author_shadow_but_not_browser_internals() {
        for (kind, expected) in [("open", false), ("closed", false), ("user-agent", true)] {
            let root = json!({"nodeType":9,"backendNodeId":1,"children":[{"nodeType":1,"backendNodeId":2,"shadowRoots":[{"nodeType":11,"backendNodeId":3,"shadowRootType":kind}]}]});
            assert_eq!(
                simple_name_inventory(
                    &root,
                    &security_root_ids(&root).unwrap(),
                    &browser_internal_ids(&root).unwrap()
                ),
                expected
            );
        }
        assert!(!simple_name_inventory(
            &json!({}),
            &[1],
            &Default::default()
        ));
    }

    #[test]
    fn complete_empty_reference_clears_ax_without_title_or_label_fallback() {
        let native = ax("reference", 42, &[]);
        let mut data = metadata();
        data["completeEmptyReference"] = json!(true);
        data["attributes"]["title"] = json!("Must not restore");
        data["simpleAssociatedName"] = json!("Must not restore");
        let project = |data: &Value| {
            project_node(&frame(), 42, &native, &mut observed_refs(), 1, data, false)
                .unwrap()
                .name
        };
        assert_eq!(project(&data), None);
        data["redactName"] = json!(true);
        assert_eq!(project(&data), None);
        data["redactName"] = json!(false);
        data["completeEmptyReference"] = json!(false);
        assert_eq!(project(&data).as_deref(), Some("Save"));
    }

    #[test]
    fn complete_associated_label_only_fills_missing_unprotected_ax_name() {
        let mut native = ax("control", 42, &[]);
        native.name = None;
        let mut data = metadata();
        data["simpleAssociatedName"] = json!("Name");
        let project = |native: &AXNode, data: &Value| {
            project_node(&frame(), 42, native, &mut observed_refs(), 1, data, false)
                .unwrap()
                .name
        };
        assert_eq!(project(&native, &data).as_deref(), Some("Name"));
        for attribute in ["aria-label", "aria-labelledby"] {
            data["attributes"][attribute] = json!("Higher priority");
            assert_eq!(project(&native, &data), None);
            data["attributes"] = json!({});
        }
        for flag in ["redactName", "secureDescendants"] {
            data[flag] = json!(true);
            assert_eq!(project(&native, &data), None);
            data[flag] = json!(false);
        }
        native.name = ax("named", 42, &[]).name;
        assert_eq!(project(&native, &data).as_deref(), Some("Save"));
    }

    #[test]
    fn complete_button_names_correct_ax_and_distinguish_empty_from_unavailable() {
        for bounded in [false, true] {
            for (ax_name, complete, expected) in [
                ("Save ", Some("Save draft"), Some("Save draft")),
                ("", Some("Child tooltip"), Some("Child tooltip")),
                ("AX fallback", Some(""), None),
                ("AX fallback", None, Some("AX fallback")),
            ] {
                let mut native = ax("button", 42, &[]);
                native.name.as_mut().unwrap().value = Some(json!(ax_name));
                let mut data = metadata();
                data["completeButtonContentName"] = json!(complete);
                data["attributes"]["title"] = json!("Must not restore");
                data["simpleAssociatedName"] = json!("Must not restore");
                let node = project_node(
                    &frame(),
                    42,
                    &native,
                    &mut observed_refs(),
                    1,
                    &data,
                    bounded,
                )
                .unwrap();
                assert_eq!(node.name.as_deref(), expected);
            }
        }
        for invalid in [json!(true), json!({}), json!("x".repeat(513))] {
            let mut data = metadata();
            data["completeButtonContentName"] = invalid;
            assert_eq!(
                project_node(
                    &frame(),
                    42,
                    &ax("button", 42, &[]),
                    &mut observed_refs(),
                    1,
                    &data,
                    true
                )
                .unwrap_err(),
                ObservationError::BackendFailure
            );
        }
    }

    #[test]
    fn complete_button_names_preserve_role_priority_and_security_selection() {
        let native = ax("button", 42, &[]);
        let mut data = metadata();
        data["completeButtonContentName"] = json!("Proof name");
        let project = |native: &AXNode, data: &Value| {
            project_node(&frame(), 42, native, &mut observed_refs(), 1, data, false)
                .unwrap()
                .name
        };
        assert_eq!(project(&native, &data).as_deref(), Some("Proof name"));
        for attr in ["aria-label", "aria-labelledby"] {
            data["attributes"][attr] = json!("");
            assert_eq!(project(&native, &data).as_deref(), Some("Save"));
            data["attributes"] = json!({});
        }
        for role in ["link", "none", "unknown button"] {
            data["attributes"]["role"] = json!(role);
            assert_eq!(project(&native, &data).as_deref(), Some("Save"));
        }
        data["attributes"] = json!({});
        for role in ["link", "none", "generic"] {
            let mut other = native.clone();
            other.role.as_mut().unwrap().value = Some(json!(role));
            assert_eq!(project(&other, &data).as_deref(), Some("Save"));
        }
        data["author"]["tag"] = json!("div");
        assert_eq!(project(&native, &data).as_deref(), Some("Save"));
        data["author"]["tag"] = json!("button");
        data["__nativeReadonlyPseudo"] = json!(true);
        assert_eq!(project(&native, &data).as_deref(), Some("Save"));
        data["__nativeReadonlyPseudo"] = json!(false);
        data["states"]["secure"] = json!(true);
        assert_eq!(project(&native, &data).as_deref(), Some("Save"));
        data["states"]["secure"] = json!(false);
        for flag in ["secureDescendants", "redactName", "completeEmptyReference"] {
            data[flag] = json!(true);
            assert_eq!(project(&native, &data), None);
            data[flag] = json!(false);
        }
        data["safePublicName"] = json!("Safe public name");
        assert_eq!(project(&native, &data).as_deref(), Some("Safe public name"));
    }

    #[test]
    fn inherited_ax_disabled_is_projected_without_overriding_native_disabled() {
        let mut ax = ax("control", 42, &[]);
        ax.properties = serde_json::from_value(
            json!([{"name":"disabled","value":{"type":"boolean","value":true}}]),
        )
        .unwrap();
        let node = project_node(
            &frame(),
            42,
            &ax,
            &mut observed_refs(),
            1,
            &metadata(),
            true,
        )
        .unwrap();
        assert_eq!(node.states.get("disabled"), Some(&true));
        ax.properties = serde_json::from_value(
            json!([{"name":"disabled","value":{"type":"boolean","value":false}}]),
        )
        .unwrap();
        let mut data = metadata();
        data["states"]["disabled"] = json!(true);
        let node = project_node(&frame(), 42, &ax, &mut observed_refs(), 1, &data, true).unwrap();
        assert_eq!(node.states.get("disabled"), Some(&true));
    }
    #[test]
    fn observation_publication_retains_only_emitted_additions_without_resurrection() {
        let mut baseline = observed_refs();
        baseline.set_exact_limit_for_test(4);
        let old = baseline.bind_exact(1, "button", "", frame().binding);
        let located = baseline
            .try_bind_located(
                1,
                "button",
                frame().binding,
                LocatedIssuance {
                    identity_scope: "scope".into(),
                    generation: 1,
                    revision: 1,
                },
                None,
            )
            .unwrap();
        let mut staged = baseline.clone();
        staged.begin_observation("scope", 1, 2);
        assert_eq!(staged.bind_exact(1, "button", "", frame().binding), old);
        let omitted = staged.bind_exact(2, "text", "", frame().binding);
        let emitted = staged.bind_exact(3, "button", "", frame().binding);
        staged.retain_snapshot_entries(
            &baseline,
            &std::collections::HashSet::from([emitted.clone()]),
        );
        assert!(
            staged.get(&old).is_none(),
            "reread but omitted old observed authority must not be published"
        );
        assert!(staged.get(&omitted).is_none());
        assert!(staged.get(&emitted).is_some());
        assert!(
            staged.get(&located).is_some(),
            "same-backend pinned issuance survives"
        );
        assert_eq!(staged.retained_identity_counts(), (2, 2));
        assert_eq!(
            staged.durable_ref(
                &frame().binding.page_session,
                Some(&frame().binding.frame),
                1
            ),
            Some(old.as_str())
        );
        assert_eq!(
            staged.durable_ref(
                &frame().binding.page_session,
                Some(&frame().binding.frame),
                2
            ),
            None
        );
        let reacquired = staged
            .try_bind_exact(2, "text", "", frame().binding)
            .unwrap();
        assert_ne!(reacquired, omitted, "discarded reservations never recycle");
        assert_eq!(staged.retained_identity_counts(), (3, 3));
    }
    #[test]
    fn author_formatting_role_is_omitted_without_changing_explicit_role_or_identity() {
        for native in ["generic", "none", "paragraph", "strong", "emphasis", "code"] {
            let mut ax = ax("formatting", 42, &[]);
            ax.role.as_mut().unwrap().value = Some(json!(native));
            let mut refs = observed_refs();
            let node = project_node(&frame(), 42, &ax, &mut refs, 1, &metadata(), true).unwrap();
            assert!(node.role.is_none());
            let mut explicit = metadata();
            explicit["attributes"]["role"] = json!(native);
            let named = project_node(&frame(), 42, &ax, &mut refs, 1, &explicit, true).unwrap();
            assert_eq!(named.role.as_deref(), Some(native));
            assert_eq!(named.reference, node.reference);
        }
    }
    #[test]
    fn incidental_ax_roles_do_not_become_public_roles_from_invalid_authored_tokens() {
        for (native, authored) in [
            ("generic", "unknown\u{a0}button"),
            ("generic", "unknown widget"),
            ("sectionheader", ""),
            ("sectionfooter", ""),
            ("LabelText", "LabelText"),
        ] {
            let mut ax = ax("incidental", 42, &[]);
            ax.role.as_mut().unwrap().value = Some(json!(native));
            let mut data = metadata();
            data["attributes"]["role"] = json!(authored);
            let node =
                project_node(&frame(), 42, &ax, &mut observed_refs(), 1, &data, true).unwrap();
            assert!(node.role.is_none(), "{native} from {authored:?}");
        }
        let mut ax = ax("explicit", 42, &[]);
        ax.role.as_mut().unwrap().value = Some(json!("strong"));
        let mut data = metadata();
        data["attributes"]["role"] = json!("unknown\tstrong");
        let node = project_node(&frame(), 42, &ax, &mut observed_refs(), 1, &data, true).unwrap();
        assert_eq!(node.role.as_deref(), Some("strong"));
    }

    #[test]
    fn hidden_iframe_proof_survives_compaction_without_tolerating_missing_owners() {
        let parent = frame();
        let mut child = frame();
        child.binding.frame = "child".into();
        child.parent_frame_id = Some("main".into());
        child.owner_backend_id = Some(42);
        let mut owner = SemanticNode {
            reference: NodeReference {
                id: "@owner".into(),
                revision: "1".into(),
            },
            role: Some("iframe".into()),
            author: Some(author_projection::Facts {
                tag: "iframe".into(),
                node_type: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        owner.states.insert("hidden".into(), true);
        assert!(proven_hidden_iframe(&owner));
        let hidden = std::collections::HashSet::from([("main".into(), 42)]);
        let mut skipped = std::collections::HashSet::new();
        assert!(frame_has_hidden_owner(&child, &hidden, &skipped).unwrap());
        let root = SemanticNode {
            author: Some(author_projection::Facts {
                node_type: 9,
                visible: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let graph = author_projection::Graph::read(
            &json!({"nodeType":9,"backendNodeId":1,"children":[{"nodeType":1,"backendNodeId":42}]}),
        )
        .unwrap();
        let nodes = HashMap::from([(1, root), (42, owner.clone())]);
        let emitted = author_projection::compact(&graph, nodes, 100).unwrap().0;
        assert!(
            emitted[0].children.is_empty(),
            "Hidden owner is intentionally absent"
        );
        assert!(
            !frame_has_hidden_owner(&child, &Default::default(), &skipped).unwrap(),
            "Missing owner is not hidden proof"
        );
        owner.states.insert("hidden".into(), false);
        assert!(!proven_hidden_iframe(&owner));
        owner.states.insert("hidden".into(), true);
        owner.author.as_mut().unwrap().tag = "div".into();
        assert!(!proven_hidden_iframe(&owner));
        owner.author.as_mut().unwrap().tag = "iframe".into();
        owner.author.as_mut().unwrap().node_type = 3;
        assert!(!proven_hidden_iframe(&owner));
        let mut nested = child.clone();
        nested.binding.frame = "nested".into();
        nested.parent_frame_id = Some("child".into());
        nested.owner_backend_id = Some(43);
        skipped.insert("child".into());
        assert!(frame_has_hidden_owner(&nested, &hidden, &skipped).unwrap());
        nested.owner_backend_id = None;
        assert!(frame_has_hidden_owner(&nested, &hidden, &skipped).is_err());
        let frames = [child.clone(), parent];
        let ordered = observation_frame_order(&frames).unwrap();
        assert_eq!(ordered[0].binding.frame, "main");
        assert_eq!(ordered[1].binding.frame, "child");
        assert!(observation_frame_order(&[child.clone()]).is_err());
        child.parent_frame_id = Some("child".into());
        assert!(observation_frame_order(&[child]).is_err());
    }

    #[test]
    fn exact_control_metadata_precedes_native_ax_state() {
        for name in ["checked", "selected"] {
            for expected in [true, false] {
                let mut native = ax("control", 42, &[]);
                native.properties = Some(
                    serde_json::from_value(json!([
                        {"name":name,"value":{"type":"boolean","value":!expected}}
                    ]))
                    .unwrap(),
                );
                let mut data = metadata();
                data["controlStates"] = json!({name:expected});
                let node =
                    project_node(&frame(), 42, &native, &mut observed_refs(), 1, &data, true)
                        .unwrap();
                assert_eq!(node.states.get(name), Some(&expected));
                data["__nativeReadonlyPseudo"] = json!(true);
                let pseudo =
                    project_node(&frame(), 42, &native, &mut observed_refs(), 1, &data, true)
                        .unwrap();
                assert_eq!(pseudo.states.get(name), Some(&!expected));
            }
        }
        for invalid in [
            json!({"checked":null}),
            json!({"checked":"true"}),
            json!({"hidden":true}),
            json!([]),
        ] {
            let mut data = metadata();
            data["controlStates"] = invalid;
            assert_eq!(
                project_node(
                    &frame(),
                    42,
                    &ax("control", 42, &[]),
                    &mut observed_refs(),
                    1,
                    &data,
                    true
                )
                .unwrap_err(),
                ObservationError::BackendFailure
            );
        }
    }

    #[test]
    fn editing_host_role_uses_concrete_authored_precedence() {
        for (authored, expected) in [
            ("", "textbox"),
            ("widget", "textbox"),
            ("unknown\u{a0}button", "textbox"),
            ("unknown article", "article"),
            ("img button", "image"),
        ] {
            let mut data = metadata();
            data["editingHost"] = json!(true);
            data["attributes"]["role"] = json!(authored);
            data["value"] = json!("  rendered\nvalue  ");
            let node = project_node(
                &frame(),
                42,
                &ax("editor", 42, &[]),
                &mut observed_refs(),
                1,
                &data,
                true,
            )
            .unwrap();
            assert_eq!(node.role.as_deref(), Some(expected));
            assert_eq!(node.value.as_deref(), Some("  rendered\nvalue  "));
        }
    }

    #[test]
    fn public_glyph_names_preserve_real_text_and_security_boundaries() {
        for (name, title, expected) in [
            ("→ Next", None, Some("→ Next")),
            ("\u{f090} Sign in", None, Some("Sign in")),
            ("Log\u{f0000}out", None, Some("Log out")),
            ("\u{10fffd}", Some(" Sign out "), Some("Sign out")),
            ("\u{e000}", None, None),
            ("  unchanged  ", None, Some("  unchanged  ")),
        ] {
            assert_eq!(
                reported_public_name(name.into(), title).as_deref(),
                expected
            );
        }
        assert_eq!(normalize_public_label("\u{f090} Phone"), "Phone");
        assert_eq!(
            reported_public_name("\u{f090}\u{feff}".into(), Some("\u{feff}Title\u{feff}"))
                .as_deref(),
            Some("Title")
        );
        assert_eq!(
            reported_public_name("\u{f090}\u{85}".into(), Some("Title")).as_deref(),
            Some("\u{85}")
        );
        assert_eq!(
            reported_public_name("\u{f090}".into(), Some("\u{85}Title\u{85}")).as_deref(),
            Some("\u{85}Title\u{85}")
        );
        let mut ax = ax("glyph", 42, &[]);
        ax.name.as_mut().unwrap().value = Some(json!("\u{f090}"));
        let mut data = metadata();
        data["attributes"]["title"] = json!("Must not restore");
        data["redactName"] = json!(true);
        let node = project_node(&frame(), 42, &ax, &mut observed_refs(), 1, &data, true).unwrap();
        assert!(node.name.is_none());
        data["safePublicName"] = json!("\u{f090} Public");
        let node = project_node(&frame(), 42, &ax, &mut observed_refs(), 1, &data, true).unwrap();
        assert_eq!(node.name.as_deref(), Some("Public"));
        assert_eq!(node.safe_public_name.as_deref(), Some("Public"));
    }

    #[test]
    fn summary_and_description_list_roles_require_recognized_author_tokens() {
        for (tag, native) in [
            ("summary", "DisclosureTriangle"),
            ("dt", "term"),
            ("dd", "definition"),
        ] {
            let mut ax = ax("structural", 42, &[]);
            ax.role.as_mut().unwrap().value = Some(json!(native));
            let mut data = metadata();
            data["author"]["tag"] = json!(tag);
            for authored in ["", "unknown widget"] {
                data["attributes"]["role"] = json!(authored);
                let node =
                    project_node(&frame(), 42, &ax, &mut observed_refs(), 1, &data, true).unwrap();
                assert!(node.role.is_none());
            }
            // Preserve the effective AX role when an explicit recognized role
            // was selected. Do not infer roles from a malformed token string.
            ax.role.as_mut().unwrap().value = Some(json!("term"));
            data["attributes"]["role"] = json!("unknown term");
            let node =
                project_node(&frame(), 42, &ax, &mut observed_refs(), 1, &data, true).unwrap();
            assert_eq!(node.role.as_deref(), Some("term"));
        }
    }

    #[test]
    fn public_labels_normalize_embedded_control_whitespace() {
        assert_eq!(normalize_public_label("Qty  items"), "Qty items");
        assert_eq!(normalize_public_label("  PIN\n \tfield  "), "PIN field");
    }
    #[test]
    fn renderer_tree_join_requires_native_parent_and_preserves_existing_edges() {
        let child = json!({"frame":{"id":"child","parentId":"main"}});
        let remote = json!({"frame":{"id":"remote","parentId":"main"}});
        let foreign = json!({"frame":{"id":"foreign","parentId":"other"}});
        let unknown = json!({"frame":{"id":"unknown"}});
        let owned = HashMap::from([
            ("child".into(), child.clone()),
            ("remote".into(), remote.clone()),
            ("foreign".into(), foreign),
            ("unknown".into(), unknown),
        ]);
        let tree = json!({"frame":{"id":"main"},"childFrames":[child.clone()]});
        assert_eq!(
            joined_frame_children(&tree, "main", &owned),
            vec![child, remote]
        );
        let unknown_parent = json!({"frame":{"id":"other-unowned"}});
        assert!(joined_frame_children(&unknown_parent, "other-unowned", &owned).is_empty());
    }
    #[test]
    fn live_source_retains_full_frames_and_original_projection_selection() {
        assert_eq!(retained_query_selection(1, 0), LiveQuerySelection::Strict);
        // One output surviving a three-entry projection is still nth(2).
        assert_eq!(retained_query_selection(3, 2), LiveQuerySelection::Nth(2));
        let options: QueryOptions = serde_json::from_value(json!({"expression":{
            "kind":"frame","selector":"#outer","source":{"kind":"frame","selector":"#inner","source":{
                "kind":"index","index":1,"source":{"kind":"selector","selector":"button"}
            }}
        }})).unwrap();
        let source = LiveQuerySource {
            options: options.clone(),
            selection: LiveQuerySelection::Strict,
        };
        let stored: LiveQuerySource =
            serde_json::from_str(&serde_json::to_string(&source).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&stored.options).unwrap(),
            serde_json::to_value(&options).unwrap()
        );
        assert_eq!(
            split_frame_expression(&stored.options.expression)
                .unwrap()
                .0,
            vec!["#outer", "#inner"]
        );
        assert!(!query_uses_pinned_handles(&stored.options.expression));
        for expression in [
            json!({"kind":"query","query":{"kind":"displayValue","value":{"kind":"string","value":"x","exact":true}}}),
            json!({"kind":"index","index":"first","source":{"kind":"query","query":{"kind":"label","value":{"kind":"string","value":"x","exact":true}}}}),
        ] {
            assert!(query_uses_pinned_handles(
                &serde_json::from_value(expression).unwrap()
            ));
        }
        let scoped: LocatorExpression = serde_json::from_value(json!({"kind":"query","query":{"kind":"role","value":{"kind":"string","value":"button","exact":true}},"scope":{"kind":"query","query":{"kind":"label","value":{"kind":"string","value":"x","exact":true}}}})).unwrap();
        assert!(!query_uses_pinned_handles(&scoped));
    }

    #[test]
    fn acquisition_inventory_excludes_foreign_documents_ua_and_pseudo_nodes() {
        let (op, _sender) = lease();
        let root = json!({"nodeType":9,"backendNodeId":1,"children":[
            {"nodeType":1,"backendNodeId":2,"children":[{"nodeType":3,"backendNodeId":3}],
             "shadowRoots":[{"nodeType":11,"shadowRootType":"closed","children":[{"nodeType":1,"backendNodeId":4}]},
                {"nodeType":11,"shadowRootType":"user-agent","children":[{"nodeType":1,"backendNodeId":5}]}],
             "pseudoElements":[{"nodeType":1,"backendNodeId":6,"pseudoType":"before"}],
             "contentDocument":{"nodeType":9,"backendNodeId":7,"children":[{"nodeType":1,"backendNodeId":8}]}}
        ]});
        assert_eq!(
            acquisition_backend_inventory(&root, &op).unwrap(),
            std::collections::HashSet::from([1, 2, 3, 4])
        );
    }

    #[tokio::test]
    async fn retained_frame_sources_recheck_full_parent_dom_and_current_owned_documents() {
        use futures_util::{SinkExt, StreamExt};
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        };
        for mode in [
            "nested-replacement",
            "css-prefix",
            "ancestor-ambiguous",
            "ancestor-missing",
            "unowned-match",
            "invalid-selector",
            "frame-replacement",
            "child-navigation",
            "root-navigation",
        ] {
            let changed = Arc::new(AtomicBool::new(false));
            let state = changed.clone();
            let dom_reads = Arc::new(AtomicUsize::new(0));
            let reads = dom_reads.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("ws://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                while let Some(Ok(message)) = socket.next().await {
                    let Ok(text) = message.to_text() else {
                        continue;
                    };
                    let request: Value = serde_json::from_str(text).unwrap();
                    let session = request["sessionId"].as_str().unwrap();
                    let mutated = state.load(Ordering::SeqCst);
                    let is_root = session == "renderer";
                    let is_outer = session == "outer-session";
                    let frame_id = if is_root {
                        "main"
                    } else if is_outer {
                        "outer"
                    } else if session == "inner-new-session" {
                        "inner-new"
                    } else {
                        "inner"
                    };
                    let loader = if is_root {
                        if mutated && mode == "root-navigation" {
                            "doc-new"
                        } else {
                            "doc"
                        }
                    } else if is_outer {
                        "outer-doc"
                    } else if mutated && mode == "child-navigation" {
                        "inner-doc-new"
                    } else {
                        "inner-doc"
                    };
                    let ids = if is_root {
                        [42, 43]
                    } else if is_outer {
                        [82, 83]
                    } else if mutated {
                        [143, 144]
                    } else {
                        [142, 143]
                    };
                    let method = request["method"].as_str().unwrap();
                    let result = match method {
                        "Page.getFrameTree" => {
                            json!({"frameTree":{"frame":{"id":frame_id,"loaderId":loader}}})
                        }
                        "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                        "DOM.getFrameOwner" => {
                            json!({"backendNodeId":match request["params"]["frameId"].as_str().unwrap() { "outer"=>42, "inner-new"=>83, _=>82 }})
                        }
                        "DOM.getDocument" => {
                            reads.fetch_add(1, Ordering::SeqCst);
                            json!({"root":{"nodeType":9,"backendNodeId":99,"children":[{"nodeType":1,"backendNodeId":ids[0]},{"nodeType":1,"backendNodeId":ids[1]}]}})
                        }
                        "Accessibility.getFullAXTree" => {
                            json!({"nodes":ids.iter().map(|id|json!({"nodeId":id.to_string(),"backendDOMNodeId":id,"role":{"type":"role","value":"button"},"name":{"type":"string","value":"Save"}})).collect::<Vec<_>>()})
                        }
                        "DOM.resolveNode" => {
                            json!({"object":{"objectId":format!("node-{}",request["params"]["backendNodeId"]),"subtype":"node"}})
                        }
                        "Runtime.getProperties" => json!({"result":[]}),
                        "Runtime.callFunctionOn" => {
                            let source = request["params"]["functionDeclaration"].as_str().unwrap();
                            if source.contains("Array.from(result)") {
                                json!({"result":{"objectId":"security"}})
                            } else if source.starts_with("function(expression") {
                                if mode == "css-prefix" && (is_root || is_outer) {
                                    assert_eq!(
                                        request["params"]["arguments"][0]["value"]["selector"],
                                        if is_root { "#outer" } else { "#inner" }
                                    );
                                }
                                if is_root && mutated && mode == "invalid-selector" {
                                    json!({"result":{"value":{"error":"invalid-arguments"}}})
                                } else {
                                    let indices = if is_root && mutated {
                                        match mode {
                                            "ancestor-ambiguous" => vec![0, 1],
                                            "ancestor-missing" => vec![],
                                            "unowned-match" => vec![1],
                                            _ => vec![0],
                                        }
                                    } else if is_outer && mutated && mode == "frame-replacement" {
                                        vec![1]
                                    } else {
                                        vec![0]
                                    };
                                    json!({"result":{"value":{"indices":indices,"redacted":[]}}})
                                }
                            } else {
                                let count =
                                    request["params"]["arguments"].as_array().unwrap().len() - 2;
                                json!({"result":{"value":vec![metadata();count]}})
                            }
                        }
                        "Runtime.releaseObjectGroup" => json!({}),
                        _ => panic!("unexpected live frame command {method}"),
                    };
                    if socket
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            json!({"id":request["id"],"result":result}).to_string(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let client = CdpClient::connect(&endpoint).await.unwrap();
            let (op, _sender) = lease();
            let root = frame();
            let mut outer = root.clone();
            outer.binding.session = "outer-session".into();
            outer.binding.frame = "outer".into();
            outer.binding.loader = "outer-doc".into();
            outer.parent_frame_id = Some("main".into());
            outer.owner_backend_id = Some(42);
            let mut inner = root.clone();
            inner.binding.session = "inner-session".into();
            inner.binding.frame = "inner".into();
            inner.binding.loader = "inner-doc".into();
            inner.parent_frame_id = Some("outer".into());
            inner.owner_backend_id = Some(82);
            let mut frames = vec![root, outer, inner];
            let options: QueryOptions = serde_json::from_value(json!({"expression":{"kind":"frame","selector":if mode == "css-prefix" { "css=#outer" } else { "#outer" },"source":{"kind":"frame","selector":if mode == "css-prefix" { "css=#inner" } else { "#inner" },"source":{"kind":"selector","selector":"button"}}}})).unwrap();
            let mut refs = observed_refs();
            let found = query(&client, &frames, &mut refs, "scope", 1, &options, &op)
                .await
                .unwrap();
            let id = super::super::element::parse_ref(&found.nodes[0].reference.id).unwrap();
            let acquired = refs.get(&id).unwrap().clone();
            let before = refs.next_ref_num();
            let count = dom_reads.load(Ordering::SeqCst);
            validate_acquisition_bindings(
                &client,
                &frames,
                &[
                    (frames[0].binding.clone(), 99),
                    (frames[0].binding.clone(), 42),
                    (frames[0].binding.clone(), 43),
                ],
                &op,
            )
            .await
            .unwrap();
            assert_eq!(
                dom_reads.load(Ordering::SeqCst) - count,
                1,
                "one inventory per document, not candidate"
            );
            changed.store(true, Ordering::SeqCst);
            if mode == "frame-replacement" {
                frames[2].binding.frame = "inner-new".into();
                frames[2].binding.session = "inner-new-session".into();
                frames[2].owner_backend_id = Some(83);
            }
            if mode == "child-navigation" {
                frames[2].binding.loader = "inner-doc-new".into();
            }
            if mode == "root-navigation" {
                frames[0].binding.loader = "doc-new".into();
            }
            let result = resolve_live_query(
                &client,
                &frames,
                acquired.live_query.as_ref().unwrap(),
                acquired.exact_binding.as_ref().unwrap(),
                &op,
            )
            .await;
            match mode {
                "ancestor-ambiguous" | "ancestor-missing" | "unowned-match" => assert!(
                    matches!(result, Err(ObservationError::StaleReference)),
                    "{mode}"
                ),
                "invalid-selector" => {
                    assert!(matches!(result, Err(ObservationError::InvalidArguments)))
                }
                _ => {
                    let selected = result.unwrap();
                    assert_eq!(selected.backend_node_id, 143);
                    assert_eq!(acquired.backend_node_id, Some(142));
                }
            }
            assert_eq!(refs.next_ref_num(), before);
            if matches!(
                mode,
                "nested-replacement" | "frame-replacement" | "child-navigation"
            ) {
                assert_eq!(
                    validate_acquisition_binding(&client, &frames, &acquired, &op).await,
                    Err(ObservationError::StaleReference)
                );
            }
            server.abort();
            let _ = server.await;
        }
    }

    #[tokio::test]
    async fn query_group_cleanup_failure_preserves_primary_and_never_publishes() {
        use futures_util::{SinkExt, StreamExt};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        for (cleanup_failure, timeout) in [(true, false), (true, true), (false, false)] {
            for primary_failure in [
                None,
                Some(ObservationError::BackendFailure),
                Some(ObservationError::ResourceLimit),
            ] {
                // Retain the existing cleanup-failure matrix, and prove the
                // renderer's typed resource limit also survives clean release.
                if !cleanup_failure && primary_failure != Some(ObservationError::ResourceLimit) {
                    continue;
                }
                let query_releases = Arc::new(AtomicUsize::new(0));
                let query_matches = Arc::new(AtomicUsize::new(0));
                let released = query_releases.clone();
                let matched = query_matches.clone();
                let renderer_failure = primary_failure.clone();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let endpoint = format!("ws://{}", listener.local_addr().unwrap());
                let server = tokio::spawn(async move {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                    while let Some(Ok(message)) = ws.next().await {
                        let Ok(text) = message.to_text() else {
                            continue;
                        };
                        let request: Value = serde_json::from_str(text).unwrap();
                        let method = request["method"].as_str().unwrap();
                        let query_release = method == "Runtime.releaseObjectGroup"
                            && request["params"]["objectGroup"]
                                .as_str()
                                .unwrap()
                                .starts_with("native-query-");
                        if query_release {
                            released.fetch_add(1, Ordering::SeqCst);
                        }
                        if query_release && timeout {
                            continue;
                        }
                        let result = match method {
                            "Page.getFrameTree" => {
                                json!({"frameTree":{"frame":{"id":"main","loaderId":"doc"}}})
                            }
                            "Accessibility.getFullAXTree" => {
                                json!({"nodes":[{"nodeId":"button","backendDOMNodeId":42,"role":{"type":"role","value":"button"},"name":{"type":"string","value":"Save"}}]})
                            }
                            "DOM.getDocument" => {
                                json!({"root":{"nodeType":9,"backendNodeId":99,"children":[{"nodeType":1,"backendNodeId":42}]}})
                            }
                            "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                            "DOM.resolveNode" => {
                                json!({"object":{"objectId":"owned","subtype":"node"}})
                            }
                            "Runtime.getProperties" => json!({"result":[]}),
                            "Runtime.callFunctionOn" => {
                                let declaration =
                                    request["params"]["functionDeclaration"].as_str().unwrap();
                                if declaration.contains("Array.from(result)") {
                                    json!({"result":{"objectId":"security"}})
                                } else if declaration.starts_with("function(expression") {
                                    matched.fetch_add(1, Ordering::SeqCst);
                                    assert_eq!(declaration, MATCH_QUERY);
                                    assert_eq!(
                                        request["params"]["arguments"][4]["value"],
                                        ".secure"
                                    );
                                    assert_eq!(
                                        request["params"]["arguments"][5]["value"],
                                        json!([false])
                                    );
                                    match renderer_failure.as_ref() {
                                        Some(ObservationError::ResourceLimit) => {
                                            json!({"result":{"value":{"error":"resource-limit"}}})
                                        }
                                        Some(_) => json!({"exceptionDetails":{}}),
                                        None => {
                                            json!({"result":{"value":{"indices":[0],"redacted":[]}}})
                                        }
                                    }
                                } else {
                                    json!({"result":{"value":[metadata()]}})
                                }
                            }
                            "Runtime.releaseObjectGroup" => json!({}),
                            _ => panic!("unexpected scoped query command"),
                        };
                        let response = if query_release && cleanup_failure {
                            json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic cleanup failure"}})
                        } else {
                            json!({"id":request["id"],"result":result})
                        };
                        if ws
                            .send(tokio_tungstenite::tungstenite::Message::Text(
                                response.to_string(),
                            ))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
                let client = CdpClient::connect(&endpoint).await.unwrap();
                let (op, _sender) = lease();
                let mut refs = observed_refs();
                let previous = refs.bind_exact(7, "button", "Previous", frame().binding);
                let options: QueryOptions = serde_json::from_value(
                    json!({"secureFieldSelector":".secure","expression":{"kind":"filter","source":{"kind":"selector","selector":"button"},"hasText":{"kind":"string","value":"Save","exact":false}}}),
                )
                .unwrap();
                let result = query(&client, &[frame()], &mut refs, "scope", 1, &options, &op).await;
                let expected = if cleanup_failure {
                    ObservationError::CleanupFailed {
                        primary: primary_failure.map(Box::new),
                    }
                } else {
                    primary_failure.unwrap()
                };
                assert_eq!(result.unwrap_err(), expected);
                assert_eq!(query_matches.load(Ordering::SeqCst), 1);
                assert_eq!(query_releases.load(Ordering::SeqCst), 1);
                assert_eq!(refs.retained_identity_counts(), (1, 1));
                assert!(refs.get(&previous).is_some());
                assert!(refs.get("e2").is_none());
                server.abort();
                let _ = server.await;
            }
        }
    }
    #[tokio::test]
    async fn frame_enumeration_owner_cleanup_failure_and_timeout_preserve_read_primary() {
        use futures_util::{SinkExt, StreamExt};
        // Frame selection uses the whole-query cleanup matrix above.
        for enumeration in [true] {
            for timeout in [false, true] {
                for primary_failure in [false, true] {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
                    let server = tokio::spawn(async move {
                        let (stream, _) = listener.accept().await.unwrap();
                        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                        while let Some(Ok(message)) = ws.next().await {
                            let Ok(text) = message.to_text() else {
                                continue;
                            };
                            let request: Value = serde_json::from_str(text).unwrap();
                            let method = request["method"].as_str().unwrap();
                            if method == "Runtime.releaseObject" && timeout {
                                continue;
                            }
                            let result = match method {
                                "Page.getFrameTree" => json!({"frameTree":{
                                    "frame":{"id":"main","loaderId":"doc","url":"https://fixture.invalid"},
                                    "childFrames":[{"frame":{"id":"child","loaderId":"child-doc","parentId":"main","url":"https://fixture.invalid/child"}}]
                                }}),
                                "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                                "DOM.getFrameOwner" => json!({"backendNodeId":42}),
                                "DOM.resolveNode" => {
                                    json!({"object":{"objectId":"owner","subtype":"node"}})
                                }
                                "Runtime.callFunctionOn" if primary_failure => {
                                    json!({"exceptionDetails":{}})
                                }
                                "Runtime.callFunctionOn" if enumeration => {
                                    json!({"result":{"value":{"x":0,"y":0,"selector":"iframe"}}})
                                }
                                "Runtime.callFunctionOn" => json!({"result":{"value":true}}),
                                "Runtime.releaseObject" => json!({}),
                                _ => panic!("unexpected frame owner command: {method}"),
                            };
                            let response = if method == "Runtime.releaseObject" {
                                assert_eq!(request["params"]["objectId"], "owner");
                                json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic cleanup failure"}})
                            } else {
                                json!({"id":request["id"],"result":result})
                            };
                            if ws
                                .send(tokio_tungstenite::tungstenite::Message::Text(
                                    response.to_string(),
                                ))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    });
                    let client = CdpClient::connect(&endpoint).await.unwrap();
                    let (op, _sender) = lease();
                    let result = enumerate_frames(&client, "renderer", &HashMap::new(), &op)
                        .await
                        .map(|_| ());
                    assert_eq!(
                        result.unwrap_err(),
                        ObservationError::CleanupFailed {
                            primary: primary_failure.then(|| Box::new(if enumeration {
                                ObservationError::StaleReference
                            } else {
                                ObservationError::InvalidArguments
                            })),
                        }
                    );
                    server.abort();
                    let _ = server.await;
                }
            }
        }
    }

    fn observed_refs() -> RefMap {
        let mut refs = RefMap::new();
        refs.begin_observation("scope", 1, 1);
        refs
    }

    fn frame() -> ObservationFrame {
        ObservationFrame {
            parent_frame_id: None,
            owner_backend_id: None,
            url: "https://fixture.invalid".into(),
            binding: ExactBinding {
                page_session: "page".into(),
                session: "renderer".into(),
                frame: "main".into(),
                loader: "doc".into(),
                actionable: false,
            },
            offset_x: 10.0,
            offset_y: 20.0,
            frame_path: vec![],
        }
    }
    fn ax(id: &str, backend: i64, children: &[&str]) -> AXNode {
        serde_json::from_value(json!({"nodeId":id,"backendDOMNodeId":backend,"role":{"type":"role","value":"button"},"name":{"type":"string","value":"Save"},"childIds":children})).unwrap()
    }
    fn metadata() -> Value {
        json!({"author":{"tag":"button","action":true,"visible":true},"attributes":{},"labels":[],"states":{"secure":false,"hidden":false},"text":"Save","rect":{"x":1,"y":2,"width":3,"height":4}})
    }
    async fn mock_client(fail_after_metadata: bool) -> (CdpClient, tokio::task::JoinHandle<()>) {
        use futures_util::{SinkExt, StreamExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut metadata_read = false;
            while let Some(Ok(message)) = ws.next().await {
                let Ok(text) = message.to_text() else {
                    continue;
                };
                let request: Value = serde_json::from_str(text).unwrap();
                let result = match request["method"].as_str().unwrap() {
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"main","loaderId":if metadata_read&&fail_after_metadata{"replaced"}else{"doc"}}}})
                    }
                    "Accessibility.getFullAXTree" => {
                        json!({"nodes":[{"nodeId":"1","backendDOMNodeId":42,"role":{"type":"role","value":"button"},"name":{"type":"string","value":"Save"}}]})
                    }
                    "DOM.getDocument" => {
                        json!({"root":{"nodeType":9,"backendNodeId":99,"children":[]}})
                    }
                    "Runtime.getProperties" => json!({"result":[]}),
                    "Page.createIsolatedWorld" => json!({"executionContextId":1}),
                    "DOM.resolveNode" => json!({"object":{"objectId":"node-42","subtype":"node"}}),
                    "Runtime.callFunctionOn" => {
                        if request["params"]["functionDeclaration"]
                            .as_str()
                            .unwrap_or("")
                            .contains("Array.from(result)")
                        {
                            json!({"result":{"objectId":"security-array"}})
                        } else {
                            metadata_read = true;
                            json!({"result":{"type":"object","value":[metadata()]}})
                        }
                    }
                    _ => json!({}),
                };
                if ws
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        json!({"id":request["id"],"result":result}).to_string(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        (CdpClient::connect(&url).await.unwrap(), server)
    }
    fn lease() -> (OperationLease, tokio::sync::watch::Sender<CancelSignal>) {
        let (sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        (
            OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(5),
                cancellation,
            },
            sender,
        )
    }
    #[tokio::test]
    async fn late_document_failure_keeps_previous_generation_and_consumes_ids() {
        let (client, server) = mock_client(true).await;
        let (lease, _sender) = lease();
        let mut refs = observed_refs();
        let previous = refs.bind_exact(7, "button", "Previous", frame().binding);
        assert!(observe(
            &client,
            &[frame()],
            &mut refs,
            "scope",
            2,
            &ObservationOptions::default(),
            &lease
        )
        .await
        .is_err());
        assert!(refs.get(&previous).is_some());
        assert!(refs.get("e2").is_none());
        assert_eq!(refs.allocate_ref(), "e3");
        server.abort();
    }
    #[tokio::test]
    async fn successful_snapshot_publishes_once_and_stable_node_keeps_id() {
        let (client, server) = mock_client(false).await;
        let (lease, _sender) = lease();
        let mut refs = observed_refs();
        let a = observe(
            &client,
            &[frame()],
            &mut refs,
            "scope",
            1,
            &ObservationOptions::default(),
            &lease,
        )
        .await
        .unwrap();
        let b = observe(
            &client,
            &[frame()],
            &mut refs,
            "scope",
            2,
            &ObservationOptions::default(),
            &lease,
        )
        .await
        .unwrap();
        assert_eq!(a.roots[0].reference.id, b.roots[0].reference.id);
        assert_eq!(a.roots[0].reference, b.roots[0].reference);
        assert_eq!(b.revision, 2);
        assert_eq!(a.viewport_ref, b.viewport_ref);
        server.abort();
    }
    #[tokio::test]
    async fn cancellation_before_capture_does_not_publish() {
        let (client, server) = mock_client(false).await;
        let (lease, sender) = lease();
        sender.send_replace(CancelSignal::Requested);
        let mut refs = observed_refs();
        assert!(observe(
            &client,
            &[frame()],
            &mut refs,
            "scope",
            1,
            &ObservationOptions::default(),
            &lease
        )
        .await
        .is_err());
        assert!(refs.ref_ids().is_empty());
        server.abort();
    }
    // Query and observation capabilities may intentionally use different IDs
    // for one node. Join diagnostic views by backend plus every binding field,
    // never by selector/name or by dropping frame/session/loader boundaries.
    type FixtureExactIdentity = (i64, String, String, String, String, bool);
    fn fixture_exact_identity(
        refs: &RefMap,
        reference: &str,
    ) -> Result<FixtureExactIdentity, String> {
        let id = super::super::element::parse_ref(reference).ok_or("Invalid fixture ref")?;
        let entry = refs.get(&id).ok_or("Missing fixture exact identity")?;
        let binding = entry
            .exact_binding
            .as_ref()
            .ok_or("Missing fixture binding")?;
        Ok((
            entry.backend_node_id.ok_or("Missing fixture backend")?,
            binding.page_session.clone(),
            binding.session.clone(),
            binding.frame.clone(),
            binding.loader.clone(),
            binding.actionable,
        ))
    }

    #[tokio::test]
    #[ignore = "requires a real installed Chromium; run in browser CI"]
    async fn chromium_native_observation_query_exact_and_secure_contract() {
        use super::super::actions::{execute_command, DaemonState};
        let mut state = DaemonState::new();
        let launch = execute_command(
            &json!({"id":"observation-launch","action":"launch","headless":true}),
            &mut state,
        )
        .await;
        assert_eq!(launch["success"], true, "{launch}");
        let run=async {
            let mgr=state.browser.as_ref().ok_or("Missing browser")?;
            let session=mgr.active_session_id()?;
            mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":r#"document.body.innerHTML='<main><label for="account">Account</label><input id="account" value="synthetic-user"><input id="secret" type="password" value="synthetic-password"><ul><li>Alpha <button>Save</button></li><li>Beta <button>Save</button></li></ul><div id="shadow"></div></main>'; const root=document.querySelector('#shadow').attachShadow({mode:'closed'}); root.innerHTML='<button>Shadow save</button>'; true"#,"returnByValue":true})),Some(session)).await.map_err(|_| "native observation stage: fixture_cdp_1".to_string())?;
            let (mut lease,_sender)=lease();lease.deadline=std::time::Instant::now()+std::time::Duration::from_secs(30);let mut refs=observed_refs();
            let frames=enumerate_frames(&mgr.client,session,&HashMap::new(),&lease).await.map_err(|_| "native observation stage: enumerate_frames_1".to_string())?;
            let observation=observe(&mgr.client,&frames,&mut refs,"fixture",1,&ObservationOptions::default(),&lease).await.map_err(|_| "native observation stage: observe_1".to_string())?;
            let pseudo_refs:Vec<_>=refs.entries_sorted().into_iter().filter(|(_,entry)|entry.kind==super::super::element::NativeReferenceKind::ReadOnlyCssPseudo).collect();
            if pseudo_refs.len()<2{return Err("Native list-marker readonly identities were lost".into());}
            for (id,_) in pseudo_refs { if super::super::element::resolve_element_object_id(&mgr.client,session,&refs,&format!("@{id}"),&HashMap::new()).await.is_ok(){return Err("Readonly pseudo became actionable".into());} }
            let serialized=serde_json::to_string(&observation).unwrap();
            if serialized.contains("synthetic-password"){return Err("Password leaked in observation".to_string());}
            let options:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"index","source":{"kind":"query","query":{"kind":"role","value":{"kind":"string","value":"button","exact":true},"name":{"kind":"string","value":"Save","exact":true}}},"index":"last"}})).unwrap();
            let result=query(&mgr.client,&frames,&mut refs,"fixture",1,&options,&lease).await.map_err(|_| "native observation stage: query_1".to_string())?;
            if result.nodes.len()!=1{return Err("Query index failed".into());}
            let old=result.nodes[0].reference.id.clone();
            mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":"document.querySelectorAll('li button')[1].outerHTML='<button>Save</button>'; true","returnByValue":true})),Some(session)).await.map_err(|_| "native observation stage: fixture_cdp_2".to_string())?;
            if super::super::element::resolve_element_object_id(&mgr.client,session,&refs,&old,&HashMap::new()).await.is_ok(){return Err("Removed exact node rebound".into());}
            let replacement=query(&mgr.client,&frames,&mut refs,"fixture",1,&options,&lease).await.map_err(|_| "native observation stage: query_2".to_string())?;
            if replacement.nodes[0].reference.id==old{return Err("Replacement reused exact ref".into());}
            let options:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"query","query":{"kind":"role","value":{"kind":"string","value":"button","exact":true},"name":{"kind":"regexp","source":"Shadow save","flags":"u"}}}})).unwrap();
            if query(&mgr.client,&frames,&mut refs,"fixture",1,&options,&lease).await.map_err(|_| "native observation stage: query_3".to_string())?.nodes.len()!=1{return Err("Closed shadow query failed".into());}
            let options:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"query","query":{"kind":"label","value":{"kind":"string","value":"Account","exact":true}}}})).unwrap();
            let result=query(&mgr.client,&frames,&mut refs,"fixture",1,&options,&lease).await.map_err(|_| "native observation stage: query_4".to_string())?;
            if result.nodes.len()!=1||result.nodes[0].value.as_deref()!=Some("synthetic-user"){return Err("Label/read contract failed".into());}
            mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":r#"new Promise(resolve=>{const f=document.createElement('iframe');f.dataset.frame='demo';f.onload=resolve;f.srcdoc='<button id="inner">Frame action</button>';document.body.appendChild(f);})"#,"awaitPromise":true,"returnByValue":true})),Some(session)).await.map_err(|_| "native observation stage: fixture_cdp_3".to_string())?;
            let frames=enumerate_frames(&mgr.client,session,&HashMap::new(),&lease).await.map_err(|_| "native observation stage: enumerate_frames_2".to_string())?;
            if frames.len()!=2{return Err("Same-process frame missing".into());}
            let framed:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"frame","selector":"iframe[data-frame=demo]","source":{"kind":"selector","selector":"#inner"}}})).unwrap();
            let result=query(&mgr.client,&frames,&mut refs,"fixture",1,&framed,&lease).await.map_err(|_| "native observation stage: query_5".to_string())?;
            if result.nodes.len()!=1||result.nodes[0].name.as_deref()!=Some("Frame action"){return Err("Frame query failed".into());}
            let framed_observation=observe(&mgr.client,&frames,&mut refs,"fixture",2,&ObservationOptions::default(),&lease).await.map_err(|_| "native observation stage: observe_2".to_string())?;
            if framed_observation.roots.len()!=1||!serde_json::to_string(&framed_observation).unwrap().contains("Frame action"){return Err("Frame subtree was flattened or lost".into());}
            let adopt:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"selector","selector":"li button"}})).unwrap();
            let result=query(&mgr.client,&frames,&mut refs,"fixture",2,&adopt,&lease).await.map_err(|_| "native observation stage: query_6".to_string())?;
            let adopted=result.nodes[0].reference.id.clone();
            mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":"document.querySelector('iframe').contentDocument.body.appendChild(document.querySelector('li button')); true","returnByValue":true})),Some(session)).await.map_err(|_| "native observation stage: fixture_cdp_4".to_string())?;
            if super::super::element::resolve_element_object_id(&mgr.client,session,&refs,&adopted,&HashMap::new()).await.is_ok(){return Err("Cross-document adopted node retained old exact authority".into());}
            mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":r#"for(const mode of ['open','closed']){const h=document.createElement('div');h.id=mode+'-secure-host';h.className='secure';document.body.appendChild(h);h.attachShadow({mode}).innerHTML='<span>synthetic-shadow-secret</span><input value="synthetic-shadow-secret">';}const h=document.createElement('div');h.id='unmarked-host';document.body.appendChild(h);h.attachShadow({mode:'closed'}).innerHTML='<span class="secure">synthetic-closed-child</span><span class="secure" id="root-local-secret">synthetic-root-local-secret</span><button aria-labelledby="root-local-secret">Public</button>';const b=document.createElement('button');b.setAttribute('aria-labelledby','unmarked-host');document.body.appendChild(b);true"#,"returnByValue":true})),Some(session)).await.map_err(|_| "native observation stage: fixture_cdp_5".to_string())?;
            mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":"const generated=document.createElement('div');generated.className='secure generated';document.body.appendChild(generated);const style=document.createElement('style');style.textContent='.generated::before{content:\"synthetic-generated-secret\"}';document.head.appendChild(style);true","returnByValue":true})),Some(session)).await?;
            let policy=ObservationOptions{secure_field_selector:".secure".into(),..Default::default()};
            let secret_tree=observe(&mgr.client,&frames,&mut refs,"fixture",3,&policy,&lease).await.map_err(|_| "native observation stage: observe_3".to_string())?;
            let serialized=serde_json::to_string(&secret_tree).unwrap();if serialized.contains("synthetic-generated-secret")||serialized.contains("synthetic-shadow-secret")||serialized.contains("synthetic-closed-child")||serialized.contains("synthetic-root-local-secret"){return Err("Shadow secure subtree leaked in observation".into());}
            let unmarked:QueryOptions=serde_json::from_value(json!({"secureFieldSelector":".secure","expression":{"kind":"selector","selector":"#unmarked-host"}})).unwrap();
            let found=query(&mgr.client,&frames,&mut refs,"fixture",3,&unmarked,&lease).await.map_err(|_| "native observation stage: query_7".to_string())?;
            let read_options:ReadOptions=serde_json::from_value(json!({"ref":found.nodes[0].reference.id,"secureFieldSelector":".secure"})).unwrap();
            let one=read(&mgr.client,&frames,&mut refs,"fixture",3,&read_options,&lease).await.map_err(|_| "native observation stage: read_1".to_string())?;if one.to_string().contains("synthetic-closed-child"){return Err("Closed secure descendant leaked in full read".into());}
            // Author controls retain exact query identity, while Chromium's
            // implementation controls never become extra model actions.
            mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":r#"document.body.innerHTML='<select id="choice"><option>One</option></select><input id="date" type="date"><input id="color" type="color"><div aria-disabled="true"><button id="blocked">Blocked</button><div aria-disabled="false"><button id="enabled">Enabled</button></div></div><ul><li>Item</li></ul>';true"#,"returnByValue":true})),Some(session)).await?;
            let frames=enumerate_frames(&mgr.client,session,&HashMap::new(),&lease).await?;
            let tree=observe(&mgr.client,&frames,&mut refs,"fixture",4,&ObservationOptions::default(),&lease).await?;
            let mut pending=tree.roots.iter().collect::<Vec<_>>();
            let dom=frame_dom(&mgr.client,&frames[0],&lease).await?;
            let internal=browser_internal_ids(&dom["root"])?;
            let mut observed=HashMap::new();
            while let Some(node)=pending.pop(){
                pending.extend(node.children.iter());
                let entry=refs.get(node.reference.id.trim_start_matches('@')).ok_or("Missing observed identity")?;
                if entry.backend_node_id.is_some_and(|id|internal.contains(&id)){return Err("Browser-internal control exposed".into());}
                if entry.kind==super::super::element::NativeReferenceKind::ReadOnlyCssPseudo && node.role.as_deref()!=Some("text"){return Err("List marker is not structural text".into());}
                observed.insert(fixture_exact_identity(&refs,&node.reference.id)?,node);
            }
            let all:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"selector","selector":"*"}})).unwrap();
            for node in query(&mgr.client,&frames,&mut refs,"fixture",4,&all,&lease).await?.nodes {
                let entry=refs.get(node.reference.id.trim_start_matches('@')).ok_or("Missing queried identity")?;
                if entry.backend_node_id.is_some_and(|id|internal.contains(&id)){return Err("Browser-internal query target exposed".into());}
            }
            for (selector,role,disabled) in [("#choice","combobox",false),("#date","textbox",false),("#color","textbox",false),("#blocked","button",true),("#enabled","button",false)] {
                let options:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"selector","selector":selector}})).unwrap();
                let found=query(&mgr.client,&frames,&mut refs,"fixture",4,&options,&lease).await?;
                if found.nodes.len()!=1{return Err("Author control query lost identity".into());}
                let identity=fixture_exact_identity(&refs,&found.nodes[0].reference.id)?;
                let node=observed.get(&identity).ok_or("Query and observation backend/binding identities differ")?;
                if node.reference.id==found.nodes[0].reference.id{return Err("Strict query reused observed authority ID".into());}
                if node.role.as_deref()!=Some(role)||node.states.get("disabled").copied().unwrap_or(false)!=disabled{return Err("Author control semantics differ".into());}
            }
            mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":r#"document.body.innerHTML='<details><summary id="summary">Summary</summary><button id="folded">Folded</button></details><div id="contents" style="display:contents"><button>Child</button></div><div id="text" style="display:contents">Text</div><div id="hidden-text" style="display:contents;visibility:hidden">Text</div><div id="skip" style="content-visibility:hidden;width:20px;height:20px"><button id="skipped">Skipped</button></div><button id="transparent" style="opacity:0">Transparent</button><div id="zero" style="width:0;height:0"></div>';true"#,"returnByValue":true})),Some(session)).await?;
            for (selector,hidden,has_rect) in [("#summary",false,true),("#folded",true,true),("#contents",false,false),("#text",false,false),("#hidden-text",true,false),("#skip",false,true),("#skipped",true,true),("#transparent",false,true),("#zero",true,true)] {
                let options:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"selector","selector":selector}})).unwrap();
                let found=query(&mgr.client,&frames,&mut refs,"fixture",5,&options,&lease).await?;
                let node=found.nodes.first().ok_or("Visibility fixture missing")?;
                if node.states.get("hidden")!=Some(&hidden){return Err(format!("Visibility differs for {selector}"));}
                if node.rect.is_some()!=has_rect{return Err(format!("Layout box differs for {selector}"));}
            }
            // Match the public line-text contract without inferring actionability
            // from arbitrary addEventListener registrations or executing handlers.
            mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":r#"document.body.innerHTML='<p>Use <span id="attribute-endpoint" onclick="">attribute</span>, <span id="property-endpoint">property</span>, <span id="tabindex-endpoint" tabindex="-1">tabindex</span>, and <span id="listener-only">listener</span>.</p>'; document.getElementById('property-endpoint').onclick=()=>undefined; document.getElementById('listener-only').addEventListener('click',()=>undefined); true"#,"returnByValue":true})),Some(session)).await?;
            let tree=observe(&mgr.client,&frames,&mut refs,"fixture",6,&ObservationOptions::default(),&lease).await?;
            let mut pending=tree.roots.iter().collect::<Vec<_>>();
            let mut emitted=HashMap::new();
            while let Some(node)=pending.pop(){emitted.insert(fixture_exact_identity(&refs,&node.reference.id)?,node.reference.id.clone());pending.extend(node.children.iter());}
            for (ordinal,selector,wanted) in [(0,"#attribute-endpoint",true),(1,"#property-endpoint",true),(2,"#tabindex-endpoint",true),(3,"#listener-only",false)] {
                let options:QueryOptions=serde_json::from_value(json!({"expression":{"kind":"selector","selector":selector}})).unwrap();
                let found=query(&mgr.client,&frames,&mut refs,"fixture",6,&options,&lease).await?;
                let node=found.nodes.first().ok_or("Inline endpoint exact query missing")?;
                let identity=fixture_exact_identity(&refs,&node.reference.id)?;
                let observed_id=emitted.get(&identity);
                let included=observed_id.is_some();
                if observed_id==Some(&node.reference.id){return Err("Strict endpoint query reused observed authority ID".into());}
                if included!=wanted{return Err(format!("Inline endpoint ordinal={ordinal} included={included} expected={wanted}"));}
            }
            Ok::<(),String>(())
        }.await;
        let close = execute_command(
            &json!({"id":"observation-close","action":"close"}),
            &mut state,
        )
        .await;
        assert_eq!(close["success"], true, "{close}");
        run.unwrap();
    }
    #[tokio::test]
    #[ignore = "requires real Chromium; coordinate convention probe, not full geometry acceptance"]
    async fn chromium_native_same_process_frame_coordinate_convention() {
        use super::super::actions::{execute_command, DaemonState};
        let mut state = DaemonState::new();
        let launch = execute_command(
            &json!({"id":"geometry-launch","action":"launch","headless":true}),
            &mut state,
        )
        .await;
        assert_eq!(launch["success"], true, "{launch}");
        let result = async {
            let mgr = state.browser.as_ref().ok_or("Missing browser")?;
            let session = mgr.active_session_id()?;
            let setup = mgr.client.send_command("Runtime.evaluate", Some(json!({
                "expression": r#"new Promise(resolve=>{document.body.style.cssText='margin:0;height:3000px';const f=document.createElement('iframe');f.id='geometry-frame';f.style.cssText='position:absolute;left:100px;top:150px;width:200px;height:150px;border:10px solid black;transform:scale(2);transform-origin:0 0';f.onload=()=>resolve(true);f.srcdoc='<body style="margin:0;height:2000px"><button id="target" style="position:absolute;left:20px;top:30px;width:40px;height:25px;border:0;padding:0">Probe</button>';document.body.appendChild(f);})"#,
                "awaitPromise":true,"returnByValue":true
            })), Some(session)).await?;
            if setup.get("exceptionDetails").is_some() { return Err("Coordinate fixture failed".to_string()); }
            let resolved = mgr.client.send_command("Runtime.evaluate", Some(json!({
                "expression":"document.querySelector('#geometry-frame').contentDocument.querySelector('#target')",
                "returnByValue":false,"objectGroup":"native-coordinate-probe"
            })), Some(session)).await?;
            let object = resolved["result"]["objectId"].as_str().ok_or("No fixture node")?;
            for (scrolled, expected_y) in [(false,230.0),(true,130.0)] {
                if scrolled {
                    let scroll = mgr.client.send_command("Runtime.evaluate", Some(json!({
                        "expression":"window.scrollTo(0,80);document.querySelector('#geometry-frame').contentWindow.scrollTo(0,10);[scrollY,document.querySelector('#geometry-frame').contentWindow.scrollY]",
                        "returnByValue":true
                    })),Some(session)).await?;
                    if scroll["result"]["value"] != json!([80,10]) { return Err("Synthetic scroll did not settle".into()); }
                }
                let box_model=mgr.client.send_command("DOM.getBoxModel",Some(json!({"objectId":object})),Some(session)).await?;
                let quads=mgr.client.send_command("DOM.getContentQuads",Some(json!({"objectId":object})),Some(session)).await?;
                let expected=[160.0,expected_y,240.0,expected_y,240.0,expected_y+50.0,160.0,expected_y+50.0];
                for quad in [&box_model["model"]["border"],&quads["quads"][0]] {
                    let points=quad.as_array().ok_or("Native quad unavailable")?;
                    if points.len()!=8 || points.iter().zip(expected).any(|(actual,want)|actual.as_f64().is_none_or(|value|(value-want).abs()>0.5)) {
                        return Err(format!("Native quad convention differs: {quad}; expected {expected:?}"));
                    }
                }
            }
            mgr.client.send_command("Runtime.releaseObjectGroup",Some(json!({"objectGroup":"native-coordinate-probe"})),Some(session)).await?;
            Ok::<(),String>(())
        }.await;
        let close =
            execute_command(&json!({"id":"geometry-close","action":"close"}), &mut state).await;
        assert_eq!(close["success"], true, "{close}");
        result.unwrap();
    }
    #[test]
    fn sibling_order_follows_child_ids_not_ax_array_order() {
        let order = vec![
            ax("second", 3, &[]),
            ax("first", 2, &[]),
            ax("root", 1, &["first", "second"]),
        ];
        let mut refs = observed_refs();
        let mut nodes = HashMap::new();
        for a in &order {
            nodes.insert(
                a.node_id.clone(),
                project_node(
                    &frame(),
                    a.backend_d_o_m_node_id.unwrap(),
                    a,
                    &mut refs,
                    1,
                    &metadata(),
                    true,
                )
                .unwrap(),
            );
        }
        let forest = assemble_forest(&order, nodes).unwrap();
        assert_eq!(forest[0].children[0].reference.id, "@e2");
        assert_eq!(forest[0].children[1].reference.id, "@e1");
    }
    #[test]
    fn query_frame_wrappers_lift_through_index_and_scope() {
        let expr:LocatorExpression=serde_json::from_value(json!({"kind":"index","index":"last","source":{"kind":"frame","selector":"#child","source":{"kind":"selector","selector":"button"}}})).unwrap();
        let (path, inner) = split_frame_expression(&expr).unwrap();
        assert_eq!(path, vec!["#child"]);
        assert!(matches!(inner, LocatorExpression::Index { .. }));
        let bad:LocatorExpression=serde_json::from_value(json!({"kind":"query","query":{"kind":"role","value":{"kind":"regexp","source":".*","flags":""}}})).unwrap();
        assert!(validate_expression(&bad, 0).is_err());
        assert!(serde_json::from_value::<QueryOptions>(json!({"expression":{"kind":"query","query":{"kind":"role","states":{"script":true},"value":{"kind":"string","value":"button","exact":true}}}})).is_err());
    }
    #[test]
    fn diagnostic_labels_never_echo_renderer_source() {
        assert_eq!(
            diagnostic_site(&json!({"functionDeclaration": METADATA})),
            "metadata-single"
        );
        assert_eq!(
            diagnostic_site(
                &json!({"functionDeclaration": format!("function(testId,secureSelector,...nodes) {{ const read={METADATA}; return nodes.map(node=>read.call(node,testId,secureSelector)); }}")})
            ),
            "metadata-batch"
        );
        assert_eq!(
            diagnostic_site(
                &json!({"functionDeclaration":"function(selector,...roots){ synthetic-private-data }"})
            ),
            "security-inventory"
        );
        assert_eq!(
            diagnostic_site(&json!({"functionDeclaration":"synthetic-private-data"})),
            "other-native-command"
        );
    }
    #[test]
    fn metadata_acquisition_policy_follows_mixed_native_receivers_not_pseudo_identity() {
        let element = ax("element", 42, &[]);
        let protected_pseudo = ax("protected-pseudo", 3, &[]);
        let public_pseudo = ax("public-pseudo", 4, &[]);
        let nodes = [&element, &protected_pseudo, &public_pseudo];
        let origins = [None, Some(45), Some(46)];
        let policy = SecurityInventory {
            ancestors: std::collections::HashSet::from([42, 45, 4]),
            ..Default::default()
        };
        assert_eq!(
            metadata_receiver_protection(&nodes, &origins, &policy).unwrap(),
            vec![true, true, false]
        );
        assert_eq!(
            nodes
                .iter()
                .map(|node| node.backend_d_o_m_node_id)
                .collect::<Vec<_>>(),
            vec![Some(42), Some(3), Some(4)]
        );
        assert!(metadata_receiver_protection(&nodes, &origins[..2], &policy).is_err());
    }

    #[test]
    fn hint_collection_preserves_cleanup_failure_after_primary() {
        assert_eq!(
            collect_hint_results::<bool>(vec![
                Err(ObservationError::BackendFailure),
                Err(ObservationError::CleanupFailed { primary: None })
            ]),
            Err(ObservationError::CleanupFailed {
                primary: Some(Box::new(ObservationError::BackendFailure))
            })
        );
    }

    #[tokio::test]
    async fn onclick_sibling_failure_drains_held_resolution_and_cleanup() {
        use futures_util::{stream, SinkExt, StreamExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut held = None;
            let mut pending_failure = None;
            let mut released = 0;
            while let Some(Ok(message)) = socket.next().await {
                let Ok(text) = message.to_text() else {
                    continue;
                };
                let request: Value = serde_json::from_str(text).unwrap();
                let result = match request["method"].as_str().unwrap() {
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"main","loaderId":"doc"}}})
                    }
                    "DOM.resolveNode" => {
                        if request["params"]["backendNodeId"] == 43 {
                            held = Some(request["id"].clone());
                            if let Some(id) = pending_failure.take() {
                                socket
                                    .send(tokio_tungstenite::tungstenite::Message::Text(
                                        json!({"id":id,"result":{"exceptionDetails":{}}})
                                            .to_string(),
                                    ))
                                    .await
                                    .unwrap();
                            }
                            continue;
                        }
                        json!({"object":{"type":"object","subtype":"node","objectId":"main-42"}})
                    }
                    "DOM.describeNode" => {
                        json!({"node":{"nodeType":1,"backendNodeId":if request["params"]["objectId"]=="main-42"{42}else{43}}})
                    }
                    "Runtime.callFunctionOn" => {
                        if request["params"]["objectId"] == "main-42" {
                            if held.is_none() {
                                pending_failure = Some(request["id"].clone());
                                continue;
                            }
                            json!({"exceptionDetails":{}})
                        } else {
                            json!({"result":{"type":"boolean","value":true}})
                        }
                    }
                    "Runtime.releaseObjectGroup" => {
                        released += 1;
                        if released == 1 {
                            let id = held.take().expect("sibling resolution must be in flight");
                            socket.send(tokio_tungstenite::tungstenite::Message::Text(json!({"id":id,"result":{"object":{"type":"object","subtype":"node","objectId":"main-43"}}}).to_string())).await.unwrap();
                        }
                        json!({})
                    }
                    method => panic!("unexpected sibling command {method}"),
                };
                socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        json!({"id":request["id"],"result":result}).to_string(),
                    ))
                    .await
                    .unwrap();
                if released == 2 {
                    break;
                }
            }
            assert_eq!(released, 2);
        });
        let client = CdpClient::connect(&url).await.unwrap();
        let (lease, _sender) = lease();
        let frame = frame();
        let results = stream::iter(
            [42, 43]
                .into_iter()
                .map(|backend| main_onclick_hint(&client, &frame, backend, "isolated", &lease)),
        )
        .buffered(16)
        .collect::<Vec<_>>()
        .await;
        assert_eq!(
            collect_hint_results(results),
            Err(ObservationError::BackendFailure)
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn main_onclick_hint_is_boolean_only_exact_and_always_cleans_up() {
        use futures_util::{SinkExt, StreamExt};
        for mode in [
            "true",
            "false",
            "exception",
            "shape",
            "unsupported",
            "receiver",
            "loader",
            "cleanup",
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut reads = 0;
                let mut handles = Vec::new();
                while let Some(Ok(message)) = socket.next().await {
                    let Ok(text) = message.to_text() else {
                        continue;
                    };
                    let request: Value = serde_json::from_str(text).unwrap();
                    assert_eq!(request["sessionId"], "renderer");
                    let method = request["method"].as_str().unwrap();
                    let mut error = false;
                    let result = match method {
                        "Page.getFrameTree" => {
                            json!({"frameTree":{"frame":{"id":"main","loaderId":if mode=="loader"{"retired"}else{"doc"}}}})
                        }
                        "DOM.resolveNode" => {
                            assert_eq!(request["params"]["backendNodeId"], 42);
                            assert!(request["params"].get("executionContextId").is_none());
                            assert!(request["params"]["objectGroup"]
                                .as_str()
                                .unwrap()
                                .starts_with("native-onclick-"));
                            json!({"object":{"type":"object","subtype":"node","objectId":"main-node"}})
                        }
                        "DOM.describeNode" => {
                            assert_eq!(request["params"]["objectId"], "main-node");
                            json!({"node":{"backendNodeId":if mode=="receiver"{43}else{42},"nodeType":1}})
                        }
                        "Runtime.callFunctionOn" => {
                            assert_eq!(request["params"]["throwOnSideEffect"], true);
                            assert_eq!(request["params"]["returnByValue"], true);
                            if request["params"]["objectId"] == "isolated-node" {
                                assert_eq!(
                                    request["params"]["functionDeclaration"],
                                    EXACT_HINT_RECEIVER
                                );
                                json!({"result":{"type":"boolean","value":true}})
                            } else {
                                reads += 1;
                                assert_eq!(request["params"]["objectId"], "main-node");
                                assert_eq!(
                                    request["params"]["functionDeclaration"],
                                    MAIN_ONCLICK_HINT
                                );
                                match mode {
                                    "exception" => {
                                        json!({"exceptionDetails":{"exception":{"objectId":"exception-handle"}}})
                                    }
                                    "shape" => {
                                        json!({"result":{"type":"object","objectId":"result-handle","value":true}})
                                    }
                                    "unsupported" => {
                                        error = true;
                                        json!({})
                                    }
                                    _ => json!({"result":{"type":"boolean","value":mode!="false"}}),
                                }
                            }
                        }
                        "Runtime.releaseObject" => {
                            handles
                                .push(request["params"]["objectId"].as_str().unwrap().to_owned());
                            json!({})
                        }
                        "Runtime.releaseObjectGroup" => {
                            error = mode == "cleanup";
                            json!({})
                        }
                        _ => panic!("unexpected hint command {method}"),
                    };
                    let response = if error {
                        json!({"id":request["id"],"error":{"code":-32602,"message":"refused"}})
                    } else {
                        json!({"id":request["id"],"result":result})
                    };
                    socket
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            response.to_string(),
                        ))
                        .await
                        .unwrap();
                    if method == "Runtime.releaseObjectGroup" {
                        break;
                    }
                }
                assert_eq!(
                    reads,
                    if matches!(mode, "loader" | "receiver") {
                        0
                    } else {
                        1
                    }
                );
                assert_eq!(
                    handles,
                    match mode {
                        "exception" => vec!["exception-handle"],
                        "shape" => vec!["result-handle"],
                        _ => vec![],
                    }
                );
            });
            let client = CdpClient::connect(&url).await.unwrap();
            let (lease, _sender) = lease();
            let result = main_onclick_hint(&client, &frame(), 42, "isolated-node", &lease).await;
            match mode {
                "true" => assert_eq!(result, Ok(true)),
                "false" => assert_eq!(result, Ok(false)),
                "receiver" | "loader" => assert_eq!(result, Err(ObservationError::StaleReference)),
                "cleanup" => assert_eq!(
                    result,
                    Err(ObservationError::CleanupFailed { primary: None })
                ),
                _ => assert_eq!(result, Err(ObservationError::BackendFailure)),
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn metadata_batch_keeps_remote_arguments_in_native_candidate_order() {
        use futures_util::{SinkExt, StreamExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                let Ok(text) = message.to_text() else {
                    continue;
                };
                let request: Value = serde_json::from_str(text).unwrap();
                let result = match request["method"].as_str().unwrap() {
                    "Page.createIsolatedWorld" => json!({"executionContextId":17}),
                    "DOM.resolveNode" => {
                        assert_eq!(request["params"]["executionContextId"], 17);
                        let backend = request["params"]["backendNodeId"].as_i64().unwrap();
                        json!({"object":{"type":"object","subtype":"node","objectId":format!("native-{backend}")}})
                    }
                    "Runtime.callFunctionOn" => {
                        assert_eq!(request["params"]["objectId"], "native-42");
                        assert_eq!(
                            request["params"]["arguments"],
                            json!([
                                {"value":"data-testid"},{"value":"input[type=\"password\" i]"},
                                {"objectId":"native-42"},{"objectId":"native-43"}
                            ])
                        );
                        assert_eq!(diagnostic_site(&request["params"]), "metadata-batch");
                        assert!(request["params"]["functionDeclaration"]
                            .as_str()
                            .unwrap()
                            .contains("const protectedEditors=[true,false]"));
                        json!({"result":{"type":"object","value":[metadata(),metadata()]}})
                    }
                    "Runtime.releaseObjectGroup" => json!({}),
                    _ => panic!("unexpected metadata command"),
                };
                socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        json!({"id":request["id"],"result":result}).to_string(),
                    ))
                    .await
                    .unwrap();
                if request["method"] == "Runtime.releaseObjectGroup" {
                    break;
                }
            }
        });
        let client = CdpClient::connect(&url).await.unwrap();
        let (lease, _sender) = lease();
        let mut refs = observed_refs();
        let one = ax("first", 42, &[]);
        let two = ax("second", 43, &[]);
        let nodes = read_batch(
            &client,
            &frame(),
            &[&one, &two],
            &mut refs,
            1,
            &ObservationOptions::default(),
            &lease,
            true,
            &SecurityInventory {
                ancestors: std::collections::HashSet::from([42]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(nodes.len(), 2);
        assert_ne!(nodes[0].reference.id, nodes[1].reference.id);
        server.await.unwrap();
    }
    #[test]
    fn observation_preserves_href_elision_markers_but_full_read_keeps_raw_attribute() {
        let mut data = metadata();
        // The former markerless expectation contradicted the original public
        // href contract. Shared JS tests exercise actual METADATA reduction;
        // this unit checks that Rust preserves its already-protected result.
        data["attributes"]["href"] = json!("https://fixture.invalid/path?…#…");
        let mut refs = observed_refs();
        let observed =
            project_node(&frame(), 1, &ax("a", 1, &[]), &mut refs, 1, &data, true).unwrap();
        assert_eq!(
            observed.attributes["href"],
            "https://fixture.invalid/path?…#…"
        );
        let raw = "https://fixture.invalid/path?token=synthetic-token#secret";
        data["attributes"]["href"] = json!(raw);
        let full = project_node(&frame(), 1, &ax("a", 1, &[]), &mut refs, 1, &data, false).unwrap();
        assert_eq!(full.attributes["href"], raw);
    }
    #[test]
    fn secure_shadow_text_and_ancestor_names_never_serialize() {
        let mut data = metadata();
        data["states"]["secure"] = json!(true);
        data["redactName"] = json!(true);
        let mut text = ax("secret", 2, &[]);
        text.name.as_mut().unwrap().value = Some(json!("synthetic-shadow-secret"));
        let mut refs = observed_refs();
        let child = project_node(&frame(), 2, &text, &mut refs, 1, &data, false).unwrap();
        assert!(child.name.is_none());
        let mut parent = SemanticNode {
            name: Some("synthetic-shadow-secret".into()),
            text: Some("synthetic-shadow-secret".into()),
            children: vec![child],
            ..Default::default()
        };
        assert!(scrub_sensitive_ancestors(&mut parent));
        assert!(!serde_json::to_string(&parent)
            .unwrap()
            .contains("synthetic-shadow-secret"));
        let mut labelled = SemanticNode {
            name: Some("synthetic-shadow-secret".into()),
            attributes: BTreeMap::from([("aria-labelledby".into(), "closed-host".into())]),
            ..Default::default()
        };
        let security = SecurityInventory {
            browser_internal: Default::default(),
            simple_name_inventory: false,
            ancestors: Default::default(),
            label_ids: std::collections::HashSet::from(["closed-host".into()]),
        };
        apply_security(&mut labelled, 9, &security);
        assert!(labelled.name.is_none());
    }
    #[test]
    fn security_inventory_bounds_dom_depth_and_root_count() {
        let mut deep = json!({"nodeType":1,"backendNodeId":9});
        for _ in 0..257 {
            deep = json!({"nodeType":1,"children":[deep]});
        }
        let deep = json!({"nodeType":9,"backendNodeId":1,"children":[deep]});
        assert!(security_root_ids(&deep).is_err());
        assert!(bounded_dom_ids(&deep, &[1], 100_000).is_err());
        let wide = json!({"nodeType":9,"backendNodeId":1,"shadowRoots":
            (0..10_000).map(|i|json!({"nodeType":11,"backendNodeId":i+2})).collect::<Vec<_>>()});
        assert!(security_root_ids(&wide).is_err());
        let valid = json!({"nodeType":9,"backendNodeId":1,"children":[
            {"nodeType":1,"shadowRoots":[{"nodeType":11,"backendNodeId":2}]}]});
        assert_eq!(security_root_ids(&valid).unwrap(), vec![1, 2]);
    }
    #[test]
    fn secure_ancestor_uses_only_sanitized_public_name_not_ax_content() {
        let mut data = metadata();
        data["safePublicName"] = json!("Unlock now");
        data["secureDescendants"] = json!(true);
        data["text"] = json!("Unlock now");
        let mut refs = observed_refs();
        let mut node = project_node(
            &frame(),
            2,
            &ax("synthetic-secret", 2, &[]),
            &mut refs,
            1,
            &data,
            false,
        )
        .unwrap();
        apply_security(
            &mut node,
            2,
            &SecurityInventory {
                browser_internal: Default::default(),
                simple_name_inventory: false,
                ancestors: std::collections::HashSet::from([2]),
                label_ids: Default::default(),
            },
        );
        assert_eq!(node.name.as_deref(), Some("Unlock now"));
        assert!(node.text.is_none());
        assert!(!serde_json::to_string(&node)
            .unwrap()
            .contains("synthetic-secret"));
        assert!(!serde_json::to_string(&node)
            .unwrap()
            .contains("safePublicName"));
        let mut unproved = SemanticNode {
            name: Some("synthetic-secret".into()),
            ..Default::default()
        };
        scrub_ancestor_content(&mut unproved);
        assert!(unproved.name.is_none());
    }
    #[test]
    fn secure_inventory_keeps_public_password_labels_without_value() {
        let mut data = metadata();
        data["states"]["secure"] = json!(true);
        data["labels"] = json!(["Password"]);
        data["value"] = json!("synthetic-secret");
        let mut refs = observed_refs();
        let mut node = project_node(
            &frame(),
            2,
            &ax("password", 2, &[]),
            &mut refs,
            1,
            &data,
            false,
        )
        .unwrap();
        apply_security(
            &mut node,
            2,
            &SecurityInventory {
                browser_internal: Default::default(),
                simple_name_inventory: false,
                ancestors: std::collections::HashSet::from([2]),
                label_ids: Default::default(),
            },
        );
        assert_eq!(node.labels, vec!["Password"]);
        assert!(node.value.is_none());
    }
    #[test]
    fn observation_attributes_are_bounded_but_explicit_read_preserves_them() {
        let mut data = metadata();
        data["attributes"] =
            json!({"data-private":"synthetic-secret","aria-label":"Public","placeholder":"Public"});
        let mut refs = observed_refs();
        let observed =
            project_node(&frame(), 2, &ax("a", 2, &[]), &mut refs, 1, &data, true).unwrap();
        assert!(!observed.attributes.contains_key("data-private"));
        assert_eq!(observed.attributes["aria-label"], "Public");
        let read = project_node(&frame(), 2, &ax("a", 2, &[]), &mut refs, 1, &data, false).unwrap();
        assert_eq!(read.attributes["data-private"], "synthetic-secret");
    }
    #[test]
    fn exact_reference_exhaustion_returns_error_without_publishing() {
        let mut refs = observed_refs();
        refs.set_next_ref_num(usize::MAX);
        assert!(project_node(
            &frame(),
            2,
            &ax("a", 2, &[]),
            &mut refs,
            1,
            &metadata(),
            true
        )
        .is_err());
        assert_eq!(refs.next_ref_num(), usize::MAX);
        assert!(refs
            .durable_ref(
                &frame().binding.page_session,
                Some(&frame().binding.frame),
                2
            )
            .is_none());
    }
    fn hidden_proof_frames() -> Vec<ObservationFrame> {
        let parent = frame();
        let mut child = parent.clone();
        child.binding.frame = "child".into();
        child.binding.loader = "child-doc".into();
        child.parent_frame_id = Some("main".into());
        child.owner_backend_id = Some(42);
        let mut nested = child.clone();
        nested.binding.frame = "nested".into();
        nested.binding.loader = "nested-doc".into();
        nested.parent_frame_id = Some("child".into());
        nested.owner_backend_id = Some(43);
        vec![parent, child, nested]
    }
    #[test]
    fn hidden_frame_proof_requires_exact_inventory_and_positive_descendant_closure() {
        let frames = hidden_proof_frames();
        let mut proof = HiddenFrameProof::for_test(&frames, &["child"]);
        assert_eq!(
            proof.excluded_frames(),
            &std::collections::HashSet::from(["child".into(), "nested".into()])
        );
        proof.validate_inventory(&frames).unwrap();
        for field in ["loader", "owner", "parent"] {
            let mut changed = frames.clone();
            match field {
                "loader" => changed[1].binding.loader = "replaced".into(),
                "owner" => changed[1].owner_backend_id = Some(44),
                _ => changed[2].parent_frame_id = Some("main".into()),
            }
            assert!(proof.validate_inventory(&changed).is_err());
        }
        assert!(proof.validate_inventory(&frames[..2]).is_err());
        proof.excluded.remove("nested");
        assert!(proof.validate_inventory(&frames).is_err());
        assert!(HiddenFrameProof::for_test(&frames, &[])
            .excluded_frames()
            .is_empty());
    }
    #[tokio::test]
    async fn hidden_frame_proof_rechecks_owner_visibility_and_always_settles_group() {
        use futures_util::{SinkExt, StreamExt};
        for mode in [
            "hidden",
            "visible",
            "owner",
            "loader",
            "malformed",
            "exception",
            "cleanup",
            "cleanup-primary",
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut metadata = false;
                while let Some(Ok(message)) = socket.next().await {
                    let Ok(text) = message.to_text() else {
                        continue;
                    };
                    let request: Value = serde_json::from_str(text).unwrap();
                    assert_eq!(request["sessionId"], "renderer");
                    let method = request["method"].as_str().unwrap();
                    let result = match method {
                        "Page.getFrameTree" => {
                            json!({"frameTree":{"frame":{"id":"main","loaderId":"doc"},"childFrames":[{"frame":{"id":"child","loaderId":if mode=="loader"{"changed"}else{"child-doc"}}}]}})
                        }
                        "DOM.getFrameOwner" => {
                            assert_eq!(request["params"]["frameId"], "child");
                            json!({"backendNodeId":if mode=="owner"{44}else{42}})
                        }
                        "Page.createIsolatedWorld" => {
                            assert_eq!(request["params"]["frameId"], "main");
                            json!({"executionContextId":17})
                        }
                        "DOM.resolveNode" => {
                            assert_eq!(request["params"]["backendNodeId"], 42);
                            assert_eq!(request["params"]["executionContextId"], 17);
                            json!({"object":{"type":"object","subtype":"node","objectId":"exact-owner"}})
                        }
                        "Runtime.callFunctionOn" => {
                            metadata = true;
                            assert_eq!(request["params"]["objectId"], "exact-owner");
                            assert_eq!(request["params"]["returnByValue"], true);
                            let function =
                                request["params"]["functionDeclaration"].as_str().unwrap();
                            assert!(function.contains(METADATA));
                            assert!(function.contains("true,true,false"));
                            if mode == "exception" {
                                json!({"exceptionDetails":{"exception":{"objectId":"owned-exception"}}})
                            } else {
                                json!({"result":{"type":"object","value":{"nodeType":1,"tag":"iframe","hidden":if mode=="malformed"{json!("true")}else{json!(!matches!(mode,"visible"|"cleanup-primary"))}}}})
                            }
                        }
                        "Runtime.releaseObjectGroup" => json!({}),
                        _ => panic!("unexpected hidden proof command {method}"),
                    };
                    let response = if method == "Runtime.releaseObjectGroup"
                        && matches!(mode, "cleanup" | "cleanup-primary")
                    {
                        json!({"id":request["id"],"error":{"code":-32000,"message":"cleanup refused"}})
                    } else {
                        json!({"id":request["id"],"result":result})
                    };
                    socket
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            response.to_string(),
                        ))
                        .await
                        .unwrap();
                    if method == "Runtime.releaseObjectGroup" {
                        break;
                    }
                }
                assert_eq!(metadata, !matches!(mode, "owner" | "loader"));
            });
            let client = CdpClient::connect(&url).await.unwrap();
            let (lease, _sender) = lease();
            let proof = HiddenFrameProof::for_test(&hidden_proof_frames(), &["child"]);
            let result = proof.revalidate(&client, &lease).await;
            match mode {
                "hidden" => assert_eq!(result, Ok(())),
                "visible" | "owner" | "loader" => {
                    assert_eq!(result, Err(ObservationError::StaleReference))
                }
                "cleanup" => assert_eq!(
                    result,
                    Err(ObservationError::CleanupFailed { primary: None })
                ),
                "cleanup-primary" => assert_eq!(
                    result,
                    Err(ObservationError::CleanupFailed {
                        primary: Some(Box::new(ObservationError::StaleReference))
                    })
                ),
                _ => assert_eq!(result, Err(ObservationError::BackendFailure)),
            }
            server.await.unwrap();
        }
    }

    #[test]
    fn revision_wire_preserves_full_native_integer_precision() {
        let observation = Observation {
            hidden_frame_proof: HiddenFrameProof::default(),
            identity_scope: "scope".into(),
            revision: u64::MAX,
            roots: vec![],
            viewport_ref: NodeReference {
                id: "@e1".into(),
                revision: u64::MAX.to_string(),
            },
            truncated: false,
        };
        let encoded = serde_json::to_value(&observation).unwrap();
        assert_eq!(encoded["revision"], u64::MAX.to_string());
        assert!(encoded.get("hiddenFrameProof").is_none());
        assert_eq!(
            serde_json::from_value::<Observation>(encoded.clone())
                .unwrap()
                .revision,
            u64::MAX
        );
        let mut numeric = encoded.clone();
        numeric["revision"] = json!(42);
        assert!(serde_json::from_value::<Observation>(numeric).is_err());
        let mut noncanonical = encoded;
        noncanonical["revision"] = json!("042");
        assert!(serde_json::from_value::<Observation>(noncanonical).is_err());
        let query = QueryResult {
            identity_scope: "scope".into(),
            revision: u64::MAX,
            nodes: vec![],
        };
        assert_eq!(
            serde_json::to_value(query).unwrap()["revision"],
            u64::MAX.to_string()
        );
    }
    fn node_with_public_states(value: bool) -> SemanticNode {
        SemanticNode {
            reference: NodeReference {
                id: "@e42".into(),
                revision: u64::MAX.to_string(),
            },
            states: [
                "disabled", "focused", "hidden", "secure", "checked", "selected", "expanded",
                "pressed",
            ]
            .into_iter()
            .map(|name| (name.into(), value))
            .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn public_state_serialization_preserves_raw_flags_and_explicit_false_controls() {
        let node = node_with_public_states(false);
        let raw_states = node.states.clone();
        let encoded = serde_json::to_value(&node).unwrap();
        assert_eq!(
            encoded["states"],
            json!({"checked":false,"selected":false,"expanded":false,"pressed":false})
        );
        assert_eq!(
            encoded["ref"],
            serde_json::to_value(&node.reference).unwrap()
        );
        assert_eq!(node.states, raw_states);
        for flag in ["disabled", "focused", "hidden", "secure"] {
            assert_eq!(node.states.get(flag), Some(&false));
        }
        // Deserialization still accepts complete native facts; omission is
        // exclusively a serialization choice, not a mutation of input data.
        let mut complete = encoded;
        complete["states"] = serde_json::to_value(&raw_states).unwrap();
        assert_eq!(
            serde_json::from_value::<SemanticNode>(complete)
                .unwrap()
                .states,
            raw_states
        );
    }

    #[test]
    fn public_state_serialization_keeps_nonstandard_false_states() {
        let mut node = SemanticNode::default();
        node.states.insert("readonly".into(), false);
        node.states.insert("required".into(), false);
        node.states.insert("customFlag".into(), false);
        assert_eq!(
            serde_json::to_value(&node).unwrap()["states"],
            serde_json::to_value(&node.states).unwrap()
        );
    }

    #[test]
    fn public_state_serialization_preserves_all_true_flags_and_empty_maps() {
        let node = node_with_public_states(true);
        assert_eq!(
            serde_json::to_value(&node).unwrap()["states"],
            serde_json::to_value(&node.states).unwrap()
        );
        assert_eq!(
            serde_json::to_value(SemanticNode::default()).unwrap()["states"],
            json!({})
        );
    }

    #[test]
    fn observation_query_and_exact_read_share_public_state_serialization() {
        let mut node = node_with_public_states(false);
        node.children.push(node_with_public_states(false));
        let expected = serde_json::to_value(&node).unwrap();
        let observation = Observation {
            hidden_frame_proof: HiddenFrameProof::default(),
            identity_scope: "scope".into(),
            revision: u64::MAX,
            roots: vec![node.clone()],
            viewport_ref: NodeReference {
                id: "@viewport".into(),
                revision: u64::MAX.to_string(),
            },
            truncated: false,
        };
        let query = QueryResult {
            identity_scope: "scope".into(),
            revision: u64::MAX,
            nodes: vec![node.clone()],
        };
        assert_eq!(
            serde_json::to_value(observation).unwrap()["roots"][0],
            expected
        );
        assert_eq!(serde_json::to_value(query).unwrap()["nodes"][0], expected);
        assert_eq!(project_read_fields(node, None).unwrap(), expected);
        assert_eq!(expected["children"][0]["states"], expected["states"]);
    }

    #[test]
    fn selected_read_states_share_public_projection_and_keep_exact_reference() {
        let mut node = node_with_public_states(false);
        node.name = Some("Save".into());
        let expected_ref = serde_json::to_value(&node.reference).unwrap();
        assert_eq!(
            project_read_fields(node.clone(), Some(&[ReadField::States])).unwrap(),
            json!({"ref":expected_ref,"states":{
                "checked":false,"selected":false,"expanded":false,"pressed":false
            }})
        );
        assert_eq!(
            project_read_fields(node, Some(&[ReadField::Name])).unwrap(),
            json!({"ref":expected_ref,"name":"Save"})
        );
    }

    #[test]
    fn selected_secure_read_states_preserve_policy_flags_and_redaction() {
        let mut node = node_with_public_states(false);
        node.states.insert("secure".into(), true);
        node.states.insert("focused".into(), true);
        node.value = Some("synthetic-secret".into());
        node.text = Some("synthetic-secret".into());
        node.selection = Some("synthetic-secret".into());
        node.attributes
            .insert("value".into(), "synthetic-secret".into());
        let expected_ref = serde_json::to_value(&node.reference).unwrap();
        let selected = project_read_fields(
            node,
            Some(&[
                ReadField::States,
                ReadField::Value,
                ReadField::Text,
                ReadField::Selection,
                ReadField::Attributes,
            ]),
        )
        .unwrap();
        assert_eq!(
            selected,
            json!({"ref":expected_ref,"states":{
                "secure":true,"focused":true,
                "checked":false,"selected":false,"expanded":false,"pressed":false
            },"attributes":{}})
        );
    }

    #[test]
    fn selected_secure_read_retains_policy_metadata_not_an_empty_value() {
        let node = SemanticNode {
            reference: NodeReference {
                id: "@e1".into(),
                revision: "1".into(),
            },
            value: Some("synthetic-secret".into()),
            states: BTreeMap::from([("secure".into(), true), ("focused".into(), true)]),
            ..Default::default()
        };
        let value = project_read_fields(node, Some(&[ReadField::Value])).unwrap();
        assert_eq!(value["states"], json!({"secure":true}));
        assert!(value.get("value").is_none());
        assert!(value.get("ref").is_some());
    }
    #[test]
    fn schema_rejects_unknown_nested_query_fields() {
        let good = json!({"expression":{"kind":"query","query":{"kind":"role","value":{"kind":"string","value":"button","exact":true}}}});
        assert!(serde_json::from_value::<QueryOptions>(good.clone()).is_ok());
        let mut bad = good;
        bad["expression"]["query"]["value"]["script"] = json!("bad");
        assert!(serde_json::from_value::<QueryOptions>(bad).is_err());
        assert!(
            serde_json::from_value::<ReadOptions>(json!({"ref":"@e1","fields":["password"]}))
                .is_err()
        );
    }
    #[test]
    fn projection_redacts_secure_even_if_renderer_returns_value() {
        let mut data = metadata();
        data["states"]["secure"] = json!(true);
        data["value"] = json!("synthetic-secret");
        data["text"] = json!("synthetic-secret");
        data["selection"] = json!("synthetic-secret");
        data["attributes"]["value"] = json!("synthetic-secret");
        let node = project_node(
            &frame(),
            42,
            &ax("a", 42, &[]),
            &mut observed_refs(),
            1,
            &data,
            true,
        )
        .unwrap();
        assert!(!serde_json::to_string(&node)
            .unwrap()
            .contains("synthetic-secret"));
        assert_eq!(node.states.get("secure"), Some(&true));
        assert_eq!(node.rect.unwrap().x, 11.0);
    }
    #[test]
    fn shuffled_tree_keeps_real_parent_and_children() {
        let order = vec![ax("child", 2, &[]), ax("root", 1, &["child"])];
        let mut refs = observed_refs();
        let mut nodes = HashMap::new();
        for a in &order {
            nodes.insert(
                a.node_id.clone(),
                project_node(
                    &frame(),
                    a.backend_d_o_m_node_id.unwrap(),
                    a,
                    &mut refs,
                    1,
                    &metadata(),
                    true,
                )
                .unwrap(),
            );
        }
        let forest = assemble_forest(&order, nodes).unwrap();
        assert_eq!(forest.len(), 1);
        assert_eq!(forest[0].children.len(), 1);
        assert_eq!(forest[0].reference.id, "@e2");
        assert_eq!(forest[0].children[0].reference.id, "@e1");
    }
    #[test]
    fn abandoned_staging_never_recycles_ids_or_publishes_nodes() {
        let mut refs = observed_refs();
        let id = refs.bind_exact(1, "button", "Save", frame().binding);
        let mut abandoned = refs.clone();
        let skipped = abandoned.bind_exact(2, "button", "Save", frame().binding);
        drop(abandoned);
        assert!(refs.get(&skipped).is_none());
        assert!(refs.get(&id).is_some());
        let next = refs.bind_exact(3, "button", "Save", frame().binding);
        assert_ne!(next, skipped);
        assert_eq!(next, "e3");
        refs.invalidate_all_documents();
        assert_eq!(refs.allocate_ref(), "e4");
    }
    #[test]
    fn frame_or_document_replacement_allocates_new_identity() {
        let mut refs = observed_refs();
        let a = refs.bind_exact(42, "button", "Save", frame().binding);
        let mut replacement = frame().binding;
        replacement.loader = "new".into();
        let b = refs.bind_exact(42, "button", "Save", replacement);
        let mut other = frame().binding;
        other.frame = "child".into();
        let c = refs.bind_exact(42, "button", "Save", other);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }
    #[test]
    fn structural_refs_are_not_actionable() {
        let mut root = ax("root", 1, &[]);
        root.role.as_mut().unwrap().value = Some(json!("RootWebArea"));
        let mut refs = observed_refs();
        let node = project_node(&frame(), 1, &root, &mut refs, 1, &metadata(), true).unwrap();
        assert!(
            !refs
                .get(node.reference.id.trim_start_matches('@'))
                .unwrap()
                .exact_binding
                .as_ref()
                .unwrap()
                .actionable
        );
    }
    #[test]
    fn native_pseudo_classification_requires_owned_inventory_and_exact_descriptor() {
        let dom = json!({"nodeType":9,"backendNodeId":1,"children":[{"nodeType":1,"backendNodeId":2,"pseudoElements":[{"nodeType":1,"backendNodeId":3,"pseudoType":"marker"}]}]});
        let inventory = pseudo_origins(&dom).unwrap();
        let remote = json!({"type":"object","className":"CSSPseudoElement","objectId":"opaque"});
        let described = json!({"node":{"nodeType":1,"backendNodeId":3,"pseudoType":"marker"}});
        assert_eq!(
            verified_pseudo_origin(&remote, &described, 3, &inventory).unwrap(),
            2
        );
        for invalid in [
            json!({"type":"object","className":"Object"}),
            json!({"type":"object","className":"Window"}),
        ] {
            assert!(verified_pseudo_origin(&invalid, &described, 3, &inventory).is_err());
        }
        assert!(verified_pseudo_origin(&remote, &described, 3, &HashMap::new()).is_err());
        assert!(verified_pseudo_origin(
            &remote,
            &json!({"node":{"nodeType":1,"backendNodeId":4,"pseudoType":"marker"}}),
            3,
            &inventory
        )
        .is_err());
        assert!(verified_pseudo_origin(
            &remote,
            &json!({"node":{"nodeType":1,"backendNodeId":3,"pseudoType":"before"}}),
            3,
            &inventory
        )
        .is_err());
    }
    #[test]
    fn pseudo_projection_keeps_own_readonly_identity_and_redacts_origin_secrets() {
        use super::super::element::NativeReferenceKind;
        let mut node = ax("marker", 3, &[]);
        node.role.as_mut().unwrap().value = Some(json!("ListMarker"));
        node.name.as_mut().unwrap().value = Some(json!("synthetic-marker"));
        let mut refs = observed_refs();
        let owner = refs.bind_exact(2, "listitem", "", frame().binding);
        let data = readonly_pseudo_metadata(&metadata(), &node);
        let projected = project_node(&frame(), 3, &node, &mut refs, 1, &data, true).unwrap();
        assert_ne!(projected.reference.id, format!("@{owner}"));
        let entry = refs
            .get(projected.reference.id.trim_start_matches('@'))
            .unwrap();
        assert_eq!(entry.backend_node_id, Some(3));
        assert_eq!(entry.kind, NativeReferenceKind::ReadOnlyCssPseudo);
        assert!(!entry.exact_binding.as_ref().unwrap().actionable);
        assert_eq!(projected.role.as_deref(), Some("text"));
        assert_eq!(projected.text.as_deref(), Some("synthetic-marker"));
        assert!(projected.selector.is_none());
        assert!(projected.value.is_none());
        let mut secure = metadata();
        secure["states"]["secure"] = json!(true);
        let protected = project_node(
            &frame(),
            3,
            &node,
            &mut refs,
            1,
            &readonly_pseudo_metadata(&secure, &node),
            true,
        )
        .unwrap();
        assert!(!serde_json::to_string(&protected)
            .unwrap()
            .contains("synthetic-marker"));
        let stale = readonly_pseudo_metadata(&json!({"__nativeStatus":"stale-reference"}), &node);
        assert!(matches!(
            project_node(&frame(), 3, &node, &mut refs, 1, &stale, true),
            Err(ObservationError::StaleReference)
        ));
    }
    #[tokio::test]
    async fn pseudo_metadata_uses_verified_origin_without_rebinding_and_rejects_late_change() {
        use futures_util::{SinkExt, StreamExt};
        for mode in [
            "valid",
            "secure",
            "unknown",
            "wrong-realm",
            "changed-origin",
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("ws://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut metadata_done = false;
                while let Some(Ok(message)) = socket.next().await {
                    let Ok(text) = message.to_text() else {
                        continue;
                    };
                    let request: Value = serde_json::from_str(text).unwrap();
                    let result = match request["method"].as_str().unwrap() {
                        "Page.createIsolatedWorld" => json!({"executionContextId":17}),
                        "Page.getFrameTree" => {
                            json!({"frameTree":{"frame":{"id":"main","loaderId":"doc"}}})
                        }
                        "DOM.getDocument" => {
                            json!({"root":{"nodeType":9,"backendNodeId":1,"children":[{"nodeType":1,"backendNodeId":if mode=="changed-origin"&&metadata_done{4}else{2},"pseudoElements":[{"nodeType":1,"backendNodeId":3,"pseudoType":"marker"}]}]}})
                        }
                        "DOM.describeNode" => {
                            json!({"node":{"nodeType":1,"backendNodeId":3,"pseudoType":"marker"}})
                        }
                        "DOM.resolveNode" => {
                            let backend = request["params"]["backendNodeId"].as_i64().unwrap();
                            if backend == 3 {
                                json!({"object":{"type":"object","className":if mode=="unknown"{"Object"}else{"CSSPseudoElement"},"objectId":"pseudo"}})
                            } else {
                                json!({"object":{"type":"object","subtype":"node","objectId":format!("node-{backend}")}})
                            }
                        }
                        "Runtime.callFunctionOn" => {
                            let source = request["params"]["functionDeclaration"].as_str().unwrap();
                            if source.contains("Array.from(result)") {
                                json!({"result":{"objectId":"security-array"}})
                            } else {
                                assert_eq!(request["params"]["objectId"], "node-2");
                                assert_eq!(request["params"]["arguments"][2]["objectId"], "node-2");
                                metadata_done = true;
                                let mut data = metadata();
                                if mode == "secure" {
                                    data["states"]["secure"] = json!(true);
                                }
                                if mode == "wrong-realm" {
                                    data = json!({"__nativeStatus":"stale-reference"});
                                }
                                json!({"result":{"value":[data]}})
                            }
                        }
                        "Runtime.getProperties" => json!({"result":[]}),
                        "Runtime.releaseObjectGroup" => json!({}),
                        _ => panic!("unexpected native pseudo command"),
                    };
                    if socket
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            json!({"id":request["id"],"result":result}).to_string(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let client = CdpClient::connect(&endpoint).await.unwrap();
            let (op, _sender) = lease();
            let mut refs = observed_refs();
            let node = ax("marker", 3, &[]);
            let result = read_batch(
                &client,
                &frame(),
                &[&node],
                &mut refs,
                1,
                &ObservationOptions::default(),
                &op,
                true,
                &SecurityInventory::default(),
            )
            .await;
            if mode == "valid" || mode == "secure" {
                let projected = result.unwrap().remove(0);
                let entry = refs
                    .get(projected.reference.id.trim_start_matches('@'))
                    .unwrap();
                assert_eq!(entry.backend_node_id, Some(3));
                assert_eq!(
                    entry.kind,
                    super::super::element::NativeReferenceKind::ReadOnlyCssPseudo
                );
                if mode == "secure" {
                    assert!(projected.name.is_none());
                    assert!(projected.text.is_none());
                }
            } else {
                assert!(result.is_err(), "{mode}");
                assert!(
                    refs.entries_sorted().is_empty(),
                    "failed proof allocated identity"
                );
            }
            server.abort();
        }
    }
}

#[cfg(test)]
#[path = "client_observation_equivalence_tests.rs"]
mod equivalence_tests;
