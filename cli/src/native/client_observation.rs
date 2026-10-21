//! Typed native observations. Browser identity and node ownership stay native;
//! clients receive only canonical references and semantic data.
use super::{
    cdp::{
        client::CdpClient,
        types::{AXNode, GetFullAXTreeResult},
    },
    client_session::{CancelSignal, OperationLease},
    element::{ExactBinding, RefMap},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

/// Public failures are semantic categories, never raw CDP text or string heuristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationError {
    InvalidArguments,
    StaleReference,
    Cancelled,
    DeadlineExceeded,
    BackendFailure,
    PolicyDenied,
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
    pub labels: Vec<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
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
const METADATA: &str = r#"function(testId,secureSelector) {
 const nodeProto=Node.prototype;
 if (!Object.getOwnPropertyDescriptor(nodeProto,'isConnected').get.call(this) || (this!==document && Object.getOwnPropertyDescriptor(nodeProto,'ownerDocument').get.call(this)!==document)) return {__nativeStatus:'stale-reference'};
 const e=this.nodeType===1?this:null, doc=this.ownerDocument||this;
 try { Element.prototype.matches.call(document.documentElement,secureSelector); } catch { return {__nativeStatus:'invalid-arguments'}; }
 const secureSelectorAll='input[type="password" i],'+secureSelector;
 function composedSecure(node){
   const seen=new Set();for(let p=node;p&&!seen.has(p);p=p.parentElement||(p.getRootNode&&p.getRootNode().host)){seen.add(p);if(p.nodeType===1&&Element.prototype.matches.call(p,secureSelectorAll))return true;}return false;
 }
 const secureElement=e||this.parentElement;
 const secure=composedSecure(secureElement);
 const secureDescendants=!!e&&!!Element.prototype.querySelector.call(e,secureSelectorAll);
 function safeText(node){
   if(!node)return null; if(node.nodeType===3)return composedSecure(node.parentElement)?null:node.textContent;
   if(!secureDescendants)return node.innerText;
   const walker=doc.createTreeWalker(node,NodeFilter.SHOW_TEXT);const parts=[];let text;
   while(text=walker.nextNode()){const p=text.parentElement;if(p&&!composedSecure(p))parts.push(text.textContent);}
   return parts.join(' ');
 }
 const attrs={}; if(e) for(const a of e.attributes) if(!(secure&&a.name.toLowerCase()==='value')) attrs[a.name]=a.value;
 const style=e?doc.defaultView.getComputedStyle(e):null;
 const r=e?e.getBoundingClientRect():null;
 const hidden=!!e&&(!r||!r.width||!r.height||style.visibility==='hidden'||style.display==='none');
 const focused=doc.activeElement===e;
 let selection=null;
 if(!secure&&focused&&typeof e.selectionStart==='number'&&e.selectionEnd>e.selectionStart) selection=e.value.slice(e.selectionStart,e.selectionEnd);
 else if(!secure&&focused&&e.isContentEditable) selection=String(doc.getSelection()||'')||null;
 const ac=(e&&e.getAttribute('autocomplete')||'').toLowerCase().split(/\s+/);
 const purpose=((e&&Element.prototype.matches.call(e,'input[type="password" i]'))||ac.includes('current-password')||ac.includes('new-password'))?'password':secure?'generic-secret':ac.includes('one-time-code')?'one-time-code':ac.includes('username')?'username':'none';
 const labels=e?[e.getAttribute('aria-label'), ...(e.labels?Array.from(e.labels,l=>l.innerText):[]), ...(e.getAttribute('aria-labelledby')||'').split(/\s+/).map(id=>doc.getElementById(id)?.innerText)].filter(Boolean):[];
 let selector=null;if(e&&e.id)selector='#'+CSS.escape(e.id);else if(e&&e.hasAttribute(testId))selector='['+CSS.escape(testId)+'='+JSON.stringify(e.getAttribute(testId))+']';
 const secureText=secure&&(!e||!Element.prototype.matches.call(e,'input,textarea,select'));
 const unsafeLabel=!!e&&(e.getAttribute('aria-labelledby')||'').split(/\s+/).some(id=>composedSecure(doc.getElementById(id)));
 return {selector,redactName:secureText||unsafeLabel,labels:secureText||secureDescendants||unsafeLabel?[]:labels,secureDescendants,attributes:attrs,text:secure?null:safeText(this),
 value:secure?null:e&&typeof e.value==='string'?e.value:null,selection, inputPurpose:purpose,
 testId:e?e.getAttribute(testId):null, states:{secure,hidden,focused,disabled:!!e&&(Element.prototype.matches.call(e,':disabled')||e.getAttribute('aria-disabled')==='true')},
 rect:r&&r.width&&r.height?{x:r.x,y:r.y,width:r.width,height:r.height}:null};
}"#;
#[allow(clippy::too_many_arguments)] // Explicit browser ownership, revision, policy, and deadline inputs.
async fn read_backend(
    client: &CdpClient,
    frame: &ObservationFrame,
    backend: i64,
    ax: &AXNode,
    refs: &mut RefMap,
    revision: u64,
    options: &ObservationOptions,
    lease: &OperationLease,
    bounded: bool,
) -> Result<SemanticNode, ObservationError> {
    if ax.backend_d_o_m_node_id != Some(backend) {
        return Err(ObservationError::StaleReference);
    }
    let mut node = read_batch(
        client,
        frame,
        &[ax],
        refs,
        revision,
        options,
        lease,
        bounded,
    )
    .await?
    .into_iter()
    .next()
    .ok_or(ObservationError::BackendFailure)?;
    let security = security_inventory(client, frame, options, lease).await?;
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
    match data["__nativeStatus"].as_str() {
        Some("stale-reference") => return Err(ObservationError::StaleReference),
        Some("invalid-arguments") => return Err(ObservationError::InvalidArguments),
        Some(_) => return Err(ObservationError::BackendFailure),
        None => {}
    }
    let role = ax_string(&ax.role).map(|role| match role.as_str() {
        "img" => "image".into(),
        "RootWebArea" | "WebArea" => "document".into(),
        "StaticText" => "text".into(),
        _ => role,
    });
    let mut binding = frame.binding.clone();
    binding.actionable = !matches!(role.as_deref(), Some("document" | "text" | "InlineTextBox"));
    let id = if data["__nativeReadonlyPseudo"] == true {
        refs.try_bind_readonly_pseudo(backend, role.as_deref().unwrap_or(""), binding)
    } else {
        refs.try_bind_exact(backend, role.as_deref().unwrap_or(""), "", binding)
    }
    .map_err(|_| ObservationError::BackendFailure)?;
    let mut node = SemanticNode {
        reference: NodeReference {
            id: format!("@{id}"),
            revision: revision.to_string(),
        },
        role,
        name: ax_string(&ax.name),
        frame_path: frame.frame_path.clone(),
        ..Default::default()
    };
    if data["secureDescendants"] == true || data["redactName"] == true {
        node.name = None;
    }
    node.labels = serde_json::from_value(data["labels"].clone()).map_err(|_| "Invalid labels")?;
    node.attributes =
        serde_json::from_value(data["attributes"].clone()).map_err(|_| "Invalid attributes")?;
    node.states = serde_json::from_value(data["states"].clone()).map_err(|_| "Invalid states")?;
    for p in ax.properties.as_deref().unwrap_or_default() {
        if ["checked", "selected", "expanded", "pressed"].contains(&p.name.as_str()) {
            if let Some(value) = p.value.value.as_ref().and_then(|v| {
                v.as_bool().or_else(|| match v.as_str() {
                    Some("true") => Some(true),
                    Some("false") => Some(false),
                    _ => None,
                })
            }) {
                node.states.insert(p.name.clone(), value);
            }
        }
        if p.name == "level" {
            node.level = p.value.value.as_ref().and_then(Value::as_i64);
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
        node.attributes.retain(|name, _| {
            matches!(
                name.as_str(),
                "type" | "autocomplete" | "href" | "role" | "placeholder"
            ) || name.starts_with("aria-")
        });
        if let Some(href) = node.attributes.get_mut("href") {
            *href = href.split(['?', '#']).next().unwrap_or("").to_string();
        }
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
    staged.begin_snapshot();
    let mut frame_roots: HashMap<String, Vec<SemanticNode>> = HashMap::new();
    let mut count = 0;
    let mut truncated = false;
    for frame in frames {
        check(lease)?;
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
        let mut nodes = HashMap::new();
        let eligible: Vec<&AXNode> = tree
            .nodes
            .iter()
            .filter(|ax| {
                ax.ignored != Some(true)
                    && ax_string(&ax.role).as_deref() != Some("InlineTextBox")
                    && ax.backend_d_o_m_node_id.is_some()
            })
            .collect();
        let remaining = options.max_nodes - count;
        if eligible.len() > remaining {
            truncated = true;
        }
        for chunk in eligible
            .into_iter()
            .take(remaining)
            .collect::<Vec<_>>()
            .chunks(64)
        {
            let batch = read_batch(
                client,
                frame,
                chunk,
                &mut staged,
                revision,
                options,
                lease,
                true,
            )
            .await?;
            for (ax, mut node) in chunk.iter().zip(batch) {
                apply_security(&mut node, ax.backend_d_o_m_node_id.unwrap(), &security);
                nodes.insert(ax.node_id.clone(), node);
                count += 1;
            }
        }
        frame_roots.insert(
            frame.binding.frame.clone(),
            assemble_forest(&tree.nodes, nodes)?,
        );
        validate_frame(client, frame, lease).await?;
    }
    let mut pending: Vec<&ObservationFrame> = frames.iter().collect();
    pending.sort_by_key(|f| std::cmp::Reverse(f.frame_path.len()));
    for child in pending.iter().filter(|f| f.parent_frame_id.is_some()) {
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
    let viewport_ref = NodeReference {
        id: format!(
            "@{}",
            staged
                .try_viewport_ref()
                .map_err(|_| ObservationError::BackendFailure)?
        ),
        revision: revision.to_string(),
    };
    check(lease)?;
    *refs = staged;
    Ok(Observation {
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
#[derive(Debug, Deserialize)]
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
pub async fn read(
    client: &CdpClient,
    frames: &[ObservationFrame],
    refs: &mut RefMap,
    revision: u64,
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
    let binding = entry
        .exact_binding
        .as_ref()
        .ok_or(ObservationError::InvalidArguments)?;
    let frame = frames
        .iter()
        .find(|f| {
            f.binding.page_session == binding.page_session
                && f.binding.session == binding.session
                && f.binding.frame == binding.frame
                && f.binding.loader == binding.loader
        })
        .ok_or(ObservationError::StaleReference)?;
    validate_frame(client, frame, lease).await?;
    let backend = entry
        .backend_node_id
        .ok_or(ObservationError::StaleReference)?;
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
    let mut staged = refs.clone();
    let node = read_backend(
        client,
        frame,
        backend,
        ax,
        &mut staged,
        revision,
        &ObservationOptions {
            test_id_attribute: options.test_id_attribute.clone(),
            secure_field_selector: options.secure_field_selector.clone(),
            ..Default::default()
        },
        lease,
        false,
    )
    .await?;
    validate_frame(client, frame, lease).await?;
    check(lease)?;
    let result = project_read_fields(node, options.fields.as_deref())?;
    *refs = staged;
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
const MATCH_QUERY: &str = r#"function(expression, data, labels, ...elements) {
 const norm=s=>String(s??'').replace(/[\u200b\u200c\u200d\ufeff]/g,'').replace(/\s+/g,' ').trim();
 function match(p,s,testId=false) { if(p.kind==='regexp') return new RegExp(p.source,p.flags).test(String(s??'')); if(testId)return String(s??'')===p.value; const a=norm(s),b=norm(p.value); return p.exact?a===b:a.toLowerCase().includes(b.toLowerCase()); }
 if(elements.some(e=>!e.isConnected||e.ownerDocument!==document))return {error:'stale-reference'};
 const all=elements.map((_,i)=>i);
 const contains=(a,b)=>{if(a===b)return false;let node=elements[b];const seen=new Set();while(node&&!seen.has(node)){seen.add(node);node=node.parentNode||(node.getRootNode&&node.getRootNode().host);if(node===elements[a])return true;}return false;};
 const redacted=[];
 for(let i=0;i<data.length;i++)if(data.some((n,j)=>n.states.secure&&contains(i,j))){redacted.push(i);delete data[i].name;delete data[i].text;delete data[i].selection;delete data[i].value;labels[i]=[];}
 function semantic(q,i) {
  const n=data[i],e=elements[i]; if(q.visible&&n.states.hidden)return false;
  if(q.kind==='role') {
   if(n.states.hidden||q.value.kind!=='string'||n.role!==q.value.value)return false;
   if(q.name&&!match(q.name,q.name.kind==='string'?String(n.name??'').replace(/\p{Co}/gu,' '):n.name))return false;
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
   case 'filter': return evaluate(x.source,scope).filter(i=>(!x.hasText||match(x.hasText,data[i].text))&&(!x.has||evaluate(x.has,scope.filter(j=>contains(i,j))).length>0));
   case 'index': {const a=evaluate(x.source,scope);const i=x.index==='first'?0:x.index==='last'?a.length-1:x.index;return i>=0&&i<a.length?[a[i]]:[];}
   case 'frame': throw new Error('Frame expression must be resolved by native frame scope');
   default: throw new Error('Unknown locator expression');
  }
 }
 try { return {indices:evaluate(expression),redacted}; } catch { return {error:"invalid-arguments"}; }
}"#;

/// Query the browser's DOM/AX primitives, not a previously truncated observation.
/// A failed query cannot change the action registry; successful queries add exact
/// handles without retiring the last published observation.
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
    let mut candidates: Vec<&ObservationFrame> = frames
        .iter()
        .filter(|f| f.parent_frame_id.is_none())
        .collect();
    if candidates.len() != 1 {
        return Err("Query requires exactly one document scope".into());
    }
    let mut frame = candidates.remove(0);
    for selector in path {
        frame = select_frame(client, frames, frame, &selector, lease).await?;
    }
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
    let ids = bounded_dom_ids(&dom["root"], &[1], 100_000)?;
    let mut staged = refs.clone();
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
            nodes.extend(read_batch(client,frame,&chunk.iter().collect::<Vec<_>>(),&mut staged,revision,&metadata_options,lease,false).await?);
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
        if objects.is_empty() { return Ok(Vec::new()); }
        let mut arguments=vec![json!({"value":expression}),json!({"value":nodes}),json!({"value":nodes.iter().map(|n|&n.labels).collect::<Vec<_>>()})];
        arguments.extend(objects.iter().map(|id|json!({"objectId":id})));
        let result=command(client,session,"Runtime.callFunctionOn",json!({"objectId":objects[0],"functionDeclaration":MATCH_QUERY,"arguments":arguments,"returnByValue":true}),lease).await?;
        if result.get("exceptionDetails").is_some(){return Err(ObservationError::BackendFailure);}
        let value=&result["result"]["value"];
        match value["error"].as_str(){Some("stale-reference")=>return Err(ObservationError::StaleReference),Some("invalid-arguments")=>return Err(ObservationError::InvalidArguments),Some(_)=>return Err(ObservationError::BackendFailure),None=>{}}
        let indices:Vec<usize>=serde_json::from_value(value["indices"].clone()).map_err(|_|ObservationError::BackendFailure)?;
        let redacted:Vec<usize>=serde_json::from_value(value["redacted"].clone()).map_err(|_|ObservationError::BackendFailure)?;
        for index in redacted { let node=nodes.get_mut(index).ok_or(ObservationError::BackendFailure)?;scrub_content(node); }
        indices.into_iter().map(|i|nodes.get(i).cloned().ok_or_else(||"Invalid query index".into())).collect::<Result<Vec<_>,ObservationError>>()
    }.await;
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        client.send_command(
            "Runtime.releaseObjectGroup",
            Some(json!({"objectGroup":group})),
            Some(session),
        ),
    )
    .await;
    let nodes = result?;
    validate_frame(client, frame, lease).await?;
    check(lease)?;
    *refs = staged;
    Ok(QueryResult {
        identity_scope: identity_scope.into(),
        revision,
        nodes,
    })
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
    json!({"__nativeReadonlyPseudo":true,"redactName":protected,"secureDescendants":data["secureDescendants"],"labels":[],"attributes":{},"states":{"secure":data["states"]["secure"]==true,"hidden":data["states"]["hidden"]==true,"disabled":true},"text":if protected{None}else{ax_string(&ax.name)},"rect":null})
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
        let function=format!("function(testId,secureSelector,...nodes) {{ const read={METADATA}; return nodes.map(node=>read.call(node,testId,secureSelector)); }}");
        let result=command(client,session,"Runtime.callFunctionOn",json!({"objectId":objects[0],"functionDeclaration":function,"arguments":arguments,"returnByValue":true}),lease).await?;
        if result.get("exceptionDetails").is_some(){
            #[cfg(test)]
            diagnostic_receivers(client,session,&objects,lease).await;
            return Err(ObservationError::BackendFailure);
        }
        let values=result["result"]["value"].as_array().ok_or("Missing metadata batch")?;
        if values.len()!=nodes.len(){return Err("Incomplete metadata batch".into());}
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
        nodes.iter().zip(values).zip(pseudo).map(|((ax,data),origin)|{
            let readonly=if origin.is_some(){readonly_pseudo_metadata(data,ax)}else{data.clone()};
            let mut node=project_node(frame,ax.backend_d_o_m_node_id.unwrap(),ax,refs,revision,&readonly,bounded)?;
            if let (Some(origin),Some(policy))=(origin,&policy){apply_security(&mut node,origin,policy);if node.states.get("secure")==Some(&true){scrub_content(&mut node);}}
            Ok(node)
        }).collect()
    }.await;
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        client.send_command(
            "Runtime.releaseObjectGroup",
            Some(json!({"objectGroup":group})),
            Some(session),
        ),
    )
    .await;
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
fn scrub_sensitive_ancestors(node: &mut SemanticNode) -> bool {
    let mut descendant = false;
    for child in &mut node.children {
        descendant |= scrub_sensitive_ancestors(child);
    }
    if descendant {
        scrub_content(node);
    }
    descendant || node.states.get("secure") == Some(&true)
}

/// AX order is not an identity or topology guarantee. Build retained-node
/// adjacency first, then assemble bottom-up without recursion or repeated walks.
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
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(250),
                client.send_command(
                    "Runtime.releaseObject",
                    Some(json!({"objectId":object})),
                    Some(&parent.binding.session),
                ),
            )
            .await;
            let value = value?;
            if value.get("exceptionDetails").is_some() {
                return Err(ObservationError::StaleReference);
            }
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
        if let Some(children) = tree["childFrames"].as_array() {
            for child in children {
                queue.push_back((child.clone(), Some(index)));
            }
        }
    }
    if !owned_trees.is_empty() {
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
async fn select_frame<'a>(
    client: &CdpClient,
    frames: &'a [ObservationFrame],
    parent: &ObservationFrame,
    selector: &str,
    lease: &OperationLease,
) -> Result<&'a ObservationFrame, ObservationError> {
    let session = &parent.binding.session;
    validate_frame(client, parent, lease).await?;
    let world = command(
        client,
        session,
        "Page.createIsolatedWorld",
        json!({"frameId":parent.binding.frame,"worldName":"agent-browser-native-observation"}),
        lease,
    )
    .await?;
    let mut matches = Vec::new();
    for child in frames
        .iter()
        .filter(|f| f.parent_frame_id.as_deref() == Some(parent.binding.frame.as_str()))
    {
        let backend = child
            .owner_backend_id
            .ok_or("Frame owner identity missing")?;
        let object = command(
            client,
            session,
            "DOM.resolveNode",
            json!({"backendNodeId":backend,"executionContextId":world["executionContextId"]}),
            lease,
        )
        .await?;
        let object = object["object"]["objectId"]
            .as_str()
            .ok_or(ObservationError::StaleReference)?;
        let result=command(client,session,"Runtime.callFunctionOn",json!({"objectId":object,"functionDeclaration":r#"function(selector){
            if(!this.isConnected||this.ownerDocument!==document)throw new Error('Frame owner moved');
            if(selector.startsWith('//')||selector.startsWith('xpath=')){const r=document.evaluate(selector.replace(/^xpath=/,''),document,null,XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,null);for(let i=0;i<r.snapshotLength;i++)if(r.snapshotItem(i)===this)return true;return false;}
            return Element.prototype.matches.call(this,selector.replace(/^css=/,''));
        }"#,"arguments":[{"value":selector}],"returnByValue":true}),lease).await;
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            client.send_command(
                "Runtime.releaseObject",
                Some(json!({"objectId":object})),
                Some(session),
            ),
        )
        .await;
        let result = result?;
        if result.get("exceptionDetails").is_some() {
            return Err(ObservationError::InvalidArguments);
        }
        if result["result"]["value"] == true {
            matches.push(child);
        }
    }
    if matches.len() != 1 {
        return Err(ObservationError::InvalidArguments);
    }
    validate_frame(client, matches[0], lease).await?;
    Ok(matches[0])
}

#[derive(Default)]
struct SecurityInventory {
    ancestors: std::collections::HashSet<i64>,
    label_ids: std::collections::HashSet<String>,
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
        scrub_content(node);
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
async fn security_inventory(
    client: &CdpClient,
    frame: &ObservationFrame,
    options: &ObservationOptions,
    lease: &OperationLease,
) -> Result<SecurityInventory, ObservationError> {
    use futures_util::{stream, StreamExt, TryStreamExt};
    let dom = frame_dom(client, frame, lease).await?;
    let ids = security_root_ids(&dom["root"])?;
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
        let mut security=SecurityInventory::default();
        for description in descriptions{
            let node=&description["node"];security.ancestors.insert(node["backendNodeId"].as_i64().ok_or(ObservationError::BackendFailure)?);
            if let Some(attributes)=node["attributes"].as_array(){for pair in attributes.as_chunks::<2>().0{if pair[0]=="id"{if let Some(id)=pair[1].as_str(){security.label_ids.insert(id.to_string());}}}}
        }
        Ok(security)
    }.await;
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        client.send_command(
            "Runtime.releaseObjectGroup",
            Some(json!({"objectGroup":group})),
            Some(session),
        ),
    )
    .await;
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
            let polygons = geometry
                .node_border_polygons(client, &frame, backend, lease)
                .await?;
            let mut bounds = None::<super::client_geometry::Bounds>;
            for polygon in polygons {
                if let Some(next) = polygon.bounds() {
                    bounds = Some(match bounds {
                        None => next,
                        Some(old) => {
                            let x = old.x.min(next.x);
                            let y = old.y.min(next.y);
                            super::client_geometry::Bounds {
                                x,
                                y,
                                width: (old.x + old.width).max(next.x + next.width) - x,
                                height: (old.y + old.height).max(next.y + next.height) - y,
                            }
                        }
                    });
                }
            }
            let b = bounds.ok_or(GeometryError::InvalidGeometry)?;
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
        json!({"attributes":{},"labels":[],"states":{"secure":false,"hidden":false},"text":"Save","rect":{"x":1,"y":2,"width":3,"height":4}})
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
        let mut refs = RefMap::new();
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
        let mut refs = RefMap::new();
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
        assert_eq!(b.roots[0].reference.revision, "2");
        server.abort();
    }
    #[tokio::test]
    async fn cancellation_before_capture_does_not_publish() {
        let (client, server) = mock_client(false).await;
        let (lease, sender) = lease();
        sender.send_replace(CancelSignal::Requested);
        let mut refs = RefMap::new();
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
            let (mut lease,_sender)=lease();lease.deadline=std::time::Instant::now()+std::time::Duration::from_secs(30);let mut refs=RefMap::new();
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
            let one=read(&mgr.client,&frames,&mut refs,3,&read_options,&lease).await.map_err(|_| "native observation stage: read_1".to_string())?;if one.to_string().contains("synthetic-closed-child"){return Err("Closed secure descendant leaked in full read".into());}
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
        let mut refs = RefMap::new();
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
        let mut refs = RefMap::new();
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
        )
        .await
        .unwrap();
        assert_eq!(nodes.len(), 2);
        assert_ne!(nodes[0].reference.id, nodes[1].reference.id);
        server.await.unwrap();
    }
    #[test]
    fn observation_href_omits_tokens_but_full_read_preserves_requested_attribute() {
        let mut data = metadata();
        data["attributes"]["href"] =
            json!("https://fixture.invalid/path?token=synthetic-token#secret");
        let mut refs = RefMap::new();
        let observed =
            project_node(&frame(), 1, &ax("a", 1, &[]), &mut refs, 1, &data, true).unwrap();
        assert_eq!(observed.attributes["href"], "https://fixture.invalid/path");
        let full = project_node(&frame(), 1, &ax("a", 1, &[]), &mut refs, 1, &data, false).unwrap();
        assert!(full.attributes["href"].contains("?token="));
    }
    #[test]
    fn secure_shadow_text_and_ancestor_names_never_serialize() {
        let mut data = metadata();
        data["states"]["secure"] = json!(true);
        data["redactName"] = json!(true);
        let mut text = ax("secret", 2, &[]);
        text.name.as_mut().unwrap().value = Some(json!("synthetic-shadow-secret"));
        let mut refs = RefMap::new();
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
    fn secure_inventory_keeps_public_password_labels_without_value() {
        let mut data = metadata();
        data["states"]["secure"] = json!(true);
        data["labels"] = json!(["Password"]);
        data["value"] = json!("synthetic-secret");
        let mut refs = RefMap::new();
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
        let mut refs = RefMap::new();
        let observed =
            project_node(&frame(), 2, &ax("a", 2, &[]), &mut refs, 1, &data, true).unwrap();
        assert!(!observed.attributes.contains_key("data-private"));
        assert_eq!(observed.attributes["aria-label"], "Public");
        let read = project_node(&frame(), 2, &ax("a", 2, &[]), &mut refs, 1, &data, false).unwrap();
        assert_eq!(read.attributes["data-private"], "synthetic-secret");
    }
    #[test]
    fn exact_reference_exhaustion_returns_error_without_publishing() {
        let mut refs = RefMap::new();
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
    #[test]
    fn revision_wire_preserves_full_native_integer_precision() {
        let observation = Observation {
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
            &mut RefMap::new(),
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
        let mut refs = RefMap::new();
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
        let mut refs = RefMap::new();
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
        let mut refs = RefMap::new();
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
        let mut refs = RefMap::new();
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
        let mut refs = RefMap::new();
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
            let mut refs = RefMap::new();
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
