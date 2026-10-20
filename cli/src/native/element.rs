use std::collections::{HashMap, HashSet, VecDeque};

use serde_json::Value;

use super::cdp::client::CdpClient;
use super::cdp::types::*;

#[derive(Debug, Clone)]
pub struct RefEntry {
    pub backend_node_id: Option<i64>,
    pub role: String,
    pub name: String,
    pub nth: Option<usize>,
    pub selector: Option<String>,
    pub frame_id: Option<String>,
    pub session_id: Option<String>,
    pub context_id: Option<i64>,
    allow_role_fallback: bool,
}

impl RefEntry {
    pub fn is_exact(&self) -> bool {
        !self.allow_role_fallback
    }
}

#[derive(Clone)]
struct DocumentRefs {
    session: String,
    loader: String,
    refs: HashMap<(i64, bool), String>,
}

#[derive(Clone)]
pub struct RefMap {
    map: HashMap<String, RefEntry>,
    documents: HashMap<(String, Option<String>), DocumentRefs>,
    next_ref: usize,
    // Preserve recent exact-ref retirement errors without retaining DOM metadata.
    retired_exact: HashSet<String>,
    retired_exact_order: VecDeque<String>,
}

impl RefMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            documents: HashMap::new(),
            next_ref: 1,
            retired_exact: HashSet::new(),
            retired_exact_order: VecDeque::new(),
        }
    }

    pub fn add(
        &mut self,
        ref_id: String,
        backend_node_id: Option<i64>,
        role: &str,
        name: &str,
        nth: Option<usize>,
    ) {
        self.add_with_frame(ref_id, backend_node_id, role, name, nth, None);
    }

    pub fn add_with_frame(
        &mut self,
        ref_id: String,
        backend_node_id: Option<i64>,
        role: &str,
        name: &str,
        nth: Option<usize>,
        frame_id: Option<&str>,
    ) {
        self.map.insert(
            ref_id,
            RefEntry {
                backend_node_id,
                role: role.to_string(),
                name: name.to_string(),
                nth,
                selector: None,
                frame_id: frame_id.map(|s| s.to_string()),
                session_id: None,
                context_id: None,
                allow_role_fallback: true,
            },
        );
    }

    /// Add a ref that must keep resolving to this exact backend node. This is
    /// used for actions that select a concrete DOM node before interacting;
    /// falling back by role/name could silently target a different element.
    pub fn add_exact_backend_node(&mut self, ref_id: String, backend_node_id: i64) {
        if self.retired_exact.remove(&ref_id) {
            self.retired_exact_order
                .retain(|retired| retired != &ref_id);
        }
        self.map.insert(
            ref_id,
            RefEntry {
                backend_node_id: Some(backend_node_id),
                role: String::new(),
                name: String::new(),
                nth: None,
                selector: None,
                frame_id: None,
                session_id: None,
                context_id: None,
                allow_role_fallback: false,
            },
        );
    }

    /// Register an exact snapshot capability using the same primitive as explicit
    /// DOM-node selection, while retaining descriptive snapshot metadata.
    pub fn add_exact_with_frame(
        &mut self,
        ref_id: String,
        backend_node_id: i64,
        role: &str,
        name: &str,
        nth: Option<usize>,
        frame_id: Option<&str>,
    ) {
        self.add_exact_backend_node(ref_id.clone(), backend_node_id);
        let entry = self.map.get_mut(&ref_id).expect("ref was just inserted");
        entry.role = role.to_string();
        entry.name = name.to_string();
        entry.nth = nth;
        entry.frame_id = frame_id.map(str::to_string);
    }

    pub fn add_selector(
        &mut self,
        ref_id: String,
        selector: String,
        role: &str,
        name: &str,
        nth: Option<usize>,
    ) {
        self.map.insert(
            ref_id,
            RefEntry {
                backend_node_id: None,
                role: role.to_string(),
                name: name.to_string(),
                nth,
                selector: Some(selector),
                frame_id: None,
                session_id: None,
                context_id: None,
                allow_role_fallback: true,
            },
        );
    }

    pub fn bind_world(&mut self, ref_id: &str, session_id: &str, context_id: i64) {
        if let Some(entry) = self.map.get_mut(ref_id) {
            entry.session_id = Some(session_id.to_string());
            entry.context_id = Some(context_id);
        }
    }

    pub fn get(&self, ref_id: &str) -> Option<&RefEntry> {
        self.map.get(ref_id)
    }

    pub fn entries_sorted(&self) -> Vec<(String, RefEntry)> {
        let mut entries = self
            .map
            .iter()
            .map(|(ref_id, entry)| (ref_id.clone(), entry.clone()))
            .collect::<Vec<_>>();

        entries.sort_by_key(|(ref_id, _)| {
            ref_id
                .strip_prefix('e')
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(usize::MAX)
        });

        entries
    }

    pub fn ref_ids(&self) -> std::collections::HashSet<String> {
        self.map.keys().cloned().collect()
    }

    pub fn remove(&mut self, ref_id: &str) {
        if self
            .map
            .remove(ref_id)
            .is_some_and(|entry| entry.is_exact())
        {
            self.retire_exact(ref_id.to_string());
        }
    }

    /// Keep only bounded, session-local tombstones. Expired tombstones become
    /// ordinary unknown-ref errors, never permission to rebind or replay input.
    fn retire_exact(&mut self, ref_id: String) {
        const MAX_RETIRED_EXACT_REFS: usize = 4096;
        if self.retired_exact.insert(ref_id.clone()) {
            self.retired_exact_order.push_back(ref_id);
        }
        while self.retired_exact_order.len() > MAX_RETIRED_EXACT_REFS {
            if let Some(expired) = self.retired_exact_order.pop_front() {
                self.retired_exact.remove(&expired);
            }
        }
    }

    fn missing_ref_error(&self, ref_id: &str) -> String {
        if self.retired_exact.contains(ref_id) {
            stale_ref_error(ref_id)
        } else {
            format!("Unknown ref: {}", ref_id)
        }
    }

    pub fn begin_snapshot(&mut self) {
        let exact = self
            .map
            .iter()
            .filter(|(_, entry)| entry.is_exact())
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in exact {
            self.retire_exact(id);
        }
        self.map.clear();
    }

    /// Trace snapshots may append exact identities but cannot retire or rebind
    /// any existing handle, even when the caller timed out before completion.
    pub fn merge_snapshot(&mut self, snapshot: RefMap) -> Result<(), String> {
        for (id, entry) in &snapshot.map {
            if self.map.get(id).is_some_and(|old| {
                old.backend_node_id != entry.backend_node_id
                    || old.frame_id != entry.frame_id
                    || old.session_id != entry.session_id
                    || old.is_exact() != entry.is_exact()
                    || (old.is_exact() && old.context_id != entry.context_id)
            }) {
                return Err("Preserved snapshot attempted to rebind an exact reference".into());
            }
        }
        self.map.extend(snapshot.map);
        for id in snapshot.retired_exact_order {
            if !self.map.contains_key(&id) {
                self.retire_exact(id);
            }
        }
        self.documents = snapshot.documents;
        self.next_ref = self.next_ref.max(snapshot.next_ref);
        Ok(())
    }

    /// Observe the document behind a page/frame pair. Unknown documents never
    /// retain refs, while a changed session or loader replaces the prior bucket.
    pub fn observe_document(
        &mut self,
        page_session: &str,
        frame: Option<&str>,
        session: &str,
        loader: Option<&str>,
    ) -> bool {
        let key = (page_session.to_string(), frame.map(str::to_string));
        let Some(loader) = loader.filter(|id| !id.is_empty()) else {
            self.invalidate_frame(page_session, frame);
            return false;
        };
        let changed = self
            .documents
            .get(&key)
            .is_none_or(|document| document.session != session || document.loader != loader);
        if changed {
            if frame.is_none() {
                self.documents
                    .retain(|(entry_page, _), _| entry_page != page_session);
            }
            self.documents.insert(
                key,
                DocumentRefs {
                    session: session.to_string(),
                    loader: loader.to_string(),
                    refs: HashMap::new(),
                },
            );
        }
        true
    }

    fn invalidate_frame(&mut self, page_session: &str, frame: Option<&str>) {
        if frame.is_none() {
            self.documents
                .retain(|(entry_page, _), _| entry_page != page_session);
        } else {
            self.documents
                .remove(&(page_session.to_string(), frame.map(str::to_string)));
        }
    }

    pub fn durable_ref(
        &self,
        page_session: &str,
        frame: Option<&str>,
        backend_node_id: i64,
        exact: bool,
    ) -> Option<&str> {
        self.documents
            .get(&(page_session.to_string(), frame.map(str::to_string)))?
            .refs
            .get(&(backend_node_id, exact))
            .map(String::as_str)
    }

    pub fn remember_durable_ref(
        &mut self,
        page_session: &str,
        frame: Option<&str>,
        backend_node_id: i64,
        ref_id: &str,
        exact: bool,
    ) {
        if let Some(document) = self
            .documents
            .get_mut(&(page_session.to_string(), frame.map(str::to_string)))
        {
            document
                .refs
                .insert((backend_node_id, exact), ref_id.to_string());
        }
    }

    pub fn invalidate_page(&mut self, page_session: &str) {
        self.documents
            .retain(|(entry_page, _), _| entry_page != page_session);
        self.begin_snapshot();
    }

    /// Drop all document identities while preserving the monotonic ref counter.
    pub fn invalidate_all_documents(&mut self) {
        self.documents.clear();
        self.begin_snapshot();
    }

    pub fn next_ref_num(&self) -> usize {
        self.next_ref
    }

    pub fn set_next_ref_num(&mut self, n: usize) {
        self.next_ref = n;
    }
}

pub fn parse_ref(input: &str) -> Option<String> {
    let trimmed = input.trim();

    if let Some(stripped) = trimmed.strip_prefix('@') {
        if stripped.starts_with('e') && stripped[1..].chars().all(|c| c.is_ascii_digit()) {
            return Some(stripped.to_string());
        }
    }

    if let Some(stripped) = trimmed.strip_prefix("ref=") {
        if stripped.starts_with('e') && stripped[1..].chars().all(|c| c.is_ascii_digit()) {
            return Some(stripped.to_string());
        }
    }

    if trimmed.starts_with('e')
        && trimmed.len() > 1
        && trimmed[1..].chars().all(|c| c.is_ascii_digit())
    {
        return Some(trimmed.to_string());
    }

    None
}

/// Mirror of DaemonState.active_frame_id, refreshed before every command
/// (commands are serialized by the daemon's state lock, so this cannot
/// race). It lets CSS-selector resolution honor `frame <sel>` without
/// threading a parameter through every interaction signature; snapshot refs
/// already carry their frame through the ref map.
static ACTIVE_FRAME: std::sync::OnceLock<std::sync::Mutex<Option<String>>> =
    std::sync::OnceLock::new();

pub fn set_active_frame(frame_id: Option<&str>) {
    *ACTIVE_FRAME
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap() = frame_id.map(String::from);
}

fn active_frame() -> Option<String> {
    ACTIVE_FRAME.get().and_then(|m| m.lock().unwrap().clone())
}

/// Object handle for the <iframe> element that owns a frame, resolved on the
/// parent session. Works for same-process frames where no dedicated CDP
/// session exists.
pub(super) async fn frame_owner_object_id(
    client: &CdpClient,
    session_id: &str,
    frame_id: &str,
) -> Result<String, String> {
    let owner = client
        .send_command(
            "DOM.getFrameOwner",
            Some(serde_json::json!({ "frameId": frame_id })),
            Some(session_id),
        )
        .await?;
    let backend_node_id = owner
        .get("backendNodeId")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| format!("Could not resolve the owner element of frame {}", frame_id))?;
    let result: DomResolveNodeResult = client
        .send_command_typed(
            "DOM.resolveNode",
            &DomResolveNodeParams {
                backend_node_id: Some(backend_node_id),
                node_id: None,
                object_group: Some("agent-browser".to_string()),
            },
            Some(session_id),
        )
        .await?;
    result
        .object
        .object_id
        .ok_or_else(|| format!("No objectId for the owner element of frame {}", frame_id))
}

/// Find a selector inside a same-process iframe and return its center in
/// top-level viewport coordinates (input events dispatch in that space).
/// Same-origin access to contentDocument is what makes this possible; a
/// cross-origin frame never takes this path because it has its own session.
async fn resolve_center_in_same_process_frame(
    client: &CdpClient,
    session_id: &str,
    frame_id: &str,
    selector: &str,
) -> Result<(f64, f64), String> {
    let owner_object_id = frame_owner_object_id(client, session_id, frame_id).await?;
    let find_expr = build_find_element_js_in("doc", selector);
    let function = format!(
        r#"function() {{
            const doc = this.contentDocument;
            if (!doc) return null;
            const el = {find_expr};
            if (!el) return null;
            if (el.scrollIntoViewIfNeeded) el.scrollIntoViewIfNeeded(true);
            else el.scrollIntoView({{ block: 'center', inline: 'center' }});
            const rect = el.getBoundingClientRect();
            let x = rect.x + rect.width / 2;
            let y = rect.y + rect.height / 2;
            let win = doc.defaultView;
            while (win && win.frameElement) {{
                const frameRect = win.frameElement.getBoundingClientRect();
                x += frameRect.x + win.frameElement.clientLeft;
                y += frameRect.y + win.frameElement.clientTop;
                win = win.parent;
            }}
            const blockerAt = {BLOCKER_AT_JS};
            const topDoc = win ? win.document : doc;
            return {{ x: x, y: y, blocker: blockerAt(topDoc, el, x, y) }};
        }}"#,
    );
    let result = client
        .send_command(
            "Runtime.callFunctionOn",
            Some(serde_json::json!({
                "objectId": owner_object_id,
                "functionDeclaration": function,
                "returnByValue": true,
            })),
            Some(session_id),
        )
        .await?;
    let value = result.get("result").and_then(|r| r.get("value"));
    if let Some(blocker) = value
        .and_then(|v| v.get("blocker"))
        .and_then(|v| v.as_str())
    {
        return Err(intercepted_error(selector, blocker));
    }
    let x = value.and_then(|v| v.get("x")).and_then(|v| v.as_f64());
    let y = value.and_then(|v| v.get("y")).and_then(|v| v.as_f64());
    match (x, y) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(format!(
            "Element not found in the selected frame: {}",
            selector
        )),
    }
}

/// Find a selector inside a same-process iframe and return its object handle.
async fn resolve_object_in_same_process_frame(
    client: &CdpClient,
    session_id: &str,
    frame_id: &str,
    selector: &str,
) -> Result<String, String> {
    let owner_object_id = frame_owner_object_id(client, session_id, frame_id).await?;
    let find_expr = build_find_element_js_in("doc", selector);
    let function = format!(
        "function() {{ const doc = this.contentDocument; if (!doc) return null; return {find_expr}; }}",
    );
    let result = client
        .send_command(
            "Runtime.callFunctionOn",
            Some(serde_json::json!({
                "objectId": owner_object_id,
                "functionDeclaration": function,
                "returnByValue": false,
            })),
            Some(session_id),
        )
        .await?;
    result
        .get("result")
        .and_then(|r| r.get("objectId"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| format!("Element not found in the selected frame: {}", selector))
}

/// Resolve and preflight a pointer target. CDP geometry/hit-testing and input
/// dispatch are separate commands: page script can still mutate the DOM between
/// them. An exact ref prevents semantic rebinding, not that pointer TOCTOU race.
pub async fn resolve_element_center(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(f64, f64, String), String> {
    if let Some(ref_id) = parse_ref(selector_or_ref) {
        let entry = ref_map
            .get(&ref_id)
            .ok_or_else(|| ref_map.missing_ref_error(&ref_id))?;
        // An AX-only ref remains observable, but has no exact DOM action target.
        if entry.backend_node_id.is_none() && !entry.allow_role_fallback {
            return Err(stale_ref_error(&ref_id));
        }
        if entry.is_exact() {
            // Coordinate actions must use the same connected exact-ref gate as
            // element actions before scrolling, hit-testing, or input dispatch.
            let (checked_object, checked_session) = resolve_element_object_id(
                client,
                session_id,
                ref_map,
                selector_or_ref,
                iframe_sessions,
            )
            .await?;
            let _ = client
                .send_command(
                    "Runtime.releaseObject",
                    Some(serde_json::json!({"objectId":checked_object})),
                    Some(&checked_session),
                )
                .await;
        }

        let effective_session_id = entry.session_id.as_deref().unwrap_or_else(|| {
            resolve_frame_session(entry.frame_id.as_deref(), session_id, iframe_sessions)
        });

        // Try cached backend_node_id first (fast path)
        if let Some(backend_node_id) = entry.backend_node_id {
            scroll_node_into_view(client, effective_session_id, backend_node_id).await;
            let result: Result<DomGetBoxModelResult, String> = client
                .send_command_typed(
                    "DOM.getBoxModel",
                    &DomGetBoxModelParams {
                        backend_node_id: Some(backend_node_id),
                        node_id: None,
                        object_id: None,
                    },
                    Some(effective_session_id),
                )
                .await;

            if let Ok(r) = result {
                let (x, y) = box_model_center(&r.model);
                check_node_interception(
                    client,
                    effective_session_id,
                    backend_node_id,
                    selector_or_ref,
                    x,
                    y,
                )
                .await?;
                return Ok((x, y, effective_session_id.to_string()));
            }
            if !entry.allow_role_fallback {
                return Err(stale_ref_error(&ref_id));
            }
            // backend_node_id is stale; re-query the accessibility tree below
        }

        // Fallback: re-query the accessibility tree to find a fresh node by role/name
        let fresh_id = find_node_id_by_role_name(
            client,
            session_id,
            &entry.role,
            &entry.name,
            entry.nth,
            entry.frame_id.as_deref(),
            iframe_sessions,
        )
        .await?;
        scroll_node_into_view(client, effective_session_id, fresh_id).await;
        let result: DomGetBoxModelResult = client
            .send_command_typed(
                "DOM.getBoxModel",
                &DomGetBoxModelParams {
                    backend_node_id: Some(fresh_id),
                    node_id: None,
                    object_id: None,
                },
                Some(effective_session_id),
            )
            .await?;
        let (x, y) = box_model_center(&result.model);
        check_node_interception(
            client,
            effective_session_id,
            fresh_id,
            selector_or_ref,
            x,
            y,
        )
        .await?;
        return Ok((x, y, effective_session_id.to_string()));
    }

    // CSS selector: honor an active `frame <sel>` selection.
    if let Some(frame_id) = active_frame() {
        // Cross-process iframe: its dedicated session's main frame IS the
        // iframe, so plain document-rooted resolution works there.
        if let Some(frame_session) = iframe_sessions.get(&frame_id) {
            let (x, y) = resolve_by_selector(client, frame_session, selector_or_ref).await?;
            return Ok((x, y, frame_session.clone()));
        }
        let (x, y) =
            resolve_center_in_same_process_frame(client, session_id, &frame_id, selector_or_ref)
                .await?;
        return Ok((x, y, session_id.to_string()));
    }
    let (x, y) = resolve_by_selector(client, session_id, selector_or_ref).await?;
    Ok((x, y, session_id.to_string()))
}

/// Origin of a CDP session's viewport in the recorded page's CSS coordinates.
/// Input sent to an OOPIF is local to that session; cursor history is page-local.
/// Walk owner sessions for nested OOPIFs. Content quads include iframe borders
/// and scrolling in the owning viewport.
pub async fn session_viewport_offset(
    client: &CdpClient,
    page_session: &str,
    target_session: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(f64, f64), String> {
    let mut current = target_session.to_string();
    let mut offset = (0.0, 0.0);
    for _ in 0..=iframe_sessions.len() {
        if current == page_session {
            return Ok(offset);
        }
        let frame = iframe_sessions
            .iter()
            .find(|(_, session)| **session == current)
            .map(|(frame, _)| frame)
            .ok_or("Cannot locate recording cursor frame")?;
        let mut owner = None;
        for candidate in
            std::iter::once(page_session).chain(iframe_sessions.values().map(String::as_str))
        {
            if candidate == current {
                continue;
            }
            let Ok(node) = client
                .send_command(
                    "DOM.getFrameOwner",
                    Some(serde_json::json!({"frameId": frame})),
                    Some(candidate),
                )
                .await
            else {
                continue;
            };
            let Some(backend_id) = node["backendNodeId"].as_i64() else {
                continue;
            };
            let model = client
                .send_command(
                    "DOM.getBoxModel",
                    Some(serde_json::json!({"backendNodeId": backend_id})),
                    Some(candidate),
                )
                .await?;
            let quad = model
                .pointer("/model/content")
                .and_then(Value::as_array)
                .ok_or("Cannot locate recording cursor frame bounds")?;
            let x = quad
                .first()
                .and_then(Value::as_f64)
                .ok_or("Missing frame content x")?;
            let y = quad
                .get(1)
                .and_then(Value::as_f64)
                .ok_or("Missing frame content y")?;
            offset.0 += x;
            offset.1 += y;
            owner = Some(candidate.to_string());
            break;
        }
        current = owner.ok_or("Cannot locate recording cursor frame owner")?;
    }
    Err("Cyclic recording cursor frame ownership".to_string())
}

/// Hit-test a ref-resolved node at its computed click point and error if an
/// unrelated element (overlay, banner, sticky header) would receive the input
/// instead. Best effort: resolution failures skip the check rather than block
/// the interaction.
async fn check_node_interception(
    client: &CdpClient,
    session_id: &str,
    backend_node_id: i64,
    target: &str,
    x: f64,
    y: f64,
) -> Result<(), String> {
    let resolved: Result<DomResolveNodeResult, String> = client
        .send_command_typed(
            "DOM.resolveNode",
            &DomResolveNodeParams {
                backend_node_id: Some(backend_node_id),
                node_id: None,
                object_group: Some("agent-browser".to_string()),
            },
            Some(session_id),
        )
        .await;
    let Ok(resolved) = resolved else {
        return Ok(());
    };
    let Some(object_id) = resolved.object.object_id else {
        return Ok(());
    };
    // Box-model coordinates are in the top-level viewport space, so the
    // hit-test starts from the top document. For an OOPIF node the
    // frameElement walk stops at the process boundary, where the frame's own
    // document and session-local coordinates are already consistent.
    let function = format!(
        r#"function(x, y) {{
            let topDoc = this.ownerDocument || document;
            while (topDoc.defaultView && topDoc.defaultView.frameElement) {{
                topDoc = topDoc.defaultView.frameElement.ownerDocument;
            }}
            const blockerAt = {BLOCKER_AT_JS};
            return blockerAt(topDoc, this, x, y);
        }}"#,
    );
    let result = client
        .send_command(
            "Runtime.callFunctionOn",
            Some(serde_json::json!({
                "objectId": object_id,
                "functionDeclaration": function,
                "arguments": [{ "value": x }, { "value": y }],
                "returnByValue": true,
            })),
            Some(session_id),
        )
        .await;
    if let Ok(value) = result {
        if let Some(blocker) = value
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_str())
        {
            return Err(intercepted_error(target, blocker));
        }
    }
    Ok(())
}

/// Coordinates from DOM.getBoxModel are viewport-relative, and input events
/// only land inside the viewport, so make sure the node is visible first.
/// Best effort: a node that cannot be scrolled (display:none, detached) will
/// fail in DOM.getBoxModel with a clearer error anyway.
async fn scroll_node_into_view(client: &CdpClient, session_id: &str, backend_node_id: i64) {
    let _ = client
        .send_command(
            "DOM.scrollIntoViewIfNeeded",
            Some(serde_json::json!({ "backendNodeId": backend_node_id })),
            Some(session_id),
        )
        .await;
}

/// Closed marker generated only by exact-ref resolution before input dispatch.
pub const STALE_REF_PREFIX: &str = "e2e_node_stale:";

fn stale_ref_error(ref_id: &str) -> String {
    format!("{STALE_REF_PREFIX}{ref_id}")
}

pub async fn resolve_element_object_id(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(String, String), String> {
    if let Some(ref_id) = parse_ref(selector_or_ref) {
        let entry = ref_map
            .get(&ref_id)
            .ok_or_else(|| ref_map.missing_ref_error(&ref_id))?;

        let effective_session_id = entry.session_id.as_deref().unwrap_or_else(|| {
            resolve_frame_session(entry.frame_id.as_deref(), session_id, iframe_sessions)
        });

        // Try cached backend_node_id first (fast path)
        if let Some(backend_node_id) = entry.backend_node_id {
            let result: Result<DomResolveNodeResult, String> = client
                .send_command_typed(
                    "DOM.resolveNode",
                    &{
                        let mut params=serde_json::json!({"backendNodeId":backend_node_id,"objectGroup":"agent-browser"});
                        if let Some(context)=entry.context_id{params["executionContextId"]=serde_json::json!(context);}
                        params
                    },
                    Some(effective_session_id),
                )
                .await;

            if let Ok(r) = result {
                if let Some(object_id) = r.object.object_id {
                    if entry.is_exact() {
                        // Resolving a detached backend node can still succeed. Never
                        // dispatch input to it, or rebind it to a same-name replacement.
                        let connected: Result<EvaluateResult,String> = client
                            .send_command_typed(
                                "Runtime.callFunctionOn",
                                &CallFunctionOnParams {
                                    function_declaration: "function() { return this.isConnected === true && (this.nodeType === 9 || this.ownerDocument === document); }".to_string(),
                                    object_id: Some(object_id.clone()),
                                    arguments: None,
                                    return_by_value: Some(true),
                                    await_promise: Some(false),
                                },
                                Some(effective_session_id),
                            )
                            .await;
                        let accepted = connected.as_ref().is_ok_and(|result| {
                            result.exception_details.is_none()
                                && result.result.value.as_ref().and_then(Value::as_bool)
                                    == Some(true)
                        });
                        if !accepted {
                            // The caller never receives a rejected handle, so this
                            // gate owns cleanup even on protocol/evaluation failure.
                            let mut objects = std::collections::HashSet::from([object_id]);
                            if let Ok(result) = connected {
                                objects.extend(result.result.object_id);
                                objects.extend(
                                    result
                                        .exception_details
                                        .and_then(|details| details.exception)
                                        .and_then(|exception| exception.object_id),
                                );
                            }
                            for object in objects {
                                let _ = client
                                    .send_command(
                                        "Runtime.releaseObject",
                                        Some(serde_json::json!({"objectId":object})),
                                        Some(effective_session_id),
                                    )
                                    .await;
                            }
                            return Err(stale_ref_error(&ref_id));
                        }
                    }
                    return Ok((object_id, effective_session_id.to_string()));
                }
            }
        }
        if !entry.allow_role_fallback {
            return Err(stale_ref_error(&ref_id));
        }

        // Ordinary snapshot refs retain upstream role/name fallback; exact refs do not.
        // Fallback: re-query the accessibility tree to find a fresh node by role/name
        let fresh_id = find_node_id_by_role_name(
            client,
            session_id,
            &entry.role,
            &entry.name,
            entry.nth,
            entry.frame_id.as_deref(),
            iframe_sessions,
        )
        .await?;
        let result: DomResolveNodeResult = client
            .send_command_typed(
                "DOM.resolveNode",
                &DomResolveNodeParams {
                    backend_node_id: Some(fresh_id),
                    node_id: None,
                    object_group: Some("agent-browser".to_string()),
                },
                Some(effective_session_id),
            )
            .await?;
        let object_id = result
            .object
            .object_id
            .ok_or_else(|| format!("No objectId for ref {}", ref_id))?;
        return Ok((object_id, effective_session_id.to_string()));
    }

    // Selector fallback (CSS or XPath): honor an active `frame <sel>` selection.
    if let Some(frame_id) = active_frame() {
        if let Some(frame_session) = iframe_sessions.get(&frame_id) {
            let js = build_find_element_js(selector_or_ref);
            let result: EvaluateResult = client
                .send_command_typed(
                    "Runtime.evaluate",
                    &EvaluateParams {
                        expression: js,
                        return_by_value: Some(false),
                        await_promise: Some(false),
                    },
                    Some(frame_session.as_str()),
                )
                .await?;
            let object_id = result
                .result
                .object_id
                .ok_or_else(|| format!("Element not found: {}", selector_or_ref))?;
            return Ok((object_id, frame_session.clone()));
        }
        let object_id =
            resolve_object_in_same_process_frame(client, session_id, &frame_id, selector_or_ref)
                .await?;
        return Ok((object_id, session_id.to_string()));
    }

    let js = build_find_element_js(selector_or_ref);
    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.evaluate",
            &EvaluateParams {
                expression: js,
                return_by_value: Some(false),
                await_promise: Some(false),
            },
            Some(session_id),
        )
        .await?;

    let object_id = result
        .result
        .object_id
        .ok_or_else(|| format!("Element not found: {}", selector_or_ref))?;
    Ok((object_id, session_id.to_string()))
}

/// Determine which CDP session and parameters to use for an AX tree query.
/// Cross-origin iframes have a dedicated session (no frameId needed);
/// same-origin iframes use the parent session with a frameId parameter.
pub(super) fn resolve_ax_session<'a>(
    frame_id: Option<&str>,
    session_id: &'a str,
    iframe_sessions: &'a HashMap<String, String>,
) -> (serde_json::Value, &'a str) {
    if let Some(frame_id) = frame_id {
        if let Some(iframe_sid) = iframe_sessions.get(frame_id) {
            (serde_json::json!({}), iframe_sid.as_str())
        } else {
            (serde_json::json!({ "frameId": frame_id }), session_id)
        }
    } else {
        (serde_json::json!({}), session_id)
    }
}

/// Resolve the effective CDP session for an element's frame.
/// If the element's frame_id has a dedicated cross-origin iframe session, return it.
/// Otherwise, return the parent session.
fn resolve_frame_session<'a>(
    frame_id: Option<&str>,
    session_id: &'a str,
    iframe_sessions: &'a HashMap<String, String>,
) -> &'a str {
    frame_id
        .and_then(|fid| iframe_sessions.get(fid))
        .map(|s| s.as_str())
        .unwrap_or(session_id)
}

/// Re-query the accessibility tree to find a node matching role+name+nth,
/// returning its fresh backendDOMNodeId. This uses the same data source
/// (Accessibility.getFullAXTree) that built the ref map during snapshot,
/// so role/name matching is guaranteed to be consistent.
async fn find_node_id_by_role_name(
    client: &CdpClient,
    session_id: &str,
    role: &str,
    name: &str,
    nth: Option<usize>,
    frame_id: Option<&str>,
    iframe_sessions: &HashMap<String, String>,
) -> Result<i64, String> {
    let (ax_params, effective_session_id) =
        resolve_ax_session(frame_id, session_id, iframe_sessions);
    let ax_tree: GetFullAXTreeResult = client
        .send_command_typed(
            "Accessibility.getFullAXTree",
            &ax_params,
            Some(effective_session_id),
        )
        .await?;

    let nth_index = nth.unwrap_or(0);
    let mut match_count: usize = 0;

    for node in &ax_tree.nodes {
        if node.ignored.unwrap_or(false) {
            continue;
        }
        let node_role = extract_ax_string(&node.role);
        let node_name = extract_ax_string(&node.name);
        if node_role == role && node_name == name {
            if match_count == nth_index {
                return node.backend_d_o_m_node_id.ok_or_else(|| {
                    format!(
                        "AX node has no backendDOMNodeId for role={} name={}",
                        role, name
                    )
                });
            }
            match_count += 1;
        }
    }

    Err(format!(
        "Could not locate element with role={} name={}",
        role, name
    ))
}

pub(super) fn extract_ax_string(value: &Option<AXValue>) -> String {
    match value {
        Some(v) => match &v.value {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::Bool(b)) => b.to_string(),
            _ => String::new(),
        },
        None => String::new(),
    }
}

/// Build a JS expression that finds a DOM element by CSS selector or XPath.
fn build_find_element_js(selector: &str) -> String {
    build_find_element_js_in("document", selector)
}

/// Same as build_find_element_js but rooted at an arbitrary Document
/// expression (e.g. an iframe's contentDocument).
fn build_find_element_js_in(root: &str, selector: &str) -> String {
    if let Some(xpath) = selector.strip_prefix("xpath=") {
        format!(
            "{root}.evaluate({xpath}, {root}, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue",
            xpath = serde_json::to_string(xpath).unwrap_or_default(),
        )
    } else {
        format!(
            "{root}.querySelector({selector})",
            selector = serde_json::to_string(selector).unwrap_or_default(),
        )
    }
}

/// Build a JS expression that counts matching DOM elements by CSS selector or XPath.
fn build_count_elements_js(selector: &str) -> String {
    if let Some(xpath) = selector.strip_prefix("xpath=") {
        format!(
            "document.evaluate({}, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null).snapshotLength",
            serde_json::to_string(xpath).unwrap_or_default()
        )
    } else {
        format!(
            "document.querySelectorAll({}).length",
            serde_json::to_string(selector).unwrap_or_default()
        )
    }
}

/// JS function source for `blockerAt(doc, el, x, y)`: returns a short
/// description of the element that would actually receive a click at (x, y)
/// when that element is unrelated to `el`, or null when the click would land
/// on `el` (or something that activates it). Relations that count as "lands
/// on el": shadow-including ancestors/descendants in either direction, and
/// label/control association (custom checkboxes hide the input under a styled
/// sibling inside the same label).
const BLOCKER_AT_JS: &str = r#"(doc, el, x, y) => {
    // Descend from the given document through same-origin iframes so a point
    // over a frame resolves to the element inside it, in that frame's space.
    let d = doc, lx = x, ly = y;
    let hit = d.elementFromPoint(lx, ly);
    while (hit && (hit.tagName === 'IFRAME' || hit.tagName === 'FRAME') && hit.contentDocument && hit !== el) {
        const r = hit.getBoundingClientRect();
        lx -= r.x + hit.clientLeft;
        ly -= r.y + hit.clientTop;
        d = hit.contentDocument;
        hit = d.elementFromPoint(lx, ly);
    }
    if (!hit || hit === el) return null;
    const up = (n) => n.parentNode || n.host || (n.getRootNode && n.getRootNode().host) || null;
    for (let n = hit; n; n = up(n)) { if (n === el) return null; }
    for (let n = el; n; n = up(n)) { if (n === hit) return null; }
    const hitLabel = hit.closest ? hit.closest('label') : null;
    if (hitLabel && (hitLabel.control === el || hitLabel.contains(el))) return null;
    const elLabel = el.closest ? el.closest('label') : null;
    if (elLabel && elLabel.contains(hit)) return null;
    let desc = hit.tagName.toLowerCase();
    if (hit.id) desc += '#' + hit.id;
    else if (typeof hit.className === 'string' && hit.className.trim())
        desc += '.' + hit.className.trim().split(/\s+/).slice(0, 2).join('.');
    if (!hit.id && hit.closest) {
        const anchored = hit.closest('[id]');
        if (anchored && anchored !== hit)
            desc += ' inside ' + anchored.tagName.toLowerCase() + '#' + anchored.id;
    }
    return desc;
}"#;

fn build_selector_js(selector: &str) -> String {
    let find_expr = build_find_element_js(selector);
    // Input events dispatch at viewport coordinates, so an element outside the
    // viewport must be scrolled into view first or the click lands on nothing.
    // The blocker check reports an overlay covering the click point instead of
    // letting the input land on it and silently doing the wrong thing.
    format!(
        r#"(() => {{
            const el = {find_expr};
            if (!el) return null;
            const inView = (r) => r.width > 0 && r.height > 0 &&
                r.bottom > 0 && r.right > 0 &&
                r.top < (window.innerHeight || document.documentElement.clientHeight) &&
                r.left < (window.innerWidth || document.documentElement.clientWidth);
            let rect = el.getBoundingClientRect();
            if (!inView(rect)) {{
                el.scrollIntoView({{ block: 'center', inline: 'center', behavior: 'instant' }});
                rect = el.getBoundingClientRect();
            }}
            const x = rect.x + rect.width / 2;
            const y = rect.y + rect.height / 2;
            const blockerAt = {BLOCKER_AT_JS};
            return {{ x: x, y: y, blocker: blockerAt(document, el, x, y) }};
        }})()"#,
    )
}

async fn resolve_by_selector(
    client: &CdpClient,
    session_id: &str,
    selector: &str,
) -> Result<(f64, f64), String> {
    let js = build_selector_js(selector);

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.evaluate",
            &EvaluateParams {
                expression: js,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(session_id),
        )
        .await?;

    let val = result.result.value.unwrap_or(Value::Null);
    if let Some(blocker) = val.get("blocker").and_then(|v| v.as_str()) {
        return Err(intercepted_error(selector, blocker));
    }
    let x = val.get("x").and_then(|v| v.as_f64());
    let y = val.get("y").and_then(|v| v.as_f64());

    match (x, y) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(format!("Element not found: {}", selector)),
    }
}

fn intercepted_error(target: &str, blocker: &str) -> String {
    format!(
        "Element '{}' is covered by <{}> at its click point, so the input would land on that element instead. Dismiss or interact with the covering element first (it is often a dialog, banner, or sticky header).",
        target, blocker
    )
}

fn box_model_center(model: &BoxModel) -> (f64, f64) {
    // content quad: [x1,y1, x2,y2, x3,y3, x4,y4]
    if model.content.len() >= 8 {
        let x = (model.content[0] + model.content[2] + model.content[4] + model.content[6]) / 4.0;
        let y = (model.content[1] + model.content[3] + model.content[5] + model.content[7]) / 4.0;
        (x, y)
    } else {
        (0.0, 0.0)
    }
}

pub async fn get_element_text(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<String, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration:
                    "function() { return this.innerText || this.textContent || ''; }".to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result
        .result
        .value
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default())
}

pub async fn get_element_attribute(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    attribute: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<Value, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: format!(
                    "function() {{ return this.getAttribute({}); }}",
                    serde_json::to_string(attribute).unwrap_or_default()
                ),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result.result.value.unwrap_or(Value::Null))
}

pub async fn is_element_visible(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<bool, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: r#"function() {
                    const rect = this.getBoundingClientRect();
                    const style = window.getComputedStyle(this);
                    return rect.width > 0 && rect.height > 0 &&
                           style.visibility !== 'hidden' &&
                           style.display !== 'none' &&
                           parseFloat(style.opacity) > 0;
                }"#
                .to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result
        .result
        .value
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

pub async fn is_element_enabled(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<bool, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: "function() { return !this.disabled; }".to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result
        .result
        .value
        .and_then(|v| v.as_bool())
        .unwrap_or(true))
}

pub async fn is_element_checked(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<bool, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    // Mirrors Playwright's getChecked() with follow-label retargeting:
    // 1. If element is a native checkbox/radio input, return .checked
    // 2. If element has an ARIA checked role, return aria-checked
    // 3. Follow label → input association (label.control)
    // 4. Check for nested checkbox/radio input as last resort
    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: r#"function() {
                    var el = this;
                    // Native checkbox/radio input
                    var tag = el.tagName && el.tagName.toUpperCase();
                    if (tag === 'INPUT' && (el.type === 'checkbox' || el.type === 'radio')) {
                        return el.checked;
                    }
                    // ARIA role-based checked state
                    var role = el.getAttribute && el.getAttribute('role');
                    var ariaCheckedRoles = ['checkbox','radio','switch','menuitemcheckbox','menuitemradio','option','treeitem'];
                    if (role && ariaCheckedRoles.indexOf(role) !== -1) {
                        return el.getAttribute('aria-checked') === 'true';
                    }
                    // Follow label association (Playwright follow-label retarget)
                    var label = el;
                    if (tag !== 'LABEL') {
                        label = el.closest && el.closest('label');
                    }
                    if (label && label.tagName && label.tagName.toUpperCase() === 'LABEL' && label.control) {
                        var ctrl = label.control;
                        if (ctrl.type === 'checkbox' || ctrl.type === 'radio') {
                            return ctrl.checked;
                        }
                    }
                    // Check for nested native input
                    var input = el.querySelector && el.querySelector('input[type="checkbox"], input[type="radio"]');
                    if (input) return input.checked;
                    return false;
                }"#.to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result
        .result
        .value
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

pub async fn get_element_inner_text(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<String, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: "function() { return this.innerText || ''; }".to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result
        .result
        .value
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default())
}

pub async fn get_element_inner_html(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<String, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: "function() { return this.innerHTML || ''; }".to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result
        .result
        .value
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default())
}

pub async fn get_element_input_value(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<String, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration:
                    r#"function() {
                        const autocomplete = (this.getAttribute?.('autocomplete') || '').toLowerCase().split(/\s+/);
                        if (this.type === 'password' || autocomplete.includes('current-password') || autocomplete.includes('new-password')) return '';
                        return typeof this.value === 'string' ? this.value : '';
                    }"#
                        .to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result
        .result
        .value
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default())
}

pub async fn set_element_value(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    value: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(), String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let js = format!(
        "function() {{ this.value = {}; this.dispatchEvent(new Event('input', {{bubbles: true}})); this.dispatchEvent(new Event('change', {{bubbles: true}})); }}",
        serde_json::to_string(value).unwrap_or_default()
    );

    client
        .send_command_typed::<_, EvaluateResult>(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: js,
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(())
}

pub async fn get_element_bounding_box(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<Value, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: r#"function() {
                    const r = this.getBoundingClientRect();
                    return { x: r.x, y: r.y, width: r.width, height: r.height };
                }"#
                .to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    result
        .result
        .value
        .ok_or_else(|| format!("Could not get bounding box for: {}", selector_or_ref))
}

pub async fn get_element_count(
    client: &CdpClient,
    session_id: &str,
    selector: &str,
) -> Result<i64, String> {
    let js = build_count_elements_js(selector);

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.evaluate",
            &EvaluateParams {
                expression: js,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(session_id),
        )
        .await?;

    Ok(result.result.value.and_then(|v| v.as_i64()).unwrap_or(0))
}

pub async fn get_element_styles(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    properties: Option<Vec<String>>,
    iframe_sessions: &HashMap<String, String>,
) -> Result<Value, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let js = match properties {
        Some(props) => {
            let props_json = serde_json::to_string(&props).unwrap_or("[]".to_string());
            format!(
                r#"function() {{
                    const s = window.getComputedStyle(this);
                    const props = {};
                    const result = {{}};
                    for (const p of props) result[p] = s.getPropertyValue(p);
                    return result;
                }}"#,
                props_json
            )
        }
        None => r#"function() {
                    const s = window.getComputedStyle(this);
                    const result = {};
                    for (let i = 0; i < s.length; i++) {
                        const p = s[i];
                        result[p] = s.getPropertyValue(p);
                    }
                    return result;
                }"#
        .to_string(),
    };

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: js,
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result.result.value.unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_exact_refs_are_bounded_and_never_become_semantic_refs() {
        let mut refs = RefMap::new();
        refs.add("e0".into(), Some(1), "button", "ordinary", None);
        refs.remove("e0");
        assert_eq!(refs.missing_ref_error("e0"), "Unknown ref: e0");
        for id in 1..=4097 {
            let name = format!("e{id}");
            refs.add_exact_backend_node(name.clone(), id);
            refs.remove(&name);
        }
        assert_eq!(refs.retired_exact.len(), 4096);
        assert_eq!(refs.missing_ref_error("e1"), "Unknown ref: e1");
        assert_eq!(refs.missing_ref_error("e4097"), "e2e_node_stale:e4097");
        refs.add_exact_backend_node("e4097".into(), 4097);
        assert!(!refs.retired_exact.contains("e4097"));
        refs.invalidate_all_documents();
        assert_eq!(refs.missing_ref_error("e4097"), "e2e_node_stale:e4097");
    }

    #[test]
    fn durable_refs_keep_exact_and_semantic_capabilities_separate() {
        let mut refs = RefMap::new();
        refs.observe_document("page", None, "page", Some("loader"));
        refs.remember_durable_ref("page", None, 42, "e1", false);
        refs.remember_durable_ref("page", None, 42, "e2", true);
        assert_eq!(refs.durable_ref("page", None, 42, false), Some("e1"));
        assert_eq!(refs.durable_ref("page", None, 42, true), Some("e2"));
    }

    #[tokio::test]
    async fn ordinary_ref_retains_upstream_role_name_fallback() {
        use futures_util::{SinkExt, StreamExt};
        use serde_json::json;
        use tokio_tungstenite::tungstenite::Message;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            for (step, method) in [
                "DOM.resolveNode",
                "Accessibility.getFullAXTree",
                "DOM.resolveNode",
            ]
            .into_iter()
            .enumerate()
            {
                let request = ws.next().await.unwrap().unwrap();
                let request: Value = serde_json::from_str(request.to_text().unwrap()).unwrap();
                assert_eq!(request["method"], method);
                let mut response = json!({"id":request["id"], "result":{}});
                match step {
                    0 => {
                        assert_eq!(request["params"]["backendNodeId"], 42);
                        response["error"] = json!({"code":-32000,"message":"Node removed"});
                    }
                    1 => {
                        response["result"] = json!({"nodes":[{"nodeId":"replacement","role":{"type":"role","value":"button"},"name":{"type":"string","value":"Save"},"backendDOMNodeId":43}]})
                    }
                    _ => {
                        assert_eq!(request["params"]["backendNodeId"], 43);
                        response["result"] =
                            json!({"object":{"type":"object","objectId":"replacement"}});
                    }
                }
                ws.send(Message::Text(response.to_string())).await.unwrap();
            }
        });
        let client = CdpClient::connect(&url).await.unwrap();
        let mut refs = RefMap::new();
        refs.add("e1".into(), Some(42), "button", "Save", None);
        let (object, session) =
            resolve_element_object_id(&client, "page", &refs, "@e1", &HashMap::new())
                .await
                .unwrap();
        assert_eq!((object.as_str(), session.as_str()), ("replacement", "page"));
        server.await.unwrap();
    }

    #[test]
    fn ordinary_refs_allow_fallback_but_exact_refs_never_rebind() {
        let mut map = RefMap::new();
        map.add_with_frame("e1".into(), Some(42), "button", "Save", None, None);
        map.add_exact_with_frame("e2".into(), 43, "button", "Save", None, None);
        assert!(map.get("e1").unwrap().allow_role_fallback);
        assert!(!map.get("e2").unwrap().allow_role_fallback);
        assert_ne!(
            map.get("e1").unwrap().backend_node_id,
            map.get("e2").unwrap().backend_node_id
        );
    }

    #[tokio::test]
    async fn unknown_ref_rejects_both_resolvers_without_querying_same_name_node() {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            if let Ok(Some(Ok(Message::Text(command)))) =
                tokio::time::timeout(std::time::Duration::from_millis(100), ws.next()).await
            {
                panic!("AX-only ref must not query or dispatch: {command}");
            }
        });
        let client = CdpClient::connect(&url).await.unwrap();
        let mut map = RefMap::new();
        // No exact ref is issued for an AX-only node without a backend identity.
        map.add_with_frame("e2".into(), Some(43), "button", "Save", None, None);
        let object = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            resolve_element_object_id(&client, "page-session", &map, "@e1", &HashMap::new()),
        )
        .await
        .unwrap();
        assert_eq!(object.unwrap_err(), "Unknown ref: e1");
        let center = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            resolve_element_center(&client, "page-session", &map, "@e1", &HashMap::new()),
        )
        .await
        .unwrap();
        assert_eq!(center.unwrap_err(), "Unknown ref: e1");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn coordinate_probe_releases_its_handle_before_geometry() {
        use futures_util::{SinkExt, StreamExt};
        use serde_json::json;
        use tokio_tungstenite::tungstenite::Message;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            for method in [
                "DOM.resolveNode",
                "Runtime.callFunctionOn",
                "Runtime.releaseObject",
                "DOM.scrollIntoViewIfNeeded",
                "DOM.getBoxModel",
            ] {
                let incoming = ws.next().await.unwrap().unwrap();
                let request: Value = serde_json::from_str(incoming.to_text().unwrap()).unwrap();
                assert_eq!(request["method"], method);
                let mut response = json!({"id":request["id"],"result":{}});
                match method {
                    "DOM.resolveNode" => {
                        response["result"] = json!({"object":{"type":"object","objectId":"probe"}})
                    }
                    "Runtime.callFunctionOn" => {
                        response["result"] = json!({"result":{"type":"boolean","value":true}})
                    }
                    "Runtime.releaseObject" => assert_eq!(request["params"]["objectId"], "probe"),
                    "DOM.getBoxModel" => {
                        response["error"] = json!({"code":-32000,"message":"No box"})
                    }
                    _ => {}
                }
                ws.send(Message::Text(response.to_string())).await.unwrap();
            }
        });
        let client = CdpClient::connect(&url).await.unwrap();
        let mut refs = RefMap::new();
        refs.add_exact_with_frame("e1".into(), 42, "button", "Save", None, None);
        assert!(
            resolve_element_center(&client, "page", &refs, "@e1", &HashMap::new())
                .await
                .is_err()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn detached_ref_rejects_without_querying_same_name_node() {
        use futures_util::{SinkExt, StreamExt};
        use serde_json::json;
        use tokio_tungstenite::tungstenite::Message;
        for (backend_missing, center) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                let expected = if backend_missing { 1 } else { 2 };
                for step in 0..expected {
                    let incoming = ws.next().await.unwrap().unwrap();
                    let request: Value = serde_json::from_str(incoming.to_text().unwrap()).unwrap();
                    let mut response =
                        json!({ "id": request["id"], "sessionId": request["sessionId"] });
                    if step == 0 {
                        assert_eq!(request["method"], "DOM.resolveNode");
                        assert_eq!(request["params"]["backendNodeId"], 42);
                        if backend_missing {
                            response["error"] = json!({"code": -32000, "message": "Node removed"});
                        } else {
                            response["result"] =
                                json!({"object":{"type":"object","objectId":"old-node"}});
                        }
                    } else {
                        assert_eq!(request["method"], "Runtime.callFunctionOn");
                        assert_eq!(request["params"]["objectId"], "old-node");
                        response["result"] = json!({"result":{"type":"boolean","value":false}});
                    }
                    ws.send(Message::Text(response.to_string())).await.unwrap();
                }
                if !backend_missing {
                    let incoming = ws.next().await.unwrap().unwrap();
                    let request: Value = serde_json::from_str(incoming.to_text().unwrap()).unwrap();
                    assert_eq!(request["method"], "Runtime.releaseObject");
                    assert_eq!(request["params"]["objectId"], "old-node");
                    ws.send(Message::Text(
                        json!({"id":request["id"],"result":{}}).to_string(),
                    ))
                    .await
                    .unwrap();
                }
                // No Accessibility.getFullAXTree or input event may follow.
                if let Ok(Some(Ok(Message::Text(next)))) =
                    tokio::time::timeout(std::time::Duration::from_millis(50), ws.next()).await
                {
                    panic!("Stale ref caused another command: {next}");
                }
            });
            let client = CdpClient::connect(&url).await.unwrap();
            let mut map = RefMap::new();
            map.add_exact_with_frame("e1".into(), 42, "button", "Save", None, None);
            map.add_with_frame("e2".into(), Some(43), "button", "Save", None, None);
            let error = if center {
                resolve_element_center(&client, "page-session", &map, "@e1", &HashMap::new())
                    .await
                    .unwrap_err()
            } else {
                resolve_element_object_id(&client, "page-session", &map, "@e1", &HashMap::new())
                    .await
                    .unwrap_err()
            };
            assert_eq!(error, "e2e_node_stale:e1");
            server.await.unwrap();
        }
    }

    #[test]
    fn preserved_snapshot_keeps_imported_identity_and_rejects_rebinding() {
        let mut live = RefMap::new();
        live.add_with_frame("e1".into(), Some(42), "button", "original", None, None);
        live.set_next_ref_num(2);
        let mut snapshot = live.clone();
        snapshot.begin_snapshot();
        snapshot.add_with_frame("e2".into(), Some(43), "button", "new", None, None);
        snapshot.set_next_ref_num(3);
        live.merge_snapshot(snapshot).unwrap();
        assert_eq!(live.get("e1").unwrap().backend_node_id, Some(42));
        assert_eq!(live.next_ref_num(), 3);
        let mut bad = live.clone();
        bad.add_with_frame("e1".into(), Some(99), "button", "replacement", None, None);
        assert!(live.merge_snapshot(bad).is_err());
        assert_eq!(live.get("e1").unwrap().backend_node_id, Some(42));
    }

    #[test]
    fn test_parse_ref_at_prefix() {
        assert_eq!(parse_ref("@e1"), Some("e1".to_string()));
        assert_eq!(parse_ref("@e123"), Some("e123".to_string()));
    }

    #[test]
    fn test_parse_ref_equals_prefix() {
        assert_eq!(parse_ref("ref=e1"), Some("e1".to_string()));
    }

    #[test]
    fn test_parse_ref_bare() {
        assert_eq!(parse_ref("e1"), Some("e1".to_string()));
        assert_eq!(parse_ref("e42"), Some("e42".to_string()));
    }

    #[test]
    fn test_parse_ref_invalid() {
        assert_eq!(parse_ref("button"), None);
        assert_eq!(parse_ref("e"), None);
        assert_eq!(parse_ref("1"), None);
        assert_eq!(parse_ref(""), None);
    }

    #[test]
    fn test_ref_map_basic() {
        let mut map = RefMap::new();
        map.add("e1".to_string(), Some(42), "button", "Submit", None);
        assert!(map.get("e1").is_some());
        assert_eq!(map.get("e1").unwrap().role, "button");
        assert!(map.get("e2").is_none());
    }

    #[test]
    fn test_ref_map_clear_preserves_monotonic_numbering() {
        let mut map = RefMap::new();
        map.add("e1".to_string(), Some(42), "button", "Submit", None);
        map.set_next_ref_num(2);

        map.begin_snapshot();

        assert!(map.get("e1").is_none());
        assert_eq!(map.next_ref_num(), 2);
    }

    #[test]
    fn test_durable_refs_are_scoped_by_document_and_frame() {
        let mut map = RefMap::new();
        assert!(map.observe_document("page-a", None, "session-a", Some("loader-a")));
        assert!(map.observe_document(
            "page-a",
            Some("frame-a"),
            "frame-session",
            Some("frame-loader")
        ));
        map.remember_durable_ref("page-a", None, 42, "e1", false);
        map.remember_durable_ref("page-a", Some("frame-a"), 42, "e2", false);
        assert_eq!(map.durable_ref("page-a", None, 42, false), Some("e1"));
        assert_eq!(
            map.durable_ref("page-a", Some("frame-a"), 42, false),
            Some("e2")
        );
        assert_eq!(map.durable_ref("page-b", None, 42, false), None);

        map.invalidate_page("page-a");
        assert_eq!(map.durable_ref("page-a", None, 42, false), None);
        assert_eq!(map.next_ref_num(), 1);
    }

    #[test]
    fn invalidating_one_page_preserves_other_page_documents() {
        let mut map = RefMap::new();
        assert!(map.observe_document("page-a", None, "session-a", Some("loader-a")));
        map.remember_durable_ref("page-a", None, 42, "e1", false);
        assert!(map.observe_document("page-b", None, "session-b", Some("loader-b")));
        map.remember_durable_ref("page-b", None, 42, "e2", false);

        map.invalidate_page("page-b");

        assert_eq!(map.durable_ref("page-a", None, 42, false), Some("e1"));
        assert_eq!(map.durable_ref("page-b", None, 42, false), None);
    }

    #[test]
    fn test_build_selector_js_css() {
        let js = build_selector_js("#submit-btn");
        assert!(js.contains("document.querySelector(\"#submit-btn\")"));
        assert!(!js.contains("document.evaluate"));
    }

    #[test]
    fn test_build_selector_js_xpath() {
        let js = build_selector_js("xpath=//button[@id='ok']");
        assert!(js.contains("document.evaluate(\"//button[@id='ok']\", document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null)"));
        assert!(!js.contains("document.querySelector"));
    }

    #[test]
    fn test_build_selector_js_xpath_empty() {
        let js = build_selector_js("xpath=");
        assert!(js.contains("document.evaluate"));
    }

    #[test]
    fn test_build_selector_js_not_xpath_prefix() {
        // "xpath" without "=" should be treated as CSS selector
        let js = build_selector_js("xpath//div");
        assert!(js.contains("document.querySelector"));
    }

    #[test]
    fn test_build_count_elements_js_css() {
        let js = build_count_elements_js(".item");
        assert!(js.contains("document.querySelectorAll(\".item\").length"));
        assert!(!js.contains("document.evaluate"));
    }

    #[test]
    fn test_build_count_elements_js_xpath() {
        let js = build_count_elements_js("xpath=//li");
        assert!(js.contains("document.evaluate(\"//li\", document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null).snapshotLength"));
        assert!(!js.contains("querySelectorAll"));
    }

    #[test]
    fn test_box_model_center() {
        let model = BoxModel {
            content: vec![10.0, 20.0, 110.0, 20.0, 110.0, 60.0, 10.0, 60.0],
            padding: vec![],
            border: vec![],
            margin: vec![],
            width: 100,
            height: 40,
        };
        let (x, y) = box_model_center(&model);
        assert!((x - 60.0).abs() < 0.01);
        assert!((y - 40.0).abs() < 0.01);
    }

    // -----------------------------------------------------------------------
    // resolve_frame_session tests (Issue #925)
    // Cross-origin iframe elements must resolve to the dedicated session.
    // -----------------------------------------------------------------------

    #[test]
    fn test_cross_origin_element_uses_dedicated_session() {
        let mut iframe_sessions = HashMap::new();
        iframe_sessions.insert(
            "cross-origin-frame".to_string(),
            "iframe-session".to_string(),
        );

        let session = resolve_frame_session(
            Some("cross-origin-frame"),
            "parent-session",
            &iframe_sessions,
        );

        assert_eq!(session, "iframe-session");
    }

    #[test]
    fn test_same_origin_element_uses_parent_session() {
        let iframe_sessions = HashMap::new();

        let session = resolve_frame_session(
            Some("same-origin-frame"),
            "parent-session",
            &iframe_sessions,
        );

        assert_eq!(session, "parent-session");
    }

    #[test]
    fn test_main_frame_element_uses_parent_session() {
        let iframe_sessions = HashMap::new();

        let session = resolve_frame_session(None, "parent-session", &iframe_sessions);

        assert_eq!(session, "parent-session");
    }
}
