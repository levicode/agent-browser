//! Chromium publishes structural, attribute, character, shadow and pseudo
//! changes for a deeply bound frontend Document. The snapshot holds no
//! execution handles. Focus, accessibility, computed styles, form state,
//! JavaScript handlers, geometry and security policy are sampled on every read.
use super::*;
use crate::native::cdp::dom_epoch::DomEpoch;
use std::sync::Arc;

pub(super) struct Snapshot {
    value: Value,
    structure: Result<Structure, ObservationError>,
}

pub(super) struct Structure {
    pub graph: author_projection::Graph,
    pub light_index: Arc<light_document::LightIndex>,
    pub candidates: HashSet<i64>,
    pub suppressed: HashMap<i64, (i64, String)>,
    pub roots: Vec<i64>,
    pub domains: SecurityDomains,
    field_roots: Option<fresh_query::RootInventory>,
    pub folds: HashMap<i64, Vec<FoldedText>>,
    pub folded: HashSet<i64>,
    pub origins: Arc<std::sync::OnceLock<Result<HashMap<i64, PseudoOrigin>, ObservationError>>>,
}

impl Structure {
    fn read(root: &Value) -> Result<Self, ObservationError> {
        let (graph, internal) = author_projection::Graph::read_with_internals(root)?;
        let candidates = graph.ids.iter().copied().collect();
        let mut suppressed = HashMap::new();
        collect_suppressed(root, false, &mut suppressed);
        let roots = security_root_ids(root)?;
        let domains = SecurityDomains::from_internal(root, &roots, internal)?;
        let field_roots = fresh_query::roots_from_inventory(root, &roots, &domains.internal)
            .ok()
            .flatten();
        let mut folds = HashMap::new();
        let mut folded = HashSet::new();
        collect_folded_text(
            root,
            &mut folds,
            &mut folded,
            &candidates,
            &suppressed.keys().copied().collect(),
            &HashMap::new(),
        );
        Ok(Self {
            graph,
            light_index: Default::default(),
            candidates,
            suppressed,
            roots,
            domains,
            folds,
            folded,
            field_roots,
            origins: Default::default(),
        })
    }
}

/// Only the tree edges and native identities used for light, pseudo and
/// display membership survive the acquisition. The folded plan was already
/// bounded. Raw text, attributes, URLs and child Documents need not be kept.
fn retain_membership(node: &mut Value) {
    let Some(map) = node.as_object_mut() else {
        return;
    };
    map.retain(|key, _| {
        matches!(
            key.as_str(),
            "nodeId"
                | "backendNodeId"
                | "nodeType"
                | "localName"
                | "nodeName"
                | "pseudoType"
                | "shadowRootType"
                | "children"
                | "shadowRoots"
                | "pseudoElements"
        )
    });
    for key in ["children", "shadowRoots", "pseudoElements"] {
        if let Some(children) = map.get_mut(key).and_then(Value::as_array_mut) {
            for child in children {
                retain_membership(child);
            }
        }
    }
}

impl Snapshot {
    fn new(mut value: Value) -> Self {
        let structure = Structure::read(&value["root"]);
        // Reading/validating the graph establishes the recursion bound.
        if structure.is_ok() {
            retain_membership(&mut value["root"]);
        }
        Self { value, structure }
    }

    pub(super) fn structure(&self) -> Result<&Structure, ObservationError> {
        self.structure.as_ref().map_err(Clone::clone)
    }
}

impl std::ops::Deref for Snapshot {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.value
    }
}

#[derive(Clone)]
pub(crate) struct DocumentInventory {
    monitor: Arc<DomEpoch>,
    stamp: u64,
    scope: String,
    generation: u64,
    binding: ExactBinding,
    root: i64,
    backend: i64,
    value: Arc<Snapshot>,
    order: Arc<std::sync::OnceLock<Arc<light_document::Order>>>,
}

pub(super) async fn acquire(
    client: &CdpClient,
    frame: &ObservationFrame,
    lease: &OperationLease,
    frame_tree: &Value,
    prior: &mut Option<DocumentInventory>,
    scope: &str,
    layout: &AxRead<'_>,
    layout_ready: bool,
    start_ax: &tokio::sync::Notify,
    barrier: Option<&super::super::client_targets::ProtectedTargetBarrier>,
) -> Result<Arc<Snapshot>, ObservationError> {
    // Blink materializes CSS pseudo elements during style/layout. Even a valid
    // cached frontend root must see any resulting DOM events before reuse.
    // On a cold document, getDocument before this barrier can omit ::marker.
    InventoryCheckpoint::Document.check(barrier, lease)?;
    if !layout_ready {
        layout.clone().await?;
        InventoryCheckpoint::Document.check(barrier, lease)?;
    }
    let top = frame.parent_frame_id.is_none()
        && frame_tree["frameTree"]["frame"]["id"].as_str() == Some(frame.binding.frame.as_str());
    if !top || client.debt_ledger().is_none() {
        return frame_dom_from_tree(client, frame, lease, frame_tree)
            .await
            .map(|value| Arc::new(Snapshot::new(value)));
    }
    let monitor = client.frontend_dom_epoch();
    let before = monitor.stamp();
    if let Some(saved) = prior.as_ref().filter(|saved| {
        Arc::ptr_eq(&saved.monitor, &monitor)
            && before == Some(saved.stamp)
            && saved.scope == scope
            && saved.generation == lease.generation
            && saved.binding == frame.binding
    }) {
        // The renderer must still bind the original frontend ID to this exact
        // Document. The response also fences previously queued DOM events.
        let current = command(
            client,
            &frame.binding.session,
            "DOM.pushNodesByBackendIdsToFrontend",
            json!({"backendNodeIds":[saved.backend]}),
            lease,
        )
        .await?;
        let nodes = current["nodeIds"]
            .as_array()
            .ok_or(ObservationError::BackendFailure)?;
        if nodes.len() != 1 || nodes[0].as_i64().is_none() {
            return Err(ObservationError::BackendFailure);
        }
        if nodes[0].as_i64() == Some(saved.root) && monitor.stamp() == before {
            return Ok(Arc::clone(&saved.value));
        }
    }
    *prior = None;
    let layout_root = if layout_ready {
        // A shallow AX read completes Blink's layout lifecycle, including
        // generated ::marker nodes. Keep the complete AX read for projection.
        let shallow = command(
            client,
            &frame.binding.session,
            "Accessibility.getFullAXTree",
            json!({"frameId":frame.binding.frame,"depth":1}),
            lease,
        )
        .await?;
        let root = shallow["nodes"].as_array().and_then(|nodes| {
            nodes.iter().find_map(|node| {
                (node["role"]["value"] == "RootWebArea")
                    .then(|| node["backendDOMNodeId"].as_i64().filter(|id| *id > 0))
                    .flatten()
            })
        });
        if root.is_none() {
            layout.clone().await?;
        }
        // Start both complete reads after the layout fence. Neither grants
        // authority until its own result and the final frame proof settle.
        start_ax.notify_one();
        root
    } else {
        None
    };
    let before = monitor.stamp();
    InventoryCheckpoint::Document.check(barrier, lease)?;
    let document = frame_dom_from_tree(client, frame, lease, frame_tree).await?;
    InventoryCheckpoint::Document.check(barrier, lease)?;
    if layout_root.is_some_and(|id| document["root"]["backendNodeId"].as_i64() != Some(id)) {
        return Err(ObservationError::StaleReference);
    }
    let snapshot = if layout_ready {
        tokio::task::spawn_blocking(move || Snapshot::new(document))
            .await
            .map_err(|_| ObservationError::BackendFailure)?
    } else {
        Snapshot::new(document)
    };
    let value = Arc::new(snapshot);
    let root = &value["root"];
    // getDocument itself advances the epoch exactly once. A concurrent
    // reset or renderer event makes this a one-use full read.
    if let (Some(stamp), Some(root_id), Some(backend)) = (
        before.and_then(|n| n.checked_add(1)),
        root["nodeId"].as_i64().filter(|id| *id > 0),
        root["backendNodeId"].as_i64().filter(|id| *id > 0),
    ) {
        if root["nodeType"] == 9 && root["children"].is_array() && monitor.stamp() == Some(stamp) {
            *prior = Some(DocumentInventory {
                monitor,
                stamp,
                scope: scope.to_owned(),
                generation: lease.generation,
                binding: frame.binding.clone(),
                root: root_id,
                backend,
                value: Arc::clone(&value),
                order: Default::default(),
            });
        }
    }
    Ok(value)
}

/// Resolve the active isolated realm on a dense top document and flush its
/// layout. A sparse, ineligible or unproven document keeps the ordered AX
/// barrier. The live probe reads only a size threshold and the root box.
pub(super) async fn prepare_layout(
    client: &CdpClient,
    frame: &ObservationFrame,
    scope: &str,
    lease: &OperationLease,
    prior: Option<&DocumentInventory>,
) -> Result<(Option<i64>, bool), ObservationError> {
    if frame.parent_frame_id.is_some() || client.debt_ledger().is_none() {
        return Ok((None, false));
    }
    if let Some(saved) = prior.filter(|i| i.matches(client, frame, scope, lease)) {
        if saved.value.structure()?.candidates.len() < 512 {
            return Ok((None, false));
        }
    }
    let realm = observation_realm(client, frame, lease).await?;
    let reply = command(client, &frame.binding.session, "Runtime.evaluate", json!({
        "contextId":realm,"returnByValue":true,"awaitPromise":false,
        "expression":"!!document.documentElement && Document.prototype.getElementsByTagName.call(document,'*').item(511)!==null && Number.isFinite(Element.prototype.getBoundingClientRect.call(document.documentElement).width)"
    }),lease).await?;
    Ok((
        Some(realm),
        reply.get("exceptionDetails").is_none() && reply["result"]["value"] == true,
    ))
}

impl DocumentInventory {
    pub(super) fn matches(
        &self,
        client: &CdpClient,
        frame: &ObservationFrame,
        scope: &str,
        lease: &OperationLease,
    ) -> bool {
        self.scope == scope
            && self.generation == lease.generation
            && self.binding == frame.binding
            && Arc::ptr_eq(&self.monitor, &client.frontend_dom_epoch())
            && self.monitor.stamp() == Some(self.stamp)
    }

    /// The deep frontend binding keeps Chromium's connected light-tree order
    /// current until a DOM mutation, a navigation or a frontend reset. Fence
    /// prior notifications with a fresh exact Document comparison on every use.
    pub(super) async fn current_order(
        &self,
        client: &CdpClient,
        frame: &ObservationFrame,
        root: i64,
        members: &[(i64, i64)],
        lease: &OperationLease,
    ) -> Result<Option<Arc<light_document::Order>>, ObservationError> {
        let Some(order) = self
            .order
            .get()
            .filter(|_| root == self.root && self.matches(client, frame, &self.scope, lease))
        else {
            return Ok(None);
        };
        let backends = std::iter::once(self.backend)
            .chain(members.iter().map(|(backend, _)| *backend))
            .collect::<Vec<_>>();
        let reply = command(
            client,
            &frame.binding.session,
            "DOM.pushNodesByBackendIdsToFrontend",
            json!({"backendNodeIds":backends}),
            lease,
        )
        .await?;
        let nodes = reply["nodeIds"]
            .as_array()
            .ok_or(ObservationError::BackendFailure)?;
        if nodes.len() != backends.len() || nodes.iter().any(|id| !id.is_i64()) {
            return Err(ObservationError::BackendFailure);
        }
        if nodes[0].as_i64() != Some(root) || !self.matches(client, frame, &self.scope, lease) {
            return Ok(None);
        }
        if !members
            .iter()
            .zip(&nodes[1..])
            .all(|((_, expected), id)| id.as_i64() == Some(*expected))
        {
            return Err(ObservationError::StaleReference);
        }
        Ok(Some(Arc::clone(order)))
    }

    pub(super) fn remember_order(
        &self,
        client: &CdpClient,
        frame: &ObservationFrame,
        root: i64,
        lease: &OperationLease,
        value: &Arc<light_document::Order>,
    ) {
        if root == self.root && self.matches(client, frame, &self.scope, lease) {
            self.order.get_or_init(|| Arc::clone(value));
        }
    }

    /// The read-fields transaction supplies a fresh active-frame realm. Compare
    /// the exact original Document in that realm and fence all DOM events on
    /// either side. A missing or changed proof takes the complete DOM path.
    pub(super) async fn field_roots(
        &self,
        client: &CdpClient,
        frame: &ObservationFrame,
        lease: &OperationLease,
    ) -> Result<Option<fresh_query::RootInventory>, ObservationError> {
        if self.generation != lease.generation
            || self.binding != frame.binding
            || !self.bound_root(
                client,
                &self.scope,
                lease.generation,
                &frame.binding,
                self.backend,
            )
        {
            return Ok(None);
        }
        let Some(roots) = self.value.structure()?.field_roots.as_ref() else {
            return Ok(None);
        };
        let reply = command(
            client,
            &frame.binding.session,
            "DOM.pushNodesByBackendIdsToFrontend",
            json!({"backendNodeIds":[self.backend]}),
            lease,
        )
        .await?;
        let [id] = reply["nodeIds"]
            .as_array()
            .map(Vec::as_slice)
            .ok_or(ObservationError::BackendFailure)?
        else {
            return Err(ObservationError::BackendFailure);
        };
        if id.as_i64() != Some(self.root) || self.monitor.stamp() != Some(self.stamp) {
            return Ok(None);
        }
        verify_active_root(client, &frame.binding, self.backend, lease).await?;
        Ok((self.monitor.stamp() == Some(self.stamp)).then(|| roots.clone()))
    }

    pub(crate) fn bound_root(
        &self,
        client: &CdpClient,
        scope: &str,
        generation: u64,
        binding: &ExactBinding,
        backend: i64,
    ) -> bool {
        Arc::ptr_eq(&self.monitor, &client.frontend_dom_epoch())
            && self.scope == scope
            && self.generation == generation
            && self.binding.session == binding.session
            && self.binding.frame == binding.frame
            && self.binding.loader == binding.loader
            && self.binding.page_session == binding.page_session
            && self.backend == backend
            && self.monitor.stamp() == Some(self.stamp)
    }
}

/// A fresh isolated realm of the active frame supplies the Document being
/// compared. Describing the previously observed backend alone cannot prove it
/// is still the active document after navigation.
pub(crate) async fn verify_active_root(
    client: &CdpClient,
    binding: &ExactBinding,
    backend: i64,
    lease: &OperationLease,
) -> Result<(), ObservationError> {
    let world = command(
        client,
        &binding.session,
        "Page.createIsolatedWorld",
        json!({"frameId":binding.frame,"worldName":"agent-browser-native-observation"}),
        lease,
    )
    .await?;
    let context = world["executionContextId"]
        .as_i64()
        .filter(|id| *id > 0)
        .ok_or(ObservationError::BackendFailure)?;
    let group = client
        .readonly_group_instance(&format!("native-frame-owner-{}-root", lease.sequence))
        .map_err(|_| ObservationError::ResourceLimit)?;
    let capture = client_debt::ReadonlyGroupCapture::new(&group);
    let result = capture.scope(async {
        let node = resolve_page_object(client, &binding.session, backend, Some(context), &group, lease).await?;
        let id = node["object"]["objectId"].as_str().ok_or(ObservationError::StaleReference)?;
        let reply = command(client, &binding.session, "Runtime.callFunctionOn", json!({
            "objectId":id,"objectGroup":group,"functionDeclaration":"function(){return this === document && this.nodeType === 9}",
            "returnByValue":true
        }), lease).await?;
        if reply.get("exceptionDetails").is_some() { return Err(ObservationError::BackendFailure); }
        match reply["result"]["value"].as_bool() {
            Some(true) => Ok(()),
            Some(false) => Err(ObservationError::StaleReference),
            None => Err(ObservationError::BackendFailure),
        }
    }).await;
    settle_captured_object_group(client, &binding.session, &group, result, lease, &capture).await
}
