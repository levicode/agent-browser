//! Browser-owned identities for connected light-DOM elements of a session root.
//! Frontend IDs are compared only within one Document binding, never published.

use super::*;
use document_inventory::DocumentInventory;
use std::sync::Arc;

#[derive(Debug)]
pub(super) struct Order {
    ids: Vec<i64>,
    positions: HashMap<i64, usize>,
}

pub(super) struct LightDocument {
    root: i64,
    ordered: Arc<Order>,
    inventory: Option<DocumentInventory>,
}

impl LightDocument {
    /// Resolve the previously acquired, typed Document through CDP. A fresh
    /// getDocument would reset all frontend IDs and force Chromium to push
    /// the complete author tree a second time before it could answer this query.
    pub(super) async fn for_backend(
        client: &CdpClient,
        frame: &ObservationFrame,
        backend: i64,
        inventory: Option<&DocumentInventory>,
        lease: &OperationLease,
    ) -> Result<Self, ObservationError> {
        let map = command(
            client,
            &frame.binding.session,
            "DOM.pushNodesByBackendIdsToFrontend",
            json!({"backendNodeIds":[backend]}),
            lease,
        )
        .await?;
        let ids = ids(&map)?;
        let [root] = ids.as_slice() else {
            return Err(ObservationError::BackendFailure);
        };
        if *root <= 0 {
            return Err(ObservationError::StaleReference);
        }
        let reply = command(
            client,
            &frame.binding.session,
            "DOM.describeNode",
            json!({"nodeId":root,"depth":0}),
            lease,
        )
        .await?;
        if document_backend(&reply["node"])? != backend {
            return Err(ObservationError::StaleReference);
        }
        Self::from_root(client, frame, *root, inventory, lease).await
    }

    pub(super) async fn from_root(
        client: &CdpClient,
        frame: &ObservationFrame,
        root: i64,
        inventory: Option<&DocumentInventory>,
        lease: &OperationLease,
    ) -> Result<Self, ObservationError> {
        validate_semantic_frame(client, frame, lease).await?;
        let ordered = Self::query(client, frame, root, inventory, lease).await?;
        Ok(Self {
            root,
            ordered,
            inventory: inventory.cloned(),
        })
    }

    async fn query(
        client: &CdpClient,
        frame: &ObservationFrame,
        root: i64,
        inventory: Option<&DocumentInventory>,
        lease: &OperationLease,
    ) -> Result<Arc<Order>, ObservationError> {
        if let Some(saved) = inventory {
            if let Some(order) = saved.current_order(client, frame, root, &[], lease).await? {
                return Ok(order);
            }
        }
        let reply = command(
            client,
            &frame.binding.session,
            "DOM.querySelectorAll",
            json!({"nodeId":root,"selector":"*"}),
            lease,
        )
        .await?;
        let ids = ids(&reply)?;
        let positions = ids
            .iter()
            .copied()
            .enumerate()
            .map(|(i, id)| (id, i))
            .collect::<HashMap<_, _>>();
        if positions.len() != ids.len() || ids.iter().any(|id| *id <= 0) {
            return Err(ObservationError::BackendFailure);
        }
        let order = Arc::new(Order { ids, positions });
        if let Some(saved) = inventory {
            saved.remember_order(client, frame, root, lease, &order);
        }
        Ok(order)
    }

    pub(super) async fn connected_elements(
        &self,
        client: &CdpClient,
        frame: &ObservationFrame,
        backends: &[i64],
        lease: &OperationLease,
    ) -> Result<Vec<Option<i64>>, ObservationError> {
        let reply = command(
            client,
            &frame.binding.session,
            "DOM.pushNodesByBackendIdsToFrontend",
            json!({"backendNodeIds":backends}),
            lease,
        )
        .await?;
        let frontend = ids(&reply)?;
        if frontend.len() != backends.len() {
            return Err(ObservationError::BackendFailure);
        }
        let members = &self.ordered.positions;
        Ok(frontend
            .into_iter()
            .map(|id| (id > 0 && members.contains_key(&id)).then_some(id))
            .collect())
    }

    /// A depth-zero native description includes an element's generated
    /// pseudoElements. One reply proves the exact origin, type and native
    /// identity together. Nested/unsupported pseudo shapes use the full walk.
    pub(super) async fn confirms_pseudos(
        &self,
        client: &CdpClient,
        frame: &ObservationFrame,
        deferred: &[(i64, i64)],
        initial: Option<&HashMap<i64, PseudoOrigin>>,
        lease: &OperationLease,
    ) -> Result<bool, ObservationError> {
        use futures_util::{stream, StreamExt};
        let mut by_origin = HashMap::<i64, HashSet<i64>>::new();
        for &(backend, owner) in deferred {
            by_origin.entry(owner).or_default().insert(backend);
        }
        let backends = by_origin.keys().copied().collect::<Vec<_>>();
        let members = self
            .connected_elements(client, frame, &backends, lease)
            .await?;
        let Some(members) = members.into_iter().collect::<Option<Vec<_>>>() else {
            return Ok(false);
        };
        let replies = stream::iter(by_origin.into_iter().map(|(owner, expected)| async move {
            let reply = command(
                client,
                &frame.binding.session,
                "DOM.describeNode",
                json!({"backendNodeId":owner,"depth":0,"pierce":true}),
                lease,
            )
            .await?;
            let node = &reply["node"];
            if node["backendNodeId"].as_i64() != Some(owner) || node["nodeType"] != 1 {
                return Err(ObservationError::StaleReference);
            }
            let Some(pseudos) = node["pseudoElements"].as_array() else {
                return Ok(false);
            };
            Ok(expected.iter().all(|id| {
                pseudos.iter().any(|pseudo| {
                    pseudo["backendNodeId"].as_i64() == Some(*id)
                        && pseudo["nodeType"] == 1
                        && pseudo["pseudoType"].as_str().is_some_and(|kind| {
                            initial
                                .and_then(|origins| origins.get(id))
                                .is_none_or(|origin| {
                                    origin.backend == owner && origin.pseudo_type == kind
                                })
                        })
                })
            }))
        }))
        .buffered(16)
        .collect::<Vec<_>>()
        .await;
        if !collect_hint_results(replies)?
            .into_iter()
            .all(|matched| matched)
        {
            return Ok(false);
        }
        let pairs = backends.into_iter().zip(members).collect::<Vec<_>>();
        self.confirm(client, frame, &pairs, lease).await?;
        Ok(true)
    }

    pub(super) async fn confirm(
        &self,
        client: &CdpClient,
        frame: &ObservationFrame,
        members: &[(i64, i64)],
        lease: &OperationLease,
    ) -> Result<(), ObservationError> {
        if let Some(saved) = &self.inventory {
            if let Some(current) = saved
                .current_order(client, frame, self.root, members, lease)
                .await?
            {
                if members
                    .iter()
                    .any(|(_, original)| !current.positions.contains_key(original))
                {
                    return Err(ObservationError::StaleReference);
                }
                return validate_semantic_frame(client, frame, lease).await;
            }
        }
        let current = Self::query(client, frame, self.root, None, lease).await?;
        let backends = members
            .iter()
            .map(|(backend, _)| *backend)
            .collect::<Vec<_>>();
        let reply = command(
            client,
            &frame.binding.session,
            "DOM.pushNodesByBackendIdsToFrontend",
            json!({"backendNodeIds":backends}),
            lease,
        )
        .await?;
        let restored = ids(&reply)?;
        if restored.len() != members.len() {
            return Err(ObservationError::BackendFailure);
        }
        if !members.iter().zip(restored).all(|((_, original), now)| {
            *original == now && current.positions.contains_key(original)
        }) {
            return Err(ObservationError::StaleReference);
        }
        validate_semantic_frame(client, frame, lease).await
    }

    /// Chromium signs the backend identity of every member of a private main
    /// world array. Document order is only a lookup hint. A replaced getter,
    /// reordered list or unsupported serialization uses the exact per-node path.
    pub(super) async fn main_click_hints(
        &self,
        client: &CdpClient,
        frame: &ObservationFrame,
        members: &[(i64, i64)],
        group: &str,
        lease: &OperationLease,
    ) -> Result<Option<Vec<bool>>, ObservationError> {
        if !(64..=1024).contains(&members.len()) {
            return Ok(None);
        }
        let session = &frame.binding.session;
        let positions = &self.ordered.positions;
        let slots = members
            .iter()
            .map(|(_, id)| positions.get(id).copied())
            .collect::<Option<Vec<_>>>();
        let Some(slots) = slots else {
            return Ok(None);
        };
        let root = command(
            client,
            session,
            "DOM.resolveNode",
            json!({"nodeId":self.root,"objectGroup":group}),
            lease,
        )
        .await?;
        let Some(doc) = root["object"]["objectId"]
            .as_str()
            .filter(|_| root["object"]["subtype"] == "node")
        else {
            return Ok(None);
        };
        let verified = command(
            client,
            session,
            "DOM.requestNode",
            json!({"objectId":doc}),
            lease,
        )
        .await?;
        if verified["nodeId"].as_i64() != Some(self.root) {
            return Err(ObservationError::StaleReference);
        }
        let slots = slots
            .iter()
            .map(|i| format!("list[{i}]"))
            .collect::<Vec<_>>()
            .join(",");
        let array = command(client, session, "Runtime.callFunctionOn", json!({"objectId":doc,"objectGroup":group,
            "throwOnSideEffect":true,"functionDeclaration":format!("function(){{'use strict';const list=this.querySelectorAll('*');return [{slots}]}}")}), lease).await?;
        let Some(array) = array["result"]["objectId"].as_str().filter(|_| {
            array.get("exceptionDetails").is_none() && array["result"]["subtype"] == "array"
        }) else {
            return Ok(None);
        };
        // This identity function has no property access or author code. Only
        // Blink's typed nodeType/backendNodeId are consumed. The array literal
        // owns each indexed data property and was never handed to the page.
        let proof = command(client, session, "Runtime.callFunctionOn", json!({"objectId":array,"objectGroup":group,
            "functionDeclaration":"function(){'use strict';return this}",
            "serializationOptions":{"serialization":"deep","maxDepth":2,"additionalParameters":{"maxNodeDepth":0,"includeShadowTree":"none"}}}), lease).await?;
        let deep = &proof["result"]["deepSerializedValue"];
        if proof.get("exceptionDetails").is_some()
            || deep["type"] != "array"
            || !deep["value"].as_array().is_some_and(|rows| {
                rows.len() == members.len()
                    && rows.iter().zip(members).all(|(row, (backend, _))| {
                        row["type"] == "node"
                            && row["value"]["nodeType"] == 1
                            && row["value"]["backendNodeId"].as_i64() == Some(*backend)
                    })
            })
        {
            return Ok(None);
        }
        let tests = (0..members.len())
            .map(|i| format!("typeof this[{i}].onclick==='function'"))
            .collect::<Vec<_>>()
            .join(",");
        let result = command(client, session, "Runtime.callFunctionOn", json!({"objectId":array,"objectGroup":group,
            "functionDeclaration":format!("function(){{'use strict';return [{tests}]}}"),"throwOnSideEffect":true,"returnByValue":true}),lease).await?;
        if result.get("exceptionDetails").is_some() {
            return Ok(None);
        }
        let values = result["result"]["value"]
            .as_array()
            .filter(|rows| rows.len() == members.len())
            .ok_or(ObservationError::BackendFailure)?;
        Ok(Some(
            values
                .iter()
                .map(|v| v.as_bool().ok_or(ObservationError::BackendFailure))
                .collect::<Result<_, _>>()?,
        ))
    }
}

fn ids(reply: &Value) -> Result<Vec<i64>, ObservationError> {
    let list = reply["nodeIds"]
        .as_array()
        .ok_or(ObservationError::BackendFailure)?;
    if list.len() > 100_000 {
        return Err(ObservationError::ResourceLimit);
    }
    list.iter()
        .map(|id| id.as_i64().ok_or(ObservationError::BackendFailure))
        .collect()
}

// Both querySelectorAll calls have the same native Document root and return
// light-tree elements in document order. A short-lived observer fences the JS
// snapshot and the CDP query, including an A → B → A replacement. The retained
// static NodeList subsequently identifies the original objects even after a
// reorder. Every metadata read still proves its own receiver's document.
const COLLECT: &str = r#"function(remaining) {
    if (this !== document) throw new Error('unexpected document');
    let changed = false;
    const guard = new MutationObserver(() => { changed = true; guard.disconnect(); });
    guard.observe(document, {childList:true, subtree:true});
    const timer = setTimeout(() => { changed = true; guard.disconnect(); }, remaining);
    const elements = Document.prototype.querySelectorAll.call(document, '*');
    return {elements, finish() {
        const stable = !changed && guard.takeRecords().length === 0;
        guard.disconnect();
        clearTimeout(timer);
        return {stable, count:elements.length};
    }};
}"#;

pub(super) struct LightReceivers {
    pub document: LightDocument,
    pub handle: String,
    pub slots: Vec<Option<usize>>,
}

#[derive(Default)]
pub(super) struct LightIndex(std::sync::OnceLock<Result<HashMap<i64, i64>, ObservationError>>);
impl LightIndex {
    /// Structural IDs only. The synchronous renderer snapshot and the live
    /// backend-to-frontend comparison below still bind every requested node.
    fn original(&self, source: &Value) -> Result<&HashMap<i64, i64>, ObservationError> {
        self.0
            .get_or_init(|| {
                let mut original = HashMap::new();
                let mut visit = vec![source];
                while let Some(node) = visit.pop() {
                    if node["nodeType"] == 1 {
                        if let (Some(id), Some(frontend)) = (
                            node["backendNodeId"].as_i64(),
                            node["nodeId"].as_i64().filter(|n| *n > 0),
                        ) {
                            if original.insert(id, frontend).is_some() {
                                return Err(ObservationError::BackendFailure);
                            }
                        }
                    }
                    if let Some(children) = node["children"].as_array() {
                        visit.extend(children);
                    }
                }
                Ok(original)
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}

impl LightReceivers {
    pub(super) async fn collect(
        client: &CdpClient,
        frame: &ObservationFrame,
        context: i64,
        source: &Value,
        index: &LightIndex,
        inventory: Option<&DocumentInventory>,
        root: i64,
        backend: i64,
        backends: &[i64],
        group: &str,
        lease: &OperationLease,
    ) -> Result<Option<Self>, ObservationError> {
        // The deep native Document already bound each author-light element to a
        // frontend ID. Compare *all* those IDs with the current native list
        // before asking Blink to push any detached subtrees to this frontend.
        let index = index.original(source)?;
        let original = backends
            .iter()
            .filter_map(|id| Some((*id, *index.get(id)?)))
            .collect::<HashMap<_, _>>();
        if original.is_empty() {
            return Ok(None);
        }
        let resolved = resolve_page_object(
            client,
            &frame.binding.session,
            backend,
            Some(context),
            group,
            lease,
        )
        .await?;
        let object = resolved["object"]["objectId"]
            .as_str()
            .ok_or(ObservationError::StaleReference)?;
        let remaining = lease
            .deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis()
            .clamp(1, i32::MAX as u128) as u64;
        for _ in 0..2 {
            let held = command(client, &frame.binding.session, "Runtime.callFunctionOn",
                json!({"objectId":object,"functionDeclaration":COLLECT,"arguments":[{"value":remaining}],"objectGroup":group}), lease).await?;
            if held.get("exceptionDetails").is_some() {
                return Err(ObservationError::BackendFailure);
            }
            let handle = held["result"]["objectId"]
                .as_str()
                .ok_or(ObservationError::BackendFailure)?
                .to_owned();
            let ordered = LightDocument::query(client, frame, root, inventory, lease).await;
            // Close even on a rejected native query. The lease-bounded timer is
            // a backup if the operation retires before explicit cleanup.
            let finished = command(client, &frame.binding.session, "Runtime.callFunctionOn",
                json!({"objectId":handle,"functionDeclaration":"function(){return this.finish()}","returnByValue":true,"objectGroup":group}), lease).await;
            let ordered = ordered?;
            let proof = finished?;
            let value = &proof["result"]["value"];
            if proof.get("exceptionDetails").is_some() || !value["stable"].is_boolean() {
                return Err(ObservationError::BackendFailure);
            }
            let positions = &ordered.positions;
            if original.values().any(|id| !positions.contains_key(id)) {
                return Err(ObservationError::StaleReference);
            }
            if value["stable"] != true || value["count"].as_u64() != Some(ordered.ids.len() as u64)
            {
                continue;
            }
            let known: Vec<_> = original.keys().copied().collect();
            let reply = command(
                client,
                &frame.binding.session,
                "DOM.pushNodesByBackendIdsToFrontend",
                json!({"backendNodeIds":known}),
                lease,
            )
            .await?;
            let current = ids(&reply)?;
            if current.len() != known.len() {
                return Err(ObservationError::BackendFailure);
            }
            if known
                .iter()
                .zip(current)
                .any(|(id, now)| original[id] != now)
            {
                return Err(ObservationError::StaleReference);
            }
            let slots = backends
                .iter()
                .map(|id| original.get(id).and_then(|id| positions.get(id)).copied())
                .collect();
            return Ok(Some(Self {
                document: LightDocument {
                    root,
                    ordered,
                    inventory: inventory.cloned(),
                },
                handle,
                slots,
            }));
        }
        Ok(None)
    }

    pub(super) fn member(&self, index: usize) -> Option<i64> {
        self.slots
            .get(index)
            .copied()
            .flatten()
            .and_then(|i| self.document.ordered.ids.get(i).copied())
    }
}
