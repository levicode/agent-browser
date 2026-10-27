use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::hash::{Hash, Hasher};

use super::cdp::client::CdpClient;
use super::cdp::types::*;

/// Native-only identity. Never export renderer/backend IDs as client handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactBinding {
    pub page_session: String,
    pub session: String,
    pub frame: String,
    pub loader: String,
    pub actionable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeReferenceKind {
    Dom,
    ReadOnlyCssPseudo,
}

/// Immutable full live-query source, distinct from its acquisition backend.
/// Keys hash a fixed fingerprint; equality still checks the complete source so
/// even a hash collision cannot merge different query authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveQueryOrigin {
    fingerprint: [u8; 32],
    pub source: Arc<str>,
}
impl LiveQueryOrigin {
    pub fn new(source: String) -> Self {
        Self {
            fingerprint: Sha256::digest(source.as_bytes()).into(),
            source: source.into(),
        }
    }
}
impl Hash for LiveQueryOrigin {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.fingerprint.hash(state);
    }
}
type DurableRefKey = (i64, Option<LiveQueryOrigin>);

/// Native issuance proof shared by located, observed, and viewport authorities.
/// Its revision is immutable, independent of later snapshot publication revisions.
/// Located references survive ordinary observations; observed membership does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedIssuance {
    pub identity_scope: String,
    pub generation: u64,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefLifetime {
    Observed,
    Located(LocatedIssuance),
}

#[derive(Debug, Clone)]
pub struct RefEntry {
    pub lifetime: RefLifetime,
    pub kind: NativeReferenceKind,
    pub backend_node_id: Option<i64>,
    pub role: String,
    pub name: String,
    pub nth: Option<usize>,
    pub selector: Option<String>,
    pub frame_id: Option<String>,
    allow_role_fallback: bool,
    pub exact_binding: Option<ExactBinding>,
    pub live_query: Option<LiveQueryOrigin>,
    observed_issuance: Option<LocatedIssuance>,
    observed_membership: Option<u64>,
}

impl RefEntry {
    fn issuance(&self) -> Option<&LocatedIssuance> {
        match &self.lifetime {
            RefLifetime::Observed => self.observed_issuance.as_ref(),
            RefLifetime::Located(issuance) => Some(issuance),
        }
    }

    pub fn issued_revision(&self) -> Option<u64> {
        self.issuance().map(|issuance| issuance.revision)
    }

    pub fn is_current_observed(&self, snapshot_revision: u64) -> bool {
        matches!(self.lifetime, RefLifetime::Observed)
            && snapshot_revision != 0
            && self.observed_membership == Some(snapshot_revision)
    }

    /// Legacy unissued refs are never client-protocol authority. The caller
    /// supplies its leased owner, not fields reported by the renderer.
    pub fn matches_scope(&self, identity_scope: &str, generation: u64, page_session: &str) -> bool {
        self.exact_binding
            .as_ref()
            .is_some_and(|binding| binding.page_session == page_session)
            && self.issuance().is_some_and(|issuance| {
                issuance.identity_scope == identity_scope
                    && issuance.generation == generation
                    && issuance.revision != 0
            })
    }

    pub fn matches_reference(
        &self,
        identity_scope: &str,
        generation: u64,
        page_session: &str,
        supplied_revision: &str,
    ) -> bool {
        self.matches_scope(identity_scope, generation, page_session)
            && self
                .issued_revision()
                .is_some_and(|revision| supplied_revision == revision.to_string())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct DurableRef {
    id: String,
    issuance: Option<LocatedIssuance>,
    kind: NativeReferenceKind,
}
impl DurableRef {
    fn compatible(&self, kind: NativeReferenceKind, publication: Option<&LocatedIssuance>) -> bool {
        self.kind == kind
            && match (publication, self.issuance.as_ref()) {
                (Some(current), Some(issued)) => {
                    current.identity_scope == issued.identity_scope
                        && current.generation == issued.generation
                }
                (None, None) => true,
                _ => false,
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewportReference {
    pub id: String,
    pub issuance: LocatedIssuance,
    pub page_session: String,
}

#[derive(Clone)]
struct DocumentRefs {
    session: String,
    loader: String,
    refs: HashMap<DurableRefKey, DurableRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefAllocationError {
    Exhausted,
    Capacity,
}

/// Exact metadata admission is bounded; exhaustion never evicts published authority.
pub(crate) const MAX_EXACT_REFERENCES: usize = 100_000;
/// Conservatively charge each retained source in both map and durable bucket,
/// even when they share an Arc. Entry quota separately bounds key/Arc overhead.
/// This retained-origin admission bound is not a performance guarantee.
pub(crate) const MAX_RETAINED_QUERY_ORIGIN_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct RefMap {
    map: HashMap<String, RefEntry>,
    exact_ref_limit: usize,
    query_origin_byte_limit: usize,
    documents: HashMap<(String, Option<String>), DocumentRefs>,
    next_ref: Arc<AtomicUsize>,
    viewport_ref: Option<ViewportReference>,
    observed_publication: Option<LocatedIssuance>,
}

/// Exclusive admission token for one staged locate publication. The complete
/// batch is checked once; each insertion consumes only its reserved allowance.
pub(crate) struct LocatedBatch<'a> {
    refs: &'a mut RefMap,
    remaining_entries: usize,
    remaining_source_bytes: usize,
}
impl LocatedBatch<'_> {
    pub(crate) fn try_bind(
        &mut self,
        backend_node_id: i64,
        role: &str,
        binding: ExactBinding,
        issuance: LocatedIssuance,
        live_query: Option<LiveQueryOrigin>,
    ) -> Result<String, RefAllocationError> {
        let bytes = live_query.as_ref().map_or(0, |origin| origin.source.len());
        if self.remaining_entries == 0 || bytes > self.remaining_source_bytes {
            return Err(RefAllocationError::Capacity);
        }
        let id = self.refs.try_allocate_ref()?;
        self.remaining_entries -= 1;
        self.remaining_source_bytes -= bytes;
        self.refs.map.insert(
            id.clone(),
            RefEntry {
                lifetime: RefLifetime::Located(issuance),
                observed_issuance: None,
                observed_membership: None,
                kind: NativeReferenceKind::Dom,
                backend_node_id: Some(backend_node_id),
                role: role.into(),
                name: String::new(),
                nth: None,
                selector: None,
                frame_id: Some(binding.frame.clone()),
                allow_role_fallback: false,
                exact_binding: Some(binding),
                live_query,
            },
        );
        Ok(id)
    }
}

impl RefMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            exact_ref_limit: MAX_EXACT_REFERENCES,
            query_origin_byte_limit: MAX_RETAINED_QUERY_ORIGIN_BYTES,
            documents: HashMap::new(),
            next_ref: Arc::new(AtomicUsize::new(1)),
            viewport_ref: None,
            observed_publication: None,
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
                lifetime: RefLifetime::Observed,
                observed_issuance: None,
                observed_membership: None,
                kind: NativeReferenceKind::Dom,
                backend_node_id,
                role: role.to_string(),
                name: name.to_string(),
                nth,
                selector: None,
                frame_id: frame_id.map(|s| s.to_string()),
                allow_role_fallback: true,
                exact_binding: None,
                live_query: None,
            },
        );
    }

    /// Add a ref that must keep resolving to this exact backend node. This is
    /// used for actions that select a concrete DOM node before interacting;
    /// falling back by role/name could silently target a different element.
    pub fn add_exact_backend_node(&mut self, ref_id: String, backend_node_id: i64) {
        self.map.insert(
            ref_id,
            RefEntry {
                lifetime: RefLifetime::Observed,
                observed_issuance: None,
                observed_membership: None,
                kind: NativeReferenceKind::Dom,
                backend_node_id: Some(backend_node_id),
                role: String::new(),
                name: String::new(),
                nth: None,
                selector: None,
                frame_id: None,
                allow_role_fallback: false,
                exact_binding: None,
                live_query: None,
            },
        );
    }

    pub fn bind_exact(
        &mut self,
        backend_node_id: i64,
        role: &str,
        name: &str,
        binding: ExactBinding,
    ) -> String {
        self.try_bind_exact(backend_node_id, role, name, binding)
            .expect("native reference space exhausted")
    }

    pub fn try_bind_exact(
        &mut self,
        backend_node_id: i64,
        role: &str,
        name: &str,
        binding: ExactBinding,
    ) -> Result<String, RefAllocationError> {
        self.try_bind_exact_with_origin(backend_node_id, role, name, binding, None)
    }

    pub fn try_bind_exact_with_origin(
        &mut self,
        backend_node_id: i64,
        role: &str,
        name: &str,
        binding: ExactBinding,
        live_query: Option<LiveQueryOrigin>,
    ) -> Result<String, RefAllocationError> {
        self.try_bind_exact_kind(
            backend_node_id,
            role,
            name,
            binding,
            live_query,
            NativeReferenceKind::Dom,
        )
    }

    fn try_bind_exact_kind(
        &mut self,
        backend_node_id: i64,
        role: &str,
        name: &str,
        binding: ExactBinding,
        live_query: Option<LiveQueryOrigin>,
        kind: NativeReferenceKind,
    ) -> Result<String, RefAllocationError> {
        self.check_exact_admission_with_origin(
            &binding,
            &[backend_node_id],
            live_query.as_ref(),
            kind,
        )?;
        self.observe_document(
            &binding.page_session,
            Some(&binding.frame),
            &binding.session,
            Some(&binding.loader),
        );
        let key = (backend_node_id, live_query.clone());
        let document_key = (binding.page_session.clone(), Some(binding.frame.clone()));
        let existing = self
            .documents
            .get(&document_key)
            .and_then(|document| document.refs.get_key_value(&key));
        let publication = self.observed_publication.as_ref();
        let compatible = existing.filter(|(_, prior)| prior.compatible(kind, publication));
        let (identity, live_query) = match compatible {
            Some(((_, origin), identity)) => (identity.clone(), origin.clone()),
            None => (
                DurableRef {
                    id: self.try_allocate_ref()?,
                    issuance: publication.cloned(),
                    kind,
                },
                live_query,
            ),
        };
        let id = identity.id.clone();
        let observed_issuance = identity.issuance.clone();
        let observed_membership = publication.map(|publication| publication.revision);
        let key = (backend_node_id, live_query.clone());
        self.documents
            .get_mut(&document_key)
            .expect("observed document")
            .refs
            .insert(key, identity);
        self.map.insert(
            id.clone(),
            RefEntry {
                lifetime: RefLifetime::Observed,
                observed_issuance,
                observed_membership,
                kind,
                backend_node_id: Some(backend_node_id),
                role: role.into(),
                name: name.into(),
                nth: None,
                selector: None,
                frame_id: Some(binding.frame.clone()),
                allow_role_fallback: false,
                exact_binding: Some(binding),
                live_query,
            },
        );
        Ok(id)
    }

    /// Admit the entire locate acquisition before reserving any public IDs.
    /// Located identities are fresh per acquisition, not durable backend aliases.
    pub(crate) fn located_origin_budget(&self, count: usize) -> Result<usize, RefAllocationError> {
        let (entries, durable) = self.retained_identity_counts();
        if entries
            .checked_add(count)
            .is_none_or(|total| total > self.exact_ref_limit)
            || durable > self.exact_ref_limit
        {
            return Err(RefAllocationError::Capacity);
        }
        self.query_origin_byte_limit
            .checked_sub(self.retained_query_origin_bytes())
            .ok_or(RefAllocationError::Capacity)
    }

    pub(crate) fn check_located_admission(
        &self,
        origins: &[Option<LiveQueryOrigin>],
    ) -> Result<(), RefAllocationError> {
        let remaining = self.located_origin_budget(origins.len())?;
        let added_bytes = origins.iter().flatten().try_fold(0usize, |total, origin| {
            total
                .checked_add(origin.source.len())
                .ok_or(RefAllocationError::Capacity)
        })?;
        if added_bytes > remaining {
            return Err(RefAllocationError::Capacity);
        }
        Ok(())
    }

    pub(crate) fn admit_located_batch(
        &mut self,
        origins: &[Option<LiveQueryOrigin>],
    ) -> Result<LocatedBatch<'_>, RefAllocationError> {
        self.check_located_admission(origins)?;
        let remaining_source_bytes = origins
            .iter()
            .flatten()
            .map(|origin| origin.source.len())
            .sum();
        Ok(LocatedBatch {
            refs: self,
            remaining_entries: origins.len(),
            remaining_source_bytes,
        })
    }

    pub(crate) fn try_bind_located(
        &mut self,
        backend_node_id: i64,
        role: &str,
        binding: ExactBinding,
        issuance: LocatedIssuance,
        live_query: Option<LiveQueryOrigin>,
    ) -> Result<String, RefAllocationError> {
        self.admit_located_batch(std::slice::from_ref(&live_query))?
            .try_bind(backend_node_id, role, binding, issuance, live_query)
    }

    pub fn try_bind_readonly_pseudo(
        &mut self,
        backend: i64,
        role: &str,
        binding: ExactBinding,
    ) -> Result<String, RefAllocationError> {
        let mut binding = binding;
        binding.actionable = false;
        self.try_bind_exact_kind(
            backend,
            role,
            "",
            binding,
            None,
            NativeReferenceKind::ReadOnlyCssPseudo,
        )
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
                lifetime: RefLifetime::Observed,
                observed_issuance: None,
                observed_membership: None,
                kind: NativeReferenceKind::Dom,
                backend_node_id: None,
                role: role.to_string(),
                name: name.to_string(),
                nth,
                selector: Some(selector),
                frame_id: None,
                allow_role_fallback: true,
                exact_binding: None,
                live_query: None,
            },
        );
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
        self.map.remove(ref_id);
    }

    pub(crate) fn retained_identity_counts(&self) -> (usize, usize) {
        (
            self.map.len(),
            self.documents.values().map(|d| d.refs.len()).sum(),
        )
    }

    pub(crate) fn retained_query_origin_bytes(&self) -> usize {
        let entries = self
            .map
            .values()
            .filter_map(|entry| entry.live_query.as_ref())
            .map(|origin| origin.source.len())
            .sum::<usize>();
        let durable = self
            .documents
            .values()
            .flat_map(|document| document.refs.keys())
            .filter_map(|(_, origin)| origin.as_ref())
            .map(|origin| origin.source.len())
            .sum::<usize>();
        entries.saturating_add(durable)
    }

    pub(crate) fn check_exact_admission(
        &self,
        binding: &ExactBinding,
        backends: &[i64],
    ) -> Result<(), RefAllocationError> {
        self.check_exact_admission_with_origin(binding, backends, None, NativeReferenceKind::Dom)
    }

    fn check_exact_admission_with_origin(
        &self,
        binding: &ExactBinding,
        backends: &[i64],
        origin: Option<&LiveQueryOrigin>,
        kind: NativeReferenceKind,
    ) -> Result<(), RefAllocationError> {
        let previous = self
            .documents
            .get(&(binding.page_session.clone(), Some(binding.frame.clone())));
        let document =
            previous.filter(|d| d.session == binding.session && d.loader == binding.loader);
        let mut new_durable = 0usize;
        let mut new_map = 0usize;
        let mut seen = std::collections::HashSet::new();
        for backend in backends {
            if !seen.insert(*backend) {
                continue;
            }
            match document.and_then(|d| d.refs.get(&(*backend, origin.cloned()))) {
                Some(id) => {
                    if !id.compatible(kind, self.observed_publication.as_ref())
                        || !self.map.contains_key(&id.id)
                    {
                        new_map += 1;
                    }
                }
                None => {
                    new_durable += 1;
                    new_map += 1;
                }
            }
        }
        let (entries, durable) = self.retained_identity_counts();
        let replaced =
            previous.filter(|d| d.session != binding.session || d.loader != binding.loader);
        let durable = durable.saturating_sub(replaced.map_or(0, |d| d.refs.len()));
        // Default exact publication cannot add origin bytes. Avoid walking all
        // sources for every ordinary observation candidate.
        let origin_bytes = origin.map_or(0, |origin| {
            let replaced_bytes = replaced.map_or(0, |d| {
                d.refs
                    .keys()
                    .filter_map(|(_, origin)| origin.as_ref())
                    .map(|origin| origin.source.len())
                    .sum::<usize>()
            });
            self.retained_query_origin_bytes()
                .saturating_sub(replaced_bytes)
                .saturating_add(
                    origin
                        .source
                        .len()
                        .saturating_mul(new_map.saturating_add(new_durable)),
                )
        });
        if entries.saturating_add(new_map) > self.exact_ref_limit
            || durable.saturating_add(new_durable) > self.exact_ref_limit
            || origin_bytes > self.query_origin_byte_limit
        {
            return Err(RefAllocationError::Capacity);
        }
        Ok(())
    }

    /// Query matching may inspect many candidates. Only returned identities gain
    /// durable authority; previously published identities are never evicted.
    pub(crate) fn retain_query_additions(
        &mut self,
        baseline: &Self,
        matched: &std::collections::HashSet<String>,
    ) {
        self.map
            .retain(|id, _| baseline.map.contains_key(id) || matched.contains(id));
        for (key, document) in &mut self.documents {
            let previous = baseline.documents.get(key);
            document.refs.retain(|backend, id| {
                matched.contains(&id.id) || previous.and_then(|d| d.refs.get(backend)) == Some(id)
            });
        }
    }

    /// Snapshot membership is exact: rereading a previous durable observed ID
    /// does not publish it if final projection omitted it. Located lifetimes are
    /// independent; durable historical IDs retain their existing bounded policy.
    pub(crate) fn retain_snapshot_entries(
        &mut self,
        baseline: &Self,
        published: &std::collections::HashSet<String>,
    ) {
        self.retain_query_additions(baseline, published);
        self.map.retain(|id, entry| {
            matches!(&entry.lifetime, RefLifetime::Located(_)) || published.contains(id)
        });
    }

    #[cfg(test)]
    pub(crate) fn set_exact_limit_for_test(&mut self, limit: usize) {
        self.exact_ref_limit = limit;
    }

    #[cfg(test)]
    pub(crate) fn set_query_origin_byte_limit_for_test(&mut self, limit: usize) {
        self.query_origin_byte_limit = limit;
    }

    /// A new semantic observation replaces only observed authority. Located
    /// handles (including pinned exact ones) keep their original issuance.
    pub fn begin_snapshot(&mut self) {
        self.observed_publication = None;
        self.map
            .retain(|_, entry| matches!(&entry.lifetime, RefLifetime::Located(_)));
    }

    /// Set trusted issuance and membership for a cloned observation transaction.
    /// The caller publishes this clone atomically; failed captures discard it.
    pub fn begin_observation(&mut self, identity_scope: &str, generation: u64, revision: u64) {
        self.begin_snapshot();
        self.observed_publication = Some(LocatedIssuance {
            identity_scope: identity_scope.into(),
            generation,
            revision,
        });
    }

    pub fn retire_owner_references(&mut self) {
        self.retire_interaction_references();
    }

    /// Retire document and viewport authority without recycling any issued ID.
    /// The stable owner, its artifacts and the shared allocator are unchanged.
    pub fn retire_interaction_references(&mut self) {
        self.invalidate_all_documents();
        self.viewport_ref = None;
    }

    /// Semantic fallback removes all current element and located authority.
    /// Durable document identities stay inert and bounded by existing admission
    /// quotas; only fresh exact observation evidence can restore membership.
    /// Viewport capability lifetime is separate, as with retire_all_references.
    pub(crate) fn retire_semantic_authority(&mut self) {
        self.observed_publication = None;
        self.map.clear();
    }

    /// Retire both reference populations and their durable document identities.
    /// The shared allocator never rolls back. Viewport lifetime is separate.
    pub fn retire_all_references(&mut self) {
        self.invalidate_all_documents();
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
    ) -> Option<&str> {
        self.documents
            .get(&(page_session.to_string(), frame.map(str::to_string)))?
            .refs
            .get(&(backend_node_id, None))
            .map(|identity| identity.id.as_str())
    }

    pub fn remember_durable_ref(
        &mut self,
        page_session: &str,
        frame: Option<&str>,
        backend_node_id: i64,
        ref_id: &str,
    ) {
        if let Some(document) = self
            .documents
            .get_mut(&(page_session.to_string(), frame.map(str::to_string)))
        {
            document.refs.insert(
                (backend_node_id, None),
                DurableRef {
                    id: ref_id.to_string(),
                    issuance: None,
                    kind: NativeReferenceKind::Dom,
                },
            );
        }
    }

    pub fn invalidate_page(&mut self, page_session: &str) {
        self.documents
            .retain(|(entry_page, _), _| entry_page != page_session);
        self.map.clear();
    }

    /// Drop all document identities while preserving the monotonic ref counter.
    pub fn invalidate_all_documents(&mut self) {
        self.observed_publication = None;
        self.documents.clear();
        self.map.clear();
    }

    /// Reserve a globally unique ref in this client's lifetime. Cloned staging
    /// maps share the allocator: abandoning a snapshot never recycles IDs.
    pub fn allocate_ref(&self) -> String {
        self.try_allocate_ref()
            .expect("native reference space exhausted")
    }

    pub fn try_allocate_ref(&self) -> Result<String, RefAllocationError> {
        #[allow(deprecated)] // Keep compatibility with older stable toolchains.
        let n = self
            .next_ref
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| RefAllocationError::Exhausted)?;
        Ok(format!("e{n}"))
    }

    /// Clone-local Page capability. A failed staged first publication burns an
    /// allocator ID but cannot install authority in the committed RefMap.
    pub fn try_viewport_ref(
        &mut self,
        identity_scope: &str,
        generation: u64,
        page_session: &str,
        revision: u64,
    ) -> Result<&ViewportReference, RefAllocationError> {
        let same_owner = self.viewport_ref.as_ref().is_some_and(|viewport| {
            viewport.issuance.identity_scope == identity_scope
                && viewport.issuance.generation == generation
                && viewport.page_session == page_session
        });
        if !same_owner {
            self.viewport_ref = Some(ViewportReference {
                id: self.try_allocate_ref()?,
                page_session: page_session.into(),
                issuance: LocatedIssuance {
                    identity_scope: identity_scope.into(),
                    generation,
                    revision,
                },
            });
        }
        Ok(self.viewport_ref.as_ref().expect("staged viewport"))
    }

    /// Commit only the staged Page capability, never semantic/node membership.
    pub(crate) fn commit_viewport_from(&mut self, staged: &Self) {
        self.viewport_ref = staged.viewport_ref.clone();
    }

    pub fn is_viewport_ref(&self, reference: &str) -> bool {
        self.viewport_ref
            .as_ref()
            .is_some_and(|viewport| parse_ref(reference).as_deref() == Some(viewport.id.as_str()))
    }

    pub fn matches_viewport_reference(
        &self,
        identity_scope: &str,
        generation: u64,
        page_session: &str,
        reference: &str,
        revision: &str,
    ) -> bool {
        self.viewport_ref.as_ref().is_some_and(|viewport| {
            self.is_viewport_ref(reference)
                && viewport.issuance.identity_scope == identity_scope
                && viewport.issuance.generation == generation
                && viewport.page_session == page_session
                && viewport.issuance.revision != 0
                && revision == viewport.issuance.revision.to_string()
        })
    }

    pub fn next_ref_num(&self) -> usize {
        self.next_ref.load(Ordering::Relaxed)
    }

    pub fn set_next_ref_num(&mut self, n: usize) {
        self.next_ref.fetch_max(n, Ordering::Relaxed);
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
    require_actionable: bool,
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
            const notActionable = {ACTIONABILITY_JS};
            const topDoc = win ? win.document : doc;
            return {{ x: x, y: y, reason: notActionable(topDoc, el, x, y), blocker: blockerAt(topDoc, el, x, y) }};
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
    if require_actionable {
        if let Some(reason) = value.and_then(|v| v.get("reason")).and_then(|v| v.as_str()) {
            return Err(not_actionable_error(selector, reason));
        }
    }
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

pub async fn resolve_element_center(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
    require_actionable: bool,
) -> Result<(f64, f64, String), String> {
    if let Some(ref_id) = parse_ref(selector_or_ref) {
        let entry = ref_map
            .get(&ref_id)
            .ok_or_else(|| format!("Unknown ref: {}", ref_id))?;

        if entry.kind == NativeReferenceKind::ReadOnlyCssPseudo {
            return Err("Native reference is read-only and not actionable".into());
        }
        if let Some(binding) = &entry.exact_binding {
            validate_exact_binding(client, session_id, binding).await?;
        }
        let effective_session_id = entry
            .exact_binding
            .as_ref()
            .map(|b| b.session.as_str())
            .unwrap_or_else(|| {
                resolve_frame_session(entry.frame_id.as_deref(), session_id, iframe_sessions)
            });

        // Try cached backend_node_id first (fast path)
        if let Some(backend_node_id) = entry.backend_node_id {
            if let Some(binding) = &entry.exact_binding {
                if !binding.actionable {
                    return Err("Reference is observation-only".into());
                }
                let (object, _) = resolve_element_object_id(
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
                        Some(serde_json::json!({"objectId": object})),
                        Some(effective_session_id),
                    )
                    .await;
            }
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
                    require_actionable,
                )
                .await?;
                return Ok((x, y, effective_session_id.to_string()));
            }
            if !entry.allow_role_fallback {
                return Err(format!("Element ref {ref_id} is stale"));
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
            require_actionable,
        )
        .await?;
        return Ok((x, y, effective_session_id.to_string()));
    }

    // CSS selector: honor an active `frame <sel>` selection.
    if let Some(frame_id) = active_frame() {
        // Cross-process iframe: its dedicated session's main frame IS the
        // iframe, so plain document-rooted resolution works there.
        if let Some(frame_session) = iframe_sessions.get(&frame_id) {
            let (x, y) =
                resolve_by_selector(client, frame_session, selector_or_ref, require_actionable)
                    .await?;
            return Ok((x, y, frame_session.clone()));
        }
        let (x, y) = resolve_center_in_same_process_frame(
            client,
            session_id,
            &frame_id,
            selector_or_ref,
            require_actionable,
        )
        .await?;
        return Ok((x, y, session_id.to_string()));
    }
    let (x, y) =
        resolve_by_selector(client, session_id, selector_or_ref, require_actionable).await?;
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
    require_actionable: bool,
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
            const notActionable = {ACTIONABILITY_JS};
            return {{ blocker: blockerAt(topDoc, this, x, y), reason: notActionable(topDoc, this, x, y) }};
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
        let value = value.get("result").and_then(|r| r.get("value"));
        if require_actionable {
            if let Some(reason) = value.and_then(|v| v.get("reason")).and_then(|v| v.as_str()) {
                return Err(not_actionable_error(target, reason));
            }
        }
        if let Some(blocker) = value
            .and_then(|v| v.get("blocker"))
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
            .ok_or_else(|| format!("Unknown ref: {}", ref_id))?;

        if let Some(binding) = &entry.exact_binding {
            validate_exact_binding(client, session_id, binding).await?;
            let backend = entry
                .backend_node_id
                .ok_or("Exact reference has no DOM node")?;
            let object = resolve_exact_object(client, binding, backend).await?;
            return Ok((object, binding.session.clone()));
        }
        let effective_session_id = entry
            .exact_binding
            .as_ref()
            .map(|b| b.session.as_str())
            .unwrap_or_else(|| {
                resolve_frame_session(entry.frame_id.as_deref(), session_id, iframe_sessions)
            });

        // Try cached backend_node_id first (fast path)
        if let Some(backend_node_id) = entry.backend_node_id {
            let result: Result<DomResolveNodeResult, String> = client
                .send_command_typed(
                    "DOM.resolveNode",
                    &DomResolveNodeParams {
                        backend_node_id: Some(backend_node_id),
                        node_id: None,
                        object_group: Some("agent-browser".to_string()),
                    },
                    Some(effective_session_id),
                )
                .await;

            if let Ok(r) = result {
                if let Some(object_id) = r.object.object_id {
                    let connected = if !entry.allow_role_fallback {
                        match exact_connected(client, effective_session_id, &object_id).await {
                            Ok(true) => true,
                            Ok(false) => {
                                release_native_object(client, effective_session_id, &object_id)
                                    .await;
                                false
                            }
                            Err(error) => {
                                release_native_object(client, effective_session_id, &object_id)
                                    .await;
                                return Err(error);
                            }
                        }
                    } else {
                        !is_detached(client, effective_session_id, &object_id).await
                    };
                    if connected {
                        return Ok((object_id, effective_session_id.to_string()));
                    }
                }
            }
            if !entry.allow_role_fallback {
                return Err(format!("Element ref {ref_id} is stale"));
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

/// Resolve into the frame's isolated realm and prove document ownership, not
/// just connectedness (adoptNode can move a still-connected node across frames).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExactResolutionError {
    StaleReference,
    Superseded,
    BackendFailure,
    CleanupFailed {
        primary: Option<Box<ExactResolutionError>>,
    },
}
impl std::fmt::Display for ExactResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::StaleReference => "Reference no longer belongs to its document",
            Self::Superseded => "Observation capture was superseded",
            Self::BackendFailure => "Exact reference proof unavailable",
            Self::CleanupFailed { .. } => "Exact reference cleanup failed",
        })
    }
}
impl From<String> for ExactResolutionError {
    fn from(_: String) -> Self {
        Self::BackendFailure
    }
}

pub async fn resolve_exact_object(
    client: &CdpClient,
    binding: &ExactBinding,
    backend: i64,
) -> Result<String, String> {
    resolve_exact_object_typed(client, binding, backend)
        .await
        .map_err(|error| error.to_string())
}

/// Stale requires a successful native negative proof. Protocol exceptions,
/// malformed replies and lost acknowledgements never authorize retry.
pub async fn resolve_exact_object_typed(
    client: &CdpClient,
    binding: &ExactBinding,
    backend: i64,
) -> Result<String, ExactResolutionError> {
    let context = create_exact_realm(client, binding).await?;
    resolve_exact_object_in_realm_typed(client, binding, backend, context).await
}
// Ordinary actions do not have this Observe-only task-local context. Stop
// before new proof/acquisition commands, never inside mandatory handle release.
fn check_capture_retirement() -> Result<(), ExactResolutionError> {
    if super::client_observation::capture_superseded() {
        Err(ExactResolutionError::Superseded)
    } else {
        Ok(())
    }
}
pub async fn create_exact_realm(
    client: &CdpClient,
    binding: &ExactBinding,
) -> Result<i64, ExactResolutionError> {
    check_capture_retirement()?;
    let world = client
        .send_command(
            "Page.createIsolatedWorld",
            Some(serde_json::json!({
                "frameId": binding.frame, "worldName": "agent-browser-native-observation"
            })),
            Some(&binding.session),
        )
        .await?;
    let context = world["executionContextId"]
        .as_i64()
        .ok_or(ExactResolutionError::BackendFailure)?;
    Ok(context)
}
pub async fn resolve_exact_object_in_realm_typed(
    client: &CdpClient,
    binding: &ExactBinding,
    backend: i64,
    context: i64,
) -> Result<String, ExactResolutionError> {
    check_capture_retirement()?;
    let result = client.send_command("DOM.resolveNode", Some(serde_json::json!({
        "backendNodeId": backend, "executionContextId": context, "objectGroup": "native-exact"
    })), Some(&binding.session)).await?;
    let object = result["object"]["objectId"]
        .as_str()
        .ok_or(ExactResolutionError::BackendFailure)?
        .to_string();
    let proof: Result<(), ExactResolutionError> = async {
        check_capture_retirement()?;
        let result = super::client_debt::command_scope(super::client_debt::CommandCategory::ApplicationRead, false, client.send_command("Runtime.callFunctionOn", Some(serde_json::json!({
            "objectId": object, "functionDeclaration": "function() { const p=Node.prototype; return Object.getOwnPropertyDescriptor(p,'isConnected').get.call(this) === true && (this === document || Object.getOwnPropertyDescriptor(p,'ownerDocument').get.call(this) === document); }", "returnByValue": true
        })), Some(&binding.session))).await?;
        let mut seen = std::collections::HashSet::new();
        let mut cleanup_failed = false;
        for handle in [result["result"]["objectId"].as_str(), result["exceptionDetails"]["exception"]["objectId"].as_str()].into_iter().flatten() {
            if handle != object && seen.insert(handle) { cleanup_failed |= !release_exact_handle(client, &binding.session, handle).await; }
        }
        let result = if result.get("exceptionDetails").is_some() { Err(ExactResolutionError::BackendFailure) } else {
            match result["result"]["value"].as_bool() {
                Some(true) => validate_exact_binding_typed(client, &binding.page_session, binding).await,
                Some(false) => Err(ExactResolutionError::StaleReference),
                None => Err(ExactResolutionError::BackendFailure),
            }
        };
        if cleanup_failed { Err(ExactResolutionError::CleanupFailed { primary: result.err().map(Box::new) }) } else { result }
    }.await;
    if let Err(error) = proof {
        if !release_exact_handle(client, &binding.session, &object).await {
            return Err(ExactResolutionError::CleanupFailed {
                primary: Some(Box::new(error)),
            });
        }
        return Err(error);
    }
    Ok(object)
}
async fn release_exact_handle(client: &CdpClient, session: &str, object: &str) -> bool {
    // Only exact reader-accounted object disposal may survive a missing ACK.
    // Mask/security restoration remains on its existing strict cleanup path.
    super::client_actions::release_object_accounted(client, session, object).await
}

pub async fn validate_exact_binding(
    client: &CdpClient,
    page_session: &str,
    binding: &ExactBinding,
) -> Result<(), String> {
    validate_exact_binding_typed(client, page_session, binding)
        .await
        .map_err(|error| error.to_string())
}
pub async fn validate_exact_binding_typed(
    client: &CdpClient,
    page_session: &str,
    binding: &ExactBinding,
) -> Result<(), ExactResolutionError> {
    if page_session != binding.page_session {
        return Err(ExactResolutionError::StaleReference);
    }
    check_capture_retirement()?;
    let tree = client
        .send_command_no_params("Page.getFrameTree", Some(&binding.session))
        .await?;
    exact_document_present(&tree, binding)
}
fn exact_document_present(
    tree: &Value,
    binding: &ExactBinding,
) -> Result<(), ExactResolutionError> {
    if exact_document_loader(tree, binding)? == Some(binding.loader.as_str()) {
        Ok(())
    } else {
        Err(ExactResolutionError::StaleReference)
    }
}
/// Positive replacement evidence is narrower than generic stale reference:
/// a missing frame or empty loader cannot certify a new document.
pub(crate) async fn exact_document_replaced(
    client: &CdpClient,
    binding: &ExactBinding,
) -> Result<bool, ExactResolutionError> {
    let tree = client
        .send_command_no_params("Page.getFrameTree", Some(&binding.session))
        .await?;
    exact_document_replacement_in_tree(&tree, binding)
}
fn exact_document_replacement_in_tree(
    tree: &Value,
    binding: &ExactBinding,
) -> Result<bool, ExactResolutionError> {
    Ok(exact_document_loader(tree, binding)?
        .is_some_and(|loader| !loader.is_empty() && loader != binding.loader))
}
fn exact_document_loader<'a>(
    tree: &'a Value,
    binding: &ExactBinding,
) -> Result<Option<&'a str>, ExactResolutionError> {
    let mut pending = vec![(&tree["frameTree"], 0usize)];
    let mut ids = std::collections::HashSet::new();
    let mut found = None;
    while let Some((node, depth)) = pending.pop() {
        if depth > 64 || ids.len() >= 4096 {
            return Err(ExactResolutionError::BackendFailure);
        }
        let frame = &node["frame"];
        let id = frame["id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or(ExactResolutionError::BackendFailure)?;
        let loader = frame["loaderId"]
            .as_str()
            .ok_or(ExactResolutionError::BackendFailure)?;
        if !ids.insert(id) {
            return Err(ExactResolutionError::BackendFailure);
        }
        if id == binding.frame {
            found = Some(loader);
        }
        if let Some(children) = node.get("childFrames") {
            let children = children
                .as_array()
                .ok_or(ExactResolutionError::BackendFailure)?;
            if children.len() > 4096 {
                return Err(ExactResolutionError::BackendFailure);
            }
            pending.extend(children.iter().map(|child| (child, depth + 1)));
        }
    }
    Ok(found)
}

async fn release_native_object(client: &CdpClient, session: &str, object: &str) {
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        client.send_command(
            "Runtime.releaseObject",
            Some(serde_json::json!({"objectId":object})),
            Some(session),
        ),
    )
    .await;
}

// Even returnByValue calls can return remote exception/result objects. Release
// those auxiliary handles while keeping the caller's owned node until its proof
// either succeeds or the caller releases it on every failed outcome.
async fn release_evaluation_handles(
    client: &CdpClient,
    session: &str,
    result: &Value,
    owned: &str,
) {
    let handles = [
        result["result"]["objectId"].as_str(),
        result["exceptionDetails"]["exception"]["objectId"].as_str(),
    ];
    let mut released = std::collections::HashSet::new();
    for handle in handles.into_iter().flatten() {
        if handle != owned && released.insert(handle) {
            release_native_object(client, session, handle).await;
        }
    }
}

async fn exact_connected(client: &CdpClient, session: &str, object: &str) -> Result<bool, String> {
    let result = client.send_command("Runtime.callFunctionOn", Some(serde_json::json!({
        "objectId": object, "functionDeclaration": "function() { return this.isConnected === true; }",
        "returnByValue": true
    })), Some(session)).await?;
    release_evaluation_handles(client, session, &result, object).await;
    if result.get("exceptionDetails").is_some() {
        return Err("Cannot verify reference connectivity".into());
    }
    result["result"]["value"]
        .as_bool()
        .ok_or_else(|| "Cannot verify reference connectivity".into())
}

/// Reports whether a resolved node has been removed from its document, releasing it if so.
async fn is_detached(client: &CdpClient, session_id: &str, object_id: &str) -> bool {
    let result: Result<EvaluateResult, String> = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: "function() { return this.isConnected; }".to_string(),
                object_id: Some(object_id.to_string()),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(session_id),
        )
        .await;
    let detached = matches!(result, Ok(r) if r.result.value == Some(Value::Bool(false)));
    if detached {
        let _ = client
            .send_command(
                "Runtime.releaseObject",
                Some(serde_json::json!({ "objectId": object_id })),
                Some(session_id),
            )
            .await;
    }
    detached
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

/// Finds a stale ref's replacement by role and name, refusing any match that could be ambiguous.
async fn find_node_id_by_role_name(
    client: &CdpClient,
    session_id: &str,
    role: &str,
    name: &str,
    nth: Option<usize>,
    frame_id: Option<&str>,
    iframe_sessions: &HashMap<String, String>,
) -> Result<i64, String> {
    if nth.is_some() {
        return Err(format!(
            "Stale ref for role={} name={} cannot be recovered: the snapshot had several matching elements. Run snapshot again and use a fresh ref.",
            role, name
        ));
    }
    let (ax_params, effective_session_id) =
        resolve_ax_session(frame_id, session_id, iframe_sessions);
    let ax_tree: GetFullAXTreeResult = client
        .send_command_typed(
            "Accessibility.getFullAXTree",
            &ax_params,
            Some(effective_session_id),
        )
        .await?;

    select_unique_node_id(&ax_tree.nodes, role, name)
}

/// Returns the backendDOMNodeId of the only non-ignored node matching role and name.
fn select_unique_node_id(nodes: &[AXNode], role: &str, name: &str) -> Result<i64, String> {
    let mut found: Option<&AXNode> = None;

    for node in nodes {
        if node.ignored.unwrap_or(false) {
            continue;
        }
        if extract_ax_string(&node.role) == role && extract_ax_string(&node.name) == name {
            if found.is_some() {
                return Err(format!(
                    "Stale ref for role={} name={} cannot be recovered: several elements now match. Run snapshot again and use a fresh ref.",
                    role, name
                ));
            }
            found = Some(node);
        }
    }

    match found {
        Some(node) => node.backend_d_o_m_node_id.ok_or_else(|| {
            format!(
                "AX node has no backendDOMNodeId for role={} name={}",
                role, name
            )
        }),
        None => Err(format!(
            "Could not locate element with role={} name={}",
            role, name
        )),
    }
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
pub(crate) const BLOCKER_AT_JS: &str = r#"(doc, el, x, y) => {
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

/// Returns why a click at (x, y) cannot reach `el`, or null when it can.
/// It fails open when the engine lacks an API it needs.
pub(crate) const ACTIONABILITY_JS: &str = r#"(doc, el, x, y) => {
    try {
        const rect = el.getBoundingClientRect();
        if ((rect.width <= 0 && rect.height <= 0) || ['hidden', 'collapse'].includes(el.ownerDocument.defaultView.getComputedStyle(el).visibility)) return 'not visible';
        if (el.disabled || el.matches(':disabled')) return 'disabled';
        const view = doc.defaultView;
        const outside = x < 0 || y < 0 || x >= view.innerWidth || y >= view.innerHeight;
        if (outside && !doc.elementFromPoint(x, y)) return 'outside the viewport';
    } catch (e) {}
    return null;
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
            const notActionable = {ACTIONABILITY_JS};
            return {{ x: x, y: y, reason: notActionable(document, el, x, y), blocker: blockerAt(document, el, x, y) }};
        }})()"#,
    )
}

async fn resolve_by_selector(
    client: &CdpClient,
    session_id: &str,
    selector: &str,
    require_actionable: bool,
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
    if require_actionable {
        if let Some(reason) = val.get("reason").and_then(|v| v.as_str()) {
            return Err(not_actionable_error(selector, reason));
        }
    }
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

fn not_actionable_error(target: &str, reason: &str) -> String {
    format!(
        "Element '{}' is {}, so the click would not reach it",
        target, reason
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
                function_declaration: "function() { return !this.disabled && !(this.matches && this.matches(':disabled')); }".to_string(),
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
                    "function() { return typeof this.value === 'string' ? this.value : ''; }"
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
    fn strict_binding(loader: &str) -> ExactBinding {
        ExactBinding {
            page_session: "page".into(),
            session: "session".into(),
            frame: "frame".into(),
            loader: loader.into(),
            actionable: true,
        }
    }

    fn located_issuance() -> LocatedIssuance {
        LocatedIssuance {
            identity_scope: "scope".into(),
            generation: 7,
            revision: 3,
        }
    }

    #[test]
    fn located_sources_have_fresh_issuance_and_survive_only_normal_observation() {
        let mut refs = RefMap::new();
        let observed = refs.bind_exact(42, "button", "", strict_binding("doc"));
        let origin = LiveQueryOrigin::new("complete-query-source".into());
        let first = refs
            .try_bind_located(
                42,
                "button",
                strict_binding("doc"),
                located_issuance(),
                Some(origin.clone()),
            )
            .unwrap();
        let second = refs
            .try_bind_located(
                42,
                "button",
                strict_binding("doc"),
                located_issuance(),
                Some(origin.clone()),
            )
            .unwrap();
        let pinned = refs
            .try_bind_located(
                42,
                "button",
                strict_binding("doc"),
                located_issuance(),
                None,
            )
            .unwrap();
        assert_ne!(first, second);
        assert_ne!(first, observed);
        assert_ne!(pinned, observed);
        let issued = refs.get(&first).unwrap().exact_binding.clone();
        let before = refs.next_ref_num();
        refs.begin_snapshot();
        assert!(refs.get(&observed).is_none());
        assert_eq!(refs.get(&first).unwrap().exact_binding, issued);
        assert_eq!(refs.get(&first).unwrap().live_query.as_ref(), Some(&origin));
        assert!(refs.get(&pinned).unwrap().live_query.is_none());
        assert_eq!(refs.get(&first).unwrap().issued_revision(), Some(3));
        assert!(refs
            .get(&first)
            .unwrap()
            .matches_reference("scope", 7, "page", "3"));
        for (scope, generation, page, revision) in [
            ("other", 7, "page", "3"),
            ("scope", 8, "page", "3"),
            ("scope", 7, "foreign", "3"),
            ("scope", 7, "page", "10"),
            ("scope", 7, "page", "03"),
        ] {
            assert!(!refs
                .get(&first)
                .unwrap()
                .matches_reference(scope, generation, page, revision));
        }
        refs.retire_all_references();
        assert_eq!(refs.retained_identity_counts(), (0, 0));
        assert_eq!(refs.next_ref_num(), before);
        let next = refs
            .try_bind_located(
                42,
                "button",
                strict_binding("doc"),
                located_issuance(),
                None,
            )
            .unwrap();
        assert_ne!(next, first);
        assert_ne!(next, pinned);
    }

    #[test]
    fn semantic_fallback_keeps_only_inert_identity_until_fresh_exact_observation() {
        let mut refs = RefMap::new();
        refs.begin_observation("scope", 7, 1);
        let observed = refs.bind_exact(42, "button", "", strict_binding("doc"));
        let located = refs
            .try_bind_located(
                42,
                "button",
                strict_binding("doc"),
                located_issuance(),
                None,
            )
            .unwrap();
        let allocated = refs.next_ref_num();
        let mut staged = refs.clone();
        staged.retire_semantic_authority();
        assert!(refs.get(&observed).is_some());
        assert!(refs.get(&located).is_some());
        assert!(staged.get(&observed).is_none());
        assert!(staged.get(&located).is_none());
        assert_eq!(staged.retained_identity_counts(), (0, 1));
        assert_eq!(staged.next_ref_num(), allocated);
        staged.begin_observation("scope", 7, 2);
        assert!(staged.get(&observed).is_none());
        assert_eq!(
            staged.bind_exact(42, "button", "changed", strict_binding("doc")),
            observed
        );
        let current = staged.get(&observed).unwrap();
        assert!(current.is_current_observed(2));
        assert!(!current.is_current_observed(1));
        assert!(current.matches_reference("scope", 7, "page", "1"));
        for revision in ["0", "2", "01", "999"] {
            assert!(!current.matches_reference("scope", 7, "page", revision));
        }
        assert!(staged.get(&located).is_none());
        assert_eq!(staged.next_ref_num(), allocated);
    }

    #[test]
    fn semantic_fallback_does_not_merge_replaced_or_foreign_native_identity() {
        for change in [
            "backend",
            "session",
            "loader",
            "frame",
            "page",
            "scope",
            "generation",
            "unknown",
            "kind",
            "origin",
        ] {
            let mut refs = RefMap::new();
            refs.begin_observation("scope", 7, 1);
            let old = refs.bind_exact(42, "button", "same name", strict_binding("doc"));
            refs.retire_semantic_authority();
            let mut binding = strict_binding("doc");
            let mut backend = 42;
            let mut scope = "scope";
            let mut generation = 7;
            match change {
                "backend" => backend = 43,
                "session" => binding.session = "other-session".into(),
                "loader" => binding.loader = "other-document".into(),
                "frame" => binding.frame = "other-frame".into(),
                "page" => binding.page_session = "other-page".into(),
                "scope" => scope = "other-scope",
                "generation" => generation = 8,
                "unknown" => {
                    assert!(!refs.observe_document("page", Some("frame"), "session", None))
                }
                "kind" | "origin" => {}
                _ => unreachable!(),
            }
            refs.begin_observation(scope, generation, 2);
            let fresh = match change {
                "kind" => refs
                    .try_bind_readonly_pseudo(backend, "button", binding)
                    .unwrap(),
                "origin" => refs
                    .try_bind_exact_with_origin(
                        backend,
                        "button",
                        "same name",
                        binding,
                        Some(LiveQueryOrigin::new("other-source".into())),
                    )
                    .unwrap(),
                _ => refs.bind_exact(backend, "button", "same name", binding),
            };
            assert_ne!(fresh, old, "{change}");
            assert!(refs.get(&old).is_none(), "{change}");
        }
        let mut refs = RefMap::new();
        refs.begin_observation("scope", 7, 1);
        let old = refs.bind_exact(42, "button", "", strict_binding("doc"));
        refs.retire_semantic_authority();
        refs.retire_owner_references();
        assert_eq!(refs.retained_identity_counts(), (0, 0));
        refs.begin_observation("scope", 7, 2);
        assert_ne!(
            refs.bind_exact(42, "button", "", strict_binding("doc")),
            old
        );
    }

    #[test]
    fn semantic_fallback_retains_existing_durable_capacity_and_origin_byte_charges() {
        let mut refs = RefMap::new();
        refs.set_exact_limit_for_test(2);
        refs.begin_observation("scope", 7, 1);
        let old = refs.bind_exact(42, "button", "", strict_binding("doc"));
        refs.bind_exact(43, "button", "", strict_binding("doc"));
        let allocated = refs.next_ref_num();
        for revision in 2..10 {
            refs.retire_semantic_authority();
            assert_eq!(refs.retained_identity_counts(), (0, 2));
            refs.begin_observation("scope", 7, revision);
            assert_eq!(
                refs.bind_exact(42, "button", "", strict_binding("doc")),
                old
            );
            assert_eq!(
                refs.try_bind_exact(44, "button", "", strict_binding("doc")),
                Err(RefAllocationError::Capacity)
            );
            assert_eq!(refs.retained_identity_counts(), (1, 2));
            assert_eq!(refs.next_ref_num(), allocated);
        }
        let mut refs = RefMap::new();
        let origin = LiveQueryOrigin::new("same".into());
        refs.set_query_origin_byte_limit_for_test(2 * origin.source.len());
        refs.begin_observation("scope", 7, 1);
        let old = refs
            .try_bind_exact_with_origin(
                42,
                "button",
                "",
                strict_binding("doc"),
                Some(origin.clone()),
            )
            .unwrap();
        refs.retire_semantic_authority();
        assert_eq!(refs.retained_query_origin_bytes(), origin.source.len());
        refs.begin_observation("scope", 7, 2);
        assert_eq!(
            refs.try_bind_exact_with_origin(
                42,
                "button",
                "",
                strict_binding("doc"),
                Some(origin.clone())
            )
            .unwrap(),
            old
        );
        let allocated = refs.next_ref_num();
        assert_eq!(
            refs.try_bind_exact_with_origin(
                43,
                "button",
                "",
                strict_binding("doc"),
                Some(origin.clone())
            ),
            Err(RefAllocationError::Capacity)
        );
        assert_eq!(refs.retained_query_origin_bytes(), 2 * origin.source.len());
        assert_eq!(refs.retained_identity_counts(), (1, 1));
        assert_eq!(refs.next_ref_num(), allocated);
    }

    #[test]
    fn located_batch_token_consumes_reserved_entry_and_source_budgets_once() {
        let mut refs = RefMap::new();
        refs.set_exact_limit_for_test(2);
        refs.set_query_origin_byte_limit_for_test(4);
        let origin = LiveQueryOrigin::new("ab".into());
        let mut batch = refs
            .admit_located_batch(&[Some(origin.clone()), Some(origin.clone())])
            .unwrap();
        let first = batch
            .try_bind(
                1,
                "button",
                strict_binding("doc"),
                located_issuance(),
                Some(origin.clone()),
            )
            .unwrap();
        let second = batch
            .try_bind(
                2,
                "button",
                strict_binding("doc"),
                located_issuance(),
                Some(origin),
            )
            .unwrap();
        assert_eq!(
            batch.try_bind(3, "button", strict_binding("doc"), located_issuance(), None),
            Err(RefAllocationError::Capacity)
        );
        assert_ne!(first, second);
        assert_eq!(refs.next_ref_num(), 3);
        assert_eq!(refs.retained_identity_counts(), (2, 0));
        assert_eq!(refs.retained_query_origin_bytes(), 4);
    }

    #[test]
    fn located_batch_admission_and_abandoned_observation_preserve_all_authority() {
        let mut refs = RefMap::new();
        let observed = refs.bind_exact(42, "button", "", strict_binding("doc"));
        let origin = LiveQueryOrigin::new("complete-query-source".into());
        refs.set_query_origin_byte_limit_for_test(origin.source.len());
        let before = refs.next_ref_num();
        assert_eq!(
            refs.check_located_admission(&[Some(origin.clone()), Some(origin.clone())]),
            Err(RefAllocationError::Capacity)
        );
        assert_eq!(refs.next_ref_num(), before);
        let live = refs
            .try_bind_located(
                42,
                "button",
                strict_binding("doc"),
                located_issuance(),
                Some(origin.clone()),
            )
            .unwrap();
        let pinned = refs
            .try_bind_located(
                42,
                "button",
                strict_binding("doc"),
                located_issuance(),
                None,
            )
            .unwrap();
        let original = refs.ref_ids();
        let mut staged = refs.clone();
        staged.begin_snapshot();
        assert!(staged.get(&observed).is_none());
        assert!(staged.get(&live).is_some());
        assert!(staged.get(&pinned).is_some());
        let skipped = staged
            .try_bind_located(
                43,
                "button",
                strict_binding("doc"),
                located_issuance(),
                None,
            )
            .unwrap();
        drop(staged);
        assert_eq!(refs.ref_ids(), original);
        assert_eq!(refs.retained_query_origin_bytes(), origin.source.len());
        let next = refs
            .try_bind_located(
                43,
                "button",
                strict_binding("doc"),
                located_issuance(),
                None,
            )
            .unwrap();
        assert_ne!(next, skipped);
        assert!(refs.get(&observed).is_some());
    }

    #[test]
    fn strict_origins_never_overwrite_exact_or_other_query_authority() {
        let mut refs = RefMap::new();
        let origin = LiveQueryOrigin::new("query-a".into());
        let observed = refs.bind_exact(42, "button", "", strict_binding("doc"));
        let strict = refs
            .try_bind_exact_with_origin(
                42,
                "button",
                "",
                strict_binding("doc"),
                Some(origin.clone()),
            )
            .unwrap();
        assert_ne!(observed, strict);
        assert_eq!(
            refs.bind_exact(42, "button", "", strict_binding("doc")),
            observed
        );
        assert!(refs.get(&observed).unwrap().live_query.is_none());
        assert_eq!(
            refs.get(&strict).unwrap().live_query.as_ref(),
            Some(&origin)
        );
        let before = refs.next_ref_num();
        let repeat = refs
            .try_bind_exact_with_origin(
                42,
                "button",
                "",
                strict_binding("doc"),
                Some(LiveQueryOrigin::new("query-a".into())),
            )
            .unwrap();
        assert_eq!(repeat, strict);
        assert_eq!(refs.next_ref_num(), before);
        assert_eq!(refs.retained_query_origin_bytes(), 2 * origin.source.len());
        // Even an artificial digest collision cannot merge different sources.
        let mut collision = LiveQueryOrigin::new("query-b".into());
        collision.fingerprint = origin.fingerprint;
        let different = refs
            .try_bind_exact_with_origin(42, "button", "", strict_binding("doc"), Some(collision))
            .unwrap();
        assert_ne!(different, strict);
        assert_eq!(refs.retained_identity_counts(), (3, 3));
    }

    #[test]
    fn strict_origin_byte_admission_is_atomic_and_retirement_releases_budget() {
        let mut refs = RefMap::new();
        let origin = LiveQueryOrigin::new("query-a".into());
        refs.set_query_origin_byte_limit_for_test(2 * origin.source.len());
        let first = refs
            .try_bind_exact_with_origin(
                42,
                "button",
                "",
                strict_binding("doc"),
                Some(origin.clone()),
            )
            .unwrap();
        let before = refs.next_ref_num();
        assert_eq!(
            refs.try_bind_exact_with_origin(
                43,
                "button",
                "",
                strict_binding("doc"),
                Some(origin.clone())
            ),
            Err(RefAllocationError::Capacity)
        );
        assert_eq!(refs.next_ref_num(), before);
        assert_eq!(refs.retained_identity_counts(), (1, 1));
        assert_eq!(refs.retained_query_origin_bytes(), 2 * origin.source.len());
        // Replacing only the durable bucket still retains the old map entry:
        // admission must charge that source rather than dropping its accounting.
        assert_eq!(
            refs.try_bind_exact_with_origin(
                42,
                "button",
                "",
                strict_binding("next"),
                Some(origin.clone())
            ),
            Err(RefAllocationError::Capacity)
        );
        assert_eq!(refs.next_ref_num(), before);
        assert_eq!(refs.documents.values().next().unwrap().loader, "doc");
        refs.begin_snapshot();
        assert_eq!(refs.retained_query_origin_bytes(), origin.source.len());
        assert_eq!(
            refs.try_bind_exact_with_origin(
                42,
                "button",
                "",
                strict_binding("doc"),
                Some(origin.clone())
            )
            .unwrap(),
            first
        );
        assert_eq!(refs.retained_query_origin_bytes(), 2 * origin.source.len());
        refs.begin_snapshot();
        let replacement = refs
            .try_bind_exact_with_origin(
                42,
                "button",
                "",
                strict_binding("next"),
                Some(origin.clone()),
            )
            .unwrap();
        assert_ne!(replacement, first);
        assert_eq!(refs.retained_query_origin_bytes(), 2 * origin.source.len());
        refs.invalidate_all_documents();
        assert_eq!(refs.retained_query_origin_bytes(), 0);
        let after_retirement = refs
            .try_bind_exact_with_origin(42, "button", "", strict_binding("next"), Some(origin))
            .unwrap();
        assert_ne!(after_retirement, first);
        assert_ne!(after_retirement, replacement);
    }

    #[test]
    fn strict_origin_staging_pruning_and_abandonment_keep_budget_and_no_id_reuse() {
        let mut baseline = RefMap::new();
        let origin = LiveQueryOrigin::new("query-a".into());
        let first = baseline
            .try_bind_exact_with_origin(
                42,
                "button",
                "",
                strict_binding("doc"),
                Some(origin.clone()),
            )
            .unwrap();
        let mut staged = baseline.clone();
        let kept = staged
            .try_bind_exact_with_origin(
                43,
                "button",
                "",
                strict_binding("doc"),
                Some(origin.clone()),
            )
            .unwrap();
        let discarded = staged
            .try_bind_exact_with_origin(
                44,
                "button",
                "",
                strict_binding("doc"),
                Some(origin.clone()),
            )
            .unwrap();
        staged.retain_query_additions(&baseline, &std::collections::HashSet::from([kept.clone()]));
        assert_eq!(
            staged.retained_query_origin_bytes(),
            4 * origin.source.len()
        );
        assert_eq!(
            baseline.retained_query_origin_bytes(),
            2 * origin.source.len()
        );
        assert!(staged.get(&first).is_some());
        assert!(staged.get(&discarded).is_none());
        drop(staged);
        let later = baseline
            .try_bind_exact_with_origin(43, "button", "", strict_binding("doc"), Some(origin))
            .unwrap();
        assert_ne!(later, kept);
        assert_ne!(later, discarded);
    }

    #[test]
    fn exact_document_stale_requires_well_formed_complete_native_tree() {
        let binding = ExactBinding {
            page_session: "page".into(),
            session: "page".into(),
            frame: "main".into(),
            loader: "old".into(),
            actionable: true,
        };
        assert_eq!(
            exact_document_present(
                &serde_json::json!({"frameTree":{"frame":{"id":"main","loaderId":"new"}}}),
                &binding
            ),
            Err(ExactResolutionError::StaleReference)
        );
        for malformed in [
            serde_json::json!({}),
            serde_json::json!({"frameTree":{"frame":{"id":"main"}}}),
            serde_json::json!({"frameTree":{"frame":{"id":"main","loaderId":"new"},"childFrames":[{"frame":{"id":"main","loaderId":"new"}}]}}),
        ] {
            assert_eq!(
                exact_document_present(&malformed, &binding),
                Err(ExactResolutionError::BackendFailure)
            );
        }
    }

    #[test]
    fn exact_document_replacement_requires_present_frame_and_new_nonempty_loader() {
        let binding = ExactBinding {
            page_session: "page".into(),
            session: "page".into(),
            frame: "main".into(),
            loader: "old".into(),
            actionable: true,
        };
        for (id, loader, replaced) in [
            ("main", "new", true),
            ("main", "old", false),
            ("main", "", false),
            ("other", "new", false),
        ] {
            let tree = serde_json::json!({"frameTree":{"frame":{"id":id,"loaderId":loader}}});
            assert_eq!(
                exact_document_replacement_in_tree(&tree, &binding),
                Ok(replaced)
            );
        }
    }
    #[test]
    fn exact_default_admission_boundary_is_documented_and_non_mutating() {
        let refs = RefMap::new();
        let binding = ExactBinding {
            page_session: "page".into(),
            session: "session".into(),
            frame: "frame".into(),
            loader: "doc".into(),
            actionable: true,
        };
        let backends = (0..MAX_EXACT_REFERENCES as i64).collect::<Vec<_>>();
        assert_eq!(refs.check_exact_admission(&binding, &backends), Ok(()));
        let mut excessive = backends;
        excessive.push(MAX_EXACT_REFERENCES as i64);
        assert_eq!(
            refs.check_exact_admission(&binding, &excessive),
            Err(RefAllocationError::Capacity)
        );
        assert_eq!(refs.retained_identity_counts(), (0, 0));
    }
    #[test]
    fn exact_quota_rejects_atomically_and_retirement_never_reuses_ids() {
        let mut refs = RefMap::new();
        refs.set_exact_limit_for_test(2);
        let binding = ExactBinding {
            page_session: "page".into(),
            session: "session".into(),
            frame: "frame".into(),
            loader: "doc".into(),
            actionable: true,
        };
        let first = refs
            .try_bind_exact(1, "button", "", binding.clone())
            .unwrap();
        let second = refs
            .try_bind_exact(2, "button", "", binding.clone())
            .unwrap();
        assert_eq!(
            refs.try_bind_exact(3, "button", "", binding.clone()),
            Err(RefAllocationError::Capacity)
        );
        assert_eq!(refs.retained_identity_counts(), (2, 2));
        assert!(refs.get(&first).is_some());
        assert!(refs.get(&second).is_some());
        refs.invalidate_all_documents();
        assert_eq!(refs.retained_identity_counts(), (0, 0));
        assert!(refs.get(&first).is_none());
        let replacement = refs.try_bind_exact(1, "button", "", binding).unwrap();
        assert_ne!(first, replacement);
        assert_ne!(second, replacement);
    }
    #[test]
    fn query_retains_only_matched_additions_and_all_previous_authority() {
        let mut baseline = RefMap::new();
        let binding = ExactBinding {
            page_session: "page".into(),
            session: "session".into(),
            frame: "frame".into(),
            loader: "doc".into(),
            actionable: true,
        };
        let old = baseline
            .try_bind_exact(1, "button", "", binding.clone())
            .unwrap();
        let mut staged = baseline.clone();
        let kept = staged
            .try_bind_exact(2, "button", "", binding.clone())
            .unwrap();
        let discarded = staged
            .try_bind_exact(3, "button", "", binding.clone())
            .unwrap();
        staged.retain_query_additions(&baseline, &std::collections::HashSet::from([kept.clone()]));
        assert_eq!(staged.retained_identity_counts(), (2, 2));
        assert!(staged.get(&old).is_some());
        assert!(staged.get(&kept).is_some());
        assert!(staged.get(&discarded).is_none());
        assert!(staged.durable_ref("page", Some("frame"), 3).is_none());
        assert_ne!(
            staged.try_bind_exact(3, "button", "", binding).unwrap(),
            discarded
        );
    }
    #[test]
    fn viewport_publication_is_transactional_stable_and_not_dom_authority() {
        let mut refs = RefMap::new();
        let abandoned = {
            let mut staged = refs.clone();
            staged
                .try_viewport_ref("scope", 7, "page", 1)
                .unwrap()
                .clone()
        };
        assert!(!refs.is_viewport_ref(&abandoned.id));
        let first = refs
            .try_viewport_ref("scope", 7, "page", 2)
            .unwrap()
            .clone();
        assert_ne!(first.id, abandoned.id);
        assert!(refs.get(&first.id).is_none());
        refs.invalidate_all_documents();
        assert_eq!(
            refs.try_viewport_ref("scope", 7, "page", 3).unwrap(),
            &first
        );
        let mut staged = refs.clone();
        staged.retire_all_references();
        assert_eq!(
            staged.try_viewport_ref("scope", 7, "page", 4).unwrap(),
            &first
        );
        assert!(refs.matches_viewport_reference("scope", 7, "page", &first.id, "2"));
        for (scope, generation, page, revision) in [
            ("scope", 7, "page", "3"),
            ("scope", 7, "page", "02"),
            ("other", 7, "page", "2"),
            ("scope", 8, "page", "2"),
            ("scope", 7, "other", "2"),
        ] {
            assert!(!refs.matches_viewport_reference(scope, generation, page, &first.id, revision));
        }
        refs.retire_owner_references();
        assert!(!refs.is_viewport_ref(&first.id));
        let next = refs
            .try_viewport_ref("new-scope", 8, "page", 5)
            .unwrap()
            .clone();
        assert_ne!(next.id, first.id);
        assert_ne!(next.id, abandoned.id);
    }

    #[test]
    fn observed_issuance_survives_membership_refresh_not_forgery_or_retirement() {
        let mut refs = RefMap::new();
        refs.begin_observation("scope", 7, 1);
        let first = refs.bind_exact(42, "textbox", "", strict_binding("doc"));
        let mut staged = refs.clone();
        staged.begin_observation("scope", 7, 2);
        assert_eq!(
            staged.bind_exact(42, "textbox", "Changed", strict_binding("doc")),
            first
        );
        let entry = staged.get(&first).unwrap();
        assert_eq!(entry.issued_revision(), Some(1));
        assert!(entry.is_current_observed(2));
        assert!(!entry.is_current_observed(1));
        assert!(entry.matches_reference("scope", 7, "page", "1"));
        for revision in ["0", "2", "01", "999"] {
            assert!(!entry.matches_reference("scope", 7, "page", revision));
        }
        for (scope, generation, page) in [
            ("other", 7, "page"),
            ("scope", 8, "page"),
            ("scope", 7, "other"),
        ] {
            assert!(!entry.matches_reference(scope, generation, page, "1"));
        }
        refs = staged;
        let baseline = refs.clone();
        refs.begin_observation("scope", 7, 3);
        // Even a metadata reread is not current authority when projection omits it.
        assert_eq!(
            refs.bind_exact(42, "textbox", "", strict_binding("doc")),
            first
        );
        refs.retain_snapshot_entries(&baseline, &Default::default());
        assert!(refs.get(&first).is_none());
        refs.begin_observation("scope", 7, 4);
        assert_eq!(
            refs.bind_exact(42, "textbox", "", strict_binding("doc")),
            first
        );
        assert_eq!(refs.get(&first).unwrap().issued_revision(), Some(1));
        assert_ne!(
            refs.bind_exact(43, "textbox", "", strict_binding("doc")),
            first
        );
        refs.begin_observation("scope", 7, 5);
        assert_ne!(
            refs.bind_exact(42, "textbox", "", strict_binding("new-document")),
            first
        );
        refs.retire_all_references();
        refs.begin_observation("scope", 7, 6);
        assert_ne!(
            refs.bind_exact(42, "textbox", "", strict_binding("doc")),
            first
        );
    }

    #[test]
    fn observed_durable_kind_never_upgrades_or_rebinds_a_pseudo_id() {
        let mut refs = RefMap::new();
        refs.begin_observation("scope", 7, 1);
        let pseudo = refs
            .try_bind_readonly_pseudo(42, "text", strict_binding("doc"))
            .unwrap();
        let initial = refs.clone();
        refs.begin_observation("scope", 7, 2);
        assert_eq!(
            refs.try_bind_readonly_pseudo(42, "text", strict_binding("doc"))
                .unwrap(),
            pseudo
        );
        assert_eq!(refs.get(&pseudo).unwrap().issued_revision(), Some(1));
        refs.retain_snapshot_entries(&initial, &Default::default());
        assert!(refs.get(&pseudo).is_none());
        refs.begin_observation("scope", 7, 3);
        assert_eq!(
            refs.try_bind_readonly_pseudo(42, "text", strict_binding("doc"))
                .unwrap(),
            pseudo
        );
        // Same numeric backend and binding, different immutable authority kind.
        let dom = refs.bind_exact(42, "button", "", strict_binding("doc"));
        assert_ne!(dom, pseudo);
        assert_eq!(
            refs.get(&pseudo).unwrap().kind,
            NativeReferenceKind::ReadOnlyCssPseudo
        );
        assert!(
            !refs
                .get(&pseudo)
                .unwrap()
                .exact_binding
                .as_ref()
                .unwrap()
                .actionable
        );
        assert_eq!(refs.get(&dom).unwrap().kind, NativeReferenceKind::Dom);
        let next_pseudo = refs
            .try_bind_readonly_pseudo(42, "text", strict_binding("doc"))
            .unwrap();
        assert_ne!(next_pseudo, dom);
        assert_ne!(
            next_pseudo, pseudo,
            "a retired durable kind is not resurrected"
        );
        assert_eq!(refs.get(&dom).unwrap().kind, NativeReferenceKind::Dom);
        assert_eq!(
            refs.get(&next_pseudo).unwrap().kind,
            NativeReferenceKind::ReadOnlyCssPseudo
        );
        let source = LiveQueryOrigin::new("different-query-origin".into());
        let other = refs
            .try_bind_exact_with_origin(42, "button", "", strict_binding("doc"), Some(source))
            .unwrap();
        assert_ne!(other, next_pseudo);
        assert_ne!(other, dom);
        assert_eq!(
            refs.try_bind_readonly_pseudo(42, "text", strict_binding("doc"))
                .unwrap(),
            next_pseudo
        );
        let abandoned = {
            let mut staged = refs.clone();
            staged.begin_observation("scope", 7, 4);
            staged.bind_exact(42, "button", "", strict_binding("doc"))
        };
        assert_eq!(
            refs.durable_ref("page", Some("frame"), 42),
            Some(next_pseudo.as_str())
        );
        refs.begin_observation("scope", 7, 5);
        assert_ne!(
            refs.bind_exact(42, "button", "", strict_binding("doc")),
            abandoned
        );
    }

    #[test]
    fn kind_mismatch_capacity_failure_is_atomic_before_allocating() {
        let mut refs = RefMap::new();
        refs.set_exact_limit_for_test(1);
        refs.begin_observation("scope", 7, 1);
        let pseudo = refs
            .try_bind_readonly_pseudo(42, "text", strict_binding("doc"))
            .unwrap();
        let next = refs.next_ref_num();
        assert_eq!(
            refs.try_bind_exact(42, "button", "", strict_binding("doc")),
            Err(RefAllocationError::Capacity)
        );
        assert_eq!(refs.next_ref_num(), next);
        assert_eq!(
            refs.durable_ref("page", Some("frame"), 42),
            Some(pseudo.as_str())
        );
        assert_eq!(
            refs.get(&pseudo).unwrap().kind,
            NativeReferenceKind::ReadOnlyCssPseudo
        );
        refs.begin_observation("scope", 7, 2);
        assert_ne!(
            refs.bind_exact(42, "button", "", strict_binding("doc")),
            pseudo
        );
    }

    #[test]
    fn abandoned_observed_records_cannot_resurrect_and_unissued_refs_have_no_authority() {
        let mut refs = RefMap::new();
        let legacy = refs.bind_exact(42, "textbox", "", strict_binding("doc"));
        assert!(!refs
            .get(&legacy)
            .unwrap()
            .matches_reference("scope", 7, "page", "1"));
        let abandoned = {
            let mut staged = refs.clone();
            staged.begin_observation("scope", 7, 1);
            staged.bind_exact(43, "textbox", "", strict_binding("doc"))
        };
        assert!(refs.get(&abandoned).is_none());
        assert!(refs.durable_ref("page", Some("frame"), 43).is_none());
        refs.begin_observation("scope", 7, 2);
        let published = refs.bind_exact(43, "textbox", "", strict_binding("doc"));
        assert_ne!(published, abandoned);
        assert_eq!(refs.get(&published).unwrap().issued_revision(), Some(2));
        let mut next = refs.clone();
        next.begin_observation("new-scope", 8, 3);
        assert_ne!(
            next.bind_exact(43, "textbox", "", strict_binding("doc")),
            published
        );
    }

    #[test]
    fn viewport_allocation_exhaustion_is_typed_without_recycling() {
        let mut refs = RefMap::new();
        refs.set_next_ref_num(usize::MAX);
        assert_eq!(
            refs.try_viewport_ref("scope", 7, "page", 1),
            Err(RefAllocationError::Exhausted)
        );
        assert!(!refs.is_viewport_ref("@e1"));
        assert_eq!(refs.next_ref_num(), usize::MAX);
    }

    #[tokio::test]
    async fn exact_connectivity_releases_owned_and_auxiliary_handles_on_every_failure() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        for scoped in [false, true] {
            for outcome in [
                "false",
                "exception",
                "protocol",
                "malformed",
                "alias",
                "true",
            ] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let url = format!("ws://{}", listener.local_addr().unwrap());
                let server = tokio::spawn(async move {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                    let mut releases = Vec::new();
                    while let Some(Ok(Message::Text(text))) = ws.next().await {
                        let request: Value = serde_json::from_str(&text).unwrap();
                        let mut response = serde_json::json!({"id":request["id"]});
                        response["result"] = match request["method"].as_str().unwrap() {
                            "Page.getFrameTree" => {
                                serde_json::json!({"frameTree":{"frame":{"id":"frame","loaderId":"loader"}}})
                            }
                            "Page.createIsolatedWorld" => {
                                serde_json::json!({"executionContextId":1})
                            }
                            "DOM.resolveNode" => {
                                serde_json::json!({"object":{"type":"object","objectId":"owned-node"}})
                            }
                            "Runtime.callFunctionOn" => match outcome {
                                "exception" => {
                                    serde_json::json!({"result":{"objectId":"rejected-result"},"exceptionDetails":{"exception":{"objectId":"exception"}}})
                                }
                                "alias" => {
                                    serde_json::json!({"result":{"objectId":"owned-node"},"exceptionDetails":{"exception":{"objectId":"owned-node"}}})
                                }
                                "protocol" => {
                                    response["error"] = serde_json::json!({"code":-32000,"message":"Synthetic failure"});
                                    Value::Null
                                }
                                "malformed" => {
                                    serde_json::json!({"result":{"objectId":"rejected-result"}})
                                }
                                other => {
                                    serde_json::json!({"result":{"type":"boolean","value":other=="true"}})
                                }
                            },
                            "Runtime.releaseObject" => {
                                releases.push(
                                    request["params"]["objectId"].as_str().unwrap().to_string(),
                                );
                                serde_json::json!({})
                            }
                            other => panic!("Unexpected command {other}"),
                        };
                        ws.send(Message::Text(response.to_string())).await.unwrap();
                    }
                    releases
                });
                let client = CdpClient::connect(&url).await.unwrap();
                let mut refs = RefMap::new();
                let reference = if scoped {
                    refs.bind_exact(
                        42,
                        "button",
                        "",
                        ExactBinding {
                            page_session: "session".into(),
                            session: "session".into(),
                            frame: "frame".into(),
                            loader: "loader".into(),
                            actionable: true,
                        },
                    )
                } else {
                    refs.add_exact_backend_node("e1".into(), 42);
                    "e1".into()
                };
                let result = resolve_element_object_id(
                    &client,
                    "session",
                    &refs,
                    &reference,
                    &HashMap::new(),
                )
                .await;
                assert_eq!(
                    result.is_ok(),
                    outcome == "true",
                    "scoped={scoped}, {outcome}"
                );
                if let Ok((object, session)) = result {
                    release_native_object(&client, &session, &object).await;
                }
                client.close().await;
                let mut released = server.await.unwrap();
                released.sort();
                let mut expected = vec!["owned-node"];
                if matches!(outcome, "exception" | "malformed") {
                    expected.push("rejected-result");
                }
                if outcome == "exception" {
                    expected.push("exception");
                }
                expected.sort();
                assert_eq!(released, expected, "scoped={scoped}, {outcome}");
            }
        }
    }

    use super::*;

    fn ax(role: &str, name: &str, id: Option<i64>, ignored: bool) -> AXNode {
        let val = |t: &str, v: &str| AXValue {
            value_type: t.into(),
            value: Some(serde_json::json!(v)),
        };
        AXNode {
            node_id: "1".into(),
            role: Some(val("role", role)),
            name: Some(val("computedString", name)),
            value: None,
            description: None,
            properties: None,
            child_ids: None,
            backend_d_o_m_node_id: id,
            ignored: Some(ignored),
        }
    }

    #[test]
    fn test_select_unique_node_id_returns_the_only_match() {
        let nodes = vec![
            ax("button", "Approve", Some(1), true),
            ax("button", "Approve", Some(7), false),
            ax("button", "Reject", Some(8), false),
        ];
        assert_eq!(select_unique_node_id(&nodes, "button", "Approve"), Ok(7));
    }

    #[test]
    fn test_select_unique_node_id_rejects_multiple_matches() {
        let ambiguous = "Stale ref for role=button name=Approve cannot be recovered: several elements now match. Run snapshot again and use a fresh ref.";
        let two_valid = vec![
            ax("button", "Approve", Some(1), false),
            ax("button", "Approve", Some(2), false),
        ];
        assert_eq!(
            select_unique_node_id(&two_valid, "button", "Approve"),
            Err(ambiguous.to_string())
        );
        let one_without_id = vec![
            ax("button", "Approve", None, false),
            ax("button", "Approve", Some(2), false),
        ];
        assert_eq!(
            select_unique_node_id(&one_without_id, "button", "Approve"),
            Err(ambiguous.to_string())
        );
    }

    #[test]
    fn test_select_unique_node_id_keeps_not_found_and_missing_id_errors() {
        let nodes = vec![ax("button", "Reject", Some(1), false)];
        assert_eq!(
            select_unique_node_id(&nodes, "button", "Approve"),
            Err("Could not locate element with role=button name=Approve".to_string())
        );
        let nodes = vec![ax("button", "Approve", None, false)];
        assert_eq!(
            select_unique_node_id(&nodes, "button", "Approve"),
            Err("AX node has no backendDOMNodeId for role=button name=Approve".to_string())
        );
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
    fn cloned_allocators_are_unique_and_cannot_rewind() {
        let mut map = RefMap::new();
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let clone = map.clone();
                std::thread::spawn(move || {
                    (0..100).map(|_| clone.allocate_ref()).collect::<Vec<_>>()
                })
            })
            .collect();
        let ids: std::collections::HashSet<_> = workers
            .into_iter()
            .flat_map(|w| w.join().unwrap())
            .collect();
        assert_eq!(ids.len(), 800);
        map.set_next_ref_num(1);
        assert_eq!(map.allocate_ref(), "e801");
        map.invalidate_all_documents();
        assert_eq!(map.allocate_ref(), "e802");
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
        map.remember_durable_ref("page-a", None, 42, "e1");
        map.remember_durable_ref("page-a", Some("frame-a"), 42, "e2");
        assert_eq!(map.durable_ref("page-a", None, 42), Some("e1"));
        assert_eq!(map.durable_ref("page-a", Some("frame-a"), 42), Some("e2"));
        assert_eq!(map.durable_ref("page-b", None, 42), None);

        map.invalidate_page("page-a");
        assert_eq!(map.durable_ref("page-a", None, 42), None);
        assert_eq!(map.next_ref_num(), 1);
    }

    #[test]
    fn invalidating_one_page_preserves_other_page_documents() {
        let mut map = RefMap::new();
        assert!(map.observe_document("page-a", None, "session-a", Some("loader-a")));
        map.remember_durable_ref("page-a", None, 42, "e1");
        assert!(map.observe_document("page-b", None, "session-b", Some("loader-b")));
        map.remember_durable_ref("page-b", None, 42, "e2");

        map.invalidate_page("page-b");

        assert_eq!(map.durable_ref("page-a", None, 42), Some("e1"));
        assert_eq!(map.durable_ref("page-b", None, 42), None);
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
