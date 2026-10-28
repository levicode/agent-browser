//! Explicit query authority. Neither registry membership nor diagnostic roots
//! are sufficient to exclude another renderer from a selected page read.
use super::*;
use crate::native::client_targets::{SelectedPageTargetBarrier, SelectedPageTargetSnapshot};

#[derive(Clone)]
pub(crate) struct PageQueryAuthority {
    owner: Arc<ClientEnrollment>,
    selected: OwnedTarget,
}
#[derive(Clone)]
pub(crate) struct PageAcquisitionProof {
    authority: PageQueryAuthority,
    entries: Vec<Attribution>,
    targets: SelectedPageTargetSnapshot,
    watermark: BoundedEventWatermark,
}
pub(crate) struct SelectedPageReadBarrier {
    proof: PageAcquisitionProof,
    guard: SelectedPageTargetBarrier,
}
impl ClientEnrollment {
    pub(crate) fn page_query_authority(
        self: &Arc<Self>,
        page: &BrowserExecutionLease,
        selected: &OwnedTarget,
    ) -> Result<PageQueryAuthority, ProtocolError> {
        if !Arc::ptr_eq(&self.client, &page.client)
            || !Arc::ptr_eq(&self.targets, &page.targets)
            || self.targets.identity_scope != page.identity_scope
            || selected.target_id != page.target_id
            || selected.session_id != page.page_session_id
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(PageQueryAuthority {
            owner: self.clone(),
            selected: selected.clone(),
        })
    }
}
fn selected_entry(index: &Index, target: &OwnedTarget, root: &str) -> Result<bool, ProtocolError> {
    let entry = index
        .sessions
        .get(&target.session_id)
        .ok_or(ProtocolError::StaleScope)?;
    if entry.target != target.target_id
        || entry.kind != target.kind
        || entry.observation_only
        || index.retired_page_sessions.contains(&entry.session)
        || index.retired_page_sessions.contains(&entry.root)
        || index.retired_observer_sessions.contains(&entry.session)
        || index.retired_observer_targets.contains(&entry.target)
        || index.borrowed_retired_targets.contains(&entry.target)
        || index
            .retiring_pages
            .iter()
            .any(|(target, session)| target == &entry.target || session == &entry.root)
    {
        return Err(ProtocolError::StaleScope);
    }
    if matches!(entry.kind.as_str(), "browser" | "tab" | "browser_ui") {
        return if entry.root == entry.session
            && entry.parent.is_none()
            && entry.application
            && entry.resumed
        {
            Ok(false)
        } else {
            Err(ProtocolError::ScopeUnavailable)
        };
    }
    if !matches!(entry.kind.as_str(), "page" | "iframe") {
        return if matches!(
            entry.kind.as_str(),
            "worker" | "shared_worker" | "service_worker"
        ) {
            Ok(false)
        } else {
            Err(ProtocolError::ScopeUnavailable)
        };
    }
    let mut ancestor = entry;
    let mut rooted = false;
    for _ in 0..=index.sessions.len() {
        if ancestor.kind == "page" && ancestor.root == ancestor.session && ancestor.parent.is_none()
        {
            rooted = ancestor.session == entry.root;
            break;
        }
        if ancestor.kind != "iframe" || ancestor.root != entry.root {
            break;
        }
        let Some(parent) = ancestor
            .parent
            .as_ref()
            .and_then(|session| index.sessions.get(session))
        else {
            break;
        };
        ancestor = parent;
    }
    if !rooted {
        return Err(ProtocolError::StaleScope);
    }
    let relevant = entry.root == root;
    if relevant && (!entry.application || !entry.resumed) {
        return Err(ProtocolError::ScopeUnavailable);
    }
    Ok(relevant)
}
impl PageQueryAuthority {
    /// Wait only for received events to be applied and attachments classified.
    /// Called before UI/publication locks. A retained initializer need not be
    /// ready, and this never creates a fresh initializer/cleanup deadline.
    pub(crate) async fn wait_classified(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        let owner = &self.owner;
        let watermark = owner.realm_watermark()?;
        bounded(op, async {
            loop {
                let changed = owner.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                owner.check_restart_operation(op)?;
                page.permit.check()?;
                if !Arc::ptr_eq(&owner.client, &page.client)
                    || !Arc::ptr_eq(&owner.targets, &page.targets)
                    || self.selected.target_id != page.target_id
                    || self.selected.session_id != page.page_session_id
                {
                    return Err(ProtocolError::StaleScope);
                }
                let classified = {
                    let index = owner
                        .index
                        .lock()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?;
                    if let Some(error) = &index.failure {
                        return Err(error.clone());
                    }
                    if !index.reconciled
                        || owner.sealed.load(Ordering::Acquire)
                        || index.borrowed_restart.is_some()
                    {
                        return Err(ProtocolError::ScopeUnavailable);
                    }
                    let subscription = owner
                        .event_watermark
                        .lock()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?;
                    if subscription
                        .as_ref()
                        .is_none_or(|current| !watermark.same_subscription(current))
                    {
                        return Err(ProtocolError::StaleScope);
                    }
                    watermark
                        .with_received(|received| {
                            if index.applied_watermark > received {
                                return Err(ProtocolError::StaleScope);
                            }
                            Ok(index.applied_watermark == received
                                && index
                                    .pending_enrollment
                                    .keys()
                                    .all(|session| index.sessions.contains_key(session)))
                        })
                        .map_err(|_| ProtocolError::ScopeUnavailable)??
                };
                if classified {
                    return Ok(());
                }
                changed.await;
            }
        })
        .await
    }
    fn with_partition<T>(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
        expected: Option<&PageAcquisitionProof>,
        held: Option<&SelectedPageTargetBarrier>,
        acquire_barrier: bool,
        publish: impl FnOnce(
            &[Attribution],
            &SelectedPageTargetSnapshot,
            &BoundedEventWatermark,
        ) -> Result<T, ProtocolError>,
    ) -> Result<(T, Option<SelectedPageTargetBarrier>), ProtocolError> {
        let owner = &self.owner;
        owner.check_restart_operation(op)?;
        page.permit.check()?;
        if !Arc::ptr_eq(&owner.client, &page.client)
            || !Arc::ptr_eq(&owner.targets, &page.targets)
            || self.selected.target_id != page.target_id
            || self.selected.session_id != page.page_session_id
            || owner.targets.identity_scope != page.identity_scope
        {
            return Err(ProtocolError::StaleScope);
        }
        let watermark = match expected {
            Some(proof) => proof.watermark.clone(),
            None => owner.realm_watermark()?,
        };
        let index = owner
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if let Some(error) = &index.failure {
            return Err(error.clone());
        }
        if owner.sealed.load(Ordering::Acquire)
            || !index.reconciled
            || index.borrowed_restart.is_some()
            || index
                .pending_enrollment
                .keys()
                .any(|session| !index.sessions.contains_key(session))
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let mut entries: Vec<_> = index
            .sessions
            .values()
            .filter(|entry| {
                entry.root == self.selected.session_id
                    && matches!(entry.kind.as_str(), "page" | "iframe")
            })
            .cloned()
            .collect();
        entries.sort_by(|a, b| a.session.cmp(&b.session));
        if expected.is_some_and(|proof| {
            !Arc::ptr_eq(&proof.authority.owner, owner) || proof.entries != entries
        }) {
            return Err(ProtocolError::StaleScope);
        }
        let subscription = owner
            .event_watermark
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if subscription
            .as_ref()
            .is_none_or(|current| !watermark.same_subscription(current))
        {
            return Err(ProtocolError::StaleScope);
        }
        watermark
            .with_received(|received| {
                if index.applied_watermark != received {
                    return Err(ProtocolError::ScopeUnavailable);
                }
                owner.targets.with_selected_page_targets(
                    &self.selected,
                    expected.map(|proof| &proof.targets),
                    held,
                    acquire_barrier,
                    |target, registered| {
                        let relevant = selected_entry(&index, target, &self.selected.session_id)?;
                        let entry = index
                            .sessions
                            .get(&target.session_id)
                            .ok_or(ProtocolError::StaleScope)?;
                        let root_entry = index
                            .sessions
                            .get(&entry.root)
                            .ok_or(ProtocolError::StaleScope)?;
                        let root = if root_entry.kind == "page" {
                            Some(
                                registered
                                    .get(&root_entry.target)
                                    .filter(|root| root.session_id == root_entry.session)
                                    .ok_or(ProtocolError::StaleScope)?,
                            )
                        } else {
                            None
                        };
                        if !target.query_lineage_matches(root) {
                            return Err(ProtocolError::StaleScope);
                        }
                        Ok(relevant)
                    },
                    |targets| {
                        // Every selected enrollment entry needs an exact target ticket.
                        if targets.targets.len() != entries.len()
                            || entries.iter().any(|entry| {
                                !targets.targets.iter().any(|target| {
                                    target.target_id == entry.target
                                        && target.session_id == entry.session
                                        && target.kind == entry.kind
                                })
                            })
                        {
                            return Err(ProtocolError::StaleScope);
                        }
                        if *op.cancellation.borrow() != CancelSignal::None {
                            return Err(ProtocolError::Cancelled);
                        }
                        if Instant::now() >= op.deadline {
                            return Err(ProtocolError::DeadlineExceeded);
                        }
                        publish(&entries, targets, &watermark)
                    },
                )
            })
            .map_err(|_| ProtocolError::ScopeUnavailable)?
    }
    pub(crate) fn acquire(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<PageAcquisitionProof, ProtocolError> {
        self.with_partition(
            page,
            op,
            None,
            None,
            false,
            |entries, targets, watermark| {
                Ok(PageAcquisitionProof {
                    authority: self.clone(),
                    entries: entries.to_vec(),
                    targets: targets.clone(),
                    watermark: watermark.clone(),
                })
            },
        )
        .map(|(proof, _)| proof)
    }
}
impl PageAcquisitionProof {
    pub(crate) fn targets(&self) -> &[OwnedTarget] {
        &self.targets.targets
    }
    pub(crate) fn check(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.authority
            .with_partition(page, op, Some(self), None, false, |_, _, _| Ok(()))
            .map(|_| ())
    }
    pub(crate) fn with_publication<T>(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
        publish: impl FnOnce() -> Result<T, ProtocolError>,
    ) -> Result<T, ProtocolError> {
        self.authority
            .with_partition(page, op, Some(self), None, false, |_, _, _| publish())
            .map(|(value, _)| value)
    }
    pub(crate) fn begin_read(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<SelectedPageReadBarrier, ProtocolError> {
        let (_, guard) =
            self.authority
                .with_partition(page, op, Some(self), None, true, |_, _, _| Ok(()))?;
        Ok(SelectedPageReadBarrier {
            proof: self.clone(),
            guard: guard.ok_or(ProtocolError::ScopeUnavailable)?,
        })
    }
}
impl SelectedPageReadBarrier {
    pub(crate) fn targets(&self) -> &[OwnedTarget] {
        self.proof.targets()
    }
    pub(crate) fn quarantine(&self) {
        self.proof.authority.owner.targets.seal();
    }
    pub(crate) fn check(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.with_publication(page, op, || Ok(()))
    }
    pub(crate) fn with_publication<T>(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
        publish: impl FnOnce() -> Result<T, ProtocolError>,
    ) -> Result<T, ProtocolError> {
        self.proof
            .authority
            .with_partition(
                page,
                op,
                Some(&self.proof),
                Some(&self.guard),
                false,
                |_, _, _| publish(),
            )
            .map(|(value, _)| value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(
        target: &str,
        session: &str,
        kind: &str,
        root: &str,
        parent: Option<&str>,
    ) -> Attribution {
        Attribution {
            target: target.into(),
            session: session.into(),
            kind: kind.into(),
            root: root.into(),
            parent: parent.map(str::to_owned),
            application: true,
            observation_only: false,
            observer_paused: None,
            resumed: true,
        }
    }
    fn fixture() -> (Index, Arc<ClientTargets>) {
        let mut index = Index::default();
        let registry = ClientTargets::new("ctx".into(), "scope".into());
        for entry in [
            entry("main", "main-session", "page", "main-session", None),
            entry("popup", "popup-session", "page", "popup-session", None),
            entry(
                "child",
                "child-session",
                "iframe",
                "main-session",
                Some("main-session"),
            ),
            entry(
                "popup-child",
                "popup-child-session",
                "iframe",
                "popup-session",
                Some("popup-session"),
            ),
        ] {
            registry
                .attached(
                    "ctx",
                    entry.target.clone(),
                    entry.session.clone(),
                    entry.kind.clone(),
                )
                .unwrap();
            index.sessions.insert(entry.session.clone(), entry);
        }
        (index, registry)
    }
    #[test]
    fn query_partition_excludes_popup_tree_not_only_popup_root() {
        let (index, registry) = fixture();
        for (target, included) in [
            ("main", true),
            ("child", true),
            ("popup", false),
            ("popup-child", false),
        ] {
            assert_eq!(
                selected_entry(
                    &index,
                    &registry.owned_target(target).unwrap(),
                    "main-session"
                ),
                Ok(included)
            );
        }
    }
    #[test]
    fn query_partition_unknown_parent_cycle_reparent_and_retired_root_refuse() {
        for change in [
            "unknown",
            "cycle",
            "wrong-root",
            "retired",
            "session-mismatch",
            "samepage-unready",
        ] {
            let (mut index, registry) = fixture();
            match change {
                "unknown" => {
                    index.sessions.get_mut("child-session").unwrap().parent = Some("unknown".into())
                }
                "cycle" => {
                    index.sessions.get_mut("child-session").unwrap().parent =
                        Some("child-session".into())
                }
                "wrong-root" => {
                    index.sessions.get_mut("child-session").unwrap().root = "popup-session".into()
                }
                "retired" => {
                    index.retired_page_sessions.insert("main-session".into());
                }
                "session-mismatch" => {
                    index.sessions.get_mut("child-session").unwrap().target = "other".into()
                }
                _ => index.sessions.get_mut("child-session").unwrap().resumed = false,
            }
            assert!(
                selected_entry(
                    &index,
                    &registry.owned_target("child").unwrap(),
                    "main-session"
                )
                .is_err(),
                "{change}"
            );
        }
    }
    #[test]
    fn query_partition_auxiliary_requires_exact_self_root_no_parent_and_ready() {
        for invalid in ["parent", "root", "application", "resumed"] {
            let (mut index, registry) = fixture();
            let entry = index.sessions.get_mut("popup-session").unwrap();
            entry.kind = "browser_ui".into();
            match invalid {
                "parent" => entry.parent = Some("main-session".into()),
                "root" => entry.root = "main-session".into(),
                "application" => entry.application = false,
                _ => entry.resumed = false,
            }
            let mut target = registry.owned_target("popup").unwrap();
            target.kind = "browser_ui".into();
            assert!(
                selected_entry(&index, &target, "main-session").is_err(),
                "{invalid}"
            );
        }
    }
    #[test]
    fn query_partition_never_uses_opener_as_iframe_ancestry() {
        let (mut index, registry) = fixture();
        // A page root cannot be converted to a child by merely supplying its opener.
        index.sessions.get_mut("popup-session").unwrap().parent = Some("main-session".into());
        assert!(selected_entry(
            &index,
            &registry.owned_target("popup").unwrap(),
            "main-session"
        )
        .is_err());
    }
}

#[cfg(test)]
mod retained_peer_tests {
    use super::*;
    /// Real framed Runtime.enable ACK is held by the existing enrollment peer.
    /// Exercises production custody/partition/barrier and actual CDP frame
    /// acquisition, not the full semantic/geometry browser.query result.
    #[tokio::test]
    async fn selected_page_proof_overlaps_retained_popup_ack_without_forgiving_failure() {
        for fail in [false, true] {
            let (owner, _notices, log, emit, server, _broker, connection) =
                super::super::tests::fixture_with_explicit_context_ownership(
                    "owner-retirement-runtime-held-query",
                    true,
                    true,
                )
                .await;
            owner
                .enroll_existing("initial-target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            owner.start(&owner.operation()).await.unwrap();
            owner
                .client
                .debt_ledger()
                .unwrap()
                .publish_initialization(|| Ok(()))
                .unwrap();
            let initial = owner.index.lock().unwrap().sessions["initial"].clone();
            let page = owner.lease(&initial).unwrap();
            let selected = owner.targets.owned_target("initial-target").unwrap();
            let authority = owner.page_query_authority(&page, &selected).unwrap();
            let gate = CaptureTestGate::new();
            owner
                .capture_test_gates
                .lock()
                .unwrap()
                .insert(CaptureTestPoint::BeforeAttachedProcessing, gate.clone());
            let mut op = owner.operation();
            op.sequence = 2;
            let original_deadline = op.deadline;
            emit.send(json!({"method":"Target.attachedToTarget","params":{
                "sessionId":"popup-session","waitingForDebugger":true,"targetInfo":{
                "targetId":"popup-target","type":"page","browserContextId":"owned-context","openerId":"initial-target"}}})).await.unwrap();
            gate.wait_entered().await;
            let classification = authority.wait_classified(&page, &op);
            tokio::pin!(classification);
            assert!(
                tokio::time::timeout(Duration::from_millis(10), &mut classification)
                    .await
                    .is_err()
            );
            gate.release.add_permits(1);
            tokio::time::timeout(Duration::from_secs(2), &mut classification)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(op.deadline, original_deadline);
            let held = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(request) = log
                        .lock()
                        .unwrap()
                        .iter()
                        .find(|request| {
                            request["sessionId"] == "popup-session"
                                && request["method"] == "Runtime.enable"
                        })
                        .cloned()
                    {
                        break request;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let debt = owner.client.debt_ledger().unwrap();
            let outstanding = debt.snapshot().outstanding_commands;
            let proof = authority.acquire(&page, &op).unwrap();
            assert_eq!(proof.targets().len(), 1);
            let mut guard = Some(proof.begin_read(&page, &op).unwrap());
            guard.as_ref().unwrap().check(&page, &op).unwrap();
            let before = log.lock().unwrap().len();
            let journal = debt
                .operation(
                    crate::native::client_debt::OperationKey {
                        generation: op.generation,
                        operation_seq: op.sequence,
                    },
                    page.target_id.clone(),
                    page.page_session_id.clone(),
                )
                .unwrap();
            journal.bind_operation(&op).unwrap();
            let frames = journal
                .scope(
                    crate::native::client_observation_dispatch::selected_query_frames_for_test(
                        &page, &op, &proof,
                    ),
                )
                .await
                .unwrap();
            journal.finish_local_producers();
            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0].binding.session, "initial");
            assert!(log.lock().unwrap()[before..]
                .iter()
                .all(|request| request["sessionId"] != "popup-session"));
            drop(journal);
            assert!(owner.targets.inventory().is_err());
            assert!(
                !owner
                    .targets
                    .owned_target("popup-target")
                    .unwrap()
                    .configured
            );
            assert!(outstanding >= 1);
            assert!(debt.snapshot().outstanding_commands >= outstanding);
            // No pending command is declared settled by the page partition.
            if !fail {
                drop(guard.take());
            }
            let response = if fail {
                json!({"id":held["id"],"sessionId":"popup-session","error":{"code":-32000,"message":"controlled initializer error"}})
            } else {
                json!({"id":held["id"],"sessionId":"popup-session","result":{}})
            };
            emit.send(response).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if owner.index.lock().unwrap().pending_enrollment.is_empty() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let checked = proof.check(&page, &op);
            let error = owner.index.lock().unwrap().failure.clone();
            drop(guard.take());
            let _ = owner.close().await;
            connection.close().await;
            server.abort();
            let _ = server.await;
            if fail {
                assert_eq!(checked, Err(ProtocolError::BrowserFailure));
                assert_eq!(error, Some(ProtocolError::BrowserFailure));
            } else {
                assert_eq!(checked, Ok(()));
                assert_eq!(error, None);
            }
        }
    }
    /// Real framed Runtime.enable ACK is held by the existing enrollment peer.
    /// Exercises the production protected-query dispatcher, admission, selector,
    /// geometry, restoration and reference publication against modeled CDP.
    /// This is not real Chromium or the outer native wire decoder.
    #[tokio::test]
    async fn protected_query_dispatch_publishes_selected_ref_while_popup_ack_is_pending() {
        for fail in [false, true] {
            let (owner, _notices, log, emit, server, _broker, connection) =
                super::super::tests::fixture_with_explicit_context_ownership(
                    "owner-retirement-runtime-held-dispatch",
                    true,
                    true,
                )
                .await;
            owner
                .enroll_existing("initial-target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            owner.start(&owner.operation()).await.unwrap();
            owner
                .client
                .debt_ledger()
                .unwrap()
                .publish_initialization(|| Ok(()))
                .unwrap();
            // Actual framed auto-attachment and initialization of the auxiliary
            // kinds present in ordinary Chromium. They are not page renderers.
            for kind in ["browser_ui", "tab", "browser"] {
                let session = format!("aux-{kind}-session");
                let target = format!("aux-{kind}-target");
                emit.send(json!({"method":"Target.attachedToTarget","params":{
                    "sessionId":session,"waitingForDebugger":true,"targetInfo":{
                    "targetId":target,"type":kind,"browserContextId":"owned-context"}}}))
                    .await
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        if owner
                            .targets
                            .owned_target(&target)
                            .is_ok_and(|t| t.configured && t.resumed)
                            && owner.index.lock().unwrap().pending_enrollment.is_empty()
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                let index = owner.index.lock().unwrap();
                let entry = &index.sessions[&session];
                assert_eq!(entry.root, session);
                assert!(entry.parent.is_none());
            }
            let initial = owner.index.lock().unwrap().sessions["initial"].clone();
            let page = owner.lease(&initial).unwrap();
            let selected = owner.targets.owned_target("initial-target").unwrap();
            let authority = owner.page_query_authority(&page, &selected).unwrap();
            let gate = CaptureTestGate::new();
            owner
                .capture_test_gates
                .lock()
                .unwrap()
                .insert(CaptureTestPoint::BeforeAttachedProcessing, gate.clone());
            let mut op = owner.operation();
            op.sequence = 2;
            let original_deadline = op.deadline;
            emit.send(json!({"method":"Target.attachedToTarget","params":{
                "sessionId":"popup-session","waitingForDebugger":true,"targetInfo":{
                "targetId":"popup-target","type":"page","browserContextId":"owned-context","openerId":"initial-target"}}})).await.unwrap();
            gate.wait_entered().await;
            let classification = authority.wait_classified(&page, &op);
            tokio::pin!(classification);
            assert!(
                tokio::time::timeout(Duration::from_millis(10), &mut classification)
                    .await
                    .is_err()
            );
            gate.release.add_permits(1);
            tokio::time::timeout(Duration::from_secs(2), &mut classification)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(op.deadline, original_deadline);
            let held = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(request) = log
                        .lock()
                        .unwrap()
                        .iter()
                        .find(|request| {
                            request["sessionId"] == "popup-session"
                                && request["method"] == "Runtime.enable"
                        })
                        .cloned()
                    {
                        break request;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let debt = owner.client.debt_ledger().unwrap();
            let outstanding = debt.snapshot().outstanding_commands;
            let proof = authority.acquire(&page, &op).unwrap();
            assert_eq!(proof.targets().len(), 1);
            assert_eq!(
                debt.check_admission(crate::native::client_debt::AdmissionClass::Reference),
                Ok(())
            );
            let before = log.lock().unwrap().len();
            let journal = debt
                .operation(
                    crate::native::client_debt::OperationKey {
                        generation: op.generation,
                        operation_seq: op.sequence,
                    },
                    page.target_id.clone(),
                    page.page_session_id.clone(),
                )
                .unwrap();
            journal.bind_operation(&op).unwrap();
            use crate::native::client_blobs::{BlobScope, BlobStore};
            use crate::native::client_observation_dispatch::{
                DispatchContext, DispatchRequest, ObservationDispatch, QueryPurpose, QueryRequest,
                ReadPolicy,
            };
            use crate::native::element::RefMap;
            let blobs = Arc::new(BlobStore::new(Default::default()).unwrap());
            let scope = BlobScope {
                generation: op.generation,
                identity_scope: page.identity_scope.clone(),
            };
            blobs.activate_scope(scope.clone()).unwrap();
            let ui = owner.network.ui_gate_for_test();
            assert!(owner.network.uses_ui_gate(&ui));
            for scoped in [false, true] {
                let refs = Arc::new(std::sync::Mutex::new(RefMap::new()));
                let dispatch = ObservationDispatch::new(refs.clone());
                let query_page = owner.lease(&initial).unwrap();
                let prepared = dispatch.prepare(DispatchContext {
                query_authority: scoped.then(|| authority.clone()),
                #[cfg(feature="acceptance-faults")]
                faults: Arc::new(crate::native::client_test_faults::FaultController::default()),
                attachment: selected.clone(), page: query_page, ui: ui.clone(), blobs: blobs.clone(), scope: scope.clone(),
                policy: ReadPolicy { frame_policy: Default::default(), test_id_attribute: "data-testid".into(), secure_field_selector: "input[type=password]".into() },
            }, DispatchRequest::Query(QueryRequest {
                purpose: QueryPurpose::Protected,
                options: serde_json::from_value(json!({"expression":{"kind":"selector","selector":"#selected"},"secureFieldSelector":"input[type=password]"})).unwrap(),
            }), OperationLease { is_callback: op.is_callback, generation: op.generation, sequence: op.sequence, deadline: op.deadline, cancellation: op.cancellation.clone() }).unwrap();
                let task = journal
                    .scope(async { dispatch.start_prepared(prepared) })
                    .await;
                let mut result_receiver = task.result;
                let received =
                    tokio::time::timeout(Duration::from_secs(2), &mut result_receiver).await;
                if received.is_err() {
                    // Release the real held ACK and retain/join the task before failing.
                    // This is a test observation bound, not a renewed operation budget.
                    emit.send(json!({"id":held["id"],"sessionId":"popup-session","result":{}}))
                        .await
                        .unwrap();
                    let completion = tokio::time::timeout(Duration::from_secs(3), task.join).await;
                    let _ = owner.close().await;
                    connection.close().await;
                    server.abort();
                    let _ = server.await;
                    panic!("query waited for unrelated initializer; scoped={scoped}; cleanup={completion:?}");
                }
                let result = received.unwrap().unwrap();
                task.join.await.unwrap().unwrap();
                if !scoped {
                    let failure =
                        result.expect_err("strict global inventory must reject held popup");
                    assert_eq!(failure.error, ProtocolError::ScopeUnavailable);
                    assert!(!failure.cleanup_integrity_lost);
                    assert!(refs.lock().unwrap().ref_ids().is_empty());
                    assert!(owner.index.lock().unwrap().failure.is_none());
                    assert!(!owner.index.lock().unwrap().pending_enrollment.is_empty());
                    continue;
                }
                let result = result.unwrap();
                assert_eq!(result["nodes"].as_array().unwrap().len(), 1);
                assert_eq!(
                    result["nodes"][0]["rect"],
                    json!({"x":10.0,"y":20.0,"width":20.0,"height":20.0})
                );
                let id = result["nodes"][0]["ref"]["id"].as_str().unwrap();
                assert_eq!(
                    refs.lock()
                        .unwrap()
                        .get(id.trim_start_matches('@'))
                        .unwrap()
                        .backend_node_id,
                    Some(7)
                );
                assert!(refs
                    .lock()
                    .unwrap()
                    .get(id.trim_start_matches('@'))
                    .unwrap()
                    .matches_scope(&page.identity_scope, op.generation, "initial"));
                assert_eq!(
                    refs.lock()
                        .unwrap()
                        .get(id.trim_start_matches('@'))
                        .unwrap()
                        .exact_binding
                        .as_ref()
                        .unwrap()
                        .session,
                    "initial"
                );
                assert_eq!(op.deadline, original_deadline);
            }
            journal.finish_local_producers();
            let commands = log.lock().unwrap()[before..].to_vec();
            assert!(commands
                .iter()
                .any(|r| r["method"] == "Runtime.callFunctionOn"
                    && r["params"]["functionDeclaration"]
                        .as_str()
                        .is_some_and(|d| d.starts_with("function(expression"))));
            assert!(commands.iter().any(|r| r["method"] == "DOM.getBoxModel"));
            assert!(commands.iter().all(|r| r["sessionId"] != "popup-session"));
            assert!(!owner.index.lock().unwrap().pending_enrollment.is_empty());
            drop(journal);
            assert!(owner.targets.inventory().is_err());
            assert!(
                !owner
                    .targets
                    .owned_target("popup-target")
                    .unwrap()
                    .configured
            );
            assert!(outstanding >= 1);
            assert!(debt.snapshot().outstanding_commands >= outstanding);
            // No pending command is declared settled by the page partition.
            let response = if fail {
                json!({"id":held["id"],"sessionId":"popup-session","error":{"code":-32000,"message":"controlled initializer error"}})
            } else {
                json!({"id":held["id"],"sessionId":"popup-session","result":{}})
            };
            emit.send(response).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if owner.index.lock().unwrap().pending_enrollment.is_empty() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let checked = proof.check(&page, &op);
            let error = owner.index.lock().unwrap().failure.clone();
            let _ = owner.close().await;
            connection.close().await;
            server.abort();
            let _ = server.await;
            if fail {
                assert_eq!(checked, Err(ProtocolError::BrowserFailure));
                assert_eq!(error, Some(ProtocolError::BrowserFailure));
            } else {
                assert_eq!(checked, Ok(()));
                assert_eq!(error, None);
            }
        }
    }
    #[tokio::test]
    async fn query_classification_wait_keeps_original_cancel_and_deadline_without_owner_poison() {
        for cancel in [false, true] {
            let (owner, _notices, _log, emit, server, _broker, connection) =
                super::super::tests::fixture_with_explicit_context_ownership(
                    "owner-retirement",
                    true,
                    true,
                )
                .await;
            owner
                .enroll_existing("initial-target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            owner.start(&owner.operation()).await.unwrap();
            let initial = owner.index.lock().unwrap().sessions["initial"].clone();
            let page = owner.lease(&initial).unwrap();
            let authority = owner
                .page_query_authority(
                    &page,
                    &owner.targets.owned_target("initial-target").unwrap(),
                )
                .unwrap();
            let gate = CaptureTestGate::new();
            owner
                .capture_test_gates
                .lock()
                .unwrap()
                .insert(CaptureTestPoint::BeforeAttachedProcessing, gate.clone());
            emit.send(json!({"method":"Target.attachedToTarget","params":{
                "sessionId":"popup-session","waitingForDebugger":true,"targetInfo":{
                "targetId":"popup-target","type":"page","browserContextId":"owned-context","openerId":"initial-target"}}})).await.unwrap();
            gate.wait_entered().await;
            let (sender, cancellation) = watch::channel(CancelSignal::None);
            let op = OperationLease {
                is_callback: false,
                generation: owner.generation,
                sequence: 2,
                deadline: Instant::now() + Duration::from_millis(30),
                cancellation,
            };
            if cancel {
                sender.send_replace(CancelSignal::Requested);
            }
            let result = authority.wait_classified(&page, &op).await;
            assert_eq!(
                result,
                Err(if cancel {
                    ProtocolError::Cancelled
                } else {
                    ProtocolError::DeadlineExceeded
                })
            );
            assert!(owner.index.lock().unwrap().failure.is_none());
            assert!(owner
                .targets
                .operation_settlement_integrity_diagnostic(false)
                .0
                .is_ok());
            gate.release();
            tokio::time::timeout(Duration::from_secs(2), async {
                while !owner.index.lock().unwrap().pending_enrollment.is_empty() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let _ = owner.close().await;
            connection.close().await;
            server.abort();
            let _ = server.await;
        }
    }
    #[tokio::test]
    async fn query_watermark_same_count_replacement_cannot_rebind_proof_or_wait() {
        for waiting in [false, true] {
            let (owner, _notices, _log, emit, server, _broker, connection) =
                super::super::tests::fixture_with_explicit_context_ownership(
                    "owner-retirement",
                    true,
                    true,
                )
                .await;
            owner
                .enroll_existing("initial-target", "initial", "page", &owner.operation())
                .await
                .unwrap();
            owner.start(&owner.operation()).await.unwrap();
            let initial = owner.index.lock().unwrap().sessions["initial"].clone();
            let page = owner.lease(&initial).unwrap();
            let authority = owner
                .page_query_authority(
                    &page,
                    &owner.targets.owned_target("initial-target").unwrap(),
                )
                .unwrap();
            let op = owner.operation();
            let original = owner.realm_watermark().unwrap();
            let replacement = owner
                .client
                .subscribe_bounded_methods(EVENTS, 256, 128 * 1024 * 1024)
                .unwrap();
            let replacement_watermark = replacement.watermark();
            assert!(!original.same_subscription(&replacement_watermark));
            if waiting {
                let gate = CaptureTestGate::new();
                owner
                    .capture_test_gates
                    .lock()
                    .unwrap()
                    .insert(CaptureTestPoint::BeforeAttachedProcessing, gate.clone());
                emit.send(json!({"method":"Target.attachedToTarget","params":{
                    "sessionId":"popup-session","waitingForDebugger":true,"targetInfo":{
                    "targetId":"popup-target","type":"page","browserContextId":"owned-context","openerId":"initial-target"}}})).await.unwrap();
                gate.wait_entered().await;
                let classification = authority.wait_classified(&page, &op);
                tokio::pin!(classification);
                assert!(matches!(
                    futures_util::poll!(&mut classification),
                    std::task::Poll::Pending
                ));
                assert_eq!(
                    original.received().unwrap(),
                    replacement_watermark.received().unwrap()
                );
                *owner.event_watermark.lock().unwrap() = Some(replacement_watermark.clone());
                owner.changed.notify_waiters();
                assert_eq!(classification.await, Err(ProtocolError::StaleScope));
                *owner.event_watermark.lock().unwrap() = Some(original.clone());
                gate.release();
                tokio::time::timeout(Duration::from_secs(2), async {
                    while !owner.index.lock().unwrap().pending_enrollment.is_empty() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
            } else {
                let proof = authority.acquire(&page, &op).unwrap();
                assert_eq!(
                    original.received().unwrap(),
                    replacement_watermark.received().unwrap()
                );
                *owner.event_watermark.lock().unwrap() = Some(replacement_watermark.clone());
                let committed = AtomicBool::new(false);
                assert_eq!(
                    proof.with_publication(&page, &op, || {
                        committed.store(true, Ordering::SeqCst);
                        Ok(())
                    }),
                    Err(ProtocolError::StaleScope)
                );
                assert!(!committed.load(Ordering::SeqCst));
                *owner.event_watermark.lock().unwrap() = Some(original.clone());
                proof.check(&page, &op).unwrap();
            }
            assert!(owner.index.lock().unwrap().failure.is_none());
            drop(replacement);
            let _ = owner.close().await;
            connection.close().await;
            server.abort();
            let _ = server.await;
        }
    }
}
