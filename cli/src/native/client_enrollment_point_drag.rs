//! Passive point-drag observation authority, borrowed from existing enrollment.
//! No selector, DOM query, frame-tree discovery, geometry, or input authority.
use super::super::element::ExactBinding;
use super::*;

/// This token is not cleanup authority. Observer object groups and ExactRealmTicket
/// values must remain in the caller's retained input transaction until released.
pub(crate) struct PointDragRealms {
    owner: Arc<ClientEnrollment>,
    operation: OperationLease,
    target: String,
    session: String,
    snapshot: PointDragSnapshot,
    attachments: Vec<OwnedTarget>,
}

#[derive(PartialEq, Eq)]
struct PointDragSnapshot {
    // The existing monotonic epoch also rejects detach/reinsert ABA. This is
    // deliberately conservative for unrelated application navigation; it never
    // grants authority from a coincidentally equal final frame inventory.
    epoch: u64,
    entries: Vec<Attribution>,
    bindings: Vec<ExactBinding>,
    parents: Vec<Option<String>>,
}

fn point_drag_snapshot(
    index: &Index,
    page_session: &str,
    page_target: &str,
) -> Result<PointDragSnapshot, ProtocolError> {
    let root = index
        .sessions
        .get(page_session)
        .ok_or(ProtocolError::StaleScope)?;
    if root.target != page_target || root.kind != "page" || root.root != page_session {
        return Err(ProtocolError::StaleScope);
    }
    let mut entries: Vec<_> = index
        .sessions
        .values()
        .filter(|entry| {
            entry.root == page_session && matches!(entry.kind.as_str(), "page" | "iframe")
        })
        .cloned()
        .collect();
    entries.sort_by(|a, b| a.session.cmp(&b.session));
    if entries.is_empty()
        || entries
            .iter()
            .any(|entry| !entry.application || entry.observation_only || !entry.resumed)
    {
        return Err(ProtocolError::StaleScope);
    }
    let mut records = Vec::new();
    for (id, frame) in &index.frames {
        if !entries.iter().any(|entry| entry.session == frame.session) {
            continue;
        }
        if records.len() >= MAX_REALM_HOLDS {
            return Err(ProtocolError::CapacityExceeded);
        }
        // An empty loader is valid for an already enrolled initial about:blank;
        // missing loader evidence is not converted into a made-up document ID.
        let loader = frame.loader.clone().ok_or(ProtocolError::StaleReference)?;
        records.push((
            ExactBinding {
                page_session: page_session.to_owned(),
                session: frame.session.clone(),
                frame: id.clone(),
                loader,
                actionable: false,
            },
            frame.parent.clone(),
        ));
    }
    records.sort_by(|a, b| (&a.0.session, &a.0.frame).cmp(&(&b.0.session, &b.0.frame)));
    if entries.iter().any(|entry| {
        !records
            .iter()
            .any(|(binding, _)| binding.session == entry.session)
    }) {
        return Err(ProtocolError::StaleReference);
    }
    let (bindings, parents) = records.into_iter().unzip();
    Ok(PointDragSnapshot {
        epoch: index.application_epoch,
        entries,
        bindings,
        parents,
    })
}

impl ClientEnrollment {
    fn check_point_drag_page(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.check_restart_operation(op)?;
        page.permit.check()?;
        if !Arc::ptr_eq(&page.client, &self.client)
            || !Arc::ptr_eq(&page.targets, &self.targets)
            || page.identity_scope != self.targets.identity_scope
            || *self.client.remote_connection_closed().borrow()
            || *self
                .active_root
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?
                != page.page_session_id
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }

    /// Synchronous snapshot of already enrolled page-owned frame identities.
    /// Caller holds the original direct-point UI/input guards. This does not
    /// start enrollment, refresh DOM inventory, or create any remote resource.
    pub(crate) fn capture_point_drag_realms(
        self: &Arc<Self>,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<PointDragRealms, ProtocolError> {
        self.check_point_drag_page(page, op)?;
        let watermark = self.realm_watermark()?;
        let index = self
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        self.realm_snapshot_healthy(&index, &watermark)?;
        let snapshot = point_drag_snapshot(&index, &page.page_session_id, &page.target_id)?;
        let mut attachments = Vec::with_capacity(snapshot.entries.len());
        for entry in &snapshot.entries {
            let attachment = self.targets.owned_target(&entry.target)?;
            if attachment.session_id != entry.session
                || attachment.kind != entry.kind
                || !attachment.capture_ready()
            {
                return Err(ProtocolError::StaleScope);
            }
            attachments.push(attachment);
        }
        Ok(PointDragRealms {
            owner: self.clone(),
            operation: copy_operation(op),
            target: page.target_id.clone(),
            session: page.page_session_id.clone(),
            snapshot,
            attachments,
        })
    }
}

impl PointDragRealms {
    /// Native-only identities for reserve_exact_realm + the existing isolated
    /// world constructor. Never selector/actionable-element authority.
    pub(crate) fn bindings(&self) -> &[ExactBinding] {
        &self.snapshot.bindings
    }

    /// Retained cleanup observation only: no new operation, realm, or input grant.
    /// The caller supplies the original cleanup deadline and every already-held
    /// ticket; cancellation of the original action does not erase that custody.
    pub(crate) async fn verify_cleanup(
        &self,
        client: &CdpClient,
        session: &str,
        deadline: Instant,
        exact_tickets: &[Arc<ExactRealmTicket>],
    ) -> Result<(), ProtocolError> {
        let check_identity = || -> Result<(), ProtocolError> {
            self.owner.check()?;
            if Instant::now() >= deadline
                || !std::ptr::eq(self.owner.client.as_ref(), client)
                || session != self.session
                || self.owner.generation != self.operation.generation
                || *client.remote_connection_closed().borrow()
                || *self
                    .owner
                    .active_root
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?
                    != self.session
            {
                return Err(ProtocolError::CleanupFailed);
            }
            let ledger = client
                .debt_ledger()
                .ok_or(ProtocolError::ScopeUnavailable)?;
            let journal = super::super::client_debt::OperationJournalHandle::current()
                .ok_or(ProtocolError::ScopeUnavailable)?;
            if !journal.matches_protected_read(
                &ledger,
                &self.owner.targets.identity_scope,
                &self.target,
                &self.session,
                &self.operation,
            ) {
                return Err(ProtocolError::StaleScope);
            }
            Ok(())
        };
        check_identity()?;
        let watermark = self.owner.realm_watermark()?;
        // Reconcile only the existing subscribed lifecycle stream. This loop
        // never discovers frames or constructs an uncancelled application lease.
        tokio::time::timeout_at(deadline.into(), async {
            loop {
                let changed = self.owner.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                check_identity()?;
                {
                    let index = self
                        .owner
                        .index
                        .lock()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?;
                    let received = watermark
                        .received()
                        .map_err(|_| ProtocolError::ScopeUnavailable)?;
                    if capture_admission_ready(&index, received) {
                        break;
                    }
                }
                changed.await;
            }
            Ok::<(), ProtocolError>(())
        })
        .await
        .map_err(|_| ProtocolError::CleanupFailed)??;
        check_identity()?;
        let index = self
            .owner
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        self.owner.realm_snapshot_healthy(&index, &watermark)?;
        if !capture_admission_ready(
            &index,
            watermark
                .received()
                .map_err(|_| ProtocolError::ScopeUnavailable)?,
        ) || point_drag_snapshot(&index, &self.session, &self.target)? != self.snapshot
            || exact_tickets.len() != self.snapshot.bindings.len()
        {
            return Err(ProtocolError::StaleReference);
        }
        for binding in &self.snapshot.bindings {
            let mut matched = exact_tickets
                .iter()
                .filter(|ticket| ticket.binding == *binding);
            let ticket = matched.next().ok_or(ProtocolError::StaleReference)?;
            if matched.next().is_some()
                || !Arc::ptr_eq(&ticket.owner, &self.owner)
                || ticket.fact.destroyed.load(Ordering::SeqCst)
                || index.realm_sessions.get(&ticket.fact.session) != Some(&ticket.fact.tenure)
                || !index
                    .realms
                    .get(&(ticket.fact.session.clone(), ticket.fact.id))
                    .is_some_and(|fact| Arc::ptr_eq(fact, &ticket.fact))
            {
                return Err(ProtocolError::StaleReference);
            }
        }
        for captured in &self.attachments {
            if !captured.same_attachment(&self.owner.targets.owned_target(&captured.target_id)?) {
                return Err(ProtocolError::StaleScope);
            }
        }
        Ok(())
    }

    /// Invoke before installing observers and after their receipts, before any
    /// negative/no-drag decision. Each ExactRealmTicket must ALSO be verified:
    /// equal frame identities alone do not prove that an observer realm survived.
    pub(crate) async fn verify(
        &self,
        page: &BrowserExecutionLease,
        op: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.owner.check_restart_operation(op)?;
        if op.is_callback != self.operation.is_callback
            || op.generation != self.operation.generation
            || op.sequence != self.operation.sequence
            || op.deadline != self.operation.deadline
            || !op.cancellation.same_channel(&self.operation.cancellation)
        {
            return Err(ProtocolError::StaleScope);
        }
        self.owner.check_point_drag_page(page, op)?;
        if page.target_id != self.target || page.page_session_id != self.session {
            return Err(ProtocolError::StaleScope);
        }
        let watermark = self.owner.realm_watermark()?;
        self.owner.drain_capture_watermark(&watermark, op).await?;
        self.owner.check_point_drag_page(page, op)?;
        let index = self
            .owner
            .index
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        self.owner.realm_snapshot_healthy(&index, &watermark)?;
        if point_drag_snapshot(&index, &self.session, &self.target)? != self.snapshot {
            return Err(ProtocolError::StaleReference);
        }
        for captured in &self.attachments {
            if !captured.same_attachment(&self.owner.targets.owned_target(&captured.target_id)?) {
                return Err(ProtocolError::StaleScope);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn enrolled() -> Index {
        let mut index = Index::default();
        for (session, target, kind, root) in [
            ("main", "page", "page", "main"),
            ("child", "oopif", "iframe", "main"),
            ("foreign", "popup", "page", "foreign"),
        ] {
            index.sessions.insert(
                session.into(),
                Attribution {
                    target: target.into(),
                    session: session.into(),
                    parent: None,
                    root: root.into(),
                    kind: kind.into(),
                    application: true,
                    observation_only: false,
                    observer_paused: None,
                    init_paused_by_attachment: false,
                    resumed: true,
                },
            );
            index.frames.insert(
                target.into(),
                FrameOwner {
                    loader: Some("loader".into()),
                    name: None,
                    session: session.into(),
                    parent: None,
                },
            );
        }
        index.frames.insert(
            "same-process".into(),
            FrameOwner {
                loader: Some("child-loader".into()),
                name: None,
                session: "main".into(),
                parent: Some("page".into()),
            },
        );
        index
    }
    #[test]
    fn snapshot_includes_same_process_and_oopif_but_not_popup() {
        let snapshot = point_drag_snapshot(&enrolled(), "main", "page").unwrap();
        assert_eq!(snapshot.bindings.len(), 3);
        assert!(snapshot
            .bindings
            .iter()
            .all(|b| b.page_session == "main" && !b.actionable && b.session != "foreign"));
    }
    #[test]
    fn snapshot_changes_for_added_removed_parent_and_loader_frames() {
        let original = point_drag_snapshot(&enrolled(), "main", "page").unwrap();
        let mut index = enrolled();
        index.frames.get_mut("same-process").unwrap().parent = None;
        assert!(point_drag_snapshot(&index, "main", "page").unwrap() != original);
        index = enrolled();
        index.frames.get_mut("same-process").unwrap().loader = Some("replacement".into());
        assert!(point_drag_snapshot(&index, "main", "page").unwrap() != original);
        index = enrolled();
        index.frames.remove("same-process");
        assert!(point_drag_snapshot(&index, "main", "page").unwrap() != original);
        index = enrolled();
        index.frames.insert(
            "new-frame".into(),
            FrameOwner {
                loader: Some("new-loader".into()),
                name: None,
                session: "main".into(),
                parent: Some("page".into()),
            },
        );
        assert!(point_drag_snapshot(&index, "main", "page").unwrap() != original);
        index = enrolled();
        index.application_epoch += 1;
        assert!(point_drag_snapshot(&index, "main", "page").unwrap() != original);
    }
    #[test]
    fn incomplete_or_unready_ownership_is_not_empty_success() {
        let mut index = enrolled();
        index.frames.get_mut("oopif").unwrap().loader = None;
        assert!(point_drag_snapshot(&index, "main", "page").is_err());
        index = enrolled();
        index.sessions.get_mut("child").unwrap().resumed = false;
        assert!(point_drag_snapshot(&index, "main", "page").is_err());
        index = enrolled();
        index.sessions.get_mut("child").unwrap().observation_only = true;
        assert!(point_drag_snapshot(&index, "main", "page").is_err());
        index = enrolled();
        index.frames.remove("oopif");
        assert!(point_drag_snapshot(&index, "main", "page").is_err());
    }
    #[test]
    fn unrelated_application_epoch_conservatively_rejects_equal_selected_bindings() {
        let mut index = enrolled();
        let before = point_drag_snapshot(&index, "main", "page").unwrap();
        // Existing enrollment increments one application-wide epoch for the
        // unrelated popup navigation, although the selected page is unchanged.
        index.frames.get_mut("popup").unwrap().loader = Some("popup-next-document".into());
        index.application_epoch += 1;
        let after = point_drag_snapshot(&index, "main", "page").unwrap();
        assert!(before.bindings == after.bindings);
        assert!(before.entries == after.entries);
        assert!(before.parents == after.parents);
        assert!(
            before != after,
            "conservative rejection, not selected-page staleness proof"
        );
    }

    #[test]
    fn frame_cap_is_bounded_before_remote_resources() {
        let mut index = enrolled();
        for i in 0..MAX_REALM_HOLDS {
            index.frames.insert(
                format!("extra-{i}"),
                FrameOwner {
                    loader: Some("loader".into()),
                    name: None,
                    session: "main".into(),
                    parent: Some("page".into()),
                },
            );
        }
        assert!(matches!(
            point_drag_snapshot(&index, "main", "page"),
            Err(ProtocolError::CapacityExceeded)
        ));
    }
}
