//! Query-only target partition. Global capture/retirement inventory stays strict.
use super::*;

/// Native enrollment ancestry, immutable for this exact attachment tenure.
/// Page roots use a marker rather than an Arc back to themselves.
#[derive(Clone, Debug, Default)]
pub(super) enum AttachmentLineage {
    #[default]
    Unknown,
    PageRoot,
    DocumentRoot(OwnedTarget),
    IndependentWorker,
}
impl AttachmentLineage {
    pub(super) fn enrolled(kind: &str, root: Option<&OwnedTarget>) -> Result<Self, ProtocolError> {
        match (kind, root) {
            ("page", None) => Ok(Self::PageRoot),
            ("iframe", Some(root)) => Ok(Self::DocumentRoot(root.clone())),
            ("worker" | "shared_worker" | "service_worker", Some(root)) => {
                Ok(Self::DocumentRoot(root.clone()))
            }
            ("worker" | "shared_worker" | "service_worker", None) => Ok(Self::IndependentWorker),
            // Existing target enrollment policy is unchanged. Missing ancestry
            // remains Unknown and cannot bypass a selected query exclusion.
            _ => Ok(Self::Unknown),
        }
    }
}
pub(super) enum ProtectedExclusion {
    Global { token: Arc<()> },
    Selected { token: Arc<()>, root: OwnedTarget },
}
impl ProtectedExclusion {
    pub(super) fn matches_token(&self, expected: &Arc<()>) -> bool {
        let token = match self {
            Self::Global { token } | Self::Selected { token, .. } => token,
        };
        Arc::ptr_eq(token, expected)
    }
    pub(super) fn excludes_iframe(&self, child: &OwnedTarget, root: &OwnedTarget) -> bool {
        !child.query_lineage_matches(Some(root)) || self.excludes_tenure(&child.tenure)
    }
    pub(super) fn excludes_queued_iframe(&self, parent: &OwnedTarget, root: &OwnedTarget) -> bool {
        !parent.query_lineage_matches(Some(root))
            || !root.query_lineage_matches(Some(root))
            || self.excludes_tenure(&root.tenure)
    }
    /// Unknown attachment provenance is never permission to bypass exclusion.
    pub(super) fn excludes_tenure(&self, tenure: &Arc<AttachmentTenure>) -> bool {
        let Self::Selected { root, .. } = self else {
            return true;
        };
        if !Arc::ptr_eq(&root.tenure.owner, &tenure.owner) {
            return true;
        }
        match &tenure.lineage {
            AttachmentLineage::Unknown => true,
            AttachmentLineage::PageRoot => Arc::ptr_eq(&root.tenure, tenure),
            AttachmentLineage::DocumentRoot(document) => {
                !Arc::ptr_eq(&root.tenure.owner, &document.tenure.owner)
                    || root.same_initialization_attachment(document)
            }
            AttachmentLineage::IndependentWorker => false,
        }
    }
}
impl Registry {
    pub(super) fn live_resume_excluded(&self, tenure: &Arc<AttachmentTenure>) -> bool {
        let Some(exclusion) = &self.protected_read else {
            return false;
        };
        if exclusion.excludes_tenure(tenure) {
            return true;
        }
        match &tenure.lineage {
            AttachmentLineage::DocumentRoot(root) => !self
                .targets
                .get(&root.target_id)
                .is_some_and(|current| current.same_initialization_attachment(root)),
            AttachmentLineage::Unknown => true,
            _ => false,
        }
    }
}
impl OwnedTarget {
    pub(crate) fn query_lineage_matches(&self, root: Option<&OwnedTarget>) -> bool {
        match (&self.tenure.lineage, root) {
            (AttachmentLineage::PageRoot, Some(root)) => self.same_initialization_attachment(root),
            (AttachmentLineage::DocumentRoot(original), Some(root)) => {
                original.same_initialization_attachment(root)
            }
            (AttachmentLineage::IndependentWorker, None) => matches!(
                self.kind.as_str(),
                "worker" | "shared_worker" | "service_worker"
            ),
            _ => false,
        }
    }
}

#[derive(Clone)]
pub(crate) struct SelectedPageTargetSnapshot {
    pub(crate) targets: Vec<OwnedTarget>,
    revisions: Vec<u64>,
    unknown_revision: u64,
}

/// The existing exclusive resume/creation exclusion, with selected-page proof.
/// It must be checked through the enrollment-owned SelectedPageReadBarrier.
pub(crate) struct SelectedPageTargetBarrier {
    registry: Arc<ClientTargets>,
    token: Arc<()>,
}
impl Drop for SelectedPageTargetBarrier {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.state.lock() {
            if state
                .protected_read
                .as_ref()
                .is_some_and(|exclusion| exclusion.matches_token(&self.token))
            {
                state.protected_read = None;
            }
        }
        self.registry.changed.notify_waiters();
    }
}
impl ClientTargets {
    /// Caller holds enrollment index and reader watermark, in that order.
    /// Classification is authoritative ancestry, never a diagnostic/opener hint.
    pub(crate) fn with_selected_page_targets<T>(
        self: &Arc<Self>,
        selected: &OwnedTarget,
        expected: Option<&SelectedPageTargetSnapshot>,
        held: Option<&SelectedPageTargetBarrier>,
        acquire_barrier: bool,
        classify: impl Fn(&OwnedTarget, &HashMap<String, OwnedTarget>) -> Result<bool, ProtocolError>,
        publish: impl FnOnce(&SelectedPageTargetSnapshot) -> Result<T, ProtocolError>,
    ) -> Result<(T, Option<SelectedPageTargetBarrier>), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed
            || state.integrity_lost
            || !state.enrollment_ready
            || state.reservations != 0
            || state.unknown_bootstrap_create
            || state
                .auxiliary
                .values()
                .any(|entry| !entry.detached && entry.claimed_session.is_none())
            || held.is_some_and(|guard| {
                !Arc::ptr_eq(&guard.registry, self)
                    || !state
                        .protected_read
                        .as_ref()
                        .is_some_and(|exclusion| exclusion.matches_token(&guard.token))
            })
            || (acquire_barrier && (held.is_some() || state.protected_read.is_some()))
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let main = state
            .targets
            .get(&selected.target_id)
            .ok_or(ProtocolError::StaleReference)?;
        if !main.same_attachment(selected) || main.kind != "page" || !main.capture_ready() {
            return Err(ProtocolError::StaleScope);
        }
        let mut targets = Vec::new();
        let relation = ProtectedExclusion::Selected {
            token: Arc::new(()),
            root: selected.clone(),
        };
        for target in state.targets.values() {
            if !Arc::ptr_eq(&target.tenure.owner, &self.attachment_owner)
                || target.purpose.is_none()
                || matches!(&target.tenure.lineage, AttachmentLineage::Unknown)
            {
                return Err(ProtocolError::ScopeUnavailable);
            }
            let relevant = classify(target, &state.targets)?;
            // Workers rooted in this document are not frame renderers, but their
            // in-flight resume must still exclude starting a protected query.
            if relation.excludes_tenure(&target.tenure) && !target.capture_ready() {
                return Err(ProtocolError::ScopeUnavailable);
            }
            if relevant {
                if !target.capture_ready() || !matches!(target.kind.as_str(), "page" | "iframe") {
                    return Err(ProtocolError::ScopeUnavailable);
                }
                targets.push(target.clone());
            } else if !target.capture_ready()
                && !target
                    .tenure
                    .retained_initialization
                    .load(Ordering::Acquire)
            {
                return Err(ProtocolError::ScopeUnavailable);
            }
        }
        targets.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        if !targets
            .iter()
            .any(|target| target.same_attachment(selected))
        {
            return Err(ProtocolError::StaleScope);
        }
        let revisions: Vec<_> = targets
            .iter()
            .map(|target| target.tenure.query_revision.load(Ordering::Acquire))
            .collect();
        if let Some(expected) = expected {
            if revisions != expected.revisions
                || state.query_unknown_revision != expected.unknown_revision
                || targets.len() != expected.targets.len()
                || targets
                    .iter()
                    .zip(&expected.targets)
                    .any(|(a, b)| !a.same_attachment(b))
            {
                return Err(ProtocolError::StaleScope);
            }
        }
        let snapshot = SelectedPageTargetSnapshot {
            targets,
            revisions,
            unknown_revision: state.query_unknown_revision,
        };
        // Commit while index, watermark and registry fences are all retained.
        // The callback must not reenter target methods.
        let value = publish(&snapshot)?;
        // No fallible operation follows setting the flag before guard creation.
        let guard = if acquire_barrier {
            let token = Arc::new(());
            state.protected_read = Some(ProtectedExclusion::Selected {
                token: token.clone(),
                root: selected.clone(),
            });
            Some(SelectedPageTargetBarrier {
                registry: self.clone(),
                token,
            })
        } else {
            None
        };
        drop(state);
        Ok((value, guard))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn ready(registry: &Arc<ClientTargets>, target: &str, session: &str, kind: &str) {
        registry
            .attached_enrolled(
                "ctx",
                target.into(),
                session.into(),
                kind.into(),
                if kind == "iframe" {
                    Some(&registry.owned_target("main").unwrap())
                } else {
                    None
                },
            )
            .unwrap();
        registry.configured(target).unwrap();
        registry
            .resume_permit(target)
            .await
            .unwrap()
            .complete()
            .unwrap();
    }
    async fn fixture() -> (Arc<ClientTargets>, OwnedTarget) {
        let registry = ClientTargets::new("ctx".into(), "scope".into());
        ready(&registry, "main", "main-session", "page").await;
        registry.acknowledge_enrollment().unwrap();
        let main = registry.owned_target("main").unwrap();
        (registry, main)
    }
    fn snapshot(
        registry: &Arc<ClientTargets>,
        main: &OwnedTarget,
        acquire: bool,
    ) -> Result<
        (
            SelectedPageTargetSnapshot,
            Option<SelectedPageTargetBarrier>,
        ),
        ProtocolError,
    > {
        registry.with_selected_page_targets(
            main,
            None,
            None,
            acquire,
            |target, _| Ok(target.target_id == "main"),
            |snapshot| Ok(snapshot.clone()),
        )
    }
    #[tokio::test]
    async fn selected_query_retains_unrelated_initializer_without_ready_or_global_capture() {
        let (registry, main) = fixture().await;
        let mut custody = RetainedInitialization::new(registry.clone());
        custody
            .attach(
                &registry,
                "ctx",
                "popup".into(),
                "popup-session".into(),
                "page".into(),
            )
            .unwrap();
        let (proof, guard) = snapshot(&registry, &main, true).unwrap();
        assert_eq!(proof.targets.len(), 1);
        assert!(!registry.owned_target("popup").unwrap().configured);
        assert!(registry.inventory().is_err());
        assert!(registry.protected_read_barrier().is_err());
        assert!(registry
            .reserve_creation(TargetPurpose::Application)
            .is_err());
        registry
            .with_selected_page_targets(
                &main,
                Some(&proof),
                guard.as_ref(),
                false,
                |target, _| Ok(target.target_id == "main"),
                |_| Ok(()),
            )
            .unwrap();
        drop(guard);
        assert!(registry.state.lock().unwrap().protected_read.is_none());
        drop(custody);
        assert!(snapshot(&registry, &main, false).is_err());
    }
    #[tokio::test]
    async fn selected_query_unrelated_already_resuming_keeps_original_receipt() {
        let (registry, main) = fixture().await;
        let mut custody = RetainedInitialization::new(registry.clone());
        custody
            .attach(
                &registry,
                "ctx",
                "popup".into(),
                "popup-session".into(),
                "page".into(),
            )
            .unwrap();
        registry.configured("popup").unwrap();
        let resume = registry.resume_permit("popup").await.unwrap();
        let (proof, guard) = snapshot(&registry, &main, true).unwrap();
        resume.complete().unwrap();
        custody.finish(false).unwrap();
        registry
            .with_selected_page_targets(
                &main,
                Some(&proof),
                guard.as_ref(),
                false,
                |target, _| Ok(target.target_id == "main"),
                |_| Ok(()),
            )
            .unwrap();
        assert!(registry.owned_target("popup").unwrap().resumed);
        drop(guard);
    }
    #[tokio::test]
    async fn selected_query_refuses_untracked_and_selected_incomplete_targets() {
        let (registry, main) = fixture().await;
        registry
            .attached("ctx", "popup".into(), "popup-session".into(), "page".into())
            .unwrap();
        assert!(snapshot(&registry, &main, false).is_err());
        let (registry, main) = fixture().await;
        let mut custody = RetainedInitialization::new(registry.clone());
        custody
            .attach_with_root(
                &registry,
                "ctx",
                "child".into(),
                "child-session".into(),
                "iframe".into(),
                Some(main.clone()),
            )
            .unwrap();
        assert!(registry
            .with_selected_page_targets(&main, None, None, false, |_, _| Ok(true), |_| Ok(()))
            .is_err());
        assert!(!registry.owned_target("child").unwrap().configured);
    }
    #[tokio::test]
    async fn selected_query_same_text_root_and_child_aba_cannot_reuse_proof() {
        for root in [true, false] {
            let (registry, main) = fixture().await;
            ready(&registry, "child", "child-session", "iframe").await;
            let (proof, _) = registry
                .with_selected_page_targets(
                    &main,
                    None,
                    None,
                    false,
                    |_, _| Ok(true),
                    |proof| Ok(proof.clone()),
                )
                .unwrap();
            let (target, session, kind) = if root {
                ("main", "main-session", "page")
            } else {
                ("child", "child-session", "iframe")
            };
            registry.detach(target).unwrap();
            ready(&registry, target, session, kind).await;
            assert!(registry
                .with_selected_page_targets(
                    &main,
                    Some(&proof),
                    None,
                    false,
                    |_, _| Ok(true),
                    |_| Ok(())
                )
                .is_err());
        }
    }
    #[tokio::test]
    async fn selected_query_reservations_unknown_create_poison_and_foreign_guard_refuse() {
        for cause in ["reservation", "unknown-create", "poison", "unclassified"] {
            let (registry, main) = fixture().await;
            {
                let mut state = registry.state.lock().unwrap();
                match cause {
                    "reservation" => state.reservations = 1,
                    "unknown-create" => state.unknown_bootstrap_create = true,
                    "poison" => state.integrity_lost = true,
                    _ => state.targets.get_mut("main").unwrap().purpose = None,
                }
            }
            assert!(snapshot(&registry, &main, true).is_err(), "{cause}");
            assert!(registry.state.lock().unwrap().protected_read.is_none());
        }
        let (first, main) = fixture().await;
        let (_, guard) = snapshot(&first, &main, true).unwrap();
        let (other, main) = fixture().await;
        assert!(other
            .with_selected_page_targets(
                &main,
                None,
                guard.as_ref(),
                false,
                |_, _| Ok(true),
                |_| Ok(())
            )
            .is_err());
    }
    #[tokio::test]
    async fn selected_query_unrelated_worker_ack_and_retirement_do_not_borrow_global_authority() {
        for retire in [false, true] {
            for global in [false, true] {
                let (registry, main) = fixture().await;
                let mut custody = RetainedInitialization::new(registry.clone());
                custody
                    .attach(
                        &registry,
                        "ctx",
                        "worker".into(),
                        "worker-session".into(),
                        "service_worker".into(),
                    )
                    .unwrap();
                let mut permit = registry
                    .service_worker_startup_permit("worker", "worker-session")
                    .await
                    .unwrap();
                let guard = if global {
                    // Predicate negative control: production Global admission itself
                    // would already refuse this in-flight startup.
                    registry.state.lock().unwrap().protected_read =
                        Some(ProtectedExclusion::Global {
                            token: Arc::new(()),
                        });
                    None
                } else {
                    snapshot(&registry, &main, true).unwrap().1
                };
                if retire {
                    registry
                        .observe_worker_detach("worker", "worker-session")
                        .unwrap();
                    registry.detach("worker").unwrap();
                }
                let result = if retire {
                    permit.finish_retired_worker_startup(
                        &registry,
                        "worker",
                        "worker-session",
                        || Ok(()),
                    )
                } else {
                    permit
                        .complete_acknowledged_worker_startup(
                            &registry,
                            "worker",
                            "worker-session",
                            || Ok(()),
                        )
                        .map(|_| ())
                };
                assert_eq!(result.is_ok(), !global);
                if global {
                    registry.state.lock().unwrap().protected_read = None;
                    if retire {
                        permit
                            .finish_retired_worker_startup(
                                &registry,
                                "worker",
                                "worker-session",
                                || Ok(()),
                            )
                            .unwrap();
                    } else {
                        permit
                            .complete_acknowledged_worker_startup(
                                &registry,
                                "worker",
                                "worker-session",
                                || Ok(()),
                            )
                            .unwrap();
                    }
                }
                drop(permit);
                custody.finish(retire).unwrap();
                drop(guard);
                assert!(registry
                    .operation_settlement_integrity_diagnostic(false)
                    .0
                    .is_ok());
            }
        }
    }
    #[tokio::test]
    async fn selected_query_same_root_worker_wait_is_usable_and_retry_requires_real_ready() {
        let (registry, main) = fixture().await;
        let mut custody = RetainedInitialization::new(registry.clone());
        custody
            .attach_with_root(
                &registry,
                "ctx",
                "worker".into(),
                "worker-session".into(),
                "service_worker".into(),
                Some(main.clone()),
            )
            .unwrap();
        let mut permit = registry
            .service_worker_startup_permit("worker", "worker-session")
            .await
            .unwrap();
        assert!(snapshot(&registry, &main, true).is_err());
        assert!(registry
            .operation_settlement_integrity_diagnostic(false)
            .0
            .is_ok());
        assert!(registry.state.lock().unwrap().protected_read.is_none());
        permit
            .complete_acknowledged_worker_startup(&registry, "worker", "worker-session", || Ok(()))
            .unwrap();
        drop(permit);
        custody.finish(false).unwrap();
        assert!(snapshot(&registry, &main, true).is_ok());
    }
    #[tokio::test]
    async fn selected_query_detached_and_queued_iframe_retirement_is_exact_root_scoped() {
        for related in [false, true] {
            let (registry, main) = fixture().await;
            ready(&registry, "popup", "popup-session", "page").await;
            let root = if related {
                main.clone()
            } else {
                registry.owned_target("popup").unwrap()
            };
            let (_, guard) = snapshot(&registry, &main, true).unwrap();
            let mut custody = RetainedInitialization::new(registry.clone());
            custody
                .attach_with_root(
                    &registry,
                    "ctx",
                    "child".into(),
                    "child-session".into(),
                    "iframe".into(),
                    Some(root.clone()),
                )
                .unwrap();
            let child = registry.owned_target("child").unwrap();
            registry
                .observe_iframe_detach("child", "child-session")
                .unwrap();
            registry.detach("child").unwrap();
            let retired =
                registry.finish_detached_iframe_initialization(&child, &root, None, || Ok(()));
            assert_eq!(retired.is_ok(), !related);
            let queued = registry.finish_detached_queued_iframe(
                "queued",
                "queued-session",
                &root,
                &root,
                || Ok(()),
            );
            assert_eq!(queued.is_ok(), !related);
            drop(guard);
            registry
                .finish_detached_iframe_initialization(&child, &root, None, || Ok(()))
                .unwrap();
            custody.finish(true).unwrap();
            assert!(registry
                .operation_settlement_integrity_diagnostic(false)
                .0
                .is_ok());
        }
    }
    #[tokio::test]
    async fn selected_query_new_resume_admission_uses_exact_lineage_not_target_kind() {
        let (registry, main) = fixture().await;
        ready(&registry, "popup", "popup-session", "page").await;
        let popup = registry.owned_target("popup").unwrap();
        let (_, guard) = snapshot(&registry, &main, true).unwrap();
        for (target, root) in [
            ("related", Some(&main)),
            ("unrelated", Some(&popup)),
            ("unknown", None),
        ] {
            if let Some(root) = root {
                registry
                    .attached_enrolled(
                        "ctx",
                        target.into(),
                        format!("{target}-session"),
                        "iframe".into(),
                        Some(root),
                    )
                    .unwrap();
            } else {
                registry
                    .attached(
                        "ctx",
                        target.into(),
                        format!("{target}-session"),
                        "iframe".into(),
                    )
                    .unwrap();
            }
            registry.configured(target).unwrap();
            let pending = registry.resume_permit(target);
            tokio::pin!(pending);
            match futures_util::poll!(&mut pending) {
                std::task::Poll::Ready(Ok(permit)) => {
                    assert_eq!(target, "unrelated");
                    permit.complete().unwrap();
                }
                std::task::Poll::Pending => assert_ne!(target, "unrelated"),
                _ => panic!("unexpected admission result"),
            }
        }
        drop(guard);
    }
    #[tokio::test]
    async fn selected_query_stale_guard_cannot_clear_later_exclusion() {
        let (registry, main) = fixture().await;
        let (_, guard) = snapshot(&registry, &main, true).unwrap();
        let later = Arc::new(());
        registry.state.lock().unwrap().protected_read = Some(ProtectedExclusion::Global {
            token: later.clone(),
        });
        drop(guard);
        assert!(registry
            .state
            .lock()
            .unwrap()
            .protected_read
            .as_ref()
            .unwrap()
            .matches_token(&later));
        registry.state.lock().unwrap().protected_read = None;
    }
    #[tokio::test]
    async fn selected_query_forged_root_and_same_text_root_reuse_cannot_admit_live_child() {
        let (registry, main) = fixture().await;
        ready(&registry, "popup", "popup-session", "page").await;
        let popup = registry.owned_target("popup").unwrap();
        registry
            .attached_enrolled(
                "ctx",
                "child".into(),
                "child-session".into(),
                "iframe".into(),
                Some(&popup),
            )
            .unwrap();
        registry.configured("child").unwrap();
        // Admit the guard before the external root retires; the child is retained
        // as fully configured but not resumed, so create an exact custody owner.
        registry.detach("child").unwrap();
        let mut custody = RetainedInitialization::new(registry.clone());
        custody
            .attach_with_root(
                &registry,
                "ctx",
                "child".into(),
                "child-session".into(),
                "iframe".into(),
                Some(popup.clone()),
            )
            .unwrap();
        registry.configured("child").unwrap();
        let (_, guard) = snapshot(&registry, &main, true).unwrap();
        registry.detach("popup").unwrap();
        registry
            .attached_enrolled(
                "ctx",
                "popup".into(),
                "popup-session".into(),
                "page".into(),
                None,
            )
            .unwrap();
        let pending = registry.resume_permit("child");
        tokio::pin!(pending);
        assert!(matches!(
            futures_util::poll!(&mut pending),
            std::task::Poll::Pending
        ));
        let other = ClientTargets::new("ctx".into(), "scope".into());
        assert!(other
            .attached_enrolled(
                "ctx",
                "forged".into(),
                "forged-session".into(),
                "iframe".into(),
                Some(&main)
            )
            .is_err());
        drop(guard);
    }
    #[tokio::test]
    async fn selected_query_final_publication_fences_selected_and_unknown_document_changes() {
        for change in ["selected", "unrelated", "unknown", "missing-target"] {
            let (registry, main) = fixture().await;
            ready(&registry, "popup", "popup-session", "page").await;
            let (proof, guard) = snapshot(&registry, &main, true).unwrap();
            match change {
                "selected" => registry
                    .invalidate_inventory_for(
                        diagnostic::InventoryRevisionEvent::SameDocument,
                        "main",
                    )
                    .unwrap(),
                "unrelated" => registry
                    .invalidate_inventory_for(diagnostic::InventoryRevisionEvent::Navigate, "popup")
                    .unwrap(),
                "missing-target" => registry
                    .invalidate_inventory_for(
                        diagnostic::InventoryRevisionEvent::Navigate,
                        "missing",
                    )
                    .unwrap(),
                _ => registry.invalidate_inventory().unwrap(),
            }
            let committed = std::sync::atomic::AtomicBool::new(false);
            let result = registry.with_selected_page_targets(
                &main,
                Some(&proof),
                guard.as_ref(),
                false,
                |target, _| Ok(target.target_id == "main"),
                |_| {
                    committed.store(true, Ordering::SeqCst);
                    Ok(())
                },
            );
            assert_eq!(result.is_ok(), change == "unrelated", "{change}");
            assert_eq!(
                committed.load(Ordering::SeqCst),
                change == "unrelated",
                "{change}"
            );
        }
    }
    #[tokio::test]
    async fn selected_query_revision_exhaustion_cannot_reuse_last_proof() {
        for unknown in [false, true] {
            let (registry, main) = fixture().await;
            if unknown {
                registry.state.lock().unwrap().query_unknown_revision = u64::MAX;
            } else {
                main.tenure.query_revision.store(u64::MAX, Ordering::SeqCst);
            }
            let (proof, guard) = snapshot(&registry, &main, true).unwrap();
            let changed = if unknown {
                registry.invalidate_inventory()
            } else {
                registry
                    .invalidate_inventory_for(diagnostic::InventoryRevisionEvent::Navigate, "main")
            };
            assert_eq!(changed, Err(ProtocolError::IdentifierExhausted));
            assert!(registry
                .with_selected_page_targets(
                    &main,
                    Some(&proof),
                    guard.as_ref(),
                    false,
                    |target, _| Ok(target.target_id == "main"),
                    |_| Ok(())
                )
                .is_err());
        }
    }
}
