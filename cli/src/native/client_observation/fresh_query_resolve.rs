//! Local proof for the fully drained fresh-query resolve batch. This does not
//! inspect missing groups, erase debt, confer admission, or infer remote ACKs.
use super::*;
use client_debt::{CommandStatus, CommandStatusHandle, OperationJournalHandle, OwnerDebtLedger};
use std::sync::Arc;

pub(super) struct ResolveOwner {
    ledger: Arc<OwnerDebtLedger>,
    journal: OperationJournalHandle,
    session: String,
    group: String,
    capture: Arc<()>,
}
impl ResolveOwner {
    pub(super) fn capture(
        client: &CdpClient,
        session: &str,
        group: &str,
        lease: &OperationLease,
    ) -> Option<Self> {
        if capture_retirement_active() || !native_owned_group(group, lease.sequence) {
            return None;
        }
        let ledger = client.debt_ledger()?;
        let journal = OperationJournalHandle::current()?;
        let owner = Self {
            ledger,
            journal,
            session: session.to_owned(),
            group: group.to_owned(),
            capture: Arc::new(()),
        };
        owner.valid(client, session, lease).then_some(owner)
    }
    fn valid(&self, client: &CdpClient, session: &str, lease: &OperationLease) -> bool {
        !capture_retirement_active()
            && session == self.session
            && client
                .check_cleanup_owner(&Some(self.ledger.clone()))
                .is_ok()
            && self
                .journal
                .matches_readonly_resolve_owner(&self.ledger, session, lease)
    }
    /// Called only after collect has drained every resolve future. A live
    /// Reserved status is not proof, even if no writer has run yet.
    pub(super) fn proves_no_submission(
        &self,
        client: &CdpClient,
        session: &str,
        group: &str,
        lease: &OperationLease,
        receipts: &[ResolveReceipt],
    ) -> bool {
        self.group == group
            && self.valid(client, session, lease)
            && !receipts.is_empty()
            && receipts.iter().all(|receipt| receipt.matches_capture(self))
    }
    fn receipt(&self, evidence: ResolveEvidence) -> ResolveReceipt {
        ResolveReceipt {
            capture: Some(self.capture.clone()),
            group: self.group.clone(),
            evidence,
        }
    }
}
enum ResolveEvidence {
    BeforeReservation,
    Reservation(CommandStatusHandle),
    Unknown,
}
pub(super) struct ResolveReceipt {
    capture: Option<Arc<()>>,
    group: String,
    evidence: ResolveEvidence,
}
impl ResolveReceipt {
    fn matches_capture(&self, owner: &ResolveOwner) -> bool {
        self.capture
            .as_ref()
            .is_some_and(|capture| Arc::ptr_eq(capture, &owner.capture))
            && self.group == owner.group
            && match &self.evidence {
                ResolveEvidence::BeforeReservation => true,
                ResolveEvidence::Reservation(status) => status_proves_abandoned(status.snapshot()),
                ResolveEvidence::Unknown => false,
            }
    }
    fn unknown() -> Self {
        Self {
            capture: None,
            group: String::new(),
            evidence: ResolveEvidence::Unknown,
        }
    }
}

fn status_proves_abandoned(status: CommandStatus) -> bool {
    status == CommandStatus::Abandoned
}

pub(super) async fn resolve(
    client: &CdpClient,
    session: &str,
    backend: i64,
    context: i64,
    group: &str,
    lease: &OperationLease,
    owner: Option<&ResolveOwner>,
) -> (Result<Value, ObservationError>, ResolveReceipt) {
    let args = json!({"backendNodeId":backend,"executionContextId":context,"objectGroup":group});
    let Some(owner) =
        owner.filter(|owner| owner.group == group && owner.valid(client, session, lease))
    else {
        return (
            command(client, session, "DOM.resolveNode", args, lease).await,
            ResolveReceipt::unknown(),
        );
    };
    #[cfg(test)]
    let args = equivalence_tests::instrument("DOM.resolveNode", args, lease);
    let (result, receipt) = client_debt::command_scope(CommandCategory::ApplicationObject, false,
        client_debt::native_object_group(group, async {
            #[cfg(test)]
            hooks::checkpoint(owner, lease, backend, ResolveHookPoint::BeforeReservation).await;
            if let Err(error) = check(lease) {
                return (Err(error), owner.receipt(ResolveEvidence::BeforeReservation));
            }
            // Before the selected future is first polled, no reservation or
            // remote-producing command exists. Keep reservation inside that
            // future, matching ordinary send_command's cancellation topology.
            let mut evidence = ResolveEvidence::BeforeReservation;
            let result = {
                let mut cancellation = lease.cancellation.clone();
                let command = async {
                    let reservation = client.reserve_tracked_command("DOM.resolveNode", Some(&args), Some(session));
                    #[cfg(test)]
                    client.activation_command_diagnostic("cdp-reserve", "DOM.resolveNode", reservation.as_ref().map(|_| ()).map_err(String::as_str));
                    let reservation = match reservation {
                        Ok(Some(reservation)) => reservation,
                        Ok(None) => {
                            evidence = ResolveEvidence::Unknown;
                            return Err(ObservationError::BackendFailure);
                        }
                        Err(_) => return Err(ObservationError::BackendFailure),
                    };
                    // This is the exact reservation's existing status handle,
                    // never aggregate group/debt state or imported authority.
                    if !reservation.belongs_to(&owner.ledger) {
                        evidence = ResolveEvidence::Unknown;
                        drop(reservation);
                        return Err(ObservationError::BackendFailure);
                    }
                    evidence = ResolveEvidence::Reservation(reservation.status());
                    #[cfg(test)]
                    hooks::checkpoint(owner, lease, backend, ResolveHookPoint::AfterReservation).await;
                    let result = client.send_reserved_command("DOM.resolveNode", Some(args), Some(session), Some(reservation)).await;
                    #[cfg(test)]
                    client.activation_command_diagnostic("cdp-result", "DOM.resolveNode", result.as_ref().map(|_| ()).map_err(String::as_str));
                    result.map_err(|_| ObservationError::BackendFailure)
                };
                tokio::pin!(command);
                tokio::select! {
                    result = &mut command => result,
                    _ = cancellation.changed() => Err(ObservationError::Cancelled),
                    _ = tokio::time::sleep_until(lease.deadline.into()) => Err(ObservationError::DeadlineExceeded),
                }
            }; // Drop the actual selected future/reservation BEFORE observing status.
            (result, owner.receipt(evidence))
        })
    ).await;
    #[cfg(test)]
    let result = {
        let mut result = result;
        match &result {
            Ok(value) => {
                diagnostic_exception("DOM.resolveNode", diagnostic_site(&json!({})), value)
            }
            Err(_) => {
                eprintln!("native observation protocol failure at DOM.resolveNode; details omitted")
            }
        }
        if let Ok(value) = &result {
            if let Err(error) = equivalence_tests::after_command(
                client,
                session,
                "DOM.resolveNode",
                diagnostic_site(&json!({})),
                Some(group),
                value,
                lease,
            )
            .await
            {
                result = Err(error);
            }
        }
        result
    };
    (result, receipt)
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ResolveHookPoint {
    BeforeReservation,
    AfterReservation,
}
#[cfg(test)]
pub(super) use hooks::install_resolve_hook;
#[cfg(test)]
mod hooks {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use tokio::sync::oneshot;
    struct Hook {
        journal: OperationJournalHandle,
        session: String,
        deadline: std::time::Instant,
        cancellation: tokio::sync::watch::Receiver<CancelSignal>,
        backend: i64,
        point: ResolveHookPoint,
        entered: Option<oneshot::Sender<()>>,
        release: Option<oneshot::Receiver<()>>,
    }
    type Hooks = Mutex<Vec<Arc<Mutex<Hook>>>>;
    fn hooks() -> &'static Hooks {
        static HOOKS: OnceLock<Hooks> = OnceLock::new();
        HOOKS.get_or_init(|| Mutex::new(Vec::new()))
    }
    pub(in super::super) struct ResolveHookGuard(Arc<Mutex<Hook>>);
    impl Drop for ResolveHookGuard {
        fn drop(&mut self) {
            hooks()
                .lock()
                .unwrap()
                .retain(|hook| !Arc::ptr_eq(hook, &self.0));
        }
    }
    pub(in super::super) fn install_resolve_hook(
        client: &CdpClient,
        session: &str,
        lease: &OperationLease,
        backend: i64,
        point: ResolveHookPoint,
    ) -> (ResolveHookGuard, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let journal =
            OperationJournalHandle::current().expect("hook requires exact operation scope");
        let ledger = client.debt_ledger().expect("hook requires managed owner");
        assert!(client.check_cleanup_owner(&Some(ledger.clone())).is_ok());
        assert!(journal.matches_readonly_resolve_owner(&ledger, session, lease));
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let hook = Arc::new(Mutex::new(Hook {
            journal,
            session: session.to_owned(),
            deadline: lease.deadline,
            cancellation: lease.cancellation.clone(),
            backend,
            point,
            entered: Some(entered_tx),
            release: Some(release_rx),
        }));
        hooks().lock().unwrap().push(hook.clone());
        (ResolveHookGuard(hook), entered_rx, release_tx)
    }
    pub(super) async fn checkpoint(
        owner: &ResolveOwner,
        lease: &OperationLease,
        backend: i64,
        point: ResolveHookPoint,
    ) {
        let selected = {
            let registered = hooks().lock().unwrap();
            registered.iter().find_map(|hook| {
                let mut hook = hook.lock().unwrap();
                if hook.backend != backend
                    || hook.point != point
                    || hook.session != owner.session
                    || hook.deadline != lease.deadline
                    || !hook.cancellation.same_channel(&lease.cancellation)
                    || !hook.journal.same_operation(&owner.journal)
                {
                    return None;
                }
                let entered = hook.entered.take()?;
                let release = hook.release.take().expect("paired hook channels");
                Some((entered, release))
            })
        };
        if let Some((entered, release)) = selected {
            entered.send(()).expect("hook observer dropped");
            release.await.expect("hook release dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use client_debt::OperationKey;

    #[test]
    fn only_abandoned_is_never_submitted_not_ack_destroyed_or_reserved() {
        for status in [
            CommandStatus::Reserved,
            CommandStatus::Submitted,
            CommandStatus::Acknowledged,
            CommandStatus::RetainedRejected,
            CommandStatus::Destroyed,
            CommandStatus::IntegrityLost,
        ] {
            assert!(!status_proves_abandoned(status));
        }
        assert!(status_proves_abandoned(CommandStatus::Abandoned));
    }

    #[tokio::test]
    async fn resolve_receipts_require_exact_capture_group_and_terminal_drop() {
        let ledger = OwnerDebtLedger::new(1, "resolve-proof".into());
        let journal = ledger
            .operation(
                OperationKey {
                    generation: 1,
                    operation_seq: 1,
                },
                "target".into(),
                "page".into(),
            )
            .unwrap();
        let owner = ResolveOwner {
            ledger: ledger.clone(),
            journal: journal.clone(),
            session: "page".into(),
            group: "native-query-1-fields-owned".into(),
            capture: Arc::new(()),
        };
        let reservation = journal
            .scope(client_debt::native_object_group(&owner.group, async {
                ledger.reserve_command(
                    Some(&journal),
                    "DOM.resolveNode",
                    Some(&json!({"backendNodeId":7,"objectGroup":owner.group})),
                    Some("page"),
                )
            }))
            .await
            .unwrap();
        let receipt = owner.receipt(ResolveEvidence::Reservation(reservation.status()));
        assert!(
            !receipt.matches_capture(&owner),
            "live reservation is not no-submission proof"
        );
        drop(reservation);
        assert!(receipt.matches_capture(&owner));
        assert_eq!(ledger.snapshot().object_debt, 0);
        let other_capture = ResolveOwner {
            ledger: ledger.clone(),
            journal: journal.clone(),
            session: "page".into(),
            group: owner.group.clone(),
            capture: Arc::new(()),
        };
        assert!(
            !receipt.matches_capture(&other_capture),
            "same journal is not the same batch capture"
        );
        let other_group = ResolveOwner {
            ledger,
            journal,
            session: "page".into(),
            group: "native-query-1-fields-other".into(),
            capture: owner.capture.clone(),
        };
        assert!(!receipt.matches_capture(&other_group));
        assert!(!ResolveReceipt::unknown().matches_capture(&owner));
    }

    #[tokio::test]
    async fn readonly_resolve_owner_rejects_foreign_channel_session_and_journal() {
        let ledger = OwnerDebtLedger::new(1, "resolve-proof".into());
        let key = OperationKey {
            generation: 1,
            operation_seq: 1,
        };
        let journal = ledger
            .operation(key, "target".into(), "page".into())
            .unwrap();
        let (cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let lease = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(5),
            cancellation,
        };
        journal.bind_operation(&lease).unwrap();
        journal
            .scope(async {
                assert!(journal.matches_readonly_resolve_owner(&ledger, "page", &lease));
                cancel.send_replace(CancelSignal::Requested);
                assert!(
                    journal.matches_readonly_resolve_owner(&ledger, "page", &lease),
                    "cancellation does not erase exact local ownership"
                );
                assert!(!journal.matches_readonly_resolve_owner(&ledger, "other", &lease));
                let other_ledger = OwnerDebtLedger::new(1, "resolve-proof".into());
                assert!(!journal.matches_readonly_resolve_owner(&other_ledger, "page", &lease));
                let (_sender, foreign_channel) =
                    tokio::sync::watch::channel(CancelSignal::Requested);
                let wrong_lease = OperationLease {
                    is_callback: false,
                    generation: 1,
                    sequence: 1,
                    deadline: lease.deadline,
                    cancellation: foreign_channel,
                };
                assert!(!journal.matches_readonly_resolve_owner(&ledger, "page", &wrong_lease));
                let other_journal = ledger
                    .operation(key, "target".into(), "page".into())
                    .unwrap();
                other_journal.bind_operation(&lease).unwrap();
                other_journal
                    .scope(async {
                        assert!(!journal.matches_readonly_resolve_owner(&ledger, "page", &lease));
                    })
                    .await;
                journal.revoke_application_submission();
                assert!(journal.matches_readonly_resolve_owner(&ledger, "page", &lease));
                assert!(
                    journal.check_application_submission().is_err(),
                    "local proof never restores admission"
                );
                journal.finish_local_producers();
                assert!(!journal.matches_readonly_resolve_owner(&ledger, "page", &lease));
                journal.record_cleanup_disposition(client_debt::CleanupDisposition::IntegrityLost);
                assert!(!journal.matches_readonly_resolve_owner(&ledger, "page", &lease));
            })
            .await;
        assert!(
            !journal.matches_readonly_resolve_owner(&ledger, "page", &lease),
            "no ambient operation proof"
        );
    }
    #[tokio::test]
    async fn readonly_resolve_owner_rejects_actual_journal_and_ledger_integrity_loss() {
        for ledger_loss in [false, true] {
            let ledger = OwnerDebtLedger::new(1, "resolve-proof-loss".into());
            let journal = ledger
                .operation(
                    OperationKey {
                        generation: 1,
                        operation_seq: 1,
                    },
                    "target".into(),
                    "page".into(),
                )
                .unwrap();
            let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
            let lease = OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(5),
                cancellation,
            };
            journal.bind_operation(&lease).unwrap();
            journal
                .scope(async {
                    assert!(journal.matches_readonly_resolve_owner(&ledger, "page", &lease));
                    if ledger_loss {
                        ledger.connection_lost();
                    } else {
                        journal.record_cleanup_disposition(
                            client_debt::CleanupDisposition::IntegrityLost,
                        );
                    }
                    assert!(!journal.matches_readonly_resolve_owner(&ledger, "page", &lease));
                })
                .await;
        }
    }
}
