//! Bounded status of retained application producers, not browser ownership.
//! Entries never infer clean retirement from a dropped waiter or empty debt.
use super::client_debt::{
    CleanupDisposition, EvalAuthorityStamp, EvalWindowHandle, OperationJournalHandle, OperationKey,
    ReentrantEvalPermit,
};
use super::client_protocol::{ProtocolError, RetentionDescriptor, RetentionProducerState};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

pub(crate) const MAX_RETAINED_OPERATIONS: usize = 64;
pub(crate) const MAX_RETIREMENT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProducerState {
    RegisteredNotDispatched,
    Running,
    Retiring,
    Retired,
    IntegrityLost,
    DisconnectedRetired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetiredDisposition {
    Complete,
    AccountedRemoteDebt,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetentionIntegrityReason {
    LocalProducerFailed,
    RemoteConnectionLost,
    RetirementDeadline,
    OwnerAccountingLost,
    RegistryUnavailable,
}
struct Entry {
    journal: OperationJournalHandle,
    state: ProducerState,
    retirement_deadline: Option<Instant>,
    result_fixed: bool,
    disposition: Option<RetiredDisposition>,
    integrity_reason: Option<RetentionIntegrityReason>,
}
/// Only this exact retained producer registry can mint this native proof.
/// The descriptor is a snapshot, never dispatch authority or completion proof.
#[derive(Clone, Debug)]
pub(crate) struct OperationRetentionProof {
    key: OperationKey,
    descriptor: RetentionDescriptor,
    retirement_deadline: Instant,
}
impl OperationRetentionProof {
    pub(crate) fn matches(&self, key: OperationKey) -> bool {
        self.key == key && self.descriptor.retired_operation_seq == key.operation_seq
    }
    pub(crate) fn descriptor(&self) -> RetentionDescriptor {
        self.descriptor.clone()
    }
    pub(crate) fn retirement_deadline(&self) -> Instant {
        self.retirement_deadline
    }
}
#[derive(Clone, Debug)]
pub(crate) enum OperationRetentionStatus {
    NotRegistered,
    KnownActive {
        mutation_dispatched: bool,
    },
    KnownRetiring {
        mutation_dispatched: bool,
        proof: OperationRetentionProof,
    },
    Retired {
        mutation_dispatched: bool,
        proof: OperationRetentionProof,
    },
    IntegrityLost(RetentionIntegrityReason),
}
impl OperationRetentionStatus {
    pub(crate) fn mutation_dispatched(&self) -> Option<bool> {
        match self {
            Self::KnownActive {
                mutation_dispatched,
            }
            | Self::KnownRetiring {
                mutation_dispatched,
                ..
            }
            | Self::Retired {
                mutation_dispatched,
                ..
            } => Some(*mutation_dispatched),
            _ => None,
        }
    }
    pub(crate) fn proof(&self) -> Option<OperationRetentionProof> {
        match self {
            Self::KnownRetiring { proof, .. } | Self::Retired { proof, .. } => Some(proof.clone()),
            _ => None,
        }
    }
}
/// Permission to attempt one explicit exact-owner recovery, not permission to
/// submit business work or evidence that any remote Unknown effect completed.
#[derive(Clone)]
pub(crate) struct DisconnectedRecoveryProof {
    key: OperationKey,
    ledger: std::sync::Arc<super::client_debt::OwnerDebtLedger>,
    deadline: Instant,
}
impl DisconnectedRecoveryProof {
    pub(crate) fn key(&self) -> OperationKey {
        self.key
    }
    pub(crate) fn ledger(&self) -> &std::sync::Arc<super::client_debt::OwnerDebtLedger> {
        &self.ledger
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn check(&self) -> Result<(), ProtocolError> {
        if Instant::now() >= self.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        if !self.ledger.remote_eof_only() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        Ok(())
    }
}
#[derive(Default)]
pub(crate) struct OperationRegistry {
    entries: Mutex<HashMap<OperationKey, Entry>>,
    pub(crate) changed: Notify,
}
impl OperationRegistry {
    pub(crate) fn begin_protected_cleanup(&self, key: OperationKey) -> Option<Instant> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(&key)?;
        Some(entry.journal.begin_protected_cleanup())
    }
    /// Retain entries across provisional installation and snapshots. Ledger is
    /// deliberately not held while journal.snapshot performs its own accounting.
    pub(crate) fn prepare_eval_window(
        &self,
        journal: &OperationJournalHandle,
        operation: &super::client_session::OperationLease,
        stamp: EvalAuthorityStamp,
    ) -> Result<EvalWindowHandle, ProtocolError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let entry = entries
            .get(&journal.key())
            .ok_or(ProtocolError::OperationMissing)?;
        if entry.state != ProducerState::Running
            || !std::sync::Arc::ptr_eq(&entry.journal.ledger(), &journal.ledger())
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let ledger = journal.ledger();
        let handle = ledger.begin_eval_window(journal, operation, stamp)?;
        let result = (|| {
            if !Self::entries_input_ready(&entries, journal.key(), None)? {
                return Err(ProtocolError::ScopeUnavailable);
            }
            ledger.arm_eval_window(&handle)
        })();
        if let Err(error) = result {
            ledger.abandon_eval_preparation(&handle);
            return Err(error);
        }
        Ok(handle)
    }
    pub(crate) fn check_eval_dispatch(
        &self,
        permit: &ReentrantEvalPermit,
    ) -> Result<(), ProtocolError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let child = entries
            .get(&permit.child())
            .ok_or(ProtocolError::OperationMissing)?;
        let ledger = child.journal.ledger();
        if !permit.window().belongs_to(&ledger) {
            return Err(ProtocolError::StaleScope);
        }
        ledger.check_eval_input(permit)?;
        if Self::entries_input_ready(&entries, permit.child(), Some(permit.window().root()))? {
            Ok(())
        } else {
            Err(ProtocolError::ScopeUnavailable)
        }
    }
    fn revoke_eval_windows(entries: &HashMap<OperationKey, Entry>) {
        for entry in entries.values() {
            entry.journal.ledger().invalidate_eval_authority();
        }
    }
    fn fail_eval_windows(entries: &HashMap<OperationKey, Entry>) {
        for entry in entries.values() {
            entry.journal.ledger().fail_eval_authority();
        }
    }
    pub(crate) fn register(&self, journal: OperationJournalHandle) -> Result<(), ProtocolError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if entries.len() >= MAX_RETAINED_OPERATIONS {
            return Err(ProtocolError::CapacityExceeded);
        }
        let key = journal.key();
        if entries.contains_key(&key) {
            return Err(ProtocolError::InvalidSequence);
        }
        // OwnerDebtLedger already pre-reserved this journal's immutable
        // provenance in the shared 512 KiB descriptor budget. Do not create a
        // second budget or evict a live producer to make registration fit.
        let snapshot = journal.snapshot();
        if snapshot.integrity_lost
            || snapshot.local_producers_finished
            || snapshot.submission_revoked
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        entries.insert(
            key,
            Entry {
                journal,
                state: ProducerState::RegisteredNotDispatched,
                retirement_deadline: None,
                result_fixed: false,
                disposition: None,
                integrity_reason: None,
            },
        );
        Ok(())
    }
    /// Synchronous prepare failed before a future or producer was spawned.
    pub(crate) fn abandon_unstarted(&self, key: OperationKey) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if let Some(entry) = entries.get(&key) {
            if entry.state != ProducerState::RegisteredNotDispatched
                || entry.journal.snapshot().mutation_dispatched
            {
                return;
            }
            entry.journal.revoke_application_submission();
            entry
                .journal
                .record_cleanup_disposition(CleanupDisposition::Complete);
            entry.journal.finish_local_producers();
            entries.remove(&key);
        }
        self.changed.notify_waiters();
    }
    pub(crate) fn running(&self, key: OperationKey) {
        if let Ok(mut entries) = self.entries.lock() {
            if let Some(entry) = entries.get_mut(&key) {
                if entry.state == ProducerState::RegisteredNotDispatched {
                    entry.state = ProducerState::Running;
                }
            }
        }
    }
    /// Revocation linearizes before proof. The absolute bound is set exactly
    /// once; subsequent lookups/new requests cannot extend it.
    pub(crate) fn retire(&self, key: OperationKey) -> Option<Instant> {
        let mut entries = self.entries.lock().ok()?;
        if !entries.contains_key(&key)
            || entries
                .get(&key)
                .is_some_and(|entry| entry.state == ProducerState::DisconnectedRetired)
        {
            return None;
        }
        Self::revoke_eval_windows(&entries);
        let entry = entries.get_mut(&key)?;
        entry.journal.revoke_application_submission();
        if entry.state == ProducerState::IntegrityLost {
            return None;
        }
        if entry.state != ProducerState::Retired {
            entry.state = ProducerState::Retiring;
        }
        let deadline = *entry
            .retirement_deadline
            .get_or_insert_with(|| Instant::now() + MAX_RETIREMENT);
        self.changed.notify_waiters();
        Some(deadline)
    }
    pub(crate) fn finish(&self, key: OperationKey, integrity_lost: bool) -> bool {
        self.finish_with_cause(key, integrity_lost, false)
    }
    pub(crate) fn finish_remote_eof(&self, key: OperationKey) -> bool {
        self.finish_with_cause(key, true, true)
    }
    fn finish_with_cause(&self, key: OperationKey, integrity_lost: bool, remote_eof: bool) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return true;
        };
        if entries
            .get(&key)
            .is_some_and(|entry| entry.state == ProducerState::DisconnectedRetired)
        {
            return true;
        }
        let expired = entries.get(&key).is_some_and(|entry| {
            entry.state == ProducerState::Retiring
                && entry
                    .retirement_deadline
                    .is_some_and(|limit| Instant::now() >= limit)
        });
        if integrity_lost
            || expired
            || entries
                .get(&key)
                .is_some_and(|entry| entry.state == ProducerState::IntegrityLost)
        {
            Self::fail_eval_windows(&entries);
        }
        let Some(entry) = entries.get_mut(&key) else {
            return true;
        };
        // Completion and expiry linearize under the same lock. A delayed timer
        // cannot let a late producer erase its already-fixed Unknown receipt.
        // The retained future really returned. Revoke before publishing any
        // producer transition; a fixed result alone never ends this obligation.
        entry
            .journal
            .ledger()
            .eval_operation_terminal(key, true, entry.result_fixed);
        if integrity_lost || expired || entry.state == ProducerState::IntegrityLost {
            let remote_only = remote_eof
                && !expired
                && entry.state != ProducerState::IntegrityLost
                && entry.journal.local_integrity_intact()
                && entry.journal.ledger().remote_eof_only();
            if !remote_only {
                entry
                    .journal
                    .record_cleanup_disposition(CleanupDisposition::IntegrityLost);
            }
            entry.state = ProducerState::IntegrityLost;
            entry.integrity_reason.get_or_insert(if expired {
                RetentionIntegrityReason::RetirementDeadline
            } else if remote_only {
                RetentionIntegrityReason::RemoteConnectionLost
            } else {
                RetentionIntegrityReason::LocalProducerFailed
            });
            entry.disposition = None;
        } else {
            let snapshot = entry.journal.snapshot();
            let disposition = if snapshot.input_debt != 0 || snapshot.object_debt != 0 {
                RetiredDisposition::AccountedRemoteDebt
            } else {
                RetiredDisposition::Complete
            };
            entry.disposition = Some(disposition);
            entry.journal.record_cleanup_disposition(match disposition {
                RetiredDisposition::Complete => CleanupDisposition::Complete,
                RetiredDisposition::AccountedRemoteDebt => CleanupDisposition::AccountedRemoteDebt,
            });
            entry.state = ProducerState::Retired;
        }
        entry.journal.finish_local_producers();
        let integrity_lost = entry.state == ProducerState::IntegrityLost;
        if entry.result_fixed && entry.state == ProducerState::Retired {
            entries.remove(&key);
        }
        self.changed.notify_waiters();
        integrity_lost
    }
    pub(crate) fn recovery_candidate(
        &self,
        key: OperationKey,
    ) -> Option<DisconnectedRecoveryProof> {
        let entries = self.entries.lock().ok()?;
        let source = entries.get(&key)?;
        let deadline = source.retirement_deadline?;
        let ledger = source.journal.ledger();
        let proof = DisconnectedRecoveryProof {
            key,
            ledger,
            deadline,
        };
        proof.check().ok()?;
        if !source.result_fixed
            || !entries.values().all(|entry| {
                entry.state == ProducerState::DisconnectedRetired
                    || (std::sync::Arc::ptr_eq(&entry.journal.ledger(), proof.ledger())
                        && entry.state == ProducerState::IntegrityLost
                        && entry.integrity_reason
                            == Some(RetentionIntegrityReason::RemoteConnectionLost)
                        && entry.journal.snapshot().local_producers_finished
                        && entry.journal.snapshot().submission_revoked
                        && entry.journal.local_integrity_intact())
            })
        {
            return None;
        }
        Some(proof)
    }
    /// Called only after exact native old-owner/runtime retirement and verified
    /// replacement binding. Keep journals, debt and immutable Unknown receipts.
    pub(crate) fn retire_disconnected_owner(
        &self,
        proof: &DisconnectedRecoveryProof,
    ) -> Result<(), ProtocolError> {
        proof.check()?;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if !entries
            .values()
            .filter(|entry| std::sync::Arc::ptr_eq(&entry.journal.ledger(), proof.ledger()))
            .all(|entry| {
                entry.result_fixed
                    && entry.state == ProducerState::IntegrityLost
                    && entry.integrity_reason
                        == Some(RetentionIntegrityReason::RemoteConnectionLost)
                    && entry.journal.snapshot().local_producers_finished
                    && entry.journal.snapshot().submission_revoked
                    && entry.journal.local_integrity_intact()
            })
        {
            return Err(ProtocolError::CleanupFailed);
        }
        if !entries.contains_key(&proof.key) {
            return Err(ProtocolError::OperationMissing);
        }
        for entry in entries
            .values_mut()
            .filter(|entry| std::sync::Arc::ptr_eq(&entry.journal.ledger(), proof.ledger()))
        {
            entry.state = ProducerState::DisconnectedRetired;
        }
        self.changed.notify_waiters();
        Ok(())
    }
    pub(crate) fn disconnected_failure_retired(&self, key: OperationKey) -> bool {
        self.entries.lock().is_ok_and(|entries| {
            entries
                .get(&key)
                .is_some_and(|entry| entry.state == ProducerState::DisconnectedRetired)
        })
    }
    pub(crate) fn disconnected_failure_matches(
        &self,
        key: OperationKey,
        proof: &DisconnectedRecoveryProof,
    ) -> bool {
        self.entries.lock().is_ok_and(|entries| {
            entries.get(&key).is_some_and(|entry| {
                std::sync::Arc::ptr_eq(&entry.journal.ledger(), proof.ledger())
                    && entry.integrity_reason
                        == Some(RetentionIntegrityReason::RemoteConnectionLost)
                    && entry.journal.snapshot().local_producers_finished
                    && entry.journal.local_integrity_intact()
            })
        })
    }
    pub(crate) fn fix_result(&self, key: OperationKey) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if let Some(entry) = entries.get_mut(&key) {
            entry
                .journal
                .ledger()
                .eval_operation_terminal(key, false, true);
            entry.result_fixed = true;
            if entry.state == ProducerState::Retired {
                entries.remove(&key);
            }
        }
        self.changed.notify_waiters();
    }
    /// Returns true only when this exact live producer missed its fixed bound.
    pub(crate) fn expire(&self, key: OperationKey, now: Instant) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return true;
        };
        if entries.get(&key).is_some_and(|entry| {
            entry.state == ProducerState::Retiring
                && entry.retirement_deadline.is_some_and(|limit| now >= limit)
        }) {
            Self::fail_eval_windows(&entries);
        }
        let Some(entry) = entries.get_mut(&key) else {
            return false;
        };
        if entry.state == ProducerState::Retiring
            && entry.retirement_deadline.is_some_and(|limit| now >= limit)
        {
            entry
                .journal
                .record_cleanup_disposition(CleanupDisposition::IntegrityLost);
            entry.state = ProducerState::IntegrityLost;
            entry.integrity_reason = Some(RetentionIntegrityReason::RetirementDeadline);
            entry.disposition = None;
            self.changed.notify_waiters();
            return true;
        }
        false
    }
    pub(crate) fn status(&self, key: OperationKey) -> OperationRetentionStatus {
        let Ok(entries) = self.entries.lock() else {
            return OperationRetentionStatus::IntegrityLost(
                RetentionIntegrityReason::RegistryUnavailable,
            );
        };
        let Some(entry) = entries.get(&key) else {
            return OperationRetentionStatus::NotRegistered;
        };
        let snapshot = entry.journal.snapshot();
        if snapshot.integrity_lost
            || entry.state == ProducerState::IntegrityLost
            || entry.state == ProducerState::Retiring
                && entry
                    .retirement_deadline
                    .is_some_and(|limit| Instant::now() >= limit)
        {
            return OperationRetentionStatus::IntegrityLost(entry.integrity_reason.unwrap_or(
                if snapshot.integrity_lost {
                    RetentionIntegrityReason::OwnerAccountingLost
                } else {
                    RetentionIntegrityReason::RetirementDeadline
                },
            ));
        }
        let mutation_dispatched = snapshot.mutation_dispatched;
        if !snapshot.submission_revoked {
            return OperationRetentionStatus::KnownActive {
                mutation_dispatched,
            };
        }
        if snapshot.input_debt > super::client_debt::MAX_INPUT_DEBT
            || snapshot.object_debt > super::client_debt::MAX_OBJECT_DEBT
        {
            return OperationRetentionStatus::IntegrityLost(
                RetentionIntegrityReason::OwnerAccountingLost,
            );
        }
        let retired = entry.state == ProducerState::Retired
            && snapshot.local_producers_finished
            && entry.disposition.is_some();
        if !retired && entry.state != ProducerState::Retiring {
            return OperationRetentionStatus::KnownActive {
                mutation_dispatched,
            };
        }
        let Some(retirement_deadline) = entry.retirement_deadline else {
            return OperationRetentionStatus::KnownActive {
                mutation_dispatched,
            };
        };
        let proof = OperationRetentionProof {
            key,
            retirement_deadline,
            descriptor: RetentionDescriptor {
                version: 1,
                retired_operation_seq: key.operation_seq,
                producer_state: if retired {
                    RetentionProducerState::Retired
                } else {
                    RetentionProducerState::Retiring
                },
                input_debt: snapshot.input_debt,
                object_debt: snapshot.object_debt,
            },
        };
        if retired {
            OperationRetentionStatus::Retired {
                mutation_dispatched,
                proof,
            }
        } else {
            OperationRetentionStatus::KnownRetiring {
                mutation_dispatched,
                proof,
            }
        }
    }
    /// Recheck after input/UI acquisition. A prior mutation may have released
    /// its guards just before its retained owner classifies the result. Refuse
    /// that tiny completion gap as well as an already-known retirement; the
    /// next explicit request can retry after the immutable result is fixed.
    pub(crate) fn input_dispatch_ready(&self, key: OperationKey) -> Result<bool, ProtocolError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        Self::entries_input_ready(&entries, key, None)
    }
    fn entries_input_ready(
        entries: &HashMap<OperationKey, Entry>,
        key: OperationKey,
        eval_root: Option<OperationKey>,
    ) -> Result<bool, ProtocolError> {
        if entries
            .get(&key)
            .is_some_and(|entry| entry.state == ProducerState::DisconnectedRetired)
        {
            return Err(ProtocolError::StaleScope);
        }
        for (other, entry) in entries.iter() {
            if entry.state == ProducerState::DisconnectedRetired {
                continue;
            }
            let snapshot = entry.journal.snapshot();
            if snapshot.integrity_lost || entry.state == ProducerState::IntegrityLost {
                return Err(ProtocolError::ScopeUnavailable);
            }
            if *other == key {
                continue;
            }
            if Some(*other) == eval_root {
                if entry.state != ProducerState::Running
                    || snapshot.submission_revoked
                    || snapshot.local_producers_finished
                    || !snapshot.mutation_dispatched
                {
                    return Ok(false);
                }
                continue;
            }
            if entry.state == ProducerState::Retiring
                || entry.state == ProducerState::Retired
                    && entry.retirement_deadline.is_some()
                    && !entry.result_fixed
                || matches!(
                    entry.state,
                    ProducerState::Running | ProducerState::RegisteredNotDispatched
                ) && snapshot.mutation_dispatched
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub(crate) fn application_ready(&self) -> Result<bool, ProtocolError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        for entry in entries.values() {
            if entry.state == ProducerState::DisconnectedRetired {
                continue;
            }
            if entry.state == ProducerState::IntegrityLost
                || entry.journal.snapshot().integrity_lost
            {
                return Err(ProtocolError::ScopeUnavailable);
            }
            if entry.state == ProducerState::Retiring
                || entry.state == ProducerState::Retired
                    && entry.retirement_deadline.is_some()
                    && !entry.result_fixed
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::super::client_debt::OwnerDebtLedger;
    use super::*;
    fn journal(seq: u64) -> OperationJournalHandle {
        OwnerDebtLedger::new(1, "scope".into())
            .operation(
                OperationKey {
                    generation: 1,
                    operation_seq: seq,
                },
                "page".into(),
                "session".into(),
            )
            .unwrap()
    }
    fn eval_operation(
        ledger: &std::sync::Arc<OwnerDebtLedger>,
        sequence: u64,
    ) -> (
        super::super::client_session::OperationLease,
        OperationJournalHandle,
    ) {
        let (_send, cancellation) =
            tokio::sync::watch::channel(super::super::client_session::CancelSignal::None);
        let op = super::super::client_session::OperationLease {
            generation: 1,
            sequence,
            deadline: Instant::now() + Duration::from_secs(5),
            cancellation,
            is_callback: false,
        };
        let journal = ledger
            .operation(
                OperationKey {
                    generation: 1,
                    operation_seq: sequence,
                },
                "page".into(),
                "session".into(),
            )
            .unwrap();
        journal.bind_operation(&op).unwrap();
        (op, journal)
    }
    fn eval_stamp(ledger: &OwnerDebtLedger) -> EvalAuthorityStamp {
        EvalAuthorityStamp {
            revision: ledger.eval_authority_revision().unwrap(),
            target: "page".into(),
            session: "session".into(),
            frame: "frame".into(),
            loader: "loader".into(),
        }
    }
    #[tokio::test]
    async fn eval_family_exception_is_exact_root_only_and_retirement_revokes_reserved_child() {
        use super::super::client_debt::{eval_command_scope, EvalCommandGrant};
        let registry = OperationRegistry::default();
        let ledger = OwnerDebtLedger::new(1, "scope".into());
        let (root, journal) = eval_operation(&ledger, 1);
        registry.register(journal.clone()).unwrap();
        registry.running(journal.key());
        let window = registry
            .prepare_eval_window(&journal, &root, eval_stamp(&ledger))
            .unwrap();
        window.bind_root(&root).unwrap();
        let params = serde_json::json!({"expression":"1","awaitPromise":true,"returnByValue":true,"userGesture":true});
        let _command = eval_command_scope(EvalCommandGrant::Root(window.clone()), async {
            ledger
                .reserve_command(
                    Some(&journal),
                    "Runtime.evaluate",
                    Some(&params),
                    Some("session"),
                )
                .unwrap()
                .submit()
                .unwrap()
        })
        .await;
        let (mut child, child_journal) = eval_operation(&ledger, 2);
        child.is_callback = true;
        child.deadline = root.deadline;
        registry.register(child_journal.clone()).unwrap();
        registry.running(child_journal.key());
        let permit = window.issue_child(&child).unwrap();
        assert!(
            !registry.input_dispatch_ready(child_journal.key()).unwrap(),
            "normal gate still refuses root debt"
        );
        registry.check_eval_dispatch(&permit).unwrap();
        let (_, unrelated) = eval_operation(&ledger, 3);
        registry.register(unrelated.clone()).unwrap();
        registry.running(unrelated.key());
        registry.retire(unrelated.key()).unwrap();
        assert!(
            registry.check_eval_dispatch(&permit).is_err(),
            "unrelated retirement is never exempted"
        );
        assert_eq!(ledger.snapshot().input_debt, 1);
    }
    #[test]
    fn eval_provisional_is_abandoned_for_unrelated_zero_debt_unfixed_result() {
        let registry = OperationRegistry::default();
        let ledger = OwnerDebtLedger::new(1, "scope".into());
        let (root, journal) = eval_operation(&ledger, 1);
        let (_, unrelated) = eval_operation(&ledger, 2);
        registry.register(journal.clone()).unwrap();
        registry.running(journal.key());
        registry.register(unrelated.clone()).unwrap();
        registry.running(unrelated.key());
        registry.retire(unrelated.key()).unwrap();
        registry.finish(unrelated.key(), false);
        assert_eq!(ledger.snapshot().input_debt, 0);
        assert!(registry
            .prepare_eval_window(&journal, &root, eval_stamp(&ledger))
            .is_err());
        registry.fix_result(unrelated.key());
        let window = registry
            .prepare_eval_window(&journal, &root, eval_stamp(&ledger))
            .unwrap();
        ledger.abandon_eval_preparation(&window);
    }

    #[test]
    fn late_finish_cannot_erase_fixed_unknown_before_expiry_monitor_runs() {
        let registry = OperationRegistry::default();
        let handle = journal(1);
        let key = handle.key();
        registry.register(handle).unwrap();
        registry.running(key);
        registry.retire(key).unwrap();
        registry.fix_result(key);
        registry
            .entries
            .lock()
            .unwrap()
            .get_mut(&key)
            .unwrap()
            .retirement_deadline = Some(Instant::now() - Duration::from_millis(1));
        assert!(registry.finish(key, false));
        assert!(matches!(
            registry.status(key),
            OperationRetentionStatus::IntegrityLost(RetentionIntegrityReason::RetirementDeadline)
        ));
        assert!(registry.entries.lock().unwrap().contains_key(&key));
        assert!(registry.status(key).proof().is_none());
    }

    #[test]
    fn completed_producer_is_not_retroactively_expired_by_duplicate_finish() {
        let registry = OperationRegistry::default();
        let handle = journal(1);
        let key = handle.key();
        registry.register(handle).unwrap();
        registry.running(key);
        registry.retire(key).unwrap();
        assert!(!registry.finish(key, false));
        registry
            .entries
            .lock()
            .unwrap()
            .get_mut(&key)
            .unwrap()
            .retirement_deadline = Some(Instant::now() - Duration::from_millis(1));
        assert!(!registry.finish(key, false));
        assert!(matches!(
            registry.status(key),
            OperationRetentionStatus::Retired { .. }
        ));
    }

    #[test]
    fn no_registration_or_waiter_loss_can_invent_clean_proof() {
        let registry = OperationRegistry::default();
        let key = OperationKey {
            generation: 1,
            operation_seq: 1,
        };
        assert!(matches!(
            registry.status(key),
            OperationRetentionStatus::NotRegistered
        ));
        registry.register(journal(1)).unwrap();
        assert!(registry.status(key).proof().is_none());
        assert_eq!(registry.status(key).mutation_dispatched(), Some(false));
        assert!(registry.retire(key).is_some());
        assert!(matches!(
            registry.status(key),
            OperationRetentionStatus::KnownRetiring {
                mutation_dispatched: false,
                ..
            }
        ));
        assert!(!registry.application_ready().unwrap());
        registry.fix_result(key);
        assert!(
            registry.status(key).proof().is_some(),
            "live producer is not evicted by result delivery"
        );
        registry.finish(key, false);
        assert!(matches!(
            registry.status(key),
            OperationRetentionStatus::NotRegistered
        ));
    }
    #[test]
    fn mutation_marker_survives_zero_debt_and_retirement_is_not_extendable() {
        let registry = OperationRegistry::default();
        let journal = journal(2);
        let key = journal.key();
        registry.register(journal.clone()).unwrap();
        journal.mark_mutation_maybe_submitted().unwrap();
        let bound = registry.retire(key).unwrap();
        assert_eq!(bound, registry.retire(key).unwrap());
        assert_eq!(registry.status(key).mutation_dispatched(), Some(true));
        assert!(registry.expire(key, bound));
        registry.finish(key, false);
        assert!(matches!(
            registry.status(key),
            OperationRetentionStatus::IntegrityLost(_)
        ));
        assert!(registry.application_ready().is_err());
    }
    #[test]
    fn exact_retired_proof_does_not_transfer_to_sibling_operation() {
        let registry = OperationRegistry::default();
        let journal = journal(3);
        let key = journal.key();
        registry.register(journal).unwrap();
        registry.retire(key);
        registry.finish(key, false);
        let proof = registry.status(key).proof().unwrap();
        assert!(proof.matches(key));
        assert!(!proof.matches(OperationKey {
            generation: 1,
            operation_seq: 4
        }));
        assert!(!proof.matches(OperationKey {
            generation: 2,
            operation_seq: 3
        }));
        assert_eq!(
            proof.descriptor().producer_state,
            RetentionProducerState::Retired
        );
        assert!(!registry.application_ready().unwrap());
        registry.fix_result(key);
        assert!(registry.application_ready().unwrap());
    }
    #[test]
    fn capacity_never_evicts_a_live_or_unfixed_operation() {
        let registry = OperationRegistry::default();
        for sequence in 1..=MAX_RETAINED_OPERATIONS as u64 {
            registry.register(journal(sequence)).unwrap();
        }
        assert_eq!(
            registry.register(journal(65)),
            Err(ProtocolError::CapacityExceeded)
        );
        let key = OperationKey {
            generation: 1,
            operation_seq: 1,
        };
        registry.retire(key);
        registry.fix_result(key);
        assert_eq!(
            registry.register(journal(66)),
            Err(ProtocolError::CapacityExceeded)
        );
        registry.finish(key, false);
        registry.register(journal(67)).unwrap();
    }
    #[test]
    fn mutation_completion_gap_and_publication_pending_both_block_new_input() {
        let registry = OperationRegistry::default();
        let first = journal(1);
        let first_key = first.key();
        let second = journal(2);
        let second_key = second.key();
        registry.register(first.clone()).unwrap();
        registry.running(first_key);
        registry.register(second).unwrap();
        registry.running(second_key);
        first.mark_mutation_maybe_submitted().unwrap();
        assert!(!registry.input_dispatch_ready(second_key).unwrap());
        registry.retire(first_key);
        registry.finish(first_key, false);
        assert!(!registry.input_dispatch_ready(second_key).unwrap());
        assert!(!registry.application_ready().unwrap());
        registry.fix_result(first_key);
        assert!(registry.input_dispatch_ready(second_key).unwrap());
        assert!(registry.application_ready().unwrap());
    }
}
