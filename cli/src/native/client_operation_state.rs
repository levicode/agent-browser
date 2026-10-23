//! Bounded status of retained application producers, not browser ownership.
//! Entries never infer clean retirement from a dropped waiter or empty debt.
use super::client_debt::{CleanupDisposition, OperationJournalHandle, OperationKey};
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
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetiredDisposition {
    Complete,
    AccountedRemoteDebt,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetentionIntegrityReason {
    LocalProducerFailed,
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
#[derive(Default)]
pub(crate) struct OperationRegistry {
    entries: Mutex<HashMap<OperationKey, Entry>>,
    pub(crate) changed: Notify,
}
impl OperationRegistry {
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
        let Ok(mut entries) = self.entries.lock() else {
            return true;
        };
        let Some(entry) = entries.get_mut(&key) else {
            return true;
        };
        // Completion and expiry linearize under the same lock. A delayed timer
        // cannot let a late producer erase its already-fixed Unknown receipt.
        let expired = entry.state == ProducerState::Retiring
            && entry
                .retirement_deadline
                .is_some_and(|limit| Instant::now() >= limit);
        if integrity_lost || expired || entry.state == ProducerState::IntegrityLost {
            entry
                .journal
                .record_cleanup_disposition(CleanupDisposition::IntegrityLost);
            entry.state = ProducerState::IntegrityLost;
            entry.integrity_reason.get_or_insert(if expired {
                RetentionIntegrityReason::RetirementDeadline
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
        // This is only called after the retained future, including cleanup,
        // really returned. Neither transport cancellation nor Drop calls it.
        entry.journal.finish_local_producers();
        let integrity_lost = entry.state == ProducerState::IntegrityLost;
        if entry.result_fixed && entry.state == ProducerState::Retired {
            entries.remove(&key);
        }
        self.changed.notify_waiters();
        integrity_lost
    }
    pub(crate) fn fix_result(&self, key: OperationKey) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if let Some(entry) = entries.get_mut(&key) {
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
        for (other, entry) in entries.iter() {
            let snapshot = entry.journal.snapshot();
            if snapshot.integrity_lost || entry.state == ProducerState::IntegrityLost {
                return Err(ProtocolError::ScopeUnavailable);
            }
            if *other == key {
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
