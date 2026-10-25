//! Bounded, owner-local custody of protected-read cleanup coordinates.
//! A record is not a cleanup receipt, execution permit or retry continuation.
use super::cdp::client::CdpClient;
use super::client_debt::{OperationKey, OwnerDebtLedger};
use super::client_protocol::ProtocolError;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc, Mutex, OnceLock,
};

const ACTIVE: u8 = 0;
const RESIDUAL: u8 = 1;
const RESTORED: u8 = 2;
const DESTROYED: u8 = 3;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BindingMode {
    LegacyRecordOnly,
    Managed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RawState {
    NotStarted,
    Pending,
    SuccessfulReply,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaskStep {
    InstalledOrUnknown,
    Removed,
    GroupReleased,
}
#[derive(Clone)]
pub(crate) struct MaskRecord {
    pub session: String,
    pub holder: Option<String>,
    pub group: String,
    pub step: MaskStep,
}
#[derive(Clone)]
pub(crate) struct RateRecord {
    pub session: String,
    pub original: f64,
    pub acknowledged: bool,
}
pub(crate) struct Records {
    pub masks: Vec<MaskRecord>,
    pub rates: Vec<RateRecord>,
    pub raw: RawState,
}
pub(crate) struct Record {
    pub operation: OperationKey,
    pub raw_session: String,
    pub data: Mutex<Records>,
    state: AtomicU8,
}
impl Record {
    pub(crate) fn leave_residual(&self) {
        let _ = self
            .state
            .compare_exchange(ACTIVE, RESIDUAL, Ordering::SeqCst, Ordering::SeqCst);
    }
    pub(crate) fn has_effects(&self) -> bool {
        self.data.lock().map_or(true, |data| {
            !data.masks.is_empty() || !data.rates.is_empty() || data.raw != RawState::NotStarted
        })
    }
}
struct Binding {
    client: Arc<CdpClient>,
    ledger: Option<Arc<OwnerDebtLedger>>,
    generation: u64,
}
pub(crate) struct ProtectedReadResidualSlot {
    mode: BindingMode,
    context_id: String,
    identity_scope: String,
    binding: OnceLock<Binding>,
    record: Mutex<Option<Arc<Record>>>,
}
fn same_ledger(a: &Option<Arc<OwnerDebtLedger>>, b: &Option<Arc<OwnerDebtLedger>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}
impl ProtectedReadResidualSlot {
    pub(crate) fn new(mode: BindingMode, context_id: String, identity_scope: String) -> Self {
        Self {
            mode,
            context_id,
            identity_scope,
            binding: OnceLock::new(),
            record: Mutex::new(None),
        }
    }
    pub(crate) fn reserve(
        &self,
        operation: OperationKey,
        raw_session: &str,
        client: Arc<CdpClient>,
    ) -> Result<Arc<Record>, ProtocolError> {
        let ledger = client.debt_ledger();
        if self.mode == BindingMode::Managed && ledger.is_none() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if self.mode == BindingMode::Managed
            && ledger.as_ref().is_some_and(|ledger| {
                !ledger.matches_owner(operation.generation, &self.identity_scope)
                    || ledger.bound_context().as_deref().unwrap_or("") != self.context_id
            })
        {
            return Err(ProtocolError::StaleScope);
        }
        let _ = self.binding.set(Binding {
            client: client.clone(),
            ledger: ledger.clone(),
            generation: operation.generation,
        });
        let owner = self.binding.get().ok_or(ProtocolError::ScopeUnavailable)?;
        if !Arc::ptr_eq(&owner.client, &client)
            || !same_ledger(&owner.ledger, &ledger)
            || owner.generation != operation.generation
        {
            return Err(ProtocolError::StaleScope);
        }
        let mut slot = self
            .record
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if slot.is_some() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let record = Arc::new(Record {
            operation,
            raw_session: raw_session.to_owned(),
            data: Mutex::new(Records {
                masks: Vec::new(),
                rates: Vec::new(),
                raw: RawState::NotStarted,
            }),
            state: AtomicU8::new(ACTIVE),
        });
        *slot = Some(record.clone());
        Ok(record)
    }
    pub(crate) fn finish_restored(&self, expected: &Arc<Record>) -> Result<(), ProtocolError> {
        let complete = {
            let data = expected
                .data
                .lock()
                .map_err(|_| ProtocolError::CleanupFailed)?;
            matches!(data.raw, RawState::NotStarted | RawState::SuccessfulReply)
                && data
                    .masks
                    .iter()
                    .all(|mask| mask.step == MaskStep::GroupReleased)
                && data.rates.iter().all(|rate| rate.acknowledged)
        };
        if !complete {
            expected.leave_residual();
            return Err(ProtocolError::CleanupFailed);
        }
        let mut slot = self
            .record
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?;
        if slot
            .as_ref()
            .is_none_or(|actual| !Arc::ptr_eq(actual, expected))
            || expected.state.load(Ordering::SeqCst) != ACTIVE
        {
            return Err(ProtocolError::CleanupFailed);
        }
        expected.state.store(RESTORED, Ordering::SeqCst);
        *slot = None;
        Ok(())
    }
    pub(crate) fn replacement_safe(&self) -> Result<(), ProtocolError> {
        let slot = self
            .record
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?;
        if slot
            .as_ref()
            .is_some_and(|record| record.state.load(Ordering::SeqCst) != DESTROYED)
        {
            return Err(ProtocolError::CleanupFailed);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn snapshot_for_test(&self) -> Option<Arc<Record>> {
        self.record.lock().unwrap().clone()
    }
    // Only exact native lifecycle sites may call after actual dispose ACK AND
    // ledger.retire_after_context_destroy. This never retires ledger debt itself.
    pub(crate) fn record_exact_context_destroyed(
        &self,
        client: &Arc<CdpClient>,
        ledger: &Arc<OwnerDebtLedger>,
        context: &str,
    ) -> Result<(), ProtocolError> {
        let slot = self
            .record
            .lock()
            .map_err(|_| ProtocolError::CleanupFailed)?;
        let Some(record) = slot.as_ref() else {
            return Ok(());
        };
        let owner = self.binding.get().ok_or(ProtocolError::CleanupFailed)?;
        if self.mode != BindingMode::Managed
            || context != self.context_id
            || !Arc::ptr_eq(&owner.client, client)
            || owner
                .ledger
                .as_ref()
                .is_none_or(|actual| !Arc::ptr_eq(actual, ledger))
            || client
                .debt_ledger()
                .is_none_or(|actual| !Arc::ptr_eq(&actual, ledger))
            || !ledger.matches_owner(record.operation.generation, &self.identity_scope)
            || ledger.bound_context().as_deref() != Some(context)
        {
            return Err(ProtocolError::StaleScope);
        }
        record.state.store(DESTROYED, Ordering::SeqCst);
        Ok(())
    }
}
