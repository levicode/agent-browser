//! Failure-only, opt-in query receipts. No renderer data or authority is retained.
use super::{ObservationError, OperationLease};
use crate::native::client_settlement_trace::{self as trace, ObservationReadError, QueryReadStage};
use std::sync::Mutex;

pub(super) struct QueryReadWitness {
    enabled: bool,
    generation: u64,
    sequence: u64,
    state: Mutex<(QueryReadStage, bool)>,
}
impl QueryReadWitness {
    pub(super) fn new(lease: &OperationLease) -> Self {
        Self { enabled: trace::query_diagnostics_enabled(), generation: lease.generation,
            sequence: lease.sequence, state: Mutex::new((QueryReadStage::FrameEntry, false)) }
    }
    pub(super) fn disabled(lease: &OperationLease) -> Self {
        let mut witness = Self::new(lease); witness.enabled = false; witness
    }
    pub(super) fn stage(&self, stage: QueryReadStage) {
        if self.enabled {
            if let Ok(mut state) = self.state.lock() { if !state.1 { state.0 = stage; } }
        }
    }
    /// Called only on the actual returned Result. The evaluate-query object group
    /// is observed before its own cleanup. Nested helpers may already return a
    /// CleanupFailed wrapper; classify records that actual boundary error and
    /// does not claim an unobserved deeper primary cause.
    /// Success never consumes the first-failure slot. Diagnostic loss is not success.
    pub(super) fn observe<T>(&self, result: &Result<T, ObservationError>) {
        if !self.enabled { return; }
        let Err(error) = result else { return; };
        let stage = {
            let Ok(mut state) = self.state.lock() else { return; };
            if state.1 { return; }
            state.1 = true;
            state.0
        };
        trace::query_read_failure(self.generation, self.sequence, stage, classify(error));
    }
}
fn classify(error: &ObservationError) -> ObservationReadError {
    match error {
        ObservationError::InvalidArguments => ObservationReadError::InvalidArguments,
        ObservationError::InvalidLocator => ObservationReadError::InvalidLocator,
        ObservationError::FrameNotFound(_) => ObservationReadError::FrameNotFound,
        ObservationError::FrameAmbiguous(_) => ObservationReadError::FrameAmbiguous,
        ObservationError::UnsupportedCapability => ObservationReadError::UnsupportedCapability,
        ObservationError::StaleReference => ObservationReadError::StaleReference,
        ObservationError::Superseded => ObservationReadError::Superseded,
        ObservationError::Cancelled => ObservationReadError::Cancelled,
        ObservationError::DeadlineExceeded => ObservationReadError::DeadlineExceeded,
        ObservationError::BackendFailure => ObservationReadError::BackendFailure,
        ObservationError::PolicyDenied => ObservationReadError::PolicyDenied,
        ObservationError::ResourceLimit => ObservationReadError::ResourceLimit,
        ObservationError::CleanupFailed { .. } => ObservationReadError::CleanupFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn witness() -> QueryReadWitness {
        QueryReadWitness { enabled: true, generation: 1, sequence: 2,
            state: Mutex::new((QueryReadStage::Ax, false)) }
    }
    #[test]
    fn success_does_not_consume_first_failure_and_cleanup_cannot_replace_it() {
        let witness = witness();
        witness.observe(&Ok::<_, ObservationError>(()));
        assert!(!witness.state.lock().unwrap().1);
        witness.stage(QueryReadStage::Metadata);
        let original = Err::<(), _>(ObservationError::BackendFailure);
        witness.observe(&original);
        assert!(matches!(original, Err(ObservationError::BackendFailure)));
        assert!(witness.state.lock().unwrap().1);
        witness.stage(QueryReadStage::Cleanup);
        witness.observe(&Err::<(), _>(ObservationError::CleanupFailed { primary: None }));
        // Already consumed: no second receipt or replacement stage.
        assert_eq!(*witness.state.lock().unwrap(), (QueryReadStage::Metadata, true));
    }
    #[test]
    fn disabled_diagnostic_does_not_consume_error() {
        let mut witness = witness(); witness.enabled = false;
        witness.observe(&Err::<(), _>(ObservationError::BackendFailure));
        assert!(!witness.state.lock().unwrap().1);
    }
}
