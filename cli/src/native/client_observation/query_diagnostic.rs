//! Failure-only, opt-in query receipts. No renderer data or authority is retained.
use super::{ObservationError, OperationLease};
use crate::native::client_protocol::ProtocolError;
use crate::native::client_settlement_trace::{self as trace, ObservationReadError, QueryReadStage};
use std::sync::Mutex;
use std::time::Instant;

pub(crate) struct QueryReadWitness {
    enabled: bool,
    generation: u64,
    sequence: u64,
    state: Mutex<(QueryReadStage, bool, Option<FieldTiming>)>,
}
impl QueryReadWitness {
    #[cfg(test)]
    pub(crate) fn schema_test(enabled: bool) -> Self {
        Self {
            enabled,
            generation: 1,
            sequence: 2,
            state: Mutex::new((QueryReadStage::CandidatePlan, false, None)),
        }
    }
    #[cfg(test)]
    pub(crate) fn schema_test_stage(&self) -> QueryReadStage {
        self.state.lock().unwrap().0
    }

    pub(crate) fn new(lease: &OperationLease) -> Self {
        Self {
            enabled: trace::query_diagnostics_enabled(),
            generation: lease.generation,
            sequence: lease.sequence,
            state: Mutex::new((QueryReadStage::FrameEntry, false, None)),
        }
    }
    /// One fixed-size timer owned by the existing read-fields dispatch. Disabled
    /// capture does not read the clock, lock state, allocate output, or read budget.
    pub(crate) fn field_dispatch(lease: &OperationLease) -> Self {
        let mut witness = Self::new(lease);
        if witness.enabled {
            witness.state = Mutex::new((
                QueryReadStage::ReadAdmission,
                false,
                Some(FieldTiming::new(Instant::now())),
            ));
        }
        witness
    }
    pub(crate) fn disabled(lease: &OperationLease) -> Self {
        let mut witness = Self::new(lease);
        witness.enabled = false;
        witness
    }
    pub(crate) fn stage(&self, stage: QueryReadStage) {
        if self.enabled {
            if let Ok(mut state) = self.state.lock() {
                if !state.1 {
                    if let Some(timing) = &mut state.2 {
                        timing.advance(stage, Instant::now());
                    }
                    state.0 = stage;
                }
            }
        }
    }
    /// Called only on the actual returned Result. The evaluate-query object group
    /// is observed before its own cleanup. Nested helpers may already return a
    /// CleanupFailed wrapper; classify records that actual boundary error and
    /// does not claim an unobserved deeper primary cause.
    /// Success never consumes the first-failure slot. Diagnostic loss is not success.
    pub(crate) fn observe<T>(&self, result: &Result<T, ObservationError>) {
        if !self.enabled {
            return;
        }
        let Err(error) = result else {
            return;
        };
        let Some((stage, timing)) = self.take_failure() else {
            return;
        };
        trace::query_read_failure(
            self.generation,
            self.sequence,
            stage,
            classify(error),
            timing,
        );
    }
    pub(crate) fn observe_protocol(&self, error: &ProtocolError) {
        let Some((stage, timing)) = self.take_failure() else {
            return;
        };
        trace::query_read_protocol_failure(
            self.generation,
            self.sequence,
            stage,
            error.clone(),
            timing,
        );
    }
    fn take_failure(&self) -> Option<(QueryReadStage, Option<[u16; 13]>)> {
        if !self.enabled {
            return None;
        }
        let mut state = self.state.lock().ok()?;
        if state.1 {
            return None;
        }
        state.1 = true;
        let timing = state.2.as_mut().map(|timing| timing.finish(Instant::now()));
        Some((state.0, timing))
    }
}

/// Cumulative milliseconds, saturated at 65535 per slot. No wall-clock IDs or
/// renderer values. Slots: admission, UI, frames-before, fresh-inventory, world,
/// resolve, sample, group-settlement, fresh-roots-final, fallback, field-final,
/// frames-after, final-authority. Only local monotonic elapsed time is observed.
struct FieldTiming {
    last: Instant,
    bucket: usize,
    micros: [u64; 13],
}
impl FieldTiming {
    fn new(now: Instant) -> Self {
        Self {
            last: now,
            bucket: 0,
            micros: [0; 13],
        }
    }
    fn bucket(stage: QueryReadStage) -> usize {
        use QueryReadStage::*;
        match stage {
            ReadAdmission => 0,
            ReadUi => 1,
            ReadFramesBefore => 2,
            FreshFields | FreshInventory => 3,
            FreshWorld => 4,
            FreshResolve => 5,
            FreshSample => 6,
            FreshCleanup => 7,
            FreshRootsFinal => 8,
            FrameFinal | LeaseFinal => 10,
            ReadFramesAfter => 11,
            ReadPublish => 12,
            _ => 9,
        }
    }
    fn accrue(&mut self, now: Instant) {
        let elapsed = now
            .saturating_duration_since(self.last)
            .as_micros()
            .min(u64::MAX as u128) as u64;
        self.micros[self.bucket] = self.micros[self.bucket].saturating_add(elapsed);
        self.last = now;
    }
    fn advance(&mut self, stage: QueryReadStage, now: Instant) {
        self.accrue(now);
        self.bucket = Self::bucket(stage);
    }
    fn finish(&mut self, now: Instant) -> [u16; 13] {
        self.accrue(now);
        self.micros
            .map(|value| (value / 1000).min(u16::MAX as u64) as u16)
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
        QueryReadWitness {
            enabled: true,
            generation: 1,
            sequence: 2,
            state: Mutex::new((QueryReadStage::Ax, false, None)),
        }
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
        witness.observe(&Err::<(), _>(ObservationError::CleanupFailed {
            primary: None,
        }));
        // Already consumed: no second receipt or replacement stage.
        assert_eq!(
            {
                let state = witness.state.lock().unwrap();
                (state.0, state.1)
            },
            (QueryReadStage::Metadata, true)
        );
    }
    #[test]
    fn disabled_diagnostic_does_not_consume_error() {
        let mut witness = witness();
        witness.enabled = false;
        witness.observe(&Err::<(), _>(ObservationError::BackendFailure));
        assert!(!witness.state.lock().unwrap().1);
    }
    #[test]
    fn timing_accumulates_original_monotonic_intervals_and_saturates() {
        use std::time::Duration;
        let now = Instant::now();
        let mut timing = FieldTiming::new(now);
        timing.advance(QueryReadStage::ReadUi, now + Duration::from_millis(3));
        timing.advance(QueryReadStage::FreshSample, now + Duration::from_millis(8));
        timing.advance(
            QueryReadStage::FreshCleanup,
            now + Duration::from_millis(18),
        );
        let values = timing.finish(now + Duration::from_secs(90));
        assert_eq!(values[0], 3);
        assert_eq!(values[1], 5);
        assert_eq!(values[6], 10);
        assert_eq!(values[7], u16::MAX);
        assert_eq!(values.len(), 13);
    }
    #[test]
    fn disabled_witness_does_not_change_stage_timing_or_consume_protocol_failure() {
        let now = Instant::now();
        let witness = QueryReadWitness {
            enabled: false,
            generation: 1,
            sequence: 2,
            state: Mutex::new((
                QueryReadStage::ReadAdmission,
                false,
                Some(FieldTiming::new(now)),
            )),
        };
        witness.stage(QueryReadStage::FreshSample);
        witness.observe_protocol(&ProtocolError::DeadlineExceeded);
        let state = witness.state.lock().unwrap();
        assert_eq!(state.0, QueryReadStage::ReadAdmission);
        assert!(!state.1);
        assert_eq!(state.2.as_ref().unwrap().last, now);
        assert_eq!(state.2.as_ref().unwrap().micros, [0; 13]);
    }
    #[test]
    fn sample_failure_stays_first_when_cleanup_and_protocol_fail_later() {
        let witness = witness();
        witness.stage(QueryReadStage::FreshSample);
        let primary = Err::<(), _>(ObservationError::DeadlineExceeded);
        witness.observe(&primary);
        witness.stage(QueryReadStage::FreshCleanup);
        witness.observe_protocol(&ProtocolError::CleanupFailed);
        let state = witness.state.lock().unwrap();
        assert_eq!(state.0, QueryReadStage::FreshSample);
        assert!(state.1);
        assert!(matches!(primary, Err(ObservationError::DeadlineExceeded)));
    }
}
