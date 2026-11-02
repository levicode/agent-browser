//! Bounded one-use read continuation metadata. It never retains a page lease.
use super::*;
use crate::native::client_debt::OperationKey;
use crate::native::client_protocol::ObserveContinuationDescriptor;

impl ObservationDispatch {
    // Fixed-size binding avoids retaining unbounded caller strings per owner.
    pub(super) fn observe_request_digest(request: &ObserveRequest) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update([
            u8::from(request.options.pixels),
            u8::from(request.options.pixel_fallback),
            u8::from(request.options.comparable),
        ]);
        for field in [&request.test_id_attribute, &request.secure_field_selector] {
            digest.update((field.len() as u64).to_le_bytes());
            digest.update(field.as_bytes());
        }
        digest.finalize().into()
    }

    pub(super) fn clear_observe_continuation(capture: Option<&Arc<CaptureAdmission>>) {
        if let Some(capture) = capture {
            if let Ok(mut state) = capture.continuation.lock() {
                *state = None;
            }
        }
    }
    pub(super) fn mark_observe_continuation(capture: Option<&Arc<CaptureAdmission>>) {
        if let Some(capture) = capture {
            if let Ok(mut state) = capture.continuation.lock() {
                if let Some(state) = state.as_mut() {
                    if state.phase == ObserveContinuationPhase::Initial {
                        state.phase = ObserveContinuationPhase::Eligible;
                    }
                }
            }
        }
    }
    /// Re-read exact owner and full debt at each authorization boundary.
    pub(super) fn continuation_owner_settled(owner: &CaptureOwner, sequence: u64) -> bool {
        let (Some(client), Some(targets)) = (owner.client.upgrade(), owner.targets.upgrade())
        else {
            return false;
        };
        if targets.identity_scope != owner.scope.identity_scope
            || targets.inventory().is_err()
            || !targets.owned_target(&owner.target_id).is_ok_and(|current| {
                owner.attachment.same_attachment(&current) && current.capture_ready()
            })
        {
            return false;
        }
        let Some(ledger) = client.debt_ledger() else {
            return false;
        };
        if !ledger.matches_owner(owner.scope.generation, &owner.scope.identity_scope)
            || client.check_cleanup_owner(&Some(ledger.clone())).is_err()
            || ledger
                .check_admission(super::super::client_debt::AdmissionClass::Reference)
                .is_err()
            || ledger.operation_has_rejected_cleanup(
                OperationKey {
                    generation: owner.scope.generation,
                    operation_seq: sequence,
                },
                &owner.scope.identity_scope,
            ) != Ok(false)
        {
            return false;
        }
        let debt = ledger.snapshot();
        !debt.integrity_lost
            && debt.input_debt == 0
            && debt.object_debt == 0
            && debt.outstanding_commands == 0
    }
    /// Transport invokes this only after original cleanup/join and usable broker settlement.
    /// Refused or late candidates are permanently consumed; late ACKs cannot revive one.
    pub(crate) fn offer_observe_continuation(
        &self,
        settlement: super::super::client_session::ObservationSettlement,
    ) -> Option<ObserveContinuationDescriptor> {
        let key = settlement.key();
        let authority = self.captures.lock().ok()?;
        let capture = authority.latest.iter().find(|entry| {
            entry.sequence == key.operation_seq && entry.owner.scope.generation == key.generation
        })?;
        let mut slot = capture.continuation.lock().ok()?;
        let state = slot.as_mut()?;
        if state.phase != ObserveContinuationPhase::Eligible {
            return None;
        }
        state.phase = ObserveContinuationPhase::Consumed;
        if !settlement.matches(state.deadline, &state.cancellation)
            || state.retirement_fence != authority.retirement_fence
            || *capture.retired.borrow()
            || Instant::now() >= state.deadline
            || !Self::continuation_owner_settled(&capture.owner, capture.sequence)
        {
            return None;
        }
        state.phase = ObserveContinuationPhase::Offered;
        Some(state.descriptor.clone())
    }
    /// Admission shortens the next actual operation's deadline before any browser work.
    pub(crate) fn observe_deadline_cap(
        &self,
        generation: u64,
        sequence: u64,
        args: &serde_json::Map<String, Value>,
    ) -> Result<Option<Instant>, ProtocolError> {
        let Some(value) = args.get("continuation") else {
            return Ok(None);
        };
        let descriptor: ObserveContinuationDescriptor =
            serde_json::from_value(value.clone()).map_err(|_| ProtocolError::InvalidArguments)?;
        let authority = self
            .captures
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let capture = authority
            .latest
            .iter()
            .find(|entry| {
                entry.sequence == descriptor.retired_operation_seq
                    && entry.owner.scope.generation == generation
            })
            .ok_or(ProtocolError::StaleScope)?;
        let mut slot = capture
            .continuation
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let state = slot.as_mut().ok_or(ProtocolError::StaleScope)?;
        let offered = state.phase == ObserveContinuationPhase::Offered;
        // Burn at first admission attempt, including broker capacity/cancel failures.
        state.phase = ObserveContinuationPhase::Reserved(sequence);
        let mut original = args.clone();
        original.remove("identityScope");
        original.remove("continuation");
        let original: Result<ObserveRequest, _> = serde_json::from_value(Value::Object(original));
        if !offered
            || sequence <= descriptor.retired_operation_seq
            || descriptor != state.descriptor
            || original.as_ref().ok().map(Self::observe_request_digest)
                != Some(state.request_digest)
            || args.get("identityScope").and_then(Value::as_str)
                != Some(capture.owner.scope.identity_scope.as_str())
            || state.retirement_fence != authority.retirement_fence
            || *capture.retired.borrow()
            || !Self::continuation_owner_settled(&capture.owner, capture.sequence)
        {
            state.phase = ObserveContinuationPhase::Consumed;
            return Err(ProtocolError::StaleScope);
        }
        if Instant::now() >= state.deadline {
            state.phase = ObserveContinuationPhase::Consumed;
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(Some(state.deadline))
    }
}
