// Private rendezvous inside the original reset/restore operation. No new RPC
// lease, lifecycle supervisor, browser transport, or ordinary cleanup budget.
use super::super::client_protocol::Decision;
use super::super::client_session::{DecisionKind, DecisionOutcome, DecisionOwner, OperationLease};
use super::*;

pub(super) async fn rendezvous(
    broker: &Arc<super::super::client_session::ClientSession>,
    sink: &super::super::client_transport::ClientEventSink,
    operation: &OperationLease,
    scope: &str,
    kind: DecisionKind,
    context_id: Option<&str>,
) -> Result<Decision, ProtocolError> {
    check_lifecycle_budget(operation)?;
    let left = operation
        .deadline
        .saturating_duration_since(std::time::Instant::now());
    let timeout = u64::try_from(left.as_millis())
        .unwrap_or(super::super::client_protocol::MAX_TIMEOUT_MS)
        .min(super::super::client_protocol::MAX_TIMEOUT_MS)
        .max(1);
    let mut lease = broker.decision(
        operation.generation,
        DecisionOwner::Operation(operation.sequence),
        kind,
        timeout,
        None,
    )?;
    if let Err(error) = sink.emit_interop_decision(operation, scope, kind, &lease, context_id) {
        let _ = broker.revoke_decision(&lease.token);
        return Err(error);
    }
    let mut cancel = operation.cancellation.clone();
    let result = tokio::select! {
        biased;
        _ = cancel.changed() => Err(ProtocolError::Cancelled),
        _ = tokio::time::sleep_until(operation.deadline.into()) => Err(ProtocolError::DeadlineExceeded),
        response = &mut lease.outcome => match response {
            Ok(DecisionOutcome::Selected(Decision::InteropFailed {})) => Err(ProtocolError::BrowserFailure),
            Ok(DecisionOutcome::Selected(decision)) => Ok(decision),
            Ok(DecisionOutcome::Expired) => Err(ProtocolError::DeadlineExceeded),
            Ok(DecisionOutcome::Cancelled | DecisionOutcome::SessionClosed) => Err(ProtocolError::Cancelled),
            _ => Err(ProtocolError::DecisionKindMismatch),
        },
    };
    let _ = broker.revoke_decision(&lease.token);
    check_lifecycle_budget(operation)?;
    result
}
