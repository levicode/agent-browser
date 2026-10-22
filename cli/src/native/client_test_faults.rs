//! Acceptance-only scheduling faults. This module is absent from normal builds.
//! It never reads page data, changes the reader, opens a listener, or resets a deadline.
use super::client_protocol::ProtocolError;
use super::client_session::{CancelSignal, OperationLease};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Instant;
use tokio::sync::watch;

const MAX_RECORDS: usize = 32;
const MAX_REFS: usize = 4096;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    SemanticAcquire,
    SemanticPublish,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Armed,
    Reached,
    Expired,
    Released,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub phase: Phase,
    pub state: State,
    pub allocated_refs: Vec<String>,
}
struct Record {
    scope: String,
    token: String,
    status: Status,
    wake: watch::Sender<bool>,
}
#[derive(Default)]
pub struct FaultController {
    records: Mutex<Vec<Record>>,
}
impl FaultController {
    pub fn arm(&self, scope: &str, phase: Phase) -> Result<String, ProtocolError> {
        if scope.is_empty() {
            return Err(ProtocolError::StaleScope);
        }
        let mut records = self
            .records
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if records.iter().any(|r| {
            r.scope == scope
                && r.status.phase == phase
                && matches!(r.status.state, State::Armed | State::Reached)
        }) {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if records.len() >= MAX_RECORDS {
            let position = records
                .iter()
                .position(|r| matches!(r.status.state, State::Expired | State::Released))
                .ok_or(ProtocolError::CapacityExceeded)?;
            records.remove(position);
        }
        let token = uuid::Uuid::new_v4().to_string();
        let (wake, _) = watch::channel(false);
        records.push(Record {
            scope: scope.to_owned(),
            token: token.clone(),
            status: Status {
                phase,
                state: State::Armed,
                allocated_refs: vec![],
            },
            wake,
        });
        Ok(token)
    }
    pub fn status(&self, scope: &str, token: &str) -> Result<Status, ProtocolError> {
        self.records
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?
            .iter()
            .find(|r| r.scope == scope && r.token == token)
            .map(|r| r.status.clone())
            .ok_or(ProtocolError::StaleScope)
    }
    pub fn release(&self, scope: &str, token: &str) -> Result<(), ProtocolError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let record = records
            .iter_mut()
            .find(|r| r.scope == scope && r.token == token)
            .ok_or(ProtocolError::StaleScope)?;
        if record.status.state != State::Expired {
            record.status.state = State::Released;
        }
        record.wake.send_replace(true);
        Ok(())
    }
    pub fn retire_scope(&self, scope: &str) -> Result<(), ProtocolError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        records.retain(|record| !(record.scope == scope && record.status.state == State::Armed));
        for record in records.iter_mut().filter(|r| r.scope == scope) {
            if record.status.state == State::Reached {
                record.status.state = State::Expired;
            }
            record.wake.send_replace(true);
        }
        Ok(())
    }
    pub async fn checkpoint(
        &self,
        scope: &str,
        phase: Phase,
        allocated_refs: Vec<String>,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        let (token, mut wake) = {
            let mut records = self
                .records
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            let Some(record) = records.iter_mut().find(|r| {
                r.scope == scope && r.status.phase == phase && r.status.state == State::Armed
            }) else {
                return Ok(());
            };
            if allocated_refs.len() > MAX_REFS
                || allocated_refs
                    .iter()
                    .any(|id| !id.starts_with("@e") || id.len() > 32)
            {
                return Err(ProtocolError::CapacityExceeded);
            }
            record.status.state = State::Reached;
            record.status.allocated_refs = allocated_refs;
            (record.token.clone(), record.wake.subscribe())
        };
        let mut cancellation = operation.cancellation.clone();
        let result = loop {
            if *cancellation.borrow() != CancelSignal::None {
                break Err(ProtocolError::Cancelled);
            }
            if Instant::now() >= operation.deadline {
                break Err(ProtocolError::DeadlineExceeded);
            }
            if super::client_observation::capture_superseded() {
                break Err(ProtocolError::StaleReference);
            }
            if *wake.borrow() {
                break match self.status(scope, &token)?.state {
                    State::Released => Ok(()),
                    _ => Err(ProtocolError::StaleScope),
                };
            }
            tokio::select! {
                biased;
                changed=cancellation.changed()=>{ if changed.is_err() { break Err(ProtocolError::Cancelled); } },
                _=tokio::time::sleep_until(operation.deadline.into())=>{},
                _=super::client_observation::capture_retired()=>{},
                _=wake.changed()=>{},
            }
        };
        if result.is_err() {
            let mut records = self
                .records
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if let Some(record) = records
                .iter_mut()
                .find(|r| r.scope == scope && r.token == token)
            {
                if record.status.state == State::Reached {
                    record.status.state = State::Expired;
                }
            }
        }
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    fn lease(timeout: Duration) -> (watch::Sender<CancelSignal>, OperationLease) {
        let (sender, cancellation) = watch::channel(CancelSignal::None);
        (
            sender,
            OperationLease {
                generation: 1,
                sequence: 1,
                deadline: Instant::now() + timeout,
                cancellation,
                is_callback: false,
            },
        )
    }
    #[tokio::test]
    async fn release_is_scope_bound_and_does_not_replace_the_reader() {
        let faults = Arc::new(FaultController::default());
        let token = faults.arm("one", Phase::SemanticPublish).unwrap();
        assert!(faults.release("two", &token).is_err());
        let task = {
            let faults = faults.clone();
            tokio::spawn(async move {
                let (_sender, operation) = lease(Duration::from_secs(1));
                faults
                    .checkpoint(
                        "one",
                        Phase::SemanticPublish,
                        vec!["@e7".into()],
                        &operation,
                    )
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert_eq!(faults.status("one", &token).unwrap().state, State::Reached);
        assert_eq!(
            faults.status("one", &token).unwrap().allocated_refs,
            vec!["@e7"]
        );
        faults.release("one", &token).unwrap();
        task.await.unwrap().unwrap();
        let (_sender, operation) = lease(Duration::from_secs(1));
        faults
            .checkpoint("one", Phase::SemanticPublish, vec![], &operation)
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn original_deadline_expires_hold_and_late_release_cannot_revive_it() {
        let faults = FaultController::default();
        let token = faults.arm("one", Phase::SemanticAcquire).unwrap();
        let (_sender, operation) = lease(Duration::from_millis(5));
        assert_eq!(
            faults
                .checkpoint("one", Phase::SemanticAcquire, vec![], &operation)
                .await,
            Err(ProtocolError::DeadlineExceeded)
        );
        faults.release("one", &token).unwrap();
        assert_eq!(faults.status("one", &token).unwrap().state, State::Expired);
    }
    #[tokio::test]
    async fn unarmed_checkpoint_never_changes_normal_reader_limits() {
        let faults = FaultController::default();
        let (_sender, operation) = lease(Duration::from_secs(1));
        faults
            .checkpoint(
                "scope",
                Phase::SemanticPublish,
                vec!["@e1".into(); MAX_REFS + 1],
                &operation,
            )
            .await
            .unwrap();
    }
    #[test]
    fn arms_are_bounded_and_retirement_never_retargets() {
        let faults = FaultController::default();
        let token = faults.arm("old", Phase::SemanticAcquire).unwrap();
        assert!(faults.arm("old", Phase::SemanticAcquire).is_err());
        faults.retire_scope("old").unwrap();
        assert!(faults.status("old", &token).is_err());
        assert!(faults.status("new", &token).is_err());
        for n in 0..32 {
            faults
                .arm(&format!("scope{n}"), Phase::SemanticAcquire)
                .unwrap();
        }
        assert!(faults.arm("replacement", Phase::SemanticAcquire).is_err());
        assert!(faults.arm("overflow", Phase::SemanticAcquire).is_err());
    }
}
