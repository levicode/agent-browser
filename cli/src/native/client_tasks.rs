//! Retained native command ownership, independent of an RPC receiver's lifetime.
//! Callers capture an execution permit before registration and keep it, UI
//! admission, and all resource leases inside the submitted future. Lifecycle
//! closes execution admission and drains those permits before draining this set.
use super::client_protocol::{Effects, ProtocolError};
use super::client_targets::ClientTargets;
use super::client_transport::NativeOutcome;
use futures_util::FutureExt;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinSet;

const MAX_RETAINED: usize = 64;

pub struct RetainedCompletion {
    pub identity_scope: String,
    pub cleanup_integrity_lost: bool,
}
#[derive(Default)]
struct Tasks {
    closing: bool,
    tasks: JoinSet<RetainedCompletion>,
    failures: Vec<String>,
    unscoped_failure: bool,
}
#[derive(Default)]
pub struct RetainedTasks {
    inner: Mutex<Tasks>,
}
impl Tasks {
    fn record(&mut self, result: Result<RetainedCompletion, tokio::task::JoinError>) {
        match result {
            Ok(result) if result.cleanup_integrity_lost => {
                if !self.failures.contains(&result.identity_scope) {
                    self.failures.push(result.identity_scope);
                }
            }
            Err(_) => self.unscoped_failure = true,
            _ => {}
        }
    }
}
impl RetainedTasks {
    pub async fn start<F>(
        &self,
        identity_scope: String,
        targets: Arc<ClientTargets>,
        future: F,
    ) -> Result<oneshot::Receiver<NativeOutcome>, ProtocolError>
    where
        F: Future<Output = (NativeOutcome, bool)> + Send + 'static,
    {
        let mut tasks = self.inner.lock().await;
        while let Some(result) = tasks.tasks.try_join_next() {
            tasks.record(result);
        }
        if tasks.closing || tasks.unscoped_failure || !tasks.failures.is_empty() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if tasks.tasks.len() >= MAX_RETAINED {
            return Err(ProtocolError::CapacityExceeded);
        }
        let (send, receive) = oneshot::channel();
        // Registration and permanent shutdown linearize under this mutex.
        tasks.tasks.spawn(async move {
            let (outcome, cleanup_integrity_lost) =
                match AssertUnwindSafe(future).catch_unwind().await {
                    Ok(result) => result,
                    Err(_) => (
                        NativeOutcome {
                            result: Err(ProtocolError::BrowserFailure),
                            effects: Effects::Unknown,
                        },
                        true,
                    ),
                };
            if cleanup_integrity_lost {
                targets.seal();
            }
            // Any orphaned blob handles remain in the captured bounded BlobStore
            // scope journal until its retirement; they never transfer to another
            // scope and no completed mutation is replayed for a lost response.
            let _ = send.send(outcome);
            RetainedCompletion {
                identity_scope,
                cleanup_integrity_lost,
            }
        });
        Ok(receive)
    }

    pub async fn seal(&self) {
        self.inner.lock().await.closing = true;
    }

    /// JoinSet remains in owner storage if this wait is cancelled. All tasks
    /// are joined even when an earlier task reported cleanup failure.
    pub async fn drain(&self) -> Result<(), ProtocolError> {
        let mut tasks = self.inner.lock().await;
        while let Some(result) = tasks.tasks.join_next().await {
            tasks.record(result);
        }
        if tasks.unscoped_failure || !tasks.failures.is_empty() {
            Err(ProtocolError::CleanupFailed)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::client_browser::ExecutionGate;
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    fn complete() -> NativeOutcome {
        NativeOutcome {
            result: Ok(serde_json::Value::Null),
            effects: Effects::Completed,
        }
    }

    #[tokio::test]
    async fn lost_rpc_and_cancelled_drain_retain_execution_permit_until_cleanup() {
        let tasks = Arc::new(RetainedTasks::default());
        let gate = Arc::new(ExecutionGate::default());
        let permit = gate.enter(false).unwrap();
        let targets = ClientTargets::new("context".into(), "scope".into());
        let (release, waiting) = oneshot::channel();
        let receive = tasks
            .start("scope".into(), targets, async move {
                let _permit = permit;
                waiting.await.unwrap();
                (complete(), false)
            })
            .await
            .unwrap();
        drop(receive);
        gate.begin_transition().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), gate.drained())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), tasks.drain())
                .await
                .is_err()
        );
        release.send(()).unwrap();
        tasks.drain().await.unwrap();
        gate.drained().await.unwrap();
        gate.commit_transition().unwrap();
    }

    #[tokio::test]
    async fn cleanup_failure_still_joins_other_tasks_and_seals_only_captured_registry() {
        let tasks = RetainedTasks::default();
        let failed = ClientTargets::new("old-context".into(), "old".into());
        let other = ClientTargets::new("other-context".into(), "other".into());
        let finished = Arc::new(AtomicBool::new(false));
        let (release, waiting) = oneshot::channel();
        let flag = finished.clone();
        let second = tasks
            .start("other".into(), other.clone(), async move {
                waiting.await.unwrap();
                flag.store(true, Ordering::SeqCst);
                (complete(), false)
            })
            .await
            .unwrap();
        let first = tasks
            .start("old".into(), failed.clone(), async { (complete(), true) })
            .await
            .unwrap();
        first.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), tasks.drain())
                .await
                .is_err()
        );
        assert!(!finished.load(Ordering::SeqCst));
        release.send(()).unwrap();
        assert_eq!(tasks.drain().await, Err(ProtocolError::CleanupFailed));
        second.await.unwrap();
        assert!(finished.load(Ordering::SeqCst));
        assert!(failed.inventory().is_err());
        assert!(other.inventory().is_ok());
    }

    #[tokio::test]
    async fn retirement_rejects_late_registration_before_polling_browser_work() {
        let tasks = RetainedTasks::default();
        tasks.seal().await;
        let polled = Arc::new(AtomicBool::new(false));
        let marker = polled.clone();
        assert!(tasks
            .start(
                "scope".into(),
                ClientTargets::new("context".into(), "scope".into()),
                async move {
                    marker.store(true, Ordering::SeqCst);
                    (complete(), false)
                }
            )
            .await
            .is_err());
        assert!(!polled.load(Ordering::SeqCst));
        tasks.drain().await.unwrap();
    }
}
