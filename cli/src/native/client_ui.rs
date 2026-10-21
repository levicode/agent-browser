//! Native protected-read admission. Callback children may finish their parent
//! while an exclusive read waits, without a writer-priority lock deadlock.
use super::client_protocol::ProtocolError;
use super::client_session::CancelSignal;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{watch, Notify};

#[derive(Default)]
struct State {
    readers: usize,
    waiting: usize,
    callbacks: usize,
    exclusive: bool,
    sealed: bool,
}
#[derive(Default)]
pub struct UiGate {
    state: Mutex<State>,
    changed: Notify,
}
pub struct UiPermit {
    gate: Arc<UiGate>,
    exclusive: bool,
}
pub struct CallbackReservation {
    gate: Arc<UiGate>,
    pending: bool,
}
struct WaitingWriter {
    gate: Arc<UiGate>,
    registered: bool,
}
impl Drop for WaitingWriter {
    fn drop(&mut self) {
        if self.registered {
            if let Ok(mut state) = self.gate.state.lock() {
                state.waiting = state.waiting.saturating_sub(1);
            }
            self.gate.changed.notify_waiters();
        }
    }
}
impl UiGate {
    /// Called synchronously while an owned paused event is captured. Registry
    /// snapshot/token ownership is retained by the caller before any await.
    pub fn reserve_callback(self: &Arc<Self>) -> Result<CallbackReservation, ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed {
            return Err(ProtocolError::StaleScope);
        }
        if state.callbacks >= 256 {
            return Err(ProtocolError::CapacityExceeded);
        }
        state.callbacks += 1;
        Ok(CallbackReservation {
            gate: self.clone(),
            pending: true,
        })
    }

    pub fn seal(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.sealed = true;
        }
        self.changed.notify_waiters();
    }
    /// callback_child is set only from broker-validated OperationLease metadata.
    /// A protected read cannot itself be a child of a paused browser callback.
    pub async fn enter(
        self: &Arc<Self>,
        exclusive: bool,
        callback_child: bool,
        deadline: Instant,
        mut cancellation: watch::Receiver<CancelSignal>,
    ) -> Result<UiPermit, ProtocolError> {
        if exclusive && callback_child {
            return Err(ProtocolError::InvalidArguments);
        }
        let mut writer = WaitingWriter {
            gate: self.clone(),
            registered: false,
        };
        loop {
            if *cancellation.borrow() != CancelSignal::None {
                return Err(ProtocolError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(ProtocolError::DeadlineExceeded);
            }
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if state.sealed {
                    return Err(ProtocolError::StaleScope);
                }
                if exclusive && !writer.registered {
                    state.waiting = state
                        .waiting
                        .checked_add(1)
                        .ok_or(ProtocolError::CapacityExceeded)?;
                    writer.registered = true;
                }
                if exclusive && !state.exclusive && state.readers == 0 && state.callbacks == 0 {
                    state.waiting -= 1;
                    writer.registered = false;
                    state.exclusive = true;
                    return Ok(UiPermit {
                        gate: self.clone(),
                        exclusive: true,
                    });
                }
                if !exclusive && !state.exclusive && (state.waiting == 0 || callback_child) {
                    state.readers = state
                        .readers
                        .checked_add(1)
                        .ok_or(ProtocolError::CapacityExceeded)?;
                    return Ok(UiPermit {
                        gate: self.clone(),
                        exclusive: false,
                    });
                }
            }
            tokio::select! {
                _ = changed => {},
                _ = cancellation.changed() => return Err(ProtocolError::Cancelled),
                _ = tokio::time::sleep_until(deadline.into()) => return Err(ProtocolError::DeadlineExceeded),
            }
        }
    }
}
impl CallbackReservation {
    pub async fn enter(
        mut self,
        deadline: Instant,
        mut cancellation: watch::Receiver<CancelSignal>,
    ) -> Result<UiPermit, ProtocolError> {
        loop {
            if *cancellation.borrow() != CancelSignal::None {
                return Err(ProtocolError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(ProtocolError::DeadlineExceeded);
            }
            let changed = self.gate.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self
                    .gate
                    .state
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if state.sealed {
                    return Err(ProtocolError::StaleScope);
                }
                if !state.exclusive {
                    state.readers = state
                        .readers
                        .checked_add(1)
                        .ok_or(ProtocolError::CapacityExceeded)?;
                    state.callbacks -= 1;
                    self.pending = false;
                    return Ok(UiPermit {
                        gate: self.gate.clone(),
                        exclusive: false,
                    });
                }
            }
            tokio::select! {
                _=changed=>{},
                _=cancellation.changed()=>return Err(ProtocolError::Cancelled),
                _=tokio::time::sleep_until(deadline.into())=>return Err(ProtocolError::DeadlineExceeded),
            }
        }
    }
}
impl Drop for CallbackReservation {
    fn drop(&mut self) {
        if self.pending {
            if let Ok(mut state) = self.gate.state.lock() {
                state.callbacks = state.callbacks.saturating_sub(1);
            }
            self.gate.changed.notify_waiters();
        }
    }
}
impl Drop for UiPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.gate.state.lock() {
            if self.exclusive {
                state.exclusive = false;
            } else {
                state.readers = state.readers.saturating_sub(1);
            }
        }
        self.gate.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[tokio::test]
    async fn captured_event_waits_for_active_protection_then_precedes_next_writer() {
        let gate = Arc::new(UiGate::default());
        let (_send, cancel) = watch::channel(CancelSignal::None);
        let deadline = Instant::now() + Duration::from_secs(1);
        let protected = gate
            .enter(true, false, deadline, cancel.clone())
            .await
            .unwrap();
        let reservation = gate.reserve_callback().unwrap();
        let event = {
            let cancel = cancel.clone();
            tokio::spawn(async move { reservation.enter(deadline, cancel).await })
        };
        tokio::task::yield_now().await;
        assert!(!event.is_finished());
        assert_eq!(gate.state.lock().unwrap().callbacks, 1);
        drop(protected);
        let callback = event.await.unwrap().unwrap();
        assert_eq!(gate.state.lock().unwrap().callbacks, 0);
        assert_eq!(gate.state.lock().unwrap().readers, 1);
        drop(callback);
        gate.enter(true, false, deadline, cancel).await.unwrap();
    }
    #[tokio::test]
    async fn waiting_protected_read_does_not_deadlock_parent_callback() {
        let gate = Arc::new(UiGate::default());
        let (_send, cancel) = watch::channel(CancelSignal::None);
        let deadline = Instant::now() + Duration::from_secs(1);
        let parent = gate
            .enter(false, false, deadline, cancel.clone())
            .await
            .unwrap();
        let writer = {
            let gate = gate.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move { gate.enter(true, false, deadline, cancel).await })
        };
        tokio::task::yield_now().await;
        assert_eq!(gate.state.lock().unwrap().waiting, 1);
        let child = gate
            .enter(false, true, deadline, cancel.clone())
            .await
            .unwrap();
        assert!(!writer.is_finished());
        drop(parent);
        assert!(!writer.is_finished());
        drop(child);
        let protected = writer.await.unwrap().unwrap();
        assert!(gate.state.lock().unwrap().exclusive);
        let rejected = gate.enter(false, true, Instant::now(), cancel).await;
        assert!(matches!(rejected, Err(ProtocolError::DeadlineExceeded)));
        drop(protected);
        assert!(!gate.state.lock().unwrap().exclusive);
    }
    #[tokio::test]
    async fn cancelled_writer_releases_admission_and_sealed_gate_never_reopens() {
        let gate = Arc::new(UiGate::default());
        let (_send, cancel) = watch::channel(CancelSignal::None);
        let deadline = Instant::now() + Duration::from_secs(1);
        let parent = gate
            .enter(false, false, deadline, cancel.clone())
            .await
            .unwrap();
        let expired = gate
            .enter(
                true,
                false,
                Instant::now() + Duration::from_millis(1),
                cancel.clone(),
            )
            .await;
        assert!(matches!(expired, Err(ProtocolError::DeadlineExceeded)));
        assert_eq!(gate.state.lock().unwrap().waiting, 0);
        gate.enter(false, false, deadline, cancel.clone())
            .await
            .unwrap();
        gate.seal();
        drop(parent);
        assert!(matches!(
            gate.enter(false, true, deadline, cancel).await,
            Err(ProtocolError::StaleScope)
        ));
    }
}
