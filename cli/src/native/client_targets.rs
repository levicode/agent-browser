//! Owned target identity and creation-purpose reservations. Browser attachment
//! waits on this registry before configuration/resume; no URL or timing guess
//! assigns a bootstrap target to a generic request handler.
use super::client_protocol::ProtocolError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetPurpose {
    Application,
    StateBootstrap,
}
#[derive(Clone, Debug)]
pub struct OwnedTarget {
    pub target_id: String,
    pub session_id: String,
    pub kind: String,
    pub purpose: Option<TargetPurpose>,
    pub configured: bool,
    pub resumed: bool,
    resume_pending: bool,
}
#[derive(Default)]
struct Registry {
    revision: u64,
    sealed: bool,
    reservations: usize,
    resuming: usize,
    protected_read: bool,
    enrollment_ready: bool,
    targets: HashMap<String, OwnedTarget>,
}
pub struct ClientTargets {
    pub context_id: String,
    pub identity_scope: String,
    state: Mutex<Registry>,
    changed: Notify,
}
pub struct CreationReservation {
    registry: Arc<ClientTargets>,
    purpose: TargetPurpose,
    claimed: bool,
}
pub struct InventoryStamp {
    pub revision: u64,
    pub identity_scope: String,
    pub targets: Vec<OwnedTarget>,
}
pub struct ProtectedTargetBarrier {
    registry: Arc<ClientTargets>,
    pub stamp: InventoryStamp,
}
pub struct ResumePermit {
    registry: Arc<ClientTargets>,
    target_id: String,
    session_id: String,
    completed: bool,
}
impl ProtectedTargetBarrier {
    /// Quarantine exactly the registry captured by this transaction.
    pub fn quarantine(&self) {
        self.registry.seal();
    }
    pub fn check(&self) -> Result<(), ProtocolError> {
        self.registry.check_revision(self.stamp.revision)
    }
}
impl Drop for ProtectedTargetBarrier {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.state.lock() {
            state.protected_read = false;
        }
        self.registry.changed.notify_waiters();
    }
}
impl ResumePermit {
    pub fn complete(mut self) -> Result<(), ProtocolError> {
        let mut state = self
            .registry
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed {
            return Err(ProtocolError::StaleScope);
        }
        let target = state
            .targets
            .get_mut(&self.target_id)
            .ok_or(ProtocolError::StaleReference)?;
        if target.session_id != self.session_id {
            state.sealed = true;
            return Err(ProtocolError::StaleScope);
        }
        target.resumed = true;
        self.completed = true;
        Ok(())
    }
}
impl Drop for ResumePermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.state.lock() {
            if let Some(target) = state.targets.get_mut(&self.target_id) {
                if target.session_id == self.session_id {
                    target.resume_pending = false;
                }
            }
            state.resuming = state.resuming.saturating_sub(1);
            if !self.completed {
                state.sealed = true;
            }
        }
        self.registry.changed.notify_waiters();
    }
}
impl ClientTargets {
    pub fn new(context_id: String, identity_scope: String) -> Arc<Self> {
        Arc::new(Self {
            context_id,
            identity_scope,
            state: Mutex::new(Registry::default()),
            changed: Notify::new(),
        })
    }
    /// Lifecycle owner calls this only after bounded event routing and recursive
    /// target attachment barriers are installed and initial inventory reconciled.
    pub fn acknowledge_enrollment(&self) -> Result<(), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed || state.reservations != 0 || state.resuming != 0 {
            return Err(ProtocolError::ScopeUnavailable);
        }
        state.enrollment_ready = true;
        Ok(())
    }
    pub fn protected_read_barrier(
        self: &Arc<Self>,
    ) -> Result<ProtectedTargetBarrier, ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed
            || !state.enrollment_ready
            || state.protected_read
            || state.reservations != 0
            || state.resuming != 0
            || state
                .targets
                .values()
                .any(|target| !target.configured || !target.resumed)
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        state.protected_read = true;
        Ok(ProtectedTargetBarrier {
            registry: self.clone(),
            stamp: InventoryStamp {
                revision: state.revision,
                identity_scope: self.identity_scope.clone(),
                targets: state.targets.values().cloned().collect(),
            },
        })
    }
    /// Hold through Runtime.runIfWaitingForDebugger acknowledgement. Capture
    /// cannot enter between its admission and actual browser completion.
    pub async fn resume_permit(
        self: &Arc<Self>,
        target_id: &str,
    ) -> Result<ResumePermit, ProtocolError> {
        loop {
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
                let target = state
                    .targets
                    .get(target_id)
                    .ok_or(ProtocolError::StaleReference)?;
                if !target.configured || target.resumed || target.resume_pending {
                    return Err(ProtocolError::InvalidArguments);
                }
                if !state.protected_read {
                    let session_id = target.session_id.clone();
                    state
                        .targets
                        .get_mut(target_id)
                        .ok_or(ProtocolError::StaleReference)?
                        .resume_pending = true;
                    state.resuming = state
                        .resuming
                        .checked_add(1)
                        .ok_or(ProtocolError::CapacityExceeded)?;
                    return Ok(ResumePermit {
                        registry: self.clone(),
                        target_id: target_id.into(),
                        session_id,
                        completed: false,
                    });
                }
            }
            changed.await;
        }
    }
    pub fn reserve_creation(
        self: &Arc<Self>,
        purpose: TargetPurpose,
    ) -> Result<CreationReservation, ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed || state.protected_read {
            return Err(ProtocolError::StaleScope);
        }
        state.reservations = state
            .reservations
            .checked_add(1)
            .ok_or(ProtocolError::CapacityExceeded)?;
        Ok(CreationReservation {
            registry: self.clone(),
            purpose,
            claimed: false,
        })
    }
    /// Return false for another tenant without registering or configuring it.
    pub fn attached(
        &self,
        context_id: &str,
        target_id: String,
        session_id: String,
        kind: String,
    ) -> Result<bool, ProtocolError> {
        if context_id != self.context_id {
            return Ok(false);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed {
            return Err(ProtocolError::StaleScope);
        }
        if state.targets.len() >= 1024 {
            return Err(ProtocolError::CapacityExceeded);
        }
        if target_id.is_empty()
            || session_id.is_empty()
            || state.targets.contains_key(&target_id)
            || state
                .targets
                .values()
                .any(|target| target.session_id == session_id)
        {
            return Err(ProtocolError::InvalidArguments);
        }
        let purpose = if state.reservations == 0 {
            Some(TargetPurpose::Application)
        } else {
            None
        };
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        state.targets.insert(
            target_id.clone(),
            OwnedTarget {
                target_id,
                session_id,
                kind,
                purpose,
                configured: false,
                resumed: false,
                resume_pending: false,
            },
        );
        drop(state);
        self.changed.notify_waiters();
        Ok(true)
    }
    /// The create reply and attach event may arrive in either order. The
    /// lifecycle supervisor retains this wait under its original deadline.
    pub async fn wait_attached(&self, target_id: &str) -> Result<(), ProtocolError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if state.sealed {
                    return Err(ProtocolError::StaleScope);
                }
                if state.targets.contains_key(target_id) {
                    return Ok(());
                }
            }
            changed.await;
        }
    }
    pub async fn purpose(&self, target_id: &str) -> Result<TargetPurpose, ProtocolError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| ProtocolError::ScopeUnavailable)?;
                if state.sealed {
                    return Err(ProtocolError::StaleScope);
                }
                let target = state
                    .targets
                    .get(target_id)
                    .ok_or(ProtocolError::StaleReference)?;
                if let Some(purpose) = target.purpose {
                    return Ok(purpose);
                }
            }
            changed.await;
        }
    }
    /// Return only the exact attachment after creation purpose is claimed.
    pub fn owned_target(&self, target_id: &str) -> Result<OwnedTarget, ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed {
            return Err(ProtocolError::StaleScope);
        }
        let target = state
            .targets
            .get(target_id)
            .ok_or(ProtocolError::StaleReference)?;
        if target.purpose.is_none() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        Ok(target.clone())
    }
    pub fn configured(&self, target_id: &str) -> Result<(), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed {
            return Err(ProtocolError::StaleScope);
        }
        let target = state
            .targets
            .get_mut(target_id)
            .ok_or(ProtocolError::StaleReference)?;
        if target.purpose.is_none() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        target.configured = true;
        Ok(())
    }
    pub fn detach(&self, target_id: &str) -> Result<(), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.targets.remove(target_id).is_some() {
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or(ProtocolError::IdentifierExhausted)?;
        }
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }
    pub fn invalidate_inventory(&self) -> Result<(), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed {
            return Err(ProtocolError::StaleScope);
        }
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        Ok(())
    }
    pub fn inventory(&self) -> Result<(u64, Vec<OwnedTarget>), ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed
            || state.reservations != 0
            || state
                .targets
                .values()
                .any(|t| t.purpose.is_none() || !t.configured)
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        Ok((state.revision, state.targets.values().cloned().collect()))
    }
    pub fn check_revision(&self, revision: u64) -> Result<(), ProtocolError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed || state.revision != revision || state.reservations != 0 {
            Err(ProtocolError::StaleScope)
        } else {
            Ok(())
        }
    }
    pub fn seal(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.sealed = true;
        }
        self.changed.notify_waiters();
    }
}
impl CreationReservation {
    pub fn claim(&mut self, target_id: &str) -> Result<(), ProtocolError> {
        let mut state = self
            .registry
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.sealed || self.claimed {
            return Err(ProtocolError::StaleScope);
        }
        let target = state
            .targets
            .get_mut(target_id)
            .ok_or(ProtocolError::StaleReference)?;
        if target.purpose.is_some() {
            return Err(ProtocolError::InvalidArguments);
        }
        target.purpose = Some(self.purpose);
        self.claimed = true;
        drop(state);
        self.registry.changed.notify_waiters();
        Ok(())
    }
}
impl Drop for CreationReservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.state.lock() {
            // An abandoned create may still produce a late browser target.
            // Never reinterpret that unclaimed bootstrap as application work.
            if !self.claimed {
                state.sealed = true;
            }
            state.reservations = state.reservations.saturating_sub(1);
            if state.reservations == 0 && !state.sealed {
                for target in state.targets.values_mut() {
                    if target.purpose.is_none() {
                        target.purpose = Some(TargetPurpose::Application);
                    }
                }
            }
        }
        self.registry.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn creation_reservation_keeps_bootstrap_out_of_generic_request_handling() {
        let registry = ClientTargets::new("owned".into(), "scope".into());
        let mut reservation = registry
            .reserve_creation(TargetPurpose::StateBootstrap)
            .unwrap();
        assert!(!registry
            .attached("other", "foreign".into(), "f".into(), "page".into())
            .unwrap());
        registry
            .attached("owned", "bootstrap".into(), "b".into(), "page".into())
            .unwrap();
        registry
            .attached("owned", "popup".into(), "p".into(), "page".into())
            .unwrap();
        assert!(registry.configured("bootstrap").is_err());
        assert!(registry.owned_target("bootstrap").is_err());
        assert!(registry.inventory().is_err());
        reservation.claim("bootstrap").unwrap();
        assert_eq!(registry.owned_target("bootstrap").unwrap().session_id, "b");
        assert_eq!(
            registry.purpose("bootstrap").await.unwrap(),
            TargetPurpose::StateBootstrap
        );
        drop(reservation);
        assert_eq!(
            registry.purpose("popup").await.unwrap(),
            TargetPurpose::Application
        );
        registry.configured("bootstrap").unwrap();
        registry.configured("popup").unwrap();
        let (revision, targets) = registry.inventory().unwrap();
        assert_eq!(targets.len(), 2);
        registry.invalidate_inventory().unwrap();
        assert!(registry.check_revision(revision).is_err());
    }
    #[tokio::test]
    async fn protected_barrier_waits_for_resume_ack_and_keeps_new_targets_paused() {
        let registry = ClientTargets::new("owned".into(), "scope".into());
        registry
            .attached("owned", "page".into(), "p".into(), "page".into())
            .unwrap();
        registry.configured("page").unwrap();
        let resume = registry.resume_permit("page").await.unwrap();
        assert!(registry.protected_read_barrier().is_err());
        resume.complete().unwrap();
        assert!(registry.protected_read_barrier().is_err());
        registry.acknowledge_enrollment().unwrap();
        let barrier = registry.protected_read_barrier().unwrap();
        registry
            .attached("owned", "child".into(), "c".into(), "iframe".into())
            .unwrap();
        registry.configured("child").unwrap();
        assert!(barrier.check().is_err());
        let pending = {
            let registry = registry.clone();
            tokio::spawn(async move { registry.resume_permit("child").await })
        };
        tokio::task::yield_now().await;
        assert!(!pending.is_finished());
        drop(barrier);
        pending.await.unwrap().unwrap().complete().unwrap();
        registry.protected_read_barrier().unwrap().check().unwrap();
    }
    #[tokio::test]
    async fn old_resume_ack_never_resumes_a_replacement_attachment() {
        let registry = ClientTargets::new("owned".into(), "scope".into());
        registry
            .attached("owned", "page".into(), "old".into(), "page".into())
            .unwrap();
        registry.configured("page").unwrap();
        let old = registry.resume_permit("page").await.unwrap();
        registry.detach("page").unwrap();
        registry
            .attached("owned", "page".into(), "new".into(), "page".into())
            .unwrap();
        registry.configured("page").unwrap();
        assert!(old.complete().is_err());
        let state = registry.state.lock().unwrap();
        assert!(state.sealed);
        assert!(!state.targets["page"].resumed);
        assert_eq!(state.targets["page"].session_id, "new");
    }
    #[test]
    fn protected_transaction_quarantine_seals_only_its_original_scope() {
        let old = ClientTargets::new("owned".into(), "old".into());
        let new = ClientTargets::new("owned".into(), "new".into());
        old.acknowledge_enrollment().unwrap();
        let barrier = old.protected_read_barrier().unwrap();
        assert!(old.reserve_creation(TargetPurpose::StateBootstrap).is_err());
        barrier.quarantine();
        drop(barrier);
        assert!(old.inventory().is_err());
        assert!(new.inventory().is_ok());
    }
    #[test]
    fn abandoned_creation_never_relabels_late_bootstrap_as_application() {
        let registry = ClientTargets::new("owned".into(), "scope".into());
        let reservation = registry
            .reserve_creation(TargetPurpose::StateBootstrap)
            .unwrap();
        registry
            .attached("owned", "late".into(), "session".into(), "page".into())
            .unwrap();
        drop(reservation);
        assert!(registry.configured("late").is_err());
        assert!(registry.inventory().is_err());
    }
    #[test]
    fn old_reservation_cannot_publish_after_scope_seal() {
        let registry = ClientTargets::new("owned".into(), "old".into());
        let mut reservation = registry
            .reserve_creation(TargetPurpose::StateBootstrap)
            .unwrap();
        registry
            .attached("owned", "target".into(), "session".into(), "page".into())
            .unwrap();
        registry.seal();
        assert!(reservation.claim("target").is_err());
        drop(reservation);
        assert!(registry.inventory().is_err());
    }
}
