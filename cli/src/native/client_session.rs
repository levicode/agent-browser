//! Browser-independent control broker. No method acquires DaemonState or
//! BrowserManager locks. Browser integration must report real settlement before
//! reuse; accepting cancellation never asserts that browser effects stopped.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{oneshot, watch};
use uuid::Uuid;

use super::client_protocol::{
    Decision, Effects, ProtocolError, RequestOverrides, ScopeState, MAX_SAFE_SEQUENCE,
    MAX_TIMEOUT_MS,
};

const MAX_OPERATIONS: usize = 64;
const MAX_DECISIONS: usize = 256;
const MAX_REGISTRIES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelSignal {
    None,
    Requested,
    SessionClosed,
}

pub struct OperationLease {
    pub is_callback: bool,
    pub generation: u64,
    pub sequence: u64,
    pub deadline: Instant,
    pub cancellation: watch::Receiver<CancelSignal>,
}

struct Operation {
    callback_token: Option<String>,
    parent_sequence: Option<u64>,
    callback_depth: usize,
    deadline: Instant,
    started: bool,
    cancel: watch::Sender<CancelSignal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionKind {
    Request,
    Authentication,
    Dialog,
}

impl DecisionKind {
    fn accepts(self, decision: &Decision) -> bool {
        matches!(
            (self, decision),
            (
                Self::Request,
                Decision::Continue { .. }
                    | Decision::Fulfill { .. }
                    | Decision::Abort {}
                    | Decision::Fallback { .. }
            ) | (
                Self::Authentication,
                Decision::Auth { .. } | Decision::CancelAuth {}
            ) | (Self::Dialog, Decision::Dialog { .. })
        )
    }
}

pub enum DecisionOutcome {
    Selected(Decision),
    Fallback {
        overrides: RequestOverrides,
        next: Box<DecisionLease>,
    },
    Expired,
    SessionClosed,
    Cancelled,
}

/// Background requests/dialogs belong to the scope, not a fabricated action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionOwner {
    Operation(u64),
    Scope,
}

struct PendingDecision {
    selected: Option<Decision>,
    owner: DecisionOwner,
    kind: DecisionKind,
    deadline: Instant,
    registry: Option<u64>,
    sender: oneshot::Sender<DecisionOutcome>,
}

struct Registry {
    registrations: Arc<[String]>,
    references: usize,
    retired: bool,
}

pub struct DecisionLease {
    pub token: String,
    pub generation: u64,
    pub deadline: Instant,
    pub registry_version: Option<u64>,
    pub registrations: Arc<[String]>,
    pub outcome: oneshot::Receiver<DecisionOutcome>,
}

struct Inner {
    generation: u64,
    health: ScopeState,
    high_water: u64,
    operations: HashMap<u64, Operation>,
    decisions: HashMap<String, PendingDecision>,
    registries: HashMap<u64, Registry>,
    registry_high_water: u64,
    released_registries: Vec<u64>,
}

/// One broker lives for the entire client session. Scope generations may change;
/// operation high-water never rolls back. Canonical refs belong to RefMap, not this broker.
pub struct ClientSession {
    pub id: String,
    inner: Mutex<Inner>,
}

impl Default for ClientSession {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientSession {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            inner: Mutex::new(Inner {
                generation: 1,
                health: ScopeState::Usable,
                high_water: 0,
                operations: HashMap::new(),
                decisions: HashMap::new(),
                registries: HashMap::new(),
                registry_high_water: 0,
                released_registries: Vec::new(),
            }),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>, ProtocolError> {
        self.inner
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)
    }

    fn check(inner: &Inner, generation: u64) -> Result<(), ProtocolError> {
        if inner.generation != generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if inner.health != ScopeState::Usable {
            return Err(ProtocolError::ScopeUnavailable);
        }
        Ok(())
    }

    pub fn health(&self) -> Result<(u64, ScopeState), ProtocolError> {
        let inner = self.lock()?;
        Ok((inner.generation, inner.health))
    }

    pub fn admit(
        &self,
        generation: u64,
        sequence: u64,
        timeout_ms: u64,
    ) -> Result<OperationLease, ProtocolError> {
        self.admit_callback(generation, sequence, timeout_ms, None)
    }

    pub fn admit_callback(
        &self,
        generation: u64,
        sequence: u64,
        timeout_ms: u64,
        callback_token: Option<&str>,
    ) -> Result<OperationLease, ProtocolError> {
        let mut inner = self.lock()?;
        Self::check(&inner, generation)?;
        if sequence == 0 || sequence > MAX_SAFE_SEQUENCE {
            return Err(ProtocolError::InvalidSequence);
        }
        if sequence <= inner.high_water {
            return Err(ProtocolError::SequenceReused);
        }
        // Consume before capacity/deadline rejection: the same sequence never
        // becomes an executable operation on a later retry.
        inner.high_water = sequence;
        if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
            return Err(ProtocolError::InvalidTimeout);
        }
        if inner.operations.len() >= MAX_OPERATIONS {
            return Err(ProtocolError::CapacityExceeded);
        }
        let mut deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut parent_sequence = None;
        let mut callback_depth = 0;
        if let Some(token) = callback_token {
            let pending = inner
                .decisions
                .get(token)
                .ok_or(ProtocolError::DecisionMissing)?;
            if pending.selected.is_some() {
                return Err(ProtocolError::DecisionMissing);
            }
            if Instant::now() >= pending.deadline {
                return Err(ProtocolError::DecisionExpired);
            }
            deadline = deadline.min(pending.deadline);
            if let DecisionOwner::Operation(parent) = pending.owner {
                parent_sequence = Some(parent);
                callback_depth = inner
                    .operations
                    .get(&parent)
                    .ok_or(ProtocolError::OperationMissing)?
                    .callback_depth
                    + 1;
            } else {
                callback_depth = 1;
            }
            if callback_depth > 16 {
                return Err(ProtocolError::CapacityExceeded);
            }
        }
        let (cancel, cancellation) = watch::channel(CancelSignal::None);
        inner.operations.insert(
            sequence,
            Operation {
                callback_token: callback_token.map(str::to_owned),
                parent_sequence,
                callback_depth,
                deadline,
                started: false,
                cancel,
            },
        );
        Ok(OperationLease {
            is_callback: callback_token.is_some(),
            generation,
            sequence,
            deadline,
            cancellation,
        })
    }

    /// Called immediately before entering an action, not when dequeued earlier.
    pub fn start(&self, generation: u64, sequence: u64) -> Result<bool, ProtocolError> {
        let mut inner = self.lock()?;
        Self::check(&inner, generation)?;
        let op = inner
            .operations
            .get_mut(&sequence)
            .ok_or(ProtocolError::OperationMissing)?;
        if op.started || Instant::now() >= op.deadline || *op.cancel.borrow() != CancelSignal::None
        {
            return Ok(false);
        }
        op.started = true;
        Ok(true)
    }

    pub fn has_started(&self, sequence: u64) -> bool {
        self.lock()
            .ok()
            .and_then(|inner| inner.operations.get(&sequence).map(|op| op.started))
            .unwrap_or(true)
    }

    /// Control acknowledgement only. The action must still produce settlement.
    pub fn cancel(&self, generation: u64, sequence: u64) -> Result<(), ProtocolError> {
        let mut inner = self.lock()?;
        Self::check(&inner, generation)?;
        if !inner.operations.contains_key(&sequence) {
            return Err(ProtocolError::OperationMissing);
        }
        Self::cancel_tree(&mut inner, sequence);
        Ok(())
    }

    pub fn settle(
        &self,
        generation: u64,
        sequence: u64,
        effects: Effects,
    ) -> Result<ScopeState, ProtocolError> {
        let mut inner = self.lock()?;
        if inner.generation != generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if !inner.operations.contains_key(&sequence) {
            return Err(ProtocolError::OperationMissing);
        }
        Self::cancel_tree(&mut inner, sequence);
        let operation = inner
            .operations
            .remove(&sequence)
            .ok_or(ProtocolError::OperationMissing)?;
        Self::cancel_decisions(&mut inner, sequence);
        if effects == Effects::Unknown && inner.health != ScopeState::Closed {
            Self::seal(&mut inner, ScopeState::Quarantined);
        } else if let Some(token) = operation.callback_token {
            let has_children = inner
                .operations
                .values()
                .any(|op| op.callback_token.as_deref() == Some(&token));
            if !has_children {
                if let Some(decision) = inner
                    .decisions
                    .get_mut(&token)
                    .and_then(|p| p.selected.take())
                {
                    let _ = Self::apply_selected(&mut inner, generation, &token, decision);
                }
            }
        }
        Ok(inner.health)
    }

    pub fn register_routes(
        &self,
        generation: u64,
        version: u64,
        registrations: Vec<String>,
    ) -> Result<(), ProtocolError> {
        let mut inner = self.lock()?;
        Self::check(&inner, generation)?;
        if version == 0 || version > MAX_SAFE_SEQUENCE || version <= inner.registry_high_water {
            return Err(ProtocolError::InvalidSequence);
        }
        if registrations.len() > 1024
            || inner.registries.len() + inner.released_registries.len() >= MAX_REGISTRIES
        {
            return Err(ProtocolError::CapacityExceeded);
        }
        let unique: std::collections::HashSet<_> = registrations.iter().collect();
        if unique.len() != registrations.len()
            || registrations
                .iter()
                .any(|id| id.is_empty() || id.len() > 128 || id.chars().any(char::is_control))
        {
            return Err(ProtocolError::InvalidFrame);
        }
        inner.registry_high_water = version;
        inner.registries.insert(
            version,
            Registry {
                registrations: registrations.into(),
                references: 0,
                retired: false,
            },
        );
        Ok(())
    }

    /// Native captures opaque registrations; JavaScript pattern matching stays
    /// in the client and must use this immutable version, never a current list.
    pub fn decision(
        &self,
        generation: u64,
        owner: DecisionOwner,
        kind: DecisionKind,
        timeout_ms: u64,
        registry: Option<u64>,
    ) -> Result<DecisionLease, ProtocolError> {
        let mut inner = self.lock()?;
        Self::check(&inner, generation)?;
        if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
            return Err(ProtocolError::InvalidTimeout);
        }
        if inner.decisions.len() >= MAX_DECISIONS {
            Self::seal(&mut inner, ScopeState::Quarantined);
            return Err(ProtocolError::CapacityExceeded);
        }
        let policy_deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let deadline = match owner {
            DecisionOwner::Operation(sequence) => {
                let operation = inner
                    .operations
                    .get(&sequence)
                    .ok_or(ProtocolError::OperationMissing)?;
                if *operation.cancel.borrow() != CancelSignal::None
                    || Instant::now() >= operation.deadline
                {
                    return Err(ProtocolError::Cancelled);
                }
                operation.deadline.min(policy_deadline)
            }
            DecisionOwner::Scope => policy_deadline,
        };
        let registrations = if let Some(version) = registry {
            let entry = inner
                .registries
                .get_mut(&version)
                .ok_or(ProtocolError::RegistryMissing)?;
            if entry.retired {
                return Err(ProtocolError::RegistryMissing);
            }
            entry.references += 1;
            entry.registrations.clone()
        } else {
            Arc::from(Vec::<String>::new())
        };
        let token = Uuid::new_v4().to_string();
        let (sender, outcome) = oneshot::channel();
        inner.decisions.insert(
            token.clone(),
            PendingDecision {
                selected: None,
                owner,
                kind,
                deadline,
                registry,
                sender,
            },
        );
        Ok(DecisionLease {
            token,
            generation,
            deadline,
            registry_version: registry,
            registrations,
            outcome,
        })
    }

    pub fn resolve(
        &self,
        generation: u64,
        token: &str,
        decision: Decision,
    ) -> Result<(), ProtocolError> {
        decision.validate()?;
        let mut inner = self.lock()?;
        Self::check(&inner, generation)?;
        let pending = inner
            .decisions
            .get(token)
            .ok_or(ProtocolError::DecisionMissing)?;
        if Instant::now() >= pending.deadline {
            let pending = inner.decisions.remove(token).unwrap();
            Self::cancel_token_children(&mut inner, token);
            Self::release_registry(&mut inner, pending.registry);
            let _ = pending.sender.send(DecisionOutcome::Expired);
            return Err(ProtocolError::DecisionExpired);
        }
        if pending.selected.is_some() {
            return Err(ProtocolError::DecisionMissing);
        }
        if !pending.kind.accepts(&decision) {
            return Err(ProtocolError::DecisionKindMismatch);
        }
        if inner
            .operations
            .values()
            .any(|op| op.callback_token.as_deref() == Some(token))
        {
            inner.decisions.get_mut(token).unwrap().selected = Some(decision);
            // Selecting the resource decision revokes callback work. An
            // already-running child must report its real terminal effects.
            Self::cancel_token_children(&mut inner, token);
            return Ok(());
        }
        Self::apply_selected(&mut inner, generation, token, decision)
    }

    fn apply_selected(
        inner: &mut Inner,
        generation: u64,
        token: &str,
        decision: Decision,
    ) -> Result<(), ProtocolError> {
        let pending = inner
            .decisions
            .remove(token)
            .ok_or(ProtocolError::DecisionMissing)?;
        if Instant::now() >= pending.deadline {
            Self::release_registry(inner, pending.registry);
            let _ = pending.sender.send(DecisionOutcome::Expired);
            return Err(ProtocolError::DecisionExpired);
        }
        if let Decision::Fallback { overrides } = decision {
            // Transfer the captured registry reference and original deadline.
            // Retiring a registry affects new requests, not this paused chain.
            let registrations = pending
                .registry
                .and_then(|v| inner.registries.get(&v))
                .map(|r| r.registrations.clone())
                .unwrap_or_else(|| Arc::from(Vec::<String>::new()));
            let next_token = Uuid::new_v4().to_string();
            let (sender, outcome) = oneshot::channel();
            let next = DecisionLease {
                token: next_token.clone(),
                generation,
                deadline: pending.deadline,
                registry_version: pending.registry,
                registrations,
                outcome,
            };
            inner.decisions.insert(
                next_token.clone(),
                PendingDecision {
                    selected: None,
                    owner: pending.owner,
                    kind: pending.kind,
                    deadline: pending.deadline,
                    registry: pending.registry,
                    sender,
                },
            );
            if pending
                .sender
                .send(DecisionOutcome::Fallback {
                    overrides,
                    next: Box::new(next),
                })
                .is_err()
            {
                inner.decisions.remove(&next_token);
                Self::release_registry(inner, pending.registry);
                return Err(ProtocolError::DecisionMissing);
            }
            Ok(())
        } else {
            Self::release_registry(inner, pending.registry);
            pending
                .sender
                .send(DecisionOutcome::Selected(decision))
                .map_err(|_| ProtocolError::DecisionMissing)
        }
    }

    fn cancel_tree(inner: &mut Inner, root: u64) {
        let mut sequences = vec![root];
        let mut index = 0;
        while index < sequences.len() {
            let parent = sequences[index];
            let children: Vec<_> = inner
                .operations
                .iter()
                .filter(|(_, op)| op.parent_sequence == Some(parent))
                .map(|(seq, _)| *seq)
                .collect();
            sequences.extend(children);
            index += 1;
        }
        for sequence in sequences {
            if let Some(operation) = inner.operations.get(&sequence) {
                operation.cancel.send_replace(CancelSignal::Requested);
            }
            Self::cancel_decisions(inner, sequence);
        }
    }

    fn cancel_token_children(inner: &mut Inner, token: &str) {
        let children: Vec<_> = inner
            .operations
            .iter()
            .filter(|(_, op)| op.callback_token.as_deref() == Some(token))
            .map(|(seq, _)| *seq)
            .collect();
        for sequence in children {
            Self::cancel_tree(inner, sequence);
        }
    }

    fn cancel_decisions(inner: &mut Inner, operation_seq: u64) {
        let tokens: Vec<_> = inner
            .decisions
            .iter()
            .filter(|(_, p)| p.owner == DecisionOwner::Operation(operation_seq))
            .map(|(t, _)| t.clone())
            .collect();
        for token in tokens {
            if let Some(pending) = inner.decisions.remove(&token) {
                Self::release_registry(inner, pending.registry);
                let _ = pending.sender.send(DecisionOutcome::Cancelled);
            }
        }
    }

    /// Timer/connection owner calls this without any browser mutex.
    pub fn expire_decisions(&self) -> Result<(), ProtocolError> {
        let mut inner = self.lock()?;
        let now = Instant::now();
        let expired: Vec<String> = inner
            .decisions
            .iter()
            .filter(|(_, p)| now >= p.deadline)
            .map(|(token, _)| token.clone())
            .collect();
        for token in expired {
            let Some(pending) = inner.decisions.remove(&token) else {
                continue;
            };
            Self::cancel_token_children(&mut inner, &token);
            Self::release_registry(&mut inner, pending.registry);
            let _ = pending.sender.send(DecisionOutcome::Expired);
        }
        Ok(())
    }

    pub fn retire_registry(&self, generation: u64, version: u64) -> Result<(), ProtocolError> {
        let mut inner = self.lock()?;
        Self::check(&inner, generation)?;
        let registry = inner
            .registries
            .get_mut(&version)
            .ok_or(ProtocolError::RegistryMissing)?;
        registry.retired = true;
        if registry.references == 0 {
            inner.registries.remove(&version);
            inner.released_registries.push(version);
        }
        Ok(())
    }

    fn release_registry(inner: &mut Inner, version: Option<u64>) {
        if let Some(version) = version {
            if let Some(registry) = inner.registries.get_mut(&version) {
                registry.references -= 1;
                if registry.retired && registry.references == 0 {
                    inner.registries.remove(&version);
                    inner.released_registries.push(version);
                }
            }
        }
    }

    /// Drain release acknowledgements before the client discards callbacks.
    pub fn released_registries(&self) -> Result<Vec<u64>, ProtocolError> {
        self.take_released_registries(usize::MAX)
    }

    pub fn take_released_registries(&self, limit: usize) -> Result<Vec<u64>, ProtocolError> {
        let mut inner = self.lock()?;
        let count = limit.min(inner.released_registries.len());
        Ok(inner.released_registries.drain(..count).collect())
    }

    fn seal(inner: &mut Inner, health: ScopeState) {
        // Seal admission before waking any asynchronous waiter.
        inner.health = health;
        for operation in inner.operations.values() {
            operation.cancel.send_replace(CancelSignal::SessionClosed);
        }
        let pending: Vec<_> = inner.decisions.drain().map(|(_, p)| p).collect();
        for pending in pending {
            Self::release_registry(inner, pending.registry);
            let _ = pending.sender.send(DecisionOutcome::SessionClosed);
        }
    }

    /// EOF / writer overflow: never claims browser teardown has already finished.
    pub fn quarantine(&self) -> Result<(), ProtocolError> {
        let mut inner = self.lock()?;
        if inner.health != ScopeState::Closed {
            Self::seal(&mut inner, ScopeState::Quarantined);
        }
        Ok(())
    }

    /// Browser owner calls only after real teardown, never on cancellation ack.
    pub fn mark_closed(&self) -> Result<(), ProtocolError> {
        let mut inner = self.lock()?;
        Self::seal(&mut inner, ScopeState::Closed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settled_sequences_cannot_replay_after_record_removal() {
        let broker = ClientSession::new();
        broker.admit(1, 10, 1000).unwrap();
        broker.settle(1, 10, Effects::NotDispatched).unwrap();
        assert!(matches!(
            broker.admit(1, 10, 1000),
            Err(ProtocolError::SequenceReused)
        ));
        assert!(matches!(
            broker.admit(1, 9, 1000),
            Err(ProtocolError::SequenceReused)
        ));
        assert!(matches!(
            broker.admit(1, 11, 0),
            Err(ProtocolError::InvalidTimeout)
        ));
        assert!(matches!(
            broker.admit(1, 11, 1000),
            Err(ProtocolError::SequenceReused)
        ));
    }

    #[test]
    fn cancellation_ack_is_not_settlement() {
        let broker = ClientSession::new();
        let op = broker.admit(1, 1, 1000).unwrap();
        broker.cancel(1, 1).unwrap();
        assert_eq!(*op.cancellation.borrow(), CancelSignal::Requested);
        assert_eq!(broker.health().unwrap().1, ScopeState::Usable);
        assert!(!broker.start(1, 1).unwrap());
        assert_eq!(
            broker.settle(1, 1, Effects::Unknown).unwrap(),
            ScopeState::Quarantined
        );
        assert!(matches!(
            broker.admit(1, 2, 1000),
            Err(ProtocolError::ScopeUnavailable)
        ));
    }

    #[tokio::test]
    async fn decision_is_one_use_and_does_not_need_action_lock() {
        let broker = ClientSession::new();
        let action_mutex = tokio::sync::Mutex::new(());
        let _held = action_mutex.lock().await;
        broker.admit(1, 1, 1000).unwrap();
        let lease = broker
            .decision(
                1,
                DecisionOwner::Operation(1),
                DecisionKind::Request,
                1000,
                None,
            )
            .unwrap();
        assert_eq!(
            broker.resolve(2, &lease.token, Decision::Abort {}),
            Err(ProtocolError::StaleGeneration)
        );
        broker.resolve(1, &lease.token, Decision::Abort {}).unwrap();
        assert_eq!(
            broker.resolve(1, &lease.token, Decision::Abort {}),
            Err(ProtocolError::DecisionMissing)
        );
        assert!(matches!(
            lease.outcome.await.unwrap(),
            DecisionOutcome::Selected(Decision::Abort {})
        ));
    }

    #[tokio::test]
    async fn registry_removal_waits_for_captured_request() {
        let broker = ClientSession::new();
        broker
            .register_routes(1, 1, vec!["older".into(), "newer".into()])
            .unwrap();
        broker.admit(1, 1, 1000).unwrap();
        let lease = broker
            .decision(
                1,
                DecisionOwner::Operation(1),
                DecisionKind::Request,
                1000,
                Some(1),
            )
            .unwrap();
        broker.retire_registry(1, 1).unwrap();
        assert!(broker.released_registries().unwrap().is_empty());
        assert_eq!(
            &*lease.registrations,
            &["older".to_string(), "newer".to_string()]
        );
        broker.resolve(1, &lease.token, Decision::Abort {}).unwrap();
        assert_eq!(broker.released_registries().unwrap(), vec![1]);
    }

    #[tokio::test]
    async fn disconnect_seals_admission_before_releasing_waiters() {
        let broker = ClientSession::new();
        broker.admit(1, 1, 1000).unwrap();
        let lease = broker
            .decision(
                1,
                DecisionOwner::Operation(1),
                DecisionKind::Dialog,
                1000,
                None,
            )
            .unwrap();
        broker.quarantine().unwrap();
        assert!(matches!(
            lease.outcome.await.unwrap(),
            DecisionOutcome::SessionClosed
        ));
        assert!(broker.admit(1, 1, 1000).is_err());
        assert_eq!(broker.health().unwrap().1, ScopeState::Quarantined);
        broker.mark_closed().unwrap();
        assert_eq!(broker.health().unwrap().1, ScopeState::Closed);
    }

    #[tokio::test]
    async fn fallback_transfers_retired_snapshot_without_resetting_deadline() {
        let broker = ClientSession::new();
        broker
            .register_routes(1, 1, vec!["a".into(), "b".into()])
            .unwrap();
        broker.admit(1, 1, 1000).unwrap();
        let lease = broker
            .decision(
                1,
                DecisionOwner::Operation(1),
                DecisionKind::Request,
                1000,
                Some(1),
            )
            .unwrap();
        broker.retire_registry(1, 1).unwrap();
        broker
            .resolve(
                1,
                &lease.token,
                Decision::Fallback {
                    overrides: RequestOverrides::default(),
                },
            )
            .unwrap();
        assert!(broker.released_registries().unwrap().is_empty());
        let original_deadline = lease.deadline;
        let next = match lease.outcome.await.unwrap() {
            DecisionOutcome::Fallback { next, .. } => next,
            _ => panic!("expected fallback"),
        };
        assert_eq!(next.deadline, original_deadline);
        assert_eq!(&*next.registrations, &["a".to_string(), "b".to_string()]);
        broker.resolve(1, &next.token, Decision::Abort {}).unwrap();
        assert_eq!(broker.released_registries().unwrap(), vec![1]);
    }

    #[tokio::test]
    async fn invalid_payload_does_not_consume_decision() {
        let broker = ClientSession::new();
        broker.admit(1, 1, 1000).unwrap();
        let lease = broker
            .decision(
                1,
                DecisionOwner::Operation(1),
                DecisionKind::Request,
                1000,
                None,
            )
            .unwrap();
        assert_eq!(
            broker.resolve(
                1,
                &lease.token,
                Decision::Fulfill {
                    status: 999,
                    headers: vec![],
                    body_base64: String::new()
                }
            ),
            Err(ProtocolError::InvalidFrame)
        );
        broker.resolve(1, &lease.token, Decision::Abort {}).unwrap();
        assert!(matches!(
            lease.outcome.await.unwrap(),
            DecisionOutcome::Selected(Decision::Abort {})
        ));
    }

    #[test]
    fn concurrent_decisions_have_one_winner() {
        let broker = Arc::new(ClientSession::new());
        broker.admit(1, 1, 1000).unwrap();
        let lease = broker
            .decision(
                1,
                DecisionOwner::Operation(1),
                DecisionKind::Request,
                1000,
                None,
            )
            .unwrap();
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let broker = broker.clone();
                let token = lease.token.clone();
                std::thread::spawn(move || broker.resolve(1, &token, Decision::Abort {}))
            })
            .collect();
        let winners = threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .filter(Result::is_ok)
            .count();
        assert_eq!(winners, 1);
    }

    #[tokio::test]
    async fn callback_children_inherit_deadline_and_cancel_as_a_tree() {
        let broker = ClientSession::new();
        broker.admit(1, 1, 1000).unwrap();
        let route = broker
            .decision(
                1,
                DecisionOwner::Operation(1),
                DecisionKind::Request,
                1000,
                None,
            )
            .unwrap();
        let child = broker
            .admit_callback(1, 2, 5000, Some(&route.token))
            .unwrap();
        assert!(child.deadline <= route.deadline);
        let nested = broker
            .decision(
                1,
                DecisionOwner::Operation(2),
                DecisionKind::Dialog,
                1000,
                None,
            )
            .unwrap();
        let grandchild = broker
            .admit_callback(1, 3, 5000, Some(&nested.token))
            .unwrap();
        broker.cancel(1, 1).unwrap();
        assert_eq!(*child.cancellation.borrow(), CancelSignal::Requested);
        assert_eq!(*grandchild.cancellation.borrow(), CancelSignal::Requested);
        assert!(matches!(
            route.outcome.await.unwrap(),
            DecisionOutcome::Cancelled
        ));
        assert!(matches!(
            nested.outcome.await.unwrap(),
            DecisionOutcome::Cancelled
        ));
        assert!(matches!(
            broker.admit_callback(1, 4, 1000, Some(&route.token)),
            Err(ProtocolError::DecisionMissing)
        ));
    }

    #[tokio::test]
    async fn selected_decision_waits_for_child_terminal_without_blocking_control() {
        let broker = ClientSession::new();
        broker.admit(1, 1, 1000).unwrap();
        let mut route = broker
            .decision(
                1,
                DecisionOwner::Operation(1),
                DecisionKind::Request,
                1000,
                None,
            )
            .unwrap();
        broker
            .admit_callback(1, 2, 1000, Some(&route.token))
            .unwrap();
        broker.resolve(1, &route.token, Decision::Abort {}).unwrap();
        assert!(matches!(
            route.outcome.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(
            broker.resolve(1, &route.token, Decision::Abort {}),
            Err(ProtocolError::DecisionMissing)
        );
        assert!(matches!(
            broker.admit_callback(1, 3, 1000, Some(&route.token)),
            Err(ProtocolError::DecisionMissing)
        ));
        broker.settle(1, 2, Effects::Completed).unwrap();
        assert!(matches!(
            route.outcome.await.unwrap(),
            DecisionOutcome::Selected(Decision::Abort {})
        ));
    }

    #[tokio::test]
    async fn cancelling_operation_releases_only_its_children() {
        let broker = ClientSession::new();
        broker.admit(1, 1, 1000).unwrap();
        let child = broker
            .decision(
                1,
                DecisionOwner::Operation(1),
                DecisionKind::Request,
                5000,
                None,
            )
            .unwrap();
        let background = broker
            .decision(1, DecisionOwner::Scope, DecisionKind::Dialog, 5000, None)
            .unwrap();
        assert!(child.deadline <= broker.lock().unwrap().operations[&1].deadline);
        broker.cancel(1, 1).unwrap();
        assert!(matches!(
            child.outcome.await.unwrap(),
            DecisionOutcome::Cancelled
        ));
        broker
            .resolve(
                1,
                &background.token,
                Decision::Dialog {
                    accept: false,
                    prompt_text: None,
                },
            )
            .unwrap();
        assert!(matches!(
            background.outcome.await.unwrap(),
            DecisionOutcome::Selected(_)
        ));
    }
}
