//! Browser-independent control broker. No method acquires DaemonState or
//! BrowserManager locks. Browser integration must report real settlement before
//! reuse; accepting cancellation never asserts that browser effects stopped.
use std::collections::{HashMap, HashSet};
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
    resource_scope: Option<String>,
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
    transfer: Option<String>,
}

/// Native-only, non-cloneable hold on one exact client-tenure route snapshot.
/// Abandonment retires it; it never silently restores admission.
pub(crate) struct RouteRegistryTransfer {
    broker: Arc<ClientSession>,
    generation: u64,
    operation: Option<RegistryTransferOperation>,
    version: u64,
    source_scope: String,
    nonce: String,
    completed: bool,
}
/// A parked terminal snapshot has no RPC operation until reconnect admission.
/// It shares the same registry/nonce engine as ordinary scope replacement, but
/// exposes no rollback into a disconnected source.
pub(crate) struct ParkedRouteRegistry {
    held: RouteRegistryTransfer,
}
struct RegistryTransferOperation {
    sequence: u64,
    deadline: Instant,
    cancellation: watch::Receiver<CancelSignal>,
}
impl RegistryTransferOperation {
    fn capture(operation: &OperationLease) -> Self {
        Self {
            sequence: operation.sequence,
            deadline: operation.deadline,
            cancellation: operation.cancellation.clone(),
        }
    }
}
impl ParkedRouteRegistry {
    pub(crate) fn version(&self) -> u64 {
        self.held.version
    }
}
impl RouteRegistryTransfer {
    pub(crate) fn version(&self) -> u64 {
        self.version
    }
    fn check_operation(&self, operation: &OperationLease) -> Result<(), ProtocolError> {
        if self.completed {
            return Err(ProtocolError::StaleScope);
        }
        if operation.generation != self.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        let captured = self
            .operation
            .as_ref()
            .ok_or(ProtocolError::InvalidSequence)?;
        if operation.is_callback || operation.sequence != captured.sequence {
            return Err(ProtocolError::InvalidSequence);
        }
        if *captured.cancellation.borrow() != CancelSignal::None
            || *operation.cancellation.borrow() != CancelSignal::None
        {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= captured.deadline || Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(())
    }
}
impl Drop for RouteRegistryTransfer {
    fn drop(&mut self) {
        if !self.completed {
            let broker = self.broker.clone();
            let _ = broker.retire_registry_transfer(self);
        }
    }
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
    publication_retiring: HashSet<u64>,
    publication_retired: HashSet<u64>,
    registry_scopes: HashMap<u64, String>,
}

/// One broker lives for the entire client session. Scope generations may change;
/// operation high-water never rolls back. Canonical refs belong to RefMap, not this broker.
pub struct ClientSession {
    pub id: String,
    inner: Mutex<Inner>,
    publication_changed: tokio::sync::Notify,
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
            publication_changed: tokio::sync::Notify::new(),
            inner: Mutex::new(Inner {
                generation: 1,
                health: ScopeState::Usable,
                high_water: 0,
                operations: HashMap::new(),
                decisions: HashMap::new(),
                registries: HashMap::new(),
                registry_high_water: 0,
                released_registries: Vec::new(),
                publication_retiring: HashSet::new(),
                publication_retired: HashSet::new(),
                registry_scopes: HashMap::new(),
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
        self.settle_with_retention(generation, sequence, effects, None)
    }

    /// Block new application dispatch, then revoke the exact operation tree and
    /// its source callback token under the broker lock. No browser lock/await.
    pub(crate) fn begin_operation_retirement(
        &self,
        key: super::client_debt::OperationKey,
        proof: &super::client_operation_state::OperationRetentionProof,
    ) -> Result<(), ProtocolError> {
        if !proof.matches(key) {
            return Err(ProtocolError::InvalidSequence);
        }
        let mut inner = self.lock()?;
        Self::check(&inner, key.generation)?;
        if !inner.operations.contains_key(&key.operation_seq) {
            return Err(ProtocolError::OperationMissing);
        }
        inner.publication_retiring.insert(key.operation_seq);
        Self::revoke_uncertain_operation(&mut inner, key.operation_seq);
        Ok(())
    }
    pub(crate) fn finish_operation_publication(
        &self,
        key: super::client_debt::OperationKey,
    ) -> Result<(), ProtocolError> {
        let mut inner = self.lock()?;
        Self::check(&inner, key.generation)?;
        if !inner.publication_retiring.remove(&key.operation_seq) {
            return Err(ProtocolError::OperationMissing);
        }
        inner.publication_retired.insert(key.operation_seq);
        self.publication_changed.notify_waiters();
        Ok(())
    }
    pub(crate) fn check_application_publication(
        &self,
        generation: u64,
    ) -> Result<bool, ProtocolError> {
        let inner = self.lock()?;
        Self::check(&inner, generation)?;
        Ok(inner.publication_retiring.is_empty())
    }
    pub(crate) async fn wait_application_publication(
        &self,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        let mut cancellation = operation.cancellation.clone();
        loop {
            let changed = self.publication_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if *cancellation.borrow() != CancelSignal::None {
                return Err(ProtocolError::Cancelled);
            }
            if Instant::now() >= operation.deadline {
                return Err(ProtocolError::DeadlineExceeded);
            }
            if self.check_application_publication(operation.generation)? {
                return Ok(());
            }
            tokio::select! { biased;
                _=cancellation.changed()=>return Err(ProtocolError::Cancelled),
                _=tokio::time::sleep_until(operation.deadline.into())=>return Err(ProtocolError::DeadlineExceeded),
                _=&mut changed=>{},
            }
        }
    }
    fn revoke_uncertain_operation(inner: &mut Inner, sequence: u64) {
        let source = inner
            .operations
            .get(&sequence)
            .and_then(|operation| operation.callback_token.clone());
        Self::cancel_tree(inner, sequence);
        if let Some(token) = source {
            // Scope-owned tokens are not descendants of the child operation.
            // Discard any selected decision and cancel sibling child authority.
            Self::cancel_token_children(inner, &token);
            if let Some(pending) = inner.decisions.remove(&token) {
                Self::release_registry(inner, pending.registry);
                let _ = pending.sender.send(DecisionOutcome::Cancelled);
            }
        }
    }
    pub(crate) fn settle_with_retention(
        &self,
        generation: u64,
        sequence: u64,
        effects: Effects,
        proof: Option<&super::client_operation_state::OperationRetentionProof>,
    ) -> Result<ScopeState, ProtocolError> {
        let mut inner = self.lock()?;
        if inner.generation != generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if !inner.operations.contains_key(&sequence) {
            return Err(ProtocolError::OperationMissing);
        }
        let retained = effects == Effects::Unknown
            && proof.is_some_and(|proof| {
                proof.matches(super::client_debt::OperationKey {
                    generation,
                    operation_seq: sequence,
                })
            })
            && inner.publication_retired.remove(&sequence);
        inner.publication_retiring.remove(&sequence);
        self.publication_changed.notify_waiters();
        if effects == Effects::Unknown {
            Self::revoke_uncertain_operation(&mut inner, sequence);
        } else {
            Self::cancel_tree(&mut inner, sequence);
        }
        let operation = inner
            .operations
            .remove(&sequence)
            .ok_or(ProtocolError::OperationMissing)?;
        Self::cancel_decisions(&mut inner, sequence);
        if effects == Effects::Unknown {
            if !retained && inner.health != ScopeState::Closed {
                Self::seal(&mut inner, ScopeState::Quarantined);
            }
            // Never apply the old selected decision after an uncertain child.
        } else if let Some(token) = operation.callback_token {
            let has_children = inner
                .operations
                .values()
                .any(|op| op.callback_token.as_deref() == Some(&token));
            if !has_children {
                if let Some(decision) = inner
                    .decisions
                    .get_mut(&token)
                    .and_then(|pending| pending.selected.take())
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
        self.register_routes_scoped(generation, version, registrations, None)
    }
    pub fn register_routes_scoped(
        &self,
        generation: u64,
        version: u64,
        registrations: Vec<String>,
        identity_scope: Option<String>,
    ) -> Result<(), ProtocolError> {
        self.replace_routes_scoped(generation, version, registrations, identity_scope, None)
    }
    /// Publish the new immutable snapshot and retire the old one under one
    /// broker lock. Every rejection happens before either registry changes.
    pub fn replace_routes_scoped(
        &self,
        generation: u64,
        version: u64,
        registrations: Vec<String>,
        identity_scope: Option<String>,
        previous: Option<u64>,
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
        if identity_scope.as_ref().is_some_and(|scope| {
            inner.registry_scopes.iter().any(|(version, owner)| {
                owner == scope
                    && inner
                        .registries
                        .get(version)
                        .is_some_and(|registry| registry.transfer.is_some())
            })
        }) {
            return Err(ProtocolError::RegistryInUse);
        }
        if let Some(old) = previous {
            let registry = inner
                .registries
                .get(&old)
                .ok_or(ProtocolError::RegistryMissing)?;
            if registry.retired || inner.registry_scopes.get(&old) != identity_scope.as_ref() {
                return Err(ProtocolError::StaleScope);
            }
        }
        if let Some(scope) = identity_scope {
            if scope.is_empty() {
                return Err(ProtocolError::InvalidArguments);
            }
            inner.registry_scopes.insert(version, scope);
        }
        inner.registry_high_water = version;
        inner.registries.insert(
            version,
            Registry {
                registrations: registrations.into(),
                references: 0,
                retired: false,
                transfer: None,
            },
        );
        if let Some(old) = previous {
            // Presence and identity were checked under this same lock.
            let old_registry = inner
                .registries
                .get_mut(&old)
                .expect("validated previous registry");
            old_registry.retired = true;
            if old_registry.references == 0 && old_registry.transfer.is_none() {
                inner.registries.remove(&old);
                inner.released_registries.push(old);
            }
        }
        Ok(())
    }

    /// Capture before source teardown. Existing paused/fallback chains retain
    /// their references, but new captures cannot use this held registry.
    pub(crate) fn capture_registry_transfer(
        self: &Arc<Self>,
        version: u64,
        source_scope: &str,
        operation: &OperationLease,
    ) -> Result<RouteRegistryTransfer, ProtocolError> {
        let mut inner = self.lock()?;
        Self::check(&inner, operation.generation)?;
        if source_scope.is_empty() || operation.is_callback {
            return Err(ProtocolError::InvalidArguments);
        }
        if *operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        self.hold_registry(&mut inner, version, source_scope, Some(operation))
    }
    /// Terminal owner calls this before revoking the disconnected source. No
    /// operation is admitted or fabricated at EOF, and a retired registry can
    /// never be reconstructed from its version or registration IDs.
    pub(crate) fn park_registry(
        self: &Arc<Self>,
        generation: u64,
        version: u64,
        source_scope: &str,
    ) -> Result<ParkedRouteRegistry, ProtocolError> {
        let mut inner = self.lock()?;
        Self::check(&inner, generation)?;
        if source_scope.is_empty() {
            return Err(ProtocolError::InvalidArguments);
        }
        Ok(ParkedRouteRegistry {
            held: self.hold_registry(&mut inner, version, source_scope, None)?,
        })
    }
    fn hold_registry(
        self: &Arc<Self>,
        inner: &mut Inner,
        version: u64,
        source_scope: &str,
        operation: Option<&OperationLease>,
    ) -> Result<RouteRegistryTransfer, ProtocolError> {
        if inner.registry_scopes.get(&version).map(String::as_str) != Some(source_scope) {
            return Err(ProtocolError::StaleScope);
        }
        let registry = inner
            .registries
            .get_mut(&version)
            .ok_or(ProtocolError::RegistryMissing)?;
        if registry.retired || registry.transfer.is_some() {
            return Err(ProtocolError::RegistryInUse);
        }
        let nonce = Uuid::new_v4().to_string();
        registry.retired = true;
        registry.transfer = Some(nonce.clone());
        Ok(RouteRegistryTransfer {
            broker: self.clone(),
            generation: inner.generation,
            operation: operation.map(RegistryTransferOperation::capture),
            version,
            source_scope: source_scope.into(),
            nonce,
            completed: false,
        })
    }
    fn check_transfer(
        &self,
        inner: &Inner,
        transfer: &RouteRegistryTransfer,
    ) -> Result<(), ProtocolError> {
        if !std::ptr::eq(self, transfer.broker.as_ref()) || transfer.completed {
            return Err(ProtocolError::StaleScope);
        }
        if inner.generation != transfer.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if inner.registry_scopes.get(&transfer.version) != Some(&transfer.source_scope) {
            return Err(ProtocolError::StaleScope);
        }
        let registry = inner
            .registries
            .get(&transfer.version)
            .ok_or(ProtocolError::RegistryMissing)?;
        if registry.transfer.as_deref() != Some(&transfer.nonce) || !registry.retired {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
    fn check_live_operation(
        inner: &Inner,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        Self::check(inner, operation.generation)?;
        if operation.is_callback {
            return Err(ProtocolError::InvalidArguments);
        }
        let admitted = inner
            .operations
            .get(&operation.sequence)
            .ok_or(ProtocolError::OperationMissing)?;
        if admitted.callback_token.is_some()
            || admitted.deadline != operation.deadline
            || !admitted
                .cancel
                .subscribe()
                .same_channel(&operation.cancellation)
        {
            return Err(ProtocolError::InvalidSequence);
        }
        if *operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(())
    }
    pub(crate) fn validate_reconnect_operation(
        &self,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        let inner = self.lock()?;
        Self::check_live_operation(&inner, operation)
    }
    /// A field read borrows only its live native callback's resource scope.
    /// It gains no parent-operation, reference, or input authority.
    pub(crate) fn validate_field_read(
        &self,
        operation: &OperationLease,
        identity_scope: &str,
    ) -> Result<(), ProtocolError> {
        let inner = self.lock()?;
        Self::check(&inner, operation.generation)?;
        let admitted = inner
            .operations
            .get(&operation.sequence)
            .ok_or(ProtocolError::OperationMissing)?;
        if !admitted.started
            || admitted.deadline != operation.deadline
            || admitted.callback_token.is_some() != operation.is_callback
            || !admitted
                .cancel
                .subscribe()
                .same_channel(&operation.cancellation)
        {
            return Err(ProtocolError::InvalidSequence);
        }
        if *operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        if let Some(token) = &admitted.callback_token {
            let decision = inner
                .decisions
                .get(token)
                .ok_or(ProtocolError::DecisionMissing)?;
            if decision.selected.is_some() {
                return Err(ProtocolError::DecisionMissing);
            }
            if Instant::now() >= decision.deadline {
                return Err(ProtocolError::DecisionExpired);
            }
            if decision.resource_scope.as_deref() != Some(identity_scope) {
                return Err(ProtocolError::StaleScope);
            }
        }
        Ok(())
    }
    /// Bind once, only after real lifecycle admission. Failure leaves the hold
    /// dormant and available for explicit retirement, not implicit restoration.
    pub(crate) fn bind_parked_registry(
        &self,
        parked: &mut ParkedRouteRegistry,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        let inner = self.lock()?;
        Self::check_live_operation(&inner, operation)?;
        self.check_transfer(&inner, &parked.held)?;
        if parked.held.operation.is_some() {
            return Err(ProtocolError::InvalidSequence);
        }
        parked.held.operation = Some(RegistryTransferOperation::capture(operation));
        Ok(())
    }
    pub(crate) fn adopt_parked_registry(
        &self,
        parked: &mut ParkedRouteRegistry,
        replacement_scope: &str,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        let captured = parked
            .held
            .operation
            .as_ref()
            .ok_or(ProtocolError::InvalidSequence)?;
        if captured.deadline != operation.deadline
            || !captured.cancellation.same_channel(&operation.cancellation)
        {
            return Err(ProtocolError::InvalidSequence);
        }
        self.adopt_held_registry(&mut parked.held, replacement_scope, operation, true)
    }
    pub(crate) fn retire_parked_registry(
        &self,
        parked: &mut ParkedRouteRegistry,
    ) -> Result<(), ProtocolError> {
        self.retire_registry_transfer(&mut parked.held)
    }
    /// Move the existing immutable version, never register a second snapshot or
    /// lower the client's monotonic version high-water mark. Network ownership
    /// additionally proves its retained readers have completed before calling.
    pub(crate) fn adopt_registry_transfer(
        &self,
        transfer: &mut RouteRegistryTransfer,
        replacement_scope: &str,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        self.adopt_held_registry(transfer, replacement_scope, operation, false)
    }
    fn adopt_held_registry(
        &self,
        transfer: &mut RouteRegistryTransfer,
        replacement_scope: &str,
        operation: &OperationLease,
        require_admitted: bool,
    ) -> Result<(), ProtocolError> {
        transfer.check_operation(operation)?;
        let mut inner = self.lock()?;
        Self::check(&inner, transfer.generation)?;
        if require_admitted {
            Self::check_live_operation(&inner, operation)?;
        }
        self.check_transfer(&inner, transfer)?;
        if replacement_scope.is_empty() || replacement_scope == transfer.source_scope {
            return Err(ProtocolError::StaleScope);
        }
        if inner.registry_scopes.iter().any(|(version, scope)| {
            scope == replacement_scope && inner.registries.contains_key(version)
        }) {
            return Err(ProtocolError::RegistryInUse);
        }
        if inner.registries[&transfer.version].references != 0
            || inner
                .decisions
                .values()
                .any(|pending| pending.resource_scope.as_deref() == Some(&transfer.source_scope))
        {
            return Err(ProtocolError::RegistryInUse);
        }
        let registry = inner
            .registries
            .get_mut(&transfer.version)
            .expect("validated transfer registry");
        registry.transfer = None;
        registry.retired = false;
        inner
            .registry_scopes
            .insert(transfer.version, replacement_scope.into());
        transfer.completed = true;
        Ok(())
    }
    /// Explicit rollback is available only while the captured operation is
    /// still live. Native network ownership must also verify the source has not
    /// been revoked. Drop and cancellation never call this method.
    pub(crate) fn restore_registry_transfer(
        &self,
        transfer: &mut RouteRegistryTransfer,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        transfer.check_operation(operation)?;
        let mut inner = self.lock()?;
        Self::check(&inner, transfer.generation)?;
        self.check_transfer(&inner, transfer)?;
        let registry = inner
            .registries
            .get_mut(&transfer.version)
            .expect("validated transfer registry");
        registry.transfer = None;
        registry.retired = false;
        transfer.completed = true;
        Ok(())
    }
    /// Retirement remains available after cancellation or broker quarantine.
    /// The original scope attribution survives until its release event drains.
    pub(crate) fn retire_registry_transfer(
        &self,
        transfer: &mut RouteRegistryTransfer,
    ) -> Result<(), ProtocolError> {
        let mut inner = self.lock()?;
        self.check_transfer(&inner, transfer)?;
        let registry = inner
            .registries
            .get_mut(&transfer.version)
            .expect("validated transfer registry");
        registry.transfer = None;
        registry.retired = true;
        if registry.references == 0 {
            inner.registries.remove(&transfer.version);
            inner.released_registries.push(transfer.version);
        }
        transfer.completed = true;
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
        self.decision_scoped(generation, owner, kind, timeout_ms, registry, None)
    }
    pub fn decision_scoped(
        &self,
        generation: u64,
        owner: DecisionOwner,
        kind: DecisionKind,
        timeout_ms: u64,
        registry: Option<u64>,
        resource_scope: Option<String>,
    ) -> Result<DecisionLease, ProtocolError> {
        if resource_scope.as_ref().is_some_and(String::is_empty) {
            return Err(ProtocolError::InvalidArguments);
        }
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
            if inner.registry_scopes.get(&version) != resource_scope.as_ref() {
                return Err(ProtocolError::StaleScope);
            }
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
                resource_scope,
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

    /// Capture the pending decision's original resource scope on the control
    /// lane. Never derive upload authority from the currently active page.
    pub fn decision_resource_scope(
        &self,
        generation: u64,
        token: &str,
    ) -> Result<String, ProtocolError> {
        let inner = self.lock()?;
        Self::check(&inner, generation)?;
        let pending = inner
            .decisions
            .get(token)
            .ok_or(ProtocolError::DecisionMissing)?;
        if Instant::now() >= pending.deadline {
            return Err(ProtocolError::DecisionExpired);
        }
        if pending.selected.is_some() {
            return Err(ProtocolError::DecisionMissing);
        }
        pending
            .resource_scope
            .clone()
            .ok_or(ProtocolError::StaleScope)
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
                    resource_scope: pending.resource_scope,
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

    /// Revokes even a fallback token that has been created by control but not
    /// yet observed by its asynchronous native resource task.
    pub fn revoke_scope_decisions(&self, scope: &str) -> Result<(), ProtocolError> {
        let mut inner = self.lock()?;
        let tokens: Vec<_> = inner
            .decisions
            .iter()
            .filter(|(_, pending)| pending.resource_scope.as_deref() == Some(scope))
            .map(|(token, _)| token.clone())
            .collect();
        for token in tokens {
            if let Some(pending) = inner.decisions.remove(&token) {
                Self::cancel_token_children(&mut inner, &token);
                Self::release_registry(&mut inner, pending.registry);
                let _ = pending.sender.send(DecisionOutcome::Cancelled);
            }
        }
        Ok(())
    }

    /// Scoped native resource owner revokes one callback before destroying its
    /// context. Missing/settled tokens are harmless; sibling scopes are untouched.
    pub fn revoke_decision(&self, token: &str) -> Result<(), ProtocolError> {
        let mut inner = self.lock()?;
        if let Some(pending) = inner.decisions.remove(token) {
            Self::cancel_token_children(&mut inner, token);
            Self::release_registry(&mut inner, pending.registry);
            let _ = pending.sender.send(DecisionOutcome::Cancelled);
        }
        Ok(())
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
        if registry.references == 0 && registry.transfer.is_none() {
            inner.registries.remove(&version);
            inner.released_registries.push(version);
        }
        Ok(())
    }

    fn release_registry(inner: &mut Inner, version: Option<u64>) {
        if let Some(version) = version {
            if let Some(registry) = inner.registries.get_mut(&version) {
                registry.references -= 1;
                if registry.retired && registry.references == 0 && registry.transfer.is_none() {
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
        Ok(self
            .take_released_registry_events(limit)?
            .into_iter()
            .map(|(version, _)| version)
            .collect())
    }
    pub fn take_released_registry_events(
        &self,
        limit: usize,
    ) -> Result<Vec<(u64, Option<String>)>, ProtocolError> {
        let mut inner = self.lock()?;
        let count = limit.min(inner.released_registries.len());
        let versions: Vec<_> = inner.released_registries.drain(..count).collect();
        Ok(versions
            .into_iter()
            .map(|version| (version, inner.registry_scopes.remove(&version)))
            .collect())
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

    fn live_field_callback(broker: &ClientSession) -> (OperationLease, DecisionLease) {
        let decision = broker
            .decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Authentication,
                5000,
                None,
                Some("scope".into()),
            )
            .unwrap();
        let operation = broker
            .admit_callback(1, 1, 5000, Some(&decision.token))
            .unwrap();
        assert!(broker.start(1, 1).unwrap());
        (operation, decision)
    }

    #[test]
    fn field_read_requires_an_exact_started_operation_even_without_a_callback() {
        let broker = ClientSession::new();
        let mut operation = broker.admit(1, 1, 5000).unwrap();
        assert_eq!(
            broker.validate_field_read(&operation, "scope"),
            Err(ProtocolError::InvalidSequence)
        );
        assert!(broker.start(1, 1).unwrap());
        assert_eq!(broker.validate_field_read(&operation, "scope"), Ok(()));
        operation.is_callback = true;
        assert_eq!(
            broker.validate_field_read(&operation, "scope"),
            Err(ProtocolError::InvalidSequence)
        );
        operation.is_callback = false;
        let original = operation.cancellation.clone();
        let (_sender, forged) = watch::channel(CancelSignal::None);
        operation.cancellation = forged;
        assert_eq!(
            broker.validate_field_read(&operation, "scope"),
            Err(ProtocolError::InvalidSequence)
        );
        operation.cancellation = original;
        broker.settle(1, 1, Effects::Completed).unwrap();
        assert_eq!(
            broker.validate_field_read(&operation, "scope"),
            Err(ProtocolError::OperationMissing)
        );
    }

    #[test]
    fn field_read_rejects_cross_scope_and_selected_callback_decisions() {
        let broker = ClientSession::new();
        let (operation, decision) = live_field_callback(&broker);
        assert_eq!(broker.validate_field_read(&operation, "scope"), Ok(()));
        assert_eq!(
            broker.validate_field_read(&operation, "foreign"),
            Err(ProtocolError::StaleScope)
        );
        broker
            .resolve(1, &decision.token, Decision::CancelAuth {})
            .unwrap();
        assert_eq!(
            broker.validate_field_read(&operation, "scope"),
            Err(ProtocolError::Cancelled)
        );
    }

    #[test]
    fn field_read_rejects_expired_revoked_and_cancelled_callback_authority() {
        for case in ["expired", "revoked", "cancelled"] {
            let broker = ClientSession::new();
            let (operation, decision) = live_field_callback(&broker);
            match case {
                "expired" => {
                    broker
                        .lock()
                        .unwrap()
                        .decisions
                        .get_mut(&decision.token)
                        .unwrap()
                        .deadline = Instant::now() - Duration::from_millis(1)
                }
                "revoked" => {
                    broker.lock().unwrap().decisions.remove(&decision.token);
                }
                _ => broker.cancel(1, operation.sequence).unwrap(),
            }
            assert_eq!(
                broker.validate_field_read(&operation, "scope"),
                Err(match case {
                    "expired" => ProtocolError::DecisionExpired,
                    "revoked" => ProtocolError::DecisionMissing,
                    _ => ProtocolError::Cancelled,
                })
            );
        }
    }

    #[tokio::test]
    async fn parked_registry_waits_for_old_callbacks_and_preserves_exact_version() {
        let broker = Arc::new(ClientSession::new());
        broker
            .register_routes_scoped(
                1,
                7,
                vec!["first".into(), "second".into()],
                Some("old".into()),
            )
            .unwrap();
        let pending = broker
            .decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                1000,
                Some(7),
                Some("old".into()),
            )
            .unwrap();
        let registrations = pending.registrations.clone();
        let mut parked = broker.park_registry(1, 7, "old").unwrap();
        assert!(parked.held.operation.is_none());
        broker.retire_registry(1, 7).unwrap();
        assert!(broker.take_released_registry_events(8).unwrap().is_empty());
        assert!(broker
            .decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                1000,
                Some(7),
                Some("old".into())
            )
            .is_err());
        let operation = broker.admit(1, 1, 5000).unwrap();
        broker
            .bind_parked_registry(&mut parked, &operation)
            .unwrap();
        assert_eq!(
            broker.adopt_parked_registry(&mut parked, "new", &operation),
            Err(ProtocolError::RegistryInUse)
        );
        broker.revoke_scope_decisions("old").unwrap();
        assert!(matches!(
            pending.outcome.await.unwrap(),
            DecisionOutcome::Cancelled
        ));
        assert_eq!(
            broker.decision_resource_scope(1, &pending.token),
            Err(ProtocolError::DecisionMissing)
        );
        assert!(broker.take_released_registry_events(8).unwrap().is_empty());
        broker
            .adopt_parked_registry(&mut parked, "new", &operation)
            .unwrap();
        let next = broker
            .decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                1000,
                Some(7),
                Some("new".into()),
            )
            .unwrap();
        assert!(Arc::ptr_eq(&registrations, &next.registrations));
        assert_eq!(next.registry_version, Some(7));
        broker.revoke_scope_decisions("old").unwrap();
        assert!(broker.decision_resource_scope(1, &next.token).is_ok());
        broker.revoke_scope_decisions("new").unwrap();
        broker.retire_registry(1, 7).unwrap();
        assert_eq!(
            broker.take_released_registry_events(8).unwrap(),
            vec![(7, Some("new".into()))]
        );
    }
    #[test]
    fn parked_registry_requires_exact_admitted_operation_and_owner() {
        let broker = Arc::new(ClientSession::new());
        let other = Arc::new(ClientSession::new());
        broker
            .register_routes_scoped(1, 1, vec!["route".into()], Some("old".into()))
            .unwrap();
        assert!(broker.park_registry(1, 1, "foreign").is_err());
        assert!(broker.park_registry(2, 1, "old").is_err());
        let mut parked = broker.park_registry(1, 1, "old").unwrap();
        let (_cancel, invented) = transfer_operation();
        assert_eq!(
            broker.bind_parked_registry(&mut parked, &invented),
            Err(ProtocolError::OperationMissing)
        );
        let operation = broker.admit(1, 1, 5000).unwrap();
        let foreign_operation = other.admit(1, 1, 5000).unwrap();
        assert_eq!(
            broker.bind_parked_registry(&mut parked, &foreign_operation),
            Err(ProtocolError::InvalidSequence)
        );
        assert_eq!(
            other.bind_parked_registry(&mut parked, &foreign_operation),
            Err(ProtocolError::StaleScope)
        );
        broker
            .bind_parked_registry(&mut parked, &operation)
            .unwrap();
        assert_eq!(
            broker.bind_parked_registry(&mut parked, &operation),
            Err(ProtocolError::InvalidSequence)
        );
        assert_eq!(
            broker.adopt_parked_registry(&mut parked, "old", &operation),
            Err(ProtocolError::StaleScope)
        );
        broker.retire_parked_registry(&mut parked).unwrap();
        assert!(broker
            .adopt_parked_registry(&mut parked, "new", &operation)
            .is_err());
        assert!(broker.park_registry(1, 1, "old").is_err());
        assert_eq!(
            broker.take_released_registry_events(8).unwrap(),
            vec![(1, Some("old".into()))]
        );
    }
    #[tokio::test]
    async fn parked_registry_expiry_cancellation_and_abandonment_never_revive() {
        for expire in [false, true] {
            let broker = Arc::new(ClientSession::new());
            broker
                .register_routes_scoped(1, 1, vec!["route".into()], Some("old".into()))
                .unwrap();
            let mut parked = broker.park_registry(1, 1, "old").unwrap();
            let operation = broker.admit(1, 1, if expire { 1 } else { 5000 }).unwrap();
            broker
                .bind_parked_registry(&mut parked, &operation)
                .unwrap();
            if expire {
                tokio::time::sleep(Duration::from_millis(5)).await;
            } else {
                broker.cancel(1, 1).unwrap();
            }
            assert_eq!(
                broker.adopt_parked_registry(&mut parked, "new", &operation),
                Err(if expire {
                    ProtocolError::DeadlineExceeded
                } else {
                    ProtocolError::Cancelled
                })
            );
            assert!(broker.take_released_registry_events(8).unwrap().is_empty());
            broker.quarantine().unwrap();
            broker.retire_parked_registry(&mut parked).unwrap();
            assert_eq!(
                broker.take_released_registry_events(8).unwrap(),
                vec![(1, Some("old".into()))]
            );
        }
        let broker = Arc::new(ClientSession::new());
        broker
            .register_routes_scoped(1, 3, vec!["route".into()], Some("old".into()))
            .unwrap();
        drop(broker.park_registry(1, 3, "old").unwrap());
        assert_eq!(
            broker.take_released_registry_events(8).unwrap(),
            vec![(3, Some("old".into()))]
        );
        assert!(broker.park_registry(1, 3, "old").is_err());
    }
    fn transfer_operation() -> (watch::Sender<CancelSignal>, OperationLease) {
        let (send, cancellation) = watch::channel(CancelSignal::None);
        (
            send,
            OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline: Instant::now() + Duration::from_secs(5),
                cancellation,
            },
        )
    }
    #[tokio::test]
    async fn route_transfer_holds_release_until_old_decisions_drain_and_preserves_version() {
        let broker = Arc::new(ClientSession::new());
        let (_cancel, operation) = transfer_operation();
        broker
            .register_routes_scoped(
                1,
                7,
                vec!["first".into(), "second".into()],
                Some("old".into()),
            )
            .unwrap();
        let pending = broker
            .decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                1000,
                Some(7),
                Some("old".into()),
            )
            .unwrap();
        let registrations = pending.registrations.clone();
        let mut transfer = broker
            .capture_registry_transfer(7, "old", &operation)
            .unwrap();
        broker.retire_registry(1, 7).unwrap();
        assert!(broker.take_released_registry_events(8).unwrap().is_empty());
        assert_eq!(
            broker.adopt_registry_transfer(&mut transfer, "new", &operation),
            Err(ProtocolError::RegistryInUse)
        );
        assert!(broker
            .decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                1000,
                Some(7),
                Some("old".into())
            )
            .is_err());
        broker.revoke_scope_decisions("old").unwrap();
        assert!(matches!(
            pending.outcome.await.unwrap(),
            DecisionOutcome::Cancelled
        ));
        assert!(broker.take_released_registry_events(8).unwrap().is_empty());
        broker
            .adopt_registry_transfer(&mut transfer, "new", &operation)
            .unwrap();
        assert!(broker.take_released_registry_events(8).unwrap().is_empty());
        assert_eq!(
            broker
                .decision_scoped(
                    1,
                    DecisionOwner::Scope,
                    DecisionKind::Request,
                    1000,
                    Some(7),
                    Some("old".into())
                )
                .err()
                .unwrap(),
            ProtocolError::StaleScope
        );
        let current = broker
            .decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                1000,
                Some(7),
                Some("new".into()),
            )
            .unwrap();
        assert_eq!(current.registry_version, Some(7));
        assert!(Arc::ptr_eq(&registrations, &current.registrations));
        assert_eq!(
            broker.register_routes_scoped(1, 7, vec![], Some("new".into())),
            Err(ProtocolError::InvalidSequence)
        );
        broker
            .replace_routes_scoped(1, 8, vec![], Some("new".into()), Some(7))
            .unwrap();
        assert!(broker.take_released_registry_events(8).unwrap().is_empty());
        broker.revoke_decision(&current.token).unwrap();
        assert_eq!(
            broker.take_released_registry_events(8).unwrap(),
            vec![(7, Some("new".into()))]
        );
        broker.retire_registry(1, 8).unwrap();
        assert_eq!(
            broker.take_released_registry_events(8).unwrap(),
            vec![(8, Some("new".into()))]
        );
    }
    #[test]
    fn route_transfer_rejects_wrong_owner_scope_generation_and_cancellation() {
        let broker = Arc::new(ClientSession::new());
        let other = ClientSession::new();
        let (cancel, mut operation) = transfer_operation();
        broker
            .register_routes_scoped(1, 1, vec!["route".into()], Some("old".into()))
            .unwrap();
        assert!(broker
            .capture_registry_transfer(1, "foreign", &operation)
            .is_err());
        let mut transfer = broker
            .capture_registry_transfer(1, "old", &operation)
            .unwrap();
        assert_eq!(
            other.adopt_registry_transfer(&mut transfer, "new", &operation),
            Err(ProtocolError::StaleScope)
        );
        assert_eq!(
            broker.adopt_registry_transfer(&mut transfer, "old", &operation),
            Err(ProtocolError::StaleScope)
        );
        operation.generation = 2;
        assert_eq!(
            broker.adopt_registry_transfer(&mut transfer, "new", &operation),
            Err(ProtocolError::StaleGeneration)
        );
        operation.generation = 1;
        operation.sequence = 2;
        assert_eq!(
            broker.restore_registry_transfer(&mut transfer, &operation),
            Err(ProtocolError::InvalidSequence)
        );
        operation.sequence = 1;
        cancel.send(CancelSignal::Requested).unwrap();
        assert_eq!(
            broker.adopt_registry_transfer(&mut transfer, "new", &operation),
            Err(ProtocolError::Cancelled)
        );
        assert_eq!(
            broker.restore_registry_transfer(&mut transfer, &operation),
            Err(ProtocolError::Cancelled)
        );
        assert!(broker.take_released_registry_events(8).unwrap().is_empty());
        broker.retire_registry_transfer(&mut transfer).unwrap();
        assert_eq!(
            broker.take_released_registry_events(8).unwrap(),
            vec![(1, Some("old".into()))]
        );
        assert_eq!(
            broker.restore_registry_transfer(&mut transfer, &operation),
            Err(ProtocolError::StaleScope)
        );
    }
    #[test]
    fn explicit_restore_and_abandonment_never_confuse_route_ownership() {
        let broker = Arc::new(ClientSession::new());
        let (_cancel, operation) = transfer_operation();
        broker
            .register_routes_scoped(1, 1, vec!["route".into()], Some("old".into()))
            .unwrap();
        let mut transfer = broker
            .capture_registry_transfer(1, "old", &operation)
            .unwrap();
        assert_eq!(
            broker.replace_routes_scoped(1, 2, vec![], Some("old".into()), None),
            Err(ProtocolError::RegistryInUse)
        );
        broker
            .restore_registry_transfer(&mut transfer, &operation)
            .unwrap();
        drop(transfer);
        assert!(broker.take_released_registry_events(8).unwrap().is_empty());
        let transfer = broker
            .capture_registry_transfer(1, "old", &operation)
            .unwrap();
        drop(transfer);
        assert_eq!(
            broker.take_released_registry_events(8).unwrap(),
            vec![(1, Some("old".into()))]
        );
        assert!(broker.take_released_registry_events(8).unwrap().is_empty());
        assert!(broker
            .decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                1000,
                Some(1),
                Some("old".into())
            )
            .is_err());
    }
    #[tokio::test]
    async fn abandoned_transfer_waits_for_its_final_reader_and_survives_quarantine() {
        let broker = Arc::new(ClientSession::new());
        let (_cancel, operation) = transfer_operation();
        broker
            .register_routes_scoped(1, 1, vec!["route".into()], Some("old".into()))
            .unwrap();
        let pending = broker
            .decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                1000,
                Some(1),
                Some("old".into()),
            )
            .unwrap();
        let transfer = broker
            .capture_registry_transfer(1, "old", &operation)
            .unwrap();
        drop(transfer);
        assert!(broker.take_released_registry_events(8).unwrap().is_empty());
        broker.quarantine().unwrap();
        assert!(matches!(
            pending.outcome.await.unwrap(),
            DecisionOutcome::SessionClosed
        ));
        assert_eq!(
            broker.take_released_registry_events(8).unwrap(),
            vec![(1, Some("old".into()))]
        );
    }
    #[test]
    fn route_replacement_rejection_never_retires_old_or_publishes_new() {
        let broker = ClientSession::new();
        broker
            .register_routes_scoped(1, 1, vec!["old".into()], Some("scope".into()))
            .unwrap();
        for (previous, registrations, scope) in [
            (
                Some(1),
                vec!["duplicate".into(), "duplicate".into()],
                "scope",
            ),
            (Some(99), vec!["new".into()], "scope"),
            (Some(1), vec!["new".into()], "foreign"),
        ] {
            assert!(broker
                .replace_routes_scoped(1, 2, registrations, Some(scope.into()), previous)
                .is_err());
            let inner = broker.lock().unwrap();
            assert!(!inner.registries[&1].retired);
            assert!(!inner.registries.contains_key(&2));
            assert_eq!(inner.registry_high_water, 1);
            assert!(inner.released_registries.is_empty());
        }
        let old = broker
            .decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                1000,
                Some(1),
                Some("scope".into()),
            )
            .unwrap();
        broker
            .replace_routes_scoped(1, 2, vec!["new".into()], Some("scope".into()), Some(1))
            .unwrap();
        let inner = broker.lock().unwrap();
        assert!(inner.registries[&1].retired);
        assert_eq!(inner.registries[&1].references, 1);
        assert!(!inner.registries[&2].retired);
        assert_eq!(inner.registry_high_water, 2);
        drop(inner);
        drop(old);
    }
    #[tokio::test]
    async fn scope_revoke_cancels_fallback_before_resource_task_observes_it() {
        let broker = ClientSession::new();
        let first = broker
            .decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                1000,
                None,
                Some("old".into()),
            )
            .unwrap();
        broker
            .resolve(
                1,
                &first.token,
                Decision::Fallback {
                    overrides: Default::default(),
                },
            )
            .unwrap();
        broker.revoke_scope_decisions("old").unwrap();
        let DecisionOutcome::Fallback { next, .. } = first.outcome.await.unwrap() else {
            panic!("expected fallback");
        };
        assert!(matches!(
            next.outcome.await.unwrap(),
            DecisionOutcome::Cancelled
        ));
        assert!(matches!(
            broker.resolve(1, &next.token, Decision::Abort {}),
            Err(ProtocolError::DecisionMissing)
        ));
        assert_eq!(broker.health().unwrap().1, ScopeState::Usable);
    }

    #[tokio::test]
    async fn revoked_callback_releases_original_scope_registry() {
        let broker = ClientSession::new();
        broker
            .register_routes_scoped(1, 1, vec!["route".into()], Some("old-context".into()))
            .unwrap();
        let lease = broker
            .decision_scoped(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                1000,
                Some(1),
                Some("old-context".into()),
            )
            .unwrap();
        broker.retire_registry(1, 1).unwrap();
        broker.revoke_decision(&lease.token).unwrap();
        assert!(matches!(
            lease.outcome.await.unwrap(),
            DecisionOutcome::Cancelled
        ));
        assert_eq!(
            broker.take_released_registry_events(8).unwrap(),
            vec![(1, Some("old-context".into()))]
        );
        assert_eq!(broker.health().unwrap().1, ScopeState::Usable);
        assert!(matches!(
            broker.admit_callback(1, 1, 1000, Some(&lease.token)),
            Err(ProtocolError::DecisionMissing)
        ));
    }

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
                    body_base64: Some(String::new()),
                    body_handle: None
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

#[cfg(test)]
mod exact_retention_tests {
    use super::super::client_debt::{OperationKey, OwnerDebtLedger};
    use super::super::client_operation_state::OperationRegistry;
    use super::*;
    fn retired_proof(
        sequence: u64,
    ) -> super::super::client_operation_state::OperationRetentionProof {
        let key = OperationKey {
            generation: 1,
            operation_seq: sequence,
        };
        let journal = OwnerDebtLedger::new(1, "scope".into())
            .operation(key, "target".into(), "session".into())
            .unwrap();
        let registry = OperationRegistry::default();
        registry.register(journal).unwrap();
        registry.retire(key);
        registry.finish(key, false);
        registry.status(key).proof().unwrap()
    }
    #[tokio::test]
    async fn uncertain_scope_callback_child_revokes_only_its_exact_token_and_siblings() {
        let broker = ClientSession::new();
        broker
            .register_routes(1, 1, vec!["configured-route".into()])
            .unwrap();
        let mut old = broker
            .decision(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                5000,
                Some(1),
            )
            .unwrap();
        let unrelated = broker
            .decision(
                1,
                DecisionOwner::Scope,
                DecisionKind::Authentication,
                5000,
                None,
            )
            .unwrap();
        let first = broker.admit_callback(1, 1, 5000, Some(&old.token)).unwrap();
        let sibling = broker.admit_callback(1, 2, 5000, Some(&old.token)).unwrap();
        broker.resolve(1, &old.token, Decision::Abort {}).unwrap();
        assert!(matches!(
            old.outcome.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        let key = OperationKey {
            generation: 1,
            operation_seq: 1,
        };
        let proof = retired_proof(1);
        broker.begin_operation_retirement(key, &proof).unwrap();
        assert!(!broker.check_application_publication(1).unwrap());
        assert_eq!(*first.cancellation.borrow(), CancelSignal::Requested);
        assert_eq!(*sibling.cancellation.borrow(), CancelSignal::Requested);
        assert!(matches!(
            old.outcome.await.unwrap(),
            DecisionOutcome::Cancelled
        ));
        assert_eq!(
            broker.resolve(1, &old.token, Decision::Abort {}),
            Err(ProtocolError::DecisionMissing)
        );
        // The owner-service lane never enters the publication barrier.
        broker
            .resolve(1, &unrelated.token, Decision::CancelAuth {})
            .unwrap();
        assert!(matches!(
            unrelated.outcome.await.unwrap(),
            DecisionOutcome::Selected(Decision::CancelAuth {})
        ));
        broker.finish_operation_publication(key).unwrap();
        assert_eq!(
            broker
                .settle_with_retention(1, 1, Effects::Unknown, Some(&proof))
                .unwrap(),
            ScopeState::Usable
        );
        assert_eq!(broker.health().unwrap(), (1, ScopeState::Usable));
        broker.settle(1, 2, Effects::NotDispatched).unwrap();
        let fresh = broker
            .decision(
                1,
                DecisionOwner::Scope,
                DecisionKind::Request,
                5000,
                Some(1),
            )
            .unwrap();
        assert_eq!(
            fresh.registrations.to_vec(),
            vec!["configured-route".to_owned()]
        );
        broker.resolve(1, &fresh.token, Decision::Abort {}).unwrap();
        assert!(matches!(
            fresh.outcome.await.unwrap(),
            DecisionOutcome::Selected(Decision::Abort {})
        ));
    }
    #[test]
    fn exact_proof_without_completed_publication_barrier_is_terminal() {
        let broker = ClientSession::new();
        broker.admit(1, 1, 1000).unwrap();
        let proof = retired_proof(1);
        assert_eq!(
            broker
                .settle_with_retention(1, 1, Effects::Unknown, Some(&proof))
                .unwrap(),
            ScopeState::Quarantined
        );
    }
}
